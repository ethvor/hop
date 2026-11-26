use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::{TcpStream, ToSocketAddrs};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::config::{Device, HopConfig, edges_cache_path, ensure_parent, parse_cloudflare_host};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub host: String,
    pub rtt_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub alias: String,
    pub relay: bool,
    pub hosts: Vec<String>,
    pub description: Option<String>,
}

/// Directed weighted topology snapshot, cached at `~/.cache/hop/edges.json`
/// and emitted via `hop probe --json` as a clean feed for topology maps and dashboards.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeGraph {
    pub schema: String,
    pub updated_unix: u64,
    pub self_node: String,
    pub max_hops: usize,
    pub nodes: Vec<NodeInfo>,
    pub edges: Vec<Edge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteStep {
    pub alias: String,
    pub host: String,
    pub rtt_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub target: String,
    /// Ordered acyclic chain `[hop1, ..., target]` (len 1 = direct, len 2 = 2-hop, len 3 = 3-hop)
    pub steps: Vec<RouteStep>,
    pub total_rtt_ms: f64,
}

impl Route {
    pub fn hop_count(&self) -> usize {
        self.steps.len()
    }

    pub fn compact_path(&self) -> String {
        if self.steps.len() == 1 {
            let host = &self.steps[0].host;
            let transport = crate::config::classify_host_transport(host);
            let label = match transport {
                "vpn/zt" => "vpn",
                other => other,
            };
            format!("direct ({label})")
        } else {
            self.steps
                .iter()
                .map(|s| s.alias.as_str())
                .collect::<Vec<_>>()
                .join(" -> ")
        }
    }

    pub fn summary(&self) -> String {
        let rtt = if self.total_rtt_ms >= 100.0 {
            format!("{:.0}ms", self.total_rtt_ms)
        } else {
            format!("{:.1}ms", self.total_rtt_ms)
        };
        if self.steps.len() == 1 {
            let host = crate::ui::short_host(&self.steps[0].host);
            format!("direct ({host}) {rtt}")
        } else {
            let chain = self
                .steps
                .iter()
                .map(|s| s.alias.as_str())
                .collect::<Vec<_>>()
                .join(" -> ");
            format!("{chain} ({rtt})")
        }
    }
}

/// Measures TCP port-22 RTT to a single host (1 RTT = live TCP SYN/SYN-ACK time).
pub fn measure_tcp_rtt(host: &str, port: u16, timeout: Duration) -> Option<f64> {
    let addrs: Vec<_> = (host, port).to_socket_addrs().ok()?.collect();
    for addr in addrs {
        let start = Instant::now();
        if TcpStream::connect_timeout(&addr, timeout).is_ok() {
            return Some((start.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0);
        }
    }
    None
}

/// Probes a `cf://<hostname>` Cloudflare Access SSH endpoint via HTTPS status check.
/// Rejects HTTP 530/502/503 (tunnel disconnected) and requires local `cloudflared`.
pub fn probe_cloudflare_host(cf_host: &str, timeout: Duration) -> Option<f64> {
    crate::connect::find_cloudflared_bin()?;
    let max_secs = timeout.as_secs_f64().clamp(1.2, 4.0);
    let url = format!("https://{cf_host}/");
    let start = Instant::now();
    let out = Command::new("curl")
        .args([
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            &format!("{max_secs:.1}"),
            &url,
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let code: u16 = String::from_utf8_lossy(&out.stdout).trim().parse().ok()?;
    if code == 0 || code == 530 || code == 502 || code == 503 || code == 522 || code == 524 {
        return None;
    }
    let elapsed_ms = (start.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0;
    // Keep a conservative floor above typical LAN/Tailscale direct RTTs so direct transports win when healthy
    Some(elapsed_ms.max(45.0))
}

/// Races all configured `hosts` for one device in parallel and returns all reachable hosts sorted by RTT.
pub fn probe_device_hosts(dev: &Device, timeout: Duration) -> Vec<(String, f64)> {
    let port = dev.ssh_port();
    let mut handles = Vec::with_capacity(dev.hosts.len());
    for host in dev.hosts.clone() {
        handles.push(thread::spawn(move || {
            if let Some(cf_host) = parse_cloudflare_host(&host) {
                probe_cloudflare_host(cf_host, timeout.max(Duration::from_millis(1800)))
                    .map(|rtt| (host, rtt))
            } else {
                measure_tcp_rtt(&host, port, timeout).map(|rtt| (host, rtt))
            }
        }));
    }
    let mut hits: Vec<(String, f64)> = handles
        .into_iter()
        .filter_map(|h| h.join().ok().flatten())
        .collect();
    hits.sort_by(|a, b| a.1.total_cmp(&b.1));
    hits
}

/// Probes direct 1-hop TCP edges from this machine to every configured device in parallel.
pub fn probe_local(cfg: &HopConfig, timeout: Duration) -> EdgeGraph {
    let self_node = cfg.self_label();
    let mut handles = Vec::new();
    for (alias, dev) in &cfg.devices {
        if alias == &self_node {
            continue;
        }
        let alias = alias.clone();
        let dev = dev.clone();
        handles.push(thread::spawn(move || {
            let hits = probe_device_hosts(&dev, timeout);
            (alias, hits)
        }));
    }

    let mut edges = Vec::new();
    for h in handles {
        if let Ok((alias, hits)) = h.join() {
            // Keep the fastest reachable host per direct peer, plus up to 1 alternate for visibility
            for (host, rtt_ms) in hits.into_iter().take(2) {
                edges.push(Edge {
                    from: self_node.clone(),
                    to: alias.clone(),
                    host,
                    rtt_ms,
                });
            }
        }
    }

    let nodes = cfg
        .devices
        .iter()
        .map(|(alias, dev)| NodeInfo {
            alias: alias.clone(),
            relay: dev.relay.unwrap_or(false),
            hosts: dev.hosts.clone(),
            description: dev.description.clone(),
        })
        .collect();

    EdgeGraph {
        schema: "hop.graph/v1".to_string(),
        updated_unix: now_unix(),
        self_node,
        max_hops: cfg.effective_max_hops(),
        nodes,
        edges,
    }
}

/// Probes local edges AND queries every reachable `relay = true` peer in parallel
/// via `ssh <relay> hop probe --local --json` to assemble the full multi-hop graph.
pub fn probe_fleet(cfg: &HopConfig, timeout: Duration) -> EdgeGraph {
    let mut graph = probe_local(cfg, timeout);

    // Find best direct host for each reachable relay peer
    let mut relay_targets: Vec<(String, String, Device)> = Vec::new();
    for (alias, dev) in &cfg.devices {
        if !dev.relay.unwrap_or(false) || alias == &graph.self_node {
            continue;
        }
        if let Some(best) = graph
            .edges
            .iter()
            .filter(|e| e.from == graph.self_node && e.to == *alias)
            .min_by(|a, b| a.rtt_ms.total_cmp(&b.rtt_ms))
        {
            relay_targets.push((alias.clone(), best.host.clone(), dev.clone()));
        }
    }

    let mut handles = Vec::with_capacity(relay_targets.len());
    for (alias, host, dev) in relay_targets {
        handles.push(thread::spawn(move || {
            let target = dev.target_spec(&host);
            let mut cmd = Command::new("ssh");
            cmd.args([
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=3",
                "-o",
                "StrictHostKeyChecking=accept-new",
            ]);
            if let Some(p) = dev.port {
                cmd.args(["-p", &p.to_string()]);
            }
            if let Some(key) = dev.expanded_identity_file() {
                cmd.args(["-i", &key, "-o", "IdentitiesOnly=yes"]);
            }
            cmd.args([&target, "hop probe --local --json"]);
            cmd.stdin(Stdio::null());
            let Ok(out) = cmd.output() else {
                return Vec::new();
            };
            if !out.status.success() {
                return Vec::new();
            }
            let Ok(peer_graph) = serde_json::from_slice::<EdgeGraph>(&out.stdout) else {
                return Vec::new();
            };
            peer_graph
                .edges
                .into_iter()
                .map(|mut e| {
                    // Normalize `from` to this peer's configured alias
                    e.from = alias.clone();
                    e
                })
                .collect::<Vec<_>>()
        }));
    }

    for h in handles {
        if let Ok(peer_edges) = h.join() {
            graph.edges.extend(peer_edges);
        }
    }

    graph
}

/// Finds all strictly acyclic routes from `src` to `dst` with `1..=max_hops` hops,
/// sorted ascending by total cumulative RTT. Picks 2-hop or 3-hop over 1-hop whenever
/// the multi-hop cumulative RTT is strictly faster.
pub fn ranked_acyclic_routes(
    graph: &EdgeGraph,
    src: &str,
    dst: &str,
    max_hops: usize,
) -> Vec<Route> {
    // Collapse parallel edges between the same (from, to) to the lowest-RTT host
    let mut adj: BTreeMap<&str, BTreeMap<&str, (&str, f64)>> = BTreeMap::new();
    for e in &graph.edges {
        let entry = adj.entry(e.from.as_str()).or_default();
        let replace = entry
            .get(e.to.as_str())
            .is_none_or(|(_, rtt)| e.rtt_ms < *rtt);
        if replace {
            entry.insert(e.to.as_str(), (e.host.as_str(), e.rtt_ms));
        }
    }

    let mut results = Vec::new();
    let mut visited = BTreeSet::new();
    visited.insert(src.to_string());
    let mut path = Vec::new();

    dfs_routes(
        &adj,
        src,
        dst,
        max_hops.clamp(1, 4),
        &mut visited,
        &mut path,
        0.0,
        &mut results,
    );

    results.sort_by(|a, b| {
        a.total_rtt_ms
            .total_cmp(&b.total_rtt_ms)
            .then_with(|| a.hop_count().cmp(&b.hop_count()))
    });
    results
}

#[allow(clippy::too_many_arguments)]
fn dfs_routes(
    adj: &BTreeMap<&str, BTreeMap<&str, (&str, f64)>>,
    cur: &str,
    dst: &str,
    remaining_hops: usize,
    visited: &mut BTreeSet<String>,
    path: &mut Vec<RouteStep>,
    acc_rtt: f64,
    out: &mut Vec<Route>,
) {
    if remaining_hops == 0 {
        return;
    }
    let Some(neighbors) = adj.get(cur) else {
        return;
    };
    for (&next, &(host, rtt_ms)) in neighbors {
        if visited.contains(next) {
            continue;
        }
        let step = RouteStep {
            alias: next.to_string(),
            host: host.to_string(),
            rtt_ms,
        };
        let next_rtt = acc_rtt + rtt_ms;
        path.push(step);

        if next == dst {
            out.push(Route {
                target: dst.to_string(),
                steps: path.clone(),
                total_rtt_ms: (next_rtt * 10.0).round() / 10.0,
            });
        } else if remaining_hops > 1 {
            visited.insert(next.to_string());
            dfs_routes(
                adj,
                next,
                dst,
                remaining_hops - 1,
                visited,
                path,
                next_rtt,
                out,
            );
            visited.remove(next);
        }

        path.pop();
    }
}

pub fn save_graph_cache(graph: &EdgeGraph) -> Result<()> {
    let path = edges_cache_path()?;
    ensure_parent(&path)?;
    fs::write(&path, serde_json::to_string_pretty(graph)?)?;
    Ok(())
}

pub fn load_graph_cache() -> Option<EdgeGraph> {
    let path = edges_cache_path().ok()?;
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
