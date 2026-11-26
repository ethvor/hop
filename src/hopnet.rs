use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::config::{
    HopConfig, cache_dir, classify_host_transport, direct_routes_path, ensure_parent,
    ingress_state_path,
};
use crate::connect::{build_ssh_command_with_flags, select_route};
use crate::graph::{load_graph_cache, measure_tcp_rtt, ranked_acyclic_routes};
use crate::serve::{
    ServeReport, ServerEntry, TailscaleSnapshot, augmented_path, build_local_report,
    collect_fleet_reports, evaluate_access_audit, expose_tailscale_route, split_command_line,
    stop_tailscale_route, tailscale_shim_port,
};
use crate::ui::{Align, Style, Table};

const LAUNCHD_LABEL: &str = "io.hopnet.serve";
const SYSTEMD_UNIT: &str = "hop-serve.service";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectRoutesState {
    pub pid: u32,
    pub updated_unix: u64,
    pub routes: Vec<DirectRouteRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectRouteRecord {
    pub server_id: String,
    pub bind_ip: String,
    pub bind_port: u16,
    pub upstream_host: String,
    pub upstream_port: u16,
    pub scheme: String,
    pub url: String,
    pub trusted_ip_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressRoutesState {
    pub pid: u32,
    pub updated_unix: u64,
    pub ingress_port: u16,
    pub routes: Vec<IngressRouteRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressRouteRecord {
    pub server_id: String,
    pub slug: String,
    pub upstream_host: String,
    pub upstream_port: u16,
    pub scheme: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HopnetReport {
    pub schema: String,
    pub self_device: String,
    pub max_hops: usize,
    pub transports: Vec<String>,
    pub bind_ips: Vec<String>,
    pub tailscale_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tailscale_dns: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_domain: Option<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub status: BTreeMap<String, serde_json::Value>,
    pub trusted_devices: Vec<HopnetDeviceView>,
    pub trusted_peers: Vec<String>,
    pub relays: Vec<HopnetDeviceView>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tailscale_peers: Vec<HopnetTailscalePeer>,
    pub servers: Vec<ServerEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HopnetTailscalePeer {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    pub online: bool,
    pub trusted: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct HopnetDeviceView {
    pub alias: String,
    pub role: String,
    pub transports: Vec<String>,
    pub hosts: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub best_route: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LocatedServer {
    pub device: String,
    pub is_local: bool,
    pub id: String,
    pub host: String,
    pub port: u16,
    pub scheme: String,
    pub path: Option<String>,
    pub exposed_url: Option<String>,
}

pub fn load_live_direct_routes() -> Vec<DirectRouteRecord> {
    let Ok(path) = direct_routes_path() else {
        return Vec::new();
    };
    let Ok(raw) = fs::read_to_string(&path) else {
        return Vec::new();
    };
    let Ok(state) = serde_json::from_str::<DirectRoutesState>(&raw) else {
        return Vec::new();
    };
    if state.pid == 0 || !pid_alive(state.pid) {
        return Vec::new();
    }
    state.routes
}

pub fn load_live_ingress_routes() -> Vec<IngressRouteRecord> {
    let Ok(path) = ingress_state_path() else {
        return Vec::new();
    };
    let Ok(raw) = fs::read_to_string(&path) else {
        return Vec::new();
    };
    let Ok(state) = serde_json::from_str::<IngressRoutesState>(&raw) else {
        return Vec::new();
    };
    if state.pid == 0 || !pid_alive(state.pid) {
        return Vec::new();
    }
    state.routes
}

fn save_ingress_routes(ingress_port: u16, routes: &[IngressRouteRecord]) -> Result<()> {
    let path = ingress_state_path()?;
    ensure_parent(&path)?;
    let state = IngressRoutesState {
        pid: std::process::id(),
        updated_unix: now_unix(),
        ingress_port,
        routes: routes.to_vec(),
    };
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_string_pretty(&state)?)?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

fn save_direct_routes(routes: &[DirectRouteRecord]) -> Result<()> {
    let path = direct_routes_path()?;
    ensure_parent(&path)?;
    let state = DirectRoutesState {
        pid: std::process::id(),
        updated_unix: now_unix(),
        routes: routes.to_vec(),
    };
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_string_pretty(&state)?)?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

/// Formal hopnet overview: transports, trusted mesh nodes, one-way relays, and active servers.
pub fn cmd_net(cfg: &HopConfig, fleet: bool, as_json: bool) -> Result<()> {
    let (local_report, ts) = build_local_report(cfg)?;
    let self_label = cfg.self_label();
    let graph = load_graph_cache();

    let mut trusted_devices = Vec::new();
    let mut relays = Vec::new();

    let mut route_display: BTreeMap<String, (String, Option<f64>)> = BTreeMap::new();
    for (alias, dev) in &cfg.devices {
        let mut trans: Vec<String> = dev
            .hosts
            .iter()
            .map(|h| classify_host_transport(h).to_string())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if trans.is_empty() {
            trans.push("none".to_string());
        }

        let best = if alias == &self_label {
            None
        } else {
            graph.as_ref().and_then(|g| {
                ranked_acyclic_routes(g, &g.self_node, alias, cfg.effective_max_hops())
                    .into_iter()
                    .next()
            })
        };

        let best_route = if alias == &self_label {
            route_display.insert(alias.clone(), ("this device".to_string(), None));
            Some("local".to_string())
        } else if let Some(ref r) = best {
            route_display.insert(alias.clone(), (r.compact_path(), Some(r.total_rtt_ms)));
            Some(r.summary())
        } else {
            None
        };

        let is_trusted = dev.trusted.unwrap_or(false) || alias == &self_label;
        let is_relay = dev.relay.unwrap_or(false);
        let role = match (is_trusted, is_relay) {
            (true, true) => "trusted + relay",
            (true, false) => "trusted",
            (false, true) => "one-way relay",
            (false, false) => "untrusted",
        }
        .to_string();

        let view = HopnetDeviceView {
            alias: alias.clone(),
            role,
            transports: trans,
            hosts: dev.hosts.clone(),
            best_route,
            description: dev.description.clone(),
        };

        if is_trusted {
            trusted_devices.push(view);
        } else if is_relay {
            relays.push(view);
        }
    }

    let mut servers = local_report.servers.clone();
    if fleet {
        let peer_outcomes = collect_fleet_reports(cfg);
        for peer in peer_outcomes {
            if let Some(rep) = peer.report {
                for entry in rep.servers {
                    if entry.device != rep.device {
                        continue;
                    }
                    if let Some(existing) = servers
                        .iter_mut()
                        .find(|s| s.device == entry.device && s.id == entry.id)
                    {
                        *existing = entry;
                    } else {
                        servers.push(entry);
                    }
                }
            }
        }
    }

    let tailscale_peers: Vec<HopnetTailscalePeer> = ts
        .peers
        .iter()
        .map(|p| HopnetTailscalePeer {
            name: p.name.clone(),
            dns_name: p.dns_name.clone(),
            os: p.os.clone(),
            online: p.online,
            trusted: p.trusted,
        })
        .collect();

    let report = HopnetReport {
        schema: "hop.net/v1".to_string(),
        self_device: self_label,
        max_hops: cfg.effective_max_hops(),
        transports: cfg.hopnet.effective_transports(),
        bind_ips: cfg.hopnet.bind_ips.clone(),
        tailscale_available: ts.available,
        tailscale_dns: ts.self_dns.clone(),
        origin_host: cfg.hopnet.origin_host.clone(),
        public_domain: cfg.hopnet.public_domain.clone(),
        status: local_report.status.clone(),
        trusted_devices,
        trusted_peers: cfg.trusted_peers.clone(),
        relays,
        tailscale_peers,
        servers,
    };

    if as_json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    let st = Style::stdout();
    let subtitle = match report.tailscale_dns.as_deref() {
        Some(dns) => format!("{}  ({dns})", report.self_device),
        None => report.self_device.clone(),
    };
    st.header("hopnet", Some(&subtitle));

    let mut meta = format!(
        "exposure: {}   max hops: {}",
        report.transports.join(", "),
        report.max_hops
    );
    if !report.bind_ips.is_empty() {
        meta.push_str(&format!("   bind: {}", report.bind_ips.join(", ")));
    }
    println!("  {}", st.dim(&meta));

    // Unified aligned Devices table: local first, then trusted, then outbound relays
    let mut ordered_trusted: Vec<&HopnetDeviceView> = report.trusted_devices.iter().collect();
    ordered_trusted.sort_by_key(|d| {
        let rank = if d.alias == report.self_device {
            0
        } else if d.role == "trusted + relay" {
            1
        } else {
            2
        };
        (rank, d.alias.as_str())
    });

    st.section(&format!(
        "Devices ({})",
        report.trusted_devices.len() + report.relays.len()
    ));
    let mut dev_tbl = Table::new(
        2,
        &[
            ("DEVICE", Align::Left),
            ("ROLE", Align::Left),
            ("VIA", Align::Left),
            ("ROUTE", Align::Left),
            ("RTT", Align::Right),
        ],
    );
    let fmt_transports = |ts: &[String]| -> String {
        ts.iter()
            .map(|t| match t.as_str() {
                "vpn/zt" => "vpn",
                other => other,
            })
            .collect::<Vec<_>>()
            .join(", ")
    };

    for d in ordered_trusted {
        let is_self = d.alias == report.self_device;
        let name = if is_self {
            st.bold_cyan(&d.alias)
        } else {
            st.bold(&d.alias)
        };
        let role = if is_self {
            st.green("local")
        } else if d.role == "trusted + relay" {
            st.cyan("trusted+relay")
        } else {
            "trusted".to_string()
        };
        let via = fmt_transports(&d.transports);
        let (route, rtt) = match route_display.get(&d.alias) {
            Some((r, Some(ms))) => (r.clone(), st.rtt(*ms)),
            Some((r, None)) => (st.dim(r), st.dim("-")),
            None => (st.dim("not probed"), st.dim("-")),
        };
        dev_tbl.row(vec![name, role, via, route, rtt]);
    }
    for r in &report.relays {
        let name = st.bold(&r.alias);
        let role = st.yellow("outbound");
        let via = fmt_transports(&r.transports);
        let (route, rtt) = match route_display.get(&r.alias) {
            Some((p, Some(ms))) => (p.clone(), st.rtt(*ms)),
            Some((p, None)) => (st.dim(p), st.dim("-")),
            None => (st.dim("not probed"), st.dim("-")),
        };
        dev_tbl.row(vec![name, role, via, route, rtt]);
    }
    dev_tbl.print(&st);

    if !report.trusted_peers.is_empty() {
        let peers: Vec<String> = report.trusted_peers.iter().map(|p| st.dim(p)).collect();
        println!();
        st.wrapped_labeled(2, &st.dim("Other trusted:"), &peers, ", ");
    }
    if !report.relays.is_empty() {
        st.note(
            2,
            "Outbound relays are jump-only (blocked from dev servers).",
        );
    }

    // Servers table: sort running first, then remote, then down
    let mut up_servers: Vec<&ServerEntry> = report
        .servers
        .iter()
        .filter(|s| s.kind != "unregistered")
        .collect();
    up_servers.sort_by_key(|s| {
        let state_rank = match s.up {
            Some(true) => 0,
            None => 1,
            Some(false) => 2,
        };
        (state_rank, s.device.as_str(), s.id.as_str())
    });

    st.section(&format!("Servers ({})", up_servers.len()));
    if up_servers.is_empty() {
        st.note(
            2,
            "None declared. Configure server_sources or run `hop serve add`.",
        );
    } else {
        let mut srv_tbl = Table::new(
            2,
            &[
                ("SERVER", Align::Left),
                ("DEVICE", Align::Left),
                ("PORT", Align::Right),
                ("STATE", Align::Left),
                ("ACCESS", Align::Left),
            ],
        );
        for s in up_servers {
            let state = if s.port_conflict.is_some() {
                st.yellow("▲ conflict")
            } else {
                st.state_badge(&s.kind, s.up)
            };
            let mut urls: Vec<String> = Vec::new();
            if let Some(pu) = &s.public_url {
                urls.push(pu.clone());
            }
            if let Some(u) = &s.exposed_url {
                urls.push(u.clone());
            }
            urls.extend(s.direct_urls.iter().cloned());
            let access = if let Some(conflict) = &s.port_conflict {
                st.yellow(conflict)
            } else if !urls.is_empty() {
                if s.up == Some(false) {
                    format!("{} {}", st.yellow(&urls.join(" | ")), st.dim("(stale)"))
                } else {
                    st.cyan(&urls.join(" | "))
                }
            } else if s.up == Some(false) {
                st.dim("stopped")
            } else if s.up == Some(true) {
                format!("hop open {}", s.id)
            } else {
                st.dim(&format!("hop open {}", s.id))
            };
            let id_col = if s.up == Some(false) {
                st.dim(&s.id)
            } else {
                st.bold(&s.id)
            };
            let dev_col = if s.up == Some(false) {
                st.dim(&s.device)
            } else {
                s.device.clone()
            };
            let port_col = if s.up == Some(false) {
                st.dim(&s.port.to_string())
            } else {
                s.port.to_string()
            };
            srv_tbl.row(vec![id_col, dev_col, port_col, state, access]);
        }
        srv_tbl.print(&st);
    }

    if !fleet {
        println!();
        st.note(
            2,
            "Tip: `hop net --fleet` queries awake peers; `hop open <server>` connects over the best route.",
        );
    }
    Ok(())
}

/// Locates a declared server across the local host and awake trusted hopnet peers.
pub fn find_server_across_hopnet(
    cfg: &HopConfig,
    target: &str,
    device_filter: Option<&str>,
) -> Result<LocatedServer> {
    let self_label = cfg.self_label();
    let (local_report, _) = build_local_report(cfg)?;

    let mut all_entries: Vec<ServerEntry> = Vec::new();
    if device_filter.is_none() || device_filter == Some(self_label.as_str()) {
        all_entries.extend(
            local_report
                .servers
                .iter()
                .filter(|s| s.device == self_label && s.kind != "unregistered")
                .cloned(),
        );
    }

    // Check if an exact live local match already exists before querying remote peers
    let local_matches = match_entries(&all_entries, target);
    if local_matches.len() == 1 && local_matches[0].up == Some(true) {
        return Ok(entry_to_located(local_matches[0], &self_label));
    }

    // Query awake trusted peers in parallel (respecting optional device filter)
    let peer_outcomes = collect_fleet_reports(cfg);
    for peer in peer_outcomes {
        if let Some(df) = device_filter
            && peer.device != df
        {
            continue;
        }
        if let Some(rep) = peer.report {
            for entry in rep.servers {
                if entry.device == rep.device && entry.kind != "unregistered" {
                    all_entries.push(entry);
                }
            }
        }
    }

    // Also include static remote fleet entries declared in local servers.toml
    for entry in &local_report.servers {
        if entry.device != self_label
            && (device_filter.is_none() || device_filter == Some(entry.device.as_str()))
            && !all_entries
                .iter()
                .any(|e| e.device == entry.device && e.id == entry.id)
        {
            all_entries.push(entry.clone());
        }
    }

    let matches = match_entries(&all_entries, target);
    if matches.is_empty() {
        let known: Vec<String> = all_entries
            .iter()
            .map(|s| format!("{} ({})", s.id, s.device))
            .collect();
        bail!(
            "server `{target}` not found on local host or awake trusted hopnet peers (known: {})",
            if known.is_empty() {
                "none".to_string()
            } else {
                known.join(", ")
            }
        );
    }

    // Prefer live (`up == Some(true)`) matches over down/unknown entries
    let live: Vec<&ServerEntry> = matches
        .iter()
        .copied()
        .filter(|s| s.up == Some(true))
        .collect();
    let pool = if !live.is_empty() { live } else { matches };

    if pool.len() == 1 {
        let chosen = pool[0];
        if chosen.up == Some(false) {
            let hint = chosen
                .cmd
                .as_deref()
                .map(|c| format!(" (start with `{c}`)"))
                .unwrap_or_default();
            bail!(
                "`{}` on `{}` is currently down (not listening on {}:{}){hint}",
                chosen.id,
                chosen.device,
                chosen.host,
                chosen.port
            );
        }
        return Ok(entry_to_located(chosen, &self_label));
    }

    let choices: Vec<String> = pool
        .iter()
        .map(|s| format!("{} on {} (port {})", s.id, s.device, s.port))
        .collect();
    bail!(
        "multiple hopnet matches for `{target}`: {}. Specify `--device <alias>` or full id.",
        choices.join(", ")
    )
}

fn match_entries<'a>(entries: &'a [ServerEntry], target: &str) -> Vec<&'a ServerEntry> {
    let t = target.trim();
    let exact: Vec<&ServerEntry> = entries
        .iter()
        .filter(|s| s.id.eq_ignore_ascii_case(t))
        .collect();
    if !exact.is_empty() {
        return exact;
    }
    let clean = t.strip_prefix("fleet:").unwrap_or(t);
    let by_name: Vec<&ServerEntry> = entries
        .iter()
        .filter(|s| s.name.eq_ignore_ascii_case(clean))
        .collect();
    if !by_name.is_empty() {
        return by_name;
    }
    entries
        .iter()
        .filter(|s| {
            s.project
                .as_deref()
                .is_some_and(|p| p.eq_ignore_ascii_case(t))
        })
        .collect()
}

fn entry_to_located(entry: &ServerEntry, self_label: &str) -> LocatedServer {
    LocatedServer {
        device: entry.device.clone(),
        is_local: entry.device == self_label,
        id: entry.id.clone(),
        host: entry.host.clone(),
        port: entry.port,
        scheme: entry.scheme.clone(),
        path: entry.path.clone(),
        exposed_url: entry.exposed_url.clone(),
    }
}

/// Device-free, transport-agnostic `hop open <server>` over the best available hopnet route.
pub fn cmd_open(
    cfg: &HopConfig,
    target: &str,
    device_filter: Option<&str>,
    local_port: Option<u16>,
    direct_only: bool,
    no_browser: bool,
) -> Result<()> {
    let loc = find_server_across_hopnet(cfg, target, device_filter)?;
    let suffix = loc
        .path
        .as_deref()
        .filter(|p| !p.is_empty() && *p != "/")
        .unwrap_or("");

    if loc.is_local {
        let url = format!("{}://127.0.0.1:{}{suffix}", loc.scheme, loc.port);
        println!("[hopnet] `{}` is local: {url}", loc.id);
        if let Some(ex) = &loc.exposed_url {
            println!("         hopnet URL: {ex}");
        }
        if !no_browser {
            let _ = launch_browser(&url);
        }
        return Ok(());
    }

    let bind_port = local_port.unwrap_or(loc.port);
    let route = select_route(cfg, &loc.device, direct_only)?;
    let local_url = format!("{}://127.0.0.1:{bind_port}{suffix}", loc.scheme);
    eprintln!(
        "[hopnet] opening `{}` on `{}` -> {local_url} via {}",
        loc.id,
        loc.device,
        route.summary()
    );
    eprintln!("[hopnet] press Ctrl-C to close tunnel");

    let forward_spec = format!("127.0.0.1:{bind_port}:{}:{}", loc.host, loc.port);
    let flags = vec![
        "-N".to_string(),
        "-o".to_string(),
        "ExitOnForwardFailure=yes".to_string(),
        "-L".to_string(),
        forward_spec,
    ];
    let mut cmd = build_ssh_command_with_flags(cfg, &route, false, false, &flags)?;
    let mut child = cmd
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("failed spawning SSH tunnel")?;

    // Wait up to 5s for the forwarded local port to accept connections before opening browser
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut ready = false;
    while Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            bail!("SSH tunnel exited prematurely with {status}");
        }
        if measure_tcp_rtt("127.0.0.1", bind_port, Duration::from_millis(80)).is_some() {
            ready = true;
            break;
        }
        thread::sleep(Duration::from_millis(80));
    }

    if ready {
        println!("{local_url}");
        if !no_browser {
            let _ = launch_browser(&local_url);
        }
    } else {
        eprintln!("[hopnet] tunnel started, waiting for local port {bind_port}...");
    }

    let status = child.wait().context("failed waiting on SSH tunnel")?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

fn launch_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
    }
    #[cfg(target_os = "linux")]
    {
        Command::new("xdg-open")
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
    }
    #[cfg(target_os = "windows")]
    {
        Command::new("cmd")
            .args(["/C", "start", "", url])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
    }
    Ok(())
}

/// One-shot reconciliation: expose all currently running declared servers and prune dead routes.
pub fn cmd_serve_sync(
    cfg: &HopConfig,
    dry_run: bool,
    no_prune: bool,
    allow_untrusted: bool,
) -> Result<()> {
    let (report, ts) = build_local_report(cfg)?;
    let self_label = cfg.self_label();
    let use_ts = cfg.hopnet.uses_transport("tailscale");
    let use_direct = cfg.hopnet.uses_transport("direct") && !cfg.hopnet.bind_ips.is_empty();

    if !use_ts && !use_direct {
        bail!(
            "no hopnet exposure transports configured (enable `tailscale` or set `[hopnet] bind_ips`)"
        );
    }

    let declared_local: Vec<&ServerEntry> = report
        .servers
        .iter()
        .filter(|s| s.device == self_label && s.kind != "unregistered")
        .collect();

    let mut exposed_now = 0usize;
    let mut already_exposed = 0usize;
    let mut pruned = 0usize;
    let mut skipped_down = 0usize;

    if use_ts {
        if !ts.available || ts.bin.is_none() {
            if !use_direct {
                bail!(
                    "tailscale unavailable on this host (configure `[hopnet] bind_ips` for direct VPN/ZeroTier/LAN exposure, or start Tailscale)"
                );
            }
            println!("Note: tailscale unavailable; skipping tailscale transport.");
        } else if let Some(ts_bin) = ts.bin.as_deref() {
            for entry in &declared_local {
                if entry.up != Some(true) {
                    skipped_down += 1;
                    continue;
                }
                if entry.exposed {
                    already_exposed += 1;
                    continue;
                }
                let https_port = if entry.port == 80 || entry.port == 443 {
                    443
                } else {
                    entry.port
                };
                if dry_run {
                    let dns = ts.self_dns.as_deref().unwrap_or("<this-device>");
                    println!(
                        "Will expose `{}` on tailnet: https://{dns}:{https_port} -> {}://{}:{}",
                        entry.id, entry.scheme, entry.host, entry.port
                    );
                    exposed_now += 1;
                } else {
                    match expose_tailscale_route(
                        ts_bin,
                        &ts,
                        &entry.id,
                        &entry.scheme,
                        &entry.host,
                        entry.port,
                        entry.path.as_deref(),
                        Some(https_port),
                        allow_untrusted,
                    ) {
                        Ok(url) => {
                            println!("Exposed `{}` (tailnet): {url}", entry.id);
                            exposed_now += 1;
                        }
                        Err(err) => {
                            eprintln!("Skipped `{}`: {err}", entry.id);
                        }
                    }
                }
            }

            if !no_prune && cfg.hopnet.auto_prune {
                for route in &ts.routes {
                    let alive = measure_tcp_rtt(
                        &route.upstream_host,
                        route.upstream_port,
                        Duration::from_millis(60),
                    )
                    .is_some();
                    if !alive {
                        if dry_run {
                            println!(
                                "Will prune dead route {} -> {}",
                                route.exposed_url, route.upstream_raw
                            );
                        } else {
                            stop_tailscale_route(ts_bin, route)?;
                            println!(
                                "Pruned dead route {} -> {}",
                                route.exposed_url, route.upstream_raw
                            );
                        }
                        pruned += 1;
                    }
                }
            }
        }
    }

    if use_direct {
        println!(
            "Direct VPN/ZeroTier/LAN bind_ips configured ({}). Run `hop serve watch` (or `hop serve daemon install`) to keep allowlisted direct listeners running.",
            cfg.hopnet.bind_ips.join(", ")
        );
    }

    println!(
        "hopnet sync: {exposed_now} exposed, {already_exposed} already up, {pruned} pruned, {skipped_down} stopped."
    );
    Ok(())
}

struct ActiveDirectListener {
    stop: Arc<AtomicBool>,
    record: DirectRouteRecord,
}

#[derive(Debug, Clone)]
struct IngressTarget {
    server_id: String,
    upstream_host: String,
    upstream_port: u16,
    scheme: String,
    rewrite_host: bool,
}

/// One-shot heartbeat (and optional snapshot) push to `[hopnet] push_url`.
pub fn cmd_serve_push(cfg: &HopConfig, dry_run: bool, with_snapshot: bool) -> Result<()> {
    let push_url = cfg
        .hopnet
        .push_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .context("no `[hopnet] push_url` configured in devices.toml")?;
    let token = cfg.hopnet.resolve_push_token().context(
        "no heartbeat push token found (set `[hopnet] push_token_env` or `push_token_file`)",
    )?;
    let (report, ts) = build_local_report(cfg)?;
    let ingress_active = !load_live_ingress_routes().is_empty();
    let payload = build_heartbeat_payload(cfg, &report, &ts, ingress_active);

    if dry_run {
        println!("Would POST heartbeat to {push_url}:");
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        let code = post_json_bearer(push_url, &token, &payload)?;
        println!(
            "Pushed heartbeat for `{}` -> {push_url} (HTTP {code})",
            report.device
        );
    }

    if with_snapshot {
        push_snapshot_once(cfg, &token, dry_run)?;
    }
    Ok(())
}

/// Continuous hopnet reconciler: auto-exposes running declared servers across Tailscale, Cloudflare ingress, and/or direct allowlisted VPN/ZeroTier/LAN IPs, plus optional heartbeat push.
pub fn cmd_serve_watch(
    cfg: &HopConfig,
    interval_override: Option<u64>,
    bind_overrides: &[String],
    allow_untrusted: bool,
) -> Result<()> {
    let poll_secs = interval_override
        .unwrap_or_else(|| cfg.hopnet.effective_poll_secs())
        .clamp(2, 60);

    let mut bind_ips: Vec<IpAddr> = Vec::new();
    let raw_binds = if !bind_overrides.is_empty() {
        bind_overrides
    } else {
        &cfg.hopnet.bind_ips
    };
    for raw in raw_binds {
        let ip: IpAddr = raw
            .trim()
            .parse()
            .with_context(|| format!("invalid bind IP `{raw}`"))?;
        if ip.is_unspecified() {
            bail!(
                "refusing to bind unspecified address `{raw}`; specify a concrete VPN, ZeroTier, WireGuard, or LAN interface IP"
            );
        }
        bind_ips.push(ip.to_canonical());
    }

    let use_ts = cfg.hopnet.uses_transport("tailscale");
    let use_direct = !bind_ips.is_empty();
    let use_cf_ingress =
        cfg.hopnet.uses_transport("cloudflare") && cfg.hopnet.ingress_port.is_some();
    let rewrite_host = cfg.hopnet.rewrite_host;
    let allowed_ips = Arc::new(RwLock::new(cfg.trusted_ips()));

    // Optional fail-closed loopback HTTP+WebSocket ingress router for cloudflared (`127.0.0.1:<ingress_port>`)
    let ingress_targets: Arc<RwLock<BTreeMap<String, IngressTarget>>> =
        Arc::new(RwLock::new(BTreeMap::new()));
    let mut ingress_active = false;
    if use_cf_ingress && let Some(ingress_port) = cfg.hopnet.ingress_port {
        match cfg.hopnet.resolve_ingress_secret() {
            Some(secret) => {
                match spawn_cloudflare_ingress(ingress_port, secret, Arc::clone(&ingress_targets)) {
                    Ok(()) => {
                        ingress_active = true;
                        println!(
                            "[hopnet watch] cloudflare ingress listening on 127.0.0.1:{ingress_port} (fail-closed)"
                        );
                    }
                    Err(err) => {
                        eprintln!(
                            "[hopnet watch] failed starting cloudflare ingress on 127.0.0.1:{ingress_port}: {err}"
                        );
                    }
                }
            }
            None => {
                eprintln!(
                    "[hopnet watch] cloudflare ingress disabled (fail-closed): configure `ingress_secret_env` or `ingress_secret_file`"
                );
            }
        }
    }

    println!(
        "[hopnet watch] device={} poll={}s tailscale={} cloudflare_ingress={} direct_binds={} push={}",
        cfg.self_label(),
        poll_secs,
        use_ts,
        ingress_active,
        if bind_ips.is_empty() {
            "none".to_string()
        } else {
            bind_ips
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        },
        cfg.hopnet.push_url.as_deref().unwrap_or("off")
    );

    let mut active_direct: BTreeMap<(IpAddr, u16), ActiveDirectListener> = BTreeMap::new();
    let mut active_ts_shims: BTreeMap<u16, ActiveDirectListener> = BTreeMap::new();
    let push_interval = Duration::from_secs(cfg.hopnet.effective_push_interval_secs());
    let snap_interval = Duration::from_secs(cfg.hopnet.effective_snapshot_interval_secs());
    let mut last_push: Option<Instant> = None;
    let mut last_snap: Option<Instant> = None;
    let mut last_sig = String::new();

    loop {
        if let Ok((mut report, ts)) = build_local_report(cfg) {
            // Refresh live trusted IP allowlist (configured IPs + trusted Tailscale peers)
            let mut next_allowed = cfg.trusted_ips();
            for peer in &ts.peers {
                if peer.trusted {
                    for raw_ip in &peer.ips {
                        if let Ok(ip) = raw_ip.parse::<IpAddr>() {
                            next_allowed.insert(ip.to_canonical());
                        }
                    }
                }
            }
            for sip in &ts.self_ips {
                next_allowed.insert(sip.to_canonical());
            }
            if let Ok(mut guard) = allowed_ips.write() {
                *guard = next_allowed.clone();
            }

            let self_label = cfg.self_label();
            let running_declared: Vec<ServerEntry> = report
                .servers
                .iter()
                .filter(|s| {
                    s.device == self_label && s.kind != "unregistered" && s.up == Some(true)
                })
                .cloned()
                .collect();

            // 1. Reconcile Tailscale transport (with loopback Host-rewrite shim for HTTP dev servers)
            if use_ts
                && ts.available
                && let Some(ts_bin) = ts.bin.as_deref()
            {
                let mut desired_shim_ports: BTreeSet<u16> = BTreeSet::new();
                for entry in &running_declared {
                    let https_port = if entry.port == 80 || entry.port == 443 {
                        443
                    } else {
                        entry.port
                    };
                    let port_audit = evaluate_access_audit(&ts, &[https_port]);
                    if !port_audit.untrusted_peers.is_empty() && !allow_untrusted {
                        continue;
                    }

                    // For HTTP servers when rewrite_host is enabled, proxy through a loopback shim so Vite/Next/SvelteKit
                    // receive `Host: 127.0.0.1:<port>` instead of rejecting `*.ts.net`.
                    let mut target_port = entry.port;
                    if rewrite_host
                        && entry.scheme == "http"
                        && let Some(shim_port) = tailscale_shim_port(entry.port)
                    {
                        desired_shim_ports.insert(entry.port);
                        if let std::collections::btree_map::Entry::Vacant(vac) =
                            active_ts_shims.entry(entry.port)
                        {
                            let stop = Arc::new(AtomicBool::new(false));
                            let loopback_only = Arc::new(RwLock::new(BTreeSet::new()));
                            if spawn_direct_proxy(
                                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                                shim_port,
                                entry.host.clone(),
                                entry.port,
                                entry.scheme.clone(),
                                true,
                                true,
                                loopback_only,
                                Arc::clone(&stop),
                            )
                            .is_ok()
                            {
                                let record = DirectRouteRecord {
                                    server_id: entry.id.clone(),
                                    bind_ip: "127.0.0.1".to_string(),
                                    bind_port: shim_port,
                                    upstream_host: entry.host.clone(),
                                    upstream_port: entry.port,
                                    scheme: entry.scheme.clone(),
                                    url: format!("http://127.0.0.1:{shim_port}"),
                                    trusted_ip_count: 1,
                                };
                                vac.insert(ActiveDirectListener { stop, record });
                                println!(
                                    "[hopnet watch] started tailnet Host-rewrite shim 127.0.0.1:{shim_port} -> {}:{} ({})",
                                    entry.host, entry.port, entry.id
                                );
                            }
                        }
                        if active_ts_shims.contains_key(&entry.port) {
                            target_port = shim_port;
                        }
                    }

                    let already_wired = ts.routes.iter().any(|r| {
                        !r.is_tcp_forward
                            && r.https_port == https_port
                            && r.upstream_port == target_port
                    });
                    if already_wired {
                        continue;
                    }
                    if let Ok(url) = expose_tailscale_route(
                        ts_bin,
                        &ts,
                        &entry.id,
                        &entry.scheme,
                        if target_port == entry.port {
                            &entry.host
                        } else {
                            "127.0.0.1"
                        },
                        target_port,
                        entry.path.as_deref(),
                        Some(https_port),
                        allow_untrusted,
                    ) {
                        println!(
                            "[hopnet watch] exposed `{}` (tailnet -> 127.0.0.1:{target_port}): {url}",
                            entry.id
                        );
                    }
                }
                // Stop loopback shims for servers that are no longer running
                let stale_shims: Vec<u16> = active_ts_shims
                    .keys()
                    .copied()
                    .filter(|p| !desired_shim_ports.contains(p))
                    .collect();
                for p in stale_shims {
                    if let Some(old) = active_ts_shims.remove(&p) {
                        old.stop.store(true, Ordering::Relaxed);
                    }
                }
                if cfg.hopnet.auto_prune {
                    for route in &ts.routes {
                        let alive = measure_tcp_rtt(
                            &route.upstream_host,
                            route.upstream_port,
                            Duration::from_millis(60),
                        )
                        .is_some();
                        if !alive && stop_tailscale_route(ts_bin, route).is_ok() {
                            println!(
                                "[hopnet watch] pruned dead tailnet route {}",
                                route.exposed_url
                            );
                        }
                    }
                }
            }

            // 2. Reconcile Cloudflare loopback ingress target table
            if ingress_active && let Some(ingress_port) = cfg.hopnet.ingress_port {
                let mut next_map: BTreeMap<String, IngressTarget> = BTreeMap::new();
                let mut records: Vec<IngressRouteRecord> = Vec::new();
                for entry in &running_declared {
                    let slug = entry
                        .slug
                        .clone()
                        .unwrap_or_else(|| crate::config::slugify_label(&entry.name));
                    let target = IngressTarget {
                        server_id: entry.id.clone(),
                        upstream_host: entry.host.clone(),
                        upstream_port: entry.port,
                        scheme: entry.scheme.clone(),
                        rewrite_host,
                    };
                    next_map.insert(slug.clone(), target.clone());
                    next_map.insert(entry.id.to_ascii_lowercase(), target.clone());
                    let dev_prefixed =
                        crate::config::slugify_label(&format!("{self_label}-{slug}"));
                    next_map.entry(dev_prefixed).or_insert(target);

                    records.push(IngressRouteRecord {
                        server_id: entry.id.clone(),
                        slug,
                        upstream_host: entry.host.clone(),
                        upstream_port: entry.port,
                        scheme: entry.scheme.clone(),
                        public_url: entry.public_url.clone(),
                    });
                }
                if let Ok(mut guard) = ingress_targets.write() {
                    *guard = next_map;
                }
                let _ = save_ingress_routes(ingress_port, &records);
                // Mark exposed in current report snapshot for heartbeat push
                for s in &mut report.servers {
                    if s.device == self_label && s.kind != "unregistered" && s.up == Some(true) {
                        s.exposed = true;
                    }
                }
            }

            // 3. Reconcile Direct allowlisted VPN/ZeroTier/LAN listeners
            if use_direct {
                let self_ips_canon: BTreeSet<IpAddr> =
                    ts.self_ips.iter().map(|ip| ip.to_canonical()).collect();
                let non_loopback_trusted = next_allowed
                    .iter()
                    .filter(|ip| {
                        !ip.is_loopback() && !bind_ips.contains(ip) && !self_ips_canon.contains(ip)
                    })
                    .count();
                let mut desired: BTreeMap<(IpAddr, u16), &ServerEntry> = BTreeMap::new();
                if non_loopback_trusted > 0 || allow_untrusted {
                    for entry in &running_declared {
                        for &bip in &bind_ips {
                            desired.insert((bip, entry.port), entry);
                        }
                    }
                } else {
                    eprintln!(
                        "[hopnet watch] direct proxy paused (fail-closed): no trusted non-loopback peer IPs found in devices.toml / trusted_peers (or pass --allow-untrusted)."
                    );
                }

                // Tear down listeners whose servers stopped
                let to_stop: Vec<(IpAddr, u16)> = active_direct
                    .keys()
                    .copied()
                    .filter(|k| !desired.contains_key(k))
                    .collect();
                for key in to_stop {
                    if let Some(old) = active_direct.remove(&key) {
                        old.stop.store(true, Ordering::Relaxed);
                        println!(
                            "[hopnet watch] stopped direct allowlist route {} ({})",
                            old.record.url, old.record.server_id
                        );
                    }
                }

                // Start listeners for newly running servers
                for ((bip, port), entry) in desired {
                    if active_direct.contains_key(&(bip, port)) {
                        continue;
                    }
                    let stop = Arc::new(AtomicBool::new(false));
                    match spawn_direct_proxy(
                        bip,
                        port,
                        entry.host.clone(),
                        entry.port,
                        entry.scheme.clone(),
                        rewrite_host,
                        allow_untrusted,
                        Arc::clone(&allowed_ips),
                        Arc::clone(&stop),
                    ) {
                        Ok(()) => {
                            let url =
                                format_direct_url(&entry.scheme, bip, port, entry.path.as_deref());
                            println!(
                                "[hopnet watch] exposed `{}` (direct allowlist, {} trusted IPs): {url}",
                                entry.id,
                                next_allowed.len()
                            );
                            let record = DirectRouteRecord {
                                server_id: entry.id.clone(),
                                bind_ip: bip.to_string(),
                                bind_port: port,
                                upstream_host: entry.host.clone(),
                                upstream_port: entry.port,
                                scheme: entry.scheme.clone(),
                                url,
                                trusted_ip_count: next_allowed.len(),
                            };
                            active_direct
                                .insert((bip, port), ActiveDirectListener { stop, record });
                        }
                        Err(err) => {
                            eprintln!(
                                "[hopnet watch] failed binding direct proxy {bip}:{port} for `{}`: {err}",
                                entry.id
                            );
                        }
                    }
                }

                let records: Vec<DirectRouteRecord> =
                    active_direct.values().map(|v| v.record.clone()).collect();
                let _ = save_direct_routes(&records);
            }

            // 4. Optional Heartbeat & Snapshot push to remote hub (e.g. Cloudflare Worker dashboard)
            if let Some(push_url) = cfg
                .hopnet
                .push_url
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                && let Some(token) = cfg.hopnet.resolve_push_token()
            {
                let sig = heartbeat_signature(&report, &ts);
                let due = last_push.is_none_or(|t| t.elapsed() >= push_interval);
                if due || sig != last_sig {
                    let payload = build_heartbeat_payload(cfg, &report, &ts, ingress_active);
                    match post_json_bearer(push_url, &token, &payload) {
                        Ok(code) if (200..300).contains(&code) => {
                            last_sig = sig;
                            last_push = Some(Instant::now());
                        }
                        Ok(code) => {
                            eprintln!("[hopnet watch] heartbeat push HTTP {code} ({push_url})");
                            last_push = Some(Instant::now());
                        }
                        Err(err) => {
                            eprintln!("[hopnet watch] heartbeat push error: {err}");
                            last_push = Some(Instant::now());
                        }
                    }
                }

                let snap_due = last_snap.is_none_or(|t| t.elapsed() >= snap_interval);
                if snap_due
                    && cfg.hopnet.snapshot_url.is_some()
                    && cfg.hopnet.snapshot_cmd.is_some()
                {
                    if let Err(err) = push_snapshot_once(cfg, &token, false) {
                        eprintln!("[hopnet watch] snapshot push error: {err}");
                    }
                    last_snap = Some(Instant::now());
                }
            }
        }

        thread::sleep(Duration::from_secs(poll_secs));
    }
}

fn heartbeat_signature(report: &ServeReport, ts: &TailscaleSnapshot) -> String {
    let mut parts: Vec<String> = report
        .servers
        .iter()
        .map(|s| {
            format!(
                "{}:{}:{:?}:{:?}:{:?}",
                s.id, s.port, s.up, s.slug, s.exposed_url
            )
        })
        .collect();
    let mut peer_parts: Vec<String> = ts
        .peers
        .iter()
        .map(|p| {
            format!(
                "ts:{}:{}",
                p.dns_name.as_deref().unwrap_or(&p.name),
                p.online
            )
        })
        .collect();
    peer_parts.sort();
    parts.extend(peer_parts);
    if let Ok(st) = serde_json::to_string(&report.status) {
        parts.push(st);
    }
    parts.join("|")
}

fn build_heartbeat_payload(
    cfg: &HopConfig,
    report: &ServeReport,
    ts: &TailscaleSnapshot,
    ingress_active: bool,
) -> serde_json::Value {
    let self_label = cfg.self_label();
    let graph = load_graph_cache();

    let mut devices_json = Vec::new();
    for (alias, dev) in &cfg.devices {
        let best = if alias == &self_label {
            None
        } else {
            graph.as_ref().and_then(|g| {
                ranked_acyclic_routes(g, &g.self_node, alias, cfg.effective_max_hops())
                    .into_iter()
                    .next()
            })
        };
        let is_trusted = dev.trusted.unwrap_or(false) || alias == &self_label;
        let is_relay = dev.relay.unwrap_or(false);
        let transports: Vec<&str> = dev
            .hosts
            .iter()
            .map(|h| classify_host_transport(h))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let ts_peer_online = if ts.available {
            dev.hosts.iter().find_map(|h| {
                let norm = h.trim_end_matches('.').to_ascii_lowercase();
                ts.peers.iter().find_map(|p| {
                    let pdns = p
                        .dns_name
                        .as_deref()
                        .map(|d| d.trim_end_matches('.').to_ascii_lowercase());
                    if pdns.as_deref() == Some(norm.as_str()) {
                        Some(p.online)
                    } else {
                        None
                    }
                })
            })
        } else {
            None
        };
        let is_reachable = if alias == &self_label {
            true
        } else if let Some(online) = ts_peer_online {
            online
        } else {
            best.is_some()
        };
        devices_json.push(serde_json::json!({
            "alias": alias,
            "is_self": alias == &self_label,
            "trusted": is_trusted,
            "relay": is_relay,
            "hosts": dev.hosts,
            "transports": transports,
            "description": dev.description,
            "wol_via": dev.wol_via,
            "best_rtt_ms": if alias == &self_label { Some(0.0) } else if is_reachable { best.as_ref().map(|r| r.total_rtt_ms) } else { None },
            "best_path": if alias == &self_label { Some("local".to_string()) } else if is_reachable { best.as_ref().map(|r| r.compact_path()) } else { None },
            "reachable": is_reachable,
        }));
    }

    let edges: Vec<serde_json::Value> = graph
        .as_ref()
        .map(|g| {
            g.edges
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "from": e.from,
                        "to": e.to,
                        "host": e.host,
                        "transport": classify_host_transport(&e.host),
                        "rtt_ms": e.rtt_ms,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let tailscale_peers: Vec<serde_json::Value> = ts
        .peers
        .iter()
        .map(|p| {
            serde_json::json!({
                "name": p.name,
                "dns_name": p.dns_name,
                "os": p.os,
                "online": p.online,
                "trusted": p.trusted,
            })
        })
        .collect();

    serde_json::json!({
        "schema": "hop.heartbeat/v1",
        "device": self_label,
        "sent_unix": now_unix(),
        "tailscale_available": ts.available,
        "tailscale_dns": ts.self_dns,
        "origin_host": cfg.hopnet.origin_host,
        "public_domain": cfg.hopnet.public_domain,
        "ingress_active": ingress_active,
        "transports": cfg.hopnet.effective_transports(),
        "trusted_peers": cfg.trusted_peers,
        "tailscale_peers": tailscale_peers,
        "status": report.status,
        "devices": devices_json,
        "edges": edges,
        "servers": report.servers,
    })
}

fn post_json_bearer(url: &str, token: &str, payload: &serde_json::Value) -> Result<u16> {
    let body = serde_json::to_vec(payload)?;
    post_raw_json_bearer(url, token, &body)
}

fn post_raw_json_bearer(url: &str, token: &str, body: &[u8]) -> Result<u16> {
    let mut child = Command::new("curl")
        .args([
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            "8",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-H",
            &format!("Authorization: Bearer {token}"),
            "--data-binary",
            "@-",
            url,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed spawning curl for hop heartbeat push")?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(body)?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        bail!("curl push failed ({}): {stderr}", out.status);
    }
    let code: u16 = String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .unwrap_or(0);
    Ok(code)
}

fn push_snapshot_once(cfg: &HopConfig, token: &str, dry_run: bool) -> Result<()> {
    let Some(snap_url) = cfg
        .hopnet
        .snapshot_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Ok(());
    };
    let Some(snap_cmd) = cfg
        .hopnet
        .snapshot_cmd
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Ok(());
    };
    let argv = split_command_line(snap_cmd);
    let Some((bin, args)) = argv.split_first() else {
        return Ok(());
    };
    let out = Command::new(bin)
        .args(args)
        .env("PATH", augmented_path())
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("failed running snapshot_cmd `{snap_cmd}`"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        bail!("snapshot_cmd exited {}: {stderr}", out.status);
    }
    // Validate JSON before pushing
    let _: serde_json::Value =
        serde_json::from_slice(&out.stdout).context("snapshot_cmd emitted invalid JSON")?;
    if dry_run {
        println!(
            "Would POST snapshot ({} bytes) -> {snap_url}",
            out.stdout.len()
        );
        return Ok(());
    }
    let code = post_raw_json_bearer(snap_url, token, &out.stdout)?;
    println!(
        "Pushed snapshot ({} bytes) -> {snap_url} (HTTP {code})",
        out.stdout.len()
    );
    Ok(())
}

fn spawn_cloudflare_ingress(
    ingress_port: u16,
    secret: String,
    targets: Arc<RwLock<BTreeMap<String, IngressTarget>>>,
) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", ingress_port))
        .with_context(|| format!("could not bind 127.0.0.1:{ingress_port}"))?;
    let secret = Arc::new(secret);

    thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(client) = incoming else {
                thread::sleep(Duration::from_millis(50));
                continue;
            };
            let secret_c = Arc::clone(&secret);
            let targets_c = Arc::clone(&targets);
            thread::spawn(move || {
                let _ = handle_ingress_connection(client, &secret_c, &targets_c);
            });
        }
    });
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn write_http_error(stream: &mut TcpStream, status: &str, msg: &str) {
    let body = format!("{msg}\n");
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes());
}

fn handle_ingress_connection(
    mut client: TcpStream,
    expected_secret: &str,
    targets: &Arc<RwLock<BTreeMap<String, IngressTarget>>>,
) -> Result<()> {
    let _ = client.set_nodelay(true);
    let _ = client.set_read_timeout(Some(Duration::from_secs(5)));

    let mut head = Vec::with_capacity(4096);
    let mut buf = [0u8; 4096];
    let mut end_idx: Option<usize> = None;
    while head.len() < 32_768 {
        match client.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                head.extend_from_slice(&buf[..n]);
                if let Some(pos) = head.windows(4).position(|w| w == b"\r\n\r\n") {
                    end_idx = Some(pos);
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = client.set_read_timeout(None);

    let Some(hdr_end) = end_idx else {
        write_http_error(&mut client, "400 Bad Request", "Invalid HTTP request");
        return Ok(());
    };
    let Ok(headers_str) = std::str::from_utf8(&head[..hdr_end]) else {
        write_http_error(&mut client, "400 Bad Request", "Non-UTF8 HTTP headers");
        return Ok(());
    };

    let mut provided_secret: Option<&str> = None;
    let mut target_slug: Option<String> = None;
    let mut fwd_host: Option<&str> = None;
    let mut raw_host: Option<&str> = None;
    let mut is_websocket = false;

    for (idx, line) in headers_str.split("\r\n").enumerate() {
        if idx == 0 {
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let kl = k.trim().to_ascii_lowercase();
        let val = v.trim();
        match kl.as_str() {
            "x-hop-ingress-secret" => provided_secret = Some(val),
            "x-hop-target-slug" => target_slug = Some(val.to_ascii_lowercase()),
            "x-forwarded-host" => fwd_host = Some(val),
            "host" => raw_host = Some(val),
            "upgrade" if val.eq_ignore_ascii_case("websocket") => is_websocket = true,
            _ => {}
        }
    }

    // Fail-closed secret check
    let secret_ok =
        provided_secret.is_some_and(|s| constant_time_eq(s.as_bytes(), expected_secret.as_bytes()));
    if !secret_ok {
        write_http_error(&mut client, "403 Forbidden", "Forbidden");
        return Ok(());
    }

    // Resolve target slug from explicit header or subdomain prefix
    let slug = target_slug.or_else(|| {
        let host = fwd_host.or(raw_host)?;
        let no_port = host.split(':').next().unwrap_or(host);
        let first = no_port.split('.').next()?.trim();
        (!first.is_empty()).then(|| first.to_ascii_lowercase())
    });

    let Some(slug) = slug else {
        write_http_error(&mut client, "400 Bad Request", "Missing hop target slug");
        return Ok(());
    };

    if slug == "__hop_health__" {
        let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nX-Hop-Ingress: alive\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
        let _ = client.write_all(resp.as_bytes());
        return Ok(());
    }

    let target = targets.read().ok().and_then(|map| map.get(&slug).cloned());
    let Some(target) = target else {
        write_http_error(
            &mut client,
            "502 Bad Gateway",
            &format!("hopnet server `{slug}` is not active on this device"),
        );
        return Ok(());
    };

    if target.scheme != "http" {
        write_http_error(
            &mut client,
            "502 Bad Gateway",
            &format!(
                "hopnet ingress currently supports http/ws upstreams (`{}` uses `{}`)",
                target.server_id, target.scheme
            ),
        );
        return Ok(());
    }

    let mut upstream =
        match TcpStream::connect((target.upstream_host.as_str(), target.upstream_port)) {
            Ok(s) => s,
            Err(_) => {
                write_http_error(
                    &mut client,
                    "502 Bad Gateway",
                    &format!(
                        "upstream `{}` ({}:{}) refused connection",
                        target.server_id, target.upstream_host, target.upstream_port
                    ),
                );
                return Ok(());
            }
        };
    let _ = upstream.set_nodelay(true);

    // Rebuild headers: strip internal hop headers, rewrite Host if enabled, and force Connection: close on non-WS requests
    // so cloudflared never reuses one TCP socket across different subdomain targets.
    let mut rebuilt = String::with_capacity(hdr_end + 64);
    let mut saw_connection = false;
    for (idx, line) in headers_str.split("\r\n").enumerate() {
        if idx == 0 {
            rebuilt.push_str(line);
            continue;
        }
        let Some((k, _)) = line.split_once(':') else {
            continue;
        };
        let kl = k.trim().to_ascii_lowercase();
        if kl == "x-hop-ingress-secret" || kl == "x-hop-target-slug" {
            continue;
        }
        if kl == "host" && target.rewrite_host {
            rebuilt.push_str(&format!(
                "\r\nHost: {}:{}",
                target.upstream_host, target.upstream_port
            ));
            continue;
        }
        if kl == "connection" && !is_websocket {
            rebuilt.push_str("\r\nConnection: close");
            saw_connection = true;
            continue;
        }
        rebuilt.push_str("\r\n");
        rebuilt.push_str(line);
    }
    if !is_websocket && !saw_connection {
        rebuilt.push_str("\r\nConnection: close");
    }

    let mut out_head = rebuilt.into_bytes();
    out_head.extend_from_slice(&head[hdr_end..]);
    upstream.write_all(&out_head)?;

    let mut c_read = client.try_clone()?;
    let mut u_write = upstream.try_clone()?;
    let t1 = thread::spawn(move || {
        let _ = std::io::copy(&mut c_read, &mut u_write);
        let _ = u_write.shutdown(std::net::Shutdown::Write);
    });
    let _ = std::io::copy(&mut upstream, &mut client);
    let _ = client.shutdown(std::net::Shutdown::Write);
    if is_websocket {
        let _ = t1.join();
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn spawn_direct_proxy(
    bind_ip: IpAddr,
    bind_port: u16,
    upstream_host: String,
    upstream_port: u16,
    scheme: String,
    rewrite_host: bool,
    allow_untrusted: bool,
    allowed_ips: Arc<RwLock<BTreeSet<IpAddr>>>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    let listener = TcpListener::bind(SocketAddr::new(bind_ip, bind_port))
        .with_context(|| format!("could not bind {bind_ip}:{bind_port}"))?;
    listener.set_nonblocking(true)?;

    thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((client, peer_addr)) => {
                    let peer_ip = peer_addr.ip().to_canonical();
                    let permitted = allow_untrusted
                        || allowed_ips
                            .read()
                            .map(|set| set.contains(&peer_ip))
                            .unwrap_or(false);
                    if !permitted {
                        drop(client);
                        continue;
                    }
                    let u_host = upstream_host.clone();
                    let u_scheme = scheme.clone();
                    thread::spawn(move || {
                        let _ = proxy_connection(
                            client,
                            &u_host,
                            upstream_port,
                            u_scheme == "http" && rewrite_host,
                        );
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(_) => {
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
    });
    Ok(())
}

fn proxy_connection(
    mut client: TcpStream,
    upstream_host: &str,
    upstream_port: u16,
    rewrite_http_host: bool,
) -> Result<()> {
    client.set_nonblocking(false)?;
    let _ = client.set_nodelay(true);
    let mut upstream = TcpStream::connect((upstream_host, upstream_port))?;
    let _ = upstream.set_nodelay(true);

    if rewrite_http_host {
        let _ = client.set_read_timeout(Some(Duration::from_secs(2)));
        let mut head = Vec::with_capacity(2048);
        let mut buf = [0u8; 2048];
        while head.len() < 16_384 {
            match client.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    head.extend_from_slice(&buf[..n]);
                    if head.windows(4).any(|w| w == b"\r\n\r\n") || !looks_like_http(&head) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = client.set_read_timeout(None);
        if !head.is_empty() {
            let rewritten = rewrite_http_host_header(&head, upstream_host, upstream_port);
            upstream.write_all(&rewritten)?;
        }
    }

    let mut c_read = client.try_clone()?;
    let mut u_write = upstream.try_clone()?;
    let t1 = thread::spawn(move || {
        let _ = std::io::copy(&mut c_read, &mut u_write);
        let _ = u_write.shutdown(std::net::Shutdown::Write);
    });
    let _ = std::io::copy(&mut upstream, &mut client);
    let _ = client.shutdown(std::net::Shutdown::Write);
    let _ = t1.join();
    Ok(())
}

fn looks_like_http(buf: &[u8]) -> bool {
    const METHODS: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"PUT ",
        b"PATCH ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
    ];
    METHODS.iter().any(|m| {
        let n = buf.len().min(m.len());
        buf[..n] == m[..n]
    })
}

fn rewrite_http_host_header(raw: &[u8], upstream_host: &str, upstream_port: u16) -> Vec<u8> {
    let Some(end_idx) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return raw.to_vec();
    };
    let Ok(headers_str) = std::str::from_utf8(&raw[..end_idx]) else {
        return raw.to_vec();
    };
    let is_ws = headers_str.split("\r\n").skip(1).any(|line| {
        line.split_once(':').is_some_and(|(k, v)| {
            k.trim().eq_ignore_ascii_case("upgrade") && v.trim().eq_ignore_ascii_case("websocket")
        })
    });
    let mut rebuilt = String::with_capacity(end_idx + 64);
    let mut first = true;
    let mut saw_connection = false;
    for line in headers_str.split("\r\n") {
        if !first {
            rebuilt.push_str("\r\n");
        }
        first = false;
        if line.len() >= 5 && line[..5].eq_ignore_ascii_case("host:") {
            rebuilt.push_str(&format!("Host: {upstream_host}:{upstream_port}"));
        } else if !is_ws && line.len() >= 11 && line[..11].eq_ignore_ascii_case("connection:") {
            rebuilt.push_str("Connection: close");
            saw_connection = true;
        } else {
            rebuilt.push_str(line);
        }
    }
    if !is_ws && !saw_connection {
        rebuilt.push_str("\r\nConnection: close");
    }
    let mut out = rebuilt.into_bytes();
    out.extend_from_slice(&raw[end_idx..]);
    out
}

fn format_direct_url(scheme: &str, ip: IpAddr, port: u16, path: Option<&str>) -> String {
    let suffix = path.filter(|p| !p.is_empty() && *p != "/").unwrap_or("");
    let host_part = match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    };
    format!("{scheme}://{host_part}:{port}{suffix}")
}

/// Manage optional background `hop serve watch` user service (macOS LaunchAgent / Linux systemd --user).
pub fn cmd_serve_daemon(action: &str, dry_run: bool) -> Result<()> {
    if cfg!(target_os = "macos") {
        manage_macos_launchd(action, dry_run)
    } else if cfg!(target_os = "linux") {
        manage_linux_systemd(action, dry_run)
    } else {
        bail!(
            "background daemon installation is supported on macOS and Linux (run `hop serve watch` directly on this OS)"
        );
    }
}

fn resolve_hop_bin() -> Result<PathBuf> {
    if let Ok(exe) = env::current_exe()
        && exe.is_file()
    {
        return Ok(exe);
    }
    let home = dirs::home_dir().context("could not resolve home directory")?;
    Ok(home.join(".local").join("bin").join("hop"))
}

fn manage_macos_launchd(action: &str, dry_run: bool) -> Result<()> {
    let home = dirs::home_dir().context("could not resolve home directory")?;
    let plist_path = home
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{LAUNCHD_LABEL}.plist"));
    let log_path = cache_dir()?.join("serve-watch.log");
    let hop_bin = resolve_hop_bin()?;
    let uid = current_uid_string();

    match action {
        "status" => {
            println!("Service: {LAUNCHD_LABEL} (macOS LaunchAgent)");
            println!(
                "Plist:   {} ({})",
                plist_path.display(),
                if plist_path.is_file() {
                    "installed"
                } else {
                    "not installed"
                }
            );
            let out = Command::new("launchctl")
                .args(["print", &format!("gui/{uid}/{LAUNCHD_LABEL}")])
                .stdin(Stdio::null())
                .output();
            match out {
                Ok(o) if o.status.success() => println!("State:   loaded"),
                _ => println!("State:   not loaded"),
            }
            let direct = load_live_direct_routes();
            let ingress = load_live_ingress_routes();
            println!("Direct allowlist routes active: {}", direct.len());
            println!("Cloudflare ingress routes active: {}", ingress.len());
            Ok(())
        }
        "install" => {
            let plist = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{}</string>
    <string>serve</string>
    <string>watch</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>{}/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{}</string>
  <key>StandardErrorPath</key>
  <string>{}</string>
</dict>
</plist>
"#,
                hop_bin.display(),
                home.display(),
                log_path.display(),
                log_path.display()
            );
            if dry_run {
                println!(
                    "Will write {} and load via launchctl:\n\n{plist}",
                    plist_path.display()
                );
                return Ok(());
            }
            ensure_parent(&plist_path)?;
            ensure_parent(&log_path)?;
            fs::write(&plist_path, plist)?;
            let _ = Command::new("launchctl")
                .args(["bootout", &format!("gui/{uid}/{LAUNCHD_LABEL}")])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let status = Command::new("launchctl")
                .args([
                    "bootstrap",
                    &format!("gui/{uid}"),
                    &plist_path.display().to_string(),
                ])
                .stdin(Stdio::null())
                .status()
                .context("failed running launchctl bootstrap")?;
            if !status.success() {
                bail!("launchctl bootstrap failed ({status})");
            }
            println!(
                "Installed and started {LAUNCHD_LABEL} ({}); declared servers now auto-sync to your hopnet.",
                plist_path.display()
            );
            Ok(())
        }
        "uninstall" => {
            if dry_run {
                println!(
                    "Will unload {LAUNCHD_LABEL} and remove {}",
                    plist_path.display()
                );
                return Ok(());
            }
            let _ = Command::new("launchctl")
                .args(["bootout", &format!("gui/{uid}/{LAUNCHD_LABEL}")])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            if plist_path.is_file() {
                fs::remove_file(&plist_path)?;
            }
            println!("Uninstalled {LAUNCHD_LABEL}.");
            Ok(())
        }
        other => bail!("unknown daemon action `{other}` (use install, uninstall, or status)"),
    }
}

fn manage_linux_systemd(action: &str, dry_run: bool) -> Result<()> {
    let home = dirs::home_dir().context("could not resolve home directory")?;
    let unit_path = home
        .join(".config")
        .join("systemd")
        .join("user")
        .join(SYSTEMD_UNIT);
    let hop_bin = resolve_hop_bin()?;

    match action {
        "status" => {
            println!("Service: {SYSTEMD_UNIT} (systemd --user)");
            println!(
                "Unit:    {} ({})",
                unit_path.display(),
                if unit_path.is_file() {
                    "installed"
                } else {
                    "not installed"
                }
            );
            let out = Command::new("systemctl")
                .args(["--user", "is-active", SYSTEMD_UNIT])
                .stdin(Stdio::null())
                .output();
            let state = out
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "inactive".to_string());
            println!("State:   {state}");
            Ok(())
        }
        "install" => {
            let unit = format!(
                "[Unit]\nDescription=hopnet automatic dev-server sync and allowlisted proxy\nAfter=network-online.target\n\n[Service]\nExecStart={} serve watch\nRestart=on-failure\nRestartSec=5\nEnvironment=PATH={}/.local/bin:/usr/local/bin:/usr/bin:/bin\n\n[Install]\nWantedBy=default.target\n",
                hop_bin.display(),
                home.display()
            );
            if dry_run {
                println!(
                    "Will write {} and enable via systemctl --user:\n\n{unit}",
                    unit_path.display()
                );
                return Ok(());
            }
            ensure_parent(&unit_path)?;
            fs::write(&unit_path, unit)?;
            let _ = Command::new("systemctl")
                .args(["--user", "daemon-reload"])
                .status();
            let status = Command::new("systemctl")
                .args(["--user", "enable", "--now", SYSTEMD_UNIT])
                .status()
                .context("failed enabling systemd user service")?;
            if !status.success() {
                bail!("systemctl --user enable --now failed ({status})");
            }
            println!(
                "Installed and started {SYSTEMD_UNIT} ({}); declared servers now auto-sync to your hopnet.",
                unit_path.display()
            );
            Ok(())
        }
        "uninstall" => {
            if dry_run {
                println!(
                    "Will disable {SYSTEMD_UNIT} and remove {}",
                    unit_path.display()
                );
                return Ok(());
            }
            let _ = Command::new("systemctl")
                .args(["--user", "disable", "--now", SYSTEMD_UNIT])
                .status();
            if unit_path.is_file() {
                fs::remove_file(&unit_path)?;
            }
            let _ = Command::new("systemctl")
                .args(["--user", "daemon-reload"])
                .status();
            println!("Uninstalled {SYSTEMD_UNIT}.");
            Ok(())
        }
        other => bail!("unknown daemon action `{other}` (use install, uninstall, or status)"),
    }
}

fn current_uid_string() -> String {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "501".to_string())
}

fn pid_alive(pid: u32) -> bool {
    if cfg!(unix) {
        Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    } else {
        Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}")])
            .stdin(Stdio::null())
            .output()
            .is_ok_and(|o| {
                o.status.success() && String::from_utf8_lossy(&o.stdout).contains(&pid.to_string())
            })
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[allow(dead_code)]
fn _path_ref(_p: &Path) {}
