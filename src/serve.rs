use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::config::{
    EphemeralServerRecord, FleetServerSpec, HopConfig, load_ephemeral_servers, load_servers_config,
    save_ephemeral_servers, save_servers_config, servers_config_path, slugify_label,
};
use crate::connect::run_remote_capture;
use crate::graph::{load_graph_cache, measure_tcp_rtt, probe_device_hosts, ranked_acyclic_routes};
use crate::ui::{Align, Style, Table};

const LOCAL_PROBE_TIMEOUT: Duration = Duration::from_millis(60);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServeReport {
    pub schema: String,
    pub device: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tailscale_dns: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_domain: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub status: BTreeMap<String, serde_json::Value>,
    pub servers: Vec<ServerEntry>,
    pub access: AccessAudit,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetServeReport {
    pub schema: String,
    pub local: ServeReport,
    pub peers: Vec<PeerServeOutcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerServeOutcome {
    pub device: String,
    pub reachable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<ServeReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEntry {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    pub name: String,
    pub device: String,
    pub host: String,
    pub port: u16,
    #[serde(default = "default_scheme")]
    pub scheme: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub up: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_conflict: Option<String>,
    pub exposed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposed_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub direct_urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub https_port: Option<u16>,
    pub funnel_public: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_unix: Option<u64>,
    pub source: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccessAudit {
    pub tailscale_available: bool,
    pub packet_filter_verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_dns: Option<String>,
    pub trusted_peers: Vec<TailscalePeerInfo>,
    pub untrusted_peers: Vec<TailscalePeerInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_untrusted_peers: Vec<TailscalePeerInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public_funnel_routes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TailscalePeerInfo {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    pub online: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound_allowed: Option<bool>,
}

pub struct FleetServerAddOptions<'a> {
    pub name: &'a str,
    pub port: u16,
    pub device: Option<&'a str>,
    pub host: &'a str,
    pub scheme: &'a str,
    pub path: Option<&'a str>,
    pub description: Option<&'a str>,
}

pub struct ServeUpOptions<'a> {
    pub target: &'a str,
    pub https_port: Option<u16>,
    pub allow_untrusted: bool,
    pub name: Option<&'a str>,
    pub project: Option<&'a str>,
    pub description: Option<&'a str>,
    pub ttl: Option<&'a str>,
    pub local_only: bool,
}

#[derive(Debug, Deserialize)]
struct ExternalServerItem {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    project: Option<String>,
    name: String,
    #[serde(default)]
    host: Option<String>,
    port: u16,
    #[serde(default)]
    scheme: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    up: Option<bool>,
    #[serde(default)]
    port_conflict: Option<String>,
    #[serde(default)]
    cmd: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    source: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ActiveServeRoute {
    pub(crate) https_port: u16,
    pub(crate) is_tcp_forward: bool,
    pub(crate) mount_path: String,
    pub(crate) exposed_url: String,
    pub(crate) upstream_raw: String,
    pub(crate) upstream_host: String,
    pub(crate) upstream_port: u16,
    pub(crate) upstream_scheme: String,
    pub(crate) funnel_public: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct RawTailscalePeer {
    pub(crate) name: String,
    pub(crate) dns_name: Option<String>,
    pub(crate) ips: Vec<String>,
    pub(crate) os: Option<String>,
    pub(crate) online: bool,
    pub(crate) trusted: bool,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct TailscaleSnapshot {
    pub(crate) available: bool,
    pub(crate) bin: Option<PathBuf>,
    pub(crate) self_dns: Option<String>,
    pub(crate) self_ips: Vec<IpAddr>,
    pub(crate) routes: Vec<ActiveServeRoute>,
    pub(crate) peers: Vec<RawTailscalePeer>,
    packet_filter: Option<Vec<PacketFilterRule>>,
    pub(crate) warnings: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct TsServeStatus {
    #[serde(rename = "TCP", default)]
    tcp: BTreeMap<String, TsTcpEntry>,
    #[serde(rename = "Web", default)]
    web: BTreeMap<String, TsWebEntry>,
    #[serde(rename = "AllowFunnel", default)]
    allow_funnel: BTreeMap<String, bool>,
}

#[derive(Debug, Clone, Deserialize)]
struct TsTcpEntry {
    #[serde(rename = "TCPForward", default)]
    tcp_forward: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct TsWebEntry {
    #[serde(rename = "Handlers", default)]
    handlers: BTreeMap<String, TsWebHandler>,
}

#[derive(Debug, Clone, Deserialize)]
struct TsWebHandler {
    #[serde(rename = "Proxy", default)]
    proxy: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct TsStatus {
    #[serde(rename = "Self", default)]
    self_node: Option<TsNode>,
    #[serde(rename = "Peer", default)]
    peers: BTreeMap<String, TsNode>,
}

#[derive(Debug, Clone, Deserialize)]
struct TsNode {
    #[serde(rename = "DNSName", default)]
    dns_name: String,
    #[serde(rename = "HostName", default)]
    host_name: String,
    #[serde(rename = "TailscaleIPs", default)]
    tailscale_ips: Vec<String>,
    #[serde(rename = "Tags", default)]
    tags: Vec<String>,
    #[serde(rename = "ShareeNode", default)]
    sharee_node: bool,
    #[serde(rename = "OS", default)]
    os: Option<String>,
    #[serde(rename = "Online", default)]
    online: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct TsNetmap {
    #[serde(rename = "PacketFilter", default)]
    packet_filter: Option<Vec<PacketFilterRule>>,
}

#[derive(Debug, Clone, Deserialize)]
struct PacketFilterRule {
    #[serde(rename = "IPProto", default)]
    ip_proto: Vec<u8>,
    #[serde(rename = "Srcs", default)]
    srcs: Vec<String>,
    #[serde(rename = "Dsts", default)]
    dsts: Vec<PacketFilterDst>,
}

#[derive(Debug, Clone, Deserialize)]
struct PacketFilterDst {
    #[serde(rename = "Net", default)]
    net: String,
    #[serde(rename = "Ports", default)]
    ports: Option<PortRange>,
}

#[derive(Debug, Clone, Deserialize)]
struct PortRange {
    #[serde(rename = "First", default)]
    first: u16,
    #[serde(rename = "Last", default)]
    last: u16,
}

fn default_scheme() -> String {
    "http".to_string()
}

pub fn cmd_serve_ls(cfg: &HopConfig, fleet: bool, as_json: bool) -> Result<()> {
    let (local_report, _) = build_local_report(cfg)?;

    if !fleet {
        if as_json {
            println!("{}", serde_json::to_string_pretty(&local_report)?);
        } else {
            print_report(&local_report);
        }
        return Ok(());
    }

    let peers = collect_fleet_reports(cfg);

    let fleet_report = FleetServeReport {
        schema: "hop.serve.fleet/v1".to_string(),
        local: local_report,
        peers,
    };

    if as_json {
        println!("{}", serde_json::to_string_pretty(&fleet_report)?);
        return Ok(());
    }

    print_report(&fleet_report.local);
    for peer in &fleet_report.peers {
        println!();
        match &peer.report {
            Some(rep) => print_report(rep),
            None => {
                let status = if peer.reachable {
                    "connected, hop serve unavailable"
                } else {
                    "unreachable"
                };
                let detail = peer.error.as_deref().unwrap_or("");
                let st = Style::stdout();
                st.header(&format!("hop serve  {}", peer.device), Some(status));
                if !detail.is_empty() {
                    st.note(2, detail);
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn collect_fleet_reports(cfg: &HopConfig) -> Vec<PeerServeOutcome> {
    let self_label = cfg.self_label();
    let targets: Vec<String> = cfg
        .devices
        .iter()
        .filter(|(alias, dev)| alias.as_str() != self_label && dev.trusted.unwrap_or(false))
        .map(|(alias, _)| alias.clone())
        .collect();

    let mut handles = Vec::with_capacity(targets.len());
    let cached_graph = load_graph_cache();
    for alias in targets {
        let cfg_clone = cfg.clone();
        let has_cached_route = cached_graph.as_ref().is_some_and(|g| {
            !ranked_acyclic_routes(g, &g.self_node, &alias, cfg.effective_max_hops()).is_empty()
        });
        handles.push(thread::spawn(move || {
            let direct_ok = cfg_clone
                .devices
                .get(&alias)
                .is_some_and(|dev| !probe_device_hosts(dev, Duration::from_millis(650)).is_empty());
            if !direct_ok && !has_cached_route {
                return PeerServeOutcome {
                    device: alias,
                    reachable: false,
                    report: None,
                    error: Some("offline (no direct host reachable)".to_string()),
                };
            }
            let remote_cmd = vec![
                "sh -lc 'PATH=\"$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:$PATH\" hop serve --json'"
                    .to_string(),
            ];
            match run_remote_capture(&cfg_clone, &alias, &remote_cmd, !has_cached_route) {
                Ok(stdout) => match serde_json::from_str::<ServeReport>(&stdout) {
                    Ok(report) => PeerServeOutcome {
                        device: alias,
                        reachable: true,
                        report: Some(report),
                        error: None,
                    },
                    Err(err) => PeerServeOutcome {
                        device: alias,
                        reachable: true,
                        report: None,
                        error: Some(format!(
                            "remote `hop serve --json` output could not be parsed: {err}"
                        )),
                    },
                },
                Err(err) => {
                    let msg = err.to_string();
                    let connected_but_old = msg.contains("unrecognized subcommand 'serve'")
                        || msg.contains("command not found")
                        || msg.contains("hop: not found");
                    PeerServeOutcome {
                        device: alias.clone(),
                        reachable: connected_but_old,
                        report: None,
                        error: Some(if connected_but_old {
                            format!(
                                "connected via SSH, but remote `hop` needs upgrade (reinstall `hop` on {alias})"
                            )
                        } else {
                            msg
                        }),
                    }
                }
            }
        }));
    }

    let mut peers: Vec<PeerServeOutcome> =
        handles.into_iter().filter_map(|h| h.join().ok()).collect();
    peers.sort_by(|a, b| a.device.cmp(&b.device));
    peers
}

/// Deterministic loopback shim port used by `hop serve watch` to rewrite HTTP `Host` headers
/// before forwarding Tailscale Serve traffic to local dev servers (e.g. Vite/Next/SvelteKit).
pub(crate) fn tailscale_shim_port(upstream_port: u16) -> Option<u16> {
    (upstream_port > 0 && upstream_port < 45_000).then_some(20_000 + upstream_port)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn expose_tailscale_route(
    ts_bin: &std::path::Path,
    ts: &TailscaleSnapshot,
    label: &str,
    scheme: &str,
    host: &str,
    port: u16,
    path: Option<&str>,
    https_port_override: Option<u16>,
    allow_untrusted: bool,
) -> Result<String> {
    let https_port =
        https_port_override.unwrap_or(if port == 80 || port == 443 { 443 } else { port });
    if https_port == 0 {
        bail!("--https-port must be between 1 and 65535");
    }

    let upstream = format_tailscale_upstream(scheme, host, port);
    let mount_path = normalized_mount_path(path);

    if let Some(existing) = ts.routes.iter().find(|r| {
        let is_same_or_shim_upgrade = r.upstream_port == port
            || tailscale_shim_port(r.upstream_port) == Some(port)
            || tailscale_shim_port(port) == Some(r.upstream_port);
        !r.is_tcp_forward
            && r.https_port == https_port
            && r.mount_path == mount_path
            && !is_same_or_shim_upgrade
    }) {
        bail!(
            "HTTPS port {https_port} (path {mount_path}) is already serving {} ({}). Stop it with `hop serve down {https_port}` or pass `--https-port <other>`.",
            existing.upstream_raw,
            existing.exposed_url
        );
    }

    let port_audit = evaluate_access_audit(ts, &[https_port]);
    if !port_audit.untrusted_peers.is_empty() && !allow_untrusted {
        let names: Vec<String> = port_audit
            .untrusted_peers
            .iter()
            .map(|p| {
                if p.online {
                    format!("{} [online]", p.name)
                } else {
                    p.name.clone()
                }
            })
            .collect();
        bail!(
            "refusing to expose `{label}` on tailnet HTTPS port {https_port}: {} untrusted peer(s) can reach this host ({}).\n  Restrict inbound access in your Tailscale ACL policy, add personal devices to `trusted_peers` / `trusted = true` in devices.toml, or override explicitly with `--allow-untrusted`.",
            names.len(),
            names.join(", ")
        );
    }

    let mut cmd = Command::new(ts_bin);
    cmd.args(["serve", "--bg", &format!("--https={https_port}")]);
    if mount_path != "/" {
        cmd.args(["--set-path", &mount_path]);
    }
    cmd.arg(&upstream);
    cmd.stdin(Stdio::null());

    let output = cmd
        .output()
        .with_context(|| format!("failed spawning {}", ts_bin.display()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if !stderr.is_empty() { stderr } else { stdout };
        bail!("tailscale serve failed ({}): {detail}", output.status);
    }

    let dns = ts.self_dns.as_deref().unwrap_or("<this-device>");
    Ok(format_https_url(dns, https_port, &mount_path))
}

pub fn cmd_serve_up(cfg: &HopConfig, opts: ServeUpOptions<'_>) -> Result<()> {
    let (report, ts) = build_local_report(cfg)?;
    let self_label = cfg.self_label();
    let mut resolved = resolve_local_expose_target(&report.servers, &self_label, opts.target)?;

    if !resolved.up {
        let hint = resolved
            .cmd
            .as_deref()
            .map(|c| format!(" (start with `{c}`)"))
            .unwrap_or_default();
        bail!(
            "`{}` is not listening on {}:{}{hint}",
            resolved.label,
            resolved.host,
            resolved.port
        );
    }

    // If `--name` (or `--project`/`--desc`/`--ttl` on a numeric port) is supplied, register an ephemeral labeled server
    let mut registered_slug: Option<String> = None;
    if let Some(ephem_name) = opts.name {
        validate_server_name(ephem_name)?;
        let ttl_secs = match opts.ttl {
            Some(raw) => Some(parse_ttl_secs(raw)?),
            None => None,
        };
        let now = now_unix_secs();
        let slug = slugify_label(ephem_name);
        let pid = detect_local_listener_pid(resolved.port);
        let rec = EphemeralServerRecord {
            name: ephem_name.to_string(),
            slug: slug.clone(),
            project: opts.project.map(str::to_string),
            host: resolved.host.clone(),
            port: resolved.port,
            scheme: resolved.scheme.clone(),
            path: resolved.path.clone(),
            description: opts.description.map(str::to_string),
            pid,
            created_unix: now,
            expires_unix: ttl_secs.map(|s| now.saturating_add(s)),
        };
        let mut store = load_ephemeral_servers();
        store
            .servers
            .retain(|s| s.port != rec.port && !s.name.eq_ignore_ascii_case(&rec.name));
        store.servers.push(rec);
        save_ephemeral_servers(&store)?;
        resolved.label = match opts.project {
            Some(p) => format!("{p}:{ephem_name}"),
            None => format!("ephemeral:{ephem_name}"),
        };
        registered_slug = Some(slug);
        println!(
            "Registered ephemeral server `{}` on {}:{} (auto-prunes on exit{})",
            resolved.label,
            resolved.host,
            resolved.port,
            opts.ttl
                .map(|t| format!(" or after {t}"))
                .unwrap_or_default()
        );
    }

    if let Some(domain) = cfg.hopnet.public_domain.as_deref() {
        let slug = registered_slug.unwrap_or_else(|| {
            report
                .servers
                .iter()
                .find(|s| s.device == self_label && s.port == resolved.port)
                .and_then(|s| s.slug.clone())
                .unwrap_or_else(|| slugify_label(&resolved.label))
        });
        println!("  Hopnet domain: https://{slug}.{domain}");
    }

    if opts.local_only || !cfg.hopnet.uses_transport("tailscale") {
        return Ok(());
    }

    let ts_bin = ts.bin.as_deref().context(
        "tailscale CLI not found in PATH or standard install locations (pass `--local-only` or use `hop serve watch` with Cloudflare/direct transport)",
    )?;
    if !ts.available {
        bail!("tailscale daemon did not respond cleanly; check `tailscale status`");
    }

    let https_port = opts
        .https_port
        .unwrap_or(if resolved.port == 80 || resolved.port == 443 {
            443
        } else {
            resolved.port
        });
    let upstream = format_tailscale_upstream(&resolved.scheme, &resolved.host, resolved.port);
    let url = expose_tailscale_route(
        ts_bin,
        &ts,
        &resolved.label,
        &resolved.scheme,
        &resolved.host,
        resolved.port,
        resolved.path.as_deref(),
        Some(https_port),
        opts.allow_untrusted,
    )?;

    let port_audit = evaluate_access_audit(&ts, &[https_port]);
    println!(
        "Exposed `{}` (tailnet-only): {url} -> {upstream}",
        resolved.label
    );
    if !port_audit.untrusted_peers.is_empty() {
        println!(
            "  WARNING: overridden with --allow-untrusted ({} untrusted peer(s) can reach port {https_port})",
            port_audit.untrusted_peers.len()
        );
    } else {
        println!(
            "  Access: {} trusted peer(s), 0 untrusted inbound",
            port_audit.trusted_peers.len()
        );
    }
    Ok(())
}

pub fn cmd_serve_down(
    cfg: &HopConfig,
    target: Option<&str>,
    all: bool,
    dry_run: bool,
) -> Result<()> {
    let (report, ts) = build_local_report(cfg)?;
    let ts_bin = ts.bin.as_deref().context(
        "tailscale CLI not found in PATH or standard install locations (required for `hop serve down`)",
    )?;
    if !ts.available {
        bail!("tailscale daemon did not respond cleanly; check `tailscale status`");
    }

    if all {
        let mut ephem = load_ephemeral_servers();
        let ephem_count = ephem.servers.len();
        if !dry_run && ephem_count > 0 {
            ephem.servers.clear();
            let _ = save_ephemeral_servers(&ephem);
            println!("Cleared {ephem_count} ephemeral server registration(s).");
        }
        if ts.routes.is_empty() {
            if ephem_count == 0 {
                println!("No active tailscale serve routes on {}.", report.device);
            }
            return Ok(());
        }
        if dry_run {
            for r in &ts.routes {
                println!("Will stop serving {} -> {}", r.exposed_url, r.upstream_raw);
            }
            return Ok(());
        }
        let output = Command::new(ts_bin)
            .args(["serve", "reset"])
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("failed spawning {}", ts_bin.display()))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            bail!("tailscale serve reset failed: {stderr}");
        }
        println!(
            "Stopped all {} active tailscale serve route(s) on {}.",
            ts.routes.len(),
            report.device
        );
        return Ok(());
    }

    let spec = target.context("missing <target> (pass a server id/name/port, or `--all`)")?;
    let mut removed_ephem = false;
    {
        let mut ephem = load_ephemeral_servers();
        let before = ephem.servers.len();
        let port_num = spec.parse::<u16>().ok();
        ephem.servers.retain(|s| {
            let id = match &s.project {
                Some(p) => format!("{p}:{}", s.name),
                None => format!("ephemeral:{}", s.name),
            };
            let hit = id == spec
                || s.name == spec
                || s.slug == spec
                || port_num.is_some_and(|p| p == s.port);
            !hit
        });
        if ephem.servers.len() != before {
            removed_ephem = true;
            if dry_run {
                println!("Will remove ephemeral registration matching `{spec}`.");
            } else {
                let _ = save_ephemeral_servers(&ephem);
                println!("Removed ephemeral registration matching `{spec}`.");
            }
        }
    }

    let matched = find_matching_routes(&report.servers, &ts.routes, spec)?;
    if matched.is_empty() {
        if removed_ephem {
            return Ok(());
        }
        bail!("no active tailscale serve route matches `{spec}`");
    }

    for route in &matched {
        if dry_run {
            println!(
                "Will stop serving {} -> {}",
                route.exposed_url, route.upstream_raw
            );
        } else {
            stop_tailscale_route(ts_bin, route)?;
            println!(
                "Stopped serving {} -> {}",
                route.exposed_url, route.upstream_raw
            );
        }
    }
    Ok(())
}

pub fn cmd_serve_prune(cfg: &HopConfig, dry_run: bool) -> Result<()> {
    let (_, ts) = build_local_report(cfg)?;
    let ts_bin = ts.bin.as_deref().context(
        "tailscale CLI not found in PATH or standard install locations (required for `hop serve prune`)",
    )?;
    if !ts.available {
        bail!("tailscale daemon did not respond cleanly; check `tailscale status`");
    }

    let mut dead_routes = Vec::new();
    let mut live_count = 0usize;
    for route in &ts.routes {
        let alive = measure_tcp_rtt(
            &route.upstream_host,
            route.upstream_port,
            LOCAL_PROBE_TIMEOUT,
        )
        .is_some();
        if alive {
            live_count += 1;
        } else {
            dead_routes.push(route);
        }
    }

    if dead_routes.is_empty() {
        println!(
            "No stale tailscale serve routes found ({live_count} active route(s) have live upstreams)."
        );
        return Ok(());
    }

    for route in &dead_routes {
        if dry_run {
            println!(
                "Will prune stale route {} -> {} (upstream {}:{} down)",
                route.exposed_url, route.upstream_raw, route.upstream_host, route.upstream_port
            );
        } else {
            stop_tailscale_route(ts_bin, route)?;
            println!(
                "Pruned stale route {} -> {} (upstream {}:{} down)",
                route.exposed_url, route.upstream_raw, route.upstream_host, route.upstream_port
            );
        }
    }
    Ok(())
}

pub fn cmd_serve_add(cfg: &HopConfig, opts: FleetServerAddOptions<'_>) -> Result<()> {
    validate_server_name(opts.name)?;
    if opts.port == 0 {
        bail!("port must be between 1 and 65535");
    }
    let scheme = opts.scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        bail!("scheme must be `http` or `https` (got `{}`)", opts.scheme);
    }
    if let Some(dev) = opts.device
        && !cfg.devices.contains_key(dev)
        && dev != cfg.self_label()
    {
        bail!(
            "unknown device `{dev}` in devices.toml (add it first or omit `--device` for local host)"
        );
    }

    let mut file = load_servers_config()?;
    let target_device = opts.device.map(str::to_string);
    let spec = FleetServerSpec {
        name: opts.name.to_string(),
        device: target_device.clone(),
        port: opts.port,
        host: opts.host.to_string(),
        scheme,
        path: opts.path.map(str::to_string),
        description: opts.description.map(str::to_string),
    };

    if let Some(existing) = file
        .servers
        .iter_mut()
        .find(|s| s.name == spec.name && s.device == spec.device)
    {
        *existing = spec;
    } else {
        file.servers.push(spec);
    }

    save_servers_config(&file)?;
    let path = servers_config_path()?;
    let dev_label = target_device.unwrap_or_else(|| cfg.self_label());
    println!(
        "Registered fleet server `fleet:{}` on `{dev_label}` ({}:{}) in {}",
        opts.name,
        opts.host,
        opts.port,
        path.display()
    );
    Ok(())
}

pub fn cmd_serve_rm(cfg: &HopConfig, name: &str, device: Option<&str>) -> Result<()> {
    let mut file = load_servers_config()?;
    let before = file.servers.len();
    let self_label = cfg.self_label();
    file.servers.retain(|s| {
        if s.name != name {
            return true;
        }
        match device {
            Some(d) => s.device.as_deref().unwrap_or(&self_label) != d,
            None => false,
        }
    });
    if file.servers.len() == before {
        bail!("no fleet server `{name}` found in servers.toml");
    }
    save_servers_config(&file)?;
    let path = servers_config_path()?;
    println!(
        "Removed fleet server `fleet:{name}` from {}",
        path.display()
    );
    Ok(())
}

pub(crate) fn resolve_remote_tunnel_target(
    cfg: &HopConfig,
    alias: &str,
    target: &str,
    direct_only: bool,
) -> Result<(String, u16, String)> {
    if let Ok(port) = target.parse::<u16>() {
        if port == 0 {
            bail!("port must be between 1 and 65535");
        }
        return Ok(("127.0.0.1".to_string(), port, format!("port {port}")));
    }

    // 1. Check local ~/.config/hop/servers.toml for a fleet server assigned to `alias`
    if let Ok(file) = load_servers_config() {
        let clean_name = target.strip_prefix("fleet:").unwrap_or(target);
        if let Some(spec) = file
            .servers
            .iter()
            .find(|s| s.device.as_deref() == Some(alias) && s.name == clean_name)
        {
            return Ok((spec.host.clone(), spec.port, format!("fleet:{}", spec.name)));
        }
    }

    // 2. Query remote `hop serve --json` on `alias`
    let remote_cmd = vec![
        "sh -lc 'PATH=\"$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:$PATH\" hop serve --json'"
            .to_string(),
    ];
    let stdout = run_remote_capture(cfg, alias, &remote_cmd, direct_only).with_context(|| {
        format!(
            "could not resolve server `{target}` on `{alias}` via remote `hop serve --json` (pass a numeric port directly if `hop` is not installed on `{alias}`)"
        )
    })?;
    let report: ServeReport = serde_json::from_str(&stdout)
        .with_context(|| format!("invalid JSON from `hop serve --json` on `{alias}`"))?;

    if let Some(exact) = report
        .servers
        .iter()
        .find(|s| s.device == alias && s.id == target)
    {
        return Ok((exact.host.clone(), exact.port, exact.id.clone()));
    }

    let by_name: Vec<&ServerEntry> = report
        .servers
        .iter()
        .filter(|s| s.device == alias && s.name == target)
        .collect();
    match by_name.as_slice() {
        [single] => Ok((single.host.clone(), single.port, single.id.clone())),
        [] => {
            let known: Vec<&str> = report
                .servers
                .iter()
                .filter(|s| s.device == alias)
                .map(|s| s.id.as_str())
                .collect();
            bail!(
                "no server `{target}` found on `{alias}` (known: {})",
                if known.is_empty() {
                    "none".to_string()
                } else {
                    known.join(", ")
                }
            )
        }
        many => {
            let ids: Vec<&str> = many.iter().map(|s| s.id.as_str()).collect();
            bail!(
                "ambiguous server name `{target}` on `{alias}`; specify one of: {}",
                ids.join(", ")
            )
        }
    }
}

pub(crate) fn build_local_report(cfg: &HopConfig) -> Result<(ServeReport, TailscaleSnapshot)> {
    let self_label = cfg.self_label();
    let mut warnings = Vec::new();
    let mut servers = Vec::new();

    // 1. External project/server sources configured via `server_sources` (e.g. `kern servers --all --json`)
    let (source_servers, source_warnings) = collect_source_servers(cfg, &self_label);
    servers.extend(source_servers);
    warnings.extend(source_warnings);

    // 2. Non-project fleet servers declared in ~/.config/hop/servers.toml
    match load_servers_config() {
        Ok(file) => {
            servers.extend(collect_fleet_servers(&file.servers, &self_label));
        }
        Err(err) => {
            warnings.push(format!("failed loading servers.toml: {err}"));
        }
    }

    // 2b. Labeled ephemeral servers (`hop serve up <port> --name ...`), auto-pruning dead/expired entries
    servers.extend(collect_ephemeral_servers(&self_label));

    // 2c. Pluggable status_sources (e.g. `caf = "caf status --json"`)
    let (status_map, status_warnings) = collect_status_sources(cfg);
    warnings.extend(status_warnings);

    // 3. Live Tailscale serve routes + peer access audit
    let ts = inspect_tailscale(cfg);
    warnings.extend(ts.warnings.clone());

    // 4. Join active Tailscale Serve routes onto declared/ephemeral local servers; surface unregistered routes
    for route in &ts.routes {
        let mut matched_any = false;
        for entry in &mut servers {
            let matches_port = entry.port == route.upstream_port
                || tailscale_shim_port(entry.port) == Some(route.upstream_port);
            if entry.device == self_label && matches_port {
                entry.exposed = true;
                entry.exposed_url = Some(route.exposed_url.clone());
                entry.https_port = Some(route.https_port);
                entry.funnel_public = entry.funnel_public || route.funnel_public;
                matched_any = true;
            }
        }
        if !matched_any {
            let live = measure_tcp_rtt(
                &route.upstream_host,
                route.upstream_port,
                LOCAL_PROBE_TIMEOUT,
            )
            .is_some();
            servers.push(ServerEntry {
                id: format!("unregistered:{}", route.https_port),
                slug: Some(format!("port-{}", route.upstream_port)),
                kind: "unregistered".to_string(),
                project: None,
                name: format!("port-{}", route.upstream_port),
                device: self_label.clone(),
                host: route.upstream_host.clone(),
                port: route.upstream_port,
                scheme: route.upstream_scheme.clone(),
                path: (route.mount_path != "/").then(|| route.mount_path.clone()),
                up: Some(live),
                port_conflict: None,
                exposed: true,
                exposed_url: Some(route.exposed_url.clone()),
                public_url: None,
                direct_urls: Vec::new(),
                https_port: Some(route.https_port),
                funnel_public: route.funnel_public,
                cmd: None,
                description: Some(format!("Tailscale serve proxy -> {}", route.upstream_raw)),
                pid: None,
                expires_unix: None,
                source: "tailscale-serve".to_string(),
            });
        }
    }

    // 4b. Assign deterministic DNS-safe slugs and optional Cloudflare public_url
    assign_server_slugs(&mut servers, &self_label, cfg);

    // 4c. Merge active direct VPN/ZeroTier/LAN allowlisted proxy routes (from `hop serve watch`)
    for direct in crate::hopnet::load_live_direct_routes() {
        for entry in &mut servers {
            if entry.device == self_label
                && (entry.id == direct.server_id || entry.port == direct.upstream_port)
            {
                entry.exposed = true;
                if !entry.direct_urls.contains(&direct.url) {
                    entry.direct_urls.push(direct.url.clone());
                }
            }
        }
    }

    // 4d. Merge active Cloudflare local ingress routes (from `hop serve watch`)
    for ing in crate::hopnet::load_live_ingress_routes() {
        for entry in &mut servers {
            if entry.device == self_label
                && (entry.id == ing.server_id || entry.port == ing.upstream_port)
            {
                entry.exposed = true;
                if entry.public_url.is_none() {
                    entry.public_url = ing.public_url.clone();
                }
            }
        }
    }

    servers.sort_by(|a, b| {
        kind_rank(&a.kind)
            .cmp(&kind_rank(&b.kind))
            .then_with(|| a.device.cmp(&b.device))
            .then_with(|| a.id.cmp(&b.id))
    });

    let audit_ports: Vec<u16> = if ts.routes.is_empty() {
        vec![443]
    } else {
        ts.routes.iter().map(|r| r.https_port).collect()
    };
    let access = evaluate_access_audit(&ts, &audit_ports);

    let report = ServeReport {
        schema: "hop.serve/v1".to_string(),
        device: self_label,
        tailscale_dns: ts.self_dns.clone(),
        origin_host: cfg.hopnet.origin_host.clone(),
        public_domain: cfg.hopnet.public_domain.clone(),
        status: status_map,
        servers,
        access,
        warnings,
    };
    Ok((report, ts))
}

fn kind_rank(kind: &str) -> u8 {
    match kind {
        "project" => 0,
        "ephemeral" => 1,
        "fleet" => 2,
        _ => 3,
    }
}

fn collect_source_servers(cfg: &HopConfig, self_label: &str) -> (Vec<ServerEntry>, Vec<String>) {
    let mut entries = Vec::new();
    let mut warnings = Vec::new();
    let aug_path = augmented_path();

    for raw_cmd in &cfg.server_sources {
        let argv = split_command_line(raw_cmd);
        let Some((bin, args)) = argv.split_first() else {
            continue;
        };
        let output = Command::new(bin)
            .args(args)
            .env("PATH", &aug_path)
            .stdin(Stdio::null())
            .output();
        let output = match output {
            Ok(o) => o,
            Err(err) => {
                warnings.push(format!("server_source `{raw_cmd}` failed to run: {err}"));
                continue;
            }
        };
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            warnings.push(format!(
                "server_source `{raw_cmd}` exited with {}: {}",
                output.status,
                if stderr.is_empty() {
                    "no stderr"
                } else {
                    &stderr
                }
            ));
            continue;
        }
        let items: Vec<ExternalServerItem> = match serde_json::from_slice(&output.stdout) {
            Ok(v) => v,
            Err(err) => {
                warnings.push(format!(
                    "server_source `{raw_cmd}` returned invalid JSON: {err}"
                ));
                continue;
            }
        };
        let bin_name = std::path::Path::new(bin)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(bin);

        for item in items {
            let host = item.host.unwrap_or_else(|| "127.0.0.1".to_string());
            let up = item.up.unwrap_or_else(|| {
                measure_tcp_rtt(&host, item.port, LOCAL_PROBE_TIMEOUT).is_some()
            });
            let id = item.id.unwrap_or_else(|| match &item.project {
                Some(p) => format!("{p}:{}", item.name),
                None => item.name.clone(),
            });
            let source = match item.source {
                Some(s) if !s.is_empty() => format!("{bin_name}:{s}"),
                _ => bin_name.to_string(),
            };
            entries.push(ServerEntry {
                id,
                slug: None,
                kind: item.kind.unwrap_or_else(|| "project".to_string()),
                project: item.project,
                name: item.name,
                device: self_label.to_string(),
                host,
                port: item.port,
                scheme: item.scheme.unwrap_or_else(default_scheme),
                path: item.path,
                up: Some(up),
                port_conflict: item.port_conflict,
                exposed: false,
                exposed_url: None,
                public_url: None,
                direct_urls: Vec::new(),
                https_port: None,
                funnel_public: false,
                cmd: item.cmd,
                description: item.description,
                pid: None,
                expires_unix: None,
                source,
            });
        }
    }

    (entries, warnings)
}

fn collect_fleet_servers(specs: &[FleetServerSpec], self_label: &str) -> Vec<ServerEntry> {
    let mut handles = Vec::with_capacity(specs.len());
    for spec in specs.iter().cloned() {
        let local_label = self_label.to_string();
        handles.push(thread::spawn(move || {
            let device = spec.device.unwrap_or_else(|| local_label.clone());
            let up = if device == local_label {
                Some(measure_tcp_rtt(&spec.host, spec.port, LOCAL_PROBE_TIMEOUT).is_some())
            } else {
                None
            };
            ServerEntry {
                id: format!("fleet:{}", spec.name),
                slug: Some(slugify_label(&spec.name)),
                kind: "fleet".to_string(),
                project: None,
                name: spec.name,
                device,
                host: spec.host,
                port: spec.port,
                scheme: spec.scheme,
                path: spec.path,
                up,
                port_conflict: None,
                exposed: false,
                exposed_url: None,
                public_url: None,
                direct_urls: Vec::new(),
                https_port: None,
                funnel_public: false,
                cmd: None,
                description: spec.description,
                pid: None,
                expires_unix: None,
                source: "hop:servers.toml".to_string(),
            }
        }));
    }
    handles.into_iter().filter_map(|h| h.join().ok()).collect()
}

fn collect_ephemeral_servers(self_label: &str) -> Vec<ServerEntry> {
    let mut store = load_ephemeral_servers();
    if store.servers.is_empty() {
        return Vec::new();
    }
    let now = now_unix_secs();
    let mut kept = Vec::with_capacity(store.servers.len());
    let mut entries = Vec::new();
    let mut dirty = false;

    for rec in store.servers.drain(..) {
        if rec.expires_unix.is_some_and(|exp| exp <= now) {
            dirty = true;
            continue;
        }
        let port_up = measure_tcp_rtt(&rec.host, rec.port, LOCAL_PROBE_TIMEOUT).is_some();
        if !port_up {
            dirty = true;
            continue;
        }
        let id = match &rec.project {
            Some(p) => format!("{p}:{}", rec.name),
            None => format!("ephemeral:{}", rec.name),
        };
        entries.push(ServerEntry {
            id,
            slug: Some(rec.slug.clone()),
            kind: "ephemeral".to_string(),
            project: rec.project.clone(),
            name: rec.name.clone(),
            device: self_label.to_string(),
            host: rec.host.clone(),
            port: rec.port,
            scheme: rec.scheme.clone(),
            path: rec.path.clone(),
            up: Some(true),
            port_conflict: None,
            exposed: false,
            exposed_url: None,
            public_url: None,
            direct_urls: Vec::new(),
            https_port: None,
            funnel_public: false,
            cmd: None,
            description: rec.description.clone(),
            pid: rec.pid,
            expires_unix: rec.expires_unix,
            source: "hop:ephemeral".to_string(),
        });
        kept.push(rec);
    }

    if dirty {
        store.servers = kept;
        let _ = save_ephemeral_servers(&store);
    }
    entries
}

fn collect_status_sources(cfg: &HopConfig) -> (BTreeMap<String, serde_json::Value>, Vec<String>) {
    let mut map = BTreeMap::new();
    let mut warnings = Vec::new();
    if cfg.status_sources.is_empty() {
        return (map, warnings);
    }
    let aug_path = augmented_path();
    let mut handles = Vec::with_capacity(cfg.status_sources.len());

    for (key, raw_cmd) in &cfg.status_sources {
        let k = key.clone();
        let cmd_str = raw_cmd.clone();
        let path_env = aug_path.clone();
        handles.push(thread::spawn(move || {
            let argv = split_command_line(&cmd_str);
            let Some((bin, args)) = argv.split_first() else {
                return (k, None, None);
            };
            match Command::new(bin)
                .args(args)
                .env("PATH", &path_env)
                .stdin(Stdio::null())
                .output()
            {
                Ok(out) if out.status.success() => {
                    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if stdout.is_empty() {
                        return (k, None, None);
                    }
                    let val = match serde_json::from_str::<serde_json::Value>(&stdout) {
                        Ok(v) => v,
                        Err(_) => serde_json::Value::String(stdout),
                    };
                    (k, Some(val), None)
                }
                Ok(out) => {
                    let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
                    (
                        k.clone(),
                        None,
                        Some(format!(
                            "status_source `{k}` exited {}: {}",
                            out.status,
                            if err.is_empty() { "failed" } else { &err }
                        )),
                    )
                }
                Err(err) => (
                    k.clone(),
                    None,
                    Some(format!("status_source `{k}` failed to run: {err}")),
                ),
            }
        }));
    }

    for h in handles {
        if let Ok((k, val, warn)) = h.join() {
            if let Some(v) = val {
                map.insert(k, v);
            }
            if let Some(w) = warn {
                warnings.push(w);
            }
        }
    }
    (map, warnings)
}

fn assign_server_slugs(servers: &mut [ServerEntry], self_label: &str, cfg: &HopConfig) {
    let mut used: BTreeSet<String> = BTreeSet::new();
    let cf_domain = if cfg.hopnet.uses_transport("cloudflare") {
        cfg.hopnet
            .public_domain
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
    } else {
        None
    };

    for entry in servers.iter_mut() {
        let base = if let Some(existing) = entry.slug.clone().filter(|s| !s.is_empty()) {
            slugify_label(&existing)
        } else if let Some(proj) = entry.project.as_deref() {
            let generic = matches!(
                entry.name.to_ascii_lowercase().as_str(),
                "web" | "app" | "dev" | "preview" | "server" | "ui" | "api" | "site" | "main"
            );
            if generic {
                slugify_label(proj)
            } else {
                slugify_label(&format!("{proj}-{}", entry.name))
            }
        } else {
            slugify_label(&entry.name)
        };

        let mut chosen = base.clone();
        if used.contains(&chosen) {
            let with_name = slugify_label(&format!("{base}-{}", entry.name));
            if !used.contains(&with_name) {
                chosen = with_name;
            } else {
                chosen = slugify_label(&format!("{base}-{}", entry.port));
            }
        }
        used.insert(chosen.clone());
        entry.slug = Some(chosen.clone());

        if let Some(domain) = cf_domain
            && entry.device == self_label
            && entry.kind != "unregistered"
            && entry.up == Some(true)
        {
            entry.public_url = Some(format!("https://{chosen}.{domain}"));
        }
    }
}

fn parse_ttl_secs(raw: &str) -> Result<u64> {
    let t = raw.trim().to_ascii_lowercase();
    if t.is_empty() {
        bail!("empty --ttl duration");
    }
    if let Ok(mins) = t.parse::<u64>() {
        return Ok(mins.saturating_mul(60).max(60));
    }
    let (num_str, mult) = if let Some(n) = t.strip_suffix('s') {
        (n, 1u64)
    } else if let Some(n) = t.strip_suffix('m') {
        (n, 60u64)
    } else if let Some(n) = t.strip_suffix('h') {
        (n, 3600u64)
    } else if let Some(n) = t.strip_suffix('d') {
        (n, 86400u64)
    } else {
        bail!("invalid --ttl `{raw}` (use e.g. 30m, 4h, 1d)");
    };
    let n: u64 = num_str
        .trim()
        .parse()
        .with_context(|| format!("invalid --ttl `{raw}`"))?;
    Ok(n.saturating_mul(mult).max(60))
}

fn detect_local_listener_pid(port: u16) -> Option<u32> {
    if cfg!(windows) {
        return None;
    }
    let lsof_bin = if std::path::Path::new("/usr/sbin/lsof").is_file() {
        "/usr/sbin/lsof"
    } else {
        "lsof"
    };
    let out = Command::new(lsof_bin)
        .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-Fp"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some(rest) = line.strip_prefix('p')
            && let Ok(pid) = rest.trim().parse::<u32>()
        {
            return Some(pid);
        }
    }
    None
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn inspect_tailscale(cfg: &HopConfig) -> TailscaleSnapshot {
    let mut snap = TailscaleSnapshot::default();
    let Some(bin) = find_tailscale_bin() else {
        return snap;
    };
    snap.bin = Some(bin.clone());

    let trusted_ids = cfg.trusted_identifiers();

    // 1. `tailscale status --json`
    match Command::new(&bin)
        .args(["status", "--json"])
        .stdin(Stdio::null())
        .output()
    {
        Ok(out) if out.status.success() => {
            if let Ok(status) = serde_json::from_slice::<TsStatus>(&out.stdout) {
                snap.available = true;
                if let Some(self_node) = status.self_node {
                    let dns = clean_dns(&self_node.dns_name);
                    if !dns.is_empty() {
                        snap.self_dns = Some(dns);
                    }
                    snap.self_ips = self_node
                        .tailscale_ips
                        .iter()
                        .filter_map(|s| s.parse::<IpAddr>().ok())
                        .collect();
                }

                for node in status.peers.values() {
                    let full_dns = clean_dns(&node.dns_name);
                    if full_dns.ends_with(".mullvad.ts.net") {
                        continue;
                    }
                    // Skip Tailscale's built-in regional Funnel ingress relays;
                    // public Funnel exposure is already flagged via AllowFunnel.
                    if full_dns.is_empty()
                        && node.sharee_node
                        && node.host_name == "funnel-ingress-node"
                        && node.tags.iter().any(|t| t == "tag:ingress")
                    {
                        continue;
                    }
                    let short_name = if !full_dns.is_empty() {
                        full_dns.split('.').next().unwrap_or(&full_dns).to_string()
                    } else if !node.host_name.trim().is_empty() {
                        node.host_name.trim().to_string()
                    } else {
                        node.tailscale_ips
                            .first()
                            .cloned()
                            .unwrap_or_else(|| "unknown".to_string())
                    };

                    let trusted = is_peer_trusted(
                        &trusted_ids,
                        &short_name,
                        &full_dns,
                        &node.host_name,
                        &node.tailscale_ips,
                    );

                    snap.peers.push(RawTailscalePeer {
                        name: short_name,
                        dns_name: (!full_dns.is_empty()).then_some(full_dns),
                        ips: node.tailscale_ips.clone(),
                        os: node.os.clone(),
                        online: node.online,
                        trusted,
                    });
                }
            } else {
                snap.warnings
                    .push("could not parse JSON from `tailscale status --json`".to_string());
            }
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            snap.warnings.push(format!(
                "tailscale status returned {}: {}",
                out.status,
                if stderr.is_empty() {
                    "daemon not running"
                } else {
                    &stderr
                }
            ));
        }
        Err(err) => {
            snap.warnings
                .push(format!("failed running tailscale status: {err}"));
        }
    }

    if !snap.available {
        return snap;
    }

    // 2. `tailscale serve status --json`
    if let Ok(out) = Command::new(&bin)
        .args(["serve", "status", "--json"])
        .stdin(Stdio::null())
        .output()
        && out.status.success()
    {
        let stdout_trimmed = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !stdout_trimmed.is_empty() && stdout_trimmed != "null" {
            match serde_json::from_str::<TsServeStatus>(&stdout_trimmed) {
                Ok(serve_st) => {
                    snap.routes = parse_active_serve_routes(&serve_st, snap.self_dns.as_deref());
                }
                Err(err) => {
                    snap.warnings.push(format!(
                        "could not parse JSON from `tailscale serve status --json`: {err}"
                    ));
                }
            }
        }
    }

    // 3. Optional WireGuard PacketFilter verification (`tailscale debug netmap`)
    // If unavailable or changed, fail closed (inbound_allowed stays None and untrusted peers remain flagged).
    if let Ok(out) = Command::new(&bin)
        .args(["debug", "netmap"])
        .stdin(Stdio::null())
        .output()
        && out.status.success()
        && let Ok(netmap) = serde_json::from_slice::<TsNetmap>(&out.stdout)
        && let Some(pf) = netmap.packet_filter
        && !pf.is_empty()
    {
        snap.packet_filter = Some(pf);
    }

    snap
}

pub(crate) fn evaluate_access_audit(ts: &TailscaleSnapshot, target_ports: &[u16]) -> AccessAudit {
    let mut audit = AccessAudit {
        tailscale_available: ts.available,
        packet_filter_verified: ts.packet_filter.is_some(),
        self_dns: ts.self_dns.clone(),
        trusted_peers: Vec::new(),
        untrusted_peers: Vec::new(),
        blocked_untrusted_peers: Vec::new(),
        public_funnel_routes: ts
            .routes
            .iter()
            .filter(|r| r.funnel_public)
            .map(|r| r.exposed_url.clone())
            .collect(),
    };

    for peer in &ts.peers {
        let inbound_allowed = ts.packet_filter.as_deref().map(|rules| {
            packet_filter_allows_peer_tcp(rules, &peer.ips, &ts.self_ips, target_ports)
        });
        let primary_ip = peer
            .ips
            .iter()
            .find(|ip| ip.contains('.'))
            .or_else(|| peer.ips.first())
            .cloned();
        let info = TailscalePeerInfo {
            name: peer.name.clone(),
            dns_name: peer.dns_name.clone(),
            ip: primary_ip,
            os: peer.os.clone(),
            online: peer.online,
            inbound_allowed,
        };
        if peer.trusted {
            audit.trusted_peers.push(info);
        } else if inbound_allowed == Some(false) {
            audit.blocked_untrusted_peers.push(info);
        } else {
            // Either confirmed allowed (`Some(true)`) or PacketFilter unavailable (`None` -> fail-closed)
            audit.untrusted_peers.push(info);
        }
    }

    let sort_peers = |list: &mut Vec<TailscalePeerInfo>| {
        list.sort_by(|a, b| b.online.cmp(&a.online).then_with(|| a.name.cmp(&b.name)));
    };
    sort_peers(&mut audit.trusted_peers);
    sort_peers(&mut audit.untrusted_peers);
    sort_peers(&mut audit.blocked_untrusted_peers);
    audit
}

fn parse_active_serve_routes(st: &TsServeStatus, self_dns: Option<&str>) -> Vec<ActiveServeRoute> {
    let mut routes = Vec::new();
    let mut seen_web_ports: BTreeSet<u16> = BTreeSet::new();

    for (host_port, web) in &st.web {
        let Some((host_raw, port_str)) = host_port.rsplit_once(':') else {
            continue;
        };
        let Ok(https_port) = port_str.parse::<u16>() else {
            continue;
        };
        seen_web_ports.insert(https_port);
        let funnel_public = st.allow_funnel.get(host_port).copied().unwrap_or(false);

        for (mount_path, handler) in &web.handlers {
            let Some(proxy) = &handler.proxy else {
                continue;
            };
            let (scheme, upstream_host, upstream_port) = parse_proxy_target(proxy);
            let url = format_https_url(host_raw, https_port, mount_path);
            routes.push(ActiveServeRoute {
                https_port,
                is_tcp_forward: false,
                mount_path: mount_path.clone(),
                exposed_url: url,
                upstream_raw: proxy.clone(),
                upstream_host,
                upstream_port,
                upstream_scheme: scheme,
                funnel_public,
            });
        }
    }

    // Pure TCP forward routes not represented under Web
    for (port_str, tcp) in &st.tcp {
        let Ok(tcp_port) = port_str.parse::<u16>() else {
            continue;
        };
        if seen_web_ports.contains(&tcp_port) {
            continue;
        }
        let Some(fwd) = &tcp.tcp_forward else {
            continue;
        };
        let (upstream_host, upstream_port) = parse_host_port(fwd, tcp_port);
        let host = self_dns.unwrap_or("tailnet-host");
        routes.push(ActiveServeRoute {
            https_port: tcp_port,
            is_tcp_forward: true,
            mount_path: "/".to_string(),
            exposed_url: format!("tcp://{host}:{tcp_port}"),
            upstream_raw: fwd.clone(),
            upstream_host,
            upstream_port,
            upstream_scheme: "tcp".to_string(),
            funnel_public: false,
        });
    }

    routes
}

fn parse_proxy_target(raw: &str) -> (String, String, u16) {
    let (scheme, rest, default_port) = if let Some(r) = raw.strip_prefix("https+insecure://") {
        ("https".to_string(), r, 443)
    } else if let Some(r) = raw.strip_prefix("https://") {
        ("https".to_string(), r, 443)
    } else if let Some(r) = raw.strip_prefix("http://") {
        ("http".to_string(), r, 80)
    } else {
        ("http".to_string(), raw, 80)
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    let (host, port) = parse_host_port(authority, default_port);
    (scheme, host, port)
}

fn parse_host_port(authority: &str, default_port: u16) -> (String, u16) {
    if let Some(rest) = authority.strip_prefix('[')
        && let Some((ipv6, tail)) = rest.split_once(']')
    {
        let port = tail
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(default_port);
        return (ipv6.to_string(), port);
    }
    if let Some((host, port_str)) = authority.rsplit_once(':')
        && let Ok(port) = port_str.parse::<u16>()
    {
        let normalized_host = if host.is_empty() || host == "localhost" {
            "127.0.0.1".to_string()
        } else {
            host.to_string()
        };
        return (normalized_host, port);
    }
    let normalized_host = if authority.is_empty() || authority == "localhost" {
        "127.0.0.1".to_string()
    } else {
        authority.to_string()
    };
    (normalized_host, default_port)
}

struct ResolvedExposeTarget {
    label: String,
    host: String,
    port: u16,
    scheme: String,
    path: Option<String>,
    up: bool,
    cmd: Option<String>,
}

fn resolve_local_expose_target(
    servers: &[ServerEntry],
    self_label: &str,
    target: &str,
) -> Result<ResolvedExposeTarget> {
    // 1. Exact ID match
    if let Some(entry) = servers.iter().find(|s| s.id == target) {
        if entry.device != self_label {
            bail!(
                "`{}` belongs to device `{}` (run `hop run {} -- hop serve up {}` or `hop tunnel {} {}`)",
                entry.id,
                entry.device,
                entry.device,
                entry.id,
                entry.device,
                entry.name
            );
        }
        return Ok(ResolvedExposeTarget {
            label: entry.id.clone(),
            host: entry.host.clone(),
            port: entry.port,
            scheme: entry.scheme.clone(),
            path: entry.path.clone(),
            up: entry.up.unwrap_or(false),
            cmd: entry.cmd.clone(),
        });
    }

    // 2. Local server unique name match
    let by_name: Vec<&ServerEntry> = servers
        .iter()
        .filter(|s| s.name == target && s.kind != "unregistered")
        .collect();
    if by_name.len() == 1 {
        let entry = by_name[0];
        if entry.device != self_label {
            bail!(
                "`{}` belongs to device `{}` (run `hop run {} -- hop serve up {}` or `hop tunnel {} {}`)",
                entry.id,
                entry.device,
                entry.device,
                entry.id,
                entry.device,
                entry.name
            );
        }
        return Ok(ResolvedExposeTarget {
            label: entry.id.clone(),
            host: entry.host.clone(),
            port: entry.port,
            scheme: entry.scheme.clone(),
            path: entry.path.clone(),
            up: entry.up.unwrap_or(false),
            cmd: entry.cmd.clone(),
        });
    } else if by_name.len() > 1 {
        let ids: Vec<&str> = by_name.iter().map(|s| s.id.as_str()).collect();
        bail!(
            "ambiguous server name `{target}`; specify one of: {}",
            ids.join(", ")
        );
    }

    // 3. Numeric local port (matches declared local server on that port if present)
    if let Ok(port) = target.parse::<u16>() {
        if port == 0 {
            bail!("port must be between 1 and 65535");
        }
        if let Some(entry) = servers
            .iter()
            .find(|s| s.device == self_label && s.port == port && s.kind != "unregistered")
        {
            return Ok(ResolvedExposeTarget {
                label: entry.id.clone(),
                host: entry.host.clone(),
                port: entry.port,
                scheme: entry.scheme.clone(),
                path: entry.path.clone(),
                up: entry.up.unwrap_or(false),
                cmd: entry.cmd.clone(),
            });
        }
        let up = measure_tcp_rtt("127.0.0.1", port, LOCAL_PROBE_TIMEOUT).is_some();
        return Ok(ResolvedExposeTarget {
            label: format!("127.0.0.1:{port}"),
            host: "127.0.0.1".to_string(),
            port,
            scheme: "http".to_string(),
            path: None,
            up,
            cmd: None,
        });
    }

    let known: Vec<&str> = servers
        .iter()
        .filter(|s| s.device == self_label && s.kind != "unregistered")
        .map(|s| s.id.as_str())
        .collect();
    bail!(
        "unknown local server `{target}` (declared on `{self_label}`: {})",
        if known.is_empty() {
            "none".to_string()
        } else {
            known.join(", ")
        }
    )
}

fn find_matching_routes<'a>(
    servers: &[ServerEntry],
    routes: &'a [ActiveServeRoute],
    spec: &str,
) -> Result<Vec<&'a ActiveServeRoute>> {
    // Match by declared server id or name first
    let matched_server_ports: BTreeSet<u16> = servers
        .iter()
        .filter(|s| s.id == spec || s.name == spec)
        .map(|s| s.port)
        .collect();

    let port_num = spec.parse::<u16>().ok();
    let mut found = Vec::new();
    for route in routes {
        let hit_id = format!("unregistered:{}", route.https_port) == spec;
        let hit_server = matched_server_ports.contains(&route.upstream_port);
        let hit_port = port_num.is_some_and(|p| p == route.https_port || p == route.upstream_port);
        if hit_id || hit_server || hit_port {
            found.push(route);
        }
    }
    Ok(found)
}

pub(crate) fn stop_tailscale_route(
    ts_bin: &std::path::Path,
    route: &ActiveServeRoute,
) -> Result<()> {
    let mut cmd = Command::new(ts_bin);
    if route.is_tcp_forward {
        cmd.args(["serve", &format!("--tcp={}", route.https_port), "off"]);
    } else {
        cmd.args(["serve", &format!("--https={}", route.https_port)]);
        if route.mount_path != "/" {
            cmd.args(["--set-path", &route.mount_path]);
        }
        cmd.arg("off");
    }
    cmd.stdin(Stdio::null());
    let out = cmd
        .output()
        .with_context(|| format!("failed spawning {}", ts_bin.display()))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let detail = if !stderr.is_empty() { stderr } else { stdout };
        bail!(
            "failed stopping route {} ({}): {detail}",
            route.exposed_url,
            out.status
        );
    }
    Ok(())
}

fn print_report(report: &ServeReport) {
    let st = Style::stdout();
    let subtitle = match report.tailscale_dns.as_deref() {
        Some(dns) => format!("{}  ({dns})", report.device),
        None => report.device.clone(),
    };
    st.header("hop serve", Some(&subtitle));

    st.section(&format!("Servers ({})", report.servers.len()));
    if report.servers.is_empty() {
        st.note(
            2,
            "No official project servers, fleet servers, or active routes.",
        );
    } else {
        let mut sorted: Vec<&ServerEntry> = report.servers.iter().collect();
        sorted.sort_by_key(|s| {
            let state_rank = match (s.kind.as_str(), s.up) {
                ("unregistered", Some(true)) => 1,
                (_, Some(true)) => 0,
                (_, None) => 2,
                ("unregistered", Some(false)) => 3,
                (_, Some(false)) => 4,
            };
            (state_rank, s.device.as_str(), s.id.as_str())
        });

        let mut tbl = Table::new(
            2,
            &[
                ("SERVER", Align::Left),
                ("KIND", Align::Left),
                ("PORT", Align::Right),
                ("STATE", Align::Left),
                ("EXPOSURE", Align::Left),
            ],
        );

        for s in sorted {
            let is_down = s.up == Some(false) && s.kind != "unregistered";
            let server_raw = if s.device != report.device {
                format!("{} ({})", s.id, s.device)
            } else {
                s.id.clone()
            };
            let server_col = if is_down {
                st.dim(&server_raw)
            } else {
                st.bold(&server_raw)
            };
            let kind_col = st.dim(&s.kind);
            let port_col = if is_down {
                st.dim(&s.port.to_string())
            } else {
                s.port.to_string()
            };
            let state_col = if s.port_conflict.is_some() {
                st.yellow("▲ conflict")
            } else {
                st.state_badge(&s.kind, s.up)
            };
            let mut urls: Vec<String> = Vec::new();
            if let Some(pu) = &s.public_url {
                urls.push(pu.clone());
            }
            if let Some(url) = &s.exposed_url {
                urls.push(url.clone());
            }
            urls.extend(s.direct_urls.iter().cloned());

            let exposure_col = if let Some(conflict) = &s.port_conflict {
                st.yellow(conflict)
            } else if !urls.is_empty() {
                if s.funnel_public {
                    format!(
                        "{} {}",
                        st.red(&urls.join(" | ")),
                        st.red("[PUBLIC FUNNEL]")
                    )
                } else if s.up == Some(false) {
                    format!(
                        "{} {}",
                        st.yellow(&urls.join(" | ")),
                        st.dim("(stale - hop serve prune)")
                    )
                } else {
                    st.cyan(&urls.join(" | "))
                }
            } else if s.device != report.device {
                st.dim(&format!("hop open {}", s.id))
            } else {
                st.dim("local only")
            };
            tbl.row(vec![
                server_col,
                kind_col,
                port_col,
                state_col,
                exposure_col,
            ]);
        }
        tbl.print(&st);
    }

    if !report.access.tailscale_available {
        st.section("Access");
        st.note(2, "Tailscale unavailable on this host.");
    } else {
        let mode = if report.access.packet_filter_verified {
            "WireGuard PacketFilter verified"
        } else {
            "peer-list fallback (fail-closed)"
        };
        println!("\n{}  {}", st.bold("Access"), st.dim(mode));

        let trusted_items = format_peer_items(&st, &report.access.trusted_peers, false);
        st.wrapped_labeled(
            2,
            &st.dim(&format!("Trusted ({}):", report.access.trusted_peers.len())),
            &trusted_items,
            "  ",
        );

        let untrusted_label = format!("Untrusted ({}):", report.access.untrusted_peers.len());
        if report.access.untrusted_peers.is_empty() {
            println!("  {} {}", st.dim(&untrusted_label), st.green("none"));
        } else {
            let untrusted_items = format_peer_items(&st, &report.access.untrusted_peers, true);
            st.wrapped_labeled(2, &st.red(&untrusted_label), &untrusted_items, "  ");
        }

        if !report.access.blocked_untrusted_peers.is_empty() {
            let blocked_items =
                format_peer_items(&st, &report.access.blocked_untrusted_peers, false);
            st.wrapped_labeled(
                2,
                &st.dim(&format!(
                    "Blocked by ACL ({}):",
                    report.access.blocked_untrusted_peers.len()
                )),
                &blocked_items,
                "  ",
            );
        }

        if !report.access.public_funnel_routes.is_empty() {
            println!(
                "  {} {}",
                st.red("CRITICAL:"),
                st.red(&format!(
                    "PUBLIC FUNNEL ACTIVE on {}",
                    report.access.public_funnel_routes.join(", ")
                ))
            );
        }
        if !report.access.untrusted_peers.is_empty() {
            println!(
                "  {} {} untrusted tailnet peer(s) can reach exposed ports.",
                st.yellow("WARNING:"),
                report.access.untrusted_peers.len()
            );
            st.note(
                4,
                "`hop serve up` refuses until restricted via Tailscale ACL (or --allow-untrusted).",
            );
        }
    }

    for w in &report.warnings {
        st.note(2, &format!("Note: {w}"));
    }
}

fn format_peer_items(st: &Style, peers: &[TailscalePeerInfo], alert: bool) -> Vec<String> {
    peers
        .iter()
        .map(|p| {
            if alert {
                let dot = if p.online { "●" } else { "·" };
                st.red(&format!("{dot} {}", p.name))
            } else if p.online {
                format!("{} {}", st.green("●"), p.name)
            } else {
                st.dim(&format!("· {}", p.name))
            }
        })
        .collect()
}

fn format_tailscale_upstream(scheme: &str, host: &str, port: u16) -> String {
    if scheme == "https" {
        format!("https+insecure://{host}:{port}")
    } else {
        format!("http://{host}:{port}")
    }
}

fn format_https_url(host: &str, https_port: u16, mount_path: &str) -> String {
    let suffix = if mount_path == "/" { "" } else { mount_path };
    if https_port == 443 {
        format!("https://{host}{suffix}")
    } else {
        format!("https://{host}:{https_port}{suffix}")
    }
}

fn normalized_mount_path(path: Option<&str>) -> String {
    match path.map(str::trim) {
        Some(p) if !p.is_empty() && p != "/" => {
            if p.starts_with('/') {
                p.to_string()
            } else {
                format!("/{p}")
            }
        }
        _ => "/".to_string(),
    }
}

fn clean_dns(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_string()
}

fn is_peer_trusted(
    trusted_ids: &BTreeSet<String>,
    short_name: &str,
    full_dns: &str,
    host_name: &str,
    ips: &[String],
) -> bool {
    if trusted_ids.contains(&short_name.to_ascii_lowercase()) {
        return true;
    }
    if !full_dns.is_empty() && trusted_ids.contains(&full_dns.to_ascii_lowercase()) {
        return true;
    }
    let hn = host_name.trim().to_ascii_lowercase();
    if !hn.is_empty() && hn != "localhost" && trusted_ids.contains(&hn) {
        return true;
    }
    for ip in ips {
        if trusted_ids.contains(&ip.to_ascii_lowercase()) {
            return true;
        }
    }
    false
}

fn packet_filter_allows_peer_tcp(
    rules: &[PacketFilterRule],
    peer_ip_strs: &[String],
    self_ips: &[IpAddr],
    target_ports: &[u16],
) -> bool {
    let peer_ips: Vec<IpAddr> = peer_ip_strs
        .iter()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .collect();
    if peer_ips.is_empty() {
        return true; // fail-closed if peer has no parseable IP
    }

    for rule in rules {
        // IPProto empty means all protocols; 6 is TCP
        if !rule.ip_proto.is_empty() && !rule.ip_proto.contains(&6) {
            continue;
        }
        let src_match = peer_ips
            .iter()
            .any(|ip| rule.srcs.iter().any(|cidr| ip_in_cidr(*ip, cidr)));
        if !src_match {
            continue;
        }
        for dst in &rule.dsts {
            let dst_ip_match = if self_ips.is_empty() {
                true
            } else {
                self_ips.iter().any(|sip| ip_in_cidr(*sip, &dst.net))
            };
            if !dst_ip_match {
                continue;
            }
            let port_match = match &dst.ports {
                None => true,
                Some(range) => target_ports
                    .iter()
                    .any(|&p| p >= range.first && p <= range.last),
            };
            if port_match {
                return true;
            }
        }
    }
    false
}

fn ip_in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let c = cidr.trim();
    if c == "*" {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => ipv4_in_cidr(v4, c),
        IpAddr::V6(v6) => ipv6_in_cidr(v6, c),
    }
}

fn ipv4_in_cidr(ip: Ipv4Addr, cidr: &str) -> bool {
    let (net_str, prefix) = match cidr.split_once('/') {
        Some((n, p)) => match p.parse::<u32>() {
            Ok(v) if v <= 32 => (n, v),
            _ => return false,
        },
        None => (cidr, 32),
    };
    let Ok(net) = net_str.parse::<Ipv4Addr>() else {
        return false;
    };
    let mask = if prefix == 0 {
        0u32
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

fn ipv6_in_cidr(ip: Ipv6Addr, cidr: &str) -> bool {
    let (net_str, prefix) = match cidr.split_once('/') {
        Some((n, p)) => match p.parse::<u32>() {
            Ok(v) if v <= 128 => (n, v),
            _ => return false,
        },
        None => (cidr, 128),
    };
    let Ok(net) = net_str.parse::<Ipv6Addr>() else {
        return false;
    };
    let mask = if prefix == 0 {
        0u128
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from(ip) & mask) == (u128::from(net) & mask)
}

fn find_tailscale_bin() -> Option<PathBuf> {
    if let Some(path_var) = env::var_os("PATH") {
        for dir in env::split_paths(&path_var) {
            let cand = dir.join("tailscale");
            if cand.is_file() {
                return Some(cand);
            }
            #[cfg(windows)]
            {
                let exe = dir.join("tailscale.exe");
                if exe.is_file() {
                    return Some(exe);
                }
            }
        }
    }
    for fallback in [
        "/opt/homebrew/bin/tailscale",
        "/usr/local/bin/tailscale",
        "/usr/bin/tailscale",
        "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
    ] {
        let p = PathBuf::from(fallback);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

pub(crate) fn augmented_path() -> std::ffi::OsString {
    let mut dirs_vec: Vec<PathBuf> = Vec::new();
    if let Some(home) = dirs::home_dir() {
        dirs_vec.push(home.join(".local").join("bin"));
    }
    for extra in ["/opt/homebrew/bin", "/usr/local/bin"] {
        let p = PathBuf::from(extra);
        if p.is_dir() {
            dirs_vec.push(p);
        }
    }
    if let Some(existing) = env::var_os("PATH") {
        dirs_vec.extend(env::split_paths(&existing));
    }
    env::join_paths(dirs_vec).unwrap_or_else(|_| env::var_os("PATH").unwrap_or_default())
}

pub(crate) fn split_command_line(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;

    for ch in input.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            } else {
                cur.push(ch);
            }
            continue;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            continue;
        }
        if ch.is_whitespace() {
            if !cur.is_empty() {
                args.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(ch);
        }
    }
    if !cur.is_empty() {
        args.push(cur);
    }
    args
}

fn validate_server_name(name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("server name '{name}' must contain only ASCII letters, digits, '-' or '_'");
    }
    Ok(())
}
