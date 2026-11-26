use std::io::IsTerminal;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::config::{Device, HopConfig, cache_dir, lookup, parse_cloudflare_host};
use crate::graph::{
    Route, RouteStep, load_graph_cache, measure_tcp_rtt, probe_cloudflare_host, probe_device_hosts,
    probe_fleet, probe_local, ranked_acyclic_routes, save_graph_cache,
};
use crate::ui::{Align, Style, Table, short_host, truncate};

const DIRECT_TIMEOUT: Duration = Duration::from_millis(850);
/// Margin (ms) by which a cached multi-hop route must beat a live 1-hop route to prefer hopping
const MULTIHOP_SPEEDUP_MARGIN_MS: f64 = 15.0;

pub fn cmd_devices(cfg: &HopConfig, check: bool, as_json: bool) -> Result<()> {
    if cfg.devices.is_empty() {
        println!("No devices configured.");
        return Ok(());
    }
    let st = Style::stdout();
    let self_label = cfg.self_label();
    if check {
        let graph = probe_local(cfg, DIRECT_TIMEOUT);
        if as_json {
            println!("{}", serde_json::to_string_pretty(&graph)?);
            return Ok(());
        }
        st.header("hop devices", Some(&format!("from {self_label}")));
        println!();
        let mut tbl = Table::new(
            2,
            &[
                ("DEVICE", Align::Left),
                ("STATE", Align::Left),
                ("RTT", Align::Right),
                ("HOST", Align::Left),
                ("ROLE", Align::Left),
                ("NOTES", Align::Left),
            ],
        );
        for (alias, dev) in &cfg.devices {
            let best = graph
                .edges
                .iter()
                .filter(|e| e.to == *alias)
                .min_by(|a, b| a.rtt_ms.total_cmp(&b.rtt_ms));
            let role = if alias == &self_label {
                st.green("local")
            } else if dev.trusted.unwrap_or(false) && dev.relay.unwrap_or(false) {
                st.cyan("trusted+relay")
            } else if dev.trusted.unwrap_or(false) {
                "trusted".to_string()
            } else if dev.relay.unwrap_or(false) {
                st.yellow("outbound")
            } else {
                st.dim("-")
            };
            let notes = dev
                .description
                .as_deref()
                .map(|d| st.dim(&truncate(d, 34)))
                .unwrap_or_default();
            if alias == &self_label {
                tbl.row(vec![
                    st.bold_cyan(alias),
                    st.green("● local"),
                    st.dim("-"),
                    st.dim("this device"),
                    role,
                    notes,
                ]);
            } else if let Some(e) = best {
                tbl.row(vec![
                    st.bold(alias),
                    st.green("● up"),
                    st.rtt(e.rtt_ms),
                    short_host(&e.host),
                    role,
                    notes,
                ]);
            } else {
                let first_host = dev
                    .hosts
                    .first()
                    .map(|h| short_host(h))
                    .unwrap_or_else(|| "-".to_string());
                tbl.row(vec![
                    st.dim(alias),
                    st.dim("· down"),
                    st.dim("-"),
                    st.dim(&first_host),
                    role,
                    notes,
                ]);
            }
        }
        tbl.print(&st);
        return Ok(());
    }

    if as_json {
        println!("{}", serde_json::to_string_pretty(&cfg.devices)?);
        return Ok(());
    }
    st.header(
        "hop devices",
        Some(&format!("{} configured", cfg.devices.len())),
    );
    println!();
    let mut tbl = Table::new(
        2,
        &[
            ("DEVICE", Align::Left),
            ("ROLE", Align::Left),
            ("HOSTS", Align::Left),
            ("NOTES", Align::Left),
        ],
    );
    for (alias, dev) in &cfg.devices {
        let is_self = alias == &self_label;
        let name = if is_self {
            st.bold_cyan(alias)
        } else {
            st.bold(alias)
        };
        let role = if is_self {
            st.green("local")
        } else if dev.trusted.unwrap_or(false) && dev.relay.unwrap_or(false) {
            st.cyan("trusted+relay")
        } else if dev.trusted.unwrap_or(false) {
            "trusted".to_string()
        } else if dev.relay.unwrap_or(false) {
            st.yellow("outbound")
        } else {
            st.dim("-")
        };
        let hosts = dev
            .hosts
            .iter()
            .map(|h| short_host(h))
            .collect::<Vec<_>>()
            .join(", ");
        let notes = dev
            .description
            .as_deref()
            .map(|d| st.dim(&truncate(d, 36)))
            .unwrap_or_default();
        tbl.row(vec![name, role, hosts, notes]);
    }
    tbl.print(&st);
    Ok(())
}

pub fn cmd_probe(cfg: &HopConfig, local_only: bool, as_json: bool) -> Result<()> {
    let graph = if local_only {
        probe_local(cfg, DIRECT_TIMEOUT)
    } else {
        let g = probe_fleet(cfg, DIRECT_TIMEOUT);
        let _ = save_graph_cache(&g);
        g
    };

    let max_hops = cfg.effective_max_hops();
    let mut best_routes = serde_json::Map::new();
    for alias in cfg.devices.keys() {
        if alias == &graph.self_node {
            continue;
        }
        let routes = ranked_acyclic_routes(&graph, &graph.self_node, alias, max_hops);
        best_routes.insert(alias.clone(), serde_json::to_value(routes)?);
    }

    if as_json {
        let out = serde_json::json!({
            "graph": graph,
            "routes": best_routes,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    let st = Style::stdout();
    st.header(
        "hop probe",
        Some(&format!(
            "from {}  ({} edges, max {} hops)",
            graph.self_node,
            graph.edges.len(),
            max_hops
        )),
    );
    println!();
    let mut rows_data: Vec<(String, Option<Route>, Vec<Route>)> = Vec::new();
    let mut any_alts = false;
    for alias in cfg.devices.keys() {
        if alias == &graph.self_node {
            continue;
        }
        let mut routes = ranked_acyclic_routes(&graph, &graph.self_node, alias, max_hops);
        let best = if routes.is_empty() {
            None
        } else {
            Some(routes.remove(0))
        };
        let alts: Vec<Route> = routes.into_iter().take(2).collect();
        if !alts.is_empty() {
            any_alts = true;
        }
        rows_data.push((alias.clone(), best, alts));
    }

    let mut tbl = if any_alts {
        Table::new(
            2,
            &[
                ("DEVICE", Align::Left),
                ("BEST ROUTE", Align::Left),
                ("RTT", Align::Right),
                ("ALTERNATES", Align::Left),
            ],
        )
    } else {
        Table::new(
            2,
            &[
                ("DEVICE", Align::Left),
                ("BEST ROUTE", Align::Left),
                ("RTT", Align::Right),
            ],
        )
    };
    for (alias, best, alts) in rows_data {
        match best {
            Some(b) => {
                let mut row = vec![st.bold(&alias), b.compact_path(), st.rtt(b.total_rtt_ms)];
                if any_alts {
                    let alt_str = alts
                        .iter()
                        .map(|r| format!("{} ({:.0}ms)", r.compact_path(), r.total_rtt_ms))
                        .collect::<Vec<_>>()
                        .join(", ");
                    row.push(st.dim(&alt_str));
                }
                tbl.row(row);
            }
            None => {
                let mut row = vec![st.dim(&alias), st.dim("unreachable"), st.dim("-")];
                if any_alts {
                    row.push(String::new());
                }
                tbl.row(row);
            }
        }
    }
    tbl.print(&st);
    Ok(())
}

/// Selects the fastest reachable acyclic route (1, 2, or 3 hops).
/// Automatically prefers 2-hop or 3-hop if it beats 1-hop latency OR if all 1-hop routes fail.
pub fn select_route(cfg: &HopConfig, alias: &str, direct_only: bool) -> Result<Route> {
    let dev = lookup(cfg, alias)?;
    let direct_hits = probe_device_hosts(dev, DIRECT_TIMEOUT);
    let direct_route = direct_hits.first().map(|(host, rtt)| Route {
        target: alias.to_string(),
        steps: vec![RouteStep {
            alias: alias.to_string(),
            host: host.clone(),
            rtt_ms: *rtt,
        }],
        total_rtt_ms: *rtt,
    });

    if direct_only {
        return direct_route.with_context(|| {
            format!(
                "all direct hosts unreachable for '{alias}': {}",
                dev.hosts.join(", ")
            )
        });
    }

    // Check cached multi-hop routes (2-hop & 3-hop) if faster than direct OR if direct failed
    let max_hops = cfg.effective_max_hops();
    if let Some(cache) = load_graph_cache() {
        let candidates = ranked_acyclic_routes(&cache, &cache.self_node, alias, max_hops);
        let multihop: Vec<Route> = candidates
            .into_iter()
            .filter(|r| r.hop_count() >= 2)
            .collect();

        for cand in multihop.into_iter().take(2) {
            let worth_trying = match &direct_route {
                None => true,
                Some(d) => cand.total_rtt_ms + MULTIHOP_SPEEDUP_MARGIN_MS < d.total_rtt_ms,
            };
            if worth_trying && verify_multihop_route(cfg, &cand) {
                return Ok(cand);
            }
        }
    }

    if let Some(d) = direct_route {
        return Ok(d);
    }

    // Live 2-hop fallback when no edge cache exists yet: race configured relay peers in parallel
    let relays = cfg.relay_aliases_for(alias);
    if !relays.is_empty()
        && let Some(route) = race_live_two_hop(cfg, alias, dev, &relays)
    {
        return Ok(route);
    }

    bail!("no reachable 1..={max_hops} hop route to '{alias}' (run `hop probe` to map relay edges)")
}

fn verify_multihop_route(cfg: &HopConfig, route: &Route) -> bool {
    let Some(first) = route.steps.first() else {
        return false;
    };
    let port = cfg
        .devices
        .get(&first.alias)
        .map(Device::ssh_port)
        .unwrap_or(22);
    // Fast pre-check on first hop before running SSH jump verify
    if let Some(cf_host) = parse_cloudflare_host(&first.host) {
        if probe_cloudflare_host(cf_host, Duration::from_millis(1800)).is_none() {
            return false;
        }
    } else if measure_tcp_rtt(&first.host, port, Duration::from_millis(700)).is_none() {
        return false;
    }
    let Ok(mut cmd) = build_ssh_command(cfg, route, false, true) else {
        return false;
    };
    cmd.arg("true")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd.status().is_ok_and(|s| s.success())
}

fn race_live_two_hop(
    cfg: &HopConfig,
    target_alias: &str,
    target_dev: &Device,
    relays: &[String],
) -> Option<Route> {
    let mut handles = Vec::new();
    for relay_alias in relays {
        let Some(relay_dev) = cfg.devices.get(relay_alias).cloned() else {
            continue;
        };
        let cfg_clone = cfg.clone();
        let r_alias = relay_alias.clone();
        let t_alias = target_alias.to_string();
        let t_dev = target_dev.clone();

        handles.push(thread::spawn(move || {
            let r_hits = probe_device_hosts(&relay_dev, Duration::from_millis(700));
            let (r_host, r_rtt) = r_hits.first()?.clone();
            for t_host in &t_dev.hosts {
                let start = Instant::now();
                let cand = Route {
                    target: t_alias.clone(),
                    steps: vec![
                        RouteStep {
                            alias: r_alias.clone(),
                            host: r_host.clone(),
                            rtt_ms: r_rtt,
                        },
                        RouteStep {
                            alias: t_alias.clone(),
                            host: t_host.clone(),
                            rtt_ms: 0.0,
                        },
                    ],
                    total_rtt_ms: r_rtt,
                };
                if verify_multihop_route(&cfg_clone, &cand) {
                    let elapsed = (start.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0;
                    let mut final_route = cand;
                    final_route.total_rtt_ms = elapsed;
                    return Some(final_route);
                }
            }
            None
        }));
    }

    let mut found: Vec<Route> = handles
        .into_iter()
        .filter_map(|h| h.join().ok().flatten())
        .collect();
    found.sort_by(|a, b| a.total_rtt_ms.total_cmp(&b.total_rtt_ms));
    found.into_iter().next()
}

pub fn cmd_ssh(
    cfg: &HopConfig,
    alias: &str,
    raw_ssh: bool,
    use_mosh: bool,
    no_tmux: bool,
    direct_only: bool,
) -> Result<()> {
    let dev = lookup(cfg, alias)?;
    let route = select_route(cfg, alias, direct_only)?;
    eprintln!("[hop] {alias} via {}", route.summary());

    // 1-hop fast paths: mosh or Eternal Terminal (`et`) when requested/available (not for cf:// tunnels)
    if route.hop_count() == 1 && parse_cloudflare_host(&route.steps[0].host).is_none() {
        let host = &route.steps[0].host;
        let target = dev.target_spec(host);

        if use_mosh && command_exists("mosh") {
            let mut cmd = Command::new("mosh");
            cmd.arg(&target);
            if dev.tmux.unwrap_or(false) && !no_tmux {
                cmd.args(["--", "tmux", "new", "-As", "hop"]);
            }
            return run_interactive(cmd);
        }

        if !raw_ssh
            && dev.use_et.unwrap_or(true)
            && command_exists("et")
            && measure_tcp_rtt(host, 2022, Duration::from_millis(350)).is_some()
        {
            let mut cmd = Command::new("et");
            cmd.arg(&target);
            if dev.tmux.unwrap_or(false) && !no_tmux {
                cmd.args([
                    "-c",
                    "if command -v tmux >/dev/null 2>&1; then exec tmux new -As hop; elif [ -x /opt/homebrew/bin/tmux ]; then exec /opt/homebrew/bin/tmux new -As hop; else exec ${SHELL:-/bin/sh} -l; fi",
                ]);
            }
            return run_interactive(cmd);
        }
    }

    let mut cmd = build_ssh_command(cfg, &route, true, false)?;
    if dev.tmux.unwrap_or(false) && !no_tmux {
        cmd.args([
            "-t",
            "if command -v tmux >/dev/null 2>&1; then exec tmux new -As hop; elif [ -x /opt/homebrew/bin/tmux ]; then exec /opt/homebrew/bin/tmux new -As hop; else exec ${SHELL:-/bin/sh} -l; fi",
        ]);
    }
    run_interactive(cmd)
}

pub fn cmd_run(cfg: &HopConfig, alias: &str, command: &[String], direct_only: bool) -> Result<()> {
    if command.is_empty() {
        bail!("missing remote command (usage: hop run <device> -- <command...>)");
    }
    let route = select_route(cfg, alias, direct_only)?;
    let batch = !std::io::stdin().is_terminal();
    let mut cmd = build_ssh_command(cfg, &route, true, batch)?;
    cmd.args(command);
    run_interactive(cmd)
}

pub(crate) fn run_remote_capture(
    cfg: &HopConfig,
    alias: &str,
    command: &[String],
    direct_only: bool,
) -> Result<String> {
    if command.is_empty() {
        bail!("missing remote command");
    }
    let route = select_route(cfg, alias, direct_only)?;
    let mut cmd = build_ssh_command(cfg, &route, true, true)?;
    cmd.args(command).stdin(Stdio::null());
    let output = cmd
        .output()
        .with_context(|| format!("failed spawning ssh to '{alias}'"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        bail!(
            "remote command on '{alias}' exited with {}: {}",
            output.status,
            if stderr.is_empty() {
                "no stderr"
            } else {
                &stderr
            }
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub fn cmd_tunnel(
    cfg: &HopConfig,
    first: &str,
    second: Option<&str>,
    local_port: Option<u16>,
    direct_only: bool,
) -> Result<()> {
    let (alias, remote_host, remote_port, label) = match second {
        Some(target) => {
            let (h, p, lbl) =
                crate::serve::resolve_remote_tunnel_target(cfg, first, target, direct_only)?;
            (first.to_string(), h, p, lbl)
        }
        None => {
            let loc = crate::hopnet::find_server_across_hopnet(cfg, first, None)?;
            if loc.is_local {
                println!(
                    "[hopnet] `{}` is already local at {}://127.0.0.1:{}",
                    loc.id, loc.scheme, loc.port
                );
                return Ok(());
            }
            (loc.device, loc.host, loc.port, loc.id)
        }
    };
    let bind_port = local_port.unwrap_or(remote_port);
    let route = select_route(cfg, &alias, direct_only)?;
    eprintln!(
        "[hopnet] tunnel http://127.0.0.1:{bind_port} -> {alias} ({label} @ {remote_host}:{remote_port}) via {}",
        route.summary()
    );
    eprintln!("[hopnet] press Ctrl-C to close tunnel");

    let forward_spec = format!("127.0.0.1:{bind_port}:{remote_host}:{remote_port}");
    let flags = vec![
        "-N".to_string(),
        "-o".to_string(),
        "ExitOnForwardFailure=yes".to_string(),
        "-L".to_string(),
        forward_spec,
    ];
    let cmd = build_ssh_command_with_flags(cfg, &route, false, false, &flags)?;
    run_interactive(cmd)
}

pub fn cmd_cp(cfg: &HopConfig, src: &str, dst: &str, direct_only: bool) -> Result<()> {
    let mut ssh_transport: Option<String> = None;
    let batch = !std::io::stdin().is_terminal();

    let mut resolve_spec = |spec: &str| -> Result<String> {
        if let Some((alias, path)) = spec.split_once(':')
            && let Some(dev) = cfg.devices.get(alias)
        {
            let route = select_route(cfg, alias, direct_only)?;
            eprintln!("[hop] cp {alias} via {}", route.summary());
            let final_step = route.steps.last().context("empty route")?;
            let jump_str = build_jump_arg(cfg, &route);
            let mut ssh_cmd = String::from("ssh -o StrictHostKeyChecking=accept-new");
            if batch {
                ssh_cmd.push_str(" -o BatchMode=yes -o ConnectTimeout=5");
            }
            if let Some(j) = jump_str {
                ssh_cmd.push_str(&format!(" -J {j}"));
            }
            if let Some(p) = dev.port {
                ssh_cmd.push_str(&format!(" -p {p}"));
            }
            if let Some(key) = dev.expanded_identity_file() {
                ssh_cmd.push_str(&format!(" -i {key} -o IdentitiesOnly=yes"));
            }
            let effective_host = if let Some(cf_host) = parse_cloudflare_host(&final_step.host) {
                let cf_bin = find_cloudflared_bin()
                    .context("cloudflared binary required for cf:// host but not found in PATH")?;
                ssh_cmd.push_str(&format!(
                    " -o 'ProxyCommand={cf_bin} access ssh --hostname {cf_host}'"
                ));
                cf_host.to_string()
            } else {
                final_step.host.clone()
            };
            ssh_transport = Some(ssh_cmd);
            return Ok(format!("{}:{path}", dev.target_spec(&effective_host)));
        }
        Ok(spec.to_string())
    };

    let resolved_src = resolve_spec(src)?;
    let resolved_dst = resolve_spec(dst)?;

    let mut cmd = Command::new("rsync");
    cmd.args(["-az", "--partial", "--info=progress2"]);
    if let Some(e) = ssh_transport {
        cmd.args(["-e", &e]);
    }
    cmd.arg(&resolved_src).arg(&resolved_dst);
    run_interactive(cmd)
}

pub fn cmd_wake(cfg: &HopConfig, alias: &str) -> Result<()> {
    let dev = lookup(cfg, alias)?;
    let mac = dev
        .wol_mac
        .as_deref()
        .context("device has no `wol_mac` configured in devices.toml")?;

    if let Some(relay_alias) = &dev.wol_via {
        let remote_py = format!(
            "python3 -c 'import socket; m=bytes.fromhex({:?}.replace(\":\",\"\").replace(\"-\",\"\")); s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1); s.sendto(b\"\\xff\"*6+m*16,(\"255.255.255.255\",9))'",
            mac
        );
        cmd_run(cfg, relay_alias, &[remote_py], false)?;
        println!("Sent Wake-on-LAN packet to {alias} ({mac}) via {relay_alias}");
        return Ok(());
    }

    send_magic_packet(mac)?;
    println!("Sent local Wake-on-LAN packet to {alias} ({mac})");
    Ok(())
}

pub fn cmd_boot(cfg: &HopConfig, alias: &str, target_os: &str) -> Result<()> {
    let dev = lookup(cfg, alias)?;
    let remote_cmd = dev.boot_commands.get(target_os).with_context(|| {
        let avail: Vec<&str> = dev.boot_commands.keys().map(String::as_str).collect();
        format!(
            "no boot_commands.{target_os} configured for {alias} (available: {})",
            if avail.is_empty() {
                "none".to_string()
            } else {
                avail.join(", ")
            }
        )
    })?;
    cmd_run(cfg, alias, std::slice::from_ref(remote_cmd), false)
}

fn build_jump_arg(cfg: &HopConfig, route: &Route) -> Option<String> {
    if route.steps.len() <= 1 {
        return None;
    }
    let hops: Vec<String> = route.steps[..route.steps.len() - 1]
        .iter()
        .map(|s| match cfg.devices.get(&s.alias) {
            Some(dev) => dev.jump_spec(&s.host),
            None => s.host.clone(),
        })
        .collect();
    Some(hops.join(","))
}

pub(crate) fn build_ssh_command(
    cfg: &HopConfig,
    route: &Route,
    multiplex: bool,
    batch: bool,
) -> Result<Command> {
    build_ssh_command_with_flags(cfg, route, multiplex, batch, &[])
}

pub(crate) fn build_ssh_command_with_flags(
    cfg: &HopConfig,
    route: &Route,
    multiplex: bool,
    batch: bool,
    extra_flags: &[String],
) -> Result<Command> {
    let final_step = route.steps.last().context("empty route")?;
    let target_dev = lookup(cfg, &final_step.alias)?;
    let cf_target = parse_cloudflare_host(&final_step.host);
    let effective_host = cf_target.unwrap_or(&final_step.host);
    let target = target_dev.target_spec(effective_host);

    let mut cmd = Command::new("ssh");
    if multiplex {
        let ctrl_dir: PathBuf = cache_dir()?.join("ssh-ctl");
        let _ = std::fs::create_dir_all(&ctrl_dir);
        cmd.args([
            "-o",
            "ControlMaster=auto",
            "-o",
            &format!("ControlPath={}", ctrl_dir.join("%C").display()),
            "-o",
            "ControlPersist=10m",
        ]);
    }
    if batch {
        cmd.args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=4"]);
        // Prevent OpenSSH ProxyJump (`-J`) child processes from opening /dev/tty for passwords
        cmd.env("SSH_ASKPASS", "/usr/bin/false")
            .env("SSH_ASKPASS_REQUIRE", "force");
    } else {
        cmd.args(["-o", "ConnectTimeout=8"]);
    }
    cmd.args([
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
    ]);
    if let Some(cf_host) = cf_target {
        let cf_bin = find_cloudflared_bin()
            .context("cloudflared binary required for cf:// host but not found in PATH")?;
        cmd.args([
            "-o",
            &format!("ProxyCommand={cf_bin} access ssh --hostname {cf_host}"),
        ]);
    } else if let Some(jump) = build_jump_arg(cfg, route) {
        cmd.args(["-J", &jump]);
    }
    if let Some(p) = target_dev.port {
        cmd.args(["-p", &p.to_string()]);
    }
    if let Some(key) = target_dev.expanded_identity_file() {
        cmd.args(["-i", &key, "-o", "IdentitiesOnly=yes"]);
    }
    cmd.args(extra_flags);
    cmd.arg(target);
    Ok(cmd)
}

fn run_interactive(mut cmd: Command) -> Result<()> {
    let status = cmd
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("failed spawning remote connection command")?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

pub(crate) fn find_cloudflared_bin() -> Option<String> {
    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let cand = dir.join("cloudflared");
            if cand.is_file() {
                return Some(cand.display().to_string());
            }
            #[cfg(windows)]
            {
                let exe = dir.join("cloudflared.exe");
                if exe.is_file() {
                    return Some(exe.display().to_string());
                }
            }
        }
    }
    for fallback in [
        "/opt/homebrew/bin/cloudflared",
        "/usr/local/bin/cloudflared",
        "/usr/bin/cloudflared",
    ] {
        let p = PathBuf::from(fallback);
        if p.is_file() {
            return Some(fallback.to_string());
        }
    }
    None
}

pub(crate) fn command_exists(bin: &str) -> bool {
    let Some(path_var) = std::env::var_os("PATH") else {
        return false;
    };
    for dir in std::env::split_paths(&path_var) {
        if dir.join(bin).is_file() {
            return true;
        }
        #[cfg(windows)]
        for ext in [".exe", ".cmd", ".bat"] {
            if dir.join(format!("{bin}{ext}")).is_file() {
                return true;
            }
        }
    }
    false
}

fn send_magic_packet(mac_str: &str) -> Result<()> {
    let clean: String = mac_str.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() != 12 {
        bail!("invalid MAC address '{mac_str}'");
    }
    let mut mac = [0u8; 6];
    for i in 0..6 {
        mac[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16)?;
    }
    let mut packet = Vec::with_capacity(102);
    packet.extend_from_slice(&[0xff; 6]);
    for _ in 0..16 {
        packet.extend_from_slice(&mac);
    }
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_broadcast(true)?;
    sock.send_to(&packet, "255.255.255.255:9")?;
    Ok(())
}
