#![forbid(unsafe_code)]

mod config;
mod connect;
mod graph;
mod hopnet;
mod serve;
mod ui;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};

use crate::config::load_config;
use crate::serve::{FleetServerAddOptions, ServeUpOptions};

#[derive(Parser)]
#[command(
    name = "hop",
    version,
    about = "Trusted device network (hopnet) across LAN, Tailscale, ZeroTier, and custom VPNs: 1/2/3-hop SSH, tunnels, and automatic dev-server access"
)]
struct Cli {
    /// Emit machine-readable JSON
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show hopnet status: transports, trusted devices, one-way relays, and declared dev servers
    #[command(alias = "hopnet")]
    Net {
        /// Also query awake trusted peers in parallel
        #[arg(long)]
        fleet: bool,
    },
    /// Open a declared dev server from anywhere on your hopnet over the fastest available route
    Open {
        /// Server id (e.g. project:name), unique name, or project name
        target: String,
        /// Restrict lookup to a specific trusted device alias
        #[arg(long)]
        device: Option<String>,
        /// Local bind port when tunneling a remote server (defaults to matching remote port)
        #[arg(long)]
        local_port: Option<u16>,
        /// Require direct 1-hop only (disable 2/3-hop relays)
        #[arg(long)]
        direct: bool,
        /// Print the local URL without launching a browser
        #[arg(long)]
        no_browser: bool,
    },
    /// List configured devices (with optional live 1-hop reachability probe)
    Devices {
        #[arg(long)]
        check: bool,
    },
    /// Probe LAN/Tailscale/ZeroTier/VPN edges across relays and compute fastest 1/2/3-hop acyclic routes
    Probe {
        /// Probe only direct edges from this host (used internally by relay queries)
        #[arg(long)]
        local: bool,
    },
    /// Interactive shell via fastest 1/2/3-hop path (et/mosh/ssh -J + tmux)
    Ssh {
        device: String,
        #[arg(long)]
        raw_ssh: bool,
        #[arg(long)]
        mosh: bool,
        #[arg(long)]
        no_tmux: bool,
        /// Require direct 1-hop only (disable 2/3-hop relays)
        #[arg(long)]
        direct: bool,
    },
    /// Run a non-interactive command via fastest 1/2/3-hop path
    Run {
        device: String,
        #[arg(long)]
        direct: bool,
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Copy files via rsync over fastest 1/2/3-hop path (device:path)
    Cp {
        src: String,
        dst: String,
        #[arg(long)]
        direct: bool,
    },
    /// Forward a server or port locally over SSH (`hop tunnel <server>` or `hop tunnel <device> <target>`)
    Tunnel {
        /// Device alias (when passing 2 args) or server id/name across hopnet (when passing 1 arg)
        first: String,
        /// Remote port number or declared server id/name on `<first>`
        second: Option<String>,
        /// Local bind port (defaults to matching remote port)
        #[arg(long)]
        local_port: Option<u16>,
        /// Require direct 1-hop only (disable 2/3-hop relays)
        #[arg(long)]
        direct: bool,
    },
    /// Inspect, expose, sync, and watch hopnet dev servers across Tailscale and direct VPN/ZeroTier/LAN transports
    Serve {
        /// Also query awake trusted peer devices in parallel
        #[arg(long)]
        fleet: bool,
        #[command(subcommand)]
        action: Option<ServeAction>,
    },
    /// Send Wake-on-LAN locally or via a configured LAN relay
    Wake { device: String },
    /// Run a configured dual-boot/power target (e.g. `hop boot <device> <target>`)
    Boot { device: String, target: String },
}

#[derive(Subcommand)]
enum ServeAction {
    /// List project servers, fleet servers, active hopnet routes, and access audit
    Ls {
        /// Also query awake trusted peer devices in parallel
        #[arg(long)]
        fleet: bool,
    },
    /// Expose a local server (or `--all` running declared servers) to trusted hopnet peers
    Up {
        /// Server id (e.g. project:name), unique name, or local port (omit when using `--all`)
        target: Option<String>,
        /// Expose all currently running declared servers (same as `hop serve sync --no-prune`)
        #[arg(long)]
        all: bool,
        /// Tailnet HTTPS port (defaults to server port, or 443 for local port 80/443)
        #[arg(long)]
        https_port: Option<u16>,
        /// Register an ad-hoc/ephemeral server with a clean label (auto-prunes when process exits)
        #[arg(long)]
        name: Option<String>,
        /// Optional project tag for a labeled ephemeral server
        #[arg(long)]
        project: Option<String>,
        /// Optional description for a labeled ephemeral server
        #[arg(long)]
        desc: Option<String>,
        /// Optional TTL duration for a labeled ephemeral server (e.g. 30m, 4h, 1d)
        #[arg(long)]
        ttl: Option<String>,
        /// Register/expose without requiring Tailscale Serve (useful with Cloudflare/direct watch)
        #[arg(long)]
        local_only: bool,
        /// Preview actions without changing routes (used with `--all`)
        #[arg(long)]
        dry_run: bool,
        /// Override fail-closed check when untrusted peers have inbound access
        #[arg(long)]
        allow_untrusted: bool,
    },
    /// Push a one-shot hopnet heartbeat (and optional snapshot) to `[hopnet] push_url`
    Push {
        /// Print payload without posting
        #[arg(long)]
        dry_run: bool,
        /// Also run `[hopnet] snapshot_cmd` and push to `snapshot_url`
        #[arg(long)]
        with_snapshot: bool,
    },
    /// Reconcile declared servers once: expose all running servers and prune dead routes
    Sync {
        /// Preview exposure and prune changes without modifying routes
        #[arg(long)]
        dry_run: bool,
        /// Skip pruning stopped upstreams
        #[arg(long)]
        no_prune: bool,
        /// Override fail-closed check when untrusted peers have inbound access
        #[arg(long)]
        allow_untrusted: bool,
    },
    /// Continuously keep running declared servers available across Tailscale and/or direct allowlisted VPN/ZeroTier/LAN IPs
    Watch {
        /// Poll interval in seconds (overrides `[hopnet] poll_secs`, clamped 2..=60)
        #[arg(long)]
        interval: Option<u64>,
        /// Local VPN/ZeroTier/WireGuard/LAN interface IP(s) to bind direct allowlisted proxy (repeatable)
        #[arg(long = "bind")]
        bind_ips: Vec<String>,
        /// Override fail-closed check when untrusted peers have inbound access
        #[arg(long)]
        allow_untrusted: bool,
    },
    /// Install, inspect, or remove the background `hop serve watch` user service (launchd / systemd)
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },
    /// Stop serving a tailnet HTTPS route by server id/name/port (or `--all`)
    Down {
        /// Server id/name, upstream port, or exposed HTTPS port
        target: Option<String>,
        /// Reset all active tailscale serve routes on this device
        #[arg(long)]
        all: bool,
        /// Preview routes that would be stopped without changing Tailscale config
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove active tailscale serve routes whose local upstream port is down
    Prune {
        /// Preview stale routes that would be removed without changing Tailscale config
        #[arg(long)]
        dry_run: bool,
    },
    /// Register a non-project fleet server in ~/.config/hop/servers.toml
    Add {
        /// Short server name (e.g. proxmox, grafana)
        name: String,
        #[arg(long)]
        port: u16,
        /// Owning device alias from devices.toml (defaults to this device)
        #[arg(long)]
        device: Option<String>,
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Upstream scheme (`http` or `https`)
        #[arg(long, default_value = "http")]
        scheme: String,
        /// Optional mount path (e.g. `/ui`)
        #[arg(long)]
        path: Option<String>,
        #[arg(long)]
        description: Option<String>,
    },
    /// Remove a non-project fleet server from ~/.config/hop/servers.toml
    Rm {
        name: String,
        /// Restrict removal to a specific device alias
        #[arg(long)]
        device: Option<String>,
    },
}

#[derive(Subcommand)]
enum DaemonAction {
    /// Install and start the user-level `hop serve watch` background service
    Install {
        #[arg(long)]
        dry_run: bool,
    },
    /// Stop and remove the user-level `hop serve watch` background service
    Uninstall {
        #[arg(long)]
        dry_run: bool,
    },
    /// Show whether the background `hop serve watch` user service is installed and running
    Status,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = load_config()?;

    match cli.command {
        Commands::Net { fleet } => hopnet::cmd_net(&cfg, fleet, cli.json)?,
        Commands::Open {
            target,
            device,
            local_port,
            direct,
            no_browser,
        } => hopnet::cmd_open(
            &cfg,
            &target,
            device.as_deref(),
            local_port,
            direct,
            no_browser,
        )?,
        Commands::Devices { check } => connect::cmd_devices(&cfg, check, cli.json)?,
        Commands::Probe { local } => connect::cmd_probe(&cfg, local, cli.json)?,
        Commands::Ssh {
            device,
            raw_ssh,
            mosh,
            no_tmux,
            direct,
        } => connect::cmd_ssh(&cfg, &device, raw_ssh, mosh, no_tmux, direct)?,
        Commands::Run {
            device,
            direct,
            command,
        } => connect::cmd_run(&cfg, &device, &command, direct)?,
        Commands::Cp { src, dst, direct } => connect::cmd_cp(&cfg, &src, &dst, direct)?,
        Commands::Tunnel {
            first,
            second,
            local_port,
            direct,
        } => connect::cmd_tunnel(&cfg, &first, second.as_deref(), local_port, direct)?,
        Commands::Serve { fleet, action } => match action {
            None => serve::cmd_serve_ls(&cfg, fleet, cli.json)?,
            Some(ServeAction::Ls { fleet: sub_fleet }) => {
                serve::cmd_serve_ls(&cfg, fleet || sub_fleet, cli.json)?
            }
            Some(ServeAction::Up {
                target,
                all,
                https_port,
                name,
                project,
                desc,
                ttl,
                local_only,
                dry_run,
                allow_untrusted,
            }) => {
                if all {
                    hopnet::cmd_serve_sync(&cfg, dry_run, true, allow_untrusted)?;
                } else {
                    let Some(t) = target.as_deref() else {
                        bail!("missing <TARGET> (pass a server id/name/port, or `--all`)");
                    };
                    serve::cmd_serve_up(
                        &cfg,
                        ServeUpOptions {
                            target: t,
                            https_port,
                            allow_untrusted,
                            name: name.as_deref(),
                            project: project.as_deref(),
                            description: desc.as_deref(),
                            ttl: ttl.as_deref(),
                            local_only,
                        },
                    )?;
                }
            }
            Some(ServeAction::Push {
                dry_run,
                with_snapshot,
            }) => hopnet::cmd_serve_push(&cfg, dry_run, with_snapshot)?,
            Some(ServeAction::Sync {
                dry_run,
                no_prune,
                allow_untrusted,
            }) => hopnet::cmd_serve_sync(&cfg, dry_run, no_prune, allow_untrusted)?,
            Some(ServeAction::Watch {
                interval,
                bind_ips,
                allow_untrusted,
            }) => hopnet::cmd_serve_watch(&cfg, interval, &bind_ips, allow_untrusted)?,
            Some(ServeAction::Daemon { action }) => match action {
                DaemonAction::Install { dry_run } => hopnet::cmd_serve_daemon("install", dry_run)?,
                DaemonAction::Uninstall { dry_run } => {
                    hopnet::cmd_serve_daemon("uninstall", dry_run)?
                }
                DaemonAction::Status => hopnet::cmd_serve_daemon("status", false)?,
            },
            Some(ServeAction::Down {
                target,
                all,
                dry_run,
            }) => serve::cmd_serve_down(&cfg, target.as_deref(), all, dry_run)?,
            Some(ServeAction::Prune { dry_run }) => serve::cmd_serve_prune(&cfg, dry_run)?,
            Some(ServeAction::Add {
                name,
                port,
                device,
                host,
                scheme,
                path,
                description,
            }) => serve::cmd_serve_add(
                &cfg,
                FleetServerAddOptions {
                    name: &name,
                    port,
                    device: device.as_deref(),
                    host: &host,
                    scheme: &scheme,
                    path: path.as_deref(),
                    description: description.as_deref(),
                },
            )?,
            Some(ServeAction::Rm { name, device }) => {
                serve::cmd_serve_rm(&cfg, &name, device.as_deref())?
            }
        },
        Commands::Wake { device } => connect::cmd_wake(&cfg, &device)?,
        Commands::Boot { device, target } => connect::cmd_boot(&cfg, &device, &target)?,
    }
    Ok(())
}
