# hop

**Your trusted device network (hopnet) across every VPN and LAN you already have, making SSH and dev servers available everywhere over the best working route.**

`hop` is a single-binary Rust CLI that unifies your machines into a **hopnet** over any combination of LAN, Tailscale, ZeroTier, WireGuard, or custom VPNs. It races every configured address and relay to find the fastest working 1/2/3-hop path for shells, commands, file copies, and port tunnels, and keeps your declared development servers automatically reachable across your trusted devices only.

---

## Why hop?

- **One network across every transport:** List each machine's LAN, Tailscale, ZeroTier, WireGuard, or Cloudflare SSH tunnel addresses in `devices.toml`. `hop` probes them and picks the fastest working route, falling back through 2- or 3-hop relays when direct paths fail.
- **Dev servers reachable from your devices only:** Run `hop open <server>` from any computer to find where a dev server is running and tunnel straight to it. For phones and browsers, `hop serve` exposes running servers privately over Tailscale HTTPS, a direct VPN/LAN allowlist, or a Cloudflare Tunnel ingress, never publicly.
- **Safe one-way relays:** Mark helper machines `relay = true` and `trusted = false` so you can jump through them when direct routes drop without letting them reach your servers.

---

## Configuration & CLI

### `~/.config/hop/devices.toml`

```toml
self_name = "laptop"
max_hops = 3
server_sources = ["kern servers --all --json"]  # optional external JSON server registries
trusted_peers = ["ethvor-ipad", "ethvor-iphone"]  # optional non-SSH trusted devices (names or IPs)

[status_sources]
# Optional pluggable per-device status commands included in fleet JSON and heartbeats
caf = "caf status --json"

[hopnet]
# Exposure backends: "tailscale" (fail-closed HTTPS), "cloudflare" (local ingress + heartbeat), and/or "direct"
transports = ["tailscale", "cloudflare"]
bind_ips = []        # optional local ZeroTier/WireGuard/LAN IP(s) for direct allowlisted proxy
rewrite_host = true  # rewrite HTTP Host header to 127.0.0.1:<port> on direct/cloudflare ingress
poll_secs = 5
auto_prune = true
# Optional Cloudflare Tunnel local ingress + dashboard heartbeat push:
# public_domain = "example.net"
# origin_host = "origin-laptop.example.net"
# ingress_port = 7780
# ingress_secret_file = "~/.config/hop/ingress.secret"
# push_url = "https://example.net/api/hop/heartbeat"
# push_token_file = "~/.config/hop/push.token"
# push_interval_secs = 15

[devices.homelab]
hosts = ["192.168.1.50", "ethvor-homelab.tail1234.ts.net", "172.29.10.50"]
user = "ethvor"
identity_file = "~/.ssh/id_ed25519"
relay = true
tmux = true
use_et = true
trusted = true

[devices.workstation]
hosts = ["192.168.1.80", "172.29.10.80"]
user = "ethvor"
tmux = true
trusted = true
wol_mac = "aa:bb:cc:dd:ee:ff"
wol_via = "homelab"

[devices.regional-relay]
hosts = ["relay-node.tail1234.ts.net"]
user = "relay"
relay = true
trusted = false
```

Non-project fleet servers live in `~/.config/hop/servers.toml` (`hop serve add` / `rm`). If you use Tailscale with shared or relay-only nodes, lock down inbound access in your Tailscale ACLs: `hop serve` checks your active Tailscale access rules before exposing anything and refuses to serve if any untrusted device could reach it.

### Commands

| Command | Description |
|---|---|
| `hop net [--fleet]` | Show hopnet transports, trusted devices, one-way relays, and declared servers (alias: `hop hopnet`) |
| `hop open <server> [--device <d>] [--local-port N]` | Find a running server across trusted devices, tunnel over the best route, and open locally |
| `hop devices [--check]` | List configured devices (with optional live 1-hop RTT probe) |
| `hop probe [--local]` | Probe edges across relays and cache fastest 1/2/3-hop acyclic routes |
| `hop ssh <device> [--raw-ssh \| --mosh \| --no-tmux \| --direct]` | Interactive shell via fastest path (`et`/`mosh`/`ssh -J` + optional `tmux`) |
| `hop run <device> [--direct] -- <cmd...>` | Run a non-interactive command on `<device>` |
| `hop cp <src> <dst> [--direct]` | Copy files via `rsync` (`device:path`) over fastest path |
| `hop tunnel <server>` / `hop tunnel <device> <target>` | Forward a hopnet server or remote port locally over SSH |
| `hop serve [ls] [--fleet]` | List project + fleet servers, active Tailscale and direct routes, and access audit |
| `hop serve up <target \| --all> [--name <slug> --project <p> --ttl 4h]` | Expose a declared server or register a labeled ephemeral preview (fail-closed) |
| `hop serve down` / `prune` | Stop serving routes or prune dead upstreams |
| `hop serve push [--dry-run] [--with-snapshot]` | Push a one-shot `hop.heartbeat/v1` update (and optional snapshot) to `push_url` |
| `hop serve sync [--dry-run]` | One-shot reconcile: expose running declared servers and prune dead routes |
| `hop serve watch [--bind <ip>]` | Continuously auto-expose running servers on Tailscale, Cloudflare ingress, and/or allowlisted direct VPN/LAN IPs and push heartbeats |
| `hop serve daemon install \| uninstall \| status` | Manage optional `launchd` / `systemd --user` background service for `hop serve watch` |
| `hop serve add \| rm <name> ...` | Manage non-project fleet servers in `~/.config/hop/servers.toml` |
| `hop wake <device>` / `hop boot <device> <target>` | Send Wake-on-LAN or run a configured dual-boot target |

Global flag: `--json` (machine-readable output for `net`, `devices`, `probe`, and `serve`).

---

## Setup

Requires Rust `1.88+` (`cargo`).

### Setup with an agent

Paste this prompt into any coding agent to handle installation and initial setup:

```text
Set up hop (https://github.com/ethvor/hop) on this machine:
1. Check that Rust 1.88+ (cargo) is installed.
2. Clone https://github.com/ethvor/hop.git and install the release binary using ./scripts/install.sh (macOS/Linux), .\scripts\install.ps1 (Windows PowerShell), or `cargo install --path hop`.
3. Ask me for my device aliases, hostnames/IPs (LAN, Tailscale, ZeroTier, or custom VPN), SSH users, relay nodes, trusted peers, and any server registries (such as `kern servers --all --json`), then create `~/.config/hop/devices.toml` (and optionally `~/.config/hop/servers.toml`).
4. Ask whether I want running declared servers auto-synced to my hopnet via `hop serve daemon install`.
5. Verify everything with `hop --version`, `hop probe`, `hop net`, and `hop serve`.
```

### Manual setup

#### 1. Install

**macOS / Linux:**

```bash
git clone https://github.com/ethvor/hop.git
cd hop && ./scripts/install.sh
```

**Windows (PowerShell):**

```powershell
git clone https://github.com/ethvor/hop.git
cd hop
.\scripts\install.ps1
```

**Any OS (Cargo):**

```bash
git clone https://github.com/ethvor/hop.git
cargo install --path hop
```

#### 2. Configure your hopnet and verify

Create `~/.config/hop/devices.toml` using the example above, then run:

```bash
hop probe
hop net
hop serve
```

Optional: enable automatic default exposure for running declared servers:

```bash
hop serve daemon install
```

---

## License

MIT. See [LICENSE](LICENSE).
