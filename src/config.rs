use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub const DEFAULT_MAX_HOPS: usize = 3;
pub const DEFAULT_WATCH_POLL_SECS: u64 = 5;
pub const DEFAULT_PUSH_INTERVAL_SECS: u64 = 15;
pub const DEFAULT_SNAPSHOT_INTERVAL_SECS: u64 = 120;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopnetConfig {
    /// Active server exposure transports: `tailscale`, `cloudflare`, `direct` (VPN/ZeroTier/LAN allowlisted proxy)
    #[serde(default)]
    pub transports: Vec<String>,
    /// Local VPN/ZeroTier/WireGuard/LAN IP(s) to bind when using the `direct` allowlisted server proxy
    #[serde(default)]
    pub bind_ips: Vec<String>,
    /// Rewrite HTTP `Host` header to `127.0.0.1:<port>` on `direct` / `cloudflare` proxy connections
    #[serde(default = "default_true")]
    pub rewrite_host: bool,
    /// Poll interval in seconds for `hop serve watch` (clamped 2..=60)
    #[serde(default = "default_poll_secs")]
    pub poll_secs: u64,
    /// Automatically prune exposed routes whose local upstream stops listening during `sync` / `watch`
    #[serde(default = "default_true")]
    pub auto_prune: bool,
    /// Optional base domain for Cloudflare subdomain URLs (e.g. "example.net" -> https://<slug>.example.net)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_domain: Option<String>,
    /// Optional static Cloudflare Tunnel origin hostname for this device (e.g. "origin-laptop.example.net")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_host: Option<String>,
    /// Optional loopback port (127.0.0.1) for local Cloudflare Tunnel ingress router inside `hop serve watch`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress_port: Option<u16>,
    /// Env var holding shared secret verified on `X-Hop-Ingress-Secret`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress_secret_env: Option<String>,
    /// File path (0600) holding shared secret verified on `X-Hop-Ingress-Secret`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress_secret_file: Option<String>,
    /// Optional HTTPS endpoint receiving `hop.heartbeat/v1` POST updates from `hop serve watch`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_url: Option<String>,
    /// Env var holding bearer token for heartbeat/snapshot POST requests
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_token_env: Option<String>,
    /// File path (0600) holding bearer token for heartbeat/snapshot POST requests
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_token_file: Option<String>,
    /// Heartbeat push interval in seconds (clamped 5..=300; also pushes immediately on server change)
    #[serde(default = "default_push_interval_secs")]
    pub push_interval_secs: u64,
    /// Optional endpoint receiving periodic JSON snapshot payloads (e.g. dashboard telemetry)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_url: Option<String>,
    /// Optional command producing a JSON snapshot on stdout for `snapshot_url`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_cmd: Option<String>,
    /// Interval in seconds between periodic snapshot pushes (clamped 30..=3600)
    #[serde(default = "default_snapshot_interval_secs")]
    pub snapshot_interval_secs: u64,
}

impl Default for HopnetConfig {
    fn default() -> Self {
        Self {
            transports: Vec::new(),
            bind_ips: Vec::new(),
            rewrite_host: true,
            poll_secs: DEFAULT_WATCH_POLL_SECS,
            auto_prune: true,
            public_domain: None,
            origin_host: None,
            ingress_port: None,
            ingress_secret_env: None,
            ingress_secret_file: None,
            push_url: None,
            push_token_env: None,
            push_token_file: None,
            push_interval_secs: DEFAULT_PUSH_INTERVAL_SECS,
            snapshot_url: None,
            snapshot_cmd: None,
            snapshot_interval_secs: DEFAULT_SNAPSHOT_INTERVAL_SECS,
        }
    }
}

impl HopnetConfig {
    pub fn effective_poll_secs(&self) -> u64 {
        self.poll_secs.clamp(2, 60)
    }

    pub fn effective_push_interval_secs(&self) -> u64 {
        self.push_interval_secs.clamp(5, 300)
    }

    pub fn effective_snapshot_interval_secs(&self) -> u64 {
        self.snapshot_interval_secs.clamp(30, 3600)
    }

    /// Effective enabled exposure backends.
    /// Defaults to `["tailscale"]`, automatically adding `"direct"` when `bind_ips` is set
    /// and `"cloudflare"` when `ingress_port` or `origin_host` is configured.
    pub fn effective_transports(&self) -> Vec<String> {
        if !self.transports.is_empty() {
            return self
                .transports
                .iter()
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
        }
        let mut out = vec!["tailscale".to_string()];
        if !self.bind_ips.is_empty() {
            out.push("direct".to_string());
        }
        if self.ingress_port.is_some() || self.origin_host.is_some() {
            out.push("cloudflare".to_string());
        }
        out
    }

    pub fn uses_transport(&self, name: &str) -> bool {
        self.effective_transports()
            .iter()
            .any(|t| t.eq_ignore_ascii_case(name))
    }

    pub fn resolve_ingress_secret(&self) -> Option<String> {
        resolve_secret(
            self.ingress_secret_env.as_deref(),
            self.ingress_secret_file.as_deref(),
        )
    }

    pub fn resolve_push_token(&self) -> Option<String> {
        resolve_secret(
            self.push_token_env.as_deref(),
            self.push_token_file.as_deref(),
        )
    }
}

fn default_true() -> bool {
    true
}

fn default_poll_secs() -> u64 {
    DEFAULT_WATCH_POLL_SECS
}

fn default_push_interval_secs() -> u64 {
    DEFAULT_PUSH_INTERVAL_SECS
}

fn default_snapshot_interval_secs() -> u64 {
    DEFAULT_SNAPSHOT_INTERVAL_SECS
}

pub fn expand_tilde_path(raw: &str) -> PathBuf {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(rest);
    }
    PathBuf::from(trimmed)
}

pub fn resolve_secret(env_name: Option<&str>, file_path: Option<&str>) -> Option<String> {
    if let Some(var) = env_name.map(str::trim).filter(|s| !s.is_empty())
        && let Ok(val) = env::var(var)
    {
        let t = val.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    if let Some(raw_path) = file_path.map(str::trim).filter(|s| !s.is_empty()) {
        let p = expand_tilde_path(raw_path);
        if let Ok(raw) = fs::read_to_string(p) {
            let t = raw.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HopConfig {
    /// Optional name for this local machine (e.g. "laptop")
    #[serde(default)]
    pub self_name: Option<String>,
    /// Maximum acyclic hop count (default 3)
    #[serde(default = "default_max_hops")]
    pub max_hops: usize,
    /// Optional external CLI commands emitting JSON server arrays (e.g. `["kern servers --all --json"]`)
    #[serde(default)]
    pub server_sources: Vec<String>,
    /// Optional external CLI status probes (e.g. `{ caf = "caf status --json" }`) included in fleet reports and heartbeats
    #[serde(default)]
    pub status_sources: BTreeMap<String, String>,
    /// Additional trusted non-SSH peer names or IPs (e.g. mobile devices on Tailscale/ZeroTier/VPN)
    #[serde(default)]
    pub trusted_peers: Vec<String>,
    /// Formal hopnet exposure and sync configuration
    #[serde(default)]
    pub hopnet: HopnetConfig,
    #[serde(default)]
    pub devices: BTreeMap<String, Device>,
}

fn default_max_hops() -> usize {
    DEFAULT_MAX_HOPS
}

impl HopConfig {
    pub fn effective_max_hops(&self) -> usize {
        self.max_hops.clamp(1, 4)
    }

    pub fn self_label(&self) -> String {
        if let Some(s) = &self.self_name
            && !s.trim().is_empty()
        {
            return s.trim().to_string();
        }
        if let Ok(out) = std::process::Command::new("hostname").arg("-s").output()
            && out.status.success()
        {
            let h = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !h.is_empty() {
                return h;
            }
        }
        "local".to_string()
    }

    pub fn relay_aliases_for(&self, target: &str) -> Vec<String> {
        if let Some(dev) = self.devices.get(target)
            && !dev.via.is_empty()
        {
            return dev
                .via
                .iter()
                .filter(|r| r.as_str() != target)
                .cloned()
                .collect();
        }
        self.devices
            .iter()
            .filter(|(name, dev)| name.as_str() != target && dev.relay.unwrap_or(false))
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Lowercase identifiers (aliases, short DNS labels, full hostnames, IPs) of personal trusted peers.
    pub fn trusted_identifiers(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let self_lbl = self.self_label().to_ascii_lowercase();
        out.insert(self_lbl);

        for (alias, dev) in &self.devices {
            if !dev.trusted.unwrap_or(false) {
                continue;
            }
            out.insert(alias.to_ascii_lowercase());
            for h in &dev.hosts {
                insert_host_variants(&mut out, h);
            }
        }
        for peer in &self.trusted_peers {
            insert_host_variants(&mut out, peer);
        }
        out
    }

    /// Literal IPv4/IPv6 addresses configured on trusted devices and `trusted_peers` (plus loopback).
    pub fn trusted_ips(&self) -> BTreeSet<IpAddr> {
        let mut out = BTreeSet::new();
        out.insert(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        out.insert(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));

        let self_lbl = self.self_label();
        for (alias, dev) in &self.devices {
            if !dev.trusted.unwrap_or(false) && alias != &self_lbl {
                continue;
            }
            for h in &dev.hosts {
                if let Ok(ip) = h.trim().parse::<IpAddr>() {
                    out.insert(ip.to_canonical());
                }
            }
        }
        for peer in &self.trusted_peers {
            if let Ok(ip) = peer.trim().parse::<IpAddr>() {
                out.insert(ip.to_canonical());
            }
        }
        for bind in &self.hopnet.bind_ips {
            if let Ok(ip) = bind.trim().parse::<IpAddr>() {
                out.insert(ip.to_canonical());
            }
        }
        out
    }
}

/// Parses a `cf://<hostname>` Cloudflare Access SSH host specification.
pub fn parse_cloudflare_host(host: &str) -> Option<&str> {
    let trimmed = host.trim();
    let rest = trimmed
        .strip_prefix("cf://")
        .or_else(|| trimmed.strip_prefix("CF://"))?;
    let clean = rest.trim().trim_end_matches('/');
    (!clean.is_empty()).then_some(clean)
}

/// Produces a DNS-safe 1st-level subdomain label (`a-z`, `0-9`, `-`, max 63 chars).
pub fn slugify_label(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(63));
    let mut prev_dash = true;
    for ch in raw.chars() {
        let lower = ch.to_ascii_lowercase();
        if lower.is_ascii_alphanumeric() {
            if out.len() < 63 {
                out.push(lower);
            }
            prev_dash = false;
        } else if !prev_dash && out.len() < 63 {
            out.push('-');
            prev_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "app".to_string()
    } else {
        out
    }
}

/// Classifies a host address into a human transport label (`cloudflare`, `tailscale`, `lan`, `vpn`, or `dns`).
pub fn classify_host_transport(host: &str) -> &'static str {
    if parse_cloudflare_host(host).is_some() {
        return "cloudflare";
    }
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.ends_with(".ts.net") {
        return "tailscale";
    }
    if let Ok(ip) = h.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                if o[0] == 100 && (64..=127).contains(&o[1]) {
                    "tailscale"
                } else if o[0] == 192 && o[1] == 168 {
                    "lan"
                } else if o[0] == 10 {
                    "vpn/lan"
                } else if o[0] == 172 && (16..=31).contains(&o[1]) {
                    "vpn/zt"
                } else {
                    "direct-ip"
                }
            }
            IpAddr::V6(v6) => {
                let seg = v6.segments();
                if seg[0] == 0xfd7a && seg[1] == 0x115c && seg[2] == 0xa1e0 {
                    "tailscale"
                } else if (seg[0] & 0xfe00) == 0xfc00 {
                    "vpn"
                } else {
                    "direct-ip"
                }
            }
        };
    }
    "dns"
}

fn insert_host_variants(set: &mut BTreeSet<String>, raw: &str) {
    let trimmed = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() {
        return;
    }
    set.insert(trimmed.clone());
    if let Some((first, _)) = trimmed.split_once('.')
        && !first.chars().all(|c| c.is_ascii_digit())
    {
        set.insert(first.to_string());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// All candidate addresses (LAN, Tailscale, ZeroTier, DDNS) raced in parallel
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    /// Optional SSH private key path (e.g. `~/.ssh/id_ed25519_relay`)
    #[serde(default)]
    pub identity_file: Option<String>,
    /// Allow this device to serve as a 2-hop / 3-hop `ssh -J` relay node
    #[serde(default)]
    pub relay: Option<bool>,
    /// Optional explicit relay list for reaching this device
    #[serde(default)]
    pub via: Vec<String>,
    /// Auto-attach tmux on interactive ssh
    #[serde(default)]
    pub tmux: Option<bool>,
    /// Prefer Eternal Terminal (`et`) for 1-hop interactive ssh when installed
    #[serde(default)]
    pub use_et: Option<bool>,
    #[serde(default)]
    pub wol_mac: Option<String>,
    #[serde(default)]
    pub wol_via: Option<String>,
    #[serde(default)]
    pub boot_commands: BTreeMap<String, String>,
    /// Whether this device is a personal trusted peer allowed to access exposed private servers
    #[serde(default)]
    pub trusted: Option<bool>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServersFile {
    #[serde(default)]
    pub servers: Vec<FleetServerSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetServerSpec {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    pub port: u16,
    #[serde(default = "default_local_host")]
    pub host: String,
    #[serde(default = "default_scheme")]
    pub scheme: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

fn default_local_host() -> String {
    "127.0.0.1".to_string()
}

fn default_scheme() -> String {
    "http".to_string()
}

impl Device {
    pub fn ssh_port(&self) -> u16 {
        self.port.unwrap_or(22)
    }

    pub fn target_spec(&self, host: &str) -> String {
        match &self.user {
            Some(u) if !u.trim().is_empty() => format!("{u}@{host}"),
            _ => host.to_string(),
        }
    }

    pub fn expanded_identity_file(&self) -> Option<String> {
        let raw = self.identity_file.as_deref()?.trim();
        if raw.is_empty() {
            return None;
        }
        if let Some(rest) = raw.strip_prefix("~/")
            && let Some(home) = dirs::home_dir()
        {
            return Some(home.join(rest).display().to_string());
        }
        Some(raw.to_string())
    }

    /// Formats `user@host:port` for OpenSSH `-J` ProxyJump flags.
    pub fn jump_spec(&self, host: &str) -> String {
        let base = self.target_spec(host);
        match self.port {
            Some(p) if p != 22 => format!("{base}:{p}"),
            _ => base,
        }
    }
}

pub fn config_path() -> Result<PathBuf> {
    if let Ok(val) = env::var("HOP_CONFIG")
        && !val.trim().is_empty()
    {
        return Ok(PathBuf::from(val.trim()));
    }
    let home = dirs::home_dir().context("could not resolve home directory")?;
    Ok(home.join(".config").join("hop").join("devices.toml"))
}

pub fn cache_dir() -> Result<PathBuf> {
    if let Ok(val) = env::var("HOP_CACHE")
        && !val.trim().is_empty()
    {
        return Ok(PathBuf::from(val.trim()));
    }
    let home = dirs::home_dir().context("could not resolve home directory")?;
    Ok(home.join(".cache").join("hop"))
}

pub fn edges_cache_path() -> Result<PathBuf> {
    Ok(cache_dir()?.join("edges.json"))
}

pub fn direct_routes_path() -> Result<PathBuf> {
    Ok(cache_dir()?.join("direct-routes.json"))
}

pub fn ingress_state_path() -> Result<PathBuf> {
    Ok(cache_dir()?.join("ingress-routes.json"))
}

pub fn ephemeral_servers_path() -> Result<PathBuf> {
    Ok(cache_dir()?.join("ephemeral-servers.json"))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EphemeralServersFile {
    #[serde(default)]
    pub servers: Vec<EphemeralServerRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EphemeralServerRecord {
    pub name: String,
    pub slug: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default = "default_local_host")]
    pub host: String,
    pub port: u16,
    #[serde(default = "default_scheme")]
    pub scheme: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    pub created_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_unix: Option<u64>,
}

pub fn load_ephemeral_servers() -> EphemeralServersFile {
    let Ok(path) = ephemeral_servers_path() else {
        return EphemeralServersFile::default();
    };
    let Ok(raw) = fs::read_to_string(path) else {
        return EphemeralServersFile::default();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

pub fn save_ephemeral_servers(file: &EphemeralServersFile) -> Result<()> {
    let path = ephemeral_servers_path()?;
    ensure_parent(&path)?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_string_pretty(file)?)?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

pub fn servers_config_path() -> Result<PathBuf> {
    let cfg = config_path()?;
    let dir = cfg
        .parent()
        .context("could not resolve hop config directory")?;
    Ok(dir.join("servers.toml"))
}

pub fn load_servers_config() -> Result<ServersFile> {
    let path = servers_config_path()?;
    if !path.is_file() {
        return Ok(ServersFile::default());
    }
    let raw =
        fs::read_to_string(&path).with_context(|| format!("failed reading {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("invalid TOML in {}", path.display()))
}

pub fn save_servers_config(file: &ServersFile) -> Result<()> {
    let path = servers_config_path()?;
    ensure_parent(&path)?;
    let text = toml::to_string_pretty(file)?;
    fs::write(&path, text).with_context(|| format!("failed writing {}", path.display()))
}

pub fn load_config() -> Result<HopConfig> {
    let path = config_path()?;
    if !path.is_file() {
        bail!(
            "hop config not found at {}. Create it with [devices.<alias>] entries.",
            path.display()
        );
    }
    let raw =
        fs::read_to_string(&path).with_context(|| format!("failed reading {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("invalid TOML in {}", path.display()))
}

pub fn lookup<'a>(cfg: &'a HopConfig, alias: &str) -> Result<&'a Device> {
    cfg.devices.get(alias).with_context(|| {
        let avail: Vec<&str> = cfg.devices.keys().map(String::as_str).collect();
        format!(
            "unknown device '{alias}' (configured: {})",
            if avail.is_empty() {
                "none".to_string()
            } else {
                avail.join(", ")
            }
        )
    })
}

pub fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    Ok(())
}
