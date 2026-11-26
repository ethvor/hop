use std::env;
use std::io::IsTerminal;
use std::process::{Command, Stdio};

/// Terminal styling helper that respects `NO_COLOR`, `CLICOLOR`, and TTY detection.
#[derive(Debug, Clone, Copy)]
pub struct Style {
    color: bool,
    width: usize,
}

impl Style {
    pub fn stdout() -> Self {
        let is_tty = std::io::stdout().is_terminal();
        let no_color = env::var_os("NO_COLOR").is_some();
        let force_color = env::var("CLICOLOR_FORCE").ok().as_deref() == Some("1");
        let dumb = env::var("TERM").ok().as_deref() == Some("dumb");
        let color = !no_color && !dumb && (is_tty || force_color);
        let width = detect_term_width(is_tty);
        Self { color, width }
    }

    fn wrap(&self, code: &str, text: &str) -> String {
        if !self.color || text.is_empty() {
            text.to_string()
        } else {
            format!("\x1b[{code}m{text}\x1b[0m")
        }
    }

    pub fn bold(&self, text: &str) -> String {
        self.wrap("1", text)
    }

    pub fn dim(&self, text: &str) -> String {
        self.wrap("2", text)
    }

    pub fn green(&self, text: &str) -> String {
        self.wrap("32", text)
    }

    pub fn yellow(&self, text: &str) -> String {
        self.wrap("33", text)
    }

    pub fn red(&self, text: &str) -> String {
        self.wrap("31", text)
    }

    pub fn cyan(&self, text: &str) -> String {
        self.wrap("36", text)
    }

    pub fn bold_cyan(&self, text: &str) -> String {
        self.wrap("1;36", text)
    }

    pub fn header(&self, title: &str, subtitle: Option<&str>) {
        match subtitle {
            Some(sub) if !sub.is_empty() => {
                println!("{}  {}", self.bold_cyan(title), self.dim(sub));
            }
            _ => println!("{}", self.bold_cyan(title)),
        }
    }

    pub fn section(&self, title: &str) {
        println!("\n{}", self.bold(title));
    }

    /// Prints an indented wrapped line (e.g. peer list or footnote) within terminal width.
    pub fn wrapped_labeled(&self, indent: usize, label: &str, items: &[String], sep: &str) {
        let prefix = format!("{}{label} ", " ".repeat(indent));
        let prefix_vis = visible_len(&prefix);
        let max_w = self.width.max(60);

        if items.is_empty() {
            println!("{prefix}{}", self.dim("none"));
            return;
        }

        let mut line = prefix;
        let mut line_vis = prefix_vis;
        let sep_vis = visible_len(sep);
        let cont_indent = " ".repeat(indent + 2);
        let cont_vis = indent + 2;

        for (i, item) in items.iter().enumerate() {
            let item_vis = visible_len(item);
            let need_sep = i > 0;
            let extra = item_vis + if need_sep { sep_vis } else { 0 };

            if line_vis > prefix_vis && line_vis + extra > max_w {
                if need_sep {
                    line.push_str(sep.trim_end());
                }
                println!("{line}");
                line = format!("{cont_indent}{item}");
                line_vis = cont_vis + item_vis;
            } else {
                if need_sep {
                    line.push_str(sep);
                    line_vis += sep_vis;
                }
                line.push_str(item);
                line_vis += item_vis;
            }
        }
        println!("{line}");
    }

    /// Prints a dim wrapped note/tip that never splits mid-word.
    pub fn note(&self, indent: usize, text: &str) {
        let max_w = self.width.saturating_sub(indent).max(40);
        let pad = " ".repeat(indent);
        let mut cur = String::new();
        for word in text.split_whitespace() {
            if !cur.is_empty() && cur.len() + 1 + word.len() > max_w {
                println!("{pad}{}", self.dim(&cur));
                cur.clear();
            }
            if !cur.is_empty() {
                cur.push(' ');
            }
            cur.push_str(word);
        }
        if !cur.is_empty() {
            println!("{pad}{}", self.dim(&cur));
        }
    }

    /// Formats a latency value cleanly with subtle color cues.
    pub fn rtt(&self, rtt_ms: f64) -> String {
        let text = if rtt_ms >= 100.0 {
            format!("{:.0}ms", rtt_ms)
        } else {
            format!("{:.1}ms", rtt_ms)
        };
        if rtt_ms < 25.0 {
            self.green(&text)
        } else if rtt_ms < 120.0 {
            self.yellow(&text)
        } else {
            self.dim(&text)
        }
    }

    pub fn state_badge(&self, kind: &str, up: Option<bool>) -> String {
        match (kind, up) {
            ("unregistered", Some(false)) => self.yellow("▲ stale"),
            ("unregistered", Some(true)) => self.green("● live"),
            ("ephemeral", Some(true)) => self.green("● live"),
            (_, Some(true)) => self.green("● up"),
            (_, Some(false)) => self.dim("· down"),
            (_, None) => self.cyan("○ remote"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Align {
    Left,
    Right,
}

/// Clean ANSI-aware column table with dynamic widths and zero box clutter.
pub struct Table {
    indent: usize,
    headers: Vec<(String, Align)>,
    rows: Vec<Vec<String>>,
}

impl Table {
    pub fn new(indent: usize, headers: &[(&str, Align)]) -> Self {
        Self {
            indent,
            headers: headers
                .iter()
                .map(|(h, a)| ((*h).to_string(), *a))
                .collect(),
            rows: Vec::new(),
        }
    }

    pub fn row(&mut self, cells: Vec<String>) {
        self.rows.push(cells);
    }

    pub fn print(&self, st: &Style) {
        let cols = self.headers.len();
        if cols == 0 {
            return;
        }
        let mut widths: Vec<usize> = self.headers.iter().map(|(h, _)| visible_len(h)).collect();
        for row in &self.rows {
            for (i, cell) in row.iter().enumerate().take(cols) {
                widths[i] = widths[i].max(visible_len(cell));
            }
        }

        let pad = " ".repeat(self.indent);

        // Header line
        let mut hdr = String::new();
        for (i, (label, align)) in self.headers.iter().enumerate() {
            if i > 0 {
                hdr.push_str("  ");
            }
            let styled = st.dim(label);
            if i + 1 == cols && matches!(align, Align::Left) {
                hdr.push_str(&styled);
            } else {
                hdr.push_str(&pad_cell(&styled, widths[i], *align));
            }
        }
        println!("{pad}{hdr}");

        // Data rows
        for row in &self.rows {
            let mut line = String::new();
            for (i, (_, align)) in self.headers.iter().enumerate() {
                if i > 0 {
                    line.push_str("  ");
                }
                let cell = row.get(i).map(String::as_str).unwrap_or("");
                if i + 1 == cols && matches!(align, Align::Left) {
                    line.push_str(cell);
                } else {
                    line.push_str(&pad_cell(cell, widths[i], *align));
                }
            }
            println!("{pad}{line}");
        }
    }
}

/// Strips ANSI CSI escape sequences and counts Unicode scalar display width (simple BMP-safe count).
pub fn visible_len(s: &str) -> usize {
    let mut len = 0usize;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            chars.next();
            for esc in chars.by_ref() {
                if ('@'..='~').contains(&esc) {
                    break;
                }
            }
            continue;
        }
        len += 1;
    }
    len
}

fn pad_cell(text: &str, width: usize, align: Align) -> String {
    let vis = visible_len(text);
    if vis >= width {
        return text.to_string();
    }
    let gap = " ".repeat(width - vis);
    match align {
        Align::Left => format!("{text}{gap}"),
        Align::Right => format!("{gap}{text}"),
    }
}

/// Shortens long Tailscale MagicDNS suffixes and `cf://` prefixes for compact display.
pub fn short_host(host: &str) -> String {
    if let Some(cf) = crate::config::parse_cloudflare_host(host) {
        return format!("cf:{cf}");
    }
    if let Some((first, rest)) = host.split_once('.')
        && rest.ends_with(".ts.net")
    {
        return first.to_string();
    }
    host.to_string()
}

/// Truncates a plain (non-ANSI) string on a word boundary when exceeding `max_chars`.
pub fn truncate(s: &str, max_chars: usize) -> String {
    let count = s.chars().count();
    if count <= max_chars || max_chars < 4 {
        return s.to_string();
    }
    let slice: String = s.chars().take(max_chars - 1).collect();
    let trimmed = match slice.rfind(' ') {
        Some(idx) if idx > max_chars / 2 => slice[..idx].trim_end(),
        _ => slice.trim_end(),
    };
    format!("{trimmed}…")
}

fn detect_term_width(is_tty: bool) -> usize {
    if let Ok(raw) = env::var("COLUMNS")
        && let Ok(cols) = raw.trim().parse::<usize>()
        && cols >= 40
    {
        return cols;
    }
    if is_tty
        && let Ok(out) = Command::new("stty")
            .arg("size")
            .stdin(Stdio::inherit())
            .stderr(Stdio::null())
            .output()
        && out.status.success()
    {
        let text = String::from_utf8_lossy(&out.stdout);
        if let Some(cols_str) = text.split_whitespace().nth(1)
            && let Ok(cols) = cols_str.parse::<usize>()
            && cols >= 40
        {
            return cols;
        }
    }
    100
}
