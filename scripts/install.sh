#!/usr/bin/env bash
set -euo pipefail

# Standalone macOS & Linux installer for hop.
# Usage:
#   ./scripts/install.sh                    # build & install hop into ~/.local/bin
#   ./scripts/install.sh --bin-dir /usr/local/bin

BIN_DIR="${HOP_BIN_DIR:-$HOME/.local/bin}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin-dir) BIN_DIR="${2:?--bin-dir requires a directory}"; shift 2 ;;
    -h|--help)
      cat <<'EOF'
Usage: ./scripts/install.sh [OPTIONS]
  --bin-dir <dir>   Target directory for the hop binary (default: ~/.local/bin)
EOF
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "==> Building hop (release)..."
cargo build --release --manifest-path "$REPO_DIR/Cargo.toml"

mkdir -p "$BIN_DIR"
cp "$REPO_DIR/target/release/hop" "$BIN_DIR/hop.new"
chmod 755 "$BIN_DIR/hop.new"
mv -f "$BIN_DIR/hop.new" "$BIN_DIR/hop"

echo "==> Installed $BIN_DIR/hop ($("$BIN_DIR/hop" --version))"

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    echo "Note: $BIN_DIR is not on your PATH. Add this to your shell rc file:"
    echo "  export PATH=\"$BIN_DIR:\$PATH\""
    ;;
esac
