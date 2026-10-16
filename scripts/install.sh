#!/usr/bin/env bash
# Build netprobe and install it as a hardened systemd service on Linux.
#   sudo ./scripts/install.sh [path/to/targets.json]
set -euo pipefail

BIN_DIR=/usr/local/bin
CONF_DIR=/etc/netprobe
UNIT=/etc/systemd/system/netprobe.service
CONFIG_SRC="${1:-targets.example.json}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log() { printf '[install] %s\n' "$*"; }
die() { printf '[install] error: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root (sudo)"
[[ "$(uname -s)" == "Linux" ]] || die "systemd install is Linux-only"
command -v go >/dev/null || die "go toolchain not found in PATH"
command -v systemctl >/dev/null || die "systemctl not found"
[[ -f "$REPO_ROOT/$CONFIG_SRC" || -f "$CONFIG_SRC" ]] || die "config $CONFIG_SRC not found"

log "building binary"
( cd "$REPO_ROOT" && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o bin/netprobe ./cmd/netprobe )
install -m 0755 "$REPO_ROOT/bin/netprobe" "$BIN_DIR/netprobe"

log "creating service user"
id -u netprobe >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin netprobe

log "installing config to $CONF_DIR"
install -d -m 0755 "$CONF_DIR"
if [[ -f "$CONF_DIR/targets.json" ]]; then
  log "keeping existing $CONF_DIR/targets.json"
else
  [[ -f "$CONFIG_SRC" ]] || CONFIG_SRC="$REPO_ROOT/$CONFIG_SRC"
  install -m 0644 "$CONFIG_SRC" "$CONF_DIR/targets.json"
fi

log "validating config with a one-shot check"
"$BIN_DIR/netprobe" check -config "$CONF_DIR/targets.json" -retries 0 >/dev/null || \
  log "warning: some targets are currently unhealthy (service will still be installed)"

log "installing systemd unit"
install -m 0644 "$REPO_ROOT/deploy/netprobe.service" "$UNIT"
systemctl daemon-reload
systemctl enable --now netprobe.service

for _ in {1..10}; do
  if curl -fsS http://127.0.0.1:9115/readyz >/dev/null 2>&1; then
    log "netprobe is up: curl http://127.0.0.1:9115/metrics"
    exit 0
  fi
  sleep 1
done
die "service did not become ready; check: journalctl -u netprobe -n 50"
