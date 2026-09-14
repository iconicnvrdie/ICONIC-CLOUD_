#!/usr/bin/env bash
# Qwen Filter — XDP DDoS protection installer for Linux VPS (x86_64 + systemd)
#
# Usage:
#   sudo bash qwen-filter-install.sh [interface]
#   curl -fsSL <URL> | sudo bash -s [interface]
#
# Options:
#   QWEN_URL    <url>   download the qwen-filter binary from a URL instead
#   QWEN_IFACE  name    force the network interface
#   QWEN_PREFIX path    staging mode, install under a prefix (testing only)
set -euo pipefail

BIN_NAME="qwen-filter"
PREFIX="${QWEN_PREFIX:-}"
QWEN_URL="${QWEN_URL:-}"
QWEN_EMBEDDED_BASE64=

IFACE="${1:-${QWEN_IFACE:-}}"

log()  { printf '\033[1;32m[qwen]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[qwen]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[qwen]\033[0m ERROR: %s\n' "$*" >&2; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    warn "Not root — re-executing with sudo ..."
    exec sudo bash "$0" "$@"
  else
    die "run as root (or install sudo)"
  fi
fi

log "=== Qwen Filter installer ==="

case "$(uname -m)" in
  x86_64|amd64) log "Arch: x86_64 OK" ;;
  *) die "qwen-filter is built for x86_64 only, this VPS is $(uname -m)" ;;
esac

command -v systemctl >/dev/null 2>&1 || die "systemd (systemctl) not found on this VPS"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
BIN="$TMP/$BIN_NAME"

if [ -n "$QWEN_EMBEDDED_BASE64" ]; then
  log "Extracting bundled binary ..."
  printf '%s' "$QWEN_EMBEDDED_BASE64" | base64 -d > "$BIN"
elif [ -n "$QWEN_URL" ]; then
  log "Downloading binary from $QWEN_URL ..."
  ( curl -fsSL --max-time 120 -o "$BIN" "$QWEN_URL" || wget -q -O "$BIN" "$QWEN_URL" ) \
    || die "failed to download binary"
elif [ -f "./$BIN_NAME" ]; then
  log "Using local ./$BIN_NAME"
  cp "./$BIN_NAME" "$BIN"
else
  die "no binary source (re-pack with the binary bundled, or set QWEN_URL)"
fi

chmod 0755 "$BIN"
if ! head -c4 "$BIN" | grep -q $'\x7fELF'; then
  die "source file is not a valid ELF executable"
fi
log "Binary OK ($(( $(wc -c < "$BIN") / 1024 )) KB)"

ROOT="$PREFIX"
INSTALL_DIR="$ROOT/usr/local/bin"
CONF_DIR="$ROOT/etc/qwen-filter"
UNIT_DIR="$ROOT/etc/systemd/system"
mkdir -p "$INSTALL_DIR" "$CONF_DIR" "$UNIT_DIR"

install -m 0755 "$BIN" "$INSTALL_DIR/$BIN_NAME"
log "Installed $INSTALL_DIR/$BIN_NAME"

CONF="$CONF_DIR/config.yaml"
if [ -s "$CONF" ]; then
  warn "keeping existing config: $CONF"
else
  cat > "$CONF" <<'YAML'
# Qwen Filter configuration — auto-created by the installer.
# Edit and restart the filter to apply changes.
filter:
  port_ranges:
    - { start: 25565, end: 25565, protocol: auto, service: auto }
    - { start: 30120, end: 30120, protocol: auto, service: auto }
    - { start: 22,     end: 22,     protocol: auto, service: auto }
    - { start: 443,    end: 443,    protocol: auto, service: auto }
  drop_fragments: true
  drop_bogon: true
  tcp_flag_check: true
  ttl_min: 32
  ttl_max: 255
  udp_pps: 2000
  udp_burst: 4000
  syn_pps: 200
  syn_burst: 400
  l7_rps: 5
  l7_burst: 15
  icmp_rps: 10
  icmp_burst: 20
  fin_pps: 20
  rst_pps: 20
  drop_reflector_ports: true
  drop_known_payloads: true
  tls_handshake_limit: 10
  default_block_ttl: 600
  auto_block_threshold: 200
  auto_block_interval_secs: 3
  minecraft:
    enabled: true
    hit_count: 10
    hit_count_reset_secs: 3
    player_idle_timeout_secs: 60
    online_names: true
  ssh:
    enabled: true
    max_connections_per_ip: 5
    connection_timeout_secs: 30
xdp:
  mode: auto
  max_pending_connections: 16384
  max_player_connections: 65535
  max_throttled_ips: 65535
  max_blacklisted_ips: 65536
  max_offenders: 65536
  max_rate_limit_entries: 262144
metrics:
  enabled: true
  addr: "127.0.0.1:1999"
  poll_secs: 1
logging:
  level: info
  file_max_mb: 100
YAML
  log "Wrote default config: $CONF"
fi

if [ -z "$IFACE" ]; then
  IFACE="$(ip route get 8.8.8.8 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1 || true)"
fi
IFACE="${IFACE:-eth0}"
log "Interface: $IFACE"

UNIT="$UNIT_DIR/$BIN_NAME.service"
cat > "$UNIT" <<EOF
[Unit]
Description=Qwen Filter — XDP DDoS protection on $IFACE
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/$BIN_NAME $IFACE --config $CONF_DIR/config.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
log "Wrote systemd unit: $UNIT"

if [ -n "$PREFIX" ]; then
  warn "Staging mode (QWEN_PREFIX=$PREFIX) — systemd not touched"
  ls -l "$ROOT/usr/local/bin/$BIN_NAME"
  exit 0
fi

systemctl daemon-reload
systemctl enable "$BIN_NAME.service"
systemctl restart "$BIN_NAME.service"
sleep 2
systemctl --no-pager --full status "$BIN_NAME.service" || true

log "=== DONE ==="
log "Status : systemctl status $BIN_NAME.service"
log "Restart: systemctl restart $BIN_NAME.service"
log "Logs   : journalctl -u $BIN_NAME.service -f"
log "Config : $CONF_DIR/config.yaml"