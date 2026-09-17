#!/usr/bin/env bash
# MATRIX SHIELD — XDP DDoS protection installer (qwen-filter engine) for Linux VPS (x86_64 + systemd)
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

# Bundled UI extras: <dest>|<source>|<embedded-var-name>
EXTRA_FILES='
/usr/local/bin/matrix-shield|matrix-shield-status|MSX_STATUS
/usr/local/lib/matrix-shield/matrix-shield-dashboard.py|matrix-shield-dashboard.py|MSX_DASH
/usr/local/lib/matrix-shield/chart.umd.min.js|chart.umd.min.js|MSX_CHART
/etc/matrix-shield/banner.txt|matrix-shield-banner.txt|MSX_BANNER
'

IFACE="${1:-${QWEN_IFACE:-}}"

log()  { printf '\033[1;32m[qwen]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[qwen]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[qwen]\033[0m ERROR: %s\n' "$*" >&2; exit 1; }

banner() {
  [ -f "$ROOT/etc/matrix-shield/banner.txt" ] || return 0
  if [ -t 1 ]; then
    printf '\033[38;5;208m'
    cat "$ROOT/etc/matrix-shield/banner.txt"
    printf '\033[0m'
  else
    cat "$ROOT/etc/matrix-shield/banner.txt"
  fi
}

if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    warn "Not root — re-executing with sudo ..."
    exec sudo bash "$0" "$@"
  else
    die "run as root (or install sudo)"
  fi
fi

log "=== MATRIX SHIELD installer ==="

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

log "Installing MATRIX SHIELD UI (dashboard, status CLI, login banner) ..."
while IFS='|' read -r dest src var; do
  [ -z "$dest" ] && continue
  b64="${!var:-}"
  [ -z "$b64" ] && continue
  obj="$TMP/x-${src##*/}"
  printf '%s' "$b64" | base64 -d > "$obj"
  tgt="$ROOT$dest"
  mkdir -p "$(dirname "$tgt")"
  case "$dest" in
    */matrix-shield) install -m 0755 "$obj" "$tgt" ;;
    *) install -m 0644 "$obj" "$tgt" ;;
  esac
  log "Installed $tgt"
done <<< "$EXTRA_FILES"

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
  l7_rps: 40
  l7_burst: 120
  icmp_rps: 10
  icmp_burst: 20
  fin_pps: 20
  rst_pps: 20
  drop_reflector_ports: true
  drop_known_payloads: true
  tls_handshake_limit: 50
  default_block_ttl: 120
  auto_block_threshold: 10000
  auto_block_interval_secs: 3
  minecraft:
    enabled: true
    hit_count: 80
    hit_count_reset_secs: 5
    player_idle_timeout_secs: 60
    online_names: true
  ssh:
    enabled: true
    max_connections_per_ip: 10
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
Description=Matrix Shield (qwen-filter) — XDP DDoS protection on $IFACE
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

DASH_UNIT="$UNIT_DIR/matrix-shield-dashboard.service"
cat > "$DASH_UNIT" <<EOF
[Unit]
Description=Matrix Shield Dashboard — live status web UI
After=$BIN_NAME.service

[Service]
Type=simple
Environment=METRICS_URL=http://127.0.0.1:1999/metrics
ExecStart=/usr/bin/python3 /usr/local/lib/matrix-shield/matrix-shield-dashboard.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
log "Wrote systemd unit: $DASH_UNIT"

PROFILE="$ROOT/etc/profile.d/matrix-shield.sh"
mkdir -p "$(dirname "$PROFILE")"
cat > "$PROFILE" <<'SH'
# Matrix Shield — show branded banner once per SSH session
if [ -t 0 ] && [ -z "${MATRIX_SHIELD_SHOWN:-}" ] && [ -x /usr/local/bin/matrix-shield ]; then
  export MATRIX_SHIELD_SHOWN=1
  /usr/local/bin/matrix-shield --motd
fi
SH
log "Wrote SSH login banner: $PROFILE"

if [ -n "$PREFIX" ]; then
  warn "Staging mode (QWEN_PREFIX=$PREFIX) — systemd not touched"
  ls -l "$ROOT/usr/local/bin/$BIN_NAME" "$ROOT/usr/local/bin/matrix-shield" 2>/dev/null
  exit 0
fi

systemctl daemon-reload
systemctl enable "$BIN_NAME.service" >/dev/null 2>&1 || true
systemctl enable matrix-shield-dashboard.service >/dev/null 2>&1 || true
systemctl restart "$BIN_NAME.service" || true
systemctl restart matrix-shield-dashboard.service || true
sleep 2
systemctl --no-pager --full status "$BIN_NAME.service" || true

if command -v ufw >/dev/null 2>&1 && ufw status >/dev/null 2>&1; then
  if ufw allow 9090/tcp >/dev/null 2>&1; then
    log "ufw: allowed 9090/tcp (dashboard)"
  else
    log "ufw present but 9090 not opened - run 'ufw allow 9090/tcp' if needed"
  fi
fi

LOCAL_IP="$(curl -fsS --max-time 2 https://ifconfig.me 2>/dev/null || true)"
[ -n "$LOCAL_IP" ] || LOCAL_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"

[ -f "$ROOT/etc/matrix-shield/banner.txt" ] && banner
log "=== DONE — MATRIX SHIELD ACTIVE ==="
log "Filter : systemctl status $BIN_NAME.service"
log "CLI    : matrix-shield        (live status, run as root)"
log "Web    : http://${LOCAL_IP:-<vps-ip>}:9090   (live dashboard — MS_BIND=127.0.0.1 to lock to localhost)"
log "Login  : every SSH login shows the MATRIX SHIELD banner"
log "Logs   : journalctl -u $BIN_NAME.service -f"
log "Config : $CONF_DIR/config.yaml"