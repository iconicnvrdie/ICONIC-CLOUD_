# MATRIX SHIELD — DDoS Protection

XDP/BPF based multi-service DDoS filter for Linux VPS (Minecraft, FiveM, SSH, HTTPS).
Works on any x86_64 VPS running systemd.

Comes with a full UI package:
- **Web dashboard** at `http://<vps-ip>:9090` — live glowing Matrix-style status page (auto-refresh 2s)
- **`matrix-shield` CLI** — live threat stats right in the terminal
- **SSH login banner** — shows the Matrix Shield ASCII art + protection status on every login

## Install on any VPS (one-liner)

```bash
curl -fsSL https://raw.githubusercontent.com/iconicnvrdie/ICONIC-CLOUD_/main/qwen-filter-install.sh | sudo bash
```

Pass the network interface explicitly (auto-detected otherwise):

```bash
curl -fsSL https://raw.githubusercontent.com/iconicnvrdie/ICONIC-CLOUD_/main/qwen-filter-install.sh | sudo bash -s eth0
```

## What the installer does

- Installs the binary to `/usr/local/bin/qwen-filter`
- Installs the Matrix Shield UI:
  - `/usr/local/bin/matrix-shield` — CLI status command
  - `/usr/local/lib/matrix-shield/matrix-shield-dashboard.py` — web dashboard (port 9090, `MS_BIND=127.0.0.1` to lock to localhost)
  - `/etc/matrix-shield/banner.txt` — login banner
- Writes default config to `/etc/qwen-filter/config.yaml` (ports 25565 Minecraft / 30120 FiveM / 22 SSH / 443 HTTPS)
- Creates + enables `qwen-filter.service` and `matrix-shield-dashboard.service`
- Adds the Matrix Shield banner to SSH logins (`/etc/profile.d/matrix-shield.sh`)
- Opens port 9090 in ufw if present

## Management

```bash
matrix-shield                           # live CLI dashboard
matrix-shield --json                    # machine-readable stats
systemctl status qwen-filter.service     # filter status
journalctl -u qwen-filter.service -f     # live engine logs
```

Web dashboard: `http://<vps-ip>:9090`

## Rebuild the bundled installer

`qwen-filter-install.sh` is `install-qwen.sh` + the `qwen-filter` binary + the
Matrix Shield UI files packed into one self-contained script:

```bash
bash pack.sh                            # regenerates qwen-filter-install.sh
```

Source layout:
- `install-qwen.sh` — installer logic
- `matrix-shield/matrix-shield-status` — CLI status command
- `matrix-shield/matrix-shield-dashboard.py` — web dashboard
- `matrix-shield/matrix-shield-banner.txt` — ASCII banner
- `config.yaml` — default filter config