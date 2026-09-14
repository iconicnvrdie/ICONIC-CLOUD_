# Qwen Filter — DDoS Protection Installer

XDP/BPF based multi-service DDoS filter for Linux VPS (Minecraft, FiveM, SSH, HTTPS).
Works on any x86_64 VPS running systemd.

## Install on any VPS (one-liner)

```bash
curl -fsSL https://raw.githubusercontent.com/iconicnvrdie/ICONIC-CLOUD_/main/qwen-filter-install.sh | sudo bash
```

Pass the network interface explicitly (auto-detected otherwise):

```bash
curl -fsSL https://raw.githubusercontent.com/iconicnvrdie/ICONIC-CLOUD_/main/qwen-filter-install.sh | sudo bash -s eth0
```

## What it does

- Installs the binary to `/usr/local/bin/qwen-filter`
- Writes default config to `/etc/qwen-filter/config.yaml` (ports 25565 Minecraft / 30120 FiveM / 22 SSH / 443 HTTPS)
- Creates + enables the `qwen-filter.service` systemd unit

## Management

```bash
systemctl status qwen-filter.service     # status
systemctl restart qwen-filter.service    # restart
journalctl -u qwen-filter.service -f     # live logs
```

## Rebuild the bundled installer

`qwen-filter-install.sh` is `install-qwen.sh` + the binary packed into one
self-contained script. After changing the binary or installer:

```bash
bash pack.sh            # regenerates qwen-filter-install.sh
curl -fsSL https://<host>/upload.sh-method > /dev/null  # or push to GitHub
```