#!/usr/bin/env python3
"""Matrix Shield node agent — reads local engine metrics and reports them to
the central MATRIX SHIELD panel every 3s. Config: /etc/matrix-shield/node.conf
  PANEL=http://<panel-ip>:9090
  TOKEN=<registration token from the panel "+" button>
"""
import json
import os
import subprocess
import time
import urllib.request

CONF = "/etc/matrix-shield/node.conf"
SVC = "qwen-filter.service"
ATTACK_KEYS = [
    "xdpguard_dropped_pps", "xdpguard_syn_rate_dropped_per_sec",
    "xdpguard_udp_amp_dropped_per_sec", "xdpguard_frag_dropped_per_sec",
    "xdpguard_bogon_dropped_per_sec", "xdpguard_l7_rate_dropped_per_sec",
    "xdpguard_tls_dropped_per_sec", "xdpguard_icmp_dropped_per_sec",
    "xdpguard_fin_rst_dropped_per_sec", "xdpguard_ssh_dropped_per_sec",
]


def sh(args):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=3).stdout.strip()
    except Exception:
        return ""


def fetch_metrics():
    data = {}
    try:
        with urllib.request.urlopen("http://127.0.0.1:1999/metrics", timeout=3) as r:
            for line in r.read().decode().splitlines():
                if line.startswith("#") or " " not in line:
                    continue
                key, _, val = line.partition(" ")
                try:
                    data[key] = float(val)
                except ValueError:
                    pass
    except Exception:
        pass
    return data


def load_conf():
    c = {}
    try:
        for line in open(CONF):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                c[k.strip()] = v.strip().strip('"')
    except Exception:
        pass
    return c


def engine_iface():
    iface = "auto"
    unit = "/etc/systemd/system/%s" % SVC
    if os.path.isfile(unit):
        try:
            for line in open(unit):
                if line.startswith("ExecStart="):
                    parts = line.split("=", 1)[1].split()
                    iface = next((p for p in parts[1:] if not p.startswith(("-", "/"))), iface)
                    break
        except Exception:
            pass
    return iface


def main():
    while True:
        try:
            c = load_conf()
            url = c.get("PANEL", "").strip()
            tok = c.get("TOKEN", "").strip()
            if url and tok:
                m = fetch_metrics()
                m["_attack_live_pps"] = sum(float(m.get(k, 0)) for k in ATTACK_KEYS)
                payload = json.dumps({
                    "token": tok,
                    "name": sh(["hostname"]) or "node",
                    "state": sh(["systemctl", "is-active", SVC]) or "unknown",
                    "uptime": sh(["systemctl", "show", SVC, "-p", "ActiveEnterTimestamp", "--value"]),
                    "iface": engine_iface(),
                    "m": m,
                }).encode()
                req = urllib.request.Request(
                    url.rstrip("/") + "/report",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                )
                urllib.request.urlopen(req, timeout=5)
        except Exception:
            pass
        time.sleep(3)


if __name__ == "__main__":
    main()