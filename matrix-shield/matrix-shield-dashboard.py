#!/usr/bin/env python3
"""Matrix Shield — live DDoS protection dashboard (qwen-filter engine).
Read-only status page. Env: MS_BIND (0.0.0.0), MS_PORT (9090),
METRICS_URL (http://127.0.0.1:1999/metrics).
"""
import html
import json
import os
import socket
import subprocess
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIND = os.environ.get("MS_BIND", "0.0.0.0")
PORT = int(os.environ.get("MS_PORT", "9090"))
METRICS_URL = os.environ.get("METRICS_URL", "http://127.0.0.1:1999/metrics")
SVC = "qwen-filter.service"

CATS = [
    ("syn", "syn_rate_dropped", "SYN Flood"),
    ("udp", "udp_amp_dropped", "UDP Amplification"),
    ("frag", "frag_dropped", "Fragment Attack"),
    ("bog", "bogon_dropped", "Bogon Spoof"),
    ("l7", "l7_rate_dropped", "L7 Abuse"),
    ("tls", "tls_dropped", "TLS Handshake"),
    ("icmp", "icmp_dropped", "ICMP Flood"),
    ("fin", "fin_rst_dropped", "SYN/FIN Attack"),
    ("ack", "ack_invalid", "ACK Invalid"),
    ("ssh", "ssh_dropped", "SSH Brute"),
]


def sh(args):
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=3)
        return out.stdout.strip()
    except Exception:
        return ""


def fetch_metrics():
    data = {}
    try:
        with urllib.request.urlopen(METRICS_URL, timeout=3) as r:
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


def status():
    state = sh(["systemctl", "is-active", SVC]) or "unknown"
    uptime = sh(["systemctl", "show", SVC, "-p", "ActiveEnterTimestamp", "--value"])
    iface = "auto"
    unit = "/etc/systemd/system/%s" % SVC
    if os.path.isfile(unit):
        for line in open(unit):
            if line.startswith("ExecStart="):
                parts = line.split("=", 1)[1].split()
                iface = next((p for p in parts[1:] if not p.startswith(("-", "/"))), iface)
                break
    m = fetch_metrics()
    return {"state": state, "uptime": uptime, "iface": iface, "m": m}


def fmt_num(n):
    n = float(n or 0)
    for unit in ("", "K", "M", "B", "T"):
        if abs(n) < 1000:
            if unit == "":
                return "%.0f" % n
            return "%.2f%s" % (n, unit)
        n /= 1000.0
    return "%.2fT" % (n * 1000)


def fmt_bw(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return "%.1f %s" % (n, unit)
        n /= 1024.0


PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Matrix Shield — DDoS Protection</title>
<style>
:root { --bg:#05070a; --panel:#0b1118; --edge:#16222e; --green:#17e69a; --cyan:#22d6ff; --red:#ff3b5c; --dim:#5b7285; --txt:#cfe6d8; }
* { box-sizing:border-box; margin:0; padding:0; }
body { background:radial-gradient(1200px 600px at 50% -10%, #0d2b26 0%, var(--bg) 60%); color:var(--txt);
  font-family:'Segoe UI',system-ui,sans-serif; min-height:100vh; padding:24px 16px 40px; }
.wrap { max-width:1080px; margin:0 auto; }
.glow { text-shadow:0 0 6px rgba(23,230,154,.7), 0 0 24px rgba(23,230,154,.35); }
.hdr { text-align:center; margin-bottom:8px; }
.hdr .title { font-size:clamp(30px,6vw,56px); font-weight:900; letter-spacing:6px; color:var(--green); animation:pulse 3s infinite; }
.hdr .sub { color:var(--cyan); letter-spacing:8px; font-size:13px; margin-top:4px; font-family:Consolas,monospace; }
@keyframes pulse { 50% { text-shadow:0 0 18px rgba(23,230,154,1), 0 0 60px rgba(23,230,154,.5);} }
.status-line { text-align:center; font-family:Consolas,monospace; margin:14px 0 22px; font-size:14px; }
.dot { display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:8px; vertical-align:middle; }
.dot.up { background:var(--green); box-shadow:0 0 10px var(--green); animation:blink 1.2s infinite; }
.dot.down { background:var(--red); box-shadow:0 0 10px var(--red); }
@keyframes blink { 50% { opacity:.35; } }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:14px; }
.card { background:linear-gradient(180deg,var(--panel),#080d13); border:1px solid var(--edge); border-radius:12px; padding:16px 18px;
  position:relative; overflow:hidden; }
.card::after { content:''; position:absolute; left:0; top:0; height:2px; width:100%; background:linear-gradient(90deg,transparent,var(--green),transparent); opacity:.7; }
.card .k { color:var(--dim); font-size:12px; letter-spacing:2px; text-transform:uppercase; }
.card .v { font-size:26px; font-weight:700; margin-top:6px; font-family:Consolas,monospace; color:var(--green); }
.card .v.red { color:var(--red); }
.card .v.cyan { color:var(--cyan); }
.attack { background:linear-gradient(180deg,var(--panel),#080d13); border:1px solid var(--edge); border-radius:12px; padding:18px; margin-top:18px; }
.attack h2 { color:var(--cyan); font-size:14px; letter-spacing:3px; text-transform:uppercase; margin-bottom:14px; }
.bar { display:grid; grid-template-columns:180px 1fr 90px; align-items:center; gap:12px; margin-bottom:9px; font-size:13px; }
.bar .lbl { color:var(--txt); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.bar .trk { background:#0c1319; border-radius:20px; height:10px; overflow:hidden; }
.bar .fill { height:100%; border-radius:20px; background:linear-gradient(90deg,#0a9e6e,var(--green)); width:0%; transition:width .6s; }
.bar .val { font-family:Consolas,monospace; text-align:right; color:var(--green); }
.foot { text-align:center; color:var(--dim); font-size:12px; margin-top:26px; letter-spacing:1px; font-family:Consolas,monospace; }
.mono { font-family:Consolas,monospace; }
@media (max-width:600px){ .bar { grid-template-columns:120px 1fr 70px; } }
</style></head>
<body><div class="wrap">
  <div class="hdr">
    <div class="title glow">MATRIX&nbsp;SHIELD</div>
    <div class="sub">XDP · DDoS · PROTECTION</div>
  </div>
  <div class="status-line" id="statusline">Connecting...</div>
  <div class="cards" id="cards"></div>
  <div class="attack"><h2>Threat Breakdown</h2><div id="bars"></div></div>
  <div class="foot" id="foot">MATRIX SHIELD · qwen-filter engine · live 2s refresh</div>
</div>
<script>
const CATS = [["SYN Flood","syn_rate_dropped"],["UDP Amplification","udp_amp_dropped"],
 ["Fragment Attack","frag_dropped"],["Bogon Spoof","bogon_dropped"],["L7 Abuse","l7_rate_dropped"],
 ["TLS Handshake","tls_dropped"],["ICMP Flood","icmp_dropped"],["SYN/FIN Attack","fin_rst_dropped"],
 ["ACK Invalid","ack_invalid"],["SSH Brute","ssh_dropped"]];
const fnum=n=>{n=n||0;for(const u of ["","K","M","B","T"]){if(Math.abs(n)<1000)return (u?n.toFixed(2):n.toFixed(0))+u;n/=1000;}return n+"T";};
const fbw=n=>{n=n||0;for(const u of ["B","KB","MB","GB","TB"]){if(Math.abs(n)<1024||u=="TB")return n.toFixed(1)+" "+u;n/=1024;}};
async function tick(){
  try {
    const r=await fetch('/stats'); const d=await r.json(); const m=d.m||{};
    const up=d.state==='active';
    document.getElementById('statusline').innerHTML=
      '<span class="dot '+(up?'up':'down')+'"></span>'+ (up?'<b>ONLINE</b> — Filtering '+d.iface+' — Uptime '+d.uptime:'<b>DOWN</b> — Engine not running!');
    const cards=[
      ['Protection', up?'ACTIVE':'DOWN', up?'':'red'],
      ['Blocked IPs', fnum(m.xdpguard_active_blocked_ips)+' live', 'cyan'],
      ['Total Blocked', fnum(m.xdpguard_blocked_ips), ''],
      ['Packets Dropped', fnum(m.xdpguard_dropped_packets)+' ('+fnum(m.xdpguard_dropped_pps)+'/s)', ''],
      ['Dropped Volume', fbw(m.xdpguard_dropped_bytes)+' ('+fbw(m.xdpguard_dropped_bps)+'/s)', ''],
      ['Passed Traffic', fnum(m.xdpguard_passed_packets)+' ('+fnum(m.xdpguard_passed_pps)+'/s)', 'cyan'],
    ];
    document.getElementById('cards').innerHTML=cards.map(c=>
      '<div class="card"><div class="k">'+c[0]+'</div><div class="v '+(c[2]||'')+'">'+c[1]+'</div></div>').join('');
    let bars=''; let max=0;
    const rows=CATS.map(c=>[c[0], m['xdpguard_'+c[1]]||0]).filter(r=>r[1]>0);
    const mx=Math.max(...rows.map(r=>r[1]))||1;
    rows.forEach(r=>{
      const pct=Math.max(1,Math.round(r[1]/mx*100));
      bars+='<div class="bar"><div class="lbl">'+r[0]+'</div><div class="trk"><div class="fill" style="width:'+pct+'%"></div></div><div class="val">'+fnum(r[1])+'</div></div>';
    });
    document.getElementById('bars').innerHTML=bars||'<span style="color:var(--dim)">No threats detected — all clear.</span>';
  } catch(e){ document.getElementById('statusline').innerHTML='<span class="dot down"></span><b>OFFLINE</b> — cannot reach metrics'; }
}
setInterval(tick,2000); tick();
</script></body></html>
"""


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/stats"):
            body = json.dumps(status()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = PAGE.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    srv = ThreadingHTTPServer((BIND, PORT), H)
    print("Matrix Shield dashboard: http://%s:%d" % (socket.gethostname(), PORT))
    srv.serve_forever()


if __name__ == "__main__":
    main()