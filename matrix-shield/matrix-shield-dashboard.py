#!/usr/bin/env python3
"""Matrix Shield — live DDoS protection dashboard (qwen-filter engine).
Read-only status page. Env: MS_BIND (0.0.0.0), MS_PORT (9090),
METRICS_URL (http://127.0.0.1:1999/metrics).
"""
import json
import os
import socket
import subprocess
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
    ("win", "window_dropped", "Window Scrub"),
    ("ssh", "ssh_dropped", "SSH Brute"),
    ("rst", "rst_invalid", "RST Invalid"),
]

ATTACK_KEYS = [
    "xdpguard_dropped_pps", "xdpguard_syn_rate_dropped_per_sec",
    "xdpguard_udp_amp_dropped_per_sec", "xdpguard_frag_dropped_per_sec",
    "xdpguard_bogon_dropped_per_sec", "xdpguard_l7_rate_dropped_per_sec",
    "xdpguard_tls_dropped_per_sec", "xdpguard_icmp_dropped_per_sec",
    "xdpguard_fin_rst_dropped_per_sec", "xdpguard_ssh_dropped_per_sec",
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
    live = sum(float(m.get(k, 0)) for k in ATTACK_KEYS)
    m["_attack_live_pps"] = live
    m["_last_update"] = __import__("time").time()
    return {"state": state, "uptime": uptime, "iface": iface, "m": m}


PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Matrix Shield — Live DDoS Protection</title>
<style>
:root{
  --bg:#0b0b0e; --panel:#121216; --edge:#23232b; --panel2:#17171c;
  --txt:#e9e9eb; --dim:#9a9aa6; --faint:#6b6b76;
  --acc:#ff9f1c; --ok:#37d67a; --bad:#ff4d4d;
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  background:var(--bg);color:var(--txt);
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased;
}
.wrap{max-width:1120px;margin:0 auto;padding:36px 24px 48px}
.head{display:flex;align-items:baseline;justify-content:space-between;
  border-bottom:1px solid var(--edge);padding-bottom:20px;margin-bottom:28px}
.logo{font-size:22px;font-weight:800;letter-spacing:2px}
.logo small{font-weight:600;color:var(--acc);letter-spacing:2px}
.tag{color:var(--faint);font-size:12px;letter-spacing:3px;text-transform:uppercase;margin-top:4px}
.pill{display:inline-flex;align-items:center;gap:8px;background:var(--panel);
  border:1px solid var(--edge);padding:8px 14px;border-radius:999px;font-size:13px;color:var(--dim)}
.pill .p{width:8px;height:8px;border-radius:50%;background:var(--ok)}
.pill .p.down{background:var(--bad)}
.pill b{color:var(--txt);font-weight:600}
.meta{display:flex;align-items:center;gap:12px}
.meta .sep{width:1px;height:14px;background:var(--edge)}
#alert{display:none;background:rgba(255,77,77,.08);border:1px solid rgba(255,77,77,.5);
  color:var(--bad);padding:12px 16px;border-radius:10px;font-size:14px;font-weight:600;
  margin-bottom:22px}
#alert.show{display:block}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px}
.card{background:var(--panel);border:1px solid var(--edge);border-radius:14px;padding:18px 20px}
.card .label{font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:var(--faint)}
.card .value{font-size:30px;font-weight:700;margin-top:10px;color:var(--txt);
  font-variant-numeric:tabular-nums;letter-spacing:.5px;line-height:1}
.card .value .clr{color:var(--acc)}
.card .value .cld{color:var(--bad)}
.card .value .clg{color:var(--ok)}
.card .sub{font-size:12.5px;color:var(--faint);margin-top:8px;font-variant-numeric:tabular-nums}
.panel{background:var(--panel);border:1px solid var(--edge);border-radius:14px;padding:20px 22px;margin-top:16px}
.panel h3{font-size:12px;letter-spacing:1.5px;text-transform:uppercase;color:var(--faint);
  font-weight:600;margin-bottom:18px}
.bar{display:grid;grid-template-columns:minmax(140px,220px) 1fr 120px 84px;align-items:center;
  gap:16px;padding:9px 0;border-bottom:1px solid var(--edge)}
.bar:last-child{border-bottom:none}
.bar .name{font-size:13.5px;color:var(--txt)}
.bar .trk{height:8px;background:var(--panel2);border-radius:6px;overflow:hidden}
.bar .fill{height:100%;width:0%;border-radius:6px;background:var(--acc);
  transition:width .5s ease}
.bar .fill.hot{background:var(--bad)}
.bar .tot{font-size:13px;color:var(--txt);text-align:right;font-variant-numeric:tabular-nums}
.bar .rt{font-size:12px;color:var(--faint);text-align:right;font-variant-numeric:tabular-nums}
.empty{color:var(--faint);font-size:13.5px;padding:8px 0}
.foot{color:var(--faint);font-size:12px;margin-top:30px;text-align:center}
.foot a{color:var(--acc);text-decoration:none}
@media(max-width:640px){.head{flex-direction:column;gap:14px;align-items:flex-start}
  .bar{grid-template-columns:110px 1fr 72px 60px;gap:10px}}
</style></head><body>
<div class="wrap">
  <div class="head">
    <div>
      <div class="logo">MATRIX <small>SHIELD</small></div>
      <div class="tag">DDoS Protection</div>
    </div>
    <div class="meta">
      <span class="pill" id="statuspill"><span class="p"></span><span id="statustxt">connecting...</span></span>
      <span class="sep"></span>
      <span class="pill" id="metaiface"></span>
    </div>
  </div>

  <div id="alert"></div>

  <div class="grid">
    <div class="card"><div class="label">Blocked IPs</div>
      <div class="value" id="c_blk">--</div>
      <div class="sub" id="c_blk_tot"></div></div>
    <div class="card"><div class="label">Drop Rate</div>
      <div class="value" id="c_dpp">--</div>
      <div class="sub" id="c_dpp_vol"></div></div>
    <div class="card"><div class="label">Total Dropped</div>
      <div class="value" id="c_tot">--</div>
      <div class="sub" id="c_tot_vol"></div></div>
    <div class="card"><div class="label">Passed Traffic</div>
      <div class="value" id="c_pass">--</div>
      <div class="sub" id="c_pass_tot"></div></div>
    <div class="card"><div class="label">Verified Connections</div>
      <div class="value" id="c_ver">--</div>
      <div class="sub" id="c_ver_s"></div></div>
    <div class="card"><div class="label">Dropped Connections</div>
      <div class="value" id="c_dconn">--</div>
      <div class="sub" id="c_dconn_s"></div></div>
  </div>

  <div class="panel"><h3>Threat Breakdown</h3><div id="bars"></div></div>

  <div class="foot">MATRIX SHIELD &middot; qwen-filter engine &middot; refreshes every 5s &middot;
    raw data <a href="/stats">/stats</a></div>
</div>
<script>
const fnum=(n,dec=1)=>{n=Math.abs(n||0);
  for(const u of ['','K','M','B','T']){if(n<1000)return (u?n.toFixed(dec):n.toFixed(1))+u;n/=1000}return n.toFixed(dec)+'T'};
const fbw=(n,dec=1)=>{n=Math.abs(n||0);
  for(const u of ['B','KB','MB','GB','TB']){if(n<1024||u==='TB')return n.toFixed(dec)+' '+u;n/=1024}};
const CATS=[
 ['SYN Flood','syn_rate_dropped'],['UDP Amplification','udp_amp_dropped'],
 ['Fragment Attack','frag_dropped'],['Bogon Spoof','bogon_dropped'],['L7 Abuse','l7_rate_dropped'],
 ['TLS Handshake','tls_dropped'],['ICMP Flood','icmp_dropped'],['SYN/FIN Attack','fin_rst_dropped'],
 ['Window Scrub','window_dropped'],['ACK Invalid','ack_invalid'],['SSH Brute','ssh_dropped'],
 ['RST Invalid','rst_invalid']];
function set(id,val,clr){
  const el=document.getElementById(id);
  if(!el)return;
  el.innerHTML='<span class="'+(clr||'')+'">'+val+'</span>';
}
async function tick(){
  const st=document.getElementById('statustxt');
  const spd=document.querySelector('#statuspill .p');
  try{
    const d=await (await fetch('/stats',{cache:'no-store'})).json();
    const m=d.m||{};const up=d.state==='active';
    st.textContent=up?'Online':'Down';
    spd.className='p'+(up?'':' down');
    document.getElementById('metaiface').innerHTML=
      '<b>'+d.iface+'</b> &nbsp;&middot;&nbsp; '+d.uptime.replace(/^[A-Za-z]+ /,'');

    const blk=m.xdpguard_active_blocked_ips||0;
    set('c_blk',fnum(blk),blk>0?'cld':'clr');
    document.getElementById('c_blk_tot').textContent=fnum(m.xdpguard_blocked_ips)+' total';

    const dpp=m.xdpguard_dropped_pps||0;
    set('c_dpp',fnum(dpp,2)+' pkt/s',dpp>0?'cld':'');
    document.getElementById('c_dpp_vol').textContent=fbw(m.xdpguard_dropped_bps)+'/s volume';

    set('c_tot',fnum(m.xdpguard_dropped_packets),'');
    document.getElementById('c_tot_vol').textContent=fbw(m.xdpguard_dropped_bytes)+' total volume';

    set('c_pass',fnum(m.xdpguard_passed_pps,2)+' pkt/s','clg');
    document.getElementById('c_pass_tot').textContent=fnum(m.xdpguard_passed_packets)+' routed';

    set('c_ver',fnum(m.xdpguard_verified_connections),'');
    document.getElementById('c_ver_s').textContent=fnum(m.xdpguard_verified_connections_per_sec,2)+'/s live';

    const dc=m.xdpguard_dropped_connections||0;
    set('c_dconn',fnum(dc),dc>0?'cld':'');
    document.getElementById('c_dconn_s').textContent=fnum(m.xdpguard_dropped_connections_per_sec,2)+'/s live';

    const livePps=(m._attack_live_pps||0);
    const al=document.getElementById('alert');
    if((dpp>0&&livePps>0)||livePps>0){
      al.textContent='Attack in progress  —  dropping '+fnum(dpp,2)+' pkt/s ('+fbw(m.xdpguard_dropped_bps||0)+'/s)';
      al.classList.add('show');
    }else if(blk>0){
      al.textContent=blk+' IP'+(blk>1?'s':'')+' blocked  —  auto release within 120s';
      al.classList.add('show');
    }else{al.classList.remove('show')}

    const rows=CATS.map(c=>[c[0],m['xdpguard_'+c[1]]||0,m['xdpguard_'+c[1]+'_per_sec']||0])
      .filter(r=>r[1]||r[2]);
    const mx=Math.max(1,...rows.map(r=>r[1]));
    document.getElementById('bars').innerHTML=rows.length?rows.map(r=>{
      const pct=Math.max(1,Math.round(r[1]/mx*100));
      const hot=r[2]>0;
      return '<div class="bar"><div class="name">'+r[0]+'</div>'+
        '<div class="trk"><div class="fill'+(hot?' hot':'')+'" style="width:'+pct+'%"></div></div>'+
        '<div class="tot">'+fnum(r[1])+'</div>'+
        '<div class="rt">'+(r[2]>0?'+'+fnum(r[2],2)+' /s':'idle')+'</div></div>';
    }).join(''):'<div class="empty">All clear — no threat activity detected.</div>';
  }catch(e){
    st.textContent='Offline';
    spd.className='p down';
    document.getElementById('metaiface').textContent='engine unreachable';
  }
}
setInterval(tick,5000);tick();
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