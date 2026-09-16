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
  --bg:#070402; --panel:#120a03; --edge:#2a1a07; --edge2:#3b2710;
  --orange:#ff9f1c; --amber:#ffc14d; --deep:#b36500;
  --red:#ff3b30; --cyan:#3ae0ff; --dim:#8a6b44; --txt:#ffe9cc; --txt2:#c9a876;
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  background:radial-gradient(1400px 800px at 50% -20%,#211002 0%,#0a0501 55%,var(--bg) 100%);
  color:var(--txt);font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh;
  overflow-x:hidden;position:relative;
}
#rain{position:fixed;inset:0;opacity:.16;z-index:0;pointer-events:none}
.scan{position:fixed;inset:0;z-index:1;pointer-events:none;opacity:.5;
  background:repeating-linear-gradient(0deg,rgba(0,0,0,0) 0 2px,rgba(0,0,0,.14) 2px 4px)}
.wrap{position:relative;z-index:2;max-width:1180px;margin:0 auto;padding:26px 18px 40px}
header{text-align:center;margin-bottom:18px}
.brand{display:inline-flex;align-items:center;gap:18px}
.shield{width:54px;height:60px;filter:drop-shadow(0 0 14px rgba(255,159,28,.6));
  position:relative}
.logo-txt{font-size:clamp(28px,5.4vw,52px);font-weight:900;letter-spacing:8px;
  color:var(--orange);text-shadow:0 0 8px rgba(255,159,28,.8),0 0 34px rgba(255,159,28,.45),
    0 2px 0 #4a2500;line-height:1;font-family:Consolas,monospace}
.logo-txt em{font-style:normal;color:var(--amber)}
.sub{color:var(--cyan);letter-spacing:14px;font-size:12px;margin-top:8px;font-family:Consolas,monospace}
.statusline{text-align:center;font-family:Consolas,monospace;font-size:14px;
  margin:14px 0 4px;color:var(--txt2)}
.dot{display:inline-block;width:11px;height:11px;border-radius:50%;margin-right:8px;
  vertical-align:middle;background:var(--orange);box-shadow:0 0 12px var(--orange);
  animation:blink 1.4s infinite}
.dot.down{background:var(--red);box-shadow:0 0 12px var(--red);animation:none}
@keyframes blink{50%{opacity:.3}}
#alert{display:none;margin:0 auto 18px;max-width:640px;text-align:center;
  font-family:Consolas,monospace;font-size:15px;font-weight:700;letter-spacing:2px;
  color:#fff;background:linear-gradient(90deg,transparent,#3a0a04,var(--red),#3a0a04,transparent);
  border:1px solid var(--red);border-radius:10px;padding:12px 18px;
  box-shadow:0 0 30px rgba(255,59,48,.45);animation:flash 1s infinite}
#alert.show{display:block}
@keyframes flash{50%{box-shadow:0 0 8px rgba(255,59,48,.2);opacity:.85}}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(225px,1fr));gap:14px;margin-top:8px}
.card{background:linear-gradient(180deg,var(--panel),#0a0500);border:1px solid var(--edge);
  border-radius:14px;padding:16px 18px;position:relative;overflow:hidden;
  transition:transform .15s,box-shadow .15s}
.card:hover{transform:translateY(-2px);box-shadow:0 6px 24px rgba(255,159,28,.12)}
.card::after{content:'';position:absolute;left:8%;top:0;height:2px;width:84%;
  background:linear-gradient(90deg,transparent,var(--orange),transparent);opacity:.85}
.card .k{color:var(--dim);font-size:11px;letter-spacing:2px;text-transform:uppercase}
.card .v{font-size:25px;font-weight:800;margin-top:6px;font-family:Consolas,monospace;
  color:var(--orange);line-height:1.1}
.card .v span{display:block;font-size:12px;font-weight:400;color:var(--txt2);margin-top:2px}
.card .v.cyan{color:var(--cyan)}
.card .v.red{color:var(--red)}
.card .v.amber{color:var(--amber)}
.panel{background:linear-gradient(180deg,var(--panel),#0a0500);border:1px solid var(--edge);
  border-radius:14px;padding:18px;margin-top:16px;position:relative}
.panel::before{content:'';position:absolute;left:4%;top:0;height:2px;width:92%;
  background:linear-gradient(90deg,transparent,var(--amber),transparent);opacity:.7}
.panel h3{color:var(--amber);font-size:13px;letter-spacing:3px;text-transform:uppercase;
  margin-bottom:14px;font-family:Consolas,monospace}
.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px;margin-top:16px}
.chart-box{background:linear-gradient(180deg,var(--panel),#0a0500);border:1px solid var(--edge);
  border-radius:14px;padding:14px 16px;position:relative}
.chart-box h4{color:var(--dim);font-size:11px;letter-spacing:2px;text-transform:uppercase;
  margin-bottom:8px;font-family:Consolas,monospace}
.chart-box canvas{width:100%;height:96px;display:block}
.bar{display:grid;grid-template-columns:190px 1fr 150px 96px;align-items:center;gap:12px;
  margin-bottom:10px;font-size:13px}
.bar .lbl{color:var(--txt);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:12.5px}
.bar .trk{background:#0d0a00;border-radius:20px;height:12px;overflow:hidden;border:1px solid #221505}
.bar .fill{height:100%;border-radius:20px;width:0%;transition:width .7s cubic-bezier(.2,.8,.2,1);
  background:linear-gradient(90deg,#b36500,var(--orange),var(--amber));
  box-shadow:0 0 10px rgba(255,159,28,.5)}
.bar .val{font-family:Consolas,monospace;text-align:right;color:var(--orange);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar .rate{font-family:Consolas,monospace;text-align:right;color:var(--cyan);font-size:12px;
  white-space:nowrap}
.empty{color:var(--dim);font-style:italic}
.foot{text-align:center;color:#7a5c33;font-size:12px;margin-top:28px;letter-spacing:2px;
  font-family:Consolas,monospace}
.foot a{color:var(--amber);text-decoration:none}
@media(max-width:700px){.bar{grid-template-columns:110px 1fr 70px 58px;gap:8px}
  .bar .lbl{font-size:11px}.bar .rate{font-size:10px}}
</style></head><body>
<canvas id="rain"></canvas><div class="scan"></div>
<div class="wrap">
  <header>
    <div class="brand">
      <svg class="shield" viewBox="0 0 54 62" fill="none">
        <defs><linearGradient id="sg" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stop-color="#ffc14d"/><stop offset="1" stop-color="#b36500"/>
        </linearGradient></defs>
        <path d="M27 2 L50 10 V28 C50 44 40 56 27 60 C14 56 4 44 4 28 V10 Z"
              stroke="url(#sg)" stroke-width="3"/>
        <path d="M27 12 V32" stroke="url(#sg)" stroke-width="3" stroke-linecap="round"/>
        <path d="M17 22 H37 M20 27 H34 M23 32 H31" stroke="url(#sg)" stroke-width="3" stroke-linecap="round"/>
        <circle cx="27" cy="44" r="5" stroke="url(#sg)" stroke-width="2.5"/>
      </svg>
      <div class="logo-txt">MATRIX<em>SHIELD</em></div>
    </div>
    <div class="sub">XDP &middot; DDoS &middot; PROTECTION</div>
    <div class="statusline" id="statusline">Connecting to engine...</div>
  </header>

  <div id="alert"></div>
  <div class="grid" id="cards"></div>

  <div class="charts">
    <div class="chart-box"><h4>Dropped &mdash; packets/sec</h4><canvas id="chDrop"></canvas></div>
    <div class="chart-box"><h4>Passed &mdash; packets/sec</h4><canvas id="chPass"></canvas></div>
    <div class="chart-box"><h4>Dropped &mdash; bytes/sec</h4><canvas id="chBps"></canvas></div>
  </div>

  <div class="panel"><h3>Threat Breakdown &mdash; live vs total</h3><div id="bars"></div></div>

  <div class="foot">MATRIX SHIELD &middot; qwen-filter engine &middot; live refresh 2s &middot;
    view raw <a href="/stats">/stats</a></div>
</div>
<script>
const RAIN_CHARS='アイウエオカキクケコサシスセソタチツテト+にゃん#[{}]+=<>';
const CSS=c=>getComputedStyle(document.documentElement).getPropertyValue(c).trim();
const O=CSS('--orange'),A=CSS('--amber'),CY=CSS('--cyan'),RD=CSS('--red'),DM=CSS('--dim');
const live=new URLSearchParams(location.search).get('live');

/* matrix rain */
(function(){const cv=document.getElementById('rain');const ctx=cv.getContext('2d');
const H=Math.min(28,Math.floor(innerWidth/38));
cv.width=innerWidth;cv.height=innerHeight;
let cols=Math.floor(innerWidth/18);let drops=Array(cols).fill(1);
const size=Math.floor(innerHeight/22);
let grid=[];
function frame(){
  ctx.fillStyle='rgba(7,4,2,.12)';ctx.fillRect(0,0,cv.width,cv.height);
  ctx.font=size+'px monospace';
  for(let i=0;i<cols;i++){
    const ch=RAIN_CHARS[(Math.random()*RAIN_CHARS.length)|0];
    ctx.fillStyle=Math.random()>.92?'#ffc14d':'#3ae0ff';
    ctx.fillText(ch,i*18,drops[i]*size);
    if(drops[i]*size>cv.height&&Math.random()>.975)drops[i]=0;
    drops[i]++;
  }
  requestAnimationFrame(frame);
}requestAnimationFrame(frame);
})();

/* number formatting */
const fnum=(n,dec=1)=>{n=n||0;
  for(const u of ['','K','M','B','T']){if(Math.abs(n)<1000)return (u?(+n.toFixed(dec)):(+n.toFixed(0)))+u;n/=1000}return n.toFixed(dec)+'T'};
const fbw=(n,dec=1)=>{n=n||0;
  for(const u of ['B','KB','MB','GB','TB']){if(Math.abs(n)<1024||u==='TB')return (+n.toFixed(dec))+' '+u;n/=1024}};

/* history */
const H_drop=[],H_pass=[],H_bps=[];
const CAP=40;

/* charts */
function draw(cv,data,color,unit){
  const dpr=window.devicePixelRatio||1;
  const w=cv.width=Math.max(2,Math.floor(cv.clientWidth*dpr));
  const h=cv.height=Math.max(2,Math.floor(cv.clientHeight*dpr));
  const c=cv.getContext('2d');
  c.clearRect(0,0,w,h);
  const max=Math.max(1,...data.map(Math.abs))*1.25;
  const step=w/CAP;
  c.lineWidth=2;c.strokeStyle=color;
  c.shadowColor=color;c.shadowBlur=8;
  c.beginPath();
  for(let i=0;i<data.length;i++){
    const x=(data.length-i)*step;
    const y=h-2-(Math.abs(data[i])/max)*(h-12);
    if(i===0)c.moveTo(x,y);else c.lineTo(x,y);
  }
  if(data.length){c.stroke();
    c.lineTo(w,h);c.lineTo(0,h);c.closePath();
    c.globalAlpha=.16;c.fillStyle=color;c.fill();c.globalAlpha=1;
    c.shadowBlur=0;
    c.font='10px monospace';c.fillStyle=color;
    const lv=data[data.length-1]||0;
    c.fillText(fnum(lv)+' '+unit,6,11);
    c.font='9px monospace';c.fillStyle=DM;
    c.fillText('max '+fnum(max)+' '+unit,6,23);
  }
}
function redraw(){
  draw(document.getElementById('chDrop'),H_drop,O,'pkt/s');
  draw(document.getElementById('chPass'),H_pass,CY,'pkt/s');
  draw(document.getElementById('chBps'),H_bps,RD,'B/s');
}

/* collect attack data */
const CATS=[
 ['SYN Flood','syn_rate_dropped'],['UDP Amplification','udp_amp_dropped'],
 ['Fragment Attack','frag_dropped'],['Bogon Spoof','bogon_dropped'],['L7 Abuse','l7_rate_dropped'],
 ['TLS Handshake','tls_dropped'],['ICMP Flood','icmp_dropped'],['SYN/FIN Attack','fin_rst_dropped'],
 ['Window Scrub','window_dropped'],['ACK Invalid','ack_invalid'],['SSH Brute','ssh_dropped'],
 ['RST Invalid','rst_invalid']];

function updAlert(m,state){
  const el=document.getElementById('alert');
  const dpps=m.xdpguard_dropped_pps||0;
  const livePps=m._attack_live_pps||0;
  if(dpps>0&&livePps>0){
    el.innerHTML='&#9888; ATTACK IN PROGRESS &mdash; dropping '+fnum(dpps)+' pkt/s ('+fbw((m.xdpguard_dropped_bps||0))+'/s)';
    el.classList.add('show');el.style.background='linear-gradient(90deg,transparent,#3a0a04,var(--red),#3a0a04,transparent)';
  }else if(m.xdpguard_active_blocked_ips>0){
    el.innerHTML='&#128274; '+fnum(m.xdpguard_active_blocked_ips)+' IP'+(m.xdpguard_active_blocked_ips>1?'s':'')+' blocked &middot; auto-release in '+Math.max(120,0)+'s';
    el.classList.add('show');el.style.background='linear-gradient(90deg,transparent,#3a1400,var(--orange),#3a1400,transparent)';
    el.style.borderColor='var(--orange)';
  }else{el.classList.remove('show')}
}

async function tick(){
  try{
    const r=await fetch('/stats',{cache:'no-store'});const d=await r.json();
    const m=d.m||{};const up=d.state==='active';
    document.getElementById('statusline').innerHTML=
      '<span class="dot '+(up?'':'down')+'"></span>'+
      (up?'<b>ONLINE</b> &mdash; filtering <b>'+d.iface+'</b> &mdash; up '+d.uptime.replace(/^[A-Za-z]+ /,'')
       :'<b>DOWN</b> &mdash; engine not running (systemctl start qwen-filter)');

    const cards=[
      ['Protection',up?'ACTIVE':'DOWN',up?'':'red'],
      ['Blocked IPs',fnum(m.xdpguard_active_blocked_ips)+'<span>'+fnum(m.xdpguard_blocked_ips)+' total</span>',m.xdpguard_active_blocked_ips>0?'red':''],
      ['Drop Rate',fnum(m.xdpguard_dropped_pps,2)+'<span>pkt/s</span>',(m.xdpguard_dropped_pps||0)>0?'red':''],
      ['Drop Volume Rate',fbw(m.xdpguard_dropped_bps)+'<span>/sec</span>',''],
      ['Dropped Total',fnum(m.xdpguard_dropped_packets)+'<span>'+fbw(m.xdpguard_dropped_bytes)+'</span>',''],
      ['Passed Traffic',fnum(m.xdpguard_passed_pps,2)+'<span>pkt/s &middot; '+fnum(m.xdpguard_passed_packets)+' total</span>','cyan'],
      ['Verified Connections',fnum(m.xdpguard_verified_connections)+'<span>'+fnum(m.xdpguard_verified_connections_per_sec,2)+'/s live</span>','amber'],
      ['Dropped Connections',fnum(m.xdpguard_dropped_connections)+'<span>'+fnum(m.xdpguard_dropped_connections_per_sec,2)+'/s live</span>',(m.xdpguard_dropped_connections_per_sec||0)>0?'red':''],
      ['State Switches',fnum(m.xdpguard_state_switches)+'<span>'+fnum(m.xdpguard_state_switches_per_sec,2)+'/s live</span>','cyan'],
      ['TCP Bypass',fnum(m.xdpguard_tcp_bypass)+'<span>processed</span>','cyan'],
      ['ACK Invalid',fnum(m.xdpguard_ack_invalid)+'<span>'+fnum(m.xdpguard_ack_invalid_per_sec,2)+'/s live</span>',''],
      ['SSH Dropped',fnum(m.xdpguard_ssh_dropped)+'<span>brute drops</span>',''],
    ];
    document.getElementById('cards').innerHTML=cards.map(c=>
      '<div class="card"><div class="k">'+c[0]+'</div><div class="v '+(c[2]||'')+'">'+c[1]+'</div></div>').join('');

    H_drop.push(m.xdpguard_dropped_pps||0);H_pass.push(m.xdpguard_passed_pps||0);
    H_bps.push(m.xdpguard_dropped_bps||0);
    if(H_drop.length>CAP){H_drop.shift();H_pass.shift();H_bps.shift()}
    redraw();
    updAlert(m,up);

    const rows=CATS.map(c=>[c[0],m['xdpguard_'+c[1]]||0,m['xdpguard_'+c[1]+'_per_sec']||0])
      .filter(r=>r[1]>0||r[2]>0);
    const mx=Math.max(1,...rows.map(r=>r[1]));
    document.getElementById('bars').innerHTML=rows.length?rows.map(r=>{
      const pct=Math.max(1,Math.round(r[1]/mx*100));
      return '<div class="bar"><div class="lbl">'+r[0]+'</div><div class="trk">'+
        '<div class="fill" style="width:'+pct+'%"></div></div>'+
        '<div class="val">'+fnum(r[1])+'</div>'+
        '<div class="rate">'+(r[2]>0?'+'+fnum(r[2],2)+'/s':'idle')+'</div></div>';
    }).join(''):'<span class="empty">No threats detected &mdash; all clear.</span>';
  }catch(e){
    document.getElementById('statusline').innerHTML=
      '<span class="dot down"></span><b>OFFLINE</b> &mdash; cannot reach engine metrics';
  }
}
setInterval(tick,2000);tick();
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