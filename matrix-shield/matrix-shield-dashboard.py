#!/usr/bin/env python3
"""Matrix Shield — live DDoS protection dashboard (qwen-filter engine).
Read-only status page. Env: MS_BIND (0.0.0.0), MS_PORT (9090),
METRICS_URL (http://127.0.0.1:1999/metrics).
Graphs are rendered as inline SVG (no external JS libraries).
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
  --bg:#15151a; --panel:#1b1d23; --edge:#262a33; --panel2:#20232b;
  --txt:#e5e5ea; --dim:#a9a9b3; --faint:#6f6f7a;
  --acc:#ab46ef; --ok:#3ddc84; --bad:#ef4444;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--txt);
  font-family:'Poppins','Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  -webkit-font-smoothing:antialiased}
.wrap{max-width:1180px;margin:0 auto;padding:36px 24px 48px}
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
#alert{display:none;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.5);
  color:var(--bad);padding:12px 16px;border-radius:10px;font-size:14px;font-weight:600;
  margin-bottom:22px}
#alert.show{display:block}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px}
.card{background:var(--panel);border:1px solid var(--edge);border-radius:8px;padding:18px 20px}
.card .label{font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:var(--faint)}
.card .value{font-size:30px;font-weight:700;margin-top:10px;color:var(--txt);
  font-variant-numeric:tabular-nums;letter-spacing:.5px;line-height:1}
.card .value .clr{color:var(--acc)}
.card .value .cld{color:var(--bad)}
.card .value .clp{color:var(--acc)}
.card .sub{font-size:12.5px;color:var(--faint);margin-top:8px;font-variant-numeric:tabular-nums}
.card .spark{height:34px;margin-top:12px}
.card .spark svg{width:100%;height:100%;display:block}
.chartrow{display:grid;grid-template-columns:3fr 2fr;gap:16px;margin-top:16px}
@media(max-width:860px){.chartrow{grid-template-columns:1fr}}
.chartbox{background:var(--panel);border:1px solid var(--edge);border-radius:8px;padding:18px 20px}
.chartbox h3{font-size:12px;letter-spacing:1.5px;text-transform:uppercase;color:var(--faint);
  font-weight:600;margin-bottom:0}
.chartbox h3::before{content:'';display:inline-block;width:7px;height:7px;border-radius:50%;
  background:var(--ok);margin-right:8px;vertical-align:middle;
  box-shadow:0 0 6px var(--ok);animation:pulse 1.6s infinite}
body.down .chartbox h3::before{background:var(--bad);box-shadow:0 0 6px var(--bad);animation:none}
@keyframes pulse{50%{opacity:.3}}
.chartbox .h{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px;flex-wrap:wrap}
.win{display:inline-flex;border:1px solid var(--edge);border-radius:6px;overflow:hidden;
  background:var(--panel2)}
.win button{background:transparent;border:none;color:var(--faint);font-size:11px;font-weight:600;
  padding:5px 12px;cursor:pointer;letter-spacing:1px;font-family:inherit;transition:background .15s}
.win button:hover{color:var(--txt)}
.win button.on{background:var(--acc);color:#fff}
.livev{font-size:13px;font-weight:700;font-variant-numeric:tabular-nums;letter-spacing:.3px}
.livev i{font-style:normal}
.livev i.d{color:var(--bad)}
.livev i.o{color:var(--acc)}
.chartbox .cv{position:relative;height:200px}
.chartbox .cv svg{width:100%;height:100%;display:block}
.chartbox .cv.cat{height:auto;min-height:120px}
.foot{color:var(--faint);font-size:12px;margin-top:30px;text-align:center}
.foot a{color:var(--acc);text-decoration:none}
@media(max-width:640px){.head{flex-direction:column;gap:14px;align-items:flex-start}}
</style></head><body>
<div class="wrap">
  <div class="head">
    <div>
      <div class="logo">MATRIX <small>SHIELD</small></div>
      <div class="tag">DDoS Protection</div>
    </div>
    <div class="meta">
      <span class="pill"><span class="p" id="spdot"></span><span id="statustxt">connecting...</span></span>
      <span class="sep"></span>
      <span class="pill" id="metaiface"></span>
    </div>
  </div>

  <div id="alert"></div>

  <div class="grid">
    <div class="card"><div class="label">Blocked IPs</div><div class="value" id="c_blk">--</div>
      <div class="sub" id="c_blk_tot"></div>
      <div class="spark" id="s_blk"></div></div>
    <div class="card"><div class="label">Drop Rate</div><div class="value" id="c_dpp">--</div>
      <div class="sub" id="c_dpp_vol"></div>
      <div class="spark" id="s_dpp"></div></div>
    <div class="card"><div class="label">Total Dropped</div><div class="value" id="c_tot">--</div>
      <div class="sub" id="c_tot_vol"></div></div>
    <div class="card"><div class="label">Passed Traffic</div><div class="value" id="c_pass">--</div>
      <div class="sub" id="c_pass_tot"></div>
      <div class="spark" id="s_pass"></div></div>
    <div class="card"><div class="label">Verified Connections</div><div class="value" id="c_ver">--</div>
      <div class="sub" id="c_ver_s"></div></div>
    <div class="card"><div class="label">Dropped Connections</div><div class="value" id="c_dconn">--</div>
      <div class="sub" id="c_dconn_s"></div></div>
  </div>

  <div class="chartrow">
    <div class="chartbox wide"><div class="h"><h3>Live Traffic &mdash; packets/sec</h3>
      <span class="win" id="win"><button data-m="30" class="on">1m</button><button data-m="150">5m</button><button data-m="450">15m</button></span>
      <span class="livev" id="lv_traf"></span></div>
      <div class="cv" id="chTraf"></div></div>
    <div class="chartbox"><div class="h"><h3>Drop Volume &mdash; bytes/sec</h3>
      <span class="livev" id="lv_vol"></span></div>
      <div class="cv" id="chVol"></div></div>
    <div class="chartbox"><div class="h"><h3>Blocked IPs &mdash; live</h3>
      <span class="livev" id="lv_blk"></span></div>
      <div class="cv" id="chBlk"></div></div>
  </div>

  <div class="chartrow">
    <div class="chartbox wide"><div class="h"><h3>Threat Composition &mdash; total dropped</h3></div>
      <div class="cv cat" id="chCat"></div></div>
  </div>

  <div class="foot">MATRIX SHIELD &middot; qwen-filter engine &middot; live 2s refresh &middot;
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
const P={red:'#ff5c7c',pur:'#ab46ef',lil:'#c084fc'};
let winCap=30;
const hist={t:[],drop:[],pass:[],bps:[],blk:[]};
const peaks={dpp:0,bps:0,blk:0,pass:0};
let lastM={};
const tgt={drop:0,pass:0,bps:0,blk:0};
const cur={drop:0,pass:0,bps:0,blk:0};

function dispData(){
  if(!hist.drop.length)return hist;
  const o={t:hist.t,drop:hist.drop.slice(),pass:hist.pass.slice(),
    bps:hist.bps.slice(),blk:hist.blk.slice()};
  const n=o.drop.length;
  o.drop[n-1]=cur.drop;o.pass[n-1]=cur.pass;
  o.bps[n-1]=cur.bps;o.blk[n-1]=cur.blk;
  return o;
}

function smoothData(arr){
  const n=arr.length,out=arr.slice();
  for(let i=1;i<n-1;i++)out[i]=(arr[i-1]+arr[i]+arr[i+1])/3;
  return out;
}
function catmull(pts){
  if(pts.length<2)return '';
  let d='M'+pts[0][0].toFixed(1)+','+pts[0][1].toFixed(1);
  for(let i=0;i<pts.length-1;i++){
    const p0=pts[Math.max(0,i-1)],p1=pts[i],p2=pts[i+1],p3=pts[Math.min(pts.length-1,i+2)];
    const c1x=p1[0]+(p2[0]-p0[0])/6, c1y=p1[1]+(p2[1]-p0[1])/6;
    const c2x=p2[0]-(p3[0]-p1[0])/6, c2y=p2[1]-(p3[1]-p1[1])/6;
    d+=' C'+c1x.toFixed(1)+','+c1y.toFixed(1)+' '+c2x.toFixed(1)+','+c2y.toFixed(1)+' '+
       p2[0].toFixed(1)+','+p2[1].toFixed(1);
  }
  return d;
}
function chartSVG(el,series){
  if(!el)return;
  const W=el.clientWidth||240,H=el.clientHeight||180,pad=6;
  let inner='';
  for(const s of series){
    if(s.data.length<2)continue;
    const sm=smoothData(s.data);
    const max=Math.max(1,Math.max.apply(null,sm))*1.2;
    const pts=sm.map((v,i)=>[
      pad+(i/(sm.length-1))*(W-2*pad),
      H-pad-(v/max)*(H-2*pad)
    ]);
    const gid='g'+Math.random().toString(36).slice(2,8);
    inner+='<defs><linearGradient id="'+gid+'" x1="0" y1="0" x2="0" y2="1">'+
      '<stop offset="0" stop-color="'+s.color+'" stop-opacity=".30"/>'+
      '<stop offset="1" stop-color="'+s.color+'" stop-opacity="0"/></linearGradient></defs>';
    const line=catmull(pts);
    const lp=pts[pts.length-1];
    inner+='<path d="'+line+' L'+lp[0].toFixed(1)+','+H+' L'+pts[0][0].toFixed(1)+','+H+' Z" fill="url(#'+gid+')"/>';
    inner+='<path d="'+line+'" fill="none" stroke="'+s.color+'" stroke-width="2" stroke-linecap="round"/>';
    inner+='<circle cx="'+lp[0].toFixed(1)+'" cy="'+lp[1].toFixed(1)+'" r="5" fill="'+s.color+'" opacity=".20"/>';
    inner+='<circle cx="'+lp[0].toFixed(1)+'" cy="'+lp[1].toFixed(1)+'" r="2.4" fill="'+s.color+'"/>';
  }
  el.innerHTML='<svg viewBox="0 0 '+W+' '+H+'" width="'+W+'" height="'+H+'">'+inner+'</svg>';
}
function catSVG(el,cats){
  if(!el)return;
  const W=el.clientWidth||560;
  const RH=26,H=cats.length*RH+14;
  const max=Math.max(1,Math.max.apply(null,cats.map(c=>c.tot)));
  const bx=190,bwMax=W-190-200;
  let s='';
  cats.forEach((c,i)=>{
    const y=9+i*RH;
    const bw=Math.max(0,Math.round(bwMax*(c.tot/max)));
    s+='<text x="0" y="'+(y+13)+'" font-size="12.5" fill="#e5e5ea">'+c.name+'</text>';
    s+='<rect x="'+bx+'" y="'+y+'" height="14" width="'+bw+'" rx="3" fill="'+(c.live?'#ff5c7c':'#ab46ef')+'"/>';
    s+='<text x="'+(W-130)+'" y="'+(y+13)+'" font-size="12" fill="#c9c9d4" text-anchor="end">'+fnum(c.tot)+'</text>';
    s+='<text x="'+(W-20)+'" y="'+(y+13)+'" font-size="11" fill="#6f6f7a" text-anchor="end">'+(c.live?'+'+fnum(c.live,2)+'/s':'idle')+'</text>';
  });
  el.innerHTML='<svg viewBox="0 0 '+W+' '+H+'" width="'+W+'" height="'+H+'">'+s+'</svg>';
}
function renderAll(){
  const d=dispData();
  chartSVG(document.getElementById('chTraf'),[
    {data:d.drop,color:P.red},
    {data:d.pass,color:P.pur}
  ]);
  chartSVG(document.getElementById('chVol'),[{data:d.bps,color:P.pur}]);
  chartSVG(document.getElementById('chBlk'),[{data:d.blk,color:P.lil}]);
  chartSVG(document.getElementById('s_blk'),[{data:d.blk,color:P.lil}]);
  chartSVG(document.getElementById('s_dpp'),[{data:d.drop,color:P.red}]);
  chartSVG(document.getElementById('s_pass'),[{data:d.pass,color:P.pur}]);
  const rows=CATS.map(c=>({name:c[0],tot:lastM['xdpguard_'+c[1]]||0,live:lastM['xdpguard_'+c[1]+'_per_sec']||0}));
  catSVG(document.getElementById('chCat'),rows);
}
function animLoop(){
  let moving=false;
  for(const k in tgt){
    cur[k]+=(tgt[k]-cur[k])*0.30;
    if(Math.abs(tgt[k]-cur[k])>0.05){moving=true;}
    else cur[k]=tgt[k];
  }
  renderAll();
  if(!moving&&hist.drop[hist.drop.length-1]===tgt.drop)return;
}
document.getElementById('win').addEventListener('click',e=>{
  const b=e.target.closest('button');
  if(!b)return;
  winCap=+b.dataset.m;
  document.querySelectorAll('#win button').forEach(x=>x.classList.toggle('on',x===b));
  for(const k in tgt){cur[k]=tgt[k];}
  renderAll();
});
function set(id,html,clr){
  const el=document.getElementById(id);
  if(!el)return;
  el.innerHTML=clr?'<span class="'+clr+'">'+html+'</span>':html;
}
async function tick(){
  const st=document.getElementById('statustxt');
  const dot=document.getElementById('spdot');
  try{
    const d=await (await fetch('/stats',{cache:'no-store'})).json();
    const m=d.m||{};const up=d.state==='active';
    lastM=m;
    document.body.classList.toggle('down',!up);
    st.textContent=up?'Online':'Down';
    dot.className=up?'p ':'p down';
    document.getElementById('metaiface').innerHTML=
      '<b>'+d.iface+'</b> &nbsp;&middot;&nbsp; '+d.uptime.replace(/^[A-Za-z]+ /,'');

    const blk=m.xdpguard_active_blocked_ips||0;
    peaks.blk=Math.max(peaks.blk,blk);
    peaks.dpp=Math.max(peaks.dpp,m.xdpguard_dropped_pps||0);
    peaks.bps=Math.max(peaks.bps,m.xdpguard_dropped_bps||0);
    peaks.pass=Math.max(peaks.pass,m.xdpguard_passed_pps||0);
    set('c_blk',fnum(blk),blk>0?'cld':'clr');
    document.getElementById('c_blk_tot').textContent=
      fnum(m.xdpguard_blocked_ips)+' blocked total &middot; peak '+fnum(peaks.blk);

    const dpp=m.xdpguard_dropped_pps||0;
    set('c_dpp',fnum(dpp,2)+' pkt/s',dpp>0?'cld':'');
    document.getElementById('c_dpp_vol').textContent=
      fbw(m.xdpguard_dropped_bps)+'/s &middot; peak '+fnum(peaks.dpp)+' pkt/s';

    set('c_tot',fnum(m.xdpguard_dropped_packets),'');
    document.getElementById('c_tot_vol').textContent=fbw(m.xdpguard_dropped_bytes)+' dropped total';

    set('c_pass',fnum(m.xdpguard_passed_pps,2)+' pkt/s','clp');
    document.getElementById('c_pass_tot').textContent=
      fnum(m.xdpguard_passed_packets)+' routed &middot; peak '+fnum(peaks.pass)+' pkt/s';

    set('c_ver',fnum(m.xdpguard_verified_connections),'');
    document.getElementById('c_ver_s').textContent=fnum(m.xdpguard_verified_connections_per_sec,2)+'/s live';

    const dc=m.xdpguard_dropped_connections||0;
    set('c_dconn',fnum(dc),dc>0?'cld':'');
    document.getElementById('c_dconn_s').textContent=fnum(m.xdpguard_dropped_connections_per_sec,2)+'/s live';

    const al=document.getElementById('alert');
    const livePps=(m._attack_live_pps||0);
    if(livePps>0){
      let dom=null;
      for(const c of CATS){
        const r=m['xdpguard_'+c[1]+'_per_sec']||0;
        if(r>0&&(!dom||r>dom[1]))dom=[c[0],r];
      }
      const dTxt=dom?'  —  dominated by '+dom[0]:'';
      al.textContent='Attack in progress'+dTxt+'  —  dropping '+fnum(dpp,2)+' pkt/s ('+fbw(m.xdpguard_dropped_bps||0)+'/s)';
      al.classList.add('show');
    }else if(blk>0){
      al.textContent=blk+' IP'+(blk>1?'s':'')+' blocked  —  auto release within 120s';
      al.classList.add('show');
    }else{al.classList.remove('show')}

    document.getElementById('lv_traf').innerHTML=
      '<i class="d">'+fnum(dpp,2)+'</i> vs <i class="o">'+
      fnum(m.xdpguard_passed_pps||0,2)+'</i> pkt/s';
    document.getElementById('lv_vol').textContent=fbw(m.xdpguard_dropped_bps||0)+'/s';
    document.getElementById('lv_blk').innerHTML=blk>0?'<i class="d">'+fnum(blk)+'</i>':'<i class="o">0</i>';

    const now=new Date().toLocaleTimeString('en-GB',{hour12:false});
    hist.t.push(now);hist.drop.push(dpp);hist.pass.push(m.xdpguard_passed_pps||0);
    hist.bps.push(m.xdpguard_dropped_bps||0);hist.blk.push(blk);
    for(const k in hist){if(hist[k].length>winCap)hist[k].shift()}
    tgt.drop=dpp;tgt.pass=m.xdpguard_passed_pps||0;
    tgt.bps=m.xdpguard_dropped_bps||0;tgt.blk=blk;
    if(hist.drop.length>1){
      cur.drop=hist.drop[hist.drop.length-2];cur.pass=hist.pass[hist.pass.length-2];
      cur.bps=hist.bps[hist.bps.length-2];cur.blk=hist.blk[hist.blk.length-2];
    }else{
      for(const k in tgt)cur[k]=tgt[k];
    }
  }catch(e){
    st.textContent='Offline';dot.className='p down';
    document.getElementById('metaiface').textContent='engine unreachable';
  }
}
setInterval(tick,1000);tick();
setInterval(animLoop,200);
renderAll();
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