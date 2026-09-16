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
body{background:var(--bg);color:var(--txt);
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
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
.card .spark{height:34px;margin-top:12px;position:relative}
.card .spark canvas{width:100%;height:34px;display:block}
.chartrow{display:grid;grid-template-columns:3fr 2fr;gap:16px;margin-top:16px}
@media(max-width:860px){.chartrow{grid-template-columns:1fr}}
.chartbox{background:var(--panel);border:1px solid var(--edge);border-radius:14px;padding:18px 20px}
.chartbox h3{font-size:12px;letter-spacing:1.5px;text-transform:uppercase;color:var(--faint);
  font-weight:600;margin-bottom:0}
.chartbox .h{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px;flex-wrap:wrap}
.win{display:inline-flex;border:1px solid var(--edge);border-radius:8px;overflow:hidden;
  background:var(--panel2)}
.win button{background:transparent;border:none;color:var(--faint);font-size:11px;font-weight:600;
  padding:5px 12px;cursor:pointer;letter-spacing:1px;font-family:inherit;transition:background .15s}
.win button:hover{color:var(--txt)}
.win button.on{background:var(--acc);color:#14100a}
.livev{font-size:13px;font-weight:700;font-variant-numeric:tabular-nums;letter-spacing:.3px}
.livev i{font-style:normal}
.livev i.d{color:var(--bad)}
.livev i.g{color:var(--ok)}
.livev i.o{color:var(--acc)}
.chartbox .cv{position:relative;height:200px}
.chartbox.wide{grid-column:1/3}
@media(max-width:860px){.chartbox.wide{grid-column:1}}
.cfail{color:var(--faint);font-size:13px;padding:40px 0;text-align:center}
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
      <div class="spark"><canvas id="s_blk"></canvas></div></div>
    <div class="card"><div class="label">Drop Rate</div><div class="value" id="c_dpp">--</div>
      <div class="sub" id="c_dpp_vol"></div>
      <div class="spark"><canvas id="s_dpp"></canvas></div></div>
    <div class="card"><div class="label">Total Dropped</div><div class="value" id="c_tot">--</div>
      <div class="sub" id="c_tot_vol"></div></div>
    <div class="card"><div class="label">Passed Traffic</div><div class="value" id="c_pass">--</div>
      <div class="sub" id="c_pass_tot"></div>
      <div class="spark"><canvas id="s_pass"></canvas></div></div>
    <div class="card"><div class="label">Verified Connections</div><div class="value" id="c_ver">--</div>
      <div class="sub" id="c_ver_s"></div></div>
    <div class="card"><div class="label">Dropped Connections</div><div class="value" id="c_dconn">--</div>
      <div class="sub" id="c_dconn_s"></div></div>
  </div>

  <div class="chartrow">
    <div class="chartbox wide"><div class="h"><h3>Live Traffic &mdash; packets/sec</h3>
      <span class="win" id="win"><button data-m="30">1m</button><button data-m="150" class="on">5m</button><button data-m="450">15m</button></span>
      <span class="livev" id="lv_traf"></span></div>
      <div class="cv"><canvas id="chTraf"></canvas></div></div>
    <div class="chartbox"><div class="h"><h3>Drop Volume &mdash; bytes/sec</h3>
      <span class="livev" id="lv_vol"></span></div>
      <div class="cv"><canvas id="chVol"></canvas></div></div>
    <div class="chartbox"><div class="h"><h3>Blocked IPs &mdash; live</h3>
      <span class="livev" id="lv_blk"></span></div>
      <div class="cv"><canvas id="chBlk"></canvas></div></div>
  </div>

  <div class="chartrow">
    <div class="chartbox wide"><h3>Threat Composition &mdash; total dropped per category</h3>
      <div class="cv" style="height:280px"><canvas id="chCat"></canvas></div></div>
  </div>

  <div class="foot">MATRIX SHIELD &middot; qwen-filter engine &middot; live 2s refresh &middot;
    raw data <a href="/stats">/stats</a></div>
</div>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
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
let winCap=150;
const hist={t:[],drop:[],pass:[],bps:[],blk:[]};
const peaks={dpp:0,bps:0,blk:0,pass:0};
const COLOR={d:'#ff4d4d',g:'#37d67a',o:'#ff9f1c'};
document.getElementById('win').addEventListener('click',e=>{
  const b=e.target.closest('button');if(!b)return;
  winCap=+b.dataset.m;
  document.querySelectorAll('#win button').forEach(x=>x.classList.toggle('on',x===b));
  for(const k in hist)if(hist[k].length>winCap)hist[k].splice(0,hist[k].length-winCap);
  C.traf.update();C.vol.update();C.blk.update();
});
function spark(cv,arr,color){
  if(!cv)return;
  const dpr=window.devicePixelRatio||1;
  const w=cv.width=Math.max(2,Math.floor(cv.clientWidth*dpr));
  const h=cv.height=Math.max(2,Math.floor(cv.clientHeight*dpr));
  const c=cv.getContext('2d');c.clearRect(0,0,w,h);
  const n=arr.length;if(!n)return;
  const max=Math.max(1,...arr.map(Math.abs));
  c.beginPath();
  for(let i=0;i<n;i++){
    const x=(i/(n-1))*w;
    const y=h-2-((arr[i]||0)/max)*(h-4);
    i?c.lineTo(x,y):c.moveTo(x,y);
  }
  c.strokeStyle=color;c.lineWidth=1.8;
  c.shadowColor=color;c.shadowBlur=4;
  c.stroke();
  c.lineTo(w,h);c.lineTo(0,h);c.closePath();
  c.globalAlpha=.13;c.fillStyle=color;c.fill();
}
let C=null,valid=false;
const axisX={ticks:{color:'#6b6b76',maxTicksLimit:8,maxRotation:0,font:{size:11}},
  grid:{color:'rgba(255,255,255,.03)'}};
const axisY=f=>({beginAtZero:true,ticks:{color:'#6b6b76',callback:f,maxTicksLimit:6,font:{size:11}},
  grid:{color:'rgba(255,255,255,.06)'}});
const baseOpt={responsive:true,maintainAspectRatio:false,
  animation:{duration:1200,easing:'easeOutQuart'},
  interaction:{mode:'index',intersect:false},
  plugins:{legend:{labels:{color:'#9a9aa6',boxWidth:10,boxHeight:10,font:{size:11},padding:16}},
    tooltip:{backgroundColor:'#1a1a20',borderColor:'#30303a',borderWidth:1,titleColor:'#e9e9eb',
      bodyColor:'#cfcfd6',padding:10,cornerRadius:6}}};
const liveEnd={
  id:'liveEnd',
  beforeDatasetsDraw(chart){
    const {ctx,chartArea}=chart;
    const d=chart.getDatasetMeta(0).data;
    if(!d||!d.length)return;
    const x=d[d.length-1].x;
    ctx.save();
    const g=ctx.createLinearGradient(x-18,0,x,0);
    g.addColorStop(0,'rgba(255,255,255,0)');
    g.addColorStop(1,'rgba(255,255,255,.06)');
    ctx.fillStyle=g;
    ctx.fillRect(x-18,chartArea.top,18,chartArea.bottom-chartArea.top);
    ctx.restore();
  },
  afterDatasetsDraw(chart){
    const {ctx}=chart;
    const d=chart.getDatasetMeta(0).data;
    if(!d||!d.length)return;
    const pt=d[d.length-1];
    const col=chart.data.datasets[0].borderColor;
    ctx.save();
    ctx.shadowColor=col;ctx.shadowBlur=8;
    ctx.fillStyle=col;
    ctx.beginPath();ctx.arc(pt.x,pt.y,3,0,Math.PI*2);ctx.fill();
    ctx.shadowBlur=0;
    ctx.font='700 10px -apple-system,Segoe UI,Roboto,sans-serif';
    ctx.fillText(fnum(pt.parsed.y),pt.x+6,pt.y-6);
    ctx.restore();
  }
};
function initCharts(){
  if(!window.Chart){
    document.querySelectorAll('.chartbox .cv').forEach(c=>{
      c.innerHTML='<div class="cfail">Charts unavailable &mdash; CDN blocked. Reload with internet.</div>'});
    return;
  }
  valid=true;
  const red='#ff4d4d',green='#37d67a',acc='#ff9f1c';
  C={};
  C.traf=new Chart(document.getElementById('chTraf'),{type:'line',data:{labels:[],datasets:[
    {label:'Dropped',data:[],borderColor:red,backgroundColor:'rgba(255,77,77,.10)',borderWidth:2,
      pointRadius:0,tension:.35,fill:true},
    {label:'Passed',data:[],borderColor:green,backgroundColor:'rgba(55,214,122,.07)',borderWidth:2,
      pointRadius:0,tension:.35,fill:true}]},
    options:Object.assign({},baseOpt,{scales:{x:axisX,y:axisY(v=>fnum(v))}}),plugins:[liveEnd]});
  C.vol=new Chart(document.getElementById('chVol'),{type:'line',data:{labels:[],datasets:[
    {label:'Bytes/s',data:[],borderColor:acc,backgroundColor:'rgba(255,159,28,.12)',borderWidth:2,
      pointRadius:0,tension:.35,fill:true}]},
    options:Object.assign({},baseOpt,{plugins:Object.assign({},baseOpt.plugins,
      {legend:{display:false}}),scales:{x:axisX,y:axisY(v=>fnum(v))}}),plugins:[liveEnd]});
  C.blk=new Chart(document.getElementById('chBlk'),{type:'line',data:{labels:[],datasets:[
    {label:'Blocked',data:[],borderColor:acc,backgroundColor:'rgba(255,159,28,.12)',borderWidth:2,
      pointRadius:0,tension:.35,fill:true}]},
    options:Object.assign({},baseOpt,{plugins:Object.assign({},baseOpt.plugins,
      {legend:{display:false}}),scales:{x:axisX,y:axisY(v=>fnum(v))}}),plugins:[liveEnd]});
  C.cat=new Chart(document.getElementById('chCat'),{type:'bar',data:{labels:[],datasets:[
    {label:'Total drops',data:[],backgroundColor:[],borderColor:[],borderWidth:1,borderRadius:4}]},
    options:{responsive:true,maintainAspectRatio:false,indexAxis:'y',
      plugins:{legend:{display:false},tooltip:baseOpt.plugins.tooltip},
      scales:{x:{beginAtZero:true,ticks:{color:'#6b6b76',callback:v=>fnum(v),maxTicksLimit:6,font:{size:11}},
        grid:{color:'rgba(255,255,255,.06)'}},
        y:{ticks:{color:'#9a9aa6',font:{size:11.5}},grid:{display:false}}}}});
}
function updateCharts(dpp,pps,bps,blk,m){
  if(!valid)return;
  const now=new Date().toLocaleTimeString('en-GB',{hour12:false});
  hist.t.push(now);hist.drop.push(dpp);hist.pass.push(pps);hist.bps.push(bps);hist.blk.push(blk);
  for(const k in hist){if(hist[k].length>winCap)hist[k].shift()}
  C.traf.data.labels=hist.t;
  C.traf.data.datasets[0].data=hist.drop;
  C.traf.data.datasets[1].data=hist.pass;
  C.traf.update();
  C.vol.data.labels=hist.t;C.vol.data.datasets[0].data=hist.bps;C.vol.update();
  C.blk.data.labels=hist.t;C.blk.data.datasets[0].data=hist.blk;C.blk.update();
  const names=[],vals=[],cols=[];
  for(const c of CATS){
    const tot=m['xdpguard_'+c[1]]||0;
    const live=m['xdpguard_'+c[1]+'_per_sec']||0;
    names.push(c[0]);vals.push(tot);
    cols.push(live>0?'#ff4d4d':'#ff9f1c');
  }
  C.cat.data.labels=names;
  C.cat.data.datasets[0].data=vals;
  C.cat.data.datasets[0].backgroundColor=cols;
  C.cat.data.datasets[0].borderColor=cols.map(c=>c);
  C.cat.update();

  spark(document.getElementById('s_blk'),hist.blk,COLOR.o);
  spark(document.getElementById('s_dpp'),hist.drop,COLOR.d);
  spark(document.getElementById('s_pass'),hist.pass,COLOR.g);
}
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

    set('c_pass',fnum(m.xdpguard_passed_pps,2)+' pkt/s','clg');
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
      '<i class="d">'+fnum(dpp,2)+'</i> vs <i class="g">'+
      fnum(m.xdpguard_passed_pps||0,2)+'</i> pkt/s';
    document.getElementById('lv_vol').textContent=fbw(m.xdpguard_dropped_bps||0)+'/s';
    document.getElementById('lv_blk').innerHTML=blk>0?'<i class="d">'+fnum(blk)+'</i>':'<i class="o">0</i>';

    updateCharts(dpp,m.xdpguard_passed_pps||0,m.xdpguard_dropped_bps||0,blk,m);
  }catch(e){
    st.textContent='Offline';dot.className='p down';
    document.getElementById('metaiface').textContent='engine unreachable';
  }
}
initCharts();setInterval(tick,2000);tick();
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