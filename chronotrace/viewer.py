"""Self-contained HTML timeline viewer (no network, no dependencies). Open viewer.html in any browser."""
import json

TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ChronoTrace timeline viewer</title>
<style>
:root{--bg:#eef1ee;--panel:#f8faf8;--ink:#17262b;--mute:#56676c;--line:#cdd6d3;--corr:#0b6e8a;--raw:#b86a00;
--alert:#a3243b;--ok:#3f7a5f;--focus:#0b6e8a;--dot:#0b6e8a;
--serif:Charter,"Iowan Old Style","Palatino Linotype",Georgia,serif;--sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
@media (prefers-color-scheme:dark){:root{--bg:#121b1e;--panel:#182327;--ink:#e4ecea;--mute:#9bafb0;--line:#2c3d42;
--corr:#5cc3de;--raw:#e0a04a;--alert:#ef7f92;--ok:#79c4a0;--focus:#5cc3de;--dot:#5cc3de}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 var(--sans)}
main{max-width:880px;margin:0 auto;padding:28px 18px 56px}
h1{font:600 clamp(28px,6vw,44px)/1.12 var(--serif);margin:0 0 10px;letter-spacing:-.01em}
h2{font:600 20px/1.3 var(--serif);margin:0 0 6px}
p{margin:0 0 12px;max-width:68ch}
.lede{color:var(--mute);font-size:17px}
.lede b{color:var(--raw)}
button{font:inherit;color:inherit}
:focus-visible{outline:3px solid var(--focus);outline-offset:2px}
#list{list-style:none;margin:24px 0 0;padding:0;border-top:1px solid var(--line)}
#list button{display:flex;gap:12px;align-items:baseline;width:100%;text-align:left;background:none;border:0;
border-bottom:1px solid var(--line);padding:12px 8px;cursor:pointer}
#list button[aria-current=true]{background:var(--panel);box-shadow:inset 4px 0 0 var(--corr)}
.tag{flex:none;min-width:68px;font-weight:600;font-size:14px}
.tag.a{color:var(--alert)}.tag.r{color:var(--ok)}
.row-t{font-weight:600}.row-s{color:var(--mute);font-size:14px;display:block}
section.detail{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin-top:22px;padding:18px}
.meta{color:var(--mute);font-size:14px;margin-bottom:10px}
.ctl{margin:14px 0 4px}
.ctl label{display:flex;justify-content:space-between;font-size:14px;color:var(--mute)}
input[type=range]{width:100%;accent-color:var(--corr);margin:6px 0}
#span{font:600 15px var(--sans);margin-bottom:6px}
#span span{color:var(--corr)}
svg{width:100%;height:auto;display:block;overflow:visible}
svg text{fill:var(--mute);font:11px var(--sans)}
.grid{stroke:var(--line);stroke-width:1}
.lane{stroke:var(--line);stroke-width:1;stroke-dasharray:2 4}
.path{fill:none;stroke:var(--mute);stroke-width:1.2;opacity:.55}
circle{cursor:pointer}
.legend{font-size:13px;color:var(--mute);margin:4px 0 10px}
ol.ev{list-style:decimal;padding-left:24px;margin:8px 0 0}
ol.ev li{padding:6px 0;border-bottom:1px solid var(--line)}
ol.ev li[aria-current=true]{background:color-mix(in srgb,var(--corr) 12%,transparent)}
ol.ev button{background:none;border:0;padding:0;text-align:left;cursor:pointer;width:100%}
.loc{display:block;color:var(--mute);font-size:13px;font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-all}
ul.n{margin:6px 0 0;padding-left:20px}
details{margin-top:22px;border-top:1px solid var(--line);padding-top:10px}
summary{cursor:pointer;font-weight:600}
table{border-collapse:collapse;width:100%;font-size:14px;margin-top:8px}
th,td{text-align:left;padding:6px 8px 6px 0;border-bottom:1px solid var(--line);vertical-align:top}
.scroll{overflow-x:auto}
</style></head><body><main>
<h1 id="head"></h1><p class="lede" id="lede"></p>
<ul id="list" aria-label="Findings"></ul>
<section class="detail" aria-live="polite">
<h2 id="dtitle"></h2><div class="meta" id="dmeta"></div><p id="dtext"></p><div id="dextra"></div>
<div class="ctl"><label for="fix"><span>As the logs say</span><span>Clocks corrected</span></label>
<input id="fix" type="range" min="0" max="100" value="100" aria-label="Move from logged time to corrected time"></div>
<div id="span"></div><div id="chart"></div>
<div class="legend">Each row is one log source. Filled dots are the main evidence; hollow dots are a second log confirming it.</div>
<h2>Evidence, in corrected order</h2><ol class="ev" id="evlist"></ol>
</section>
<details><summary>How the clocks were fixed</summary><div class="scroll"><table id="skew"></table></div><p id="skewnote" class="meta"></p></details>
<details><summary>Data quality: every row accounted for</summary><div class="scroll"><table id="acct"></table></div></details>
</main>
<script id="data" type="application/json">__DATA__</script>
<script>
const D=JSON.parse(document.getElementById('data').textContent);
const $=id=>document.getElementById(id);
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const TITLES={staging_exfil_chain:'Document to data theft',staging_without_entry_point:'Files archived and uploaded',auth_failure_burst:'Password guessing'};
const V=[...D.verdicts].sort((a,b)=>(a.status==='ALERT'?0:1)-(b.status==='ALERT'?0:1)||a.start_utc.localeCompare(b.start_utc));
let cur=0,t=1,hi=-1;
function dur(sec){sec=Math.round(Math.abs(sec));const d=Math.floor(sec/86400),h=Math.floor(sec%86400/3600),m=Math.floor(sec%3600/60),s=sec%60;
const p=[];if(d)p.push(d+'d');if(d||h)p.push(h+'h');if(d||h||m)p.push(m+'m');p.push(s+'s');return p.join(' ')}
const STEPS=[1,2,5,10,15,30,60,120,300,600,900,1800,3600,7200,10800,21600,43200,86400,172800];
function ticks(a,b,n){const span=(b-a)/1000,step=(STEPS.find(s=>span/s<=n)||86400*2)*1000,o=[];
for(let x=Math.ceil(a/step)*step;x<=b;x+=step)o.push(x);return o}
function fmt(x,span){const s=new Date(x).toISOString();return span<300?s.slice(11,19):span<172800?s.slice(5,10)+' '+s.slice(11,16):s.slice(0,10)}
function header(){const al=V.filter(v=>v.status==='ALERT').length,rj=V.length-al;
$('head').textContent=al+(al===1?' alert':' alerts')+', '+rj+(rj===1?' look-alike':' look-alikes')+' cleared';
const s=D.skew.sources,worst=Object.keys(s).sort().reduce((m,k)=>Math.abs(s[k].offset_seconds)>Math.abs(s[m].offset_seconds)?k:m,Object.keys(s).sort()[0]);
const off=s[worst].offset_seconds;
$('lede').innerHTML=off?'Logs from different systems disagreed about the time. The <b>'+esc(worst)+'</b> log was '+dur(off)+(off<0?' ahead':' behind')+'. ChronoTrace fixed the clocks first, then read the story. Drag the slider to see why that matters.':'All clocks agreed, so no correction was needed.'}
function list(){const ul=$('list');ul.innerHTML='';V.forEach((v,i)=>{const li=document.createElement('li'),b=document.createElement('button');
b.setAttribute('aria-current',i===cur);b.innerHTML='<span class="tag '+(v.status==='ALERT'?'a':'r')+'">'+(v.status==='ALERT'?'Alert':'Rejected')+'</span><span><span class="row-t">'+esc(TITLES[v.rule]||v.rule)+'</span><span class="row-s">'+esc(v.subject)+' at '+esc(v.start_utc.slice(0,19).replace('T',' '))+' UTC</span></span>';
b.onclick=()=>{cur=i;hi=-1;list();detail()};li.appendChild(b);ul.appendChild(li)})}
function detail(){const v=V[cur];$('dtitle').textContent=(TITLES[v.rule]||v.rule)+' on '+v.subject;
$('dmeta').textContent=(v.status==='ALERT'?'Alert, '+v.severity+' severity, ':'Rejected as routine, ')+v.confidence+' confidence, '+v.independent_sources+' independent log source'+(v.independent_sources===1?'':'s');
$('dtext').textContent=v.explanation;let x='';
if(v.facts.exfil){const e=v.facts.exfil;x+='<strong>What left the network:</strong><ul class="n"><li>'+e.bytes.toLocaleString()+'-byte archive, '+e.files+' file(s)'+(e.records?', '+e.records.toLocaleString()+' records':'')+'; transfer '+esc(e.status)+'</li></ul>'}
if(v.facts.techniques&&v.facts.techniques.length)x+='<p style="margin:10px 0 0"><strong>Techniques:</strong> '+esc(v.facts.techniques.join(', '))+'</p>';
if(v.reasons.length)x+='<strong>Why:</strong><ul class="n">'+v.reasons.map(r=>'<li>'+esc(r)+'</li>').join('')+'</ul>';
if(v.limitations.length)x+='<strong>Limits:</strong><ul class="n">'+v.limitations.map(r=>'<li>'+esc(r)+'</li>').join('')+'</ul>';
$('dextra').innerHTML=x;evlist();draw()}
function evlist(){const ol=$('evlist');ol.innerHTML='';V[cur].evidence.forEach((e,i)=>{const li=document.createElement('li');li.id='ev'+i;
li.innerHTML='<button><span>'+esc(e.time_utc.slice(11,23))+' &nbsp;'+esc(e.label)+'</span><span class="loc">'+esc(e.stage)+' · '+esc(e.raw_file)+':'+e.raw_line+' · sha256 '+esc(e.raw_sha256.slice(0,12))+'</span></button>';
li.firstChild.onclick=()=>{hi=hi===i?-1:i;mark();draw()};ol.appendChild(li)});}
function mark(){V[cur].evidence.forEach((_,i)=>{const li=$('ev'+i);if(li)li.setAttribute('aria-current',i===hi)})}
function draw(){const v=V[cur],ev=v.evidence,srcs=[...new Set(ev.map(e=>e.source))].sort();
const pts=ev.map((e,i)=>{const r=Date.parse(e.raw_time_utc),c=Date.parse(e.time_utc);return{i,e,c,x:r*(1-t)+c*t,lane:srcs.indexOf(e.source)}});
let a=Math.min(...pts.map(p=>p.x)),b=Math.max(...pts.map(p=>p.x));const spanS=(b-a)/1000;
$('span').innerHTML='These events span <span>'+dur(spanS)+'</span>'+(t<1?' (as logged)':' (corrected)');
if(a===b){a-=500;b+=500}const pad=(b-a)*.05;a-=pad;b+=pad;
const W=Math.max(300,$('chart').clientWidth||640),L=W<500?64:86,R=16,T=12,LH=52,H=T+srcs.length*LH+30,X=x=>L+(x-a)/(b-a)*(W-L-R),Y=l=>T+LH*l+LH/2;
let s='<svg viewBox="0 0 '+W+' '+H+'" role="img" aria-label="Timeline of evidence by log source">';
ticks(a,b,W<500?4:6).forEach(x=>{s+='<line class="grid" x1="'+X(x)+'" x2="'+X(x)+'" y1="'+T+'" y2="'+(H-22)+'"/><text x="'+X(x)+'" y="'+(H-6)+'" text-anchor="middle">'+fmt(x,(b-a)/1000)+'</text>'});
srcs.forEach((n,l)=>{s+='<line class="lane" x1="'+L+'" x2="'+(W-R)+'" y1="'+Y(l)+'" y2="'+Y(l)+'"/><text x="8" y="'+(Y(l)+4)+'">'+esc(n)+'</text>'});
const ord=[...pts].sort((p,q)=>p.c-q.c);s+='<polyline class="path" points="'+ord.map(p=>X(p.x).toFixed(1)+','+Y(p.lane)).join(' ')+'"/>';
pts.forEach(p=>{const hol=p.e.stage==='corroboration',on=p.i===hi;
s+='<circle data-i="'+p.i+'" cx="'+X(p.x).toFixed(1)+'" cy="'+Y(p.lane)+'" r="'+(on?9:6)+'" fill="'+(hol?'var(--panel)':(t<1?'var(--raw)':'var(--dot)'))+'" stroke="'+(t<1?'var(--raw)':'var(--dot)')+'" stroke-width="2"><title>'+esc(p.e.label)+'</title></circle>'});
$('chart').innerHTML=s+'</svg>';
$('chart').querySelectorAll('circle').forEach(c=>c.onclick=()=>{const i=+c.dataset.i;hi=hi===i?-1:i;mark();draw();if(hi>=0)$('ev'+hi).scrollIntoView({block:'nearest'})})}
function tables(){const sk=D.skew,rows=Object.keys(sk.sources).sort();
$('skew').innerHTML='<tr><th>Log</th><th>Offset</th><th>Confidence</th><th>Meaning</th></tr>'+rows.map(k=>{const o=sk.sources[k];
return'<tr><td>'+esc(k)+'</td><td>'+o.offset_seconds+' s</td><td>'+esc(o.confidence)+'</td><td>'+esc(o.description)+'</td></tr>'}).join('');
$('skewnote').textContent='Reference clock: '+sk.reference+' ('+sk.reference_method+').'+(sk.cycle_check_max_residual_s!==null?' Independent cycle check agrees within '+sk.cycle_check_max_residual_s+' s.':'')+(sk.warnings.length?' Warnings: '+sk.warnings.join('; ')+'.':'');
const ac=Object.keys(D.acct).sort();
$('acct').innerHTML='<tr><th>Log</th><th>Raw rows</th><th>Loaded</th><th>Quarantined</th><th>Duplicates</th></tr>'+ac.map(k=>{const a=D.acct[k];
return'<tr><td>'+esc(k)+'</td><td>'+a.raw_rows+'</td><td>'+a.loaded+'</td><td>'+a.quarantined+'</td><td>'+a.duplicates+'</td></tr>'}).join('')}
$('fix').oninput=e=>{t=e.target.value/100;draw()};
let rz;addEventListener('resize',()=>{clearTimeout(rz);rz=setTimeout(draw,120)});
header();list();detail();tables();
</script></body></html>
"""


def render(summary):
    data = {"verdicts": summary["verdicts"], "skew": summary["skew"], "acct": summary["row_accounting"]}
    blob = json.dumps(data, sort_keys=True, ensure_ascii=False).replace("</", "<\\/")
    return TEMPLATE.replace("__DATA__", blob)
