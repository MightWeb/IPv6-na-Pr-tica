(function(){
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const reduce=matchMedia('(prefers-reduced-motion: reduce)').matches;
const wait=ms=>new Promise(r=>setTimeout(r,reduce?Math.min(ms,40):ms));
const store={get(k,d){try{const v=localStorage.getItem(k);return v?JSON.parse(v):d;}catch(_){return d;}},set(k,v){try{localStorage.setItem(k,JSON.stringify(v));}catch(_){}}};

/* ===== tema ===== */
function applyTheme(t){if(t==='system')document.documentElement.removeAttribute('data-theme');else document.documentElement.setAttribute('data-theme',t);
  $$('.theme button').forEach(b=>b.setAttribute('aria-pressed',b.dataset.t===t));try{localStorage.setItem('ipv6-tema',t);}catch(_){}}
let _t='system';try{_t=localStorage.getItem('ipv6-tema')||'system';}catch(_){}
applyTheme(_t);
$('.theme').addEventListener('click',e=>{const b=e.target.closest('[data-t]');if(b)applyTheme(b.dataset.t);});

/* ===== endereços ===== */
function expand(a){a=a.toLowerCase();let g;
  if(a.includes('::')){const[l,r]=a.split('::');const L=l?l.split(':'):[],R=r?r.split(':'):[];g=[...L,...Array(Math.max(0,8-L.length-R.length)).fill('0'),...R];}else g=a.split(':');
  return g.map(x=>x.padStart(4,'0'));}
function compress(g){g=g.map(x=>x.replace(/^0+(?=.)/,''));let bs=-1,bl=0,cs=-1,cl=0;
  g.forEach((x,i)=>{if(x==='0'){if(cs<0){cs=i;cl=1;}else cl++;if(cl>bl){bl=cl;bs=cs;}}else{cs=-1;cl=0;}});
  if(bl<2)return g.join(':');return g.slice(0,bs).join(':')+'::'+g.slice(bs+bl).join(':');}
const validV6=a=>{if(!/^[0-9a-f:]+$/i.test(a)||!a.includes(':')||(a.match(/::/g)||[]).length>1)return false;const g=expand(a);return g.length===8&&g.every(x=>/^[0-9a-f]{4}$/.test(x));};
const norm=a=>compress(expand(a));
const isLL=a=>norm(a).startsWith('fe80:');
const pfx=a=>expand(a).slice(0,4).join(':');
const inLan=a=>pfx(a)==='2001:0db8:0000:0000';
const inWan=a=>pfx(a)==='2001:0db8:cafe:0000';
function sn(a){const l=expand(a).join('').slice(-6);return{ip:norm(`ff02::1:ff${l.slice(0,2)}:${l.slice(2)}`),mac:`33:33:ff:${l.slice(0,2)}:${l.slice(2,4)}:${l.slice(4)}`};}
const big6=a=>expand(a).reduce((b,g)=>(b<<16n)|BigInt(parseInt(g,16)),0n);
const str6=b=>{const g=[];for(let i=0;i<8;i++){g.unshift((b&0xffffn).toString(16));b>>=16n;}return compress(g);};

/* ===== estado da rede ===== */
const LAN=['A','B','X','R'];
const MAC={A:"00:00:00:aa:00:00",B:"00:00:00:aa:00:01",R:"00:00:00:aa:00:02",X:"de:ad:be:ef:00:66",S:"00:00:00:bb:00:80"};
const DNSDB={"www.exemplo.com.br":{AAAA:"2001:db8:cafe::80",A:"192.0.2.80"},"exemplo.com.br":{AAAA:"2001:db8:cafe::80",A:"192.0.2.80"}};
let N,cap,alerts,sniff,W,buffers,tSel,busy=false,selPk=null,t0=0;
function mk(name,mac,ll,addrs,host=true){return{name,mac,ll,addrs:addrs.map((a,i)=>({a,st:'ok',main:i===0})),up:true,neigh:{},routes:host?[{via:'fe80::1',by:'R',pref:'medium'}]:[],fw:[],pmtu:{},ipsec:{}};}
function freshNet(){
  N={A:mk("Host A",MAC.A,"fe80::200:ff:feaa:0",["2001:db8::a"]),
     B:mk("Host B",MAC.B,"fe80::200:ff:feaa:1",["2001:db8::b"]),
     X:mk("Atacante",MAC.X,"fe80::dcad:beff:feef:66",["2001:db8::66"]),
     R:mk("Roteador",MAC.R,"fe80::1",["2001:db8::1","2001:db8:cafe::1"],false),
     S:mk("Servidor web",MAC.S,"fe80::80",["2001:db8:cafe::80"],false)};
  cap=[];alerts=[];sniff=[];W={dos:false,fakeRA:false,raGuard:false,spoof:null,dnsDown:false};
  buffers={A:[],B:[],R:[],X:[]};
  for(const k in buffers)buffers[k].push({c:'d',t:`Terminal de ${N[k].name}. Digite "ajuda" para ver os comandos.`});
  selPk=null;t0=performance.now();
}
const globalOf=k=>{const a=N[k].addrs.find(x=>x.main);return a&&a.st==='ok'?a.a:null;};
function ownerOf(ip){ip=norm(ip);for(const k in N){const n=N[k];if(!n.up)continue;if(n.ll===ip&&LAN.includes(k))return k;if(n.addrs.some(x=>x.a===ip&&x.st==='ok'))return k;}return null;}
const macOwner=m=>Object.keys(N).find(k=>N[k].mac===m);
function allows(n,type){for(const r of n.fw){if(!r.type||r.type===type)return r.j==='ACCEPT';}return true;}
const bestRoute=n=>n.routes.slice().sort((a,b)=>(b.pref==='high')-(a.pref==='high'))[0];

/* ===== desenho ===== */
const P={A:{x:95,y:58},B:{x:95,y:165},X:{x:95,y:272},SW:{x:262,y:165},R:{x:420,y:165},S:{x:612,y:165}};
const svg=$('#topo'),SVGNS="http://www.w3.org/2000/svg";
function nodeStatus(k){const n=N[k];
  if(!n.up)return['● desligado','var(--bad)'];
  const m=n.addrs.find(x=>x.main);
  if(m&&m.st==='failed')return['● DAD falhou','var(--bad)'];
  if(m&&m.st==='tent')return['● testando endereço…','var(--warn)'];
  if(k==='X'){if(W.dos)return['● ataque DAD ativo','var(--bad)'];if(W.fakeRA)return['● anunciando RA falsa','var(--bad)'];if(W.spoof)return['● envenenando cache','var(--bad)'];return['● ocioso','var(--muted)'];}
  if(k==='S')return['www.exemplo.com.br','var(--accent)'];
  if(k==='R'&&W.dnsDown)return['● gateway · DNS PARADO','var(--bad)'];
  if(k==='R')return[W.raGuard?'● gateway + DNS · RA Guard':'● gateway + DNS','var(--ok)'];
  const r=bestRoute(n);if(r&&r.by==='X')return['● rota via atacante!','var(--bad)'];
  if(n.fw.length)return['● firewall ativo','var(--warn)'];
  if(Object.keys(n.ipsec).length)return[`● IPsec ${Object.values(n.ipsec)[0].toUpperCase()}`,'var(--ok)'];
  return['● online','var(--ok)'];}
function draw(){
  let h=`<rect class="zone" x="12" y="10" width="498" height="310" rx="14"/><text class="zl" x="26" y="316">REDE LOCAL · 2001:db8::/64</text>
  <rect class="zone" x="528" y="72" width="164" height="190" rx="14"/><text class="zl" x="540" y="254">INTERNET · cafe::/64</text>
  <text class="zl" x="${P.S.x}" y="104" text-anchor="middle">enlace com MTU 1280</text>`;
  for(const k of ['A','B','X','R'])h+=`<line class="lnk ${N[k].up?'':'down'}" x1="${P[k].x}" y1="${P[k].y}" x2="${P.SW.x}" y2="${P.SW.y}"/>`;
  h+=`<line class="lnk wan" x1="${P.R.x}" y1="${P.R.y}" x2="${P.S.x}" y2="${P.S.y}"/>`;
  h+=`<g class="sw ${W.raGuard?'guard':''}"><rect x="${P.SW.x-42}" y="${P.SW.y-18}" width="84" height="36" rx="8"/><text x="${P.SW.x}" y="${P.SW.y+5}" text-anchor="middle" class="nm" style="font-size:12px">switch</text></g>`;
  for(const k of ['A','B','X','R','S']){const n=N[k],p=P[k],[st,sc]=nodeStatus(k);
    const ip=k==='R'?'2001:db8::1':(globalOf(k)||n.ll);
    h+=`<g class="nd ${k==='X'?'x':''} ${k==='S'?'srv':''} ${k==='X'&&(W.dos||W.fakeRA||W.spoof)?'on':''} ${tSel===k?'sel':''}" data-n="${k}" tabindex="0" role="button" aria-label="${n.name}">
      <rect class="ring" x="${p.x-70}" y="${p.y-33}" width="140" height="66" rx="12"/>
      <rect class="box" x="${p.x-70}" y="${p.y-33}" width="140" height="66" rx="12"/>
      <text class="nm" x="${p.x}" y="${p.y-11}" text-anchor="middle">${n.name}</text>
      <text class="ip" x="${p.x}" y="${p.y+5}" text-anchor="middle">${ip}</text>
      <text class="st" x="${p.x}" y="${p.y+21}" text-anchor="middle" fill="${sc}">${st}</text></g>`;}
  h+='<g id="pks"></g>';svg.innerHTML=h;
}
svg.addEventListener('click',e=>{const g=e.target.closest('[data-n]');if(!g)return;const k=g.dataset.n;
  if(k==='S'){narr('Este é o <b>servidor web</b> de <code>www.exemplo.com.br</code>, um host na Internet. Ele não é seu, então você não tem acesso ao terminal dele, como acontece com qualquer site de verdade.');return;}selectNode(k);});
svg.addEventListener('keydown',e=>{if(e.key==='Enter'){const g=e.target.closest('[data-n]');if(g&&g.dataset.n!=='S')selectNode(g.dataset.n);}});

const COL={NS:'var(--accent)',NA:'var(--ok)',RS:'var(--iid)',RA:'var(--warn)',BAD:'var(--bad)',ECHO:'var(--muted)',DNS:'var(--dns)',PTB:'var(--warn)',TE:'var(--warn)',DATA:'var(--iid)',ESP:'var(--ok)',TCP:'var(--muted)',TLS:'var(--ok)',RST:'var(--bad)'};
function seg(a,b){if((a==='R'&&b==='S')||(a==='S'&&b==='R'))return[P[a],P[b]];if(b==='SW')return[P[a],P.SW];return[P[a],P.SW,P[b]];}
function pts(nodes){let out=[];for(let i=0;i<nodes.length-1;i++){const s=seg(nodes[i],nodes[i+1]);out=out.concat(i?s.slice(1):s);}return out;}
function fly(list,kind,label){
  return new Promise(res=>{const g=$('#pks');if(!g||reduce){res();return;}
    const items=list.map(p=>{const e=document.createElementNS(SVGNS,'g');e.setAttribute('class','pk');
      e.innerHTML=`<circle r="10" fill="${COL[kind]}" stroke="var(--surface)" stroke-width="2"/><text y="-15" text-anchor="middle" fill="${COL[kind]}">${label}</text>`;g.appendChild(e);
      let L=0;const seglen=[];for(let i=0;i<p.length-1;i++){const d=Math.hypot(p[i+1].x-p[i].x,p[i+1].y-p[i].y);seglen.push(d);L+=d;}return{e,p,seglen,L};});
    const maxL=Math.max(...items.map(i=>i.L)),dur=Math.min(1700,Math.max(650,maxL*2.1)),st=performance.now();
    function fr(now){const t=Math.min(1,(now-st)/dur),z=t<.5?2*t*t:1-Math.pow(-2*t+2,2)/2;
      items.forEach(it=>{let d=z*it.L,i=0;while(i<it.seglen.length-1&&d>it.seglen[i]){d-=it.seglen[i];i++;}const r=it.seglen[i]?Math.min(1,d/it.seglen[i]):1,a=it.p[i],b=it.p[i+1]||a;
        it.e.setAttribute('transform',`translate(${a.x+(b.x-a.x)*r},${a.y+(b.y-a.y)*r})`);});
      if(t<1)requestAnimationFrame(fr);else{items.forEach(i=>i.e.remove());res();}}
    requestAnimationFrame(fr);});
}
const flyPath=(nodes,kind,label)=>fly([pts(nodes)],kind,label);
const flyMulti=(from,tos,kind,label)=>fly(tos.map(t=>pts([from,t])),kind,label);
const lanOthers=k=>LAN.filter(x=>x!==k&&N[x].up);

/* ===== captura ===== */
function addPk(p){p.no=cap.length+1;p.time=((performance.now()-t0)/1000).toFixed(3);cap.push(p);renderCap();return p;}
function icmp(o){return Object.assign({hop:o.hop||255,nh:'58 (ICMPv6)'},o,{l4:[['ICMPv6',[`Tipo: ${o.type}`].concat(o.lines||[])]]});}
function renderCap(){
  $('#capCount').textContent=`${cap.length} pacote${cap.length===1?'':'s'}`;
  if(!cap.length){$('#capWrap').innerHTML='<div class="cap-empty">Nenhum pacote ainda. Rode um comando para ver o tráfego aparecer aqui. Depois clique em qualquer linha para ver o que tem dentro do pacote.</div>';$('#detail').hidden=true;return;}
  $('#capWrap').innerHTML=`<table class="cap"><thead><tr><th>Nº</th><th>Tempo</th><th>Origem</th><th>Destino</th><th>Tipo</th><th>Info</th></tr></thead><tbody>${
    cap.map(p=>`<tr class="r ${selPk===p.no?'sel':''} ${p.bad?'bad':''}" data-no="${p.no}"><td>${p.no}</td><td>${p.time}</td><td>${p.src}</td><td>${p.dst}</td><td><i class="k" style="background:${COL[p.kind]}"></i>${p.proto}</td><td>${esc(p.info)}</td></tr>`).join('')}</tbody></table>`;
  const w=$('#capWrap');w.scrollTop=w.scrollHeight;
}
$('#capWrap').addEventListener('click',e=>{const r=e.target.closest('tr[data-no]');if(!r)return;selPk=+r.dataset.no;const p=cap[selPk-1];renderCap();
  const w=$('#capWrap'),row=w.querySelector(`tr[data-no="${selPk}"]`);if(row)row.scrollIntoView({block:'nearest'});showDetail(p);emit('inspect',{p});});
function showDetail(p){
  const d=$('#detail');d.hidden=false;
  const mcast=p.dmac.startsWith('33:33');
  d.innerHTML=`<div class="layer"><b>▸ Ethernet II (camada de enlace)</b><div>MAC origem: ${p.smac}</div><div>MAC destino: ${p.dmac} ${mcast?'<i>(33:33 = multicast)</i>':''}</div></div>
  <div class="layer"><b>▸ IPv6 (camada de rede)</b><div>Origem: ${p.src} ${p.src==='::'?'<i>(não especificado: ainda sem endereço)</i>':''}</div><div>Destino: ${p.dst}</div><div>Próximo cabeçalho: ${p.nh} · Hop limit: ${p.hop}${p.hop===255?' <i>(255 = veio do próprio enlace)</i>':''}</div></div>
  ${(p.l4||[]).map(([t,ls])=>`<div class="layer"><b>▸ ${t}</b>${ls.map(l=>`<div>${l}</div>`).join('')}</div>`).join('')}
  ${p.why?`<p class="why ${p.bad?'bad':''}">${p.why}</p>`:''}`;
}

/* ===== terminal ===== */
function out(k,t,c=''){if(!buffers[k])return;buffers[k].push({t,c});if(k===tSel)renderTerm();}
function renderTerm(){$('#tout').innerHTML=buffers[tSel].map(l=>`<div class="l ${l.c}">${esc(l.t)}</div>`).join('');$('#prompt').textContent=`root@${tSel}:~#`;const t=$('#term');t.scrollTop=t.scrollHeight;}
function selectNode(k,focus=true){tSel=k;$$('#tabs .tab').forEach(b=>b.setAttribute('aria-selected',b.dataset.n===k));renderTerm();draw();if(focus)$('#tin').focus({preventScroll:true});}
$('#tabs').innerHTML=[['A','Host A'],['B','Host B'],['R','Roteador'],['X','Atacante']].map(([k,l])=>`<button class="tab ${k==='X'?'x':''}" role="tab" data-n="${k}">${l}</button>`).join('');
$('#tabs').addEventListener('click',e=>{const b=e.target.closest('[data-n]');if(b)selectNode(b.dataset.n);});
$('#term').addEventListener('click',()=>{if(!getSelection().toString())$('#tin').focus({preventScroll:true});});
const hist=[];let hi=0;
$('#tin').addEventListener('keydown',async e=>{
  if(e.key==='ArrowUp'){if(hi>0){hi--;e.target.value=hist[hi];}e.preventDefault();return;}
  if(e.key==='ArrowDown'){if(hi<hist.length-1){hi++;e.target.value=hist[hi];}else{hi=hist.length;e.target.value='';}e.preventDefault();return;}
  if(e.key!=='Enter'||busy)return;
  const v=e.target.value.trim();e.target.value='';if(v)hist.push(v);hi=hist.length;
  out(tSel,`root@${tSel}:~# ${v}`,'p');if(!v)return;
  busy=true;$('#tin').disabled=true;
  try{await run(tSel,v);}catch(err){out(tSel,'erro: '+err,'e');console.error(err);}
  busy=false;$('#tin').disabled=false;$('#tin').focus({preventScroll:true});draw();
});
const narr=t=>{$('#narr').innerHTML=t;};

/* ===== comandos ===== */
const HELP={
 base:`Comandos:
  ipcalc <endereço>/<prefixo>   explica um endereço (IPv4 ou IPv6)
  ip -6 addr                    endereços IPv6 deste aparelho
  ip -6 neigh                   cache de vizinhos (IP → MAC)
  ip -6 neigh flush all         apaga o cache de vizinhos
  ip -6 route                   rotas (incluindo a rota padrão)
  ip -6 route flush cache       esquece o MTU aprendido
  ip link set eth0 down|up      desliga / liga a interface
  ip addr add <ip>/64 dev eth0  adiciona um endereço
  ping -6 [-c N] [-s TAM] <ip ou nome>
  traceroute -6 <ip ou nome>
  dig AAAA|A <nome>             consulta o DNS
  echo "texto" | nc -6 <ip> <porta>   envia uma mensagem
  nc -zv -6 <ip ou nome> <porta>      testa se uma porta TCP está aberta
  curl -6 http://… | https://…        abre uma página web
  telnet -6 <nome>                    acesso remoto em texto claro (porta 23)
  ssh -6 usuario@<nome>               acesso remoto cifrado (porta 22)
  ip6tables -A|-I INPUT -p icmpv6 [--icmpv6-type TIPO] -j ACCEPT|DROP
  ip6tables -L | -F             lista / apaga regras
  clear                         limpa a tela`,
 host:`
Atalho do laboratório (no livro: setkey):
  ipsec ah|esp|off <ip do outro host>
  setkey -D                     mostra as associações IPsec`,
 X:`
Ferramentas de ataque (simuladas, Experiência 3.1 e extras):
  dos-dad start|stop            responde “é meu” a todo DAD
  fake-ra start|stop            anuncia-se como roteador
  na-spoof <ip> | na-spoof stop finge ser outro aparelho
  tcpdump                       mostra o que foi interceptado`,
 R:`
Monitoramento e proteção:
  ndpmon                        alertas do monitor de NDP
  ra-guard on|off               bloqueia RAs que não vêm do roteador
  systemctl status|start|stop named   controla o serviço de DNS`};
async function run(k,raw){
  const cmd=raw.replace(/\s+/g,' ').trim(),c=cmd.toLowerCase(),n=N[k];let m;
  if(c==='ajuda'||c==='help'){out(k,HELP.base+(k==='A'||k==='B'?HELP.host:'')+(HELP[k]||''),'d');return;}
  if(c==='clear'){buffers[k]=[];renderTerm();return;}
  if((m=c.match(/^ipcalc (\S+)$/)))return ipcalc(k,m[1]);
  if(/^ip -6 (a|addr|address)( show)?$/.test(c))return showAddr(k);
  if(/^ip -6 (n|neigh|neighbou?r) flush( all)?$/.test(c)){n.neigh={};out(k,'(cache de vizinhos apagado)','d');narr(`O ${n.name} esqueceu todos os MACs que tinha aprendido. Na próxima comunicação, vai precisar perguntar de novo com uma NS.`);emit('flush',{k});return;}
  if(/^ip -6 (n|neigh|neighbou?r)( show)?$/.test(c))return showNeigh(k);
  if(/^ip -6 (r|route) flush cache$/.test(c)){n.pmtu={};out(k,'(cache de rotas/MTU apagado)','d');narr('O aparelho esqueceu o tamanho máximo de pacote (MTU) que tinha aprendido para cada destino.');emit('flushcache',{k});return;}
  if(/^ip -6 (r|route)( show)?$/.test(c))return showRoute(k);
  if((m=c.match(/^ip link set (?:dev )?eth0 (up|down)$/))){if(k==='R'){out(k,'(no laboratório, não desligue o roteador)','d');return;}return link(k,m[1]);}
  if((m=c.match(/^ip (?:-6 )?addr(?:ess)? add ([0-9a-f:]+)\/(\d+) dev eth0$/)))return addAddr(k,m[1]);
  if((m=c.match(/^ip (?:-6 )?addr(?:ess)? del ([0-9a-f:]+)\/\d+ dev eth0$/))){const a=norm(m[1]);n.addrs=n.addrs.filter(x=>x.main||x.a!==a);out(k,'(endereço removido)','d');return;}
  if((m=c.match(/^(?:ping -6|ping6)((?: -[cs] \d+)*) (\S+)$/))){const f=m[1]||'';const cc=f.match(/-c (\d+)/),ss=f.match(/-s (\d+)/);return ping(k,m[2],Math.min(cc?+cc[1]:3,6),ss?+ss[1]:56);}
  if((m=c.match(/^(?:traceroute -6|traceroute6) (\S+)$/)))return traceroute(k,m[1]);
  if((m=c.match(/^dig (aaaa|a) (\S+?)\.?$/))||(m=c.match(/^dig (\S+?)\.? (aaaa|a)$/))){let[t,nm]=[m[1],m[2]];if(!/^(aaaa|a)$/.test(t))[t,nm]=[nm,t];return dig(k,nm,t.toUpperCase());}
  if((m=cmd.match(/^echo ["'](.+)["'] \| nc -6 ([0-9a-fA-F:]+) (\d+)$/)))return nc(k,m[1],m[2],+m[3]);
  if((m=c.match(/^nc (?:-6 )?-zv(?: -6)? (\S+) (\d+)$/)))return portcheck(k,m[1],+m[2]);
  if((m=c.match(/^curl(?: -6)?(?: -s)? (\S+)$/)))return curl(k,m[1]);
  if((m=c.match(/^telnet(?: -6)? (\S+)$/)))return telnet(k,m[1]);
  if((m=c.match(/^ssh(?: -6)? (\S+)$/)))return ssh(k,m[1]);
  if(c.startsWith('ip6tables'))return fw(k,c);
  if((m=c.match(/^ipsec (ah|esp|off) ([0-9a-f:]+)$/)))return ipsec(k,m[1],m[2]);
  if(c==='setkey -d'){const e=Object.entries(n.ipsec);out(k,e.length?e.map(([p,mo])=>`${globalOf(k)} ${p}\n\t${mo} mode=transport spi=0x${mo==='ah'?'300':'301'} state=mature\n${p} ${globalOf(k)}\n\t${mo} mode=transport spi=0x${mo==='ah'?'301':'302'} state=mature`).join('\n'):'No SAD entries.');return;}
  if(k==='X'){
    if((m=c.match(/^dos-dad (start|stop)$/)))return dosDad(m[1]==='start');
    if((m=c.match(/^fake-ra (start|stop)$/)))return fakeRA(m[1]==='start');
    if((m=c.match(/^na-spoof (\S+)$/)))return naSpoof(m[1]);
    if(c==='tcpdump'||c.startsWith('tcpdump '))return tcpdump();
  }
  if(k==='R'){
    if(c==='ndpmon')return ndpmon();
    if((m=c.match(/^ra-guard (on|off)$/)))return raGuard(m[1]==='on');
    if((m=c.match(/^systemctl (start|stop|status|restart) (named|bind9)$/)))return systemctl(m[1]==='restart'?'start':m[1]);
  }
  if(/^(dos-dad|fake-ra|na-spoof|tcpdump)/.test(c)){out(k,`${c.split(' ')[0]}: só existe na máquina Atacante`,'e');return;}
  if(/^(ndpmon|ra-guard)/.test(c)){out(k,`${c.split(' ')[0]}: só existe no Roteador`,'e');return;}
  out(k,`${cmd.split(' ')[0]}: comando não reconhecido. Digite "ajuda".`,'e');
}

/* --- ipcalc --- */
function bitsHtml(bits,nb,groupLen,sep){let h='';for(let i=0;i<bits.length;i++){if(i&&i%groupLen===0)h+=`<span class="d">${sep}</span>`;h+=`<span class="${i<nb?'n':'h'}">${bits[i]}</span>`;}return h;}
function ipcalc(k,arg){
  let m=arg.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/);
  if(m){const o=m.slice(1,5).map(Number),p=m[5]===undefined?24:+m[5];
    if(o.some(x=>x>255)||p>32){out(k,'ipcalc: endereço inválido','e');return;}
    const ip=((o[0]<<24)>>>0)+(o[1]<<16)+(o[2]<<8)+o[3],mask=p?(0xffffffff<<(32-p))>>>0:0,net=(ip&mask)>>>0,bc=(net|(~mask>>>0))>>>0;
    const d=x=>[x>>>24,(x>>>16)&255,(x>>>8)&255,x&255].join('.');
    const hosts=p>=31?(p===32?1:2):Math.pow(2,32-p)-2;
    const priv=o[0]===10||(o[0]===172&&o[1]>=16&&o[1]<=31)||(o[0]===192&&o[1]===168);
    const bits=o.map(x=>x.toString(2).padStart(8,'0')).join('');
    out(k,`Endereço:    ${d(ip)}
Prefixo:     /${p}   (máscara ${d(mask)})
Binário:     ${bits.match(/.{8}/g).join('.')}
             ${'r'.repeat(p).padEnd(32,'h').match(/.{8}/g).join('.')}   r = rede, h = host
Rede:        ${d(net)}/${p}
1º aparelho: ${d(p>=31?net:net+1)}
Último:      ${d(p>=31?bc:bc-1)}
Broadcast:   ${d(bc)}
Aparelhos:   ${hosts.toLocaleString('pt-BR')}
Tipo:        ${priv?'privado (rede interna, RFC 1918)':'público'}`);
    narr(`<b>${d(ip)}/${p}</b> em bits. Os <span style="color:var(--accent);font-weight:700">${p} primeiros bits</span> são a rede (a “rua”) e os <span style="color:var(--iid);font-weight:700">${32-p} restantes</span> são o aparelho (o “número da casa”):
      <div class="bits">${bitsHtml(bits,p,8,'.')}</div>
      Todos os aparelhos que começam com <b>${d(net).split('.').slice(0,Math.ceil(p/8)).join('.')}</b>… estão na mesma rede e conversam direto. ${32-p} bits dão ${Math.pow(2,32-p)} combinações; tirando o endereço da rede (${d(net)}) e o de broadcast (${d(bc)}), sobram <b>${hosts.toLocaleString('pt-BR')} aparelhos</b>. Como é ${priv?'um endereço <b>privado</b>, ele só existe dentro da sua rede (por isso o NAT no IPv4)':'público, é alcançável pela Internet'}.`);
    emit('ipcalc',{v:4});return;}
  m=arg.match(/^([0-9a-f:]+)(?:\/(\d{1,3}))?$/i);
  if(m&&validV6(m[1])){const p=m[2]===undefined?64:+m[2];if(p>128){out(k,'ipcalc: prefixo inválido','e');return;}
    const b=big6(m[1]),mask=p?((1n<<128n)-1n)^((1n<<BigInt(128-p))-1n):0n,net=b&mask,last=net|(((1n<<128n)-1n)^mask);
    const cnt=1n<<BigInt(128-p);
    const tipo=isLL(m[1])?'link-local (só vale na rede local)':pfx(m[1]).startsWith('2001:0db8')?'documentação (usado em exemplos e laboratórios)':m[1].toLowerCase().startsWith('f')?'especial (local / multicast)':'global (público)';
    out(k,`Endereço:    ${norm(m[1])}
Completo:    ${expand(m[1]).join(':')}
Prefixo:     /${p}
Rede:        ${str6(net)}/${p}
Primeiro:    ${str6(net)}
Último:      ${str6(last)}
Endereços:   ${cnt.toLocaleString('pt-BR')}  (2^${128-p})
Tipo:        ${tipo}`);
    const g=expand(m[1]);
    narr(`<b>${norm(m[1])}/${p}</b>: mesmo princípio do IPv4, mas com 128 bits escritos em hexadecimal (cada grupo = 16 bits). Os <span style="color:var(--accent);font-weight:700">${p} primeiros bits</span> são a rede e os <span style="color:var(--iid);font-weight:700">${128-p} restantes</span> identificam o aparelho:
      <div class="bits">${g.map((x,i)=>`<span class="${(i+1)*16<=p?'n':'h'}">${x}</span>`).join('<span class="d">:</span>')}</div>
      ${p===64?'O /64 é o tamanho padrão de uma rede IPv6: metade rede, metade aparelho. Cabem ':'Cabem '}<b>${cnt.toLocaleString('pt-BR')}</b> endereços nesta rede. No IPv6 não existe endereço de broadcast, e não é preciso NAT: cada aparelho pode ter um endereço público.`);
    emit('ipcalc',{v:6});return;}
  out(k,'ipcalc: use, por exemplo, ipcalc 192.168.56.101/24 ou ipcalc 2001:db8::a/64','e');
}

/* --- show --- */
function showAddr(k){const n=N[k];
  if(!n.up){out(k,`2: eth0: <BROADCAST,MULTICAST> mtu 1500 state DOWN\n    link/ether ${n.mac}`);narr('A interface está desligada, então nenhum endereço está ativo.');emit('addr',{k,failed:false});return;}
  const fl={ok:'',tent:' tentative',failed:' tentative dadfailed'};
  let s=`1: lo: <LOOPBACK,UP> mtu 65536\n    inet6 ::1/128 scope host\n2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500 state UP\n    link/ether ${n.mac}\n`;
  const own=k==='R'?n.addrs.slice(0,1):n.addrs;
  own.forEach(a=>{s+=`    inet6 ${a.a}/64 scope global${fl[a.st]}\n`;});
  s+=`    inet6 ${n.ll}/64 scope link`;
  if(k==='R')s+=`\n3: eth1: <BROADCAST,MULTICAST,UP> mtu 1280 state UP\n    inet6 2001:db8:cafe::1/64 scope global`;
  const failed=n.addrs.some(a=>a.st==='failed');
  out(k,s,failed?'w':'');
  if(failed)narr(`<b>dadfailed</b>: o ${n.name} desistiu de um endereço porque outro aparelho disse que já o usava. O endereço fica lá, marcado, mas não é usado para nada.${globalOf(k)?'':' Sem endereço global, só sobra o link-local (fe80::), que não sai da rede local.'}`);
  else narr(`O ${n.name} tem dois endereços IPv6: o <b>global</b> (${n.addrs[0].a}), que funciona na Internet, e o <b>link-local</b> (${n.ll}), que só vale nesta rede local e é usado pelo NDP. O <b>/64</b> diz que os primeiros 64 bits são a rede: todos que começam com 2001:db8:0:0 são vizinhos. O <code>link/ether</code> é o endereço físico (MAC) da placa de rede.`);
  emit('addr',{k,failed});}
function showNeigh(k){const n=N[k],e=Object.entries(n.neigh);
  out(k,e.length?e.map(([ip,m])=>`${ip} dev eth0 lladdr ${m} ${macOwner(m)==='R'?'router ':''}REACHABLE`).join('\n'):'(vazio: este aparelho ainda não precisou falar com nenhum vizinho)');
  const poisoned=e.find(([ip,m])=>m===MAC.X&&ownerOf(ip)!=='X');
  if(poisoned)narr(`⚠ <b>Cache envenenado.</b> O IP ${poisoned[0]} aparece com o MAC <b>${MAC.X}</b>, que é do Atacante. O verdadeiro dono tem outro MAC. Tudo o que o ${n.name} mandar para esse IP vai, na verdade, para o Atacante.`);
  else if(e.length)narr(`Este é o <b>cache de vizinhos</b>: a “agenda” de IP → MAC que o NDP preencheu com as respostas NA. É o equivalente ao <code>arp -a</code> do IPv4.${n.neigh['fe80::1']?' Repare: para falar com a Internet, o aparelho só precisa do MAC do <b>roteador</b> (fe80::1), nunca do servidor.':''}`);
  else narr('O cache está vazio. Ele só é preenchido quando o aparelho precisa falar com alguém e pergunta com uma NS.');
  emit('neigh',{k,map:Object.assign({},n.neigh)});}
function showRoute(k){const n=N[k];
  if(!n.up){out(k,'(sem rotas: interface desligada)');emit('route',{k,rogue:false});return;}
  if(k==='R'){out(k,'2001:db8::/64 dev eth0 proto kernel metric 256\n2001:db8:cafe::/64 dev eth1 proto kernel metric 256\nfe80::/64 dev eth0 proto kernel metric 256');narr('O roteador está ligado diretamente às duas redes: a local (eth0) e a da Internet (eth1). Por isso consegue passar pacotes de uma para a outra.');return;}
  const rs=n.routes.slice().sort((a,b)=>(b.pref==='high')-(a.pref==='high'));
  out(k,`${globalOf(k)?'2001:db8::/64 dev eth0 proto kernel metric 256\n':''}fe80::/64 dev eth0 proto kernel metric 256${rs.map(r=>`\ndefault via ${r.via} dev eth0 proto ra metric 1024 pref ${r.pref}`).join('')}`,rs.some(r=>r.by==='X')?'w':'');
  const rogue=rs.some(r=>r.by==='X');
  if(rogue)narr(`⚠ Agora há <b>duas rotas padrão</b>. A do Atacante (<code>${N.X.ll}</code>) tem preferência <b>high</b>, então é ela que vale. Tudo o que for para fora da rede local passa primeiro pelo Atacante. Ninguém digitou isso: o aparelho aprendeu sozinho de uma RA falsa.`);
  else narr(`Leia assim: “<b>2001:db8::/64</b> está direto na eth0” (vizinhos, entrega direta) e “<b>default via fe80::1</b>”: qualquer outro destino vai para o roteador. O <code>proto ra</code> mostra que essa rota foi aprendida de uma <b>Router Advertisement</b>, sem ninguém configurar.${rs.length?'':' Não há rota padrão: este aparelho não sai da rede local.'}`);
  emit('route',{k,rogue});}

/* --- NDP: resolução de vizinho --- */
let lastWhy='';
async function resolveNH(k,nh,src){
  const n=N[k];nh=norm(nh);if(n.neigh[nh])return n.neigh[nh];
  const s=sn(nh);
  addPk(icmp({kind:'NS',proto:'NS',src,dst:s.ip,smac:n.mac,dmac:s.mac,type:'135 (Neighbor Solicitation)',lines:[`Endereço alvo: ${nh}`,`Opção: MAC de origem = ${n.mac}`],info:`Quem tem ${nh}? Responda para ${src}`,
    why:'Pergunta do NDP: “quem tem este IP? me diga seu MAC”. Vai para o multicast <b>solicited-node</b>, formado pelos últimos 24 bits do IP procurado. Só quem tem um endereço com esse final processa a mensagem.'}));
  await flyMulti(k,lanOthers(k),'NS','NS');
  const o=ownerOf(nh);
  if(!o||!LAN.includes(o)){lastWhy=`Ninguém respondeu à NS: não existe aparelho com o endereço ${nh} nesta rede local.`;return null;}
  if(!allows(N[o],'neighbour-solicitation')){lastWhy=`O <b>firewall do ${N[o].name}</b> descartou a NS (regra DROP para ICMPv6). Como ele não responde, ninguém descobre o MAC dele. É como bloquear o ARP no IPv4: a rede local simplesmente para.`;await wait(500);return null;}
  const on=N[o];
  addPk(icmp({kind:'NA',proto:'NA',src:nh,dst:src,smac:on.mac,dmac:n.mac,type:'136 (Neighbor Advertisement)',lines:[`Endereço alvo: ${nh}`,`Opção: MAC do alvo = ${on.mac}`,`Flags: Solicited, Override${o==='R'?', Router':''}`],info:`${nh} está em ${on.mac}`,
    why:'Resposta: “este IP é meu e meu MAC é este”. Repare que nada prova que é verdade. Um atacante poderia mandar uma NA igual com o MAC dele (missão 12).'}));
  await flyPath([o,k],'NA','NA');
  if(!allows(n,'neighbour-advertisement')){lastWhy=`O firewall do ${n.name} descartou a resposta NA.`;return null;}
  n.neigh[nh]=on.mac;if(!on.neigh[src])on.neigh[norm(src)]=n.mac;
  return on.mac;
}
async function prepare(k,dst){
  const n=N[k];dst=norm(dst);
  if(!n.up)return{err:'connect: Network is unreachable',why:'A interface de rede está desligada.'};
  const ll=isLL(dst);
  if(k==='R'&&inWan(dst))return{src:'2001:db8:cafe::1',path:['R','S'],dn:ownerOf(dst),wan:true,viaX:false};
  const src=ll?n.ll:globalOf(k);
  if(!src)return{err:'connect: Cannot assign requested address',why:`O ${n.name} não tem um endereço global válido (o DAD falhou), então não consegue mandar pacotes para ${dst}. Este é o efeito do ataque: <b>negação de serviço</b>.`,noaddr:true};
  let nh;
  if(ll||inLan(dst))nh=dst;
  else{const r=bestRoute(n);if(!r)return{err:'connect: Network is unreachable',why:'Não há rota padrão: o aparelho não sabe para quem entregar pacotes que saem da rede local.'};nh=r.via;}
  if(!ll&&!inLan(dst)&&!inWan(dst))return{err:'connect: Network is unreachable',why:'Esse endereço não existe neste laboratório. Use um da rede local (2001:db8::…) ou o servidor (2001:db8:cafe::80).'};
  const mac=await resolveNH(k,nh,ll||isLL(nh)?n.ll:src);
  if(!mac)return{err:`From ${src} icmp_seq=1 Destination unreachable: Address unreachable`,why:lastWhy,nsfail:true};
  const first=macOwner(mac),dn=ownerOf(dst);
  const path=[k];if(first==='X'&&dn!=='X')path.push('X');
  if(ll||inLan(dst)){if(dn)path.push(dn);else path.push(first);}else{path.push('R');if(dn)path.push('S');}
  const p2=path.filter((x,i)=>x!==path[i-1]);
  return{src,path:p2,dn,wan:!ll&&!inLan(dst),viaX:p2.includes('X')&&dn!=='X'&&k!=='X',nh};
}
const replyPath=(pr,k)=>pr.wan?(pr.path.includes('S')?['S','R',k]:['R',k]):[pr.dn,k];

/* --- DNS --- */
async function resolveName(k,name,type,who='dig'){
  name=name.toLowerCase().replace(/\.$/,'');
  const failMsg=who==='dig'?';; connection timed out; no servers could be reached':`${who}: ${name}: Temporary failure in name resolution`;
  const pr=await prepare(k,'2001:db8::1');
  if(pr.err){out(k,failMsg,'e');narr(pr.why);return{fail:true};}
  const q=addPk({kind:'DNS',proto:'DNS',src:pr.src,dst:'2001:db8::1',smac:N[k].mac,dmac:N[k].neigh['2001:db8::1']||MAC.R,hop:64,nh:'17 (UDP)',l4:[['UDP',['Porta origem: 50123 · Porta destino: 53 (DNS)']],['DNS',[`Pergunta: ${name} tipo ${type}`]]],info:`Consulta ${type} ${name}`,
    why:`O ${N[k].name} pergunta ao servidor DNS (aqui, o roteador) qual é o endereço ${type==='AAAA'?'IPv6 (registro AAAA)':'IPv4 (registro A)'} do nome <b>${name}</b>. O DNS é a “agenda de contatos” da Internet.`});
  if(pr.viaX)sniff.push({src:pr.src,dst:'2001:db8::1',what:`DNS consulta ${type} ${name}`,mode:'none'});
  await flyPath(pr.path,'DNS','DNS?');
  if(W.dnsDown){await wait(900);out(k,failMsg,'e');
    narr(`A pergunta ao DNS saiu (veja na captura), mas <b>ninguém respondeu</b>: o serviço de DNS do roteador está parado. Sem traduzir o nome, o aparelho não sabe para qual IP mandar nada. Para o usuário, parece que “a internet caiu”. Mas a rede está funcionando: o problema é só a “agenda de contatos” (camada 7).`);
    return{fail:true,dnsdown:true};}
  const rec=DNSDB[name],ans=rec?rec[type]:null;
  addPk({kind:'DNS',proto:'DNS',resp:true,src:'2001:db8::1',dst:pr.src,smac:MAC.R,dmac:N[k].mac,hop:64,nh:'17 (UDP)',l4:[['UDP',['Porta origem: 53 · Porta destino: 50123']],['DNS',[`Pergunta: ${name} ${type}`,ans?`Resposta: ${name} ${type} ${ans} (válido por 300 s)`:'Resposta: NXDOMAIN (nome não existe)']]],info:ans?`Resposta ${type} ${ans}`:'NXDOMAIN',
    why:ans?`O DNS respondeu: <b>${name}</b> → <b>${ans}</b>. A partir daqui, o aparelho usa só o número. O nome nunca aparece nos pacotes seguintes.`:'O DNS respondeu que esse nome não existe.'});
  await flyPath(['R',k],'DNS','DNS');
  return{ans,name};
}
async function dig(k,name,type){
  const r=await resolveName(k,name,type,'dig');if(r.fail){emit('dig',{type,found:false,timeout:!!r.dnsdown});return;}
  out(k,`; <<>> DiG <<>> ${type} ${r.name}\n;; ->>HEADER<<- status: ${r.ans?'NOERROR':'NXDOMAIN'}\n\n;; QUESTION SECTION:\n;${r.name}.\t\tIN\t${type}\n${r.ans?`\n;; ANSWER SECTION:\n${r.name}.\t300\tIN\t${type}\t${r.ans}\n`:''}\n;; SERVER: 2001:db8::1#53`);
  if(r.ans)narr(`O DNS traduziu o <b>nome</b> <code>${r.name}</code> para o <b>endereço ${type==='AAAA'?'IPv6':'IPv4'}</b> <code>${r.ans}</code>. Foram só <b>2 pacotes</b> (pergunta e resposta) porque o DNS usa <b>UDP</b> na porta 53: sem conexão, sem confirmação. ${type==='A'?'O mesmo nome tem um endereço IPv6 (AAAA) e um IPv4 (A). Um site pode funcionar nos dois protocolos ao mesmo tempo, e o seu aparelho prefere o IPv6 quando tem.':'Registro <b>AAAA</b> = endereço IPv6. O nome é para humanos; os pacotes só usam números.'}`);
  else narr('Esse nome não existe no DNS. Tente <code>www.exemplo.com.br</code>.');
  emit('dig',{type,found:!!r.ans});}

/* --- ping --- */
async function ping(k,arg,count,size){
  const n=N[k];let dst=arg,name=null;
  if(/[g-z]/i.test(arg)||(!arg.includes(':')&&/[a-z]/i.test(arg))){name=arg.toLowerCase();const r=await resolveName(k,name,'AAAA','ping');if(r.fail){emit('ping',{k,ok:false,dnsfail:!!r.dnsdown,name:true});return;}if(!r.ans){out(k,`ping: ${name}: Name or service not known`,'e');return;}dst=r.ans;}
  if(!validV6(dst)){out(k,`ping: ${arg}: endereço inválido`,'e');return;}
  dst=norm(dst);
  if(ownerOf(dst)===k){out(k,`PING ${dst} ${size} data bytes\n64 bytes from ${dst}: icmp_seq=1 ttl=64 time=0.03 ms`,'o');narr('Você pingou o próprio aparelho.');return;}
  const pr=await prepare(k,dst);
  if(pr.err){out(k,`PING ${dst} ${size} data bytes`);out(k,pr.err,'e');narr(pr.why);emit('ping',{k,ok:false,nsfail:!!pr.nsfail,noaddr:!!pr.noaddr,size});return;}
  const dn=pr.dn,dnN=dn?N[dn]:null,mode=n.ipsec[dst];
  out(k,`PING ${name?`${name}(${dst})`:dst} ${size} data bytes`);
  let recv=0,ptb=false,black=false,frag=false,echoBlocked=false,anim=true;
  const routers=pr.path.length-2,ttl=64-routers;
  const bigPk=size+48>1280&&pr.wan;
  for(let i=1;i<=count;i++){
    if(bigPk&&!n.pmtu[dst]){
      addPk(icmp({kind:'ECHO',proto:'ICMPv6',hop:64,src:pr.src,dst,smac:n.mac,dmac:N[pr.path[1]].mac,type:'128 (Echo Request)',lines:[`Tamanho: ${size+48} bytes`],info:`Echo request seq=${i} (${size+48} bytes)`}));
      if(anim)await flyPath(pr.path.slice(0,pr.path.indexOf('R')+1),'ECHO','grande');
      addPk(icmp({kind:'PTB',proto:'PTB',hop:64,src:'2001:db8::1',dst:pr.src,smac:MAC.R,dmac:n.mac,type:'2 (Packet Too Big)',lines:['MTU do próximo enlace: 1280',`Contém o início do pacote original (${size+48} bytes)`],info:'Packet too big: MTU = 1280',
        why:`O roteador não consegue passar um pacote de ${size+48} bytes para o enlace da Internet, que aceita no máximo <b>1280</b>. No IPv6, <b>roteadores não fragmentam</b>: ele descarta o pacote e avisa a origem com esta mensagem.`}));
      if(anim)await flyPath(['R',k],'PTB','PTB');
      anim=false;
      if(allows(n,'packet-too-big')){n.pmtu[dst]=1280;ptb=true;out(k,`From 2001:db8::1 icmp_seq=${i} Packet too big: mtu=1280`,'w');anim=true;continue;}
      black=true;await wait(250);continue;
    }
    const fr=bigPk&&n.pmtu[dst];if(fr)frag=true;
    const ips=mode?[['IPsec',[mode==='esp'?'ESP: conteúdo cifrado':'AH: autenticado (conteúdo legível)']]]:[];
    if(fr){
      addPk(icmp({kind:'ECHO',proto:mode==='esp'?'ESP':'ICMPv6',hop:64,src:pr.src,dst,smac:n.mac,dmac:N[pr.path[1]].mac,type:'128 (Echo Request)',lines:['Cabeçalho de fragmentação: fragmento 1 de 2 (1280 bytes)'],info:`Echo request seq=${i} [fragmento 1/2]`,why:'Depois do aviso, a <b>própria origem</b> divide o pacote em pedaços de até 1280 bytes. O destino junta os pedaços.'}));
      addPk(icmp({kind:'ECHO',proto:mode==='esp'?'ESP':'ICMPv6',hop:64,src:pr.src,dst,smac:n.mac,dmac:N[pr.path[1]].mac,type:'128 (Echo Request)',lines:[`Cabeçalho de fragmentação: fragmento 2 de 2 (${size+48-1232} bytes)`],info:`Echo request seq=${i} [fragmento 2/2]`}));
    } else addPk(Object.assign(icmp({kind:mode==='esp'?'ESP':'ECHO',proto:mode==='esp'?'ESP':mode==='ah'?'AH+ICMPv6':'ICMPv6',hop:64,src:pr.src,dst,smac:n.mac,dmac:N[pr.path[1]].mac,type:mode==='esp'?'(cifrado)':'128 (Echo Request)',info:mode==='esp'?'ESP (SPI=0x301) conteúdo cifrado':`Echo (ping) request seq=${i}`}),{l4:mode==='esp'?ips:ips.concat([['ICMPv6',['Tipo: 128 (Echo Request)',`Sequência: ${i}`]]])}));
    if(pr.viaX)sniff.push({src:pr.src,dst,what:`ICMP6 echo request seq ${i}`,mode:mode||'none'});
    if(anim){await flyPath(pr.path,mode==='esp'?'ESP':'ECHO',fr?'frag':'ping');}else await wait(200);
    if(!dnN||!allows(dnN,'echo-request')){echoBlocked=true;anim=false;await wait(250);continue;}
    addPk(Object.assign(icmp({kind:mode==='esp'?'ESP':'ECHO',proto:mode==='esp'?'ESP':mode==='ah'?'AH+ICMPv6':'ICMPv6',hop:64,src:dst,dst:pr.src,smac:dnN.mac,dmac:pr.wan?MAC.R:dnN.neigh[norm(pr.src)]||n.mac,type:mode==='esp'?'(cifrado)':'129 (Echo Reply)',info:mode==='esp'?'ESP (SPI=0x302) conteúdo cifrado':`Echo (ping) reply seq=${i}`}),{l4:mode==='esp'?ips:ips.concat([['ICMPv6',['Tipo: 129 (Echo Reply)',`Sequência: ${i}`]]])}));
    if(anim){await flyPath(replyPath(pr,k),mode==='esp'?'ESP':'ECHO','pong');anim=false;}else await wait(150);
    if(!allows(n,'echo-reply'))continue;
    recv++;out(k,`64 bytes from ${dst}: icmp_seq=${i} ttl=${ttl} time=${((pr.wan?11.2:0.4)+i*0.1).toFixed(1)} ms`,'o');
  }
  const loss=Math.round((1-recv/count)*100);
  out(k,`--- ${name||dst} ping statistics ---\n${count} packets transmitted, ${recv} received, ${loss}% packet loss`,recv?'':'e');
  if(black)narr(`<b>Buraco negro de MTU.</b> O roteador avisou “pacote grande demais”, mas o firewall do ${n.name} jogou o aviso fora. O aparelho continua mandando pacotes grandes que nunca chegam, e nenhum erro aparece. Na vida real: sites que abrem só em parte, downloads que travam. Por isso <b>Packet Too Big nunca pode ser bloqueado</b>.`);
  else if(ptb)narr(`Funcionou em duas etapas: o 1º pacote (${size+48} bytes) foi recusado pelo roteador, que respondeu <b>Packet Too Big: mtu=1280</b>. A partir daí, o ${n.name} passou a <b>dividir os pacotes ele mesmo</b> (fragmentos). Clique nos pacotes amarelos e nos fragmentos na captura.`);
  else if(echoBlocked)narr(`A descoberta de vizinho funcionou (houve NS e NA), mas o firewall do ${dnN?dnN.name:'destino'} descartou o <b>Echo Request</b>. Por isso nenhuma resposta chegou.`);
  else if(pr.viaX&&pr.wan)narr(`⚠ Olhe o caminho na topologia: o ping passou <b>pelo Atacante</b> antes de chegar ao roteador. Tudo funcionou, então o usuário não percebe nada. Repare até no <b>ttl=${ttl}</b> (um a menos que o normal): o Atacante virou um “roteador” no meio do caminho.`);
  else if(pr.viaX)narr(`⚠ O ping funcionou, mas passou <b>pelo Atacante</b>, que repassa tudo para o Host B depois de ler.`);
  else if(pr.wan)narr(`O servidor está em <b>outra rede</b> (2001:db8:cafe::/64 é diferente do /64 local). Então o ${n.name} não fala com ele direto: entrega o pacote ao <b>roteador</b> (o gateway), que repassa para a Internet. O <b>ttl=63</b> mostra que passou por 1 roteador.${name?` E você usou o nome: o DNS foi consultado primeiro.`:''}`);
  else narr(`Funcionou. O ${n.name} e o ${dnN.name} estão na mesma rede (mesmo /64), então a entrega é <b>direta</b>, sem passar pelo roteador. Antes do ping houve NS/NA se o MAC ainda não estava no cache. Clique nos pacotes da captura para ver o que tem dentro.`);
  emit('ping',{k,dn,ok:recv>0,viaX:pr.viaX,wan:pr.wan,frag,ptb,black,name:!!name,nsfail:false,size,echoBlocked});
}

/* --- traceroute --- */
async function traceroute(k,arg){
  let dst=arg,name=null;
  if(/[g-z]/i.test(arg)){name=arg;const r=await resolveName(k,arg,'AAAA','traceroute');if(r.fail||!r.ans){if(!r.fail)out(k,`traceroute: ${arg}: nome desconhecido`,'e');return;}dst=r.ans;}
  if(!validV6(dst)){out(k,'traceroute: endereço inválido','e');return;}
  dst=norm(dst);const pr=await prepare(k,dst);if(pr.err){out(k,pr.err,'e');narr(pr.why);return;}
  out(k,`traceroute to ${name||dst} (${dst}), 30 hops max`);
  const hops=pr.path.slice(1);
  const ipOf={X:'2001:db8::66',R:'2001:db8::1'};
  for(let i=0;i<hops.length;i++){const h=hops[i],last=i===hops.length-1,hip=last?dst:ipOf[h];
    addPk({kind:'DATA',proto:'UDP',src:pr.src,dst,smac:N[k].mac,dmac:N[pr.path[1]].mac,hop:i+1,nh:'17 (UDP)',l4:[['UDP',['Porta destino: 33434 (sonda do traceroute)']]],info:`Sonda com hop limit ${i+1}`,
      why:`O traceroute manda uma sonda com <b>hop limit = ${i+1}</b>. Cada roteador diminui esse número em 1. Quando chega a zero, o roteador descarta e avisa quem enviou: assim ele se revela.`});
    await flyPath(pr.path.slice(0,i+2),'DATA',`hop ${i+1}`);
    if(last)addPk(icmp({kind:'TE',proto:'ICMPv6',hop:64,src:hip,dst:pr.src,smac:N[h].mac,dmac:N[k].mac,type:'1 (Destination Unreachable: porta inalcançável)',info:'Port unreachable (chegou ao destino)',why:'O destino final responde “porta inalcançável”. É o sinal de que o traceroute chegou ao fim.'}));
    else addPk(icmp({kind:'TE',proto:'ICMPv6',hop:64,src:hip,dst:pr.src,smac:N[h].mac,dmac:N[k].mac,type:'3 (Time Exceeded)',lines:['Código 0: hop limit chegou a zero em trânsito'],info:`Time exceeded de ${hip}`,why:`O ${N[h].name} recebeu a sonda com hop limit 1, diminuiu para 0, descartou e mandou este <b>Time Exceeded</b> de volta. É assim que ele aparece na lista do traceroute.`}));
    await flyPath(h==='S'?['S','R',k]:[h,k],'TE','');
    out(k,` ${i+1}  ${hip}${h==='X'?'  ← Atacante!':''}  ${(0.4+i*5.3).toFixed(1)} ms`,h==='X'?'e':'');
  }
  narr(`O traceroute mostra cada <b>salto</b> (roteador) no caminho. ${hops.includes('X')?'⚠ O primeiro salto é o Atacante! Numa rede saudável, o primeiro salto é sempre o roteador oficial.':'Aqui são 2 saltos: o roteador da sua rede (2001:db8::1) e o servidor. Na Internet real, costumam ser 10 a 20.'} Ele depende de mensagens ICMPv6 <b>Time Exceeded</b>: se o firewall bloqueá-las, o diagnóstico fica cego.`);
  emit('trace',{k,viaX:hops.includes('X')});}

/* --- TCP: portas, curl, telnet, ssh --- */
const SVC={22:'ssh',23:'telnet',80:'http',443:'https'};
function tcpPk(o){
  const l4=[['TCP (camada 4 · transporte)',[`Porta origem: ${o.sp} · Porta destino: ${o.dp}${SVC[o.dp]?' ('+SVC[o.dp].toUpperCase()+')':''}`,`Flags: ${o.flags}`]]];
  if(o.app)l4.push([o.appTitle,o.app]);
  return Object.assign({hop:64,nh:'6 (TCP)',kind:'TCP',proto:'TCP'},o,{l4});}
async function hostArg(k,h,who){
  h=h.replace(/^\[|\]$/g,'');
  if(validV6(h))return norm(h);
  const r=await resolveName(k,h,'AAAA',who);if(r.fail)return null;
  if(!r.ans){out(k,`${who}: ${h}: nome desconhecido`,'e');return null;}return norm(r.ans);}
async function connect(k,dst,port,who){
  const n=N[k];const pr=await prepare(k,dst);
  if(pr.err){out(k,`${who}: ${pr.err}`,'e');narr(pr.why);return null;}
  const sp=49152+Math.floor(Math.random()*900),dmac=N[pr.path[1]].mac,back=replyPath(pr,k),rsmac=pr.wan?MAC.R:(pr.dn?N[pr.dn].mac:MAC.R);
  addPk(tcpPk({src:pr.src,dst,smac:n.mac,dmac,sp,dp:port,flags:'SYN',info:`${sp} → ${port} [SYN] posso conversar?`,
    why:`<b>1º passo do aperto de mão (handshake) do TCP:</b> “posso abrir uma conversa na porta ${port}?”. O <b>IP</b> leva o pacote até o servidor (camada 3). A <b>porta ${port}</b> diz para qual programa dentro dele (camada 4).`}));
  await flyPath(pr.path,'TCP','SYN');
  if(!pr.dn){await wait(700);out(k,`${who}: connect to ${dst} port ${port}: Connection timed out`,'e');narr('Nenhum aparelho com esse endereço respondeu.');return null;}
  const open=pr.dn==='S'&&!!SVC[port];
  if(!open){
    addPk(tcpPk({kind:'RST',src:dst,dst:pr.src,smac:rsmac,dmac:n.mac,sp:port,dp:sp,flags:'RST, ACK',info:`${port} → ${sp} [RST] ninguém atende nessa porta`,
      why:'<b>RST</b> (reset) significa “não há programa escutando nessa porta”. O servidor está vivo (camada 3 ok), mas esse serviço não existe ou está parado (camada 4). Se fosse um firewall descartando em silêncio, não viria nem o RST: o pedido ficaria sem resposta até estourar o tempo.'}));
    await flyPath(back,'RST','RST');return{open:false,pr,sp};}
  addPk(tcpPk({src:dst,dst:pr.src,smac:rsmac,dmac:n.mac,sp:port,dp:sp,flags:'SYN, ACK',info:`${port} → ${sp} [SYN, ACK] pode sim`,why:'<b>2º passo:</b> o servidor aceita: “pode, estou ouvindo nessa porta”.'}));
  await flyPath(back,'TCP','SYN-ACK');
  addPk(tcpPk({src:pr.src,dst,smac:n.mac,dmac,sp,dp:port,flags:'ACK',info:`${sp} → ${port} [ACK] combinado`,why:'<b>3º passo:</b> o cliente confirma. Conexão aberta. São 3 pacotes antes de qualquer dado: é o preço da confiabilidade do TCP.'}));
  await wait(150);
  return{open:true,pr,sp};}
async function curl(k,url){
  const m=url.match(/^(https?):\/\/(\[[0-9a-f:]+\]|[a-z0-9.-]+)(?::(\d+))?(\/\S*)?$/i);
  if(!m){out(k,'curl: use, por exemplo, curl -6 http://www.exemplo.com.br','e');return;}
  const https=m[1].toLowerCase()==='https',host=m[2].replace(/^\[|\]$/g,''),port=m[3]?+m[3]:(https?443:80),start=cap.length;
  const dst=await hostArg(k,host,'curl');if(!dst){emit('curl',{k,ok:false});return;}
  const c=await connect(k,dst,port,'curl');if(!c){emit('curl',{k,ok:false});return;}
  if(!c.open){out(k,`curl: (7) Failed to connect to ${host} port ${port}: Connection refused`,'e');narr(`O servidor respondeu com <b>RST</b>: não há nenhum programa na porta ${port}. A rede está ok; o problema é de <b>camada 4</b> (porta/serviço).`);emit('curl',{k,ok:false,refused:true});return;}
  const{pr,sp}=c,n=N[k],dmac=N[pr.path[1]].mac,back=replyPath(pr,k),rs=pr.wan?MAC.R:N[pr.dn].mac;
  if(https){
    addPk(tcpPk({kind:'TLS',proto:'TLS',src:pr.src,dst,smac:n.mac,dmac,sp,dp:port,flags:'PSH, ACK',sni:true,appTitle:'TLS 1.3 (criptografia)',app:['Handshake: Client Hello',`SNI (nome do site): ${host}  ← ainda visível`,'Versões aceitas: TLS 1.3, TLS 1.2'],info:`TLS Client Hello (SNI=${host})`,
      why:`O navegador começa o <b>TLS</b>, a camada de criptografia do HTTPS. Repare que o <b>nome do site (SNI)</b> ainda viaja visível: quem está no caminho sabe <i>qual</i> site você acessa, mas não <i>o que</i> você faz nele.`}));
    await flyPath(pr.path,'TLS','hello');
    addPk(tcpPk({kind:'TLS',proto:'TLS',src:dst,dst:pr.src,smac:rs,dmac:n.mac,sp:port,dp:sp,flags:'PSH, ACK',appTitle:'TLS 1.3',app:['Handshake: Server Hello',`Certificado: CN=${DNSDB[host]?host:'www.exemplo.com.br'} (assinado por uma autoridade certificadora)`,'Daqui em diante, tudo cifrado'],info:'TLS Server Hello + certificado',
      why:'O servidor envia seu <b>certificado digital</b>, que prova que ele é mesmo o site que diz ser. Os dois combinam uma chave secreta. O SSL, antecessor do TLS, é obsoleto; hoje se usa TLS 1.2 ou 1.3.'}));
    await flyPath(back,'TLS','cert');
    addPk(tcpPk({kind:'TLS',proto:'TLS',src:pr.src,dst,smac:n.mac,dmac,sp,dp:port,flags:'PSH, ACK',appTitle:'TLS 1.3',app:['Application Data: 3f a1 0c 77 9e 21 … (cifrado)'],info:'Application Data (cifrado)',why:'O pedido HTTP inteiro (página, cookies, senha) está aqui dentro, <b>cifrado</b>.'}));
    await wait(150);
    addPk(tcpPk({kind:'TLS',proto:'TLS',src:dst,dst:pr.src,smac:rs,dmac:n.mac,sp:port,dp:sp,flags:'PSH, ACK',appTitle:'TLS 1.3',app:['Application Data: 9b 04 e7 52 … (cifrado)'],info:'Application Data (cifrado)'}));
    if(pr.viaX)sniff.push({src:pr.src,dst,what:`TLS Client Hello SNI=${host} · depois: Application Data (cifrado, ilegível)`,mode:'tls'});
  }else{
    addPk(tcpPk({kind:'DATA',proto:'HTTP',src:pr.src,dst,smac:n.mac,dmac,sp,dp:port,flags:'PSH, ACK',appTitle:'HTTP (camada 7 · aplicação)',app:['GET / HTTP/1.1',`Host: ${host}`,'Cookie: sessao=8f2c41a9  ← visível!'],info:'GET / HTTP/1.1',
      why:'<b>HTTP sem criptografia:</b> o pedido viaja em <b>texto claro</b>, incluindo o cookie de sessão. Quem estiver no caminho pode copiar o cookie e entrar na sua conta.'}));
    await flyPath(pr.path,'DATA','GET');
    addPk(tcpPk({kind:'DATA',proto:'HTTP',src:dst,dst:pr.src,smac:rs,dmac:n.mac,sp:port,dp:sp,flags:'PSH, ACK',appTitle:'HTTP',app:['HTTP/1.1 200 OK','Content-Type: text/html','<h1>Bem-vindo…</h1>'],info:'HTTP/1.1 200 OK',why:'Resposta <b>200 OK</b>: página encontrada. Códigos 4xx e 5xx indicam erro da <b>aplicação</b> (camada 7), mesmo com a rede funcionando.'}));
    await flyPath(back,'DATA','200');
    if(pr.viaX)sniff.push({src:pr.src,dst,what:`HTTP GET / Host: ${host} Cookie: sessao=8f2c41a9`,mode:'none',secret:true});
  }
  out(k,`<!doctype html>\n<title>Exemplo</title>\n<h1>Bem-vindo ao www.exemplo.com.br</h1>\n<p>Servidor IPv6 do laboratório.</p>`,'o');
  const total=cap.length-start;
  narr(pr.viaX?(https?'⚠ O tráfego passou pelo Atacante, mas cifrado com <b>TLS</b>. Ele vê o nome do site (SNI) e quanto foi transferido, e nada mais.':'⚠ O tráfego passou pelo Atacante <b>em texto claro</b>. Ele viu a página e o <b>cookie de sessão</b>.')
    :`Página recebida. Foram <b>${total} pacotes</b>: ${total>9?'2 de DNS (UDP), ':''}3 só para o aperto de mão do TCP (SYN, SYN-ACK, ACK) e o resto com o conteúdo${https?' cifrado (TLS)':''}. Compare com a consulta DNS em UDP: só 2 pacotes. <b>TCP</b> é confiável, mas conversa mais; <b>UDP</b> é rápido, sem garantia. Clique no <b>SYN</b> na captura.`);
  emit('curl',{k,ok:true,https,viaX:pr.viaX});}
async function telnet(k,host){
  const dst=await hostArg(k,host,'telnet');if(!dst)return;
  out(k,`Trying ${dst}...`);
  const c=await connect(k,dst,23,'telnet');if(!c)return;
  if(!c.open){out(k,'telnet: Unable to connect to remote host: Connection refused','e');return;}
  const{pr,sp}=c,n=N[k],dmac=N[pr.path[1]].mac;
  addPk(tcpPk({kind:'DATA',proto:'TELNET',src:pr.src,dst,smac:n.mac,dmac,sp,dp:23,flags:'PSH, ACK',appTitle:'Telnet (texto claro)',app:['Dados: "admin\\r\\n"'],info:'Telnet dados: admin',why:'O Telnet envia cada tecla digitada como texto puro.'}));
  await flyPath(pr.path,'DATA','login');
  addPk(tcpPk({kind:'BAD',bad:true,proto:'TELNET',src:pr.src,dst,smac:n.mac,dmac,sp,dp:23,flags:'PSH, ACK',appTitle:'Telnet (texto claro)',app:['Dados: "admin123\\r\\n"  ← a senha!'],info:'Telnet dados: admin123  ← SENHA',
    why:'⚠ Na tela, a senha não apareceu (o campo Password ficou em branco). Mas <b>no pacote ela está escrita por extenso</b>. Esconder na tela não é criptografia.'}));
  await flyPath(pr.path,'BAD','senha');
  if(pr.viaX)sniff.push({src:pr.src,dst,what:'TELNET porta 23: login "admin" senha "admin123"',mode:'none',secret:true});
  out(k,`Connected to ${host}.\nEscape character is '^]'.\n\nlogin: admin\nPassword:\nadmin@servidor:~$ exit\nConnection closed by foreign host.`);
  narr(pr.viaX?'⚠ Login feito. Na tela, a senha ficou escondida, mas o Telnet a enviou <b>em texto claro</b> e ela passou pelo Atacante.':'Login feito por <b>Telnet</b> (porta 23). Abra o pacote vermelho na captura: a senha está lá, legível. Telnet, FTP e HTTP são protocolos de <b>texto claro</b>.');
  emit('telnet',{k,viaX:pr.viaX});}
async function ssh(k,arg){
  const mm=arg.match(/^(?:([a-z0-9_]+)@)?(\S+)$/i);if(!mm){out(k,'ssh: use ssh -6 admin@www.exemplo.com.br','e');return;}
  const user=mm[1]||'root',host=mm[2].replace(/^\[|\]$/g,'');
  const dst=await hostArg(k,host,'ssh');if(!dst)return;
  const c=await connect(k,dst,22,'ssh');if(!c)return;
  if(!c.open){out(k,`ssh: connect to host ${host} port 22: Connection refused`,'e');return;}
  const{pr,sp}=c,n=N[k],dmac=N[pr.path[1]].mac,back=replyPath(pr,k),rs=pr.wan?MAC.R:N[pr.dn].mac;
  addPk(tcpPk({kind:'TLS',proto:'SSH',src:pr.src,dst,smac:n.mac,dmac,sp,dp:22,flags:'PSH, ACK',appTitle:'SSH',app:['Versão: SSH-2.0-OpenSSH_9.6','Troca de chaves: curve25519 (Diffie-Hellman)'],info:'SSH-2.0 troca de chaves',why:'Cliente e servidor combinam uma chave secreta <b>sem nunca enviá-la pela rede</b> (troca Diffie-Hellman). Quem observa vê a troca, mas não consegue calcular a chave.'}));
  await flyPath(pr.path,'TLS','chaves');
  addPk(tcpPk({kind:'TLS',proto:'SSH',src:dst,dst:pr.src,smac:rs,dmac:n.mac,sp:22,dp:sp,flags:'PSH, ACK',appTitle:'SSH',app:['Chave pública do servidor: ED25519 SHA256:Xh3kQ9…','Assinatura da troca de chaves'],info:'SSH chave pública do servidor',why:'O servidor prova quem é com sua <b>chave pública</b>. O cliente compara a impressão digital (fingerprint) com a que já conhece. Se mudar de repente, pode ser um atacante se passando pelo servidor.'}));
  await flyPath(back,'TLS','chave');
  addPk(tcpPk({kind:'TLS',proto:'SSH',src:pr.src,dst,smac:n.mac,dmac,sp,dp:22,flags:'PSH, ACK',appTitle:'SSH',app:['Pacote cifrado: c4 19 ab 70 … (a senha está aqui dentro)'],info:'SSH dados cifrados',why:'A senha foi enviada, mas <b>cifrada</b>. Compare com o pacote vermelho do Telnet.'}));
  await wait(150);
  if(pr.viaX)sniff.push({src:pr.src,dst,what:'SSH-2.0 troca de chaves · depois: pacotes cifrados (ilegíveis)',mode:'ssh'});
  out(k,`The authenticity of host '${host} (${dst})' can't be established.\nED25519 key fingerprint is SHA256:Xh3kQ9vL2…\n(aceita automaticamente no laboratório)\n${user}@${host}'s password:\n${user}@servidor:~$ exit\nConnection to ${host} closed.`);
  narr(pr.viaX?'Login por <b>SSH</b>. O tráfego passou pelo Atacante, mas cifrado. A mesma senha que vazou no Telnet agora está protegida.':'Login por <b>SSH</b> (porta 22). Tudo depois da troca de chaves vai cifrado, inclusive a senha. É o substituto seguro do Telnet. O SFTP (transferência de arquivos) usa o mesmo canal SSH.');
  emit('ssh',{k,viaX:pr.viaX});}
async function portcheck(k,host,port){
  const dst=await hostArg(k,host,'nc');if(!dst)return;
  const c=await connect(k,dst,port,'nc');if(!c)return;
  if(c.open){out(k,`Connection to ${host} ${port} port [tcp/${SVC[port]}] succeeded!`,'o');
    narr(`A porta <b>${port}</b> está <b>aberta</b>: o aperto de mão do TCP (SYN, SYN-ACK, ACK) foi completo. Existe um programa (${SVC[port].toUpperCase()}) escutando ali. Um mesmo servidor tem vários serviços, cada um na sua porta, como apartamentos no mesmo prédio.`);}
  else{out(k,`nc: connect to ${host} port ${port} (tcp) failed: Connection refused`,'e');
    narr(`Porta <b>${port} fechada</b>: o servidor respondeu <b>RST</b>. Isso é um ótimo sinal para diagnóstico: o servidor <b>está vivo</b> e a rede funciona (camadas 1 a 3 ok), mas não há serviço nessa porta (camada 4).`);}
  emit('portcheck',{k,port,open:c.open});}
function systemctl(action){
  if(action==='status'){out('R',`● named.service - BIND Domain Name Server\n     Active: ${W.dnsDown?'inactive (dead)':'active (running)'}\n     Listen: [2001:db8::1]:53 UDP/TCP`,W.dnsDown?'e':'o');
    narr(W.dnsDown?'Achou! O serviço de DNS (<b>named</b>, do BIND) está <b>parado</b> no roteador. Por isso os nomes não são traduzidos.':'O DNS está rodando e escutando na porta 53, em UDP e TCP.');}
  else{W.dnsDown=action==='stop';out('R',W.dnsDown?'(named parado)':'(named iniciado)',W.dnsDown?'w':'o');
    narr(W.dnsDown?'DNS parado.':'Serviço de DNS iniciado. Os aparelhos voltam a conseguir traduzir nomes.');}
  draw();emit('dnsctl',{action,up:!W.dnsDown});}

/* --- nc --- */
async function nc(k,msg,dst,port){
  if(!validV6(dst)){out(k,'nc: endereço inválido','e');return;}
  dst=norm(dst);const n=N[k];const pr=await prepare(k,dst);
  if(pr.err){out(k,'nc: '+pr.err,'e');narr(pr.why);emit('nc',{k,ok:false});return;}
  const mode=n.ipsec[dst],dnN=pr.dn?N[pr.dn]:null;
  const l4=mode==='esp'?[['ESP',['SPI: 0x00000301 · Sequência: 1','Dados cifrados: 7f 3a 9c 51 e0 2b 88 c4 …','(o atacante não sabe nem que é TCP, nem a porta)']]]:(mode==='ah'?[['AH',['SPI: 0x00000300','Assinatura (ICV): 5c1e…9a0f']]]:[]).concat([['TCP',[`Porta origem: 49152 · Porta destino: ${port}`]],['Dados',[`"${esc(msg)}"`]]]);
  addPk({kind:mode==='esp'?'ESP':'DATA',proto:mode==='esp'?'ESP':mode==='ah'?'AH+TCP':'TCP',src:pr.src,dst,smac:n.mac,dmac:N[pr.path[1]].mac,hop:64,nh:mode==='esp'?'50 (ESP)':mode==='ah'?'51 (AH)':'6 (TCP)',l4,
    info:mode==='esp'?'ESP (SPI=0x301) conteúdo cifrado':`porta ${port} · dados: "${msg}"${mode==='ah'?' [AH]':''}`,
    why:mode==='esp'?'Com <b>ESP</b>, tudo depois do cabeçalho IPv6 está cifrado. Quem captura vê só origem, destino e bytes embaralhados.':mode==='ah'?'Com <b>AH</b>, o pacote tem uma assinatura: se alguém alterar um único bit, o destino descarta. Mas o conteúdo continua <b>legível</b>.':'Sem proteção: o conteúdo viaja em texto puro. Qualquer um no caminho lê.'});
  if(pr.viaX)sniff.push({src:pr.src,dst,what:`TCP porta ${port}, dados: "${msg}"`,mode:mode||'none',secret:mode!=='esp'});
  await flyPath(pr.path,mode==='esp'?'ESP':'DATA',mode==='esp'?'🔒':'msg');
  if(dnN&&buffers[pr.dn])out(pr.dn,`[nc ${port}] mensagem de ${pr.src}: ${msg}${mode?`  (IPsec ${mode.toUpperCase()} ok)`:''}`,'o');
  narr(pr.viaX?(mode==='esp'?'A mensagem passou pelo Atacante, mas <b>cifrada com ESP</b>. Ele só consegue repassar bytes sem sentido. O Host B decifra e lê normalmente.':mode==='ah'?'A mensagem passou pelo Atacante <b>com AH</b>: ele não consegue alterá-la sem ser descoberto, mas consegue <b>ler</b> tudo.':`⚠ A mensagem chegou ao ${dnN.name}, mas antes passou pelo <b>Atacante</b>, que leu e repassou. Nenhum dos dois percebeu nada: é um ataque <b>man-in-the-middle</b>.`):`Mensagem entregue ao ${dnN?dnN.name:'destino'}. Veja no terminal dele.`);
  emit('nc',{k,ok:true,viaX:pr.viaX,mode:mode||null});}

/* --- interface / DAD / RA --- */
async function dad(k,ao){
  const n=N[k],s=sn(ao.a);
  addPk(icmp({kind:'NS',proto:'NS',src:'::',dst:s.ip,smac:n.mac,dmac:s.mac,type:'135 (Neighbor Solicitation)',lines:[`Endereço alvo: ${ao.a}`],info:`DAD: alguém usa ${ao.a}?`,
    why:'<b>DAD (detecção de endereço duplicado).</b> A origem “::” significa “ainda não tenho endereço”. O aparelho pergunta pelo endereço que <i>quer</i> usar. Se ninguém responder em ~1 segundo, ele assume.'}));
  await flyMulti(k,lanOthers(k),'NS','DAD');
  const other=ownerOf(ao.a);
  if(W.dos&&k!=='X'){
    addPk(icmp({kind:'BAD',bad:true,proto:'NA',src:ao.a,dst:'ff02::1',smac:MAC.X,dmac:'33:33:00:00:00:01',type:'136 (Neighbor Advertisement)',lines:[`Endereço alvo: ${ao.a}`,`Opção: MAC do alvo = ${MAC.X}`,'Flags: Override'],info:`${ao.a} está em ${MAC.X}  ← FALSO`,
      why:`⚠ Resposta forjada pelo Atacante. Ele afirma ser dono de ${ao.a}, que não é dele. Compare o MAC (${MAC.X}) com o do ${n.name} (${n.mac}). O protocolo não confere, então o ${n.name} acredita.`}));
    await flyMulti('X',LAN.filter(x=>x!=='X'&&N[x].up),'BAD','NA!');
    ao.st='failed';
    alerts.push(`[ndpmon] ALERTA wrong couple IP/MAC: ${ao.a} anunciado por ${MAC.X} (esperado ${n.mac})`,`[ndpmon] ALERTA possível DoS no DAD: ${MAC.X} respondeu ao teste de endereço de outro aparelho`);
    out(k,`[kernel] IPv6: eth0: IPv6 duplicate address ${ao.a} used by ${MAC.X} detected!`,'e');
    narr(`<b>O Atacante respondeu</b> com uma NA falsa: “${ao.a} é meu”. O ${n.name} acredita e desiste do endereço. Sem endereço global, ele não consegue falar com ninguém fora do enlace. Qualquer aparelho que entrar na rede terá o mesmo destino.`);
    return 'failed';}
  if(other&&other!==k){const on=N[other];
    addPk(icmp({kind:'NA',proto:'NA',src:ao.a,dst:'ff02::1',smac:on.mac,dmac:'33:33:00:00:00:01',type:'136 (Neighbor Advertisement)',lines:[`Endereço alvo: ${ao.a}`,`Opção: MAC do alvo = ${on.mac}`,'Flags: Override'],info:`${ao.a} está em ${on.mac}`,
      why:`O verdadeiro dono (${on.name}) defende o próprio endereço com uma NA enviada a todos (ff02::1). Quem estava testando desiste.`}));
    await flyMulti(other,LAN.filter(x=>x!==other&&N[x].up),'NA','NA');
    ao.st='failed';out(k,`[kernel] IPv6: eth0: IPv6 duplicate address ${ao.a} used by ${on.mac} detected!`,'e');
    narr(`O ${on.name} respondeu: “${ao.a} já é meu”. O ${n.name} marca o endereço como <b>duplicado</b> e não o usa. O ${on.name} continua funcionando normalmente: o DAD protege quem chegou primeiro.`);
    return 'failed';}
  await wait(600);ao.st='ok';out(k,`[kernel] IPv6: eth0: endereço ${ao.a} pronto`,'o');
  narr(`Ninguém respondeu ao teste. O endereço <b>${ao.a}</b> está livre e o ${n.name} passa a usá-lo.`);
  return 'ok';}
async function link(k,state){
  const n=N[k];
  if(state==='down'){if(!n.up){out(k,'(a interface já está desligada)','d');return;}n.up=false;n.neigh={};n.routes=[];n.pmtu={};draw();
    narr(`A interface do ${n.name} foi desligada: é como tirar o cabo de rede ou desconectar do Wi-Fi. Ele esqueceu os vizinhos e as rotas. Ligue de novo para ver tudo o que acontece quando um aparelho entra numa rede.`);emit('down',{k});return;}
  if(n.up){out(k,'(a interface já está ligada)','d');return;}
  n.up=true;const ao=n.addrs.find(x=>x.main);ao.st='tent';n.addrs=n.addrs.filter(x=>x.main);draw();
  addPk(icmp({kind:'RS',proto:'RS',src:n.ll,dst:'ff02::2',smac:n.mac,dmac:'33:33:00:00:00:02',type:'133 (Router Solicitation)',lines:[`Opção: MAC de origem = ${n.mac}`],info:'Tem algum roteador aí?',
    why:'<b>Router Solicitation:</b> assim que liga, o aparelho pergunta ao grupo de todos os roteadores (ff02::2) “tem roteador aqui?” em vez de esperar o próximo anúncio. Usa o link-local como origem, que ele cria sozinho.'}));
  narr(`1º passo: o ${n.name} acabou de entrar na rede e pergunta “tem algum roteador aí?” (<b>RS</b>).`);
  await flyMulti(k,lanOthers(k),'RS','RS');
  addPk(icmp({kind:'RA',proto:'RA',src:'fe80::1',dst:'ff02::1',smac:MAC.R,dmac:'33:33:00:00:00:01',type:'134 (Router Advertisement)',lines:['Tempo de vida como gateway: 1800 s · Preferência: média','Flags: M=0 (endereço por SLAAC), O=0','Opção prefixo: 2001:db8::/64 (autônomo: monte seu endereço)','Opção MTU: 1500','Opção RDNSS (DNS): 2001:db8::1'],info:'Prefixo 2001:db8::/64, gateway fe80::1, DNS 2001:db8::1',
    why:'<b>Router Advertisement:</b> o roteador diz a todos (ff02::1): “eu sou o gateway, a rede é <b>2001:db8::/64</b>, o DNS é 2001:db8::1”. É tudo o que um aparelho precisa para se configurar sozinho, sem DHCP.'}));
  await flyMulti('R',LAN.filter(x=>x!=='R'&&N[x].up),'RA','RA');
  n.routes=[{via:'fe80::1',by:'R',pref:'medium'}];
  narr(`2º passo: o roteador respondeu com uma <b>RA</b>: prefixo 2001:db8::/64, gateway fe80::1 e DNS. Com o prefixo, o ${n.name} monta o próprio endereço (<b>SLAAC</b>): <code>2001:db8::</code> + seu identificador = <code>${ao.a}</code>.`);
  if(W.fakeRA)await sendFakeRA(true);
  await wait(600);
  const r=await dad(k,ao);
  draw();emit('up',{k,dad:r});}
async function addAddr(k,a){const n=N[k];a=norm(a);
  if(!n.up){out(k,'RTNETLINK: interface desligada','e');return;}
  if(n.addrs.some(x=>x.a===a)){out(k,'RTNETLINK answers: File exists','e');return;}
  const ao={a,st:'tent',main:false};n.addrs.push(ao);draw();
  narr(`O ${n.name} quer usar <b>${a}</b>. Antes, faz o teste de duplicidade (<b>DAD</b>).`);
  const r=await dad(k,ao);draw();emit('addadd',{k,failed:r==='failed'});}

/* --- ataques --- */
async function dosDad(on){W.dos=on;draw();
  out('X',on?'[dos-dad] escutando NS de DAD em eth0…\n[dos-dad] vou responder "esse endereço é meu" para todas.':'[dos-dad] ataque parado.',on?'w':'o');
  narr(on?'O Atacante agora fica escutando e responde a <b>toda</b> verificação de endereço duplicado. Ainda não aconteceu nada visível: o ataque só aparece quando alguém <b>entra</b> na rede. Faça o Host A sair e entrar de novo.':'Ataque desligado. Aparelhos que entrarem na rede voltam a conseguir endereço.');
  emit('dos',{on});}
async function sendFakeRA(fromUp){
  if(W.raGuard){
    addPk(icmp({kind:'BAD',bad:true,proto:'RA',src:N.X.ll,dst:'ff02::1',smac:MAC.X,dmac:'33:33:00:00:00:01',type:'134 (Router Advertisement)',info:'RA do Atacante BLOQUEADA pelo RA Guard',why:'O <b>RA Guard</b> do switch só aceita RAs vindas da porta do roteador oficial. Esta veio da porta do Atacante e foi descartada.'}));
    await flyPath(['X','SW'],'BAD','RA✕');return false;}
  addPk(icmp({kind:'BAD',bad:true,proto:'RA',src:N.X.ll,dst:'ff02::1',smac:MAC.X,dmac:'33:33:00:00:00:01',type:'134 (Router Advertisement)',lines:['Tempo de vida como gateway: 1800 s · Preferência: <b>ALTA</b>','Opção prefixo: 2001:db8::/64',`Opção MAC: ${MAC.X}`],info:'Sou o roteador! (preferência alta)  ← FALSO',
    why:`⚠ <b>RA falsa.</b> O Atacante diz “eu sou o gateway” com preferência alta. Repare: origem ${N.X.ll} e MAC ${MAC.X}, não o fe80::1 do roteador. Os aparelhos aceitam porque, por padrão, ninguém confere quem pode anunciar.`}));
  await flyMulti('X',LAN.filter(x=>x!=='X'&&N[x].up),'BAD','RA!');
  for(const h of ['A','B'])if(N[h].up&&!N[h].routes.some(r=>r.by==='X'))N[h].routes.push({via:N.X.ll,by:'X',pref:'high'});
  return true;}
async function fakeRA(on){
  if(on){W.fakeRA=true;draw();const ok=await sendFakeRA();
    out('X',ok?'[fake-ra] anunciando: "eu sou o roteador" (pref high) a cada 3 s':'[fake-ra] anúncios saindo… mas nenhum host aprendeu a rota (bloqueado?)',ok?'w':'d');
    narr(ok?'O Atacante mandou uma <b>Router Advertisement falsa</b> para todos. Os Hosts A e B aprenderam uma nova rota padrão apontando para ele. Ninguém foi avisado.':'A RA falsa foi descartada pelo switch. O RA Guard está protegendo a rede.');
    emit('fakera',{on:true,blocked:!ok});}
  else{W.fakeRA=false;
    if(!W.raGuard){addPk(icmp({kind:'BAD',bad:true,proto:'RA',src:N.X.ll,dst:'ff02::1',smac:MAC.X,dmac:'33:33:00:00:00:01',type:'134 (Router Advertisement)',lines:['Tempo de vida como gateway: 0 s'],info:'Router lifetime 0 (saindo)'}));await flyMulti('X',LAN.filter(x=>x!=='X'&&N[x].up),'BAD','RA');}
    for(const h of ['A','B'])N[h].routes=N[h].routes.filter(r=>r.by!=='X');
    out('X','[fake-ra] parado (enviado RA com lifetime 0)','o');narr('O Atacante parou e anunciou “tempo de vida 0”. Os aparelhos removeram a rota falsa.');draw();emit('fakera',{on:false});}}
async function raGuard(on){W.raGuard=on;
  if(on){for(const h of ['A','B'])N[h].routes=N[h].routes.filter(r=>r.by!=='X');}
  draw();out('R',on?'[switch] RA Guard ativado: RAs só são aceitas na porta do roteador (porta 4)':'[switch] RA Guard desativado',on?'o':'w');
  narr(on?'<b>RA Guard ligado.</b> O switch agora sabe qual porta tem o roteador de verdade e descarta RAs vindas de qualquer outra. O Atacante não consegue mais renovar a rota falsa, que expira nos hosts.':'RA Guard desligado: qualquer porta pode voltar a anunciar-se como roteador.');
  emit('raguard',{on});}
async function naSpoof(arg){
  if(arg==='stop'){const ip=W.spoof;W.spoof=null;
    if(ip)for(const h of LAN)if(N[h].neigh[ip]===MAC.X&&ownerOf(ip)!==h)delete N[h].neigh[ip];
    out('X','[na-spoof] parado','o');narr('Ataque parado. As entradas falsas expiram e, na próxima conversa, os aparelhos perguntam de novo (NS) e recebem a resposta verdadeira.');draw();emit('naspoof',{on:false});return;}
  if(!validV6(arg)){out('X','na-spoof: endereço inválido','e');return;}
  const ip=norm(arg),o=ownerOf(ip);W.spoof=ip;
  addPk(icmp({kind:'BAD',bad:true,proto:'NA',src:ip,dst:'ff02::1',smac:MAC.X,dmac:'33:33:00:00:00:01',type:'136 (Neighbor Advertisement)',lines:[`Endereço alvo: ${ip}`,`Opção: MAC do alvo = ${MAC.X}`,'Flags: Override (substitua o que você sabia)'],info:`${ip} está em ${MAC.X}  ← FALSO`,
    why:`⚠ <b>NA spoofing.</b> Ninguém perguntou nada (não houve NS), mas o Atacante anuncia “${ip} sou eu” com a flag <b>Override</b>. Os aparelhos atualizam o cache com o MAC dele. É o equivalente IPv6 do ARP spoofing.`}));
  await flyMulti('X',LAN.filter(x=>x!=='X'&&N[x].up),'BAD','NA!');
  for(const h of LAN)if(h!=='X'&&h!==o&&N[h].up)N[h].neigh[ip]=MAC.X;
  alerts.push(`[ndpmon] ALERTA changed ethernet address: ${ip} era ${o?N[o].mac:'?'} e agora é ${MAC.X}`,`[ndpmon] ALERTA NA não solicitada com Override vinda de ${MAC.X}`);
  out('X',`[na-spoof] anunciando ${ip} → ${MAC.X} a cada 2 s\n[na-spoof] encaminhamento ativado (as vítimas não percebem nada)`,'w');
  narr(`O Atacante disse a todos: “${ip} está no meu MAC”. A partir de agora, o tráfego para ${o?N[o].name:ip} passa por ele, que lê e repassa. Isso é um <b>man-in-the-middle</b>.`);
  draw();emit('naspoof',{on:true});}
function tcpdump(){
  if(!sniff.length){out('X','tcpdump: listening on eth0\n(nenhum pacote de outros aparelhos)','d');
    narr('Nada interceptado. Um <b>switch</b> só entrega a cada porta o que é endereçado a ela, então o Atacante não vê a conversa dos outros. Para espionar, ele precisa enganar alguém a mandar o tráfego para ele (RA falsa ou NA falsa).');emit('tcpdump',{count:0,last:null});return;}
  out('X','tcpdump: listening on eth0\n'+sniff.map(s=>`IP6 ${s.src} > ${s.dst}: ${s.mode==='esp'?'ESP(spi=0x301), length 96  [conteúdo cifrado: 7f3a9c51e02b88c4…]':(s.mode==='ah'?'AH(spi=0x300) ':'')+s.what}`).join('\n'),'w');
  const last=sniff[sniff.length-1].mode;
  narr(last==='none'&&!sniff.some(s=>s.secret)?'O Atacante viu cada pacote que passou por ele: origem, destino e tipo.':last==='tls'||last==='ssh'?`Compare as linhas: ${sniff.some(s=>s.secret)?'no <b>Telnet</b> e no <b>HTTP</b>, senha e cookie aparecem por extenso. ':''}No <b>SSH</b> e no <b>HTTPS</b>, o Atacante sabe com quem você falou (endereços, porta e o nome do site no SNI), mas o conteúdo é ilegível. A criptografia não tira o atacante do caminho; ela torna inútil o que ele captura.`:last==='esp'?'Com <b>ESP</b>, o Atacante ainda recebe os pacotes, mas só vê lixo cifrado. Ele não sabe o conteúdo, nem a porta, nem se é TCP ou ping. <b>Confidencialidade garantida.</b>':last==='ah'?'Com <b>AH</b>, o Atacante ainda <b>lê</b> a senha! O AH só garante que ninguém <b>alterou</b> o pacote e que ele veio mesmo do Host A. Para esconder o conteúdo, é preciso ESP.':`O Atacante leu tudo o que passou por ele${sniff.some(s=>s.secret)?', <b>inclusive a senha</b>, escrita por extenso':''}. Ele vê origem, destino e conteúdo.`);
  emit('tcpdump',{count:sniff.length,last,plain:sniff.some(s=>s.secret)});}
function ndpmon(){
  out('R',alerts.length?'[ndpmon] monitorando eth0\n'+alerts.join('\n'):'[ndpmon] monitorando eth0\n[ndpmon] nenhuma anomalia detectada.',alerts.length?'e':'o');
  narr(alerts.length?'O <b>NDPMon</b> guarda um histórico de pares IP ↔ MAC. Quando um MAC novo reivindica um IP que já tinha dono, ou responde a testes de endereço de outros, ele gera alerta. Ele <b>detecta</b>, mas não impede: o administrador precisa agir (achar a porta do switch e desligá-la).':'O NDPMon observa todas as mensagens NDP e aprende os pares IP ↔ MAC normais da rede. Por enquanto, nada suspeito.');
  emit('ndpmon',{n:alerts.length});}

/* --- firewall --- */
const FWT={'neighbor-solicitation':'neighbour-solicitation','neighbor-advertisement':'neighbour-advertisement','neighbour-solicitation':0,'neighbour-advertisement':0,'router-solicitation':0,'router-advertisement':0,'echo-request':0,'echo-reply':0,'packet-too-big':0,'time-exceeded':0,'destination-unreachable':0};
function fw(k,c){const n=N[k];let m;
  if(/^ip6tables (-l|--list)( -n)?( -v)?$/.test(c)){
    out(k,`Chain INPUT (policy ACCEPT)\n${'target'.padEnd(8)}${'prot'.padEnd(8)}regra\n`+(n.fw.length?n.fw.map(r=>`${r.j.padEnd(8)}${'icmpv6'.padEnd(8)}${r.type?'tipo '+r.type:'todos os tipos'}`).join('\n'):'(nenhuma regra)'));
    narr(n.fw.length?'O firewall lê as regras <b>de cima para baixo</b> e para na primeira que combina. Por isso as liberações foram inseridas no topo com <code>-I</code>: se ficassem depois do DROP geral, nunca seriam alcançadas.':'Sem regras: tudo é aceito.');
    emit('fw',{k,action:'list'});return;}
  if(/^ip6tables (-f|--flush)$/.test(c)){n.fw=[];out(k,'(regras apagadas)','d');narr('Todas as regras foram apagadas. O firewall volta a aceitar tudo.');draw();emit('fw',{k,action:'flush'});return;}
  m=c.match(/^ip6tables -(a|i) input -p (?:icmpv6|ipv6-icmp)(?: --icmpv6-type ([a-z-]+))? -j (accept|drop)$/);
  if(!m){out(k,'ip6tables: regra não suportada neste laboratório. Exemplo: ip6tables -A INPUT -p icmpv6 --icmpv6-type echo-request -j DROP','e');return;}
  let t=m[2]||null;if(t){if(!(t in FWT)){out(k,`ip6tables: tipo desconhecido "${t}"`,'e');return;}t=FWT[t]||t;}
  const r={type:t,j:m[3].toUpperCase()};if(m[1]==='i')n.fw.unshift(r);else n.fw.push(r);
  const ex={'neighbour-solicitation':'perguntas de vizinho (NS)','neighbour-advertisement':'respostas de vizinho (NA)','echo-request':'pedidos de ping','echo-reply':'respostas de ping','packet-too-big':'avisos de pacote grande demais','router-advertisement':'anúncios de roteador (RA)'};
  narr(`Regra ${m[1]==='i'?'<b>inserida no topo</b> (-I)':'<b>adicionada no fim</b> (-A)'}: ${r.j==='DROP'?'<b>descartar</b>':'<b>aceitar</b>'} ${t?ex[t]||t:'<b>todo</b> o ICMPv6'} que chegar ao ${n.name}.${!t&&r.j==='DROP'?' Isso é comum no IPv4 com ICMP, mas no IPv6 o ICMPv6 também faz o papel do ARP. Teste e veja.':''}`);
  draw();emit('fw',{k,action:'add',rule:r,insert:m[1]==='i'});}

/* --- IPsec --- */
function ipsec(k,mode,peer){
  if(k!=='A'&&k!=='B'){out(k,'ipsec: use nos Hosts A ou B','e');return;}
  if(!validV6(peer)){out(k,'ipsec: endereço inválido','e');return;}
  peer=norm(peer);const o=ownerOf(peer);const me=globalOf(k);
  if(!o||!['A','B'].includes(o)||o===k){out(k,'ipsec: o outro lado precisa ser o outro host (A ou B)','e');return;}
  if(mode==='off'){delete N[k].ipsec[peer];delete N[o].ipsec[me];out(k,'(IPsec desativado nas duas pontas)','d');narr('IPsec desligado. O tráfego volta a viajar sem proteção.');draw();emit('ipsec',{mode:'off'});return;}
  N[k].ipsec[peer]=mode;N[o].ipsec[me]=mode;
  out(k,`# equivalente no livro (setkey), aplicado nas duas pontas:
flush; spdflush;
add ${me} ${peer} ${mode} 0x${mode==='ah'?'300':'301'} -${mode==='ah'?'A hmac-sha256':'E aes-cbc'} 0x…chave…;
add ${peer} ${me} ${mode} 0x${mode==='ah'?'301':'302'} -${mode==='ah'?'A hmac-sha256':'E aes-cbc'} 0x…chave…;
spdadd ${me} ${peer} any -P out ipsec ${mode}/transport//require;
spdadd ${peer} ${me} any -P in  ipsec ${mode}/transport//require;`,'o');
  narr(mode==='ah'?`<b>IPsec AH</b> ativo entre ${N[k].name} e ${N[o].name}. As duas pontas compartilham uma chave secreta e cada pacote leva uma <b>assinatura</b>. Garante <b>autenticidade e integridade</b>, mas não esconde nada.`:`<b>IPsec ESP</b> ativo entre ${N[k].name} e ${N[o].name}. Agora o conteúdo de cada pacote é <b>cifrado</b> com uma chave que só os dois conhecem. Garante <b>confidencialidade</b>.`);
  draw();emit('ipsec',{mode});}

/* ===== missões ===== */
const XM=MAC.X;
const MISSIONS=[
 {id:1,g:'f',t:'Endereços e prefixos',sub:'O que é /24 e /64',
  intro:['Antes de mexer na rede, entenda o que cada parte de um endereço significa. Você vai usar a calculadora <code>ipcalc</code> com o seu próprio exemplo.','Pense num endereço IP como um endereço de correspondência: uma parte é a <b>rua</b> (a rede) e a outra é o <b>número da casa</b> (o aparelho). A barra diz onde termina a rua.'],
  steps:[
   {ev:'ipcalc',ok:d=>d.v===4,t:'Calcule o seu exemplo, <code>192.168.56.101/24</code>, em qualquer terminal.',h:'ipcalc 192.168.56.101/24'},
   {ev:'ipcalc',ok:d=>d.v===4,t:'Agora experimente outro prefixo e veja quantos aparelhos cabem: <code>/26</code>.',h:'ipcalc 192.168.56.101/26'},
   {ev:'ipcalc',ok:d=>d.v===6,t:'O mesmo raciocínio no IPv6, com o prefixo padrão /64.',h:'ipcalc 2001:db8::a/64'},
   {ev:'addr',ok:d=>d.k==='A',t:'Veja os endereços reais do <b>Host A</b> no laboratório.',h:'ip -6 addr',n:'A'}],
  teach:['Um endereço IP tem duas partes: a <b>rede</b> (a rua) e o <b>aparelho</b> (o número da casa).','A barra <b>/N</b> diz quantos bits, da esquerda para a direita, são da rede. Em 192.168.56.101/24, os 24 primeiros bits (192.168.56) são a rede e o 101 é o aparelho.','Os bits que sobram dizem quantos aparelhos cabem: /24 deixa 8 bits = 256 combinações, menos o endereço da rede e o de broadcast = 254 aparelhos. /26 deixa 6 bits = 62 aparelhos.','Aparelhos com a mesma parte de rede conversam direto. Para falar com outra rede, precisam de um roteador.','No IPv6 é igual, mas com 128 bits. O padrão é <b>/64</b>: metade rede, metade aparelho, com 18 quintilhões de endereços por rede. Todo aparelho tem um endereço <b>link-local</b> (fe80::, só vale na rede local) e um <b>global</b> (vale na Internet).'],
  quiz:[{q:'Em 192.168.56.101/24, qual parte identifica a rede?',o:['192','192.168.56','192.168.56.101','101'],a:1,e:'/24 = 24 bits. Cada número tem 8 bits, então são os três primeiros números.'},
        {q:'Com /24, os endereços 192.168.56.20 e 192.168.57.20 estão na mesma rede?',o:['Sim, só o último número importa','Não: o terceiro número (56 e 57) faz parte da rede'],a:1,e:'Em /24, os três primeiros números são a rede. 56 e 57 são redes diferentes e precisam de um roteador para se falar.'},
        {q:'Num endereço IPv6 /64, quantos bits identificam o aparelho?',o:['24','32','64','128'],a:2,e:'128 bits no total, 64 de rede, sobram 64 para o aparelho.'}]},
 {id:2,g:'f',t:'Descobrir um vizinho',sub:'Exp. 1.1 · NS e NA',
  intro:['O Host A e o Host B são <b>dois computadores na mesma rede local</b>, como o seu notebook e o celular na mesma Wi-Fi.','Para entregar um pacote dentro da rede local, não basta o IP: é preciso o endereço físico da placa de rede (o <b>MAC</b>). Veja como o IPv6 descobre isso.'],
  steps:[
   {ev:'ping',ok:d=>d.k==='A'&&d.dn==='B'&&d.ok,t:'No <b>Host A</b>, pingue o Host B. Olhe a topologia enquanto roda.',h:'ping -6 2001:db8::b',n:'A'},
   {ev:'neigh',ok:d=>d.k==='A'&&d.map['2001:db8::b'],t:'Veja o que o Host A aprendeu no cache de vizinhos.',h:'ip -6 neigh',n:'A'},
   {ev:'inspect',ok:d=>d.p.proto==='NS',t:'Na captura, clique no pacote <b>NS</b> (azul). Repare no destino: um multicast.'},
   {ev:'inspect',ok:d=>d.p.proto==='NA'&&!d.p.bad,t:'Agora clique na <b>NA</b> (verde) e encontre o MAC do Host B.'}],
  teach:['Na rede local, os pacotes são entregues pelo endereço físico, o <b>MAC</b>. O IP sozinho não basta.','Quem quer falar pergunta com uma <b>Neighbor Solicitation (NS)</b>: “quem tem o IP 2001:db8::b? Qual é o seu MAC?”.','A pergunta vai para um grupo <b>multicast</b> que, na prática, só o dono provável escuta. É mais educado que o broadcast do IPv4, que acorda todo mundo.','O dono responde com uma <b>Neighbor Advertisement (NA)</b>: “sou eu, meu MAC é este”. A resposta fica guardada no <b>cache de vizinhos</b>.','Isso substitui o ARP do IPv4. E tem a mesma fraqueza: <b>ninguém confere se a NA é verdadeira</b>.'],
  quiz:[{q:'Qual mensagem pergunta “qual é o MAC de quem tem este IP”?',o:['Router Advertisement','Neighbor Solicitation','Neighbor Advertisement','Echo Request'],a:1,e:'A NS (Neighbor Solicitation) pergunta, a NA (Neighbor Advertisement) responde.'},
        {q:'Por que a NS vai para um multicast especial e não para todos?',o:['Para incomodar só quem tem chance de ser o dono','Porque é criptografada','Para conseguir sair para a Internet'],a:0,e:'O endereço solicited-node usa os últimos 24 bits do IP procurado. Só quem tem um IP com esse final escuta.'},
        {q:'Qual protocolo do IPv4 o NDP substitui nessa função?',o:['DNS','DHCP','ARP','ICMP Echo'],a:2,e:'O ARP do IPv4 faz a mesma coisa: traduz IP em MAC.'}]},
 {id:3,g:'f',t:'Entrar na rede',sub:'Exp. 1.2–1.6 · RS, RA, SLAAC',
  intro:['O que acontece nos primeiros segundos depois que você conecta um aparelho numa rede? No IPv6, ele se configura <b>sozinho</b>, sem servidor DHCP.','Você vai desconectar o Host B e conectar de novo, acompanhando cada mensagem.'],
  steps:[
   {ev:'down',ok:d=>d.k==='B',t:'No <b>Host B</b>, desligue a interface de rede (como tirar o cabo).',h:'ip link set eth0 down',n:'B'},
   {ev:'up',ok:d=>d.k==='B'&&d.dad==='ok',t:'Ligue de novo e acompanhe as mensagens na topologia.',h:'ip link set eth0 up',n:'B'},
   {ev:'inspect',ok:d=>d.p.proto==='RA'&&!d.p.bad,t:'Clique no pacote <b>RA</b> (laranja). Encontre o prefixo e o DNS anunciados.'},
   {ev:'route',ok:d=>d.k==='B',t:'Veja a rota padrão que o Host B aprendeu sozinho.',h:'ip -6 route',n:'B'},
   {ev:'inspect',ok:d=>d.p.proto==='NS'&&d.p.src==='::',t:'Clique na NS com origem <code>::</code>. É o último teste antes de usar o endereço.'}],
  teach:['Ao conectar, o aparelho cria sozinho um endereço <b>link-local</b> (fe80::) para conseguir conversar na rede local.','Ele pergunta “tem roteador aqui?” com uma <b>Router Solicitation (RS)</b>.','O roteador responde com uma <b>Router Advertisement (RA)</b>: o prefixo da rede, “eu sou o gateway” e o DNS. Os roteadores também repetem esse anúncio de tempos em tempos.','Com o prefixo, o aparelho monta o próprio endereço global: prefixo + identificador. Isso se chama <b>SLAAC</b> (autoconfiguração sem estado).','Antes de usar, ele testa se o endereço está livre (<b>DAD</b>). Pronto: endereço, rota e DNS, sem DHCP. Ponto de atenção: o aparelho confia em <b>qualquer</b> RA (missão 11).'],
  quiz:[{q:'No IPv6, quem informa a rota padrão (gateway) ao aparelho?',o:['O servidor DHCPv6','A Router Advertisement do roteador','O DNS','O switch'],a:1,e:'A rota padrão vem da RA. Até quando se usa DHCPv6, o gateway continua vindo da RA.'},
        {q:'O que é SLAAC?',o:['Um tipo de ataque','O aparelho monta o próprio endereço usando o prefixo anunciado','Um servidor que distribui endereços','Um protocolo de criptografia'],a:1,e:'Stateless Address Autoconfiguration: ninguém precisa guardar quem recebeu qual endereço.'},
        {q:'Para qual endereço a RA é enviada?',o:['ff02::1 (todos os aparelhos)','ff02::2 (todos os roteadores)','O endereço do Host B','2001:db8::1'],a:0,e:'O roteador anuncia para todos os nós do enlace. A RS, ao contrário, vai para ff02::2.'}]},
 {id:4,g:'f',t:'Endereço duplicado',sub:'Exp. 1.4 · DAD',
  intro:['Dois aparelhos com o mesmo endereço causariam confusão: os pacotes iriam para o lugar errado. O IPv6 tem um teste para evitar isso, o <b>DAD</b> (detecção de endereço duplicado).','Você vai tentar colocar no Host B o endereço que já pertence ao Host A.'],
  steps:[
   {ev:'addadd',ok:d=>d.k==='B'&&d.failed,t:'No <b>Host B</b>, tente usar o endereço do Host A.',h:'ip addr add 2001:db8::a/64 dev eth0',n:'B'},
   {ev:'addr',ok:d=>d.k==='B'&&d.failed,t:'Veja como o Host B marcou esse endereço.',h:'ip -6 addr',n:'B'},
   {ev:'inspect',ok:d=>d.p.proto==='NA'&&!d.p.bad,t:'Na captura, clique na <b>NA</b> com que o Host A defendeu o endereço.'},
   {ev:'ping',ok:d=>d.k==='A'&&d.ok,t:'Confirme que o Host A segue funcionando: pingue o roteador.',h:'ping -6 2001:db8::1',n:'A'}],
  teach:['Antes de usar um endereço, o aparelho pergunta “alguém já usa este endereço?” com uma NS de origem <b>::</b> (“ainda não tenho endereço”).','Se o dono responder com uma NA, o endereço está ocupado: o novo aparelho o marca como <b>dadfailed</b> e não o usa.','Quem já usava o endereço <b>continua funcionando</b>. O DAD protege quem chegou primeiro.','Se ninguém responder em cerca de 1 segundo, o endereço está livre.','Problema: o DAD acredita em <b>qualquer</b> resposta. Um atacante pode responder “é meu” para todo mundo (missão 10).'],
  quiz:[{q:'Qual é o endereço de origem de uma NS de DAD?',o:['O endereço testado','fe80::1','::','ff02::1'],a:2,e:'“::” significa “não especificado”: o aparelho ainda não tem endereço válido para usar como origem.'},
        {q:'Quando o DAD detecta um duplicado, o que acontece com quem já usava o endereço?',o:['Perde o endereço','Continua funcionando normalmente','Os dois ficam sem rede'],a:1,e:'Só quem estava testando desiste do endereço.'}]},
 {id:5,g:'f',t:'Saindo para a Internet',sub:'Gateway e traceroute',
  intro:['Até aqui tudo aconteceu dentro da rede local. À direita da topologia está um <b>servidor web na Internet</b> (o “site”), numa rede diferente: <code>2001:db8:cafe::/64</code>.','Entre a sua rede e a Internet existe o <b>roteador</b>. Veja como um computador local alcança um site.'],
  steps:[
   {ev:'ping',ok:d=>d.k==='A'&&d.wan&&d.ok,t:'No <b>Host A</b>, pingue o servidor web.',h:'ping -6 2001:db8:cafe::80',n:'A'},
   {ev:'neigh',ok:d=>d.k==='A'&&d.map['fe80::1'],t:'Veja o cache de vizinhos. De quem o Host A conhece o MAC: do servidor ou do roteador?',h:'ip -6 neigh',n:'A'},
   {ev:'trace',ok:d=>d.k==='A',t:'Descubra cada salto até o servidor.',h:'traceroute -6 2001:db8:cafe::80',n:'A'},
   {ev:'inspect',ok:d=>d.p.l4&&d.p.l4[0][1][0].includes('3 (Time Exceeded)'),t:'Clique num pacote <b>Time Exceeded</b>: é assim que o traceroute descobre os roteadores.'}],
  teach:['O aparelho compara o prefixo do destino com o seu. <b>Mesma rede</b>: entrega direto ao vizinho. <b>Rede diferente</b>: entrega ao gateway (o roteador).','Por isso, para acessar um site, o seu computador só descobre o MAC do <b>roteador</b>, nunca o do servidor. Endereços MAC só valem dentro da rede local.','Cada roteador no caminho diminui o <b>hop limit</b> (no IPv4, TTL) em 1. É por isso que a resposta veio com ttl=63.','O <b>traceroute</b> aproveita isso: manda sondas com hop limit 1, 2, 3… e cada roteador que zera o contador responde <b>Time Exceeded</b>, revelando-se.','Na Internet real, um site costuma estar a 10 a 20 saltos de distância.'],
  quiz:[{q:'Ao pingar um servidor na Internet, de quem o Host A precisa descobrir o MAC?',o:['Do servidor','Do roteador (gateway)','Do DNS','De ninguém'],a:1,e:'O pacote é entregue ao roteador na rede local. O MAC do servidor nunca aparece na sua rede.'},
        {q:'Como o Host A sabe que o servidor está fora da rede local?',o:['O prefixo do servidor (cafe::/64) é diferente do seu /64','O servidor avisa','Pelo nome do site','Pelo MAC'],a:0,e:'É a comparação de prefixos da missão 1 sendo usada na prática.'},
        {q:'Que mensagem o traceroute usa para descobrir os roteadores?',o:['Packet Too Big','Time Exceeded','Router Advertisement','Neighbor Solicitation'],a:1,e:'Cada roteador que zera o hop limit devolve um ICMPv6 Time Exceeded.'}]},
 {id:6,g:'f',t:'Nomes e DNS',sub:'Exp. 2.1–2.2 · host x nome x IP',
  intro:['Você não digita <code>2001:db8:cafe::80</code> no navegador, digita <code>www.exemplo.com.br</code>. Esse texto é um <b>nome</b>, não um host nem um IP.','O <b>DNS</b> é a agenda de contatos da Internet: traduz nomes em endereços. Neste laboratório, o roteador também é o servidor DNS.'],
  steps:[
   {ev:'dig',ok:d=>d.type==='AAAA'&&d.found,t:'Pergunte ao DNS o endereço <b>IPv6</b> do site.',h:'dig AAAA www.exemplo.com.br',n:'A'},
   {ev:'dig',ok:d=>d.type==='A'&&d.found,t:'Agora o endereço <b>IPv4</b> do mesmo nome.',h:'dig A www.exemplo.com.br',n:'A'},
   {ev:'ping',ok:d=>d.name&&d.ok,t:'Pingue usando o nome em vez do número.',h:'ping -6 www.exemplo.com.br',n:'A'},
   {ev:'inspect',ok:d=>d.p.proto==='DNS'&&d.p.resp,t:'Na captura, clique numa <b>resposta DNS</b> e veja a tradução.'}],
  teach:['<b>Host</b> é qualquer aparelho com IP: seu notebook, um celular, o servidor de um site.','<b>Nome</b> (ou domínio), como www.claude.com, é um apelido legível. Ele não aparece dentro dos pacotes.','<b>Endereço IP</b> é o número que os pacotes realmente usam.','O <b>DNS</b> traduz o nome no IP. Registro <b>A</b> = endereço IPv4, registro <b>AAAA</b> = endereço IPv6. Um mesmo nome pode ter os dois.','Sequência ao abrir um site: nome → consulta DNS → IP → pacotes para o IP (via gateway, se for outra rede).'],
  quiz:[{q:'O que é “www.claude.com”?',o:['Um endereço IP','Um nome que o DNS traduz para o IP de um servidor','Um host da sua rede local','Um prefixo de rede'],a:1,e:'É um nome. O host é o servidor que está por trás dele, identificado por um ou mais IPs.'},
        {q:'Qual registro DNS guarda um endereço IPv6?',o:['A','AAAA','MX','PTR'],a:1,e:'A é IPv4 (32 bits), AAAA é IPv6 (128 bits, quatro vezes maior, daí os quatro As).'}]},
 {g:'f',t:'Portas, TCP e UDP',sub:'Camadas 4 e 7 · aperto de mão',
  intro:['O IP leva o pacote até o <b>aparelho</b> certo. Mas um servidor roda vários programas ao mesmo tempo: site, acesso remoto, e-mail. A <b>porta</b> diz para qual programa o pacote vai. Pense no IP como o endereço do prédio e na porta como o número do apartamento.','Para chegar ao programa existem dois “jeitos de entregar”: <b>TCP</b>, que combina antes e confirma tudo, e <b>UDP</b>, que só envia.'],
  steps:[
   {ev:'dig',ok:d=>d.type==='AAAA'&&d.found,t:'Faça uma consulta DNS e conte os pacotes.',h:'dig AAAA www.exemplo.com.br',n:'A'},
   {ev:'inspect',ok:d=>d.p.proto==='DNS',t:'Clique num pacote DNS e veja a camada <b>UDP</b> e a porta 53.'},
   {ev:'curl',ok:d=>d.ok&&!d.https,t:'Agora abra a página do site por HTTP.',h:'curl -6 http://www.exemplo.com.br',n:'A'},
   {ev:'inspect',ok:d=>d.p.flags==='SYN',t:'Clique no pacote <b>SYN</b>: o começo do aperto de mão do TCP.'},
   {ev:'portcheck',ok:d=>d.port===80&&d.open,t:'Teste se a porta 80 (HTTP) do servidor está aberta.',h:'nc -zv -6 2001:db8:cafe::80 80',n:'A'},
   {ev:'portcheck',ok:d=>!d.open,t:'Teste uma porta onde não há nenhum programa: 8080.',h:'nc -zv -6 2001:db8:cafe::80 8080',n:'A'},
   {ev:'inspect',ok:d=>d.p.flags&&d.p.flags.startsWith('RST'),t:'Clique no <b>RST</b> (vermelho) e leia o que ele significa.'}],
  teach:['<b>Protocolo</b> é a regra da conversa. <b>Porta</b> é o número que identifica o programa dentro do aparelho: 22 SSH, 53 DNS, 80 HTTP, 443 HTTPS.','<b>IP</b> (camada 3) entrega no aparelho. <b>TCP/UDP</b> (camada 4) entregam no programa certo. <b>HTTP, DNS, SSH</b> (camada 7) são a conversa do programa.','<b>TCP</b> é como uma ligação telefônica: antes de falar, combina (SYN, SYN-ACK, ACK), confirma tudo e reenvia o que se perder. Usado em sites, e-mail e SSH.','<b>UDP</b> é como mandar uma mensagem: envia e pronto, sem combinar nem confirmar. É mais rápido e é usado em DNS, voz, vídeo e jogos. Uma consulta DNS foram 2 pacotes; abrir a página levou bem mais.','Porta fechada responde <b>RST</b>: o servidor está vivo, mas não há serviço ali. Se não vier nada, provavelmente um firewall está descartando em silêncio. “ping” não é protocolo e não usa porta: ele usa mensagens ICMP.'],
  quiz:[{q:'Qual é a porta padrão do HTTPS?',o:['22','53','80','443'],a:3,e:'HTTP usa 80; HTTPS (HTTP + TLS) usa 443.'},
        {q:'Qual protocolo de transporte faz o aperto de mão SYN, SYN-ACK, ACK?',o:['UDP','TCP','ICMP','IP'],a:1,e:'O TCP estabelece a conexão antes de mandar dados. O UDP não.'},
        {q:'Você testa uma porta e recebe RST. O que isso indica?',o:['O servidor está desligado','O servidor responde, mas não há programa escutando nessa porta','O DNS caiu'],a:1,e:'RST é uma resposta ativa do servidor: ele está vivo, só não tem aquele serviço.'}]},
 {id:7,g:'f',t:'Pacotes grandes',sub:'Exp. 1.10 · Path MTU',
  intro:['Cada enlace tem um tamanho máximo de pacote, o <b>MTU</b>. O enlace entre o roteador e a Internet aceita no máximo <b>1280 bytes</b>.','No IPv4, os roteadores dividiam pacotes grandes no meio do caminho. No IPv6, <b>não</b>. Veja o que acontece e como um firewall mal configurado quebra tudo.'],
  steps:[
   {ev:'ping',ok:d=>d.k==='A'&&d.ptb&&d.ok,t:'Envie pings de 1400 bytes ao servidor.',h:'ping -6 -s 1400 -c 3 2001:db8:cafe::80',n:'A'},
   {ev:'inspect',ok:d=>d.p.proto==='PTB',t:'Clique no <b>Packet Too Big</b> e veja o MTU informado.'},
   {ev:'fw',ok:d=>d.k==='A'&&d.rule&&d.rule.type==='packet-too-big'&&d.rule.j==='DROP',t:'Agora cometa o erro clássico: bloqueie Packet Too Big no firewall do Host A.',h:'ip6tables -A INPUT -p icmpv6 --icmpv6-type packet-too-big -j DROP',n:'A'},
   {ev:'flushcache',ok:d=>d.k==='A',t:'Faça o Host A esquecer o MTU que tinha aprendido.',h:'ip -6 route flush cache',n:'A'},
   {ev:'ping',ok:d=>d.k==='A'&&d.black,t:'Repita o ping grande.',h:'ping -6 -s 1400 -c 3 2001:db8:cafe::80',n:'A'},
   {ev:'ping',ok:d=>d.k==='A'&&d.wan&&d.ok&&d.size<=1232,t:'Agora um ping de tamanho normal. Funciona?',h:'ping -6 2001:db8:cafe::80',n:'A'}],
  teach:['<b>MTU</b> é o maior pacote que um enlace aceita. O mínimo garantido no IPv6 é 1280 bytes.','No IPv6, <b>roteadores não fragmentam</b>. Se o pacote não cabe, o roteador o descarta e devolve um ICMPv6 <b>Packet Too Big</b> com o MTU certo.','A <b>origem</b> então divide os próximos pacotes em fragmentos menores. Isso é o <b>Path MTU Discovery</b>.','Se um firewall bloqueia Packet Too Big, pacotes pequenos funcionam e os grandes somem <b>sem nenhum erro</b>: o “buraco negro de MTU”. Na prática: sites que carregam pela metade e downloads que travam.','Lição: no IPv6, <b>nunca bloqueie todo o ICMPv6</b> (missão 14).'],
  quiz:[{q:'No IPv6, quem fragmenta um pacote grande demais?',o:['Os roteadores no caminho','A própria origem, depois do aviso Packet Too Big','O switch','O servidor de destino'],a:1,e:'Roteadores IPv6 só avisam. A divisão é feita na origem.'},
        {q:'Com Packet Too Big bloqueado, o que acontece?',o:['Nada muda','Pacotes pequenos passam e os grandes somem sem erro','A rede inteira para','O DNS deixa de funcionar'],a:1,e:'É o buraco negro de MTU, um dos problemas mais difíceis de diagnosticar.'}]},
 {g:'f',t:'A internet caiu?',sub:'Diagnóstico por camadas',setup:()=>{W.dnsDown=true;},
  intro:['Um usuário liga: <b>“a internet caiu!”</b>. Antes de reiniciar tudo, um bom técnico testa <b>camada por camada</b>, de baixo para cima, até achar onde está o problema.','Neste cenário, algo foi quebrado de propósito. Descubra o quê usando só os comandos que você já conhece.'],
  steps:[
   {ev:'ping',ok:d=>d.k==='A'&&d.dnsfail,t:'Reproduza a queixa do usuário: no <b>Host A</b>, pingue o site pelo nome.',h:'ping -6 www.exemplo.com.br',n:'A'},
   {ev:'ping',ok:d=>d.k==='A'&&d.wan&&d.ok&&!d.name,t:'Camada 3: pingue o mesmo servidor pelo <b>endereço IP</b>.',h:'ping -6 2001:db8:cafe::80',n:'A'},
   {ev:'portcheck',ok:d=>d.port===80&&d.open,t:'Camada 4: o serviço web do servidor responde?',h:'nc -zv -6 2001:db8:cafe::80 80',n:'A'},
   {ev:'dig',ok:d=>d.timeout,t:'Camada 7: pergunte direto ao DNS.',h:'dig AAAA www.exemplo.com.br',n:'A'},
   {ev:'dnsctl',ok:d=>d.action==='status'&&!d.up,t:'No <b>Roteador</b> (que é o servidor DNS), veja o estado do serviço.',h:'systemctl status named',n:'R'},
   {ev:'dnsctl',ok:d=>d.action==='start'&&d.up,t:'Conserte: inicie o DNS.',h:'systemctl start named',n:'R'},
   {ev:'ping',ok:d=>d.k==='A'&&d.name&&d.ok,t:'Confirme com o usuário: o site pelo nome funciona?',h:'ping -6 www.exemplo.com.br',n:'A'}],
  teach:['Teste de baixo para cima. <b>Camada 2</b>: os vizinhos se enxergam? (<code>ip -6 neigh</code>; se aparecer FAILED, o problema é no enlace).','<b>Camada 3</b>: o pacote chega? (<code>ping</code> no <b>IP</b>; “Network unreachable” na hora = sem rota).','<b>Camada 4</b>: a porta responde? (<code>nc -zv</code>; RST = serviço parado; nada = firewall descartando).','<b>Camada 7</b>: a aplicação funciona? (DNS responde? o site devolve 200 ou erro 500?).','Dica de ouro: <b>falha de DNS parece queda de internet</b>. Se o ping no IP funciona e no nome não, o culpado é o DNS. E lembre: o DNS usa UDP 53, mas também TCP 53 para respostas grandes. Liberar só UDP no firewall quebra essas respostas.'],
  quiz:[{q:'O ping pelo IP funciona, mas pelo nome não. Onde está o problema?',o:['No cabo de rede','No roteador','No DNS (camada 7)','No servidor web'],a:2,e:'A rede entrega pacotes (camada 3 ok). O que falha é a tradução de nome.'},
        {q:'“Connection refused” (RST) aponta para qual camada?',o:['Camada 2','Camada 3','Camada 4 (porta/serviço)','Camada 1'],a:2,e:'O host respondeu, então as camadas de baixo funcionam; o serviço naquela porta não.'},
        {q:'Por que liberar TCP 53 além de UDP 53 no firewall de um DNS?',o:['Não é necessário','Respostas grandes demais para UDP são repetidas em TCP','O TCP é mais rápido'],a:1,e:'O servidor marca a resposta como truncada e o cliente repete a consulta por TCP.'}]},
 {id:8,g:'s',t:'Ataque DoS ao DAD',sub:'Exp. 3.1 · ataque e detecção',
  intro:['Na missão 4 você viu o DAD proteger um endereço. Agora um aparelho infectado vai abusar dele: responder “é meu” para <b>todos</b> os testes. Assim ninguém novo consegue endereço.','Depois, você vai detectar o ataque com o <b>NDPMon</b>, como no livro.'],
  steps:[
   {ev:'dos',ok:d=>d.on,t:'No <b>Atacante</b>, inicie o ataque.',h:'dos-dad start',n:'X'},
   {ev:'down',ok:d=>d.k==='A',t:'No <b>Host A</b>, desligue a interface (simula sair da rede).',h:'ip link set eth0 down',n:'A'},
   {ev:'up',ok:d=>d.k==='A'&&d.dad==='failed',t:'Ligue de novo e observe o teste de endereço.',h:'ip link set eth0 up',n:'A'},
   {ev:'ping',ok:d=>d.k==='A'&&d.noaddr,t:'Tente acessar o servidor. O Host A consegue?',h:'ping -6 2001:db8:cafe::80',n:'A'},
   {ev:'inspect',ok:d=>d.p.bad&&d.p.proto==='NA',t:'Na captura, clique na <b>NA falsa</b> (vermelha) e compare o MAC.'},
   {ev:'ndpmon',ok:d=>d.n>0,t:'No <b>Roteador</b>, consulte o monitor NDPMon.',h:'ndpmon',n:'R'},
   {ev:'dos',ok:d=>!d.on,t:'Pare o ataque.',h:'dos-dad stop',n:'X'},
   {ev:'down',ok:d=>d.k==='A',t:'Desligue a interface do Host A…',h:'ip link set eth0 down',n:'A'},
   {ev:'up',ok:d=>d.k==='A'&&d.dad==='ok',t:'…e ligue de novo para recuperar o endereço.',h:'ip link set eth0 up',n:'A'}],
  teach:['O DAD acredita em qualquer NA que diga “esse endereço é meu”.','Um aparelho malicioso pode responder a <b>todos</b> os testes. Resultado: nenhum aparelho que entra na rede consegue endereço global. É uma <b>negação de serviço (DoS)</b> feita só com mensagens normais do protocolo.','O ataque só aparece quando alguém entra na rede: quem já estava conectado não é afetado.','<b>Detectar</b>: o NDPMon guarda os pares IP ↔ MAC conhecidos e alerta quando um MAC reivindica endereços de outros.','<b>Impedir</b>: SEND (NDP com assinatura criptográfica, pouco adotado) e recursos do switch que limitam quem pode enviar mensagens NDP em cada porta.'],
  quiz:[{q:'O que o atacante faz neste ataque?',o:['Envia RAs falsas','Responde a todos os testes de DAD dizendo que o endereço é dele','Inunda a rede com pings','Quebra a criptografia'],a:1,e:'Ele envia NAs falsas em resposta a cada NS de DAD.'},
        {q:'O NDPMon impede o ataque?',o:['Sim, bloqueia o atacante','Não, ele detecta e alerta; alguém precisa agir'],a:1,e:'É um monitor. A ação (desligar a porta do switch, por exemplo) é do administrador.'},
        {q:'Quem é afetado pelo ataque?',o:['Todos os aparelhos imediatamente','Só aparelhos que entram (ou reentram) na rede','Só o roteador'],a:1,e:'O DAD só acontece quando um endereço vai ser configurado.'}]},
 {id:9,g:'s',t:'RA falsa',sub:'Rogue RA · man-in-the-middle',
  intro:['Na missão 3, o Host B aceitou o roteador porque recebeu uma RA. E se <b>outra máquina</b> mandar uma RA dizendo “eu sou o roteador”?','Este ataque não está no livro, mas é um dos mais comuns em redes IPv6 e usa exatamente o que você aprendeu.'],
  steps:[
   {ev:'fakera',ok:d=>d.on&&!d.blocked,t:'No <b>Atacante</b>, comece a se anunciar como roteador.',h:'fake-ra start',n:'X'},
   {ev:'route',ok:d=>d.k==='A'&&d.rogue,t:'No <b>Host A</b>, veja as rotas.',h:'ip -6 route',n:'A'},
   {ev:'ping',ok:d=>d.k==='A'&&d.wan&&d.viaX,t:'Pingue o servidor e observe o caminho na topologia.',h:'ping -6 2001:db8:cafe::80',n:'A'},
   {ev:'trace',ok:d=>d.k==='A'&&d.viaX,t:'Confirme com o traceroute quem é o primeiro salto.',h:'traceroute -6 2001:db8:cafe::80',n:'A'},
   {ev:'tcpdump',ok:d=>d.count>0,t:'No Atacante, veja o que ele interceptou.',h:'tcpdump',n:'X'},
   {ev:'raguard',ok:d=>d.on,t:'No <b>Roteador</b> (que aqui também gerencia o switch), ative o RA Guard.',h:'ra-guard on',n:'R'},
   {ev:'route',ok:d=>d.k==='A'&&!d.rogue,t:'Confira as rotas do Host A.',h:'ip -6 route',n:'A'},
   {ev:'ping',ok:d=>d.k==='A'&&d.wan&&d.ok&&!d.viaX,t:'Pingue de novo: o tráfego volta ao caminho certo.',h:'ping -6 2001:db8:cafe::80',n:'A'}],
  teach:['Os aparelhos aceitam como gateway quem enviar uma Router Advertisement. Não há senha nem verificação.','Um atacante envia uma <b>RA falsa</b> com prioridade alta. Todos passam a mandar o tráfego para a Internet através dele.','Tudo continua funcionando, então ninguém percebe. Pistas: rota padrão estranha (<code>ip -6 route</code>), primeiro salto diferente no traceroute, TTL um a menos.','O atacante pode ler, alterar ou bloquear o tráfego (<b>man-in-the-middle</b>). Também pode anunciar um DNS falso.','Defesa: <b>RA Guard</b> no switch, que só aceita RAs vindas da porta do roteador oficial.'],
  quiz:[{q:'Por que os aparelhos aceitam a RA do atacante?',o:['Porque ela é criptografada','Porque, por padrão, qualquer um pode enviar RA e não há verificação','Porque o atacante tem um IP público'],a:1,e:'O NDP foi projetado para redes confiáveis.'},
        {q:'Qual a principal defesa contra RA falsa?',o:['Bloquear todo o ICMPv6','RA Guard no switch','Desligar o DNS','Usar senha no Wi-Fi'],a:1,e:'O RA Guard só aceita RAs da porta onde está o roteador legítimo. Bloquear todo o ICMPv6 quebraria a rede.'},
        {q:'Como você percebeu o ataque pelo terminal?',o:['O ping falhou','Apareceu uma segunda rota padrão e o traceroute mostrou o atacante como 1º salto','O computador reiniciou'],a:1,e:'O ataque é silencioso: só aparece se você olhar.'}]},
 {id:10,g:'s',t:'Cache envenenado',sub:'NA spoofing · man-in-the-middle',
  intro:['Na missão 2, o Host A acreditou na NA do Host B. Agora o Atacante vai mandar NAs <b>falsas</b> dizendo “eu sou o Host B”.','É o equivalente IPv6 do famoso ARP spoofing. O objetivo é ficar no meio da conversa e ler tudo.'],
  steps:[
   {ev:'ping',ok:d=>d.k==='A'&&d.dn==='B'&&d.ok&&!d.viaX,t:'Primeiro, uma conversa normal: pingue o Host B.',h:'ping -6 2001:db8::b',n:'A'},
   {ev:'naspoof',ok:d=>d.on,t:'No <b>Atacante</b>, finja ser o Host B.',h:'na-spoof 2001:db8::b',n:'X'},
   {ev:'neigh',ok:d=>d.k==='A'&&d.map['2001:db8::b']===XM,t:'No Host A, veja o cache de vizinhos. Compare com o MAC real do Host B (00:00:00:aa:00:01).',h:'ip -6 neigh',n:'A'},
   {ev:'nc',ok:d=>d.k==='A'&&d.viaX,t:'Envie uma “senha” ao Host B.',h:'echo "senha=banana123" | nc -6 2001:db8::b 9000',n:'A'},
   {ev:'tcpdump',ok:d=>d.plain,t:'No Atacante, veja o que ele capturou.',h:'tcpdump',n:'X'},
   {ev:'ndpmon',ok:d=>d.n>0,t:'No <b>Roteador</b>, veja se o NDPMon percebeu.',h:'ndpmon',n:'R'},
   {ev:'naspoof',ok:d=>!d.on,t:'Pare o ataque.',h:'na-spoof stop',n:'X'}],
  teach:['O cache de vizinhos é preenchido com base em NAs, e ninguém confere se elas são verdadeiras.','O atacante envia NAs falsas, sem ninguém perguntar, com a flag <b>Override</b>: “o IP do Host B agora está no meu MAC”.','O Host A passa a mandar para o atacante tudo o que era do Host B. O atacante lê e repassa, então a conversa continua funcionando e <b>ninguém percebe</b>.','Pista: o mesmo MAC aparece para IPs de aparelhos diferentes no <code>ip -6 neigh</code>. O NDPMon alerta quando o MAC de um IP muda.','Defesas: monitoramento, proteções no switch e, principalmente, <b>criptografia</b>. Se o tráfego estiver cifrado, ler não adianta (missão 15).'],
  quiz:[{q:'Qual mensagem o atacante falsifica?',o:['Neighbor Advertisement','Router Solicitation','DNS','Echo Reply'],a:0,e:'Ele envia NAs dizendo que o IP da vítima pertence ao MAC dele.'},
        {q:'Por que a vítima não percebe nada?',o:['Porque o atacante repassa o tráfego e tudo continua funcionando','Porque a rede fica lenta','Porque o atacante desliga o firewall'],a:0,e:'É a essência do man-in-the-middle: ficar no meio sem quebrar a comunicação.'}]},
 {g:'s',t:'Texto claro x cifrado',sub:'Telnet x SSH · HTTP x HTTPS',
  intro:['Vários protocolos antigos enviam tudo em <b>texto claro</b>: Telnet, FTP, HTTP, POP3 sem TLS, SNMP v1/v2c. Funcionam bem, até alguém estar no caminho.','O Atacante vai usar a RA falsa (missão 11) para ficar entre você e a Internet. Você vai acessar o mesmo servidor de quatro jeitos e ver o que ele consegue ler.'],
  steps:[
   {ev:'fakera',ok:d=>d.on&&!d.blocked,t:'No <b>Atacante</b>, coloque-se no caminho para a Internet.',h:'fake-ra start',n:'X'},
   {ev:'telnet',ok:d=>d.k==='A'&&d.viaX,t:'No <b>Host A</b>, entre no servidor por <b>Telnet</b> (porta 23).',h:'telnet -6 www.exemplo.com.br',n:'A'},
   {ev:'tcpdump',ok:d=>d.plain,t:'No Atacante, veja o que ele capturou.',h:'tcpdump',n:'X'},
   {ev:'ssh',ok:d=>d.k==='A'&&d.viaX,t:'Agora entre no mesmo servidor por <b>SSH</b> (porta 22).',h:'ssh -6 admin@www.exemplo.com.br',n:'A'},
   {ev:'curl',ok:d=>d.ok&&!d.https&&d.viaX,t:'Abra o site por <b>HTTP</b>.',h:'curl -6 http://www.exemplo.com.br',n:'A'},
   {ev:'curl',ok:d=>d.ok&&d.https&&d.viaX,t:'Abra o mesmo site por <b>HTTPS</b>.',h:'curl -6 https://www.exemplo.com.br',n:'A'},
   {ev:'tcpdump',ok:d=>d.last==='tls',t:'Compare tudo no tcpdump do Atacante.',h:'tcpdump',n:'X'},
   {ev:'inspect',ok:d=>d.p.sni,t:'Na captura, clique no <b>TLS Client Hello</b> e descubra o que ainda vaza mesmo com HTTPS.'}],
  teach:['Protocolos de <b>texto claro</b> mandam tudo legível, inclusive senhas: Telnet (23), FTP (20/21), HTTP (80), POP3 (110), SNMP v1/v2c (community “public”).','Cada um tem um substituto cifrado: <b>Telnet → SSH</b> (22), <b>FTP → SFTP</b> (22) ou FTPS, <b>HTTP → HTTPS</b> (443), <b>POP3 → POP3S</b> (995), <b>SNMP → SNMPv3</b>.','HTTPS = HTTP dentro do <b>TLS</b>. O TLS garante confidencialidade, integridade e autenticidade (pelo certificado). Use TLS 1.2 ou 1.3; todas as versões de <b>SSL</b> são obsoletas.','O SSH usa <b>chave pública</b> para provar que o servidor é legítimo. Se a impressão digital (fingerprint) mudar de repente, desconfie.','Criptografia não esconde tudo: o atacante ainda vê <b>quem fala com quem</b>, quanto e o <b>nome do site (SNI)</b>. E não o tira do caminho. Por isso se combinam defesas: RA Guard, que impede o desvio, e criptografia, que torna o desvio inútil.'],
  quiz:[{q:'Qual é o substituto seguro do Telnet?',o:['FTP','SSH','HTTP','SNMP'],a:1,e:'O SSH faz o mesmo acesso remoto por linha de comando, mas cifrado.'},
        {q:'Com HTTPS, o que o atacante no caminho ainda consegue ver?',o:['Nada','As senhas digitadas','O nome do site (SNI) e os endereços, mas não o conteúdo','A página inteira'],a:2,e:'Os metadados continuam visíveis; o conteúdo, não.'},
        {q:'Qual é a situação do SSL hoje?',o:['É o padrão atual','Todas as versões são obsoletas; usa-se TLS 1.2 ou 1.3','Só funciona em IPv4'],a:1,e:'O nome “SSL” ainda é usado no dia a dia, mas o protocolo em uso é o TLS.'}]},
 {id:11,g:'s',t:'Firewall ICMPv6',sub:'Exp. 3.2 · RFC 4890',
  intro:['No IPv4, muita gente bloqueia todo o ICMP “por segurança”. Você vai fazer isso no IPv6 e ver a rede quebrar. Depois, vai consertar liberando só o necessário.','O firewall é o <code>ip6tables</code>, separado do <code>iptables</code> do IPv4.'],
  steps:[
   {ev:'fw',ok:d=>d.k==='B'&&d.rule&&!d.rule.type&&d.rule.j==='DROP',t:'No <b>Host B</b>, bloqueie todo o ICMPv6.',h:'ip6tables -A INPUT -p icmpv6 -j DROP',n:'B'},
   {ev:'ping',ok:d=>d.k==='A'&&!d.ok&&d.nsfail,t:'No Host A, tente pingar o Host B.',h:'ping -6 2001:db8::b',n:'A'},
   {ev:'fw',ok:d=>d.k==='B'&&d.insert&&d.rule.type==='neighbour-solicitation'&&d.rule.j==='ACCEPT',t:'No Host B, libere a descoberta de vizinhos (NS) <b>no topo</b> da lista.',h:'ip6tables -I INPUT -p icmpv6 --icmpv6-type neighbour-solicitation -j ACCEPT',n:'B'},
   {ev:'ping',ok:d=>d.k==='A'&&!d.ok&&d.echoBlocked,t:'Tente de novo. O MAC é descoberto, mas e o ping?',h:'ping -6 2001:db8::b',n:'A'},
   {ev:'fw',ok:d=>d.k==='B'&&d.insert&&d.rule.type==='echo-request'&&d.rule.j==='ACCEPT',t:'Libere também o ping (echo-request).',h:'ip6tables -I INPUT -p icmpv6 --icmpv6-type echo-request -j ACCEPT',n:'B'},
   {ev:'ping',ok:d=>d.k==='A'&&d.dn==='B'&&d.ok,t:'Agora deve funcionar.',h:'ping -6 2001:db8::b',n:'A'},
   {ev:'fw',ok:d=>d.k==='B'&&d.action==='list',t:'Veja a lista final de regras e a ordem delas.',h:'ip6tables -L',n:'B'}],
  teach:['No IPv6, o ICMPv6 faz muito mais que o ping: faz o papel do ARP (NS/NA), anuncia roteadores (RS/RA) e avisa sobre MTU (Packet Too Big).','Bloquear todo o ICMPv6 é como bloquear o ARP no IPv4: <b>a rede local para</b>.','O firewall lê as regras <b>de cima para baixo</b> e usa a primeira que combina. Por isso as liberações vão no topo (<code>-I</code>).','Nunca bloqueie: NS, NA, RS, RA (dentro da rede local), Packet Too Big, Time Exceeded, Destination Unreachable, Parameter Problem. O ping pode ser liberado com limite de taxa. Redirect pode ser bloqueado.','O livro segue a <b>RFC 4890</b>, o guia oficial do que filtrar. E lembre: <code>iptables</code> e <code>ip6tables</code> são firewalls separados. Configurar só um deixa o outro aberto.'],
  quiz:[{q:'Por que o ping falhou logo após bloquear todo o ICMPv6?',o:['Porque o ping é ICMPv6','Porque a NS também é ICMPv6, então o Host A nem descobriu o MAC do Host B','Porque o roteador caiu'],a:1,e:'O ping nem chegou a sair: a descoberta de vizinho falhou antes.'},
        {q:'Por que as liberações foram inseridas com -I e não -A?',o:['-I é mais rápido','A primeira regra que combina vence; depois do DROP geral, nunca seriam lidas','-A não existe no ip6tables'],a:1,e:'Ordem importa em qualquer firewall.'},
        {q:'Qual destes NUNCA deve ser bloqueado?',o:['Redirect','Packet Too Big','Echo Request vindo da Internet'],a:1,e:'Sem Packet Too Big, o Path MTU Discovery quebra (missão 8).'}]},
 {id:12,g:'s',t:'IPsec: AH x ESP',sub:'Exp. 3.3 · proteger o conteúdo',
  intro:['Na missão 12, o Atacante leu a senha porque ela viajava em texto puro. O <b>IPsec</b> protege os pacotes na camada de rede.','Você vai enviar a mesma senha três vezes, sem proteção, com <b>AH</b> e com <b>ESP</b>, e comparar o que o Atacante consegue ver. No livro, as chaves são configuradas com <code>setkey</code>; aqui o comando <code>ipsec</code> faz isso nas duas pontas de uma vez.'],
  steps:[
   {ev:'naspoof',ok:d=>d.on,t:'Prepare o cenário: o Atacante se coloca no meio da conversa A ↔ B.',h:'na-spoof 2001:db8::b',n:'X'},
   {ev:'nc',ok:d=>d.k==='A'&&d.viaX&&!d.mode,t:'No <b>Host A</b>, envie a senha sem proteção.',h:'echo "senha=banana123" | nc -6 2001:db8::b 9000',n:'A'},
   {ev:'tcpdump',ok:d=>d.last==='none',t:'No Atacante, veja o que ele capturou.',h:'tcpdump',n:'X'},
   {ev:'ipsec',ok:d=>d.mode==='ah',t:'Ative IPsec com <b>AH</b> entre A e B.',h:'ipsec ah 2001:db8::b',n:'A'},
   {ev:'nc',ok:d=>d.mode==='ah',t:'Envie a senha de novo.',h:'echo "senha=banana123" | nc -6 2001:db8::b 9000',n:'A'},
   {ev:'tcpdump',ok:d=>d.last==='ah',t:'O Atacante ainda lê?',h:'tcpdump',n:'X'},
   {ev:'ipsec',ok:d=>d.mode==='esp',t:'Troque para <b>ESP</b>.',h:'ipsec esp 2001:db8::b',n:'A'},
   {ev:'nc',ok:d=>d.mode==='esp',t:'Envie a senha mais uma vez.',h:'echo "senha=banana123" | nc -6 2001:db8::b 9000',n:'A'},
   {ev:'tcpdump',ok:d=>d.last==='esp',t:'E agora, o que o Atacante vê?',h:'tcpdump',n:'X'},
   {ev:'inspect',ok:d=>d.p.proto==='ESP',t:'Na captura, clique no pacote <b>ESP</b> e veja o que sobrou visível.'}],
  teach:['O IPsec adiciona segurança direto no IP, protegendo qualquer aplicação sem que ela precise mudar.','<b>AH</b> (Authentication Header): assina o pacote. Garante que veio de quem diz e que <b>ninguém alterou</b>. Mas o conteúdo continua <b>legível</b>.','<b>ESP</b> (Encapsulating Security Payload): <b>cifra</b> o conteúdo. Quem intercepta vê só origem, destino e bytes embaralhados.','<b>Modo transporte</b> protege a conversa entre dois computadores (o que você fez). <b>Modo túnel</b> protege tudo entre dois roteadores: é uma VPN entre redes (Exp. 3.4).','As chaves ficam em duas tabelas: SPD (o que proteger) e SAD (com quais chaves). Em produção, quem troca as chaves é o protocolo <b>IKE</b>. E note: o IPsec não impediu o ataque, só o tornou inútil.'],
  quiz:[{q:'Com AH, o atacante consegue ler a senha?',o:['Sim: AH garante integridade, mas não esconde o conteúdo','Não, o AH criptografa tudo'],a:0,e:'AH = autenticidade e integridade. ESP = confidencialidade.'},
        {q:'O IPsec com ESP impediu o man-in-the-middle?',o:['Sim, o atacante foi bloqueado','Não: o tráfego ainda passou pelo atacante, mas ele não conseguiu ler nada'],a:1,e:'Criptografia não muda o caminho. Ela torna inútil o que o atacante captura.'},
        {q:'Qual modo do IPsec cria uma VPN entre duas redes?',o:['Modo transporte','Modo túnel'],a:1,e:'O modo túnel é configurado entre roteadores e cifra o pacote original inteiro.'}]}
];
MISSIONS.forEach((m,i)=>{m.id=i+1;});
let curM=0,prog={},quizSt={},done=store.get('ipv6-lab-done-v2',{});
function emit(ev,d={}){
  const m=MISSIONS[curM],i=prog[m.id]||0,s=m.steps[i];
  if(s&&s.ev===ev&&(!s.ok||s.ok(d))){prog[m.id]=i+1;renderMission(true);}
}
function renderBar(){
  const f=MISSIONS.filter(m=>m.g==='f'),s=MISSIONS.filter(m=>m.g==='s');
  const btn=m=>{const i=MISSIONS.indexOf(m);return `<button class="mbtn ${m.g==='s'?'sec':''} ${done[m.id]?'done':''}" data-m="${i}" aria-pressed="${i===curM}"><span class="lk">MISSÃO ${m.id}${done[m.id]?' · ✓':''}</span>${m.t}<small>${m.sub}</small></button>`;};
  $('#mbar').innerHTML=`<span class="mgroup">Fundamentos</span>${f.map(btn).join('')}<span class="mgroup" style="color:var(--bad)">Segurança</span>${s.map(btn).join('')}`;
  const n=Object.keys(done).length;$('#pbar').style.width=(n/MISSIONS.length*100)+'%';$('#ptext').textContent=`${n} de ${MISSIONS.length} missões`;
}
$('#mbar').addEventListener('click',e=>{const b=e.target.closest('[data-m]');if(!b||busy)return;startMission(+b.dataset.m);});
function renderMission(scrollStep){
  renderBar();
  const m=MISSIONS[curM],i=prog[m.id]||0,stepsDone=i>=m.steps.length,qs=quizSt[m.id]||{};
  const allRight=m.quiz.every((q,j)=>qs[j]===q.a);
  if(stepsDone&&allRight&&!done[m.id]){done[m.id]=true;store.set('ipv6-lab-done-v2',done);renderBar();}
  $('#mission').innerHTML=`<p class="eyebrow" style="${m.g==='s'?'color:var(--bad)':''}">Missão ${m.id} de ${MISSIONS.length} · ${m.sub}</p><h3>${m.t}</h3>
   <div class="intro">${m.intro.map(p=>`<p>${p}</p>`).join('')}</div>
   <ol class="steps">${m.steps.map((s,j)=>`<li class="step ${j<i?'done':j===i?'cur':'todo'}"><span class="ck">${j<i?'✓':j+1}</span><div><p>${s.t}</p>${j===i&&s.h?`<button class="hint" data-h="${esc(s.h)}" data-n="${s.n||''}">Dica: usar <code>${esc(s.h)}</code></button>`:''}</div></li>`).join('')}</ol>
   ${stepsDone?`<div class="teach"><span class="eyebrow">Como explicar para outra pessoa</span><ol>${m.teach.map(t=>`<li>${t}</li>`).join('')}</ol></div>
   <div class="qz"><p class="eyebrow">Confira se entendeu</p>${m.quiz.map((q,j)=>{const a=qs[j],ok=a===q.a;return `<div class="qq"><h4>${q.q}</h4><div class="opts">${q.o.map((o,x)=>`<button class="opt ${a===x?(ok?'right':'wrong'):''}" data-q="${j}" data-o="${x}" ${ok?'disabled':''}>${o}</button>`).join('')}</div>${a!==undefined?`<p class="qx"><b style="color:${ok?'var(--ok)':'var(--bad)'}">${ok?'Isso.':'Ainda não. Tente outra opção.'}</b> ${ok?q.e:''}</p>`:''}</div>`;}).join('')}</div>`:''}
   ${done[m.id]?`<div class="win"><strong>Missão concluída</strong><p>Você fez, viu e explicou. ${curM<MISSIONS.length-1?'Siga para a próxima.':'Você completou todo o laboratório: agora consegue explicar IPv6 e seus principais ataques para qualquer pessoa.'}</p>${curM<MISSIONS.length-1?`<button class="btn primary" id="nextM">Próxima missão: ${MISSIONS[curM+1].t} →</button>`:''}</div>`:''}`;
  if(scrollStep){const cur=$('#mission .step.cur')||$('#mission .teach');if(cur&&stepsDone&&i===m.steps.length&&!allRight){}}
}
$('#mission').addEventListener('click',e=>{
  const h=e.target.closest('.hint');if(h){if(h.dataset.n)selectNode(h.dataset.n,false);$('#tin').value=h.dataset.h;$('#tin').focus({preventScroll:true});return;}
  const o=e.target.closest('.opt');if(o&&!o.disabled){const m=MISSIONS[curM];quizSt[m.id]=quizSt[m.id]||{};quizSt[m.id][+o.dataset.q]=+o.dataset.o;renderMission();return;}
  if(e.target.closest('#nextM'))startMission(curM+1);});
function startMission(i){curM=i;try{history.replaceState(null,'','#missao-'+(i+1));}catch(_){}const m=MISSIONS[i];prog[m.id]=0;quizSt[m.id]={};freshNet();if(m.setup)m.setup();
  const first=m.steps.find(s=>s.n);tSel=first?first.n:'A';
  $$('#tabs .tab').forEach(b=>b.setAttribute('aria-selected',b.dataset.n===tSel));renderTerm();renderCap();$('#detail').hidden=true;draw();
  narr(`<b>Missão ${m.id}: ${m.t}.</b> ${m.intro[0]} Siga os passos ao lado. Se travar, use o botão <b>Dica</b>: ele coloca o comando no terminal certo, e você só aperta Enter.`);
  renderMission();}
$('#resetLab').addEventListener('click',()=>{if(!busy)startMission(curM);});
function fromHash(){const m=location.hash.match(/^#missao-(\d+)$/);const i=m?Math.min(Math.max(+m[1]-1,0),MISSIONS.length-1):0;return i;}
startMission(fromHash());
window.addEventListener('hashchange',()=>{const i=fromHash();if(i!==curM&&!busy)startMission(i);});
})();
