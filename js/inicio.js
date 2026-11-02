// Página inicial · IPv6 na Prática
(function () {
'use strict';
const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
const SVGNS = 'http://www.w3.org/2000/svg';

/* ---------- tema (compartilhado com o resto do site) ---------- */
function applyTheme(t) {
  if (t === 'system') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', t);
  $$('.theme button').forEach(b => b.setAttribute('aria-pressed', b.dataset.t === t));
  try { localStorage.setItem('ipv6-tema', t); } catch (_) {}
}
let saved = 'system'; try { saved = localStorage.getItem('ipv6-tema') || 'system'; } catch (_) {}
applyTheme(saved);
$('.theme').addEventListener('click', e => { const b = e.target.closest('[data-t]'); if (b) applyTheme(b.dataset.t); });

/* ---------- topo e brilhos ---------- */
const top = $('#top');
const onScroll = () => top.classList.toggle('scrolled', scrollY > 8);
addEventListener('scroll', onScroll, { passive: true }); onScroll();
const hero = $('#hero'), spot = $('#spot');
if (!reduce) hero.addEventListener('pointermove', e => {
  const r = hero.getBoundingClientRect();
  spot.style.setProperty('--mx', (e.clientX - r.left) + 'px');
  spot.style.setProperty('--my', (e.clientY - r.top) + 'px');
});

/* ---------- contadores ---------- */
if (!reduce) $$('[data-count]').forEach(el => {
  const to = +el.dataset.count; if (!to) return;
  const t0 = performance.now(), d = 1100;
  (function f(now) { const t = Math.min(1, (now - t0) / d); el.textContent = Math.round(to * (1 - Math.pow(1 - t, 3))); if (t < 1) requestAnimationFrame(f); })(t0);
});

/* ---------- bancada animada do hero ---------- */
const P = { A: { x: 74, y: 62 }, X: { x: 74, y: 172 }, SW: { x: 206, y: 117 }, R: { x: 334, y: 117 }, S: { x: 482, y: 117 } };
const NODES = { A: ['Host A', '2001:db8::a'], X: ['Atacante', 'fe80::dcad…'], R: ['Roteador', 'fe80::1'], S: ['Servidor', 'cafe::80'] };
const topo = $('#topo');
const state = { attack: false, guard: false, hl: null };
function drawTopo() {
  let h = `<rect class="zone" x="10" y="12" width="388" height="208" rx="12"/><text class="zl" x="22" y="212">REDE LOCAL</text>
    <rect class="zone" x="414" y="62" width="136" height="112" rx="12"/><text class="zl" x="426" y="166">INTERNET</text>`;
  [['A', 'SW'], ['X', 'SW'], ['SW', 'R'], ['R', 'S']].forEach(([a, b]) => { h += `<line class="lk" x1="${P[a].x}" y1="${P[a].y}" x2="${P[b].x}" y2="${P[b].y}"/>`; });
  h += `<g class="nd ${state.guard ? 'guard' : ''}"><rect x="${P.SW.x - 36}" y="${P.SW.y - 16}" width="72" height="32" rx="8"/><text x="${P.SW.x}" y="${P.SW.y + 4}" text-anchor="middle">switch</text></g>`;
  for (const k of ['A', 'X', 'R', 'S']) {
    const [n, ip] = NODES[k], p = P[k];
    h += `<g class="nd ${k === 'X' ? 'x' : ''} ${k === 'X' && state.attack && !state.guard ? 'on' : ''} ${state.hl === k ? 'hl' : ''}"><rect x="${p.x - 56}" y="${p.y - 23}" width="112" height="46" rx="10"/>
      <text x="${p.x}" y="${p.y - 3}" text-anchor="middle">${n}</text><text class="ip" x="${p.x}" y="${p.y + 13}" text-anchor="middle">${ip}</text></g>`;
  }
  h += '<g id="pks"></g>';
  topo.innerHTML = h;
}
const COL = { ok: '#9DB2FF', bad: '#FF8C82', warn: '#F4B26F', good: '#5CD39B' };
const CANCEL = Symbol('cancel');
let runId = 0;
const sleep = (ms, id) => new Promise((res, rej) => setTimeout(() => (id === runId ? res() : rej(CANCEL)), ms));
function fly(paths, color, label, id) {
  return new Promise((res, rej) => {
    const g = $('#pks'); if (!g) return res();
    const items = paths.map(nodes => {
      const pts = nodes.map(k => P[k]); const seg = []; let L = 0;
      for (let i = 0; i < pts.length - 1; i++) { const d = Math.hypot(pts[i + 1].x - pts[i].x, pts[i + 1].y - pts[i].y); seg.push(d); L += d; }
      const e = document.createElementNS(SVGNS, 'g'); e.setAttribute('class', 'pk');
      e.innerHTML = `<circle r="9" fill="${color}"/><text y="-14" text-anchor="middle" fill="${color}">${label}</text>`; g.appendChild(e);
      return { e, pts, seg, L };
    });
    const maxL = Math.max(...items.map(i => i.L)), dur = Math.max(650, maxL * 2.6), t0 = performance.now();
    (function f(now) {
      if (id !== runId) { items.forEach(i => i.e.remove()); return rej(CANCEL); }
      const t = Math.min(1, (now - t0) / dur), z = t < .5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;
      items.forEach(it => { let d = z * it.L, i = 0; while (i < it.seg.length - 1 && d > it.seg[i]) { d -= it.seg[i]; i++; }
        const r = it.seg[i] ? Math.min(1, d / it.seg[i]) : 1, a = it.pts[i], b = it.pts[i + 1] || a;
        it.e.setAttribute('transform', `translate(${a.x + (b.x - a.x) * r},${a.y + (b.y - a.y) * r})`); });
      if (t < 1) requestAnimationFrame(f); else { items.forEach(i => i.e.remove()); res(); }
    })(t0);
  });
}
const term = $('#term');
let lines = [];
function renderTerm(caret) {
  term.innerHTML = lines.slice(-9).map((l, i, arr) => `<div class="ln">${l.html}${caret && i === arr.length - 1 ? '<span class="caret"></span>' : ''}</div>`).join('');
}
const prompt = k => `<span class="p">root@${k}:~#</span> `;
async function type(k, cmd, id) {
  const ln = { html: prompt(k) }; lines.push(ln);
  for (const ch of cmd) { ln.html += ch.replace('<', '&lt;'); renderTerm(true); await sleep(38 + Math.random() * 40, id); }
  await sleep(260, id);
}
function outLine(cls, txt) { lines.push({ html: `<span class="${cls}">${txt}</span>` }); }

const SCENES = [
  { k: 'A', cmd: 'ping -6 www.exemplo.com.br',
    cap: 'O Host A acessa um site. O pacote sai da rede local, passa pelo roteador e chega ao servidor na Internet.',
    run: async id => { await fly([['A', 'SW', 'R', 'S']], COL.ok, 'ping', id); await fly([['S', 'R', 'SW', 'A']], COL.ok, 'pong', id); outLine('o', '64 bytes from 2001:db8:cafe::80: ttl=63'); } },
  { k: 'X', cmd: 'fake-ra start',
    cap: 'Um atacante na mesma rede anuncia: “eu sou o roteador”. O IPv6 não confere quem pode anunciar, e o Host A acredita.',
    run: async id => { state.attack = true; drawTopo(); await fly([['X', 'SW', 'A'], ['X', 'SW', 'R']], COL.bad, 'RA!', id); outLine('e', '[fake-ra] "eu sou o roteador" (pref high)'); } },
  { k: 'A', cmd: 'ping -6 www.exemplo.com.br',
    cap: 'Agora o tráfego passa pelo atacante antes de sair. Tudo continua funcionando, então ninguém percebe. A pista: ttl=62, um salto a mais.',
    run: async id => { await fly([['A', 'SW', 'X', 'SW', 'R', 'S']], COL.warn, 'ping', id); await fly([['S', 'R', 'SW', 'A']], COL.warn, 'pong', id); outLine('w', '64 bytes from 2001:db8:cafe::80: ttl=62  ← passou pelo atacante'); } },
  { k: 'R', cmd: 'ra-guard on',
    cap: 'A defesa: o RA Guard faz o switch aceitar anúncios só da porta do roteador de verdade. A RA falsa morre no switch.',
    run: async id => { state.guard = true; drawTopo(); outLine('o', '[switch] RA Guard ativado'); renderTerm(false); await fly([['X', 'SW']], COL.bad, 'RA✕', id); } },
  { k: 'A', cmd: 'ping -6 www.exemplo.com.br',
    cap: 'O caminho volta ao normal. Você acabou de ver a missão 11 inteira. No laboratório, quem digita é você.',
    run: async id => { await fly([['A', 'SW', 'R', 'S']], COL.good, 'ping', id); await fly([['S', 'R', 'SW', 'A']], COL.good, 'pong', id); outLine('o', '64 bytes from 2001:db8:cafe::80: ttl=63  ✓ caminho normal'); } }
];
const dots = $('#dots'), capText = $('#capText'), capStep = $('#capStep');
dots.innerHTML = SCENES.map((_, i) => `<button aria-label="Etapa ${i + 1}" aria-current="${i === 0}"></button>`).join('');
function setCaption(i) {
  capStep.textContent = `0${i + 1}/0${SCENES.length}`;
  $$('#dots button').forEach((b, j) => b.setAttribute('aria-current', j === i));
  if (reduce) { capText.textContent = SCENES[i].cap; return; }
  capText.classList.add('fade');
  setTimeout(() => { capText.textContent = SCENES[i].cap; capText.classList.remove('fade'); }, 200);
}
// estado da rede ANTES da etapa i
function stateAt(i) { state.attack = i >= 2; state.guard = i >= 4; state.hl = null; }
function staticScene(i) { // sem animação: mostra a etapa já concluída
  stateAt(i + 1); state.hl = SCENES[i].k; drawTopo(); lines = [];
  for (let j = 0; j <= i; j++) {
    lines.push({ html: prompt(SCENES[j].k) + SCENES[j].cmd });
    lines.push({ html: ['<span class="o">64 bytes from 2001:db8:cafe::80: ttl=63</span>', '<span class="e">[fake-ra] "eu sou o roteador" (pref high)</span>', '<span class="w">64 bytes from 2001:db8:cafe::80: ttl=62  ← passou pelo atacante</span>', '<span class="o">[switch] RA Guard ativado</span>', '<span class="o">64 bytes from 2001:db8:cafe::80: ttl=63  ✓ caminho normal</span>'][j] });
  }
  lines.push({ html: prompt(SCENES[i].k) }); renderTerm(true); setCaption(i);
}
let visible = true, paused = false;
async function play(from) {
  const id = ++runId;
  try {
    let i = from;
    stateAt(i); drawTopo();
    if (i === 0) lines = [{ html: '<span class="d"># laboratório IPv6 · missão 11 · RA falsa</span>' }];
    while (true) {
      while ((!visible || document.hidden) && id === runId) await new Promise(r => setTimeout(r, 400));
      const sc = SCENES[i]; setCaption(i);
      state.hl = sc.k; drawTopo();
      await type(sc.k, sc.cmd, id);
      renderTerm(false);
      await sc.run(id);
      lines.push({ html: prompt(sc.k) }); renderTerm(true);
      await sleep(i === SCENES.length - 1 ? 3600 : 1700, id);
      i++;
      if (i >= SCENES.length) { i = 0; stateAt(0); lines = [{ html: '<span class="d"># reiniciando a demonstração…</span>' }]; renderTerm(false); await sleep(700, id); }
    }
  } catch (e) { if (e !== CANCEL) throw e; }
}
dots.addEventListener('click', e => {
  const b = e.target.closest('button'); if (!b) return;
  const i = [...dots.children].indexOf(b);
  if (reduce) { staticScene(i); return; }
  runId++; staticScene(Math.max(0, i - 1)); if (i === 0) lines = [];
  play(i);
});
if ('IntersectionObserver' in window) new IntersectionObserver(es => { visible = es[0].isIntersecting; }).observe($('.bench'));
// estado inicial completo (visível mesmo antes de qualquer animação)
staticScene(0);
if (!reduce) { lines = []; play(0); }

/* ---------- missões ---------- */
const MIS = [
  ['f', 'Endereços e prefixos', 'O que significam /24 e /64, bit a bit.'],
  ['f', 'Descobrir um vizinho', 'NS e NA: o ARP do IPv6.'],
  ['f', 'Entrar na rede', 'RS, RA e SLAAC: configuração sem DHCP.'],
  ['f', 'Endereço duplicado', 'Como o DAD evita dois aparelhos no mesmo IP.'],
  ['f', 'Saindo para a Internet', 'Gateway, hop limit e traceroute.'],
  ['f', 'Nomes e DNS', 'Host, nome e IP: registros A e AAAA.'],
  ['f', 'Portas, TCP e UDP', 'Aperto de mão, porta aberta e RST.'],
  ['f', 'Pacotes grandes', 'Path MTU e o buraco negro do firewall.'],
  ['f', 'A internet caiu?', 'Diagnóstico camada por camada.'],
  ['s', 'Ataque DoS ao DAD', 'Ninguém mais consegue endereço. Detecte com NDPMon.'],
  ['s', 'RA falsa', 'O atacante vira o gateway. Defenda com RA Guard.'],
  ['s', 'Cache envenenado', 'NA spoofing e man-in-the-middle.'],
  ['s', 'Texto claro x cifrado', 'Telnet x SSH, HTTP x HTTPS.'],
  ['s', 'Firewall ICMPv6', 'Bloqueie tudo, veja quebrar, conserte.'],
  ['s', 'IPsec: AH x ESP', 'O que cada um protege de verdade.']
];
let mg = 'all';
function renderMissions() {
  $('#mgrid').innerHTML = MIS.map(([g, t, d], i) => (mg === 'all' || mg === g) ? `<a class="mcard ${g === 's' ? 'sec' : ''}" href="laboratorio.html#missao-${i + 1}">
    <span class="num">MISSÃO ${String(i + 1).padStart(2, '0')}<em>${g === 's' ? 'SEGURANÇA' : 'FUNDAMENTOS'}</em></span>
    <h3>${t}</h3><p>${d}</p><span class="go">Abrir missão →</span></a>` : '').join('');
  $$('#mtabs button').forEach(b => b.setAttribute('aria-pressed', b.dataset.g === mg));
}
$('#mtabs').addEventListener('click', e => { const b = e.target.closest('[data-g]'); if (b) { mg = b.dataset.g; renderMissions(); } });
$('#mgrid').addEventListener('pointermove', e => {
  const c = e.target.closest('.mcard'); if (!c) return;
  const r = c.getBoundingClientRect(); c.style.setProperty('--cx', (e.clientX - r.left) + 'px'); c.style.setProperty('--cy', (e.clientY - r.top) + 'px');
});
renderMissions();

/* ---------- demo Telnet x SSH ---------- */
const DEMO = {
  telnet: {
    rows: [['', 'TCP', '49512 → 23 [SYN]', '#7C879D'], ['r', 'TCP', '23 → 49512 [SYN, ACK]', '#7C879D'], ['', 'TELNET', 'dados: "admin"', '#C59BF2'], ['leak', 'TELNET', '"admin123" ← senha', '#FF8C82']],
    detail: '<span class="lbl">▸ Telnet (texto claro)</span><br>Dados: <mark>"admin123\\r\\n"</mark><br>Na tela, o campo Password ficou em branco. No pacote, a senha está escrita por extenso.',
    verdict: ['bad', '!', 'A senha vaza.', 'Qualquer um no caminho lê login e senha. O mesmo vale para FTP, HTTP e POP3 sem TLS.']
  },
  ssh: {
    rows: [['', 'TCP', '49601 → 22 [SYN]', '#7C879D'], ['r', 'TCP', '22 → 49601 [SYN, ACK]', '#7C879D'], ['', 'SSH', 'SSH-2.0 troca de chaves', '#5CD39B'], ['lock', 'SSH', 'pacote cifrado 🔒', '#5CD39B']],
    detail: '<span class="lbl">▸ SSH (cifrado)</span><br>Dados: <span class="enc">c4 19 ab 70 9e 21 5f d0 33 a8 …</span><br>A mesma senha foi enviada, mas cifrada. O atacante vê só bytes embaralhados.',
    verdict: ['good', '✓', 'Só bytes embaralhados.', 'O atacante ainda vê quem fala com quem, mas não o conteúdo. A senha está segura.']
  }
};
function renderDemo(p, animate) {
  const d = DEMO[p];
  $$('.seg button').forEach(b => b.setAttribute('aria-pressed', b.dataset.p === p));
  const [cls, ic, t, s] = d.verdict;
  $('#verdict').className = 'verdict ' + cls;
  $('#verdict').innerHTML = `<span class="ic">${ic}</span><div><b>${t}</b><p style="color:var(--muted);font-size:.95rem;margin-top:2px">${s}</p></div>`;
  const tb = $('#capRows'); tb.innerHTML = '';
  d.rows.forEach(([c, proto, info, col], i) => {
    const tr = document.createElement('tr'); tr.className = c === 'r' ? '' : c;
    const [src, dst] = c === 'r' ? ['cafe::80', '2001:db8::a'] : ['2001:db8::a', 'cafe::80'];
    tr.innerHTML = `<td>${i + 1}</td><td>${src}</td><td>${dst}</td><td><i class="kd" style="background:${col}"></i>${proto}</td><td>${info}</td>`;
    if (animate && !reduce) { tr.style.visibility = 'hidden'; setTimeout(() => { tr.style.visibility = ''; tr.classList.add('in'); }, 140 * i); }
    tb.appendChild(tr);
  });
  const det = $('#capDetail');
  if (animate && !reduce) { det.style.opacity = .2; setTimeout(() => { det.innerHTML = d.detail; det.style.opacity = 1; }, 140 * d.rows.length); }
  else det.innerHTML = d.detail;
}
$('.seg').addEventListener('click', e => { const b = e.target.closest('[data-p]'); if (b) renderDemo(b.dataset.p, true); });
renderDemo('telnet', false);
})();
