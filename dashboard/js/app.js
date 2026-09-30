// Dashboard bootstrap: routing, header, event rail, live feed, packet animation.
import { api } from './api.js';
import { store, subscribe, notify, engine, addEvent, systemStatus } from './store.js';
import { esc, time, $, toast } from './ui.js';
import { createDemo } from './demo.js';
import overview from './views/overview.js';
import handshake from './views/handshake.js';
import channel from './views/channel.js';
import inspector from './views/inspector.js';
import attacks from './views/attacks.js';
import vault from './views/vault.js';
import openssl from './views/openssl.js';
import bench from './views/bench.js';
import logs from './views/logs.js';
import limits from './views/limits.js';

const VIEWS = [overview, handshake, channel, inspector, attacks, vault, openssl, bench, logs, limits];
const byId = Object.fromEntries(VIEWS.map((v) => [v.id, v]));
let current = null;

/* ---- packet animation (visual only; verdict comes from the response) ---- */

const BADGES = {
  ACCEPTED: ['✓ AUTHENTICATED', '✓ DECRYPTED', '✓ ACCEPTED'],
  'AUTHENTICATION FAILED': ['✕ AUTHENTICATION FAILED'],
  'REPLAY DETECTED': ['✕ REPLAY DETECTED'],
  'INVALID PACKET': ['✕ INVALID PACKET'],
};

async function animatePacket(track, resp) {
  if (!track || !resp?.steps) return;
  for (const st of resp.steps) {
    if (!st.packet || !track.isConnected) continue;
    const p = st.packet;
    const chip = document.createElement('div');
    chip.className = `pkt-chip${p.role === 'attacker' ? ' attacker' : ''}`;
    chip.innerHTML = p.raw_hex !== undefined
      ? `<span class="c-seq">${p.length} B</span>`
      : `<span class="c-seq">SEQ ${esc(p.seq === '18446744073709551615' ? '2⁶⁴-1' : p.seq)}</span><span class="c-nonce">NONCE</span><span class="c-ct">CT ${p.ct_len}</span><span class="c-tag">TAG</span>`;
    track.querySelectorAll('.verdict-stack').forEach((s) => s.remove());
    track.appendChild(chip);
    const dist = Math.max(40, track.clientWidth - chip.offsetWidth - 6);
    chip.style.setProperty('--dist', `${dist}px`);
    chip.classList.add('fly');
    await new Promise((r) => setTimeout(r, 1100));
    if (!track.isConnected) return;
    const ok = st.verdict === 'ACCEPTED';
    chip.classList.remove('fly');
    chip.classList.add(ok ? 'accepted' : 'rejected');
    const labels = [...(BADGES[st.verdict] || [`✕ ${st.verdict}`])];
    if (!ok && resp.attack?.id === 'wrongkey') labels.push('✕ WRONG KEY');
    const stack = document.createElement('div');
    stack.className = 'verdict-stack';
    stack.innerHTML = labels.map((l) => `<span class="badge ${ok ? 'b-ok' : 'b-bad'}">${esc(l)}</span>`).join('');
    track.querySelectorAll('.verdict-stack').forEach((s) => s.remove());
    track.appendChild(stack);
    setTimeout(() => chip.remove(), 900);
    setTimeout(() => stack.remove(), 3400);
    await new Promise((r) => setTimeout(r, 450));
  }
}

/* ---- routing ------------------------------------------------------------- */

const ctx = { navigate, animatePacket, views: byId };

function navigate(id) {
  const view = byId[id] || overview;
  current = view;
  document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.dataset.view === view.id));
  const root = $('#view');
  root.innerHTML = '';
  root.scrollTop = 0;
  view.mount(root, ctx);
  if (location.hash !== `#${view.id}`) history.replaceState(null, '', `#${view.id}`);
}

function renderTabs() {
  $('#tabs').innerHTML = VIEWS.map((v) => `<button class="tab" data-view="${v.id}">${v.label.toUpperCase()}</button>`).join('');
  $('#tabs').addEventListener('click', (e) => {
    const b = e.target.closest('.tab');
    if (b) navigate(b.dataset.view);
  });
}

/* ---- header ------------------------------------------------------------- */

function renderHeader() {
  const st = systemStatus();
  const pill = $('#sys-status');
  pill.className = `pill ${st.cls}`;
  pill.innerHTML = `<i></i>${st.text}`;
  $('#sys-detail').textContent = st.detail;

  const order = ['INIT', 'AUTH', 'SECURE', 'TERMINATE'];
  const cur = order.indexOf(store.session.state);
  $('#state-track').innerHTML = order.map((s, i) => {
    const log = store.stateLog[s];
    const cls = i === cur ? `current${s === 'TERMINATE' ? ' term' : ''}` : i < cur ? 'done' : '';
    const arrow = i < 3 ? `<span class="state-arrow${i < cur ? ' lit' : ''}"></span>` : '';
    return `<li><div class="state-node ${cls}"><b>${s}</b><small>${log ? time(log.ts) : '—'}</small></div>${arrow}</li>`;
  }).join('');
}

/* ---- event rail (incremental so only new events animate) ---------------- */

let railShown = 0;
function renderRail() {
  const list = $('#rail-events');
  const evs = store.events;
  if (evs.length < railShown) { list.innerHTML = ''; railShown = 0; }
  const fresh = evs.slice(railShown);
  railShown = evs.length;
  for (const e of fresh) {
    const li = document.createElement('li');
    li.className = 'evt';
    li.innerHTML = `<time>${time(e.ts)}</time><span class="lvl lvl-${esc(e.level)}">${esc(e.level)}</span><span class="msg">${esc(e.msg)}<div class="src">${esc(e.src)}</div></span>`;
    list.prepend(li);
  }
  while (list.children.length > 200) list.lastChild.remove();
  $('#rail-count').textContent = evs.length;
}

/* ---- live feed (TCP mode + engine status) ------------------------------ */

function onStream(msg) {
  if (msg.type === 'hello' || msg.type === 'engine') {
    const up = msg.type === 'hello' ? msg.engine : msg.status === 'ready';
    if (up !== store.engineUp) {
      store.engineUp = up;
      if (msg.type === 'engine') addEvent(up ? 'INFO' : 'ERROR', up ? 'sc_engine ready' : 'sc_engine stopped', 'bridge');
      if (up && msg.type === 'engine') boot();
    }
  } else if (msg.type === 'tcp') {
    store.tcp.events.push(msg);
    if (store.tcp.events.length > 400) store.tcp.events.splice(0, 100);
    addEvent(msg.level || 'INFO', `[tcp ${msg.src}] ${msg.msg}`, `tcp-${msg.src}`, msg.ts);
  } else if (msg.type === 'tcp-status') {
    store.tcp[msg.role] = msg.running;
    if (!msg.running) addEvent('INFO', `TCP ${msg.role} process exited (${msg.code ?? 0})`, 'bridge');
  }
  notify('stream');
}

/* ---- boot --------------------------------------------------------------- */

let booted = false;
async function boot() {
  if (booted) return;
  booted = true;
  const h = await engine('hello');
  if (!h.ok) { booted = false; return; }
  store.stateLog.INIT = { ts: h.events?.[0]?.ts || Date.now(), msg: `libsodium ${h.libsodium} initialised` };
  await engine('vault');
}

async function waitForEngine() {
  for (let i = 0; i < 60; i++) {
    try {
      const h = await api.health();
      store.platform = h.platform;
      store.tcp.server = h.tcp?.server || false;
      store.tcp.client = h.tcp?.client || false;
      if (h.engine) { store.engineUp = true; notify('health'); await boot(); return; }
    } catch { /* bridge not reachable yet */ }
    await new Promise((r) => setTimeout(r, 1000));
  }
  toast('Cannot reach sc_engine. Is the bridge running (npm run dev)?', true);
}

subscribe((topic) => {
  renderHeader();
  renderRail();
  try { current?.update(topic); } catch (e) { console.error(e); }
});

renderTabs();
navigate((location.hash || '#overview').slice(1));
renderHeader();
createDemo(ctx);
api.stream(onStream);
waitForEngine();
window.addEventListener('hashchange', () => {
  const id = location.hash.slice(1);
  if (byId[id] && current?.id !== id) navigate(id);
});
