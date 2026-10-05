// Dashboard bootstrap: routing, sidebar, header, status bar, event rail and
// live feed. Everything is static: state changes re-render instantly.
import { api } from './api.js';
import { store, subscribe, notify, engine, addEvent, systemStatus } from './store.js';
import { esc, time, $, toast, icons, chip } from './ui.js';
import { createDemo } from './demo.js';
import overview from './views/overview.js';
import examiner from './views/examiner.js';
import handshake from './views/handshake.js';
import channel from './views/channel.js';
import inspector from './views/inspector.js';
import attacks from './views/attacks.js';
import tests from './views/tests.js';
import vault from './views/vault.js';
import wrap from './views/wrap.js';
import openssl from './views/openssl.js';
import bench from './views/bench.js';
import logs from './views/logs.js';
import limits from './views/limits.js';

const GROUPS = [
  ['Lab', [overview, examiner, handshake, channel, inspector]],
  ['Security', [attacks, tests, vault, wrap, openssl]],
  ['Analysis', [bench, logs, limits]],
];
const VIEWS = GROUPS.flatMap(([, vs]) => vs);
const byId = Object.fromEntries(VIEWS.map((v) => [v.id, v]));
const groupOf = Object.fromEntries(GROUPS.flatMap(([g, vs]) => vs.map((v) => [v.id, g])));
let current = null;

/* ---- routing ------------------------------------------------------------- */

const ctx = { navigate, views: byId };

function navigate(id, { focus = false } = {}) {
  const view = byId[id] || overview;
  current = view;
  document.querySelectorAll('.nav-item').forEach((t) => {
    if (t.dataset.view === view.id) t.setAttribute('aria-current', 'page');
    else t.removeAttribute('aria-current');
  });
  $('#head-group').textContent = groupOf[view.id];
  $('#head-title').textContent = view.label;
  document.title = `${view.label} · Secure Channel — Cryptographic Security Command Center`;
  const root = $('#view');
  root.innerHTML = '<div class="view-inner"></div>';
  root.scrollTop = 0;
  view.mount(root.firstElementChild, ctx);
  if (location.hash !== `#${view.id}`) history.replaceState(null, '', `#${view.id}`);
  if (focus) root.focus({ preventScroll: true });
}

function renderNav() {
  $('#nav').innerHTML = GROUPS.map(([g, vs]) => `
    <div class="nav-group" role="group" aria-label="${g}">
      <div class="nav-label">${g.toUpperCase()}</div>
      ${vs.map((v) => `<button class="nav-item" data-view="${v.id}" title="${esc(v.label)}">${icons[v.icon]}<span class="lbl">${esc(v.label)}</span></button>`).join('')}
    </div>`).join('');
  $('#nav').addEventListener('click', (e) => {
    const b = e.target.closest('.nav-item');
    if (b) navigate(b.dataset.view, { focus: true });
  });
}

/* ---- header -------------------------------------------------------------- */

function renderHeader() {
  const st = systemStatus();
  const pill = $('#sys-status');
  pill.outerHTML = chip(st.text, { tone: st.tone }).replace('<span class="chip', '<span id="sys-status" role="status" class="chip');
  $('#sys-detail').textContent = st.detail;

  const order = ['INIT', 'AUTH', 'SECURE', 'TERMINATE'];
  const cur = order.indexOf(store.session.state);
  $('#state-track').innerHTML = order.map((s, i) => {
    const cls = i === cur ? `current${s === 'TERMINATE' ? ' term' : ''}` : i < cur ? 'done' : '';
    return `<li class="${cls}"${i === cur ? ' aria-current="step"' : ''}><span class="n">${s}</span>${i < 3 ? '<i aria-hidden="true">→</i>' : ''}</li>`;
  }).join('');
}

/* ---- system block + status bar (detected values only) ------------------- */

const shortOpenssl = (v) => (v ? v.split(' ').slice(0, 2).join(' ') : null);

function renderSystem() {
  const tc = store.toolchain;
  const row = (name, okVal, label) => {
    const known = okVal !== null && okVal !== undefined && okVal !== false;
    return `<div class="sys-row"><span>${name}</span><b class="${known ? 'ok' : 'faint'}">${known ? '✓' : '○'} ${esc(label ?? (known ? 'READY' : 'UNKNOWN'))}</b></div>`;
  };
  $('#side-sys').innerHTML = `<div class="nav-label">SYSTEM · LOCAL LAB</div>
    ${row('Engine', store.engineUp || null, store.engineUp ? 'READY' : 'OFFLINE')}
    ${row('libsodium', store.libsodium || null, store.libsodium || undefined)}
    ${row('GCC', tc?.gcc, tc?.gcc || undefined)}
    ${row('OpenSSL', tc?.openssl, tc?.openssl ? shortOpenssl(tc.openssl).replace('OpenSSL ', '') : undefined)}`;

  const fi = (k, v) => `<span class="fi"><span class="k">${k}</span><b>${esc(v)}</b></span>`;
  $('#foot').innerHTML = [
    fi('ENV', store.platform || '—'),
    `<span class="fi"><span class="k">ENGINE</span><b class="${store.engineUp ? 'ok' : 'bad'}">${store.engineUp ? '✓ sc_engine ready' : '✕ offline'}</b></span>`,
    fi('LIBSODIUM', store.libsodium || '—'),
    fi('BUILD', tc?.build_ok ? `make OK · ${time(tc.build_ts)}` : '—'),
    fi('GCC', tc?.gcc || '—'),
    fi('OPENSSL', shortOpenssl(tc?.openssl) || '—'),
    fi('BRIDGE', `127.0.0.1:${location.port || '80'}`),
    fi('TCP', store.tcp.server ? `server :7700 running${store.tcp.client ? ' · client connected' : ''}` : 'stopped'),
    '<span class="grow"></span>',
    fi('EVENTS', String(store.events.length)),
  ].join('');
}

/* ---- event rail (incremental) ------------------------------------------- */

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
    li.innerHTML = `<time>${time(e.ts)}</time><span class="msg"><span class="lvl lvl-${esc(e.level)}">${esc(e.level)}</span>${esc(e.msg)}</span>`;
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
      store.toolchain = h.toolchain || null;
      store.tcp.server = h.tcp?.server || false;
      store.tcp.client = h.tcp?.client || false;
      if (h.engine) { store.engineUp = true; notify('health'); await boot(); return; }
      notify('health');
    } catch { /* bridge not reachable yet */ }
    await new Promise((r) => setTimeout(r, 1000));
  }
  toast('Cannot reach sc_engine. Is the bridge running (npm run dev)?', true);
}

let presentationMode = false;
function setMode(isPres) {
  presentationMode = isPres;
  document.body.classList.toggle('mode-presentation', isPres);
  const btnPres = $('#mode-presentation');
  const btnEng = $('#mode-engineering');
  if (btnPres && btnEng) {
    btnPres.setAttribute('aria-pressed', String(isPres));
    btnPres.className = `btn btn-sm ${isPres ? 'btn-primary' : 'btn-ghost'}`;
    btnEng.setAttribute('aria-pressed', String(!isPres));
    btnEng.className = `btn btn-sm ${!isPres ? 'btn-primary' : 'btn-ghost'}`;
  }
}

$('#mode-presentation')?.addEventListener('click', () => setMode(true));
$('#mode-engineering')?.addEventListener('click', () => setMode(false));
$('#mode-examiner')?.addEventListener('click', () => navigate('examiner', { focus: true }));
setMode(false);

subscribe((topic) => {
  renderHeader();
  renderSystem();
  renderRail();
  try { current?.update(topic); } catch (e) { console.error(e); }
});

renderNav();
navigate((location.hash || '#overview').slice(1));
renderHeader();
renderSystem();
createDemo(ctx);
api.stream(onStream);
waitForEngine();
window.addEventListener('hashchange', () => {
  const id = location.hash.slice(1);
  if (byId[id] && current?.id !== id) navigate(id);
});

