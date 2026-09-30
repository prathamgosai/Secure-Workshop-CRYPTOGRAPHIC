import { store, engine, run } from '../store.js';
import { esc, time, busy, statusBadge, icons, $ } from '../ui.js';

const STATES = [
  ['INIT', 'Libraries loaded · keys initialised', 'sodium_init() · ephemeral X25519 key pairs'],
  ['AUTH', 'Public keys exchanged · session keys derived', 'crypto_kx → BLAKE2b → rx/tx split'],
  ['SECURE', 'AEAD packets active · replay protection active', 'ChaCha20-Poly1305 · seq as AAD'],
  ['TERMINATE', 'Secrets wiped · session closed', 'sodium_free() zeroes every session key'],
];

export function stateMachine() {
  const cur = store.session.state;
  const idx = STATES.findIndex((s) => s[0] === cur);
  return `<ol class="sm">${STATES.map(([name, desc, tech], i) => {
    const log = store.stateLog[name];
    const cls = i < idx || (i === idx && name === 'TERMINATE') ? 'done' : i === idx ? 'current' : '';
    const status = i === idx ? (name === 'TERMINATE' ? 'CLOSED' : 'ACTIVE') : i < idx ? 'COMPLETE' : 'PENDING';
    return `<li class="${cls}">
      <div class="node">${i + 1}</div>
      <div><h4>${name} <span class="badge ${status === 'ACTIVE' ? 'b-cyan' : status === 'PENDING' ? 'b-muted' : 'b-ok'}">${status}</span></h4>
        <p>${desc}</p>
        <div class="ev">${esc(log?.msg || tech)}</div></div>
      <time>${log ? time(log.ts) : '—'}</time>
    </li>`;
  }).join('')}</ol>`;
}

function properties() {
  const s = store.session;
  const hist = store.attacks.history;
  const blocked = (id) => hist.find((h) => h.id === id && h.pass);
  const reqPass = store.tests && store.tests.failed === 0 && store.tests.total > 0;
  const accepted = store.packets.some((p) => p.verdict === 'ACCEPTED');
  const rows = [
    ['Confidentiality', s.state === 'SECURE' ? 'ACTIVE' : accepted ? 'VERIFIED' : 'NOT TESTED',
      accepted ? 'ChaCha20 ciphertext decrypted only with the matching session key' : 'no packet exchanged yet'],
    ['Integrity / authenticity', blocked('tamper') || blocked('aad') || reqPass ? 'VERIFIED' : 'NOT TESTED',
      blocked('tamper') ? 'live ciphertext bit-flip rejected (rc -2)' : reqPass ? 'required suite: tamper + AAD tests pass' : 'run the Attack Lab or the test suite'],
    ['Freshness (replay / reorder)', (blocked('replay') && blocked('reorder')) || reqPass ? 'VERIFIED' : blocked('replay') ? 'VERIFIED' : 'NOT TESTED',
      blocked('replay') ? 'replayed packet rejected (rc -3)' : reqPass ? 'required suite: replay + reorder pass' : 'not yet exercised'],
    ['Private-key storage', store.vault ? (store.vault.permissions_ok ? 'VERIFIED' : 'FAILED') : 'NOT TESTED',
      store.vault ? `key files checked: ${store.vault.permissions_ok ? '0600 private / 0644 public' : 'unexpected modes'}` : 'open the Key Vault to scan'],
    ['Handshake authentication', s.authenticated ? 'VERIFIED' : 'LIMITATION',
      s.authenticated ? 'Ed25519-signed transcript verified (extension)' : 'plain crypto_kx does not authenticate peers — see Handshake › extension'],
    ['Re-keying', s.state === 'SECURE' && (s.rekey_every || s.epoch > 1) ? 'ENABLED' : 'OFF',
      s.state === 'SECURE' ? `epoch ${s.epoch}${s.rekey_every ? ` · every ${s.rekey_every} msgs` : ''}` : 'optional extension'],
  ];
  return `<div class="props">${rows.map(([n, st, why]) => `<div class="prop"><b>${n}</b>${statusBadge(st)}<small>${esc(why)}</small></div>`).join('')}</div>`;
}

function kpis() {
  const a = store.attacks;
  const t = store.tests;
  const acc = store.packets.filter((p) => p.verdict === 'ACCEPTED').length;
  const rej = store.packets.filter((p) => p.verdict !== 'ACCEPTED').length;
  return `<div class="kpis">
    <div class="kpi"><span>ATTACKS BLOCKED</span><b class="${a.failed ? 'bad' : 'ok'}">${a.blocked}<span class="faint">/${a.executed - (a.history.filter((h) => h.expected === 'ACCEPTED').length)}</span></b><small>${a.executed} executed · ${a.failed} unexpected</small></div>
    <div class="kpi"><span>REQUIRED TESTS</span><b class="${t ? (t.failed ? 'bad' : 'ok') : ''}">${t ? `${t.passed}/${t.total}` : '—'}</b><small>${t ? 'tests/test_attacks.c' : 'not run yet'}</small></div>
    <div class="kpi"><span>PACKETS</span><b>${acc}<span class="faint"> ✓ </span>${rej}<span class="faint"> ✕</span></b><small>accepted · rejected</small></div>
    <div class="kpi"><span>KEY EPOCH</span><b>${store.session.state === 'SECURE' ? String(store.session.epoch).padStart(2, '0') : '—'}</b><small>seq next ${store.session.next_seq || '—'}</small></div>
  </div>`;
}

export default {
  id: 'overview',
  label: 'Overview',
  mount(root, ctx) {
    root.innerHTML = `
      <div class="page-head">
        <div><h1>OVERVIEW</h1>
          <p>Live view of a libsodium secure channel: every status on this dashboard comes from the C implementation (<code>sc_engine</code>, the test suites and the OpenSSL script), not from the browser.</p></div>
        <div class="actions">
          <button class="btn" data-a="keys">GENERATE KEYS</button>
          <button class="btn btn-primary" data-a="hs">RUN HANDSHAKE</button>
          <button class="btn" data-a="send">SEND PACKET</button>
          <button class="btn" data-a="tests">RUN TEST SUITE</button>
        </div>
      </div>
      <div class="grid">
        <section class="card s8 glow">
          <div class="card-head"><div><div class="card-title">LIVE SECURE CHANNEL</div><div class="card-sub">client ⇄ server over ChaCha20-Poly1305 · seq authenticated as AAD</div></div><div id="ov-state"></div></div>
          <div class="lane">
            <div class="endpoint" id="ov-client">${icons.client}<b>CLIENT</b><small id="ov-ctx">tx —</small></div>
            <div class="track" id="ov-track"><span class="track-label" id="ov-label">no session</span></div>
            <div class="endpoint" id="ov-server">${icons.server}<b>SERVER</b><small id="ov-srx">rx —</small></div>
          </div>
        </section>
        <section class="card s4"><div class="card-head"><div class="card-title">METRICS</div></div><div id="ov-kpis"></div></section>
        <section class="card s6"><div class="card-head"><div class="card-title">STATE MACHINE</div><span class="card-sub">timestamps from engine events</span></div><div id="ov-sm"></div></section>
        <section class="card s6"><div class="card-head"><div class="card-title">SECURITY PROPERTIES</div><span class="card-sub">status reflects checks actually run</span></div><div id="ov-props"></div></section>
        <section class="card s12">
          <div class="card-head"><div class="card-title">PACKET FORMAT</div><span class="card-sub">what travels on the wire</span></div>
          <div class="fmt">
            <div class="fx-seq"><b>SEQ · 8 B</b><span>freshness — big-endian, clear text, authenticated as AAD</span></div>
            <div class="fx-nonce"><b>NONCE · 12 B</b><span>unique encryption input — random per packet</span></div>
            <div class="fx-ct"><b>CIPHERTEXT · n B</b><span>confidentiality — ChaCha20</span></div>
            <div class="fx-tag"><b>TAG · 16 B</b><span>integrity + authenticity — Poly1305</span></div>
          </div>
          <p class="note">Minimum packet = 36 bytes. <code>unseal()</code> checks length → replay window → tag, and updates <code>last_seq</code> only after the tag verifies.</p>
        </section>
      </div>`;
    root.addEventListener('click', (e) => {
      const b = e.target.closest('button[data-a]');
      if (!b) return;
      const a = b.dataset.a;
      if (a === 'keys') busy(b, async () => { await run('keygen'); await engine('vault'); });
      if (a === 'hs') busy(b, () => engine('handshake', 'plain'));
      if (a === 'send') busy(b, async () => {
        if (store.session.state !== 'SECURE') { ctx.navigate('handshake'); return; }
        const r = await engine('send', 'Status report: all systems nominal');
        ctx.animatePacket($('#ov-track'), r);
      });
      if (a === 'tests') busy(b, () => run('tests'));
    });
    this.update();
  },
  update() {
    const s = store.session;
    const secure = s.state === 'SECURE';
    const fp = s.key_fingerprints;
    $('#ov-state').innerHTML = `<span class="badge ${secure ? 'b-ok' : s.state === 'TERMINATE' ? 'b-muted' : 'b-info'}">${s.state}${secure ? ` · EPOCH ${String(s.epoch).padStart(2, '0')}` : ''}</span>`;
    $('#ov-client').classList.toggle('live', secure);
    $('#ov-server').classList.toggle('live', secure);
    $('#ov-track').classList.toggle('live', secure);
    $('#ov-label').textContent = secure ? `AEAD channel · next seq ${s.next_seq}${s.authenticated ? ' · signed' : ''}` : s.state === 'TERMINATE' ? 'session terminated · keys wiped' : 'no session — run the handshake';
    $('#ov-ctx').textContent = fp ? `tx ${fp.client_tx}` : 'tx —';
    $('#ov-srx').textContent = fp ? `rx ${fp.server_rx}` : 'rx —';
    $('#ov-kpis').innerHTML = kpis();
    $('#ov-sm').innerHTML = stateMachine();
    $('#ov-props').innerHTML = properties();
  },
};
