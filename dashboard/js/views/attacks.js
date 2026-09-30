import { store, engine, run } from '../store.js';
import { esc, time, busy, byteMap, verdictBadge, emptyState, icons, $ } from '../ui.js';

export const ATTACKS = [
  { id: 'normal', btn: 'SEND NORMAL PACKET', desc: 'Genuine packet from the client', expect: 'ACCEPTED' },
  { id: 'tamper', btn: 'FLIP CIPHERTEXT BIT', desc: 'One bit of ciphertext flipped in transit', expect: 'BLOCKED' },
  { id: 'aad', btn: 'MODIFY SEQUENCE / AAD', desc: 'Clear-text seq rewritten (+1000)', expect: 'BLOCKED' },
  { id: 'replay', btn: 'REPLAY PACKET', desc: 'Already-accepted packet sent again', expect: 'BLOCKED' },
  { id: 'reorder', btn: 'REORDER PACKETS', desc: 'Newer packet first, older one late', expect: 'BLOCKED' },
  { id: 'wrongkey', btn: 'USE WRONG KEY', desc: 'Packet forged with an attacker key', expect: 'BLOCKED' },
  { id: 'short', btn: 'SEND SHORT PACKET', desc: 'Truncated to 10 bytes', expect: 'BLOCKED' },
  { id: 'forged', btn: 'FORGE LARGE SEQUENCE', desc: 'seq = 2^64-1 to poison the window', expect: 'BLOCKED' },
];

const WHY = {
  normal: 'Length OK, seq is fresh, Poly1305 tag verifies — the packet is authentic and new.',
  tamper: 'Poly1305 authenticates every ciphertext bit. The recomputed tag no longer matches, so nothing is decrypted or returned.',
  aad: 'The seq bytes are AAD: covered by the tag even though they are sent in clear. Renumbering a packet breaks authentication.',
  replay: 'The receiver only accepts seq strictly greater than the last accepted seq. A copy has an old seq.',
  reorder: 'After seq n is accepted, any seq ≤ n is refused. The late, older packet is treated like a replay.',
  wrongkey: 'The tag depends on the session key. A packet made with any other key cannot produce a valid tag.',
  short: 'A packet must hold at least 8 + 12 + 16 = 36 bytes. Anything shorter is rejected before any cryptography runs.',
  forged: 'The forged seq fails the tag check, and last_seq is only updated AFTER verification — so the window is not poisoned and later genuine traffic still flows.',
};

function counters() {
  const a = store.attacks;
  return `<div class="counters">
    <div class="counter"><span>TESTS EXECUTED</span><b id="c-exec">${a.executed}</b></div>
    <div class="counter"><span>PASSED</span><b class="${a.passed ? 'ok' : ''}">${a.passed}</b></div>
    <div class="counter"><span>BLOCKED</span><b class="${a.blocked ? 'ok' : ''}">${a.blocked}</b></div>
    <div class="counter"><span>FAILED</span><b class="${a.failed ? 'bad' : ''}">${a.failed}</b></div>
  </div>`;
}

let inflight = null;

function buttons() {
  const secure = store.session.state === 'SECURE';
  return ATTACKS.map((a) => {
    const last = store.attacks.history.find((h) => h.id === a.id);
    const st = last ? (last.pass ? `<span class="st ok">✓ ${last.result}</span>` : '<span class="st bad">✕ UNEXPECTED</span>') : '<span class="st faint">—</span>';
    return `<button class="atk ${a.id === 'normal' ? 'normal' : ''}${inflight === a.id ? ' busy' : ''}" data-atk="${a.id}" ${secure && !inflight ? '' : 'disabled'}>
      <b>[ ${a.btn} ]</b>${st}<small>${a.desc} · expected ${a.expect}</small></button>`;
  }).join('');
}

function stage() {
  const r = store.attacks.last;
  if (store.session.state !== 'SECURE' && !r) {
    return emptyState('Attacks run against a live session.<br>Establish one first.', '<button class="btn btn-primary" data-a="hs">ESTABLISH SESSION</button>');
  }
  if (!r) return emptyState('Choose an attack. The packet is built and verified by the real C code.');
  const a = r.attack;
  const target = (r.steps || []).find((s) => s.packet && s.packet.role === 'attacker') || (r.steps || []).find((s) => s.packet);
  const cls = !a.pass ? 'failed' : a.result === 'BLOCKED' ? 'blocked' : 'accepted';
  return `
    <div class="stage-flow">
      <div class="sf"><span>ATTACK</span><div><b>${esc(a.title)}</b></div></div>
      <div class="sf"><span>NETWORK</span><div>${esc(a.network)}</div></div>
      <div class="sf"><span>VERIFIER</span><div class="mono">${esc(a.verifier)}</div></div>
      <div class="sf result ${cls}"><span>RESULT</span><div>
        <div class="big-verdict ${a.result === 'BLOCKED' ? 'ok' : a.pass ? 'info' : 'bad'}">${a.result === 'BLOCKED' ? '✕ ' : '✓ '}${esc(a.verdict)}</div>
        <div class="small muted">return code ${a.rc} · expected ${esc(a.expected)} (rc ${a.expected_rc}) · ${a.pass ? '<span class="ok">behaved as expected</span>' : '<span class="bad">UNEXPECTED RESULT</span>'}</div>
      </div></div>
      <div class="sf"><span>WHY</span><div>${esc(WHY[a.id])}</div></div>
    </div>
    ${target ? `<div class="hr"></div><div class="card-title" style="margin-bottom:8px">${target.packet.role === 'attacker' ? 'ATTACKER PACKET' : 'PACKET'} · ${target.packet.length} B</div>${byteMap(target.packet)}` : ''}
    <div class="steps-mini">${(r.steps || []).map((s) => `<div class="step-mini"><span>${esc(s.label)}${s.packet ? ` <span class="faint mono">seq ${esc(s.packet.seq ?? '—')}</span>` : ''}</span>${verdictBadge(s.verdict, s.rc)}</div>`).join('')}</div>`;
}

function history() {
  const h = store.attacks.history.slice(0, 12);
  if (!h.length) return '<div class="small muted">No attacks launched yet.</div>';
  return `<table class="table"><thead><tr><th>TIME</th><th>ATTACK</th><th>RC</th><th>RESULT</th><th>CHECK</th></tr></thead><tbody>
    ${h.map((x) => `<tr><td class="mono">${time(x.ts)}</td><td>${esc(x.title)}</td><td class="mono">${x.rc}</td><td>${verdictBadge(x.verdict)}</td><td>${x.pass ? '<span class="badge b-ok">PASS</span>' : '<span class="badge b-bad">FAIL</span>'}</td></tr>`).join('')}
  </tbody></table>`;
}

function suite(result, title) {
  if (!result) return `<div class="small muted">${title} not run yet.</div>`;
  if (!result.tests) return `<div class="bad">${esc(result.error || 'suite failed to run')}</div>`;
  return `<div class="actions" style="margin-bottom:10px">
      <span class="badge ${result.failed ? 'b-bad' : 'b-ok'}">${result.passed} passed, ${result.failed} failed</span>
      <span class="faint small">${esc(result.suite)} · exit code ${result.code} · ${result.ms} ms</span></div>
    <div class="suite">${result.tests.map((t, i) => `<div style="animation-delay:${i * 40}ms"><span class="${t.ok ? 'ok' : 'bad'}">${t.ok ? '✓' : '✕'}</span><span>${esc(t.name)}</span></div>`).join('')}</div>`;
}

export default {
  id: 'attacks',
  label: 'Attack Lab',
  mount(root, ctx) {
    this.ctx = ctx;
    this.stageKey = null;
    root.innerHTML = `
      <div class="page-head">
        <div><h1>ATTACK SIMULATION LAB</h1><p>Each button asks <code>sc_engine</code> to build the attack packet(s) and push them through the live server's <code>unseal()</code>. Result, return code and reason come straight back from C.</p></div>
        <div id="atk-counters"></div>
      </div>
      <div class="grid">
        <section class="card s4"><div class="card-head"><div class="card-title">ATTACK CONTROLS</div><button class="btn btn-sm" data-a="all">RUN ALL 8</button></div><div class="atk-list" id="atk-btns"></div></section>
        <section class="card s8 glow" id="atk-stage-card"><div class="card-head"><div class="card-title">VERIFICATION STAGE</div><span id="atk-when" class="card-sub"></span></div>
          <div class="lane lane-mini">
            <div class="endpoint">${icons.attacker}<b>NETWORK</b><small>attacker in path</small></div>
            <div class="track" id="atk-track"><span class="track-label">packets under attack</span></div>
            <div class="endpoint">${icons.server}<b>SERVER</b><small>unseal()</small></div>
          </div>
          <div id="atk-stage"></div></section>
        <section class="card s12"><div class="card-head"><div class="card-title">ATTACK HISTORY</div></div><div id="atk-history"></div></section>
        <section class="card s6"><div class="card-head"><div><div class="card-title">REQUIRED SUITE — tests/test_attacks.c</div><div class="card-sub">the 8 tests from the brief, run as a separate process</div></div><button class="btn btn-primary btn-sm" data-a="suite">RUN</button></div><div id="atk-suite"></div></section>
        <section class="card s6"><div class="card-head"><div><div class="card-title">EXTENDED SUITE — tests/test_extended.c</div><div class="card-sub">packets, key files, wrapping, state machine, re-key, handshake</div></div><button class="btn btn-sm" data-a="ext">RUN</button></div><div id="atk-ext"></div></section>
      </div>`;
    root.addEventListener('click', (e) => {
      const atk = e.target.closest('button[data-atk]');
      if (atk) { if (!inflight) this.launch(atk.dataset.atk); return; }
      const b = e.target.closest('button[data-a]');
      if (!b) return;
      if (b.dataset.a === 'hs') busy(b, () => engine('handshake', 'plain'));
      if (b.dataset.a === 'all') busy(b, () => this.runAll());
      if (b.dataset.a === 'suite') busy(b, () => run('tests'));
      if (b.dataset.a === 'ext') busy(b, () => run('tests-extended'));
    });
    this.update();
  },
  async launch(id) {
    inflight = id;
    this.update();
    let r;
    try {
      if (store.session.state !== 'SECURE') await engine('handshake', 'plain');
      r = await engine('attack', id);
      this.ctx.animatePacket($('#atk-track'), r);
    } finally {
      inflight = null;
      this.update();
    }
    const card = $('#atk-stage-card');
    if (card) { card.classList.remove('spotlight'); void card.offsetWidth; card.classList.add('spotlight'); }
    return r;
  },
  async runAll() {
    for (const a of ATTACKS) {
      await this.launch(a.id);
      await new Promise((r) => setTimeout(r, 650));
    }
  },
  update() {
    $('#atk-counters').innerHTML = counters();
    $('#atk-btns').innerHTML = buttons();
    const key = `${store.attacks.executed}:${store.session.state}`;
    if (key !== this.stageKey) {
      this.stageKey = key;
      $('#atk-stage').innerHTML = stage();
    }
    const last = store.attacks.history[0];
    $('#atk-when').textContent = last ? `last run ${time(last.ts)}` : '';
    $('#atk-history').innerHTML = history();
    $('#atk-suite').innerHTML = suite(store.tests, 'Required suite');
    $('#atk-ext').innerHTML = suite(store.testsExtended, 'Extended suite');
  },
};
