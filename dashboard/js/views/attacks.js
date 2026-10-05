import { store, engine, run } from '../store.js';
import { esc, time, busy, byteMap, verdictBadge, chip, emptyState, packetFlow, pageHead, panelHead, seqLabel, $, staticAttackComparison, whyThisMatters } from '../ui.js';
import { securityDecisionTrace } from '../trace.js';

export const ATTACKS = [
  { id: 'normal', name: 'Normal round trip', desc: 'Genuine packet from the client', expect: 'ACCEPTED', rc: 0, prop: ['Baseline'],
    method: 'Seal a message with client_tx and deliver it unmodified.', expected: 'Packet accepted and decrypted.' },
  { id: 'tamper', name: 'Ciphertext tampering', desc: 'One bit flipped in transit', expect: 'BLOCKED', rc: -2, prop: ['Integrity'],
    method: 'Flip one bit of the first ciphertext byte while the packet is on the wire.', expected: 'Packet rejected; nothing decrypted.' },
  { id: 'aad', name: 'Sequence / AAD tampering', desc: 'Clear-text seq rewritten (+1000)', expect: 'BLOCKED', rc: -2, prop: ['Integrity'],
    method: 'Rewrite the clear-text sequence number in the header.', expected: 'Packet rejected: the seq is authenticated as AAD.' },
  { id: 'replay', name: 'Replay', desc: 'Accepted packet sent again', expect: 'BLOCKED', rc: -3, prop: ['Freshness'],
    method: 'Capture a valid, already-accepted packet and submit it again.', expected: 'Packet rejected by the replay window.' },
  { id: 'reorder', name: 'Reordering', desc: 'Newer first, older one late', expect: 'BLOCKED', rc: -3, prop: ['Freshness'],
    method: 'Deliver a newer packet first, then the older one.', expected: 'Late, older packet rejected like a replay.' },
  { id: 'wrongkey', name: 'Wrong key', desc: 'Forged with an attacker key', expect: 'BLOCKED', rc: -2, prop: ['Authenticity'],
    method: 'Seal a packet with a key the attacker generated.', expected: 'Packet rejected: the tag cannot verify.' },
  { id: 'short', name: 'Short packet', desc: 'Truncated to 10 bytes', expect: 'BLOCKED', rc: -1, prop: ['Input validation'],
    method: 'Truncate a packet to 10 bytes.', expected: 'Rejected before any cryptography runs.' },
  { id: 'forged', name: 'Forged sequence', desc: 'seq = 2⁶⁴−1 to poison the window', expect: 'BLOCKED', rc: -2, prop: ['Freshness', 'Integrity'],
    method: 'Rewrite seq to 2⁶⁴−1 hoping to block all future packets.', expected: 'Rejected; last_seq unchanged; genuine traffic still flows.' },
];

const WHY = {
  normal: 'Length is valid, the seq is fresh and the Poly1305 tag verifies — the packet is authentic and new.',
  tamper: 'Poly1305 authenticates every ciphertext bit. The recomputed tag no longer matches, so nothing is decrypted or returned.',
  aad: 'The seq bytes are AAD: covered by the tag even though they are sent in clear. Renumbering a packet breaks authentication.',
  replay: 'The sequence number is not greater than the last authenticated sequence, so the receiver refuses it.',
  reorder: 'After seq n is accepted, any seq ≤ n is refused. The late, older packet is treated exactly like a replay.',
  wrongkey: 'The tag depends on the session key. A packet made with any other key cannot produce a valid tag.',
  short: 'A packet must hold at least 8 + 12 + 16 = 36 bytes. Anything shorter is rejected before any cryptography runs.',
  forged: 'The forged seq fails the tag check, and last_seq is only updated after verification — so the window is not poisoned.',
};

const PROP_MAP = {
  normal: 'aead',
  tamper: 'aead',
  aad: 'aad',
  replay: 'replay',
  reorder: 'replay',
  wrongkey: 'directional',
  short: 'aead',
  forged: 'replay',
};

let inflight = null;
let selected = 'tamper';

const lastOf = (id) => store.attacks.history.find((h) => h.id === id);

function summary() {
  const a = store.attacks;
  const t = store.tests;
  return `<div class="summary-strip">
    <div class="metric"><span>Executed</span><b>${a.executed}</b></div>
    <div class="metric"><span>Blocked</span><b class="${a.blocked ? 'ok' : ''}">${a.blocked}</b></div>
    <div class="metric"><span>As expected</span><b class="${a.passed ? 'ok' : ''}">${a.passed}</b></div>
    <div class="metric"><span>Unexpected</span><b class="${a.failed ? 'bad' : ''}">${a.failed}</b></div>
    <div class="metric"><span>Required suite</span><b class="${t ? (t.failed ? 'bad' : 'ok') : 'faint'}">${t && t.total ? `${t.passed}/${t.total}` : '—'}<small> ${t && t.total ? (t.failed ? 'FAIL' : 'PASS') : 'not run'}</small></b></div>
  </div>`;
}

function cards() {
  return ATTACKS.map((a, i) => {
    const last = lastOf(a.id);
    const st = last ? (last.pass ? chip(last.result === 'BLOCKED' ? 'BLOCKED' : 'PASS', { text: last.result }) : chip('UNEXPECTED')) : chip('NOT RUN');
    return `<button class="atk" data-atk="${a.id}" aria-pressed="${selected === a.id}"${inflight ? ' disabled' : ''}>
      <span class="atk-n"><span>${String(i + 1).padStart(2, '0')}</span><span>${a.prop.join(' · ').toUpperCase()}</span></span>
      <b>${esc(a.name)}</b>
      <small>${esc(a.desc)}</small>
      <span class="atk-foot"><span>expect rc ${a.rc}</span>${inflight === a.id ? chip('RUNNING', { text: 'Running' }) : st}</span>
    </button>`;
  }).join('');
}

function attackMatrix() {
  const reqTests = store.tests?.tests || [];
  return `<div class="table-wrap"><table class="table matrix-table">
    <thead>
      <tr>
        <th>Attack Vector</th>
        <th>Target Invariant</th>
        <th>Expected Code</th>
        <th>Actual Engine Result</th>
        <th>Cryptographic Protection</th>
        <th>Verdict</th>
      </tr>
    </thead>
    <tbody>
      ${ATTACKS.map((a) => {
        const last = lastOf(a.id);
        const reqMatch = reqTests.find((t) => t.name.toLowerCase().includes(a.id) || t.name.toLowerCase().includes(a.name.toLowerCase()));
        const rc = last ? last.rc : (reqMatch ? a.rc : '—');
        const pass = last ? last.pass : (reqMatch ? reqMatch.ok : null);
        return `<tr>
          <td><b>${esc(a.name)}</b><div class="faint small">${esc(a.desc)}</div></td>
          <td>${a.prop.map((p) => `<span class="chip c-info">${esc(p)}</span>`).join(' ')}</td>
          <td class="mono">rc ${a.rc}</td>
          <td class="mono ${last ? (last.pass ? 'ok' : 'bad') : 'faint'}">${last ? `rc ${rc} (${last.verdict})` : (reqMatch ? `rc ${rc} (TAP PASS)` : '—')}</td>
          <td><span class="small">${esc(WHY[a.id])}</span></td>
          <td>${last ? (pass ? chip(last.result === 'BLOCKED' ? 'BLOCKED' : 'PASS', { text: last.result }) : chip('FAIL')) : (reqMatch ? chip('PASS', { text: 'VERIFIED' }) : chip('NOT RUN'))}</td>
        </tr>`;
      }).join('')}
    </tbody>
  </table></div>`;
}

function detail() {
  const a = ATTACKS.find((x) => x.id === selected) || ATTACKS[1];
  const last = lastOf(a.id);
  const resp = store.attacks.last?.attack?.id === a.id ? store.attacks.last : null;
  const secure = store.session.state === 'SECURE';
  const result = last
    ? `<div class="result-banner ${last.pass ? (last.result === 'BLOCKED' ? 'ok' : 'info') : 'bad'}">
         <div><div class="statement ${last.pass ? (last.result === 'BLOCKED' ? 'ok' : 'info') : 'bad'}">${last.pass ? (last.result === 'BLOCKED' ? '✓ BLOCKED' : '✓ ACCEPTED') : '✕ UNEXPECTED'}</div>
         <div class="faint small" style="margin-top:4px">${esc(last.verdict)} · return code ${last.rc} · expected rc ${last.expected_rc} · ${time(last.ts)}</div></div>
         ${chip(last.pass ? 'PASS' : 'FAIL', { lg: true })}
       </div>`
    : `<div class="result-banner"><div><div class="statement faint">○ NOT RUN</div><div class="faint small" style="margin-top:4px">Run the attack to get the real verdict from <code>unseal()</code> in C.</div></div></div>`;
  const target = resp ? (resp.steps || []).find((s) => s.packet && s.packet.role === 'attacker') || (resp.steps || []).find((s) => s.packet) : null;
  const activePacket = target?.packet || (resp?.steps?.[0]?.packet ?? null);

  return `
    ${panelHead(`Attack · ${esc(a.name)}`, a.prop.map((p) => `Security property: ${p}`).join(' · '),
      `<button class="btn ${a.id === 'normal' ? 'btn-primary' : 'btn-danger'}" data-run="${a.id}"${inflight ? ' disabled' : ''}>${a.id === 'normal' ? 'Send normal packet' : 'Run attack'}</button>`)}
    <div class="detail-grid">
      <div>Method</div><div>${esc(a.method)}</div>
      <div>Expected</div><div>${esc(a.expected)} <span class="faint mono small">rc ${a.rc}</span></div>
      <div>Defense</div><div>${esc(WHY[a.id])}</div>
      <div>Property</div><div class="actions">${a.prop.map((p) => chip('ACTIVE', { text: p, glyph: '' })).join('')}</div>
      ${resp ? `<div>Network</div><div>${esc(resp.attack.network)}</div><div>Verifier</div><div class="mono small">${esc(resp.attack.verifier)}</div>` : ''}
    </div>
    <div style="margin-top:16px">${result}</div>
    ${!secure && !last ? '<p class="note">No live session — running an attack first performs an initial handshake.</p>' : ''}

    <div class="section-subhead" style="margin-top:24px"><span class="eyebrow">Static Comparison</span><h3>Attack flow versus legitimate flow</h3></div>
    ${staticAttackComparison(a.id)}

    ${target ? `<div class="hr"></div>
      <div class="section-subhead"><span class="eyebrow">Wire Inspection</span><h3>Captured packet on wire</h3></div>
      ${packetFlow({ from: target.packet.role === 'attacker' ? { icon: 'network', name: 'NETWORK', sub: 'attacker in path', hostile: true } : { icon: 'client', name: 'CLIENT', sub: 'seal()' },
        to: { icon: 'server', name: 'SERVER', sub: 'unseal()' }, packet: target.packet, verdict: target.verdict, rc: target.rc, live: true,
        hostile: target.packet.role === 'attacker', label: `${target.packet.role === 'attacker' ? 'attacker packet' : 'packet'} · ${target.packet.length} B` })}
      <div style="margin-top:16px">${byteMap(target.packet)}</div>
      <div class="steps-mini">${(resp.steps || []).map((s) => `<div class="step-mini"><span>${esc(s.label)}${s.packet ? ` <span class="faint mono">seq ${esc(seqLabel(s.packet.seq))}</span>` : ''}</span>${verdictBadge(s.verdict, s.rc)}</div>`).join('')}</div>` : ''}

    <div class="hr"></div>
    <div class="section-subhead"><span class="eyebrow">Security Decision Trace</span><h3>Cryptographic evaluation sequence</h3></div>
    ${securityDecisionTrace(activePacket || (last ? { id: 1, rc: last.rc, verdict: last.verdict, seq: 1, length: 48, ct_len: 12, attack: a.id } : null))}

    <div style="margin-top:20px">
      ${whyThisMatters(PROP_MAP[a.id] || 'aead')}
    </div>`;
}

function history() {
  const h = store.attacks.history.slice(0, 12);
  if (!h.length) return '<div class="small faint">No attacks launched yet.</div>';
  return `<div class="table-wrap"><table class="table"><thead><tr><th>Time</th><th>Attack</th><th>RC</th><th>Verdict</th><th>Check</th></tr></thead><tbody>
    ${h.map((x) => `<tr><td class="mono">${time(x.ts)}</td><td>${esc(x.title)}</td><td class="mono">${x.rc}</td><td>${verdictBadge(x.verdict)}</td><td>${chip(x.pass ? 'PASS' : 'FAIL')}</td></tr>`).join('')}
  </tbody></table></div>`;
}

function suiteCard() {
  const t = store.tests;
  if (!t) return emptyState('The eight required tests from the brief run as a separate process (<code>tests/test_attacks.c</code>). Run them to populate verified results.', '<button class="btn btn-primary" data-a="suite">Run security tests</button>');
  if (!t.tests) return `<div class="alert" role="alert"><b>SUITE FAILED TO RUN</b><span>${esc(t.error || 'no TAP output')}</span></div>`;
  return `<div class="suite-head"><div><div class="score ${t.failed ? 'bad' : 'ok'}">${t.passed}<small> / ${t.total}</small></div>
      <div class="faint small mono" style="margin-top:6px">${esc(t.suite)} · exit ${t.code} · ${t.ms} ms</div></div>${chip(t.failed ? 'FAILED' : 'PASS', { lg: true })}</div>
    <div class="actions"><button class="btn btn-sm" data-a="suite">Re-run</button><button class="btn btn-sm btn-ghost" data-a="center">Open Test Center</button></div>`;
}

export default {
  id: 'attacks',
  label: 'Attack Lab',
  icon: 'attacks',
  mount(root, ctx) {
    this.ctx = ctx;
    root.innerHTML = `
      ${pageHead('Task 4 · Security boundaries', 'Attack simulation lab', 'Each attack asks <code>sc_engine</code> to build the hostile packet and push it through the live server&rsquo;s <code>unseal()</code>. Verdict, return code and reason come straight back from C.',
        '<button class="btn btn-primary" data-a="all">Run all 8</button>')}
      <div id="atk-summary"></div>
      <div class="grid section">
        <section class="panel s5" aria-label="Attacks">${panelHead('Attack scenarios', 'Select an attack vector to evaluate')}<div class="atk-grid" id="atk-grid"></div></section>
        <section class="panel focused s7" id="atk-stage-card" aria-live="polite"><div id="atk-detail"></div></section>
      </div>

      <section class="panel section" aria-labelledby="atk-matrix-title">
        ${panelHead('<span id="atk-matrix-title">Complete attack verification matrix</span>', 'Comprehensive breakdown of all evaluated attacks, invariants and return codes')}
        <div id="atk-matrix"></div>
      </section>

      <div class="grid section">
        <section class="panel s5" id="atk-suite-card">${panelHead('Required attack test suite', 'tests/test_attacks.c · 8 required tests')}<div id="atk-suite"></div></section>
        <section class="panel s7">${panelHead('Attack execution history', 'Newest first')}<div id="atk-history"></div></section>
      </div>`;
    root.addEventListener('click', (e) => {
      const card = e.target.closest('button[data-atk]');
      if (card) { selected = card.dataset.atk; this.update(); return; }
      const r = e.target.closest('button[data-run]');
      if (r) { busy(r, () => this.launch(r.dataset.run)); return; }
      const b = e.target.closest('button[data-a]');
      if (!b) return;
      if (b.dataset.a === 'all') busy(b, () => this.runAll());
      if (b.dataset.a === 'suite') busy(b, () => run('tests'));
      if (b.dataset.a === 'center') ctx.navigate('tests');
    });
    this.update();
  },
  async launch(id) {
    inflight = id;
    selected = id;
    this.update();
    let r;
    try {
      if (store.session.state !== 'SECURE') await engine('handshake', 'plain');
      r = await engine('attack', id);
    } finally {
      inflight = null;
      if ($('#atk-grid')) this.update();
    }
    return r;
  },
  async runAll() {
    for (const a of ATTACKS) {
      await this.launch(a.id);
      await new Promise((r) => setTimeout(r, 200));
    }
  },
  update() {
    if (!$('#atk-grid')) return;
    const focused = document.activeElement?.dataset?.atk;
    $('#atk-summary').innerHTML = summary();
    $('#atk-grid').innerHTML = cards();
    if (focused) $(`#atk-grid [data-atk="${focused}"]`)?.focus();
    $('#atk-detail').innerHTML = detail();
    $('#atk-matrix').innerHTML = attackMatrix();
    $('#atk-history').innerHTML = history();
    $('#atk-suite').innerHTML = suiteCard();
  },
};
