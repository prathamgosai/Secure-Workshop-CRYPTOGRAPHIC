import { store, engine, run } from '../store.js';
import { esc, time, busy, chip, icons, pad2, packetFlow, panelHead, toast, $, architecturalTiers, fullCryptoPipeline, whyThisMatters } from '../ui.js';
import { securityDecisionTrace } from '../trace.js';

const STATES = [
  ['INIT', ['Load libsodium', 'Load / generate keys'], 'sodium_init() · ephemeral X25519 key pairs'],
  ['AUTH', ['Exchange public keys', 'Derive session keys'], 'crypto_kx → BLAKE2b → rx / tx split'],
  ['SECURE', ['Encrypt', 'Authenticate', 'Check replay'], 'ChaCha20-Poly1305 · seq as AAD'],
  ['TERMINATE', ['Wipe secrets', 'Close session'], 'sodium_free() zeroes every session key'],
];

/* Session lifecycle: static diagram, current state highlighted. Timestamps
 * and event text come directly from the engine. */
export function lifecycle() {
  const cur = store.session.state;
  const idx = STATES.findIndex((s) => s[0] === cur);
  return `<ol class="lifecycle" aria-label="Session lifecycle">${STATES.map(([name, subs, tech], i) => {
    const log = store.stateLog[name];
    const term = name === 'TERMINATE' && i === idx;
    const cls = i < idx ? 'done' : i === idx ? `current${term ? ' term' : ''}` : '';
    const status = i === idx ? (term ? 'CLOSED' : 'CURRENT') : i < idx ? 'COMPLETE' : 'PENDING';
    return `<li class="stage ${cls}"${i === idx ? ' aria-current="step"' : ''}>
      <div class="stage-top"><span class="stage-num">0${i + 1}</span>${chip(status)}</div>
      <div class="stage-name">${name}</div>
      <ul class="stage-tree">${subs.map((s) => `<li>${s}</li>`).join('')}</ul>
      <div class="stage-ev">${esc(log?.msg || tech)}</div>
      <div class="stage-time">${log ? time(log.ts) : '—'}</div>
    </li>`;
  }).join('')}</ol>`;
}

/* Evidence gathered so far, strictly from real engine and test results. */
function evidence() {
  const hist = store.attacks.history;
  const blocked = (id) => hist.some((h) => h.id === id && h.pass);
  const reqPass = !!(store.tests && store.tests.total > 0 && store.tests.failed === 0);
  const extPass = !!(store.testsExtended && store.testsExtended.total > 0 && store.testsExtended.failed === 0);
  const accepted = store.packets.some((p) => p.verdict === 'ACCEPTED');
  return { blocked, reqPass, extPass, accepted };
}

function pillars() {
  const s = store.session;
  const { blocked, reqPass, accepted } = evidence();
  const secure = s.state === 'SECURE';
  const P = [
    {
      name: 'CONFIDENTIALITY', icon: 'lock', mech: 'ChaCha20 · 256-bit session key',
      ...(accepted ? { st: 'VERIFIED', ev: 'Packet decrypted only with the matching session key (rc 0).' }
        : reqPass ? { st: 'VERIFIED', ev: 'Required suite: round-trip test passed.' }
          : secure ? { st: 'ACTIVE', ev: 'AEAD channel established — send a packet to verify.' }
            : { st: 'NOT RUN', ev: 'No packet exchanged yet.' }),
    },
    {
      name: 'INTEGRITY', icon: 'shield', mech: 'Poly1305 tag · 16 B',
      ...(blocked('tamper') || blocked('aad') ? { st: 'VERIFIED', ev: `Live ${blocked('tamper') ? 'ciphertext bit-flip' : 'AAD rewrite'} rejected (rc −2).` }
        : reqPass ? { st: 'VERIFIED', ev: 'Required suite: tamper and AAD tests passed.' }
          : { st: 'NOT RUN', ev: 'Run a tamper attack or the test suite.' }),
    },
    {
      name: 'AUTHENTICITY', icon: 'fingerprint', mech: s.authenticated ? 'Ed25519-signed handshake' : 'Poly1305 · plain crypto_kx',
      ...(s.authenticated ? { st: 'VERIFIED', ev: 'Server signature over the transcript verified against pinned server_pk.bin.' }
        : secure || blocked('wrongkey') ? { st: 'LIMITED', ev: 'Packets are authenticated, but plain crypto_kx does not authenticate the peer. Use the signed handshake.' }
          : { st: 'NOT RUN', ev: 'Run the handshake (signed mode authenticates the server).' }),
    },
    {
      name: 'FRESHNESS', icon: 'clock', mech: '64-bit seq · strict window',
      ...(blocked('replay') ? { st: 'VERIFIED', ev: `Replayed packet rejected (rc −3)${blocked('reorder') ? '; reorder rejected too' : ''}.` }
        : reqPass ? { st: 'VERIFIED', ev: 'Required suite: replay and reorder tests passed.' }
          : secure ? { st: 'ACTIVE', ev: 'Replay window armed — launch a replay to verify.' }
            : { st: 'NOT RUN', ev: 'Not yet exercised.' }),
    },
  ];
  const tone = { VERIFIED: 'ok', ACTIVE: 'info', LIMITED: 'warn', 'NOT RUN': 'muted' };
  const glyph = { ok: '✓', info: '●', warn: '!', muted: '○' };
  return `<div class="pillars">${P.map((p) => `
    <div class="pillar">
      <div class="pillar-head">${icons[p.icon]}<span class="pillar-name">${p.name}</span></div>
      <div class="pillar-status ${tone[p.st]}"><span class="g" aria-hidden="true">${glyph[tone[p.st]]}</span>${p.st}</div>
      <div class="pillar-mech">${esc(p.mech)}</div>
      <div class="pillar-ev">${esc(p.ev)}</div>
    </div>`).join('')}</div>`;
}

function posture() {
  const s = store.session;
  const v = store.vault;
  const hs = store.handshake;
  const t = store.tests;
  const w = store.wrap;
  const { blocked, reqPass } = evidence();
  const rows = [
    { icon: 'key', name: 'Key Management', alg: 'Ed25519 · X25519 · 0600',
      st: v ? (v.permissions_ok ? 'PASS' : 'FAILED') : 'NOT RUN',
      why: v ? (v.permissions_ok ? 'private key files 0600, public 0644, exact sizes' : 'unexpected file modes — see Key Vault') : 'open the Key Vault to scan key files',
      detail: ['Task 1. ./keygen creates the Ed25519 identity key and the X25519 key-exchange key. Private files are created with open(…, 0600) and fchmod, reloaded and checked against their public halves, then wiped with sodium_memzero.',
        'This row reflects the most recent vault scan performed by sc_engine.'] },
    { icon: 'handshake', name: 'Session Establishment', alg: 'X25519 · crypto_kx',
      st: hs?.ok ? 'PASS' : hs ? 'FAILED' : 'NOT RUN',
      why: hs?.ok ? `${hs.mode === 'signed' ? 'signed' : 'plain'} handshake · client_tx = server_rx · directional keys` : 'run the handshake',
      detail: ['Task 2. Both sides exchange ephemeral X25519 public keys; crypto_kx hashes the shared secret with both public keys (BLAKE2b) and splits it into two directional keys.',
        'The checks client_tx == server_rx and client_tx ≠ client_rx are performed in C with sodium_memcmp.'] },
    { icon: 'lock', name: 'AEAD Protection', alg: 'ChaCha20-Poly1305-IETF',
      st: blocked('tamper') || blocked('aad') || reqPass ? 'PASS' : 'NOT RUN',
      why: blocked('tamper') ? 'live ciphertext bit-flip rejected (rc −2)' : reqPass ? 'required suite: tamper + AAD pass' : 'authenticated encryption with associated data',
      detail: ['Task 3. Each packet is [seq 8][nonce 12][ciphertext][tag 16]. The sequence number is authenticated as AAD, so it cannot be changed even though it travels in clear.',
        'unseal() checks length → replay window → tag, and returns nothing unless the tag verifies.'] },
    { icon: 'clock', name: 'Replay Protection', alg: 'seq > last_seq',
      st: blocked('replay') || reqPass ? 'PASS' : 'NOT RUN',
      why: blocked('replay') ? 'live replay rejected (rc −3)' : reqPass ? 'required suite: replay + reorder pass' : 'strict monotonic sequence window',
      detail: ['Task 4. The receiver only accepts a sequence number strictly greater than the last authenticated one. last_seq is updated only after the tag verifies, so a forged large sequence cannot poison the window.'] },
    { icon: 'wrap', name: 'Key Wrapping', alg: 'Argon2id · secretbox',
      st: w.correct?.pass && w.wrong?.pass ? 'PASS' : w.correct || w.wrong ? (w.correct?.pass === false || w.wrong?.pass === false ? 'FAILED' : 'PARTIAL') : 'NOT RUN',
      why: w.correct?.pass && w.wrong?.pass ? 'correct passphrase accepted · wrong passphrase rejected' : w.correct || w.wrong ? 'run both the correct and wrong passphrase checks' : 'private key encrypted at rest',
      detail: ['Task 5. Argon2id (64 MiB) turns a passphrase and random salt into a 32-byte key; crypto_secretbox (XSalsa20-Poly1305) encrypts the Ed25519 secret key. A wrong passphrase fails the MAC and releases nothing.'] },
    { icon: 'attacks', name: 'Attack Testing', alg: 'tests/test_attacks.c',
      st: t ? (t.total && !t.failed ? 'PASS' : 'FAILED') : 'NOT RUN',
      text: t && t.total ? `${t.passed}/${t.total} ${t.failed ? 'FAIL' : 'PASS'}` : undefined,
      why: t ? `required suite · exit code ${t.code}` : store.attacks.executed ? `${store.attacks.passed}/${store.attacks.executed} live attacks behaved as expected — suite not run` : 'run the security test suite',
      detail: ['The eight required tests from the brief run as a separate process. The Attack Lab runs the same attacks live against the session inside sc_engine.'] },
  ];
  return `<div class="posture">${rows.map((r) => `
    <details>
      <summary>${icons[r.icon].replace('<svg', '<svg class="ico"')}<span class="name">${r.name}</span><span class="alg">${esc(r.alg)}</span><span class="why">${esc(r.why)}</span>${chip(r.st, { text: r.text })}${icons.caret}</summary>
      <div class="detail">${r.detail.map((d) => `<p>${esc(d)}</p>`).join('')}<p class="faint">Current evidence: ${esc(r.why)}.</p></div>
    </details>`).join('')}</div>`;
}

function heroStatus() {
  const t = store.tests;
  const s = store.session;
  const { blocked, reqPass } = evidence();
  const isProtected = s.state === 'SECURE' && (s.authenticated || blocked('wrongkey')) && (reqPass || blocked('tamper'));

  const score = t && t.total
    ? `<div class="score ${t.failed ? 'bad' : 'ok'}">${t.passed}<small> / ${t.total}</small></div>${chip(t.failed ? 'FAILED' : 'PASS', { lg: true })}`
    : `${chip('NOT RUN', { lg: true })}<span class="faint small" style="max-width:240px">Run the security test suite to populate verified results.</span>`;

  return `
    <div class="meta"><span class="k">Session</span><span>${chip(s.state === 'SECURE' ? 'SECURE' : s.state === 'TERMINATE' ? 'TERMINATED' : s.state, { lg: true, tone: s.state === 'SECURE' ? 'ok' : s.state === 'TERMINATE' ? 'muted' : 'info' })}</span></div>
    <div class="meta"><span class="k">Security Posture</span><span>${isProtected ? chip('PROTECTED', { lg: true, tone: 'ok', text: 'VERDICT: PROTECTED' }) : chip(s.state === 'SECURE' ? 'ACTIVE' : 'READY', { lg: true, tone: 'info', text: s.state === 'SECURE' ? 'AEAD ACTIVE' : 'SYSTEM READY' })}</span></div>
    <div class="meta"><span class="k">Security tests · required</span>${score}</div>`;
}

function metrics() {
  const a = store.attacks;
  const acc = store.packets.filter((p) => p.verdict === 'ACCEPTED').length;
  const rej = store.packets.length - acc;
  const s = store.session;
  return `<div class="metrics-line">
    <div class="metric"><span>Packets accepted</span><b>${acc}</b></div>
    <div class="metric"><span>Packets rejected</span><b>${rej}</b></div>
    <div class="metric"><span>Attacks blocked</span><b class="${a.failed ? 'bad' : ''}">${a.blocked}<small> of ${a.executed} run</small></b></div>
    <div class="metric"><span>Key epoch</span><b>${s.state === 'SECURE' ? pad2(s.epoch) : '—'}</b></div>
    <div class="metric"><span>Next sequence</span><b>${s.state === 'SECURE' ? s.next_seq : '—'}</b></div>
  </div>`;
}

function lastTransmission() {
  const p = store.deliveries[0];
  const s = store.session;
  const secure = s.state === 'SECURE';
  return packetFlow({
    from: { icon: 'client', name: 'CLIENT', sub: s.key_fingerprints ? `tx ${s.key_fingerprints.client_tx}` : 'seal() · client_tx' },
    to: { icon: 'server', name: 'SERVER', sub: s.key_fingerprints ? `rx ${s.key_fingerprints.server_rx}` : 'unseal() · server_rx' },
    packet: p || null, verdict: p?.verdict, rc: p?.rc, live: secure, hostile: p?.role === 'attacker',
    label: p ? `packet #${p.id} · ${p.length} B · ${p.label}` : secure ? 'channel ready — no packet sent yet' : s.state === 'TERMINATE' ? 'session terminated · keys wiped' : 'no session — run the handshake',
  });
}

export default {
  id: 'overview',
  label: 'Overview',
  icon: 'overview',
  mount(root, ctx) {
    root.innerHTML = `
      <section class="panel hero" aria-labelledby="ov-title">
        <div class="hero-top">
          <div>
            <span class="eyebrow accent">Cryptographic Command Center</span>
            <h1 id="ov-title">SECURE CHANNEL</h1>
            <p class="lede">A live visualization of authenticated key exchange, encrypted communication, packet integrity, replay protection, attack resistance, and secure key handling powered by libsodium.</p>
            <div class="actions">
              <button class="btn btn-primary" data-a="hs">Start secure session</button>
              <button class="btn" data-a="send">Send encrypted packet</button>
              <button class="btn" data-a="tests">Run security tests</button>
              <button class="btn btn-ghost" data-a="keys">Generate identity keys</button>
            </div>
          </div>
          <div class="hero-status" id="ov-status"></div>
        </div>
        <div id="ov-pillars"></div>
        <div class="primitives" aria-label="Cryptographic primitives">
          <div class="prim"><b>ChaCha20-Poly1305</b><span>AEAD packets</span></div>
          <div class="prim"><b>X25519</b><span>Key exchange (crypto_kx)</span></div>
          <div class="prim"><b>Ed25519</b><span>Identity · signatures</span></div>
          <div class="prim"><b>Argon2id</b><span>Key wrapping KDF</span></div>
          <div class="prim"><b>seq &gt; last_seq</b><span>Replay protection</span></div>
        </div>
      </section>

      <section class="section" aria-labelledby="ov-arch">
        <div class="section-head"><div><span class="eyebrow">Trust Boundaries</span><h2 id="ov-arch">System architecture &amp; trust model</h2><p>Untrusted presentation layer is strictly isolated from the controlled bridge and the trusted C cryptographic boundary.</p></div></div>
        ${architecturalTiers()}
      </section>

      <section class="section" aria-labelledby="ov-pipe">
        <div class="section-head"><div><span class="eyebrow">Cryptographic AEAD</span><h2 id="ov-pipe">Cryptographic pipeline</h2><p>Static ten-stage message lifecycle: message validation → sequence binding → nonce generation → AAD authentication → ChaCha20 encryption → transport → unseal → release.</p></div></div>
        <div id="ov-pipeline"></div>
      </section>

      <section class="section" aria-labelledby="ov-trace">
        <div class="section-head"><div><span class="eyebrow">Instrumentation</span><h2 id="ov-trace">Security decision trace</h2><p>Every important cryptographic operation explained step-by-step with real return codes from unseal().</p></div></div>
        <div id="ov-decision"></div>
      </section>

      <section class="section" aria-labelledby="ov-life">
        <div class="section-head"><div><span class="eyebrow">Protocol</span><h2 id="ov-life">Session lifecycle</h2><p>INIT → AUTH → SECURE → TERMINATE · state transitions and timestamps from engine events</p></div></div>
        <div id="ov-sm"></div>
        <div id="ov-metrics"></div>
      </section>

      <section class="section" aria-labelledby="ov-post">
        <div class="section-head"><div><span class="eyebrow">Verification</span><h2 id="ov-post">Security posture &amp; evidence matrix</h2><p>Each row reflects checks actually executed in this session. Select a row for technical citations and libsodium implementation details.</p></div></div>
        <div id="ov-posture"></div>
      </section>

      <section class="section panel" aria-labelledby="ov-last">
        ${panelHead('<span id="ov-last">Last transmission</span>', 'Static view of the most recent packet on the wire and the server&rsquo;s verdict from unseal()')}
        <div id="ov-flow"></div>
      </section>

      <section class="section" aria-labelledby="ov-why">
        <div class="section-head"><div><span class="eyebrow">Cryptographic Foundations</span><h2 id="ov-why">Why these primitives matter</h2></div></div>
        <div class="why-grid">
          ${whyThisMatters('aead')}
          ${whyThisMatters('aad')}
          ${whyThisMatters('replay')}
          ${whyThisMatters('directional')}
          ${whyThisMatters('handshake')}
          ${whyThisMatters('keywrap')}
        </div>
      </section>`;

    root.addEventListener('click', (e) => {
      const b = e.target.closest('button[data-a]');
      if (!b) return;
      const a = b.dataset.a;
      if (a === 'keys') busy(b, async () => { await run('keygen'); await engine('vault'); });
      if (a === 'hs') busy(b, () => engine('handshake', 'plain'));
      if (a === 'send') busy(b, async () => {
        if (store.session.state !== 'SECURE') { toast('Channel is not SECURE — start a secure session first', true); return; }
        await engine('send', 'Status report: all systems nominal');
      });
      if (a === 'tests') busy(b, () => run('tests'));
    });
    this.update();
  },
  update() {
    $('#ov-status').innerHTML = heroStatus();
    $('#ov-pillars').innerHTML = pillars();
    $('#ov-sm').innerHTML = lifecycle();
    $('#ov-metrics').innerHTML = metrics();
    const open = [...document.querySelectorAll('#ov-posture details')].map((d) => d.open);
    $('#ov-posture').innerHTML = posture();
    document.querySelectorAll('#ov-posture details').forEach((d, i) => { d.open = !!open[i]; });
    $('#ov-flow').innerHTML = lastTransmission();

    const latest = store.deliveries[0] || store.packets[0];
    $('#ov-pipeline').innerHTML = fullCryptoPipeline(latest, latest?.delivered);
    $('#ov-decision').innerHTML = securityDecisionTrace(latest);
  },
};
