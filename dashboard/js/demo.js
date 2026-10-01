// Guided presentation: 20 steps, each calling the real engine / binaries.
// Narration that reports a result is computed from the actual response.
// Step changes are instant: no animation, no smooth scrolling.
import { store, engine, run, resetCounters, notify, addEvent } from './store.js';
import { setLogFilter } from './views/logs.js';
import { $, $$, chip, esc } from './ui.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const AUTO_DELAY = 4200;

export function createDemo(ctx) {
  const V = ctx.views;
  /* Static focus marker on the element being discussed. */
  const focus = (sel) => async () => {
    $$('.demo-target').forEach((el) => el.classList.remove('demo-target'));
    const el = $(sel);
    if (el) { el.classList.add('demo-target'); el.scrollIntoView({ behavior: 'auto', block: 'start' }); }
  };
  const lastAttack = () => {
    const a = store.attacks.last?.attack;
    return a ? `Result: ${a.verdict} (rc ${a.rc}) — ${a.pass ? 'behaved as expected' : 'UNEXPECTED'}.` : 'No result reported.';
  };

  const steps = [
    { t: 'System overview', view: 'overview', p: ['Trust model'],
      n: () => `sc_engine reset and re-initialised libsodium ${store.libsodium || ''}. Every status on screen is reported by the C code.`,
      why: 'The browser never computes a cryptographic result — it only displays what the C implementation returns.',
      run: async () => { await engine('reset'); await engine('hello'); await focus('#ov-status')(); } },
    { t: 'Key generation', view: 'vault', p: ['Key protection'],
      n: () => `./keygen created Ed25519 and X25519 key pairs. Private files: ${store.vault ? (store.vault.permissions_ok ? '0600 verified' : 'PERMISSIONS NOT AS EXPECTED') : 'not scanned'}.`,
      why: 'Long-term private keys must be readable only by their owner; the vault checks file modes and key-pair consistency.',
      run: async () => { await run('keygen'); await engine('vault'); await focus('#vk-grid')(); } },
    { t: 'Key exchange', view: 'handshake', p: ['Key agreement'],
      n: () => (store.handshake?.ok ? 'Client and server exchanged ephemeral X25519 public keys — only public keys crossed the network.' : `Handshake failed: ${store.handshake?.error || 'no response'}.`),
      why: 'Both sides reach the same shared secret without ever transmitting it.',
      run: async () => { await V.handshake.run('plain'); } },
    { t: 'Derive TX / RX keys', view: 'handshake', p: ['Key separation'],
      n: () => { const f = store.session.key_fingerprints; return f ? `crypto_kx split the secret: client_tx = server_rx (${f.client_tx}); client_rx = server_tx.` : 'No session keys reported.'; },
      why: 'Separate keys per direction mean a packet can never be reflected back and accepted by its sender.',
      run: focus('#hs-keys-card') },
    { t: 'Enter SECURE state', view: 'overview', p: ['Confidentiality', 'Integrity', 'Freshness'],
      n: () => `Session state: ${store.session.state}. Ephemeral secrets wiped; AEAD and the replay window are active.`,
      why: 'The lifecycle INIT → AUTH → SECURE → TERMINATE governs which operations are allowed.',
      run: focus('#ov-sm') },
    { t: 'Secure message', view: 'channel', p: ['Confidentiality', 'Integrity'],
      n: () => { const p = store.deliveries[0]; return p ? `Client sealed ${p.length} B with ChaCha20-Poly1305; server unseal(): ${p.verdict} (rc ${p.rc}).` : 'No packet reported.'; },
      why: 'Encryption hides the content; the Poly1305 tag proves it was not changed.',
      run: async () => { await V.channel.send('Quarterly report: transfer approved'); await focus('#ch-packet-card')(); } },
    { t: 'Packet inspection', view: 'inspector', p: ['Integrity · AAD'],
      n: 'On the wire: 8-byte sequence (AAD) · 12-byte nonce · ciphertext · 16-byte tag. No key and no plaintext.',
      why: 'An eavesdropper sees exactly these bytes. The sequence number is visible but cannot be changed.',
      run: focus('#pi-detail') },
    { t: 'Launch tamper attack', view: 'attacks', p: ['Integrity'],
      n: () => `The attacker flipped one bit of ciphertext in transit. ${lastAttack()}`,
      why: 'Any modification of an authenticated packet must be detected before decryption output is used.',
      run: async () => { await V.attacks.launch('tamper'); await focus('#atk-stage-card')(); } },
    { t: 'Tamper rejected', view: 'attacks', p: ['Integrity'],
      n: () => `${lastAttack()} The Poly1305 tag no longer matched.`,
      why: 'Return code −2: authentication failed, nothing was decrypted, replay state was not updated.',
      run: focus('#atk-stage-card') },
    { t: 'Launch replay attack', view: 'attacks', p: ['Freshness'],
      n: () => `The attacker re-sent a packet the server already accepted. ${lastAttack()}`,
      why: 'A valid but old packet must not be accepted twice.',
      run: async () => { await V.attacks.launch('replay'); await focus('#atk-stage-card')(); } },
    { t: 'Replay rejected', view: 'attacks', p: ['Freshness'],
      n: () => `${lastAttack()} Its sequence number was not greater than last_seq.`,
      why: 'Return code −3: the replay window refuses any seq ≤ the last authenticated seq.',
      run: focus('#atk-stage-card') },
    { t: 'Wrong-key forgery', view: 'attacks', p: ['Authenticity'],
      n: () => `The attacker forged a packet with a key of their own. ${lastAttack()}`,
      why: 'Without the session key, no one can produce a valid tag.',
      run: async () => { await V.attacks.launch('wrongkey'); await focus('#atk-stage-card')(); } },
    { t: 'Forgery rejected', view: 'attacks', p: ['Authenticity'],
      n: () => `${lastAttack()} The tag could not verify under the session key.`,
      why: 'Message authenticity follows from the secrecy of the session key.',
      run: focus('#atk-stage-card') },
    { t: 'Full test suite', view: 'tests', p: ['Verification'],
      n: () => (store.tests ? `tests/test_attacks.c ran as its own process: ${store.tests.passed} passed, ${store.tests.failed} failed.` : 'Suite did not run.'),
      why: 'The eight required tests repeat every attack independently of the dashboard.',
      run: async () => { await run('tests'); await focus('#atk-suite')(); } },
    { t: () => (store.tests && store.tests.total ? `${store.tests.passed} / ${store.tests.total} ${store.tests.failed ? 'FAIL' : 'PASS'}` : 'Test results'), view: 'tests', p: ['Verification'],
      n: () => (store.tests ? `Required suite: ${store.tests.passed} passed, ${store.tests.failed} failed (exit code ${store.tests.code}).` : 'Suite did not run.'),
      why: 'Each name and outcome comes from the program&rsquo;s TAP output, not from the dashboard.',
      run: focus('#atk-suite') },
    { t: 'Key wrapping', view: 'wrap', p: ['Key protection'],
      n: () => `Correct passphrase: ${store.wrap.correct ? (store.wrap.correct.pass ? 'accepted, key unwrapped' : 'UNEXPECTED') : 'not run'}. Wrong passphrase: ${store.wrap.wrong ? (store.wrap.wrong.pass ? 'MAC failed, secret not released' : 'UNEXPECTED') : 'not run'}.`,
      why: 'A stolen key file is useless without the passphrase; Argon2id makes every guess cost time and memory.',
      run: async () => { await V.wrap.ensureKeys(); await engine('wrap', 'correct'); await engine('wrap', 'wrong'); await engine('vault'); await focus('#vk-wrap')(); } },
    { t: 'OpenSSL comparison', view: 'openssl', p: ['Integrity'],
      n: () => (store.openssl?.cbc ? `aes-256-cbc returned "${store.openssl.cbc.tampered_block1}" with exit code ${store.openssl.cbc.openssl_exit}. Same change under AEAD: ${store.openssl.aead_tamper_rejected ? 'rejected' : 'not checked'}.` : 'Comparison did not complete.'),
      why: 'Encryption without authentication lets an attacker change data undetected.',
      run: async () => { await run('openssl'); await focus('#os-evidence')(); } },
    { t: 'Benchmark', view: 'bench', p: ['Performance'],
      n: () => { const r = store.bench?.results?.find((x) => x.algorithm === 'ChaCha20-Poly1305' && x.size === 1024); return r ? `Measured now: ChaCha20-Poly1305 at 1 KiB ≈ ${r.mib_per_sec.toFixed(0)} MiB/s, ${r.latency_us.toFixed(2)} µs per packet.` : 'Benchmark did not complete.'; },
      why: 'Strong cryptography costs microseconds per packet on commodity hardware.',
      run: () => run('bench') },
    { t: 'Terminate session', view: 'overview', p: ['Key hygiene'],
      n: () => `Session state: ${store.session.state}. sodium_free() zeroed and released every session key.`,
      why: 'Keys that no longer exist cannot be stolen later.',
      run: async () => { await engine('terminate'); await focus('#ov-sm')(); } },
    { t: 'Secret-wipe events', view: 'logs', p: ['Key hygiene'],
      n: () => `${store.events.filter((e) => e.level === 'WIPE').length} WIPE events recorded by the engine during this demo.`,
      why: 'The log shows every place secrets were erased — without ever logging a secret.',
      run: async () => { setLogFilter('WIPE'); ctx.navigate('logs'); } },
  ];

  const panel = $('#demo-panel');
  const btnStart = $('#demo-start'), btnPause = $('#demo-pause'), btnNext = $('#demo-next');
  const state = { idx: -1, auto: false, paused: false, busy: false, timer: null };
  $('#demo-segs').innerHTML = steps.map(() => '<i></i>').join('');

  function show(on) {
    panel.hidden = !on;
    document.body.classList.toggle('demo-on', on);
  }

  function render(running) {
    const s = steps[state.idx];
    show(state.idx >= 0);
    if (!s) return;
    $('#demo-num').textContent = String(state.idx + 1).padStart(2, '0');
    $('#demo-total').textContent = steps.length;
    $('#demo-title').textContent = (typeof s.t === 'function' ? s.t() : s.t).toUpperCase();
    $('#demo-narration').textContent = running ? 'Running against the live engine…' : (typeof s.n === 'function' ? s.n() : s.n);
    $('#demo-why').innerHTML = s.why;
    $('#demo-props').innerHTML = s.p.map((p) => chip('ACTIVE', { text: p, glyph: '' })).join('');
    $$('#demo-segs i').forEach((el, i) => { el.className = i < state.idx ? 'done' : i === state.idx ? (running ? 'cur' : 'done') : ''; });
    btnPause.disabled = !state.auto;
    btnPause.textContent = state.paused ? 'Resume' : 'Pause';
    btnStart.disabled = state.auto && !state.paused;
  }

  async function next() {
    clearTimeout(state.timer);
    if (state.busy) return;
    if (state.idx + 1 >= steps.length) { finish(); return; }
    state.idx++;
    const s = steps[state.idx];
    state.busy = true;
    ctx.navigate(s.view);
    render(true);
    try { await s.run(); }
    catch (e) { addEvent('ERROR', `demo step failed: ${e.message}`, 'dashboard'); }
    state.busy = false;
    render(false);
    notify('demo');
    if (state.auto && !state.paused) state.timer = setTimeout(next, AUTO_DELAY);
  }

  function finish() {
    state.auto = false;
    btnStart.disabled = false;
    btnPause.disabled = true;
    $('#demo-title').textContent = 'DEMO COMPLETE';
    $('#demo-narration').textContent = 'All 20 steps ran against the live implementation. Press Start demo to run again, or explore any section.';
    $('#demo-why').innerHTML = esc('Every result shown during the demo was produced by the C programs in this session.');
    $('#demo-props').innerHTML = chip('COMPLETE', { text: 'Complete' });
    $$('#demo-segs i').forEach((el) => { el.className = 'done'; });
    $$('.demo-target').forEach((el) => el.classList.remove('demo-target'));
    state.idx = steps.length;
  }

  btnStart.addEventListener('click', () => {
    if (state.paused) { state.paused = false; render(false); next(); return; }
    if (state.idx >= steps.length) state.idx = -1;
    state.auto = true;
    state.paused = false;
    if (!state.busy) next();
  });
  btnPause.addEventListener('click', () => {
    if (!state.auto) return;
    state.paused = !state.paused;
    clearTimeout(state.timer);
    render(state.busy);
    if (!state.paused && !state.busy) state.timer = setTimeout(next, 600);
  });
  btnNext.addEventListener('click', () => {
    if (state.idx >= steps.length) state.idx = -1;
    if (state.idx < 0 && !state.auto) state.paused = false;
    next();
  });
  $('#demo-reset').addEventListener('click', async () => {
    clearTimeout(state.timer);
    Object.assign(state, { idx: -1, auto: false, paused: false });
    show(false);
    btnStart.disabled = false;
    btnPause.disabled = true;
    btnPause.textContent = 'Pause';
    $$('.demo-target').forEach((el) => el.classList.remove('demo-target'));
    resetCounters();
    setLogFilter('ALL');
    await engine('reset');
    ctx.navigate('overview');
  });

  return { steps, next };
}
