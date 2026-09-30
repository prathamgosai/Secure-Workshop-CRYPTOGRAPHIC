// Guided presentation: 20 steps, each calling the real engine / binaries.
// Narration that reports a result is computed from the actual response.
import { store, engine, run, resetCounters, notify, addEvent } from './store.js';
import { setLogFilter } from './views/logs.js';
import { $ } from './ui.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const AUTO_DELAY = 3600;

export function createDemo(ctx) {
  const V = ctx.views;
  const spot = (sel) => async () => {
    await sleep(150);
    const el = $(sel);
    if (el) { el.classList.remove('spotlight'); void el.offsetWidth; el.classList.add('spotlight'); el.scrollIntoView({ behavior: 'smooth', block: 'center' }); }
  };
  const lastAttack = () => {
    const a = store.attacks.last?.attack;
    return a ? `Result: ${a.verdict} (rc ${a.rc}) — ${a.pass ? 'behaved as expected' : 'UNEXPECTED'}.` : '';
  };

  const steps = [
    { t: 'Initialize system', view: 'overview', n: 'sc_engine starts libsodium. Everything on screen is reported by the C code.',
      run: async () => { await engine('reset'); await engine('hello'); } },
    { t: 'Generate / load keys', view: 'vault', n: () => `./keygen created Ed25519 + X25519 key pairs. Private files: ${store.vault?.permissions_ok ? '0600 verified' : 'CHECK PERMISSIONS'}.`,
      run: async () => { await run('keygen'); await engine('vault'); } },
    { t: 'Perform handshake', view: 'handshake', n: 'Client and server exchange ephemeral X25519 public keys — only public keys cross the network.',
      run: () => V.handshake.run('plain') },
    { t: 'Derive TX / RX keys', view: 'handshake', n: () => `crypto_kx splits the shared secret: client_tx = server_rx (${store.session.key_fingerprints?.client_tx || '—'}), client_rx = server_tx.`,
      run: spot('#hs-keys') },
    { t: 'Enter SECURE state', view: 'overview', n: 'Ephemeral secrets wiped. AEAD and the replay window are now active.',
      run: spot('#ov-sm') },
    { t: 'Send normal packet', view: 'channel', n: () => `Client sealed with ChaCha20-Poly1305; server verified the tag: ${store.deliveries[0]?.verdict || '—'}.`,
      run: async () => { await sleep(300); await V.channel.send('Quarterly report: transfer approved'); } },
    { t: 'Packet inspector', view: 'inspector', n: 'On the wire: 8-byte seq (AAD) · 12-byte nonce · ciphertext · 16-byte tag. No key, no plaintext.',
      run: spot('#pi-detail') },
    { t: 'Launch tamper attack', view: 'attacks', n: 'The attacker flips one bit of ciphertext in transit.',
      run: () => V.attacks.launch('tamper') },
    { t: 'Tamper rejected', view: 'attacks', n: () => `${lastAttack()} Poly1305 no longer matches; the untouched original is still accepted.`,
      run: spot('#atk-stage-card') },
    { t: 'Launch replay attack', view: 'attacks', n: 'The attacker re-sends a packet the server already accepted.',
      run: () => V.attacks.launch('replay') },
    { t: 'Replay rejected', view: 'attacks', n: () => `${lastAttack()} Its seq is not greater than last_seq.`,
      run: spot('#atk-stage-card') },
    { t: 'Wrong-key attack', view: 'attacks', n: 'The attacker forges a packet with a key of their own.',
      run: () => V.attacks.launch('wrongkey') },
    { t: 'Wrong key rejected', view: 'attacks', n: () => `${lastAttack()} Without the session key a valid tag cannot be produced.`,
      run: spot('#atk-stage-card') },
    { t: 'Run full test suite', view: 'attacks', n: 'tests/test_attacks.c — the 8 required tests — runs as its own process.',
      run: () => run('tests') },
    { t: () => (store.tests ? `${store.tests.passed} / ${store.tests.total} PASS` : 'Test results'), view: 'attacks',
      n: () => (store.tests ? `Required suite: ${store.tests.passed} passed, ${store.tests.failed} failed (exit code ${store.tests.code}).` : 'Suite did not run.'),
      run: spot('#atk-suite') },
    { t: 'Key wrapping', view: 'vault', n: () => `Correct passphrase: ${store.wrap.correct?.unwrapped ? 'unwrapped' : '—'}. Wrong passphrase: ${store.wrap.wrong && !store.wrap.wrong.secret_released ? 'MAC failed, secret not released' : '—'}.`,
      run: async () => { await engine('wrap', 'correct'); await sleep(1400); await engine('wrap', 'wrong'); await engine('vault'); await spot('#vk-wrap')(); } },
    { t: 'OpenSSL comparison', view: 'openssl', n: () => (store.openssl?.cbc ? `aes-256-cbc: "${store.openssl.cbc.tampered_block1}" decrypted with exit code ${store.openssl.cbc.openssl_exit}. AEAD: ${store.openssl.aead_tamper_rejected ? 'rejected' : '—'}.` : 'Comparison did not complete.'),
      run: async () => { await run('openssl'); await spot('#os-evidence')(); } },
    { t: 'Benchmark', view: 'bench', n: () => {
        const r = store.bench?.results?.find((x) => x.algorithm === 'ChaCha20-Poly1305' && x.size === 1024);
        return r ? `Measured now: ChaCha20-Poly1305 at 1 KiB ≈ ${r.mib_per_sec.toFixed(0)} MiB/s, ${r.latency_us.toFixed(2)} µs per packet.` : 'Benchmark did not complete.';
      },
      run: () => run('bench') },
    { t: 'Terminate session', view: 'overview', n: 'sodium_free() zeroes and releases every session key. State: TERMINATE.',
      run: () => engine('terminate') },
    { t: 'Secret-wipe events', view: 'logs', n: () => `${store.events.filter((e) => e.level === 'WIPE').length} WIPE events recorded by the engine during this demo.`,
      run: async () => { setLogFilter('WIPE'); ctx.navigate('logs'); } },
  ];

  const bar = $('#demo-bar');
  const btnStart = $('#demo-start'), btnPause = $('#demo-pause'), btnNext = $('#demo-next');
  const state = { idx: -1, auto: false, paused: false, busy: false, timer: null };

  function render(narration, running) {
    const s = steps[state.idx];
    bar.hidden = state.idx < 0;
    if (!s) return;
    $('#demo-num').textContent = state.idx + 1;
    $('#demo-total').textContent = steps.length;
    $('#demo-title').textContent = (typeof s.t === 'function' ? s.t() : s.t).toUpperCase();
    $('#demo-narration').textContent = running ? 'running…' : narration;
    $('#demo-progress').style.width = `${((state.idx + (running ? 0.5 : 1)) / steps.length) * 100}%`;
    btnPause.disabled = !state.auto;
    btnPause.textContent = state.paused ? '▶ RESUME' : '❚❚ PAUSE';
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
    render('', true);
    try { await s.run(); }
    catch (e) { addEvent('ERROR', `demo step failed: ${e.message}`, 'dashboard'); }
    state.busy = false;
    render(typeof s.n === 'function' ? s.n() : s.n, false);
    notify('demo');
    if (state.auto && !state.paused) state.timer = setTimeout(next, AUTO_DELAY);
  }

  function finish() {
    state.auto = false;
    btnStart.disabled = false;
    btnPause.disabled = true;
    $('#demo-title').textContent = 'DEMO COMPLETE';
    $('#demo-narration').textContent = 'All steps ran against the live implementation. Press START DEMO to run again, or explore any tab.';
    $('#demo-progress').style.width = '100%';
    state.idx = steps.length;
  }

  btnStart.addEventListener('click', () => {
    if (state.paused) { state.paused = false; render($('#demo-narration').textContent, false); next(); return; }
    if (state.idx >= steps.length) state.idx = -1;
    state.auto = true;
    state.paused = false;
    if (!state.busy) next();
  });
  btnPause.addEventListener('click', () => {
    if (!state.auto) return;
    state.paused = !state.paused;
    clearTimeout(state.timer);
    render($('#demo-narration').textContent, state.busy);
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
    bar.hidden = true;
    btnStart.disabled = false;
    btnPause.disabled = true;
    btnPause.textContent = '❚❚ PAUSE';
    resetCounters();
    setLogFilter('ALL');
    await engine('reset');
    ctx.navigate('overview');
  });

  return { steps, next };
}
