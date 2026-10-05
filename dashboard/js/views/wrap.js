import { store, engine, run } from '../store.js';
import { esc, busy, chip, emptyState, pageHead, panelHead, whyThisMatters, $ } from '../ui.js';

function chain() {
  const last = store.wrap.last ? store.wrap[store.wrap.last] : null;
  const good = store.wrap.last === 'correct';
  // A wrong passphrase fails at the MAC check; the stored file itself is untouched.
  const lit = last ? ['lit', 'lit', 'lit', good ? 'lit' : 'fail', good ? 'lit' : ''] : ['', '', '', '', ''];
  const links = [
    ['01', 'Passphrase', last ? `${good ? 'correct' : 'wrong'} · test-only · never displayed` : 'never displayed'],
    ['02', 'Argon2id', last ? `${last.memlimit_mib} MiB · opslimit ${last.opslimit} · ${last.wrap_ms.toFixed(0)} ms` : 'memory-hard KDF · random salt'],
    ['03', '32-byte wrapping key', 'derived in C · not shown'],
    ['04', 'Secretbox', last ? (good ? 'XSalsa20-Poly1305 · MAC verified' : 'XSalsa20-Poly1305 · MAC failed') : 'XSalsa20-Poly1305'],
    ['05', 'Wrapped private key', last ? `${last.file_size} B · mode ${last.file_mode}${good ? ' · unwrapped' : ' · secret not released'}` : '120 bytes on disk'],
  ];
  return `<div class="chain" aria-label="Key wrapping chain">${links.map(([n, b, s], i) => `<div class="link ${lit[i]}"><span class="n">${n}</span><b>${b}</b><small>${esc(s)}</small></div>`).join('')}</div>`;
}

function outcomes() {
  const c = store.wrap.correct;
  const w = store.wrap.wrong;
  const correct = !c ? `<div class="outcome"><span class="eyebrow">Correct passphrase</span><div class="statement faint">○ NOT RUN</div><div class="faint small">Unwrap with the test-only correct passphrase.</div></div>`
    : `<div class="outcome ${c.pass ? 'ok' : 'bad'}"><span class="eyebrow">Correct passphrase</span>
        <div class="statement ${c.pass ? 'ok' : 'bad'}">${c.pass ? '✓ ACCEPTED' : '✕ UNEXPECTED FAILURE'}</div>
        <div class="faint small">MAC verified · recovered key matches the original (compared in C, not displayed) · unwrap ${c.unwrap_ms.toFixed(0)} ms</div></div>`;
  const wrong = !w ? `<div class="outcome"><span class="eyebrow">Wrong passphrase</span><div class="statement faint">○ NOT RUN</div><div class="faint small">Attempt an unwrap with a test-only wrong passphrase.</div></div>`
    : `<div class="outcome ${w.pass ? 'ok' : 'bad'}"><span class="eyebrow">Wrong passphrase</span>
        <div class="statement ${w.pass ? 'ok' : 'bad'}">${w.pass ? '✓ REJECTED' : '✕ SECRET RELEASED'}</div>
        <div class="faint small">Wrong key → Poly1305 MAC mismatch · secret released: ${w.secret_released ? 'yes' : 'no'} · output buffer zeroed: ${w.output_zeroed ? 'yes' : 'no'}</div></div>`;
  return `<div class="outcomes">${correct}${wrong}</div>`;
}

function params() {
  const last = store.wrap.last ? store.wrap[store.wrap.last] : null;
  if (!last) return emptyState('Run either check to see the real parameters reported by the engine: salt, nonce, KDF limits and timings.');
  return `<div class="kv">
    <div>Salt</div><div><span class="mono small">${esc(last.salt_hex)}</span> <span class="faint small">· 16 bytes</span></div>
    <div>Nonce</div><div><span class="mono small">${esc(last.nonce_hex)}</span> <span class="faint small">· 24 bytes</span></div>
    <div>Ciphertext</div><div>${chip('PROTECTED', { glyph: '✓' })} <span class="redacted">REDACTED</span></div>
    <div>Authentication</div><div>${chip('ENABLED', { text: 'Enabled · Poly1305 MAC' })}</div>
    <div>KDF</div><div>${esc(last.kdf)} · ${last.memlimit_mib} MiB · opslimit ${last.opslimit}</div>
    <div>Timing</div><div class="mono">${last.wrap_ms.toFixed(0)} ms wrap · ${last.unwrap_ms.toFixed(0)} ms unwrap</div>
    <div>File</div><div class="mono">keys/server_sk.wrapped · ${last.file_size} B · ${esc(last.file_mode)}</div>
  </div>`;
}

export default {
  id: 'wrap',
  label: 'Key Wrapping',
  icon: 'wrap',
  mount(root) {
    root.innerHTML = `
      ${pageHead('Task 5 · Key protection', 'Key wrapping', 'Argon2id derives a key from a passphrase and a random salt; <code>crypto_secretbox</code> encrypts the Ed25519 secret key at rest. Both checks use test-only passphrases held inside the C engine — they are never sent to the browser.',
        '<button class="btn btn-ok" data-a="wrap-correct">Correct passphrase</button><button class="btn btn-danger" data-a="wrap-wrong">Wrong passphrase</button>')}
      <section class="panel elevated" id="vk-wrap">${panelHead('Algorithm chain', 'passphrase → Argon2id → 32-byte key → secretbox → wrapped key')}<div id="wr-chain"></div></section>
      <div class="section" id="wr-outcomes"></div>
      <section class="panel section">${panelHead('Wrapped key parameters', 'Reported by sc_engine for the most recent check')}<div id="wr-params"></div></section>
      <section class="panel section">${whyThisMatters('keywrap')}</section>`;
    root.addEventListener('click', (e) => {
      const b = e.target.closest('button[data-a]');
      if (!b) return;
      const which = b.dataset.a === 'wrap-correct' ? 'correct' : b.dataset.a === 'wrap-wrong' ? 'wrong' : null;
      if (which) busy(b, async () => { await this.ensureKeys(); await engine('wrap', which); await engine('vault'); });
    });
    this.update();
  },
  async ensureKeys() {
    if (!store.vault?.files?.[1]?.exists) { await run('keygen'); await engine('vault'); }
  },
  update() {
    $('#wr-chain').innerHTML = chain();
    $('#wr-outcomes').innerHTML = outcomes();
    $('#wr-params').innerHTML = params();
  },
};
