import { store, engine, run } from '../store.js';
import { esc, busy, emptyState, $ } from '../ui.js';

const STAGES = ['GENERATED', 'STORED', 'LOADED', 'USED', 'WIPED'];

function lifecycle(states) {
  // states: array of 5 values: true (reached), false (not yet), 'na'
  const lastOn = states.lastIndexOf(true);
  return `<div class="life">${STAGES.map((s, i) => {
    const v = states[i];
    const cls = v === 'na' ? 'na' : v ? (i === lastOn ? 'cur' : 'on') : '';
    return `<div class="${cls}" title="${v === 'na' ? 'not applicable' : ''}">${s}</div>`;
  }).join('')}</div>`;
}

function protectionBadge(f) {
  if (!f.exists) return '<span class="badge b-muted">NOT PRESENT</span>';
  if (f.kind.endsWith('public')) return f.mode_ok ? `<span class="badge b-info">${f.mode} PUBLIC</span>` : `<span class="badge b-bad">${f.mode} (expected ${f.expected_mode})</span>`;
  return f.mode_ok ? `<span class="badge b-ok">${f.mode} PROTECTED</span>` : `<span class="badge b-bad">${f.mode} — EXPECTED ${f.expected_mode}</span>`;
}

function fileCard(title, subtitle, priv, pub, usedFlag) {
  if (!priv) return '';
  const states = [priv.exists, priv.exists && priv.mode_ok, priv.loaded && priv.pair_ok !== false, !!usedFlag, priv.loaded];
  return `<section class="card vk">
    <div class="vk-head"><div><h4>${title}</h4><p>${subtitle}</p></div>${protectionBadge(priv)}</div>
    <div class="vk-meta">
      <span>ALGORITHM</span><div>${esc(priv.algorithm)}</div>
      <span>PRIVATE FILE</span><div class="mono">${esc(priv.path)} · ${priv.expected_size} B</div>
      ${pub ? `<span>PUBLIC FILE</span><div class="mono">${esc(pub.path)} · ${pub.expected_size} B ${protectionBadge(pub)}</div>` : ''}
      <span>FINGERPRINT</span><div class="fp">${esc(priv.fingerprint || '—')}</div>
      ${priv.pair_ok !== undefined ? `<span>KEY PAIR</span><div>${priv.pair_ok ? '<span class="ok">✓ private key matches public file</span>' : '<span class="bad">✕ mismatch</span>'}</div>` : ''}
    </div>
    ${lifecycle(states)}
    <div class="small faint">Fingerprint of the matching public key — the secret bytes never leave the engine, and are wiped after each scan.</div>
  </section>`;
}

function sessionCard(title, dirLabel, fpA, fpB) {
  const s = store.session;
  const has = !!s.key_fingerprints;
  const used = store.packets.some((p) => p.verdict === 'ACCEPTED');
  const wiped = s.state === 'TERMINATE';
  const everHad = has || wiped;
  const states = [everHad, has ? true : wiped ? true : false, 'na', everHad && used, wiped || s.epoch > 1];
  return `<section class="card vk">
    <div class="vk-head"><div><h4>${title}</h4><p>${dirLabel}</p></div>
      ${has ? '<span class="badge b-cyan">IN sodium_malloc MEMORY</span>' : wiped ? '<span class="badge b-muted">WIPED</span>' : '<span class="badge b-muted">NO SESSION</span>'}</div>
    <div class="vk-meta">
      <span>ALGORITHM</span><div>X25519 → BLAKE2b (crypto_kx) · 32 B</div>
      <span>STORAGE</span><div>never written to disk · guard pages · mlock</div>
      <span>FINGERPRINT</span><div class="fp">${has ? `${esc(fpA)} <span class="faint">=</span> ${esc(fpB)}` : '—'}</div>
      <span>EPOCH</span><div class="mono">${has ? s.epoch : '—'}</div>
    </div>
    ${lifecycle(states)}
    <div class="small faint">STORED = held in protected memory · WIPED = zeroed by sodium_free() on TERMINATE or overwritten by re-key.</div>
  </section>`;
}

function wrappedCard(w) {
  if (!w) return '';
  const lastWrap = store.wrap.correct || store.wrap.wrong;
  const states = [w.exists, w.exists && w.mode_ok, w.loaded, !!store.wrap.correct?.unwrapped, !!lastWrap];
  return `<section class="card vk">
    <div class="vk-head"><div><h4>WRAPPED PRIVATE KEY</h4><p>Ed25519 secret encrypted at rest</p></div>${protectionBadge(w)}</div>
    <div class="vk-meta">
      <span>ALGORITHM</span><div>${esc(w.algorithm)}</div>
      <span>FILE</span><div class="mono">${esc(w.path)} · ${w.expected_size} B</div>
      <span>LAYOUT</span><div class="mono">salt 16 | nonce 24 | MAC 16 + ct 64</div>
      <span>FINGERPRINT</span><div class="fp">${esc(w.fingerprint || '—')} <span class="faint small">(of the ciphertext)</span></div>
    </div>
    ${lifecycle(states)}
    <div class="small faint">${w.exists ? 'USED = unwrapped with the correct passphrase · WIPED = plaintext key zeroed after use.' : 'Run the wrapping lab below to create it.'}</div>
  </section>`;
}

function wrapLab() {
  const last = store.wrap.last ? store.wrap[store.wrap.last] : null;
  const ok = last && last.pass;
  const good = store.wrap.last === 'correct';
  const lit = last ? ['lit', 'lit', 'lit', 'lit', good ? 'lit' : 'fail', good ? 'lit' : 'fail'] : ['', '', '', '', '', ''];
  const steps = [
    ['PASSWORD', last ? (good ? 'correct (test-only)' : 'wrong (test-only)') : 'never displayed'],
    ['ARGON2ID', last ? `${last.memlimit_mib} MiB · ops ${last.opslimit}` : 'memory-hard KDF'],
    ['SALT', last ? `${last.salt_hex.slice(0, 12)}…` : '16 random bytes'],
    ['DERIVED KEY', '32 B · not shown'],
    ['SECRETBOX', 'XSalsa20-Poly1305'],
    ['WRAPPED KEY', last ? `${last.file_size} B · ${last.file_mode}` : '120 bytes'],
  ];
  return `
    <div class="wrapflow">${steps.map(([b, s], i) => `<div class="wf ${lit[i]}"><b>${b}</b><small>${esc(s)}</small></div>`).join('')}</div>
    <div class="row"><button class="btn btn-ok" data-a="wrap-correct">[ CORRECT PASSWORD ]</button><button class="btn btn-danger" data-a="wrap-wrong">[ WRONG PASSWORD ]</button>
      <span class="small muted">Both buttons use test-only passphrases held inside the C engine; they are never sent to the browser.</span></div>
    ${last ? `<div class="hr"></div>
      <div class="grid">
        <div class="s6">${good
          ? `<div class="big-verdict ${ok ? 'ok' : 'bad'}">${ok ? '✓ UNWRAP SUCCESSFUL' : '✕ UNEXPECTED FAILURE'}</div><div class="small muted">MAC verified · recovered key matches the original (compared in C, not displayed)</div>`
          : `<div class="big-verdict ${ok ? 'bad' : 'warn'}">✕ AUTHENTICATION FAILED</div><div class="big-verdict ${ok ? 'ok' : 'bad'}" style="font-size:15px;margin-top:6px">${ok ? '✓ SECRET NOT RELEASED' : '✕ OUTPUT NOT ZEROED'}</div><div class="small muted">wrong passphrase → wrong key → Poly1305 MAC mismatch · output buffer zeroed: ${last.output_zeroed ? 'yes' : 'no'}</div>`}
        </div>
        <div class="s6"><div class="kv">
          <div>KDF</div><div>${esc(last.kdf)} · ${last.memlimit_mib} MiB · opslimit ${last.opslimit}</div>
          <div>ARGON2ID TIME</div><div class="mono">${last.wrap_ms.toFixed(0)} ms wrap · ${last.unwrap_ms.toFixed(0)} ms unwrap</div>
          <div>SALT</div><div class="mono small">${esc(last.salt_hex)}</div>
          <div>NONCE</div><div class="mono small">${esc(last.nonce_hex)}</div>
          <div>FILE</div><div class="mono">keys/server_sk.wrapped · ${last.file_size} B · ${last.file_mode}</div>
        </div></div>
      </div>` : ''}`;
}

export default {
  id: 'vault',
  label: 'Key Vault',
  mount(root) {
    root.innerHTML = `
      <div class="page-head">
        <div><h1>KEY VAULT</h1><p>Lifecycle and protection of every key. Only fingerprints, lengths, algorithms and file metadata are shown — raw key material never leaves the C engine.</p></div>
        <div class="actions"><button class="btn btn-primary" data-a="keygen">GENERATE KEYS (./keygen)</button><button class="btn" data-a="scan">RESCAN</button></div>
      </div>
      <div class="vault" id="vk-grid"></div>
      <section class="card" style="margin-top:16px"><div class="card-head"><div><div class="card-title">PASSWORD / KEY WRAPPING LAB (TASK 5)</div><div class="card-sub">Argon2id derives a key from passphrase + salt; crypto_secretbox encrypts the Ed25519 secret key</div></div></div><div id="vk-wrap"></div></section>
      <section class="card" style="margin-top:16px"><div class="card-head"><div class="card-title">LAST ./keygen RUN</div><span id="vk-kg-status"></span></div><div id="vk-keygen"></div></section>`;
    root.addEventListener('click', (e) => {
      const b = e.target.closest('button[data-a]');
      if (!b) return;
      const a = b.dataset.a;
      if (a === 'keygen') busy(b, async () => { await run('keygen'); await engine('vault'); });
      if (a === 'scan') busy(b, () => engine('vault'));
      if (a === 'wrap-correct') busy(b, async () => { await this.ensureKeys(); await engine('wrap', 'correct'); await engine('vault'); });
      if (a === 'wrap-wrong') busy(b, async () => { await this.ensureKeys(); await engine('wrap', 'wrong'); await engine('vault'); });
    });
    if (!store.vault) engine('vault');
    this.update();
  },
  async ensureKeys() {
    if (!store.vault?.files?.[1]?.exists) { await run('keygen'); await engine('vault'); }
  },
  update() {
    const v = store.vault;
    const f = (p) => v?.files?.find((x) => x.path === p);
    const fp = store.session.key_fingerprints;
    $('#vk-grid').innerHTML = !v ? emptyState('Scanning key files…')
      : fileCard('IDENTITY KEY', 'Ed25519 long-term signing key', f('keys/server_sk.bin'), f('keys/server_pk.bin'), store.session.authenticated || store.wrap.correct || store.mitm?.signed?.task1_identity)
        + fileCard('KEY EXCHANGE', 'X25519 static key pair (Task 1)', f('keys/server_kx_sk.bin'), f('keys/server_kx_pk.bin'), false)
        + sessionCard('SESSION TX KEY', 'client → server direction', fp?.client_tx, fp?.server_rx)
        + sessionCard('SESSION RX KEY', 'server → client direction', fp?.client_rx, fp?.server_tx)
        + wrappedCard(f('keys/server_sk.wrapped'));
    $('#vk-wrap').innerHTML = wrapLab();
    const kg = store.keygen;
    $('#vk-kg-status').innerHTML = kg ? `<span class="badge ${kg.ok ? 'b-ok' : 'b-bad'}">exit code ${kg.code}</span>` : '';
    $('#vk-keygen').innerHTML = kg ? `<pre class="log">${esc(kg.output)}\n$ ls -l keys/\n${esc(kg.listing)}</pre>` : '<div class="small muted">Not run from the dashboard yet. The vault above reflects whatever is currently in keys/.</div>';
  },
};
