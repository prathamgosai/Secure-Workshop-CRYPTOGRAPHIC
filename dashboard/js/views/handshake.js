import { store, engine, run } from '../store.js';
import { esc, busy, shortHex, $, $$, emptyState } from '../ui.js';

let mode = 'plain';

function rows(hs) {
  const signed = hs?.mode === 'signed';
  return [
    ['local', 'Ephemeral key pairs', 'client and server each run crypto_kx_keypair()', `client ${shortHex(hs?.client_pk, 4)} · server ${shortHex(hs?.server_pk, 4)}`],
    ['right', 'client_pk (X25519, 32 B)', hs ? `fingerprint ${hs.client_pk_fp}` : 'public key — safe to send', ''],
    ['left', signed ? 'server_pk + Ed25519 signature' : 'server_pk (X25519, 32 B)', hs ? `fingerprint ${hs.server_pk_fp}${signed ? ' · sig over transcript' : ''}` : 'public key — safe to send', ''],
    ...(signed ? [['local', 'Client verifies signature', 'crypto_sign_verify_detached() with pinned server_pk.bin', hs.signature === 1 ? '✓ signature valid' : '✕ signature invalid']] : []),
    ['local', 'crypto_kx', 'BLAKE2b-512( X25519(sk, peer_pk) ‖ client_pk ‖ server_pk )', '64 bytes → split'],
    ['local', 'RX / TX key split', 'client takes (rx, tx); server takes them in the opposite order', hs?.complementary ? '✓ complementary · ✓ directional' : ''],
    ['local', 'SECURE', 'ephemeral secret keys wiped · AEAD active', hs?.ok ? `${Math.max(0, hs.elapsed_ms).toFixed(2)} ms total` : ''],
  ];
}

function diagram(hs) {
  return `<div class="seqd">
    <div class="col"><div class="who"><b>CLIENT</b><div class="small muted">initiator</div></div><div class="life"></div></div>
    <div class="mid" id="hs-rows">${rows(hs).map(([dir, lbl, sub, box], i) => `
      <div class="msg-row ${dir}" data-i="${i}">
        <div class="lbl">${esc(lbl)}</div>
        <div class="arr"></div>
        <div class="sub">${esc(sub)}</div>
        ${box ? `<div class="box">${esc(box)}</div>` : ''}
      </div>`).join('')}</div>
    <div class="col"><div class="who"><b>SERVER</b><div class="small muted">${hs?.mode === 'signed' ? 'Ed25519 identity' : 'responder'}</div></div><div class="life"></div></div>
  </div>`;
}

function keys() {
  const fp = store.session.key_fingerprints;
  const hs = store.handshake;
  if (!fp) return emptyState('No session keys yet. Run the handshake to derive them.');
  return `<div class="split">
      <div class="keybox"><small>CLIENT TX</small><span class="fp">${esc(fp.client_tx)}</span></div>
      <div class="keybox"><small>SERVER RX</small><span class="fp">${esc(fp.server_rx)}</span></div>
      <div class="keybox"><small>CLIENT RX</small><span class="fp">${esc(fp.client_rx)}</span></div>
      <div class="keybox"><small>SERVER TX</small><span class="fp">${esc(fp.server_tx)}</span></div>
    </div>
    <div class="hr"></div>
    <div class="match">${fp.client_tx === fp.server_rx ? '<span class="ok">✓</span>' : '<span class="bad">✕</span>'} client_tx == server_rx <span class="faint">(checked in C with sodium_memcmp: ${hs?.complementary ? 'equal' : '—'})</span></div>
    <div class="match">${fp.client_rx === fp.server_tx ? '<span class="ok">✓</span>' : '<span class="bad">✕</span>'} client_rx == server_tx</div>
    <div class="match">${fp.client_tx !== fp.client_rx ? '<span class="ok">✓</span>' : '<span class="bad">✕</span>'} client_tx ≠ client_rx <span class="faint">(directional: ${hs?.directional ? 'yes' : '—'})</span></div>
    <p class="note">Fingerprints are BLAKE2b(key) with a fixed domain key, truncated to 8 bytes: equal keys give equal fingerprints, but a fingerprint cannot be turned back into the key. Raw key bytes never leave the C engine. Epoch ${store.session.epoch || '—'}.</p>`;
}

function mitm() {
  const m = store.mitm;
  if (!m) return emptyState('Runs the same MITM scenario as <code>./mitm_demo</code> inside the engine.', '<button class="btn" data-a="mitm">RUN MITM SCENARIO</button>');
  const row = (ok, text, good) => `<div class="match"><span class="${ok ? (good ? 'ok' : 'bad') : 'muted'}">${ok ? (good ? '✓' : '⚠') : '·'}</span> ${text}</div>`;
  return `<div class="split">
      <div class="keybox"><small>PLAIN crypto_kx (AS IN THE BRIEF)</small>
        ${row(m.plain.mallory_read, `Mallory decrypted client traffic: <code>${esc(m.plain.read_text)}</code>`, false)}
        ${row(m.plain.mallory_forged, `Server accepted Mallory's rewrite: <code>${esc(m.plain.forged_text)}</code>`, false)}
        <div style="margin-top:8px">${m.vulnerability_shown ? '<span class="badge b-warn">KNOWN LIMITATION DEMONSTRATED</span>' : '<span class="badge b-bad">UNEXPECTED</span>'}</div>
      </div>
      <div class="keybox"><small>AUTHENTICATED HANDSHAKE EXTENSION</small>
        ${row(m.signed.honest_ok, 'Honest run: signature verifies, message delivered', true)}
        ${row(m.signed.blocked_key_swap, 'Key swapped, real signature forwarded → <b>HANDSHAKE BLOCKED</b>', true)}
        ${row(m.signed.blocked_own_signature, 'Mallory signs with her own key → <b>HANDSHAKE BLOCKED</b>', true)}
        ${row(m.signed.blocked_replayed_signature, 'Signature replayed into another session → <b>HANDSHAKE BLOCKED</b>', true)}
        <div style="margin-top:8px">${m.extension_blocks_mitm ? '<span class="badge b-ok">ALL MITM VARIANTS BLOCKED</span>' : '<span class="badge b-bad">UNEXPECTED</span>'}
        <span class="faint small">${m.signed.task1_identity ? 'using Task 1 identity keys' : 'in-memory identity (no Task 1 keys)'}</span></div>
      </div>
    </div>
    <div class="actions" style="margin-top:12px"><button class="btn btn-sm" data-a="mitm">RE-RUN</button></div>`;
}

export default {
  id: 'handshake',
  label: 'Handshake',
  mount(root) {
    root.innerHTML = `
      <div class="page-head">
        <div><h1>HANDSHAKE LAB</h1><p>X25519 key exchange with <code>crypto_kx</code>. The brief's handshake is unauthenticated; the Ed25519-signed version is a clearly separated extension.</p></div>
        <div class="actions">
          <div class="seg" id="hs-mode"><button data-m="plain" class="on">PLAIN crypto_kx</button><button data-m="signed">SIGNED EXTENSION</button></div>
          <button class="btn btn-primary" data-a="run">RUN HANDSHAKE</button>
        </div>
      </div>
      <div class="grid">
        <section class="card s7"><div class="card-head"><div class="card-title">MESSAGE FLOW</div><span id="hs-status"></span></div><div id="hs-diagram"></div></section>
        <section class="card s5"><div class="card-head"><div class="card-title">SESSION KEY FINGERPRINTS</div></div><div id="hs-keys"></div></section>
        <section class="card s12"><div class="card-head"><div class="card-title">HOW IT WORKS</div></div>
          <div class="explain">
            <div class="ex"><h5>X25519</h5><p>Elliptic-curve Diffie–Hellman on Curve25519. Each side combines its own secret key with the other side's public key and both arrive at the same 32-byte shared secret — without it ever crossing the network.</p></div>
            <div class="ex"><h5>SHARED-SECRET DERIVATION</h5><p>The raw X25519 output is a curve point, not a uniform key. <code>crypto_kx</code> hashes it with BLAKE2b together with both public keys, binding the keys to this exact pair of participants.</p></div>
            <div class="ex"><h5>DIRECTIONAL TX / RX KEYS</h5><p>The 64-byte hash is split into two 32-byte keys, one per direction. A packet the client sends can never be reflected back and accepted by the client.</p></div>
            <div class="ex"><h5>WHY client_tx = server_rx</h5><p>Client and server take the two halves in opposite order, so the key the client transmits with is exactly the key the server receives with.</p></div>
            <div class="ex"><h5>WHY client_tx ≠ client_rx</h5><p>If both directions shared one key, an attacker could bounce a client's packet straight back to it. Separate keys make reflection fail authentication.</p></div>
          </div>
        </section>
        <section class="card s12" id="hs-mitm-card"><div class="card-head"><div><div class="card-title">AUTHENTICATED HANDSHAKE EXTENSION — MITM</div><div class="card-sub">Plain crypto_kx has no authentication. The extension signs server_eph ‖ client_eph with the long-term Ed25519 key.</div></div></div><div id="hs-mitm"></div></section>
      </div>`;
    $('#hs-mode', root).addEventListener('click', (e) => {
      const b = e.target.closest('button[data-m]');
      if (!b) return;
      mode = b.dataset.m;
      $$('#hs-mode button', root).forEach((x) => x.classList.toggle('on', x === b));
    });
    root.addEventListener('click', (e) => {
      const b = e.target.closest('button[data-a]');
      if (!b) return;
      if (b.dataset.a === 'run') busy(b, () => this.run(mode));
      if (b.dataset.a === 'mitm') busy(b, () => engine('mitm'));
    });
    this.update();
  },
  async run(m = 'plain') {
    if (m === 'signed' && !store.vault?.files?.[1]?.exists) {
      const v = await engine('vault');
      if (!v.files?.[1]?.exists) await run('keygen');
    }
    const r = await engine('handshake', m);
    this.animate();
    return r;
  },
  animate() {
    const rowsEl = $$('#hs-rows .msg-row');
    rowsEl.forEach((r) => r.classList.remove('on'));
    rowsEl.forEach((r, i) => setTimeout(() => r.classList.add('on'), 180 + i * 330));
  },
  update(topic) {
    const hs = store.handshake;
    $('#hs-diagram').innerHTML = diagram(hs && hs.cmd === 'handshake' ? hs : null);
    if (hs && hs.cmd === 'handshake' && topic !== 'handshake') $$('#hs-rows .msg-row').forEach((r) => r.classList.add('on'));
    $('#hs-status').innerHTML = !hs ? '<span class="badge b-muted">NOT RUN</span>'
      : hs.ok ? `<span class="badge b-ok">✓ SESSION ESTABLISHED · ${hs.mode === 'signed' ? 'SIGNED' : 'PLAIN'}</span>`
        : `<span class="badge b-bad">✕ ${esc(hs.error || 'FAILED')}</span>`;
    $('#hs-keys').innerHTML = keys();
    $('#hs-mitm').innerHTML = mitm();
  },
};
