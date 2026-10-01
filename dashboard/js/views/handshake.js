import { store, engine, run } from '../store.js';
import { esc, busy, shortHex, chip, emptyState, errorState, pageHead, panelHead, $, $$ } from '../ui.js';

let mode = 'plain';

function rows(hs) {
  const signed = hs?.mode === 'signed';
  return [
    ['local', 'Ephemeral key pairs', 'client and server each run crypto_kx_keypair()', hs ? `client ${shortHex(hs.client_pk, 4)} · server ${shortHex(hs.server_pk, 4)}` : ''],
    ['right', 'client_pk · X25519 · 32 B', hs ? `fingerprint ${hs.client_pk_fp}` : 'public key — safe to send', ''],
    ['left', signed ? 'server_pk + Ed25519 signature' : 'server_pk · X25519 · 32 B', hs ? `fingerprint ${hs.server_pk_fp}${signed ? ' · signature over transcript' : ''}` : 'public key — safe to send', ''],
    ...(signed ? [['local', 'Client verifies signature', 'crypto_sign_verify_detached() with pinned server_pk.bin', hs.signature === 1 ? '✓ signature valid' : '✕ signature invalid']] : []),
    ['local', 'Session derivation · crypto_kx', 'BLAKE2b-512( X25519(sk, peer_pk) ‖ client_pk ‖ server_pk )', hs ? '64 bytes → split into rx / tx' : ''],
    ['local', 'SECURE', 'ephemeral secret keys wiped · AEAD active', hs?.ok ? `${Math.max(0, hs.elapsed_ms).toFixed(2)} ms total` : ''],
  ];
}

function diagram(hs) {
  const on = !!hs?.ok;
  return `<div class="proto" role="img" aria-label="Handshake message flow between client and server">
    <div class="col"><div class="party"><b>CLIENT</b><small>initiator · X25519</small></div><div class="lifeline"></div></div>
    <div class="mid">${rows(hs).map(([dir, lbl, sub, box]) => `
      <div class="msg-row ${dir}${on ? ' on' : ''}">
        <div class="lbl">${esc(lbl)}</div>
        <div class="arr"></div>
        <div class="sub">${esc(sub)}</div>
        ${box ? `<div class="box">${esc(box)}</div>` : ''}
      </div>`).join('')}</div>
    <div class="col"><div class="party"><b>SERVER</b><small>${hs?.mode === 'signed' ? 'Ed25519 identity · X25519' : 'responder · X25519'}</small></div><div class="lifeline"></div></div>
  </div>`;
}

function derivation() {
  const fp = store.session.key_fingerprints;
  const hs = store.handshake;
  if (!fp) return emptyState('Run the handshake to derive the directional session keys. Raw keys never leave the C engine; only one-way fingerprints are shown.');
  const yes = (ok, label) => chip(ok ? 'YES' : 'NO', { tone: ok ? 'ok' : 'bad', glyph: ok ? '✓' : '✕', text: label || (ok ? 'YES' : 'NO') });
  return `<div class="derive">
      <div class="drow">
        <div class="keybox"><small>Client TX</small><span class="fp">${esc(fp.client_tx)}</span></div>
        <div class="dlink r"><span>client → server</span></div>
        <div class="keybox"><small>Server RX</small><span class="fp">${esc(fp.server_rx)}</span></div>
      </div>
      <div class="drow">
        <div class="keybox"><small>Client RX</small><span class="fp">${esc(fp.client_rx)}</span></div>
        <div class="dlink l"><span>server → client</span></div>
        <div class="keybox"><small>Server TX</small><span class="fp">${esc(fp.server_tx)}</span></div>
      </div>
    </div>
    <div class="checks">
      <div class="check"><div>client_tx == server_rx<small>checked in C with sodium_memcmp${hs?.complementary !== undefined ? '' : ' — not reported'}</small></div>${yes(fp.client_tx === fp.server_rx && hs?.complementary !== false)}</div>
      <div class="check"><div>client_rx == server_tx<small>the other direction pairs the same way</small></div>${yes(fp.client_rx === fp.server_tx)}</div>
      <div class="check"><div>client_tx != client_rx<small>directional keys stop reflection attacks</small></div>${yes(fp.client_tx !== fp.client_rx && hs?.directional !== false)}</div>
    </div>
    <p class="note">Fingerprints are BLAKE2b(key) under a fixed domain key, truncated to 8 bytes: equal keys give equal fingerprints, but a fingerprint cannot be turned back into the key. Epoch ${store.session.epoch || '—'}.</p>`;
}

function mitm() {
  const m = store.mitm;
  if (!m) return emptyState('Runs the same man-in-the-middle scenario as <code>./mitm_demo</code> inside the engine: first against plain crypto_kx, then against the signed handshake.', '<button class="btn" data-a="mitm">Run MITM scenario</button>');
  const row = (hit, text, good) => `<div class="match"><span class="g ${hit ? (good ? 'ok' : 'warn') : 'faint'}" aria-hidden="true">${hit ? (good ? '✓' : '!') : '·'}</span><span>${text}</span></div>`;
  return `<div class="split">
      <div class="tile"><div class="panel-title" style="margin-bottom:8px">Plain crypto_kx · as in the brief</div>
        ${row(m.plain.mallory_read, `Mallory decrypted client traffic: <code>${esc(m.plain.read_text)}</code>`, false)}
        ${row(m.plain.mallory_forged, `Server accepted Mallory&rsquo;s rewrite: <code>${esc(m.plain.forged_text)}</code>`, false)}
        <div style="margin-top:12px">${m.vulnerability_shown ? chip('LIMITATION', { text: 'Known limitation demonstrated' }) : chip('UNEXPECTED')}</div>
      </div>
      <div class="tile"><div class="panel-title" style="margin-bottom:8px">Authenticated handshake · extension</div>
        ${row(m.signed.honest_ok, 'Honest run: signature verifies, message delivered', true)}
        ${row(m.signed.blocked_key_swap, 'Key swapped, real signature forwarded → <b>handshake blocked</b>', true)}
        ${row(m.signed.blocked_own_signature, 'Mallory signs with her own key → <b>handshake blocked</b>', true)}
        ${row(m.signed.blocked_replayed_signature, 'Signature replayed into another session → <b>handshake blocked</b>', true)}
        <div class="actions" style="margin-top:12px">${m.extension_blocks_mitm ? chip('BLOCKED', { text: 'All MITM variants blocked' }) : chip('UNEXPECTED')}
          <span class="faint small">${m.signed.task1_identity ? 'using Task 1 identity keys' : 'in-memory identity (no Task 1 keys)'}</span></div>
      </div>
    </div>
    <div class="actions" style="margin-top:16px"><button class="btn btn-sm btn-ghost" data-a="mitm">Re-run scenario</button></div>`;
}

export default {
  id: 'handshake',
  label: 'Handshake',
  icon: 'handshake',
  mount(root) {
    root.innerHTML = `
      ${pageHead('Task 2 · Key exchange', 'Handshake protocol', 'X25519 key exchange with <code>crypto_kx</code>. The brief&rsquo;s handshake is unauthenticated; the Ed25519-signed version is a clearly separated extension.',
        `<div class="seg" id="hs-mode" role="group" aria-label="Handshake mode"><button data-m="plain" aria-pressed="${mode === 'plain'}">Plain crypto_kx</button><button data-m="signed" aria-pressed="${mode === 'signed'}">Signed extension</button></div>
         <button class="btn btn-primary" data-a="run">Run handshake</button>`)}
      <div class="grid">
        <section class="panel s7">${panelHead('Message flow', 'Only public keys cross the network', '<span id="hs-status"></span>')}<div id="hs-diagram"></div></section>
        <section class="panel elevated s5" id="hs-keys-card">${panelHead('Session derivation', 'Directional keys · fingerprints only')}<div id="hs-keys"></div></section>
        <section class="panel s12">${panelHead('How it works')}
          <div class="explain">
            <div class="ex"><h5>X25519</h5><p>Elliptic-curve Diffie–Hellman on Curve25519. Each side combines its own secret key with the other side&rsquo;s public key; both arrive at the same 32-byte shared secret without it crossing the network.</p></div>
            <div class="ex"><h5>KEY DERIVATION</h5><p>The raw X25519 output is a curve point, not a uniform key. <code>crypto_kx</code> hashes it with BLAKE2b together with both public keys, binding the keys to this exact pair of participants.</p></div>
            <div class="ex"><h5>DIRECTIONAL KEYS</h5><p>The 64-byte hash is split into two 32-byte keys, one per direction. Client and server take the halves in opposite order, so client_tx is exactly server_rx.</p></div>
            <div class="ex"><h5>WHY TX ≠ RX</h5><p>If both directions shared one key, an attacker could bounce a client&rsquo;s packet straight back to it. Separate keys make reflection fail authentication.</p></div>
          </div>
        </section>
        <section class="panel s12" id="hs-mitm-card">${panelHead('Man-in-the-middle · authenticated handshake extension', 'Plain crypto_kx has no peer authentication. The extension signs server_eph ‖ client_eph with the long-term Ed25519 key.')}<div id="hs-mitm"></div></section>
      </div>`;
    $('#hs-mode', root).addEventListener('click', (e) => {
      const b = e.target.closest('button[data-m]');
      if (!b) return;
      mode = b.dataset.m;
      $$('#hs-mode button', root).forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
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
    return engine('handshake', m);
  },
  update() {
    const hs = store.handshake && store.handshake.cmd === 'handshake' ? store.handshake : null;
    $('#hs-diagram').innerHTML = diagram(hs);
    $('#hs-status').innerHTML = !hs ? chip('NOT RUN')
      : hs.ok ? chip('SECURE', { text: `Established · ${hs.mode === 'signed' ? 'signed' : 'plain'}` })
        : chip('FAILED', { text: hs.error || 'Failed' });
    $('#hs-keys').innerHTML = hs && !hs.ok
      ? errorState('HANDSHAKE FAILED', [hs.error || 'The engine rejected the handshake.', 'No session keys were derived.'])
      : derivation();
    $('#hs-mitm').innerHTML = mitm();
  },
};
