import { store, run } from '../store.js';
import { esc, busy, emptyState, $ } from '../ui.js';

const ROWS = [
  ['KEY FORMAT', 'Raw bytes: 32 B public, 64 B Ed25519 secret (seed ‖ public key)', 'PKCS#8 / SubjectPublicKeyInfo (ASN.1 DER)'],
  ['ENCODING', 'Binary .bin files, no headers', 'PEM: Base64 between -----BEGIN/END----- lines'],
  ['ENCRYPTION', 'ChaCha20 (inside ChaCha20-Poly1305 AEAD)', 'aes-256-cbc as used in the brief'],
  ['INTEGRITY', 'Poly1305 tag over ciphertext + AAD', 'None in CBC mode — no tag'],
  ['AUTHENTICATION', 'Tag verification fails for any change or wrong key', 'Not provided by openssl enc (CBC)'],
  ['KDF', 'Argon2id (memory-hard)', 'PBKDF2 with -pbkdf2 (CPU-hard only)'],
  ['PASSWORD PROTECTION', 'Optional Argon2id + secretbox key wrap', 'Unencrypted by default; optional passphrase cipher'],
  ['CONFIGURATION', 'Few choices, safe defaults', 'Many modes and options to choose from'],
  ['MISUSE RESISTANCE', 'High: hard to pick an unauthenticated mode', 'Lower: easy to pick a mode without integrity'],
];

function evidence(o) {
  if (!o) return emptyState('Run the comparison to see real results from <code>scripts/openssl_compare.sh</code>.', '<button class="btn btn-primary" data-a="run">RUN COMPARISON</button>');
  if (!o.cbc) return `<div class="bad">${esc(o.error || 'comparison failed')}</div>`;
  const c = o.cbc;
  const orig = esc(c.original);
  const tampered = esc(c.tampered_block1).replace('90100', '<mark>9</mark>0100');
  return `
    <div class="evidence">
      <div class="box"><div class="faint small">ORIGINAL PLAINTEXT</div>${orig}</div>
      <div class="muted mono small" style="text-align:center">1 ciphertext byte<br>XOR ${esc(c.xor)} @ ${c.byte_offset}<br>→</div>
      <div class="box"><div class="faint small">DECRYPTED AFTER TAMPERING (block 1)</div>${tampered}<div class="faint small" style="margin-top:6px">block 0 garbled: ${esc(c.garbled_block0_hex)}…</div></div>
    </div>
    <div class="grid" style="margin-top:14px">
      <div class="s6"><div class="kv">
        <div>OPENSSL EXIT CODE</div><div class="mono">${c.openssl_exit} ${c.openssl_exit === 0 ? '<span class="warn">(reported success)</span>' : ''}</div>
        <div>TAMPER DETECTED?</div><div>${c.tamper_undetected ? '<span class="badge b-warn">NO — ALTERED PLAINTEXT ACCEPTED</span>' : '<span class="badge b-muted">—</span>'}</div>
        <div>SAME ATTACK ON AEAD</div><div>${o.aead_tamper_rejected ? '<span class="badge b-ok">✕ REJECTED (rc -2)</span>' : '<span class="badge b-muted">not checked</span>'}</div>
      </div></div>
      <div class="s6"><div class="kv">
        <div>TOOL</div><div class="mono">${esc(o.openssl_version)}</div>
        <div>ED25519 PRIVATE (DER)</div><div class="mono">${o.ed25519_priv_der_bytes} B PKCS#8 vs 64 B raw</div>
        <div>ED25519 PUBLIC (DER)</div><div class="mono">${o.ed25519_pub_der_bytes} B SPKI vs 32 B raw</div>
        <div>PRIVATE PEM MODE</div><div class="mono">${esc(o.priv_pem_mode)}</div>
        <div>ROUND-TRIP</div><div>${o.roundtrip_ok ? '<span class="ok">✓ encrypt/decrypt works</span>' : '<span class="bad">✕</span>'}</div>
      </div></div>
    </div>
    <div class="card-title" style="margin:16px 0 8px">ED25519 PUBLIC KEY (PEM) — private key never shown</div>
    <pre class="pem">${esc(o.ed25519_pub_pem)}</pre>`;
}

export default {
  id: 'openssl',
  label: 'OpenSSL Compare',
  mount(root) {
    root.innerHTML = `
      <div class="page-head">
        <div><h1>LIBSODIUM vs OPENSSL CLI</h1><p>Compares this project with the OpenSSL command-line workflow from the brief. OpenSSL the library supports AEAD modes; the limitation shown here is the <code>openssl enc</code> CBC workflow, not OpenSSL itself.</p></div>
        <div class="actions"><button class="btn btn-primary" data-a="run">RUN COMPARISON</button></div>
      </div>
      <div class="grid">
        <section class="card s12">
          <div class="vs">
            <div class="h"></div><div class="h sod">LIBSODIUM IMPLEMENTATION</div><div class="h ossl">OPENSSL CLI</div>
            ${ROWS.map(([k, a, b]) => `<div class="k">${k}</div><div class="sod">${esc(a)}</div><div class="ossl">${esc(b)}</div>`).join('')}
          </div>
        </section>
        <section class="card s12"><div class="cipher-cmp">
          <div class="cc warnbox"><h4>AES-256-CBC</h4><span class="down">↓</span>
            <div class="props-inline"><span class="badge b-ok">CONFIDENTIALITY</span></div>
            <div class="small warn" style="font-weight:700;letter-spacing:.12em">BUT</div>
            <div class="props-inline"><span class="badge b-warn">NO BUILT-IN AUTHENTICATION TAG</span></div>
            <p class="small muted">Flipping a bit in ciphertext block i flips the same bit in plaintext block i+1. Unauthenticated CBC is also exposed to padding-oracle attacks.</p></div>
          <div class="cc goodbox"><h4>ChaCha20-Poly1305</h4><span class="down">↓</span>
            <div class="props-inline"><span class="badge b-ok">CONFIDENTIALITY</span>+<span class="badge b-ok">INTEGRITY</span>+<span class="badge b-ok">AUTHENTICITY</span></div>
            <p class="small muted">An AEAD: decryption returns nothing unless the 16-byte Poly1305 tag over ciphertext and AAD verifies. AES-256-GCM would give the same guarantees.</p></div>
        </div></section>
        <section class="card s12"><div class="card-head"><div><div class="card-title">LIVE EVIDENCE — CBC BIT-FLIP</div><div class="card-sub">encrypt a payment instruction, change one ciphertext byte, decrypt with the correct passphrase</div></div><span id="os-status"></span></div><div id="os-evidence"></div></section>
      </div>`;
    root.addEventListener('click', (e) => {
      const b = e.target.closest('button[data-a="run"]');
      if (b) busy(b, () => run('openssl'));
    });
    this.update();
  },
  update() {
    const o = store.openssl;
    $('#os-status').innerHTML = o ? `<span class="badge ${o.ok ? 'b-ok' : 'b-bad'}">${o.ok ? 'ALL STEPS AS EXPECTED' : `${o.failures ?? '?'} STEP(S) UNEXPECTED`}</span>` : '';
    $('#os-evidence').innerHTML = evidence(o);
  },
};
