import { store, run } from '../store.js';
import { esc, busy, chip, emptyState, pageHead, panelHead, $ } from '../ui.js';

const ROWS = [
  ['Key format', 'Raw bytes — 32 B public, 64 B Ed25519 secret (seed ‖ public key)', 'PKCS#8 / SubjectPublicKeyInfo (ASN.1 DER)'],
  ['Encoding', 'Binary .bin files, no headers', 'PEM — Base64 between BEGIN / END lines'],
  ['Encryption', 'ChaCha20-Poly1305-IETF (AEAD)', 'aes-256-cbc, as used in the brief&rsquo;s <code>openssl enc</code> workflow'],
  ['Authentication', '16-byte Poly1305 tag over ciphertext + AAD; decryption fails on any change', 'No integrated tag in CBC mode; a separate MAC would be required'],
  ['Password KDF', 'Argon2id — memory-hard, 64 MiB', 'PBKDF2 via <code>-pbkdf2</code> — iterated hash'],
  ['Key protection', 'File mode 0600; optional Argon2id + secretbox wrap', 'Private PEM written 0600 (observed); unencrypted unless a passphrase cipher is chosen'],
  ['API surface', 'Small set of high-level functions with fixed algorithms', 'Many modes and options; algorithm choice left to the caller'],
];

function evidence(o) {
  if (!o) return emptyState('Run the comparison to see real results from <code>scripts/openssl_compare.sh</code>: an encrypted payment instruction, one changed ciphertext byte, and what each tool does with it.', '<button class="btn btn-primary" data-a="run">Run comparison</button>');
  if (!o.cbc) return `<div class="alert" role="alert"><b>COMPARISON FAILED</b><span>${esc(o.error || 'the script did not report results')}</span></div>`;
  const c = o.cbc;
  const tampered = esc(c.tampered_block1).replace('90100', '<mark>9</mark>0100');
  return `
    <div class="evidence">
      <div class="box"><span class="k">Original plaintext</span>${esc(c.original)}</div>
      <div class="op">1 ciphertext byte<br>XOR ${esc(c.xor)} @ ${c.byte_offset}<br>→</div>
      <div class="box"><span class="k">Decrypted after tampering · block 1</span>${tampered}<div class="faint small" style="margin-top:8px">block 0 garbled: ${esc(c.garbled_block0_hex)}…</div></div>
    </div>
    <div class="grid" style="margin-top:20px">
      <div class="s6"><div class="kv">
        <div>OpenSSL exit code</div><div class="mono">${c.openssl_exit} ${c.openssl_exit === 0 ? '<span class="faint">(reported success)</span>' : ''}</div>
        <div>Tamper detected · CBC</div><div>${c.tamper_undetected ? chip('WARNING', { text: 'No — altered plaintext returned' }) : chip('UNKNOWN')}</div>
        <div>Same change · AEAD</div><div>${o.aead_tamper_rejected ? chip('REJECTED', { text: 'Rejected · rc −2' }) : chip('NOT RUN', { text: 'Not checked' })}</div>
      </div></div>
      <div class="s6"><div class="kv">
        <div>Tool</div><div class="mono">${esc(o.openssl_version)}</div>
        <div>Ed25519 private · DER</div><div class="mono">${o.ed25519_priv_der_bytes} B PKCS#8 <span class="faint">vs 64 B raw</span></div>
        <div>Ed25519 public · DER</div><div class="mono">${o.ed25519_pub_der_bytes} B SPKI <span class="faint">vs 32 B raw</span></div>
        <div>Private PEM mode</div><div class="mono">${esc(o.priv_pem_mode)}</div>
        <div>CBC round-trip</div><div>${o.roundtrip_ok ? chip('PASS', { text: 'Encrypt / decrypt works' }) : chip('FAILED')}</div>
      </div></div>
    </div>
    <div class="panel-title" style="margin:24px 0 10px">Ed25519 public key · PEM <span class="faint">— private key never shown</span></div>
    <pre class="pem">${esc(o.ed25519_pub_pem)}</pre>`;
}

export default {
  id: 'openssl',
  label: 'OpenSSL Compare',
  icon: 'openssl',
  mount(root) {
    root.innerHTML = `
      ${pageHead('Task 6 · Toolchain comparison', 'Cryptographic toolchain comparison', 'This project&rsquo;s libsodium implementation beside the OpenSSL command-line workflow from the brief. OpenSSL&rsquo;s library also offers AEAD modes through its C API; the behaviour shown here belongs to the <code>openssl enc</code> CBC workflow.',
        '<button class="btn btn-primary" data-a="run">Run comparison</button>')}
      <section class="compare" aria-label="libsodium versus OpenSSL CLI">
        <div class="h"></div>
        <div class="h a"><span>This project</span><b>libsodium</b></div>
        <div class="h b"><span>Brief workflow</span><b>OpenSSL CLI</b></div>
        ${ROWS.map(([k, a, b]) => `<div class="k">${k}</div><div class="a">${a}</div><div class="b">${b}</div>`).join('')}
      </section>
      <div class="cipher-cmp section">
        <div class="cc"><span class="eyebrow">OpenSSL CLI · as used in the brief</span><h3>AES-256-CBC</h3>
          <div class="props-inline">${chip('PROTECTED', { text: 'Confidentiality' })}${chip('NOT RUN', { text: 'No integrated tag', glyph: '—' })}</div>
          <p>Flipping a bit in ciphertext block i flips the same bit in plaintext block i+1 and garbles block i. Without a separate MAC, the change is not detected at decryption time.</p></div>
        <div class="cc"><span class="eyebrow">libsodium · this project</span><h3>ChaCha20-Poly1305</h3>
          <div class="props-inline">${chip('PROTECTED', { text: 'Confidentiality' })}${chip('PROTECTED', { text: 'Integrity' })}${chip('PROTECTED', { text: 'Authenticity' })}</div>
          <p>An AEAD: decryption returns nothing unless the 16-byte Poly1305 tag over ciphertext and AAD verifies. AES-256-GCM provides the same class of guarantee.</p></div>
      </div>
      <section class="panel section">${panelHead('Live evidence · CBC bit-flip', 'Encrypt a payment instruction, change one ciphertext byte, decrypt with the correct passphrase', '<span id="os-status"></span>')}<div id="os-evidence"></div></section>`;
    root.addEventListener('click', (e) => {
      const b = e.target.closest('button[data-a="run"]');
      if (b) busy(b, () => run('openssl'));
    });
    this.update();
  },
  update() {
    const o = store.openssl;
    $('#os-status').innerHTML = o ? chip(o.ok ? 'PASS' : 'FAILED', { text: o.ok ? 'All steps as expected' : `${o.failures ?? '?'} step(s) unexpected` }) : chip('NOT RUN');
    $('#os-evidence').innerHTML = evidence(o);
  },
};
