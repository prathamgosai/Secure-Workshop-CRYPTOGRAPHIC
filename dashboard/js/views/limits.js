import { chip, pageHead, panelHead } from '../ui.js';

const SECTIONS = [
  ['Current guarantees', 'What the implementation provides against the network attacker in the threat model', [
    ['PROTECTED', 'Confidentiality', 'ChaCha20 under a fresh 256-bit session key per direction; keys derived with crypto_kx and never written to disk.'],
    ['PROTECTED', 'Integrity and AAD', 'Poly1305 authenticates ciphertext and the clear-text sequence number. Any change yields rc −2 and nothing is returned.'],
    ['PROTECTED', 'Freshness', 'Strictly increasing 64-bit sequence numbers; last_seq is updated only after the tag verifies, so forged values cannot poison the window.'],
    ['PROTECTED', 'Keys at rest', 'Private key files 0600 (checked, not assumed); optional Argon2id + secretbox wrapping under a passphrase.'],
  ]],
  ['MITM considerations', 'Who is on the other end?', [
    ['LIMITATION', 'Plain crypto_kx is unauthenticated', 'The brief&rsquo;s handshake proves nothing about the peer. An active man-in-the-middle can run one exchange with each side, then read and rewrite traffic. The Handshake page demonstrates this with the real code.'],
    ['EXTENSION', 'Ed25519-signed handshake', 'Implemented separately: the server signs server_eph ‖ client_eph with its long-term key; the client verifies against a pinned server_pk.bin. It relies on that public key having been distributed authentically.'],
  ]],
  ['Key memory exposure', 'Secrets while in use', [
    ['LIMITATION', 'Secrets resident in process memory', 'Session keys live in sodium_malloc() memory (guard pages, mlock) and are zeroed on TERMINATE; file keys are wiped after use. A privileged attacker, debugger or core dump can still read keys while they are in use.'],
    ['SCOPE', 'Argon2id parameters', 'Uses libsodium&rsquo;s INTERACTIVE preset (64 MiB, ops 2) so the demo stays responsive. A long-term server key could justify MODERATE or SENSITIVE limits.'],
  ]],
  ['Replay policy', 'Ordering and nonce limits', [
    ['LIMITATION', 'Strict replay window', 'A single last_seq rejects any out-of-order packet. Correct for TCP; UDP would need a sliding-window bitmap such as those in IPsec and DTLS.'],
    ['LIMITATION', 'Random 96-bit nonces', 'Safe for about 2³² messages per key (birthday bound). A counter nonce, XChaCha20-Poly1305 or re-keying well before that limit removes the concern.'],
  ]],
  ['Implemented extensions', 'Beyond the brief', [
    ['EXTENSION', 'Re-keying', 'crypto_kdf_derive_from_key moves both sides to a new epoch after N messages or on demand; old keys are overwritten. In TCP mode the re-key interval is announced unauthenticated, so an attacker could only cause a denial of service.'],
    ['EXTENSION', 'Localhost TCP transport', '127.0.0.1 with 4-byte length-prefixed frames. One client at a time; rejected packets get a clear-text ALERT frame as a demo convenience.'],
    ['EXTENSION', 'AEAD benchmark', 'ChaCha20-Poly1305 vs AES-256-GCM vs seal(), measured at run time.'],
  ]],
  ['Future work', 'Out of scope for an educational implementation', [
    ['SCOPE', 'Not a TLS 1.3 or Noise replacement', 'Those protocols add negotiated handshakes, identity binding, key updates and extensive formal analysis.'],
    ['SCOPE', 'Possible next steps', 'Sliding replay bitmap, XChaCha20 nonces, mutual authentication, multi-client server, authenticated re-key signalling.'],
  ]],
];

export default {
  id: 'limits',
  label: 'Limitations',
  icon: 'limits',
  mount(root) {
    root.innerHTML = `
      ${pageHead('Analysis · Honest scope', 'Guarantees and limitations', 'What this implementation protects, what it does not, and which extensions exist. Nothing here is hidden from the demo.')}
      <div class="lim-cols">${SECTIONS.map(([title, sub, items]) => `
        <section class="panel">${panelHead(title, sub)}
          <div class="lim-list">${items.map(([tag, h, p]) => `<div class="lim">${chip(tag, { tone: tag === 'PROTECTED' ? 'ok' : undefined })}<h4>${h}</h4><p>${p}</p></div>`).join('')}</div>
        </section>`).join('')}</div>`;
  },
  update() {},
};
