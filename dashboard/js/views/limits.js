const LIMITS = [
  ['LIMITATION', 'b-warn', 'Plain crypto_kx is unauthenticated',
    'The handshake from the brief proves nothing about who is on the other end. An active man-in-the-middle can run one exchange with each side, then read and rewrite traffic. The Handshake tab demonstrates this with the real code.'],
  ['EXTENSION', 'b-ok', 'Authenticated handshake (Ed25519)',
    'Implemented as a separate extension: the server signs server_eph ‖ client_eph with its long-term key and the client verifies against a pinned server_pk.bin. It depends on that public key being distributed authentically.'],
  ['LIMITATION', 'b-warn', 'Secrets resident in process memory',
    'Session keys live in sodium_malloc() memory (guard pages, mlock) and are zeroed on TERMINATE, and file keys are wiped after use. A privileged attacker, debugger or core dump can still read keys while they are in use.'],
  ['LIMITATION', 'b-warn', 'Strict replay window',
    'A single last_seq rejects any out-of-order packet. That is right for TCP, but UDP would need a sliding-window bitmap such as the ones in IPsec and DTLS.'],
  ['LIMITATION', 'b-warn', 'Random 96-bit nonces',
    'Safe for about 2³² messages per key (birthday bound). A counter nonce, XChaCha20-Poly1305 or re-keying well before that limit removes the concern.'],
  ['EXTENSION', 'b-ok', 'Re-keying',
    'Implemented: crypto_kdf_derive_from_key moves both sides to a new epoch after N messages or on demand, and the old keys are overwritten. The re-key count is announced unauthenticated in TCP mode, so an active attacker could desynchronise it (denial of service only).'],
  ['EXTENSION', 'b-ok', 'Localhost TCP transport',
    'Implemented for 127.0.0.1 with 4-byte length-prefixed frames. The server handles one client at a time and sends clear-text ALERT frames for rejected packets, which is a demo convenience; a production protocol would drop the packet or close the connection.'],
  ['SCOPE', 'b-info', 'Educational implementation',
    'This project demonstrates the building blocks of a secure channel. It is not a replacement for TLS 1.3 or the Noise framework, which add negotiated handshakes, identity binding, key updates and extensive analysis.'],
  ['SCOPE', 'b-info', 'Argon2id parameters',
    'Uses libsodium\'s INTERACTIVE preset (64 MiB, ops 2) so the demo stays responsive. A long-term server key could justify MODERATE or SENSITIVE limits.'],
];

export default {
  id: 'limits',
  label: 'Limitations',
  mount(root) {
    root.innerHTML = `
      <div class="page-head"><div><h1>LIMITATIONS &amp; FUTURE WORK</h1><p>What this implementation does not protect against, and which extensions exist. Nothing here is hidden from the demo.</p></div></div>
      <div class="lims">${LIMITS.map(([tag, cls, title, text]) => `
        <section class="card lim"><span class="badge ${cls} tag">${tag}</span><h4>${title}</h4><p>${text}</p></section>`).join('')}</div>`;
  },
  update() {},
};
