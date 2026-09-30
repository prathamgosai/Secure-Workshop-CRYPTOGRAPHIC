# Q&A preparation

Short answers you can say out loud, with the file to point at if asked.

## The four core design questions

**Why are private keys stored with 0600 permissions?**
0600 means only the owner can read or write. I create the file with that mode directly in `open()`, so it never exists with looser permissions. `fopen` then `chmod` has a gap where another user could open it. (`src/keyio.c`)

**Why does crypto_kx give complementary TX/RX keys?**
It hashes the shared secret with both public keys into 64 bytes and splits them into two keys. The client and server take the halves in opposite order, so what I transmit with, you receive with. Separate keys per direction mean a packet can't be bounced back to its sender and accepted. (`src/kx_demo.c`, reflection test)

**Why is the sequence number AAD?**
The receiver needs it before decrypting to reject replays, so it's sent in clear. As AAD it's still covered by the tag, so changing it makes authentication fail. (test 3)

**Why update replay state only after authentication?**
Before the tag is checked, the sequence number is just bytes the attacker chose. If I stored it first, one fake packet with the maximum number would make every real packet look like a replay: a denial of service. (`src/aead.c`, test 8)

## Other likely questions

**What is AEAD?**
Authenticated Encryption with Associated Data. One operation encrypts the message and produces a tag over the ciphertext plus extra data sent in clear. If anything changes, decryption refuses to return a result.

**What is a nonce?**
A "number used once". It makes encrypting the same message twice give different ciphertexts. Mine is 12 random bytes per packet.

**Why must a nonce not repeat with the same key?**
ChaCha20 is a stream cipher. Reusing a nonce reuses the keystream, so XORing the two ciphertexts gives the XOR of the two plaintexts. Poly1305 also becomes forgeable.

**What does Argon2id do?**
It turns a password into a key slowly and using a lot of memory (64 MiB here). Each guess costs an attacker time and RAM, so GPU cracking is expensive. The salt makes the same password give different keys for different files.

**X25519 vs Ed25519?**
Same underlying curve, different jobs. X25519 is for key agreement (two parties get a shared secret). Ed25519 is for signatures (proving who you are).

**Why sodium_memzero()?**
The compiler can delete a `memset` on a buffer that isn't used again. `sodium_memzero` can't be removed, so the key really is wiped.

**What does the authentication tag protect?**
The ciphertext and the associated data (the sequence number). It's a 16-byte Poly1305 value that only someone with the key can compute.

**Why does wrong-key decryption fail?**
The receiver recomputes the tag with its own key. A different key gives a different tag, so they don't match and nothing is returned.

**Why does ciphertext tampering fail?**
Any changed bit changes the expected tag. The chance of an attacker guessing a valid tag is negligible: for messages of this size, Poly1305's forgery probability is far below one in 2¹⁰⁰ per attempt.

**Why does reordering fail?**
The receiver accepts only a sequence number strictly greater than the last one accepted. After seq 3, seq 2 is too old.

**What limitation remains with plain crypto_kx?**
It doesn't prove who is on the other end, so an active man-in-the-middle can do two exchanges. `make mitm` shows it. The fix is for the server to sign the handshake with its long-term Ed25519 key, which the client already trusts.

**Why is AES-CBC not equivalent to AEAD?**
CBC has no tag. Flipping bits in one ciphertext block flips the same bits in the next plaintext block. I changed `00100` to `90100` and OpenSSL reported success. CBC also enables padding-oracle attacks.

**Why ChaCha20 and not AES?**
It's fast and constant-time on any CPU, with no need for AES hardware. My benchmark shows AES-GCM is faster on this laptop (it has AES-NI), but ChaCha20 is the safer portable default.

**What happens after 2⁶⁴ messages?**
The counter would wrap. In practice you re-key long before that; with random nonces you should re-key well before 2³² messages.

**Is this production-ready?**
No. It's an educational channel. Production code would use TLS 1.3 or the Noise framework, with authenticated handshakes, re-keying and a real transport.

## Dashboard and extensions

**Is the dashboard just an animation?**
No. Every result comes from the C code. The browser calls a local bridge, and the bridge runs the real binaries, such as `sc_engine`, `test_attacks` and the OpenSSL script. The packet animation is decoration; the ✓ or ✕ it lands on is the return code of `unseal()`.

**How do you show session keys without leaking them?**
I show a fingerprint: BLAKE2b of the key with a fixed domain key, cut to 8 bytes. Equal keys give equal fingerprints, so you can see `client_tx` matches `server_rx`, but you can't turn a fingerprint back into the key. The raw bytes never leave the C engine, and the integration test scans every response to check that.

**Can another website control your dashboard?**
No. The bridge listens only on 127.0.0.1. Every command needs a custom header, which browsers won't send cross-site without a permission check the bridge never grants. The bridge also rejects unexpected `Host` headers (DNS rebinding) and only accepts a fixed list of commands.

**How does re-keying work?**
Both sides run `crypto_kdf_derive_from_key(new, 32, epoch, "SCREKEY1", old)` on each key and overwrite the old one. They get the same new keys without sending anything. The KDF is one-way, so leaking today's key doesn't reveal yesterday's.

**What does TCP mode add?**
Real sockets on localhost. Each message is framed with a 4-byte length prefix, and the length is checked before anything is read. The handshake is signed, and tamper and replay are rejected across the network. If the client is pinned to a different server key, it aborts the handshake.

**Why is AES-GCM faster in your benchmark?**
My CPU has AES-NI hardware instructions. ChaCha20 is still the portable choice: it's fast and constant-time in plain software on any device.
