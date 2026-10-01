# Slides — Secure Channel // Cryptographic Command Center

Content for `docs/slides.pptx`: 12 slides, about 10–12 minutes including the live demo. It follows the guide's academic order. Each slide lists its **on-screen text**, the **visual** (a real capture from `docs/screenshots/`) and **speaker notes**.

---

## 1 — Title
**On screen:** *Secure Channel with libsodium* · Cryptographic Command Center · Pratham · Applied Cryptographic Design · 24 October 2026
**Visual:** `01-overview-initial.png` (cropped to the header and live channel)
**Say:** "I built an encrypted, authenticated channel in C with libsodium, attacked it, compared it with OpenSSL, and wrapped it in a dashboard that shows the real results live."

## 2 — Problem and goal
**On screen:** An attacker on the network can **read, modify, replay, reorder, drop and inject** packets. The goal is a channel where none of that goes unnoticed.
**Say:** "Encryption alone only stops reading. Most real failures are in the other things an attacker can do."

## 3 — Security requirements
**On screen:**
| Requirement | Mechanism |
|---|---|
| Confidentiality | ChaCha20, 256-bit session key |
| Integrity / authenticity | Poly1305 tag over ciphertext + seq (AAD) |
| Freshness | strictly increasing seq, state updated only after the tag verifies |
| Key protection | 0600 files, Argon2id-wrapped private key |

## 4 — Architecture
**On screen:** Browser dashboard → local bridge (127.0.0.1, whitelisted commands) → C binaries in WSL (`sc_engine`, `test_attacks`, `keygen`, TCP server/client, OpenSSL script).
**Callout:** "Secrets never leave C — the UI sees only public bytes, return codes and one-way fingerprints."
**Say:** "Every green or red label is a return code from the C code. There is no fake data in the browser."

## 5 — State machine
**On screen:** INIT → AUTH → SECURE → TERMINATE, each with the real engine timestamp.
**Visual:** `03-handshake.png` header or `12-terminated.png` (all four states lit)
**Say:** "It's enforced, not decorative: sealing a message outside SECURE returns an error."

## 6 — Key exchange (Task 2)
**On screen:** X25519 public keys cross the network → `crypto_kx` = BLAKE2b(shared ‖ client_pk ‖ server_pk) → split into rx / tx.
client_tx = server_rx ✓ · client_rx = server_tx ✓ · client_tx ≠ client_rx ✓
**Visual:** `03-handshake.png`
**Say:** "Matching fingerprints prove the keys agree without showing them. One key per direction means a reflected packet fails."

## 7 — Packet format (Task 3)
**On screen:** `[seq 8 B | nonce 12 B | ciphertext | tag 16 B]`, with seq sent in clear but authenticated as AAD.
**Visual:** `05-inspector.png`
**Say:** "This is exactly what an eavesdropper sees: no key, no plaintext."

## 8 — Attack Lab (Task 4)
**On screen:** 8 attacks → 7 blocked, 1 accepted as expected · required suite **8 passed, 0 failed** · extended suite 35/35 · integration 46/46
**Visual:** `18-attack-lab-all8.png`
**Say:** "The subtle one is the forged sequence number. If I stored the seq before checking the tag, one fake packet would block all real traffic. State changes only after authentication."

## 9 — Key wrapping (Task 5)
**On screen:** passphrase + salt → **Argon2id (64 MiB)** → key → **secretbox** → 120-byte wrapped file (0600).
Correct → ✓ unwrapped · Wrong → ✕ authentication failed, ✓ secret not released
**Visual:** `09-key-wrapping.png`

## 10 — OpenSSL comparison (Task 6)
**On screen:** `aes-256-cbc` bit-flip: `AMOUNT=00100` → `AMOUNT=90100`, openssl exit 0. The same change against the AEAD → rc -2.
**Visual:** `16-openssl-full.png`
**Say:** "CBC gives confidentiality but no integrity. OpenSSL the library supports AEAD; the problem is this CLI workflow."

## 11 — Limitations and extensions
**On screen:**
- Plain crypto_kx is unauthenticated → **Ed25519-signed handshake extension** blocks 3 MITM variants (`19-handshake-mitm.png`)
- Extensions: re-keying (epochs) · localhost TCP client/server (`20-tcp-mode.png`) · benchmark (`17-bench-full.png`)
- Remaining: secrets in memory while in use · strict replay window (TCP-only) · educational, not TLS

## 12 — Live demo and Q&A
**On screen:** `npm run dev` → **START DEMO** · GitHub: [INSERT GITHUB URL] + QR code · Questions?
**Demo script (about 4 minutes, all real):**
1. START DEMO: keys generated, `0600` verified in the Key Vault
2. Handshake: point at the matching fingerprints
3. Send a packet: it flies across and returns ✓ AUTHENTICATED ✓ DECRYPTED ✓ ACCEPTED
4. Tamper, replay and wrong key: each ✕ BLOCKED with its return code
5. Test suite 8/8, key wrapping, OpenSSL CBC evidence
6. TERMINATE, then the Logs filtered to WIPE events

**Backup** if WSL or the browser fails: `make present` in a terminal, or these screenshots.
