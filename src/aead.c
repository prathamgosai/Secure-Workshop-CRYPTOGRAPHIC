/* aead.c - Task 3 + 4: seal/unseal with seq as AAD and replay protection.
 *
 * Packet: [ seq 8 B big-endian ][ nonce 12 B ][ ciphertext + 16 B tag ]
 */
#include "common.h"
#include <string.h>

void store_be64(unsigned char b[8], uint64_t v) {
    for (int i = 7; i >= 0; i--) { b[i] = (unsigned char)(v & 0xff); v >>= 8; }
}

uint64_t load_be64(const unsigned char b[8]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
    return v;
}

/* Encrypts pt into out. Returns the packet length, or 0 on error
 * (a valid packet is always at least MIN_PKT_LEN bytes). */
size_t seal(unsigned char *out, size_t out_cap, uint64_t seq,
            const unsigned char *pt, size_t pt_len,
            const unsigned char key[KEY_LEN]) {
    if (out == NULL || key == NULL || (pt == NULL && pt_len > 0)) return 0;
    if (pt_len > MAX_PT_LEN || out_cap < PKT_LEN(pt_len)) return 0;

    unsigned char *seqb = out, *nonce = out + SEQ_LEN, *ct = out + HDR_LEN;
    unsigned long long ct_len = 0;

    store_be64(seqb, seq);
    /* A fresh random 96-bit nonce per message. A nonce must never repeat
     * under the same key: reuse would leak the XOR of two plaintexts and
     * allow Poly1305 forgeries. */
    randombytes_buf(nonce, NONCE_LEN);

    if (crypto_aead_chacha20poly1305_ietf_encrypt(ct, &ct_len,
            pt, (unsigned long long)pt_len,
            seqb, SEQ_LEN,          /* AAD = seq: clear text, but authenticated */
            NULL, nonce, key) != 0)
        return 0;
    return HDR_LEN + (size_t)ct_len;
}

/* Returns SC_OK, SC_ERR_SHORT, SC_ERR_AUTH, SC_ERR_REPLAY or SC_ERR_BUFFER.
 * Plaintext is written to pt only if the tag verifies. rs may be NULL to
 * disable replay checking. */
int unseal(unsigned char *pt, size_t pt_cap, size_t *pt_len,
           const unsigned char *pkt, size_t pkt_len,
           const unsigned char key[KEY_LEN], replay_state *rs) {
    if (pt_len != NULL) *pt_len = 0;
    if (pkt == NULL || key == NULL || pt_len == NULL) return SC_ERR_SHORT;

    /* 1. Reject malformed packets before doing any work. */
    if (pkt_len < MIN_PKT_LEN || pkt_len > PKT_LEN(MAX_PT_LEN)) return SC_ERR_SHORT;
    size_t body_len = pkt_len - MIN_PKT_LEN;
    if (pt == NULL || pt_cap < body_len) return SC_ERR_BUFFER;

    /* 2. Cheap replay/reorder check. This only READS the state. */
    uint64_t seq = load_be64(pkt);
    if (rs != NULL && rs->has_seq && seq <= rs->last_seq) return SC_ERR_REPLAY;

    /* 3. Verify the tag over ciphertext + AAD(seq), then decrypt. */
    unsigned long long out_len = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(pt, &out_len, NULL,
            pkt + HDR_LEN, (unsigned long long)(pkt_len - HDR_LEN),
            pkt, SEQ_LEN,           /* AAD = seq */
            pkt + SEQ_LEN, key) != 0) {
        sodium_memzero(pt, body_len);
        return SC_ERR_AUTH;
    }

    /* 4. Update replay state ONLY after the tag verifies. The seq field is
     * attacker-controlled until authenticated: if we stored it first, one
     * forged packet with seq = 2^64-1 would fail the tag check but still push
     * last_seq to the maximum, and every genuine packet after it would be
     * rejected as a replay - a one-packet denial of service. */
    if (rs != NULL) { rs->last_seq = seq; rs->has_seq = 1; }
    *pt_len = (size_t)out_len;
    return SC_OK;
}

const char *unseal_strerror(int rc) {
    switch (rc) {
    case SC_OK:         return "accepted";
    case SC_ERR_SHORT:  return "malformed/short packet";
    case SC_ERR_AUTH:   return "authentication failed (tag mismatch)";
    case SC_ERR_REPLAY: return "replay/reorder (seq not fresh)";
    case SC_ERR_BUFFER: return "output buffer too small";
    default:            return "unknown error";
    }
}
