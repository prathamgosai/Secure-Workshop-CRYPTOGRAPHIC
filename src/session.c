/* session.c - in-process secure channel state machine. */
#include "session.h"
#include <string.h>

static void free_keys(session *s) {
    unsigned char **keys[] = { &s->c_tx, &s->c_rx, &s->s_tx, &s->s_rx };
    for (size_t i = 0; i < sizeof keys / sizeof keys[0]; i++) {
        sodium_free(*keys[i]);          /* zeroes before releasing; NULL is a no-op */
        *keys[i] = NULL;
    }
}

void session_init(session *s) {
    memset(s, 0, sizeof *s);
    s->state = ST_INIT;
}

int session_handshake(session *s, const identity *id, handshake_result *hr) {
    unsigned char csk[KX_SK_LEN], ssk[KX_SK_LEN], sig[SIG_LEN];
    uint32_t rekey_every = s->rekey_every;
    int rc = SESSION_OK;

    free_keys(s);                        /* a new handshake replaces any old session */
    session_init(s);
    s->rekey_every = rekey_every;
    memset(hr, 0, sizeof *hr);
    hr->signature = -1;

    s->c_tx = sodium_malloc(SESSION_KEY_LEN); s->c_rx = sodium_malloc(SESSION_KEY_LEN);
    s->s_tx = sodium_malloc(SESSION_KEY_LEN); s->s_rx = sodium_malloc(SESSION_KEY_LEN);
    if (!s->c_tx || !s->c_rx || !s->s_tx || !s->s_rx) { rc = SESSION_ERR_CRYPTO; goto fail; }

    /* INIT: each side makes an ephemeral key pair. */
    crypto_kx_keypair(s->client_pk, csk);
    crypto_kx_keypair(s->server_pk, ssk);
    s->state = ST_AUTH;

    /* AUTH (extension): server signs (server_pk, client_pk); client verifies. */
    if (id != NULL) {
        hr->signature = hs_sign(sig, s->server_pk, s->client_pk, id->sk) == 0 &&
                        hs_verify(sig, s->server_pk, s->client_pk, id->pk) == 0;
        if (!hr->signature) { rc = SESSION_ERR_SIG; goto fail; }
        s->authenticated = 1;
    }

    /* AUTH: derive direction-specific session keys. */
    if (crypto_kx_client_session_keys(s->c_rx, s->c_tx, s->client_pk, csk, s->server_pk) != 0 ||
        crypto_kx_server_session_keys(s->s_rx, s->s_tx, s->server_pk, ssk, s->client_pk) != 0) {
        rc = SESSION_ERR_CRYPTO;
        goto fail;
    }
    hr->complementary = sodium_memcmp(s->c_tx, s->s_rx, SESSION_KEY_LEN) == 0 &&
                        sodium_memcmp(s->c_rx, s->s_tx, SESSION_KEY_LEN) == 0;
    hr->directional = sodium_memcmp(s->c_tx, s->c_rx, SESSION_KEY_LEN) != 0;
    if (!hr->complementary || !hr->directional) { rc = SESSION_ERR_CRYPTO; goto fail; }

    sodium_memzero(csk, sizeof csk);
    sodium_memzero(ssk, sizeof ssk);
    s->next_seq = 1;
    s->epoch = 1;
    s->state = ST_SECURE;
    return SESSION_OK;

fail:
    sodium_memzero(csk, sizeof csk);
    sodium_memzero(ssk, sizeof ssk);
    free_keys(s);
    s->state = ST_INIT;
    s->authenticated = 0;
    return rc;
}

int session_seal(session *s, const unsigned char *pt, size_t pt_len,
                 unsigned char *pkt, size_t pkt_cap, size_t *pkt_len, uint64_t *seq) {
    *pkt_len = 0;
    if (s->state != ST_SECURE) return SESSION_ERR_STATE;
    if (pt_len > SESSION_MSG_MAX) return SESSION_ERR_INPUT;
    uint64_t q = s->next_seq;
    size_t n = seal(pkt, pkt_cap, q, pt, pt_len, s->c_tx);
    if (n == 0) return SESSION_ERR_CRYPTO;
    s->next_seq++;
    *pkt_len = n;
    if (seq) *seq = q;
    return SESSION_OK;
}

int session_deliver(session *s, const unsigned char *pkt, size_t pkt_len,
                    unsigned char *pt, size_t pt_cap, size_t *pt_len, int *rekeyed) {
    if (rekeyed) *rekeyed = 0;
    if (s->state != ST_SECURE) { *pt_len = 0; return SESSION_ERR_STATE; }
    int rc = unseal(pt, pt_cap, pt_len, pkt, pkt_len, s->s_rx, &s->server_rs);
    if (rc == SC_OK && s->rekey_every > 0 && ++s->in_epoch >= s->rekey_every) {
        if (session_rekey(s) == SESSION_OK && rekeyed) *rekeyed = 1;
    }
    return rc;
}

int session_rekey(session *s) {
    if (s->state != ST_SECURE) return SESSION_ERR_STATE;
    uint64_t next = s->epoch + 1;
    if (rekey_key(s->c_tx, next) != 0 || rekey_key(s->c_rx, next) != 0 ||
        rekey_key(s->s_tx, next) != 0 || rekey_key(s->s_rx, next) != 0)
        return SESSION_ERR_CRYPTO;
    s->epoch = next;
    s->in_epoch = 0;
    return SESSION_OK;
}

void session_fingerprints(const session *s, unsigned char c_tx[FINGERPRINT_LEN],
                          unsigned char c_rx[FINGERPRINT_LEN], unsigned char s_tx[FINGERPRINT_LEN],
                          unsigned char s_rx[FINGERPRINT_LEN]) {
    if (s->c_tx == NULL) {
        memset(c_tx, 0, FINGERPRINT_LEN); memset(c_rx, 0, FINGERPRINT_LEN);
        memset(s_tx, 0, FINGERPRINT_LEN); memset(s_rx, 0, FINGERPRINT_LEN);
        return;
    }
    key_fingerprint(c_tx, s->c_tx, SESSION_KEY_LEN);
    key_fingerprint(c_rx, s->c_rx, SESSION_KEY_LEN);
    key_fingerprint(s_tx, s->s_tx, SESSION_KEY_LEN);
    key_fingerprint(s_rx, s->s_rx, SESSION_KEY_LEN);
}

void session_close(session *s) {
    free_keys(s);
    s->state = ST_TERMINATE;
    s->server_rs = (replay_state){0, 0};
}

const char *session_strerror(int rc) {
    switch (rc) {
    case SESSION_ERR_STATE:  return "operation not allowed in the current state";
    case SESSION_ERR_CRYPTO: return "key derivation or allocation failed";
    case SESSION_ERR_SIG:    return "handshake signature did not verify";
    case SESSION_ERR_INPUT:  return "message empty or too long";
    default:                 return unseal_strerror(rc);
    }
}
