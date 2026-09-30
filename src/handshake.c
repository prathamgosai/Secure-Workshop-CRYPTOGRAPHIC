/* handshake.c - authenticated handshake, re-keying, fingerprints, MITM scenario. */
#include "handshake.h"
#include <stdio.h>
#include <string.h>

void hs_transcript(unsigned char out[HS_TRANSCRIPT_LEN],
                   const unsigned char server_eph[KX_PK_LEN],
                   const unsigned char client_eph[KX_PK_LEN]) {
    memcpy(out, HS_LABEL, HS_LABEL_LEN);
    memcpy(out + HS_LABEL_LEN, server_eph, KX_PK_LEN);
    memcpy(out + HS_LABEL_LEN + KX_PK_LEN, client_eph, KX_PK_LEN);
}

/* Including the client's key in what the server signs stops a signature
 * from one session being replayed into another. */
int hs_sign(unsigned char sig[SIG_LEN], const unsigned char server_eph[KX_PK_LEN],
            const unsigned char client_eph[KX_PK_LEN], const unsigned char id_sk[ID_SK_LEN]) {
    unsigned char t[HS_TRANSCRIPT_LEN];
    hs_transcript(t, server_eph, client_eph);
    return crypto_sign_detached(sig, NULL, t, sizeof t, id_sk);
}

int hs_verify(const unsigned char sig[SIG_LEN], const unsigned char server_eph[KX_PK_LEN],
              const unsigned char client_eph[KX_PK_LEN], const unsigned char pinned_pk[ID_PK_LEN]) {
    unsigned char t[HS_TRANSCRIPT_LEN];
    hs_transcript(t, server_eph, client_eph);
    return crypto_sign_verify_detached(sig, t, sizeof t, pinned_pk);
}

int identity_load(identity *id) {
    if (read_file(SERVER_SIGN_PK, id->pk, sizeof id->pk) != 0 ||
        read_file(SERVER_SIGN_SK, id->sk, sizeof id->sk) != 0) {
        sodium_memzero(id->sk, sizeof id->sk);
        return -1;
    }
    return 0;
}

/* Both sides run this on the same old key with the same epoch, so they stay
 * in sync without sending anything. The KDF is one-way: a key leaked in epoch
 * n does not reveal the keys of earlier epochs. */
int rekey_key(unsigned char key[SESSION_KEY_LEN], uint64_t new_epoch) {
    unsigned char next[SESSION_KEY_LEN];
    if (crypto_kdf_derive_from_key(next, sizeof next, new_epoch, REKEY_CONTEXT, key) != 0) {
        sodium_memzero(next, sizeof next);
        return -1;
    }
    memcpy(key, next, sizeof next);
    sodium_memzero(next, sizeof next);
    return 0;
}

void key_fingerprint(unsigned char out[FINGERPRINT_LEN], const unsigned char *key, size_t len) {
    static const char domain[] = "SC-FINGERPRINT-1";   /* 16 bytes = KEYBYTES_MIN */
    crypto_generichash(out, FINGERPRINT_LEN, key, len,
                       (const unsigned char *)domain, sizeof domain - 1);
}

void fingerprint_str(char out[32], const unsigned char fp[FINGERPRINT_LEN]) {
    snprintf(out, 32, "%02X %02X %02X %02X … %02X", fp[0], fp[1], fp[2], fp[3], fp[FINGERPRINT_LEN - 1]);
}

/* ---- MITM scenario ----------------------------------------------------- */

typedef struct { unsigned char pk[KX_PK_LEN], sk[KX_SK_LEN]; } kx_pair;

static void mitm_plain(mitm_report *r) {
    static const char msg[] = "PAY BOB 100", forged[] = "PAY MAL 900";
    kx_pair client, server, mallory;
    unsigned char c_rx[32], c_tx[32], s_rx[32], s_tx[32];
    unsigned char mc_rx[32], mc_tx[32], ms_rx[32], ms_tx[32];
    unsigned char pkt[PKT_LEN(MITM_TEXT_MAX)], out[MITM_TEXT_MAX];
    size_t n, ol = 0;
    replay_state m_rs = {0, 0}, s_rs = {0, 0};

    crypto_kx_keypair(client.pk, client.sk);
    crypto_kx_keypair(server.pk, server.sk);
    crypto_kx_keypair(mallory.pk, mallory.sk);

    /* Mallory replaces each side's public key with her own. */
    int ok = crypto_kx_client_session_keys(c_rx, c_tx, client.pk, client.sk, mallory.pk) == 0 &&
             crypto_kx_server_session_keys(s_rx, s_tx, server.pk, server.sk, mallory.pk) == 0 &&
             crypto_kx_server_session_keys(mc_rx, mc_tx, mallory.pk, mallory.sk, client.pk) == 0 &&
             crypto_kx_client_session_keys(ms_rx, ms_tx, mallory.pk, mallory.sk, server.pk) == 0;

    n = seal(pkt, sizeof pkt, 1, (const unsigned char *)msg, strlen(msg), c_tx);
    if (ok && n && unseal(out, sizeof out - 1, &ol, pkt, n, mc_rx, &m_rs) == SC_OK) {
        r->plain_read = 1;
        memcpy(r->read_text, out, ol);
        r->read_text[ol] = '\0';
    }
    n = seal(pkt, sizeof pkt, 1, (const unsigned char *)forged, strlen(forged), ms_tx);
    if (ok && n && unseal(out, sizeof out - 1, &ol, pkt, n, s_rx, &s_rs) == SC_OK) {
        r->plain_forge = 1;
        memcpy(r->forged_text, out, ol);
        r->forged_text[ol] = '\0';
    }

    sodium_memzero(client.sk, 32); sodium_memzero(server.sk, 32); sodium_memzero(mallory.sk, 32);
    sodium_memzero(c_rx, 32);  sodium_memzero(c_tx, 32);  sodium_memzero(s_rx, 32);  sodium_memzero(s_tx, 32);
    sodium_memzero(mc_rx, 32); sodium_memzero(mc_tx, 32); sodium_memzero(ms_rx, 32); sodium_memzero(ms_tx, 32);
    sodium_memzero(out, sizeof out);
}

static void mitm_signed(mitm_report *r) {
    identity id, mal_id;
    kx_pair client, client2, server, mallory;
    unsigned char sig[SIG_LEN], mal_sig[SIG_LEN];
    unsigned char c_rx[32], c_tx[32], s_rx[32], s_tx[32];
    unsigned char pkt[PKT_LEN(16)], out[16];
    size_t n, ol = 0;
    replay_state s_rs = {0, 0};

    if (identity_load(&id) == 0) r->used_task1_identity = 1;
    else crypto_sign_keypair(id.pk, id.sk);
    crypto_sign_keypair(mal_id.pk, mal_id.sk);
    crypto_kx_keypair(client.pk, client.sk);
    crypto_kx_keypair(client2.pk, client2.sk);
    crypto_kx_keypair(server.pk, server.sk);
    crypto_kx_keypair(mallory.pk, mallory.sk);

    hs_sign(sig, server.pk, client.pk, id.sk);

    int honest = hs_verify(sig, server.pk, client.pk, id.pk) == 0 &&
                 crypto_kx_client_session_keys(c_rx, c_tx, client.pk, client.sk, server.pk) == 0 &&
                 crypto_kx_server_session_keys(s_rx, s_tx, server.pk, server.sk, client.pk) == 0;
    n = seal(pkt, sizeof pkt, 1, (const unsigned char *)"PAY BOB 100", 11, c_tx);
    r->signed_honest = honest && n && unseal(out, sizeof out, &ol, pkt, n, s_rx, &s_rs) == SC_OK;

    r->blocked_key_swap = hs_verify(sig, mallory.pk, client.pk, id.pk) != 0;
    hs_sign(mal_sig, mallory.pk, client.pk, mal_id.sk);
    r->blocked_own_signature = hs_verify(mal_sig, mallory.pk, client.pk, id.pk) != 0;
    r->blocked_replayed_sig = hs_verify(sig, server.pk, client2.pk, id.pk) != 0;

    sodium_memzero(id.sk, sizeof id.sk); sodium_memzero(mal_id.sk, sizeof mal_id.sk);
    sodium_memzero(client.sk, 32); sodium_memzero(client2.sk, 32);
    sodium_memzero(server.sk, 32); sodium_memzero(mallory.sk, 32);
    sodium_memzero(c_rx, 32); sodium_memzero(c_tx, 32); sodium_memzero(s_rx, 32); sodium_memzero(s_tx, 32);
}

void mitm_run(mitm_report *r) {
    memset(r, 0, sizeof *r);
    mitm_plain(r);
    mitm_signed(r);
}
