/* handshake.h - handshake helpers shared by the demos, the engine and TCP mode:
 * authenticated-handshake transcript, re-keying, public fingerprints, and the
 * MITM scenario used by mitm_demo and the dashboard.
 */
#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include "common.h"

#define KX_PK_LEN   crypto_kx_PUBLICKEYBYTES     /* 32 */
#define KX_SK_LEN   crypto_kx_SECRETKEYBYTES     /* 32 */
#define SESSION_KEY_LEN crypto_kx_SESSIONKEYBYTES /* 32 */
#define ID_PK_LEN   crypto_sign_PUBLICKEYBYTES   /* 32 */
#define ID_SK_LEN   crypto_sign_SECRETKEYBYTES   /* 64 */
#define SIG_LEN     crypto_sign_BYTES            /* 64 */

#define HS_LABEL     "SC-HANDSHAKE-v1"
#define HS_LABEL_LEN (sizeof HS_LABEL - 1)
#define HS_TRANSCRIPT_LEN (HS_LABEL_LEN + 2 * KX_PK_LEN)

#define FINGERPRINT_LEN 8
#define REKEY_CONTEXT "SCREKEY1"   /* crypto_kdf context: exactly 8 bytes */

/* Long-term server identity (Ed25519). */
typedef struct { unsigned char pk[ID_PK_LEN], sk[ID_SK_LEN]; } identity;

void hs_transcript(unsigned char out[HS_TRANSCRIPT_LEN],
                   const unsigned char server_eph[KX_PK_LEN],
                   const unsigned char client_eph[KX_PK_LEN]);
/* Server: sign label || server_eph || client_eph with the identity key. */
int  hs_sign(unsigned char sig[SIG_LEN], const unsigned char server_eph[KX_PK_LEN],
             const unsigned char client_eph[KX_PK_LEN], const unsigned char id_sk[ID_SK_LEN]);
/* Client: 0 only if sig covers (received server key, own key) under the pinned key. */
int  hs_verify(const unsigned char sig[SIG_LEN], const unsigned char server_eph[KX_PK_LEN],
               const unsigned char client_eph[KX_PK_LEN], const unsigned char pinned_pk[ID_PK_LEN]);

/* Loads keys/server_{pk,sk}.bin. Returns 0 on success; the caller must wipe id->sk. */
int  identity_load(identity *id);

/* Replaces key with KDF(key, epoch) in place; the old key is overwritten. */
int  rekey_key(unsigned char key[SESSION_KEY_LEN], uint64_t new_epoch);

/* One-way, domain-separated 8-byte fingerprint. It identifies a key (e.g. to
 * show that client_tx and server_rx match) without revealing it. */
void key_fingerprint(unsigned char out[FINGERPRINT_LEN], const unsigned char *key, size_t len);
void fingerprint_str(char out[32], const unsigned char fp[FINGERPRINT_LEN]);

/* ---- MITM scenario (stretch 2) --------------------------------------- */
#define MITM_TEXT_MAX 32
typedef struct {
    int plain_read;              /* Mallory decrypted the client's message       */
    int plain_forge;             /* server accepted Mallory's rewritten message  */
    char read_text[MITM_TEXT_MAX];
    char forged_text[MITM_TEXT_MAX];
    int used_task1_identity;     /* keys/server_*.bin were used                  */
    int signed_honest;           /* no attacker: verify ok, keys agree, delivered */
    int blocked_key_swap;        /* swapped server key + real signature          */
    int blocked_own_signature;   /* Mallory signs with her own Ed25519 key        */
    int blocked_replayed_sig;    /* signature replayed into another session       */
} mitm_report;

void mitm_run(mitm_report *r);

#endif
