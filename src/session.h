/* session.h - in-process client/server channel with the INIT -> AUTH ->
 * SECURE -> TERMINATE state machine. Used by the engine (dashboard), the
 * terminal demo and the extended tests.
 */
#ifndef SESSION_H
#define SESSION_H

#include "handshake.h"

#define SESSION_MSG_MAX 256

/* Session results (in addition to the SC_* codes from unseal()). */
#define SESSION_OK          0
#define SESSION_ERR_STATE  -10   /* operation not allowed in the current state */
#define SESSION_ERR_CRYPTO -11   /* key derivation / allocation failed         */
#define SESSION_ERR_SIG    -12   /* handshake signature did not verify         */
#define SESSION_ERR_INPUT  -13   /* message empty or too long                  */

typedef struct {
    channel_state state;
    /* Session keys live in sodium_malloc() memory: guard pages, mlock()ed so
     * they are not swapped to disk, and zeroed by sodium_free(). */
    unsigned char *c_tx, *c_rx, *s_tx, *s_rx;
    uint64_t next_seq;          /* client's send counter            */
    replay_state server_rs;     /* server's replay window           */
    uint64_t epoch;             /* key generation, 1 after handshake */
    uint32_t rekey_every;       /* accepted messages per epoch, 0 = never */
    uint32_t in_epoch;          /* accepted messages in this epoch  */
    int authenticated;          /* 1 if the signed handshake was used */
    unsigned char client_pk[KX_PK_LEN], server_pk[KX_PK_LEN];  /* public */
} session;

typedef struct {
    int complementary;          /* client_tx == server_rx && client_rx == server_tx */
    int directional;            /* client_tx != client_rx */
    int signature;              /* 1 verified, 0 failed, -1 not used */
} handshake_result;

void session_init(session *s);
/* INIT -> AUTH -> SECURE. id == NULL: plain crypto_kx (as in the brief).
 * id != NULL: server signs the transcript, client verifies with id->pk. */
int  session_handshake(session *s, const identity *id, handshake_result *hr);
/* Client side: seal the next message with client_tx. */
int  session_seal(session *s, const unsigned char *pt, size_t pt_len,
                  unsigned char *pkt, size_t pkt_cap, size_t *pkt_len, uint64_t *seq);
/* Server side: unseal with server_rx and the replay window. Returns an SC_*
 * code. On success may re-key; *rekeyed tells the caller. */
int  session_deliver(session *s, const unsigned char *pkt, size_t pkt_len,
                     unsigned char *pt, size_t pt_cap, size_t *pt_len, int *rekeyed);
/* Advance both sides to the next key epoch; old keys are overwritten. */
int  session_rekey(session *s);
/* Fingerprints of the four session keys (for display only). */
void session_fingerprints(const session *s, unsigned char c_tx[FINGERPRINT_LEN],
                          unsigned char c_rx[FINGERPRINT_LEN], unsigned char s_tx[FINGERPRINT_LEN],
                          unsigned char s_rx[FINGERPRINT_LEN]);
/* SECURE (or any state) -> TERMINATE: all key material zeroed and freed. */
void session_close(session *s);
const char *session_strerror(int rc);

#endif
