/* common.h - shared constants, packet format and prototypes.
 *
 * Keeping every length in one place means sender and receiver can never
 * disagree about where the sequence number, nonce or tag start.
 */
#ifndef COMMON_H
#define COMMON_H

#include <sodium.h>
#include <stdint.h>
#include <stddef.h>

/* ---- Key files (Task 1) ------------------------------------------------ */
#define KEY_DIR         "keys"
#define SERVER_SIGN_PK  KEY_DIR "/server_pk.bin"      /* Ed25519 public, 0644 */
#define SERVER_SIGN_SK  KEY_DIR "/server_sk.bin"      /* Ed25519 secret, 0600 */
#define SERVER_KX_PK    KEY_DIR "/server_kx_pk.bin"   /* X25519 public,  0644 */
#define SERVER_KX_SK    KEY_DIR "/server_kx_sk.bin"   /* X25519 secret,  0600 */
#define SERVER_SK_WRAP  KEY_DIR "/server_sk.wrapped"  /* Task 5 output,  0600 */

#define MODE_PRIVATE 0600u
#define MODE_PUBLIC  0644u

/* ---- Packet format (Task 3) --------------------------------------------
 *   [ seq 8 B big-endian ][ nonce 12 B ][ ciphertext + 16 B Poly1305 tag ]
 * The seq bytes are sent in clear but are passed to the AEAD as AAD, so
 * they are covered by the tag.
 */
#define KEY_LEN     crypto_aead_chacha20poly1305_ietf_KEYBYTES   /* 32 */
#define SEQ_LEN     8
#define NONCE_LEN   crypto_aead_chacha20poly1305_ietf_NPUBBYTES  /* 12 */
#define TAG_LEN     crypto_aead_chacha20poly1305_ietf_ABYTES     /* 16 */
#define HDR_LEN     (SEQ_LEN + NONCE_LEN)                        /* 20 */
#define MIN_PKT_LEN (HDR_LEN + TAG_LEN)                          /* 36 */
#define MAX_PT_LEN  65536u               /* policy limit per packet */
#define PKT_LEN(pt_len) ((size_t)HDR_LEN + (size_t)(pt_len) + (size_t)TAG_LEN)

/* unseal() results */
#define SC_OK          0
#define SC_ERR_SHORT  -1   /* too short / too long / malformed      */
#define SC_ERR_AUTH   -2   /* tag did not verify (tamper, wrong key) */
#define SC_ERR_REPLAY -3   /* seq not strictly greater than last    */
#define SC_ERR_BUFFER -4   /* caller's output buffer too small      */

/* Conceptual channel states: INIT -> AUTH -> SECURE -> TERMINATE */
typedef enum { ST_INIT = 0, ST_AUTH, ST_SECURE, ST_TERMINATE } channel_state;

/* Receiver-side replay window: accept only seq > last_seq. */
typedef struct { uint64_t last_seq; int has_seq; } replay_state;

/* ---- keyio.c ----------------------------------------------------------- */
int  ensure_dir(const char *path, unsigned mode);
int  write_file_0600(const char *path, const unsigned char *buf, size_t len);
int  write_file_pub(const char *path, const unsigned char *buf, size_t len);
int  read_file(const char *path, unsigned char *buf, size_t len);
int  file_mode(const char *path, unsigned *mode);
void mode_string(unsigned mode, char out[10]);

/* ---- aead.c ------------------------------------------------------------ */
size_t seal(unsigned char *out, size_t out_cap, uint64_t seq,
            const unsigned char *pt, size_t pt_len,
            const unsigned char key[KEY_LEN]);
int    unseal(unsigned char *pt, size_t pt_cap, size_t *pt_len,
              const unsigned char *pkt, size_t pkt_len,
              const unsigned char key[KEY_LEN], replay_state *rs);
const char *unseal_strerror(int rc);
uint64_t load_be64(const unsigned char b[8]);
void     store_be64(unsigned char b[8], uint64_t v);

#endif
