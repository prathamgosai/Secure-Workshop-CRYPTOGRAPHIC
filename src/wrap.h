/* wrap.h - Task 5 key wrapping: Argon2id + crypto_secretbox.
 * File layout: salt (16) | nonce (24) | MAC (16) + ciphertext (64) = 120 bytes
 */
#ifndef WRAP_H
#define WRAP_H

#include "common.h"

#define WRAP_SALT_LEN   crypto_pwhash_SALTBYTES       /* 16 */
#define WRAP_NONCE_LEN  crypto_secretbox_NONCEBYTES   /* 24 */
#define WRAP_MAC_LEN    crypto_secretbox_MACBYTES     /* 16 */
#define WRAP_KEY_LEN    crypto_secretbox_KEYBYTES     /* 32 */
#define WRAP_SK_LEN     crypto_sign_SECRETKEYBYTES    /* 64 */
#define WRAPPED_LEN     (WRAP_SALT_LEN + WRAP_NONCE_LEN + WRAP_MAC_LEN + WRAP_SK_LEN)

#define WRAP_OPSLIMIT   crypto_pwhash_OPSLIMIT_INTERACTIVE
#define WRAP_MEMLIMIT   crypto_pwhash_MEMLIMIT_INTERACTIVE   /* 64 MiB */

/* TEST-ONLY passphrases for automated self-tests and the dashboard buttons.
 * They are never printed or sent to the UI. A real deployment must never
 * hard-code a passphrase (use ./keywrap --interactive). */
#define WRAP_TEST_ONLY_GOOD_PASS "correct horse"
#define WRAP_TEST_ONLY_BAD_PASS  "wrong pass"

int wrap_buf(unsigned char out[WRAPPED_LEN], const unsigned char sk[WRAP_SK_LEN],
             const char *pw, size_t pw_len);
/* Returns 0 only if the MAC verifies; on failure sk is zeroed. */
int unwrap_buf(unsigned char sk[WRAP_SK_LEN], const unsigned char in[WRAPPED_LEN],
               const char *pw, size_t pw_len);
int wrap_file(const char *path, const unsigned char sk[WRAP_SK_LEN], const char *pw, size_t pw_len);
int unwrap_file(const char *path, unsigned char sk[WRAP_SK_LEN], const char *pw, size_t pw_len);

#endif
