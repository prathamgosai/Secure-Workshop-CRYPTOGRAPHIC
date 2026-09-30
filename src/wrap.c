/* wrap.c - Task 5: passphrase-wrapped private key.
 *
 * Argon2id turns passphrase + random salt into a 32-byte key. It is slow and
 * memory-hard on purpose, so every guess costs an attacker time and RAM. The
 * salt means equal passphrases give different keys. crypto_secretbox
 * (XSalsa20-Poly1305) encrypts the key; a wrong passphrase gives a wrong key,
 * the MAC check fails, and nothing is returned.
 */
#include "wrap.h"

static int derive(unsigned char key[WRAP_KEY_LEN], const char *pw, size_t pw_len,
                  const unsigned char salt[WRAP_SALT_LEN]) {
    return crypto_pwhash(key, WRAP_KEY_LEN, pw, pw_len, salt,
                         WRAP_OPSLIMIT, WRAP_MEMLIMIT, crypto_pwhash_ALG_ARGON2ID13);
}

int wrap_buf(unsigned char out[WRAPPED_LEN], const unsigned char sk[WRAP_SK_LEN],
             const char *pw, size_t pw_len) {
    unsigned char key[WRAP_KEY_LEN];
    unsigned char *salt = out, *nonce = out + WRAP_SALT_LEN;
    unsigned char *box = out + WRAP_SALT_LEN + WRAP_NONCE_LEN;
    randombytes_buf(salt, WRAP_SALT_LEN);
    randombytes_buf(nonce, WRAP_NONCE_LEN);
    if (derive(key, pw, pw_len, salt) != 0) return -1;   /* e.g. out of memory */
    int r = crypto_secretbox_easy(box, sk, WRAP_SK_LEN, nonce, key);
    sodium_memzero(key, sizeof key);
    return r;
}

int unwrap_buf(unsigned char sk[WRAP_SK_LEN], const unsigned char in[WRAPPED_LEN],
               const char *pw, size_t pw_len) {
    unsigned char key[WRAP_KEY_LEN];
    const unsigned char *salt = in, *nonce = in + WRAP_SALT_LEN;
    const unsigned char *box = in + WRAP_SALT_LEN + WRAP_NONCE_LEN;
    if (derive(key, pw, pw_len, salt) != 0) {
        sodium_memzero(sk, WRAP_SK_LEN);
        return -1;
    }
    int r = crypto_secretbox_open_easy(sk, box, WRAP_MAC_LEN + WRAP_SK_LEN, nonce, key);
    sodium_memzero(key, sizeof key);
    if (r != 0) sodium_memzero(sk, WRAP_SK_LEN);   /* never release partial output */
    return r;
}

int wrap_file(const char *path, const unsigned char sk[WRAP_SK_LEN], const char *pw, size_t pw_len) {
    unsigned char buf[WRAPPED_LEN];
    if (wrap_buf(buf, sk, pw, pw_len) != 0) return -1;
    return write_file_0600(path, buf, sizeof buf);
}

int unwrap_file(const char *path, unsigned char sk[WRAP_SK_LEN], const char *pw, size_t pw_len) {
    unsigned char buf[WRAPPED_LEN];
    if (read_file(path, buf, sizeof buf) != 0) {
        sodium_memzero(sk, WRAP_SK_LEN);
        return -1;
    }
    return unwrap_buf(sk, buf, pw, pw_len);
}
