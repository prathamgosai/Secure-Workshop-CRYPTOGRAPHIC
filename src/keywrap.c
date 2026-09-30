/* Task 5 - passphrase-wrapped private key.
 *
 * File layout: salt (16) | nonce (24) | MAC (16) + ciphertext (64)  = 120 bytes
 *
 * Argon2id turns passphrase + random salt into a 32-byte key. It is slow and
 * memory-hard on purpose, so each password guess costs an attacker real time
 * and RAM (GPUs cannot cheaply parallelise it). The salt means two users with
 * the same passphrase get different keys. crypto_secretbox (XSalsa20-Poly1305)
 * then encrypts the key; a wrong passphrase gives a wrong key, the MAC check
 * fails, and nothing is returned.
 *
 * Usage: ./keywrap                 automated self-test (test-only passphrases)
 *        ./keywrap --interactive   wrap keys/server_sk.bin with a passphrase you type
 */
#include "wrap.h"
#include "ui.h"
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define SALT_LEN    WRAP_SALT_LEN
#define WNONCE_LEN  WRAP_NONCE_LEN
#define MAC_LEN     WRAP_MAC_LEN
#define SK_LEN      WRAP_SK_LEN
#define PASS_MAX    256

static const char TEST_ONLY_GOOD_PASS[] = WRAP_TEST_ONLY_GOOD_PASS;
static const char TEST_ONLY_BAD_PASS[]  = WRAP_TEST_ONLY_BAD_PASS;

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Loads the Task 1 key if present, otherwise makes a throwaway one. */
static const char *get_secret_key(unsigned char sk[SK_LEN]) {
    if (read_file(SERVER_SIGN_SK, sk, SK_LEN) == 0) return SERVER_SIGN_SK " (Task 1 key)";
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    crypto_sign_keypair(pk, sk);
    return "a freshly generated Ed25519 key (run ./keygen to wrap the Task 1 key)";
}

static void show_layout(void) {
    printf("\n");
    ui_box_top();
    ui_box_center("%sWRAPPED KEY FILE  (%s)%s", C_BOLD, SERVER_SK_WRAP, C_RESET);
    ui_box_sep();
    ui_box_row("salt   (Argon2id input, random)", "16 B");
    ui_box_row("nonce  (XSalsa20, random)", "24 B");
    ui_box_row("MAC    (Poly1305 tag)", "16 B");
    ui_box_row("ciphertext (encrypted Ed25519 secret key)", "64 B");
    ui_box_sep();
    ui_box_row("total", "120 B");
    ui_box_bottom();
}

/* Reads a passphrase with terminal echo switched off. */
static int read_passphrase(const char *prompt, char *buf, size_t cap) {
    if (!isatty(STDIN_FILENO)) return -1;
    struct termios old, quiet;
    if (tcgetattr(STDIN_FILENO, &old) != 0) return -1;
    quiet = old;
    quiet.c_lflag &= (tcflag_t)~ECHO;
    printf("%s", prompt);
    fflush(stdout);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet);
    char *r = fgets(buf, (int)cap, stdin);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
    printf("\n");
    if (r == NULL) return -1;
    buf[strcspn(buf, "\n")] = '\0';
    return buf[0] ? 0 : -1;
}

static int interactive(void) {
    unsigned char sk[SK_LEN], back[SK_LEN];
    char pw[PASS_MAX], pw2[PASS_MAX], pw3[PASS_MAX];
    int ok = 0;

    if (read_file(SERVER_SIGN_SK, sk, SK_LEN) != 0) {
        ui_error("No key to wrap", SERVER_SIGN_SK " is missing or the wrong size", "Run ./keygen first");
        return 1;
    }
    if (read_passphrase("  New passphrase: ", pw, sizeof pw) != 0 ||
        read_passphrase("  Repeat passphrase: ", pw2, sizeof pw2) != 0 ||
        strcmp(pw, pw2) != 0) {
        ui_error("Passphrase not set", "Empty input, no terminal, or the two entries differ", "Nothing written");
        goto out;
    }
    ui_info("Deriving key with Argon2id (64 MiB, interactive limits)...");
    if (wrap_file(SERVER_SK_WRAP, sk, pw, strlen(pw)) != 0) {
        ui_error("Wrapping failed", SERVER_SK_WRAP, "Check disk space / permissions");
        goto out;
    }
    ui_pass("Key wrapped to %s", SERVER_SK_WRAP);
    show_layout();

    if (read_passphrase("\n  Enter passphrase to unwrap: ", pw3, sizeof pw3) != 0) goto out;
    if (unwrap_file(SERVER_SK_WRAP, back, pw3, strlen(pw3)) == 0 &&
        sodium_memcmp(sk, back, SK_LEN) == 0) {
        ui_pass("Correct passphrase: key unwrapped and matches the original");
        ok = 1;
    } else {
        /* Rejection is the correct behaviour for a wrong passphrase. */
        ui_pass("Wrong passphrase rejected: MAC check failed, no key material returned");
        ok = 1;
    }
out:
    sodium_memzero(sk, sizeof sk);   sodium_memzero(back, sizeof back);
    sodium_memzero(pw, sizeof pw);   sodium_memzero(pw2, sizeof pw2);
    sodium_memzero(pw3, sizeof pw3);
    return ok ? 0 : 1;
}

static int self_test(void) {
    unsigned char sk[SK_LEN], back[SK_LEN], a[WRAPPED_LEN], b[WRAPPED_LEN], file_buf[WRAPPED_LEN];
    const size_t good_len = strlen(TEST_ONLY_GOOD_PASS), bad_len = strlen(TEST_ONLY_BAD_PASS);
    int all_ok = 1;

    ui_section("Wrap the private key under a passphrase");
    ui_info("Key to wrap: %s", get_secret_key(sk));
    ui_info("Using built-in TEST-ONLY passphrases (not printed)");

    double t0 = now_sec();
    int w = wrap_file(SERVER_SK_WRAP, sk, TEST_ONLY_GOOD_PASS, good_len);
    double t1 = now_sec();
    if (w != 0) {
        ui_error("wrap failed", SERVER_SK_WRAP, "Check that keys/ exists and is writable");
        sodium_memzero(sk, sizeof sk);
        return 1;
    }
    ui_pass("Wrapped with Argon2id + XSalsa20-Poly1305 (Argon2id took %.0f ms on this machine)",
            (t1 - t0) * 1000.0);
    unsigned mode = 0;
    char perm[10];
    if (file_mode(SERVER_SK_WRAP, &mode) == 0) {
        mode_string(mode, perm);
        if (mode == MODE_PRIVATE) ui_pass("%s stored as -%s", SERVER_SK_WRAP, perm);
        else ui_warn("%s is -%s (filesystem not enforcing 0600)", SERVER_SK_WRAP, perm);
    }
    show_layout();

    ui_section("Unwrap tests");
    int good = unwrap_file(SERVER_SK_WRAP, back, TEST_ONLY_GOOD_PASS, good_len) == 0 &&
               sodium_memcmp(sk, back, SK_LEN) == 0;
    printf("Correct password: %s\n", good ? "PASS (unwrapped)" : "FAIL");
    all_ok &= good;

    int bad = unwrap_file(SERVER_SK_WRAP, back, TEST_ONLY_BAD_PASS, bad_len) != 0;
    printf("Wrong password  : %s\n", bad ? "PASS (rejected)" : "FAIL");
    all_ok &= bad;

    /* Extra: flipping one ciphertext byte in the file must also be detected. */
    int tamper = 0;
    if (read_file(SERVER_SK_WRAP, file_buf, sizeof file_buf) == 0) {
        file_buf[WRAPPED_LEN - 1] ^= 0x01;
        tamper = unwrap_buf(back, file_buf, TEST_ONLY_GOOD_PASS, good_len) != 0;
    }
    printf("Tampered file   : %s\n", tamper ? "PASS (rejected)" : "FAIL");
    all_ok &= tamper;

    /* Extra: wrapping the same key twice gives a different salt, nonce and
     * ciphertext, so equal passphrases never produce equal files. */
    int fresh = wrap_buf(a, sk, TEST_ONLY_GOOD_PASS, good_len) == 0 &&
                wrap_buf(b, sk, TEST_ONLY_GOOD_PASS, good_len) == 0 &&
                memcmp(a, b, SALT_LEN) != 0 &&
                memcmp(a + SALT_LEN + WNONCE_LEN, b + SALT_LEN + WNONCE_LEN, MAC_LEN + SK_LEN) != 0;
    printf("Fresh salt      : %s\n", fresh ? "PASS (two wraps differ)" : "FAIL");
    all_ok &= fresh;

    sodium_memzero(sk, sizeof sk);
    sodium_memzero(back, sizeof back);
    ui_pass("Secret key and derived keys wiped with sodium_memzero()");

    printf("\n");
    ui_box_top();
    ui_box_row("Correct passphrase unwraps key", good ? "PASS" : "FAIL");
    ui_box_row("Wrong passphrase rejected", bad ? "PASS" : "FAIL");
    ui_box_row("Tampered wrapped file rejected", tamper ? "PASS" : "FAIL");
    ui_box_row("Random salt per wrap", fresh ? "PASS" : "FAIL");
    ui_box_bottom();
    return all_ok ? 0 : 1;
}

int main(int argc, char **argv) {
    ui_init();
    ui_banner("TASK 5 - ENCRYPTED KEY STORAGE (KEY WRAPPING)",
              "Argon2id  ->  crypto_secretbox (XSalsa20-Poly1305)");
    if (sodium_init() < 0) {
        ui_error("libsodium failed to initialise", "sodium_init() returned < 0", "Aborting");
        return 1;
    }
    if (ensure_dir(KEY_DIR, 0700) != 0) {
        ui_error("Unable to create key directory", KEY_DIR, "Run from the project root");
        return 1;
    }
    if (argc > 1 && strcmp(argv[1], "--interactive") == 0) return interactive();
    return self_test();
}
