/* Task 1 - key generation and secure storage.
 *
 * Creates an Ed25519 signing pair and an X25519 key-exchange pair, stores
 * public keys as 0644 and private keys as 0600, reloads the private keys to
 * prove the loader works, and wipes every secret with sodium_memzero().
 * (A plain memset() on a buffer that is never read again may be removed by
 * the optimiser; sodium_memzero() is guaranteed to run.)
 */
#include "common.h"
#include "ui.h"
#include <stdio.h>

static int check_mode(const char *path, unsigned expected, const char *kind) {
    unsigned mode = 0;
    char perm[10];
    if (file_mode(path, &mode) != 0) {
        ui_fail("%-22s cannot stat file", path);
        return 0;
    }
    mode_string(mode, perm);
    if (mode == expected) {
        ui_pass("%-22s -%s  %04o  %s", path, perm, mode, kind);
        return 1;
    }
    ui_fail("%-22s -%s  %04o  %s (expected %04o)", path, perm, mode, kind, expected);
    return 0;
}

int main(void) {
    ui_init();
    ui_banner("TASK 1 - KEY GENERATION & SECURE STORAGE",
              "Ed25519 signing pair + X25519 key-exchange pair");

    if (sodium_init() < 0) {
        ui_error("libsodium failed to initialise", "sodium_init() returned < 0",
                 "Aborting: no key is generated without a working CSPRNG");
        return 1;
    }
    ui_pass("libsodium %s initialised", sodium_version_string());

    if (ensure_dir(KEY_DIR, 0700) != 0) {
        ui_error("Unable to create key directory", KEY_DIR,
                 "Run from the project root and check it is writable");
        return 1;
    }

    unsigned char sign_pk[crypto_sign_PUBLICKEYBYTES], sign_sk[crypto_sign_SECRETKEYBYTES];
    unsigned char kx_pk[crypto_kx_PUBLICKEYBYTES],     kx_sk[crypto_kx_SECRETKEYBYTES];

    /* ---- Generate ---------------------------------------------------- */
    ui_section("Generate key pairs");
    if (crypto_sign_keypair(sign_pk, sign_sk) != 0 || crypto_kx_keypair(kx_pk, kx_sk) != 0) {
        sodium_memzero(sign_sk, sizeof sign_sk);
        sodium_memzero(kx_sk, sizeof kx_sk);
        ui_error("Key generation failed", "libsodium keypair function returned an error", "Aborting");
        return 1;
    }
    ui_pass("Ed25519 signing pair generated      (public %zu B, secret %zu B)",
            sizeof sign_pk, sizeof sign_sk);
    ui_pass("X25519 key-exchange pair generated  (public %zu B, secret %zu B)",
            sizeof kx_pk, sizeof kx_sk);
    ui_hex("Ed25519 public key", sign_pk, sizeof sign_pk, 8);
    ui_hex("X25519 public key", kx_pk, sizeof kx_pk, 8);
    ui_info("Private key bytes are never printed.");

    /* ---- Store ------------------------------------------------------- */
    ui_section("Store keys  (open(O_CREAT, mode) + fchmod: no permission race)");
    int write_ok = 1;
    if (write_file_pub(SERVER_SIGN_PK, sign_pk, sizeof sign_pk) != 0) {
        write_ok = 0; ui_error("Unable to create public-key file", SERVER_SIGN_PK, "Required permission: 0644");
    }
    if (write_file_0600(SERVER_SIGN_SK, sign_sk, sizeof sign_sk) != 0) {
        write_ok = 0; ui_error("Unable to create secure private-key file", SERVER_SIGN_SK, "Required permission: 0600");
    }
    if (write_file_pub(SERVER_KX_PK, kx_pk, sizeof kx_pk) != 0) {
        write_ok = 0; ui_error("Unable to create public-key file", SERVER_KX_PK, "Required permission: 0644");
    }
    if (write_file_0600(SERVER_KX_SK, kx_sk, sizeof kx_sk) != 0) {
        write_ok = 0; ui_error("Unable to create secure private-key file", SERVER_KX_SK, "Required permission: 0600");
    }
    /* The secrets are on disk now (or writing failed): either way this
     * process no longer needs them in memory. */
    sodium_memzero(sign_sk, sizeof sign_sk);
    sodium_memzero(kx_sk, sizeof kx_sk);
    if (!write_ok) return 1;
    ui_pass("4 key files written");

    /* ---- Verify permissions ------------------------------------------ */
    ui_section("Verify file permissions");
    int perms_ok = 1;
    perms_ok &= check_mode(SERVER_SIGN_PK, MODE_PUBLIC,  "public");
    perms_ok &= check_mode(SERVER_SIGN_SK, MODE_PRIVATE, "PRIVATE");
    perms_ok &= check_mode(SERVER_KX_PK,   MODE_PUBLIC,  "public");
    perms_ok &= check_mode(SERVER_KX_SK,   MODE_PRIVATE, "PRIVATE");
    if (!perms_ok)
        ui_warn("This filesystem is not enforcing POSIX permissions. On WSL, a Windows "
                "drive (/mnt/c, /mnt/d) needs the 'metadata' mount option - see README.");

    /* ---- Reload (loader test) ---------------------------------------- */
    ui_section("Reload private keys (loader test)");
    int load_ok = 1;
    unsigned char loaded_sign[crypto_sign_SECRETKEYBYTES], loaded_kx[crypto_kx_SECRETKEYBYTES];
    unsigned char sig[crypto_sign_BYTES], derived_pk[crypto_scalarmult_BYTES];
    static const unsigned char probe[] = "loader self-test";

    /* Functional proof: a signature made with the reloaded secret key must
     * verify under the public key generated above. */
    if (read_file(SERVER_SIGN_SK, loaded_sign, sizeof loaded_sign) == 0 &&
        crypto_sign_detached(sig, NULL, probe, sizeof probe, loaded_sign) == 0 &&
        crypto_sign_verify_detached(sig, probe, sizeof probe, sign_pk) == 0) {
        ui_pass("Ed25519 secret key reloaded; test signature verifies with server_pk.bin");
    } else {
        load_ok = 0;
        ui_error("Ed25519 key reload failed", SERVER_SIGN_SK, "File missing, wrong size, or corrupt");
    }
    /* X25519: public key = scalarmult_base(secret key). */
    if (read_file(SERVER_KX_SK, loaded_kx, sizeof loaded_kx) == 0 &&
        crypto_scalarmult_base(derived_pk, loaded_kx) == 0 &&
        sodium_memcmp(derived_pk, kx_pk, sizeof kx_pk) == 0) {
        ui_pass("X25519 secret key reloaded; recomputed public key matches");
    } else {
        load_ok = 0;
        ui_error("X25519 key reload failed", SERVER_KX_SK, "File missing, wrong size, or corrupt");
    }
    sodium_memzero(loaded_sign, sizeof loaded_sign);
    sodium_memzero(loaded_kx, sizeof loaded_kx);
    ui_pass("Sensitive buffers wiped with sodium_memzero()");

    /* ---- Summary ----------------------------------------------------- */
    printf("\n");
    ui_box_top();
    ui_box_row("libsodium initialised",       "PASS");
    ui_box_row("Key pairs generated",         "PASS");
    ui_box_row("Private keys stored as 0600", perms_ok ? "PASS" : "FAIL");
    ui_box_row("Key reload verified",         load_ok ? "PASS" : "FAIL");
    ui_box_row("Secrets wiped from memory",   "PASS");
    ui_box_bottom();

    if (perms_ok && load_ok) {
        printf("Keys generated and loaded OK\n");
        return 0;
    }
    return 1;
}
