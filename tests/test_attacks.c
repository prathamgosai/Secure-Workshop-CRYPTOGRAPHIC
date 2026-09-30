/* Task 4 - attack simulations against seal()/unseal().
 *
 * Usage: ./test_attacks          boxed report
 *        ./test_attacks --tap    one "ok N - name" line per test (used by ./demo --audit)
 */
#include "../src/common.h"
#include "../src/ui.h"
#include <stdio.h>
#include <string.h>

#define MAX_TESTS 16

typedef struct { const char *name; const char *detail; int ok; } result;
static result results[MAX_TESTS];
static int n_results, passed, failed;

static void check(const char *name, const char *detail, int cond) {
    if (n_results < MAX_TESTS) results[n_results++] = (result){ name, detail, cond };
    if (cond) passed++; else failed++;
}

int main(int argc, char **argv) {
    int tap = (argc > 1 && strcmp(argv[1], "--tap") == 0);
    ui_init();
    if (sodium_init() < 0) {
        ui_error("libsodium failed to initialise", "sodium_init() returned < 0", "Aborting tests");
        return 1;
    }

    unsigned char key[KEY_LEN], key2[KEY_LEN];
    unsigned char pkt[PKT_LEN(64)], pkt2[PKT_LEN(64)], out[64];
    size_t ol = 0, n, n2, n3;
    const unsigned char *m = (const unsigned char *)"attack at dawn";
    const size_t ml = 14;
    replay_state rs;

    crypto_aead_chacha20poly1305_ietf_keygen(key);
    crypto_aead_chacha20poly1305_ietf_keygen(key2);

    /* 1. Normal packet decrypts to the original message. */
    memset(&rs, 0, sizeof rs);
    n = seal(pkt, sizeof pkt, 1, m, ml, key);
    check("Round-trip decrypts", "rc 0",
          n > 0 && unseal(out, sizeof out, &ol, pkt, n, key, &rs) == SC_OK &&
          ol == ml && memcmp(out, m, ml) == 0);

    /* 2. One flipped ciphertext bit breaks the Poly1305 tag. */
    memset(&rs, 0, sizeof rs);
    n = seal(pkt, sizeof pkt, 1, m, ml, key);
    pkt[HDR_LEN] ^= 0x01;
    check("Tamper: flip ciphertext byte -> reject", "rc -2",
          unseal(out, sizeof out, &ol, pkt, n, key, &rs) == SC_ERR_AUTH);

    /* 3. seq is clear text but is AAD, so changing it breaks the tag. */
    memset(&rs, 0, sizeof rs);
    n = seal(pkt, sizeof pkt, 1, m, ml, key);
    pkt[7] ^= 0x01;                                   /* seq 1 -> 0 */
    check("AAD tamper: change seq -> reject", "rc -2",
          unseal(out, sizeof out, &ol, pkt, n, key, &rs) == SC_ERR_AUTH);

    /* 4. The same valid packet delivered twice. */
    memset(&rs, 0, sizeof rs);
    n = seal(pkt, sizeof pkt, 1, m, ml, key);
    int first = unseal(out, sizeof out, &ol, pkt, n, key, &rs);
    check("Replay: second copy rejected", "rc -3",
          first == SC_OK && unseal(out, sizeof out, &ol, pkt, n, key, &rs) == SC_ERR_REPLAY);

    /* 5. seq 3 arrives, then the older seq 2. */
    memset(&rs, 0, sizeof rs);
    n3 = seal(pkt, sizeof pkt, 3, m, ml, key);
    n2 = seal(pkt2, sizeof pkt2, 2, m, ml, key);
    int a = unseal(out, sizeof out, &ol, pkt, n3, key, &rs);
    check("Reorder: seq 3 then seq 2 -> seq 2 rejected", "rc -3",
          a == SC_OK && unseal(out, sizeof out, &ol, pkt2, n2, key, &rs) == SC_ERR_REPLAY);

    /* 6. Decrypting with any other key fails authentication. */
    memset(&rs, 0, sizeof rs);
    n = seal(pkt, sizeof pkt, 1, m, ml, key);
    check("Wrong key -> reject", "rc -2",
          unseal(out, sizeof out, &ol, pkt, n, key2, &rs) == SC_ERR_AUTH);

    /* 7. A packet shorter than header + tag is rejected before any crypto. */
    memset(&rs, 0, sizeof rs);
    check("Short packet -> reject", "rc -1",
          unseal(out, sizeof out, &ol, pkt, 10, key, &rs) == SC_ERR_SHORT);

    /* 8. A forged packet with a huge seq must not move last_seq. */
    memset(&rs, 0, sizeof rs);
    n = seal(pkt, sizeof pkt, 1000, m, ml, key);
    pkt[HDR_LEN] ^= 1;
    int forged = unseal(out, sizeof out, &ol, pkt, n, key, &rs);
    int untouched = (rs.has_seq == 0);
    n = seal(pkt2, sizeof pkt2, 5, m, ml, key);
    check("Forged seq=1000 does not poison last_seq", "rc 0",
          forged == SC_ERR_AUTH && untouched &&
          unseal(out, sizeof out, &ol, pkt2, n, key, &rs) == SC_OK);

    sodium_memzero(key, sizeof key);
    sodium_memzero(key2, sizeof key2);

    if (tap) {
        printf("1..%d\n", n_results);
        for (int i = 0; i < n_results; i++)
            printf("%sok %d - %s\n", results[i].ok ? "" : "not ", i + 1, results[i].name);
    } else {
        printf("\n");
        ui_box_top();
        ui_box_center("%sSECURE CHANNEL ATTACK TEST SUITE%s", C_BOLD, C_RESET);
        ui_box_center("%sChaCha20-Poly1305-IETF · seq as AAD · replay window%s", C_DIM, C_RESET);
        ui_box_sep();
        for (int i = 0; i < n_results; i++) {
            char left[160], right[64];
            snprintf(left, sizeof left, "%s%s%s %s", results[i].ok ? C_GREEN : C_RED,
                     results[i].ok ? "✓" : "✗", C_RESET, results[i].name);
            snprintf(right, sizeof right, "%s%-6s %s%s%s", C_DIM, results[i].detail, C_RESET,
                     results[i].ok ? C_GREEN : C_RED, results[i].ok ? "PASS" : "FAIL");
            snprintf(right + strlen(right), sizeof right - strlen(right), "%s", C_RESET);
            ui_box_row(left, right);
        }
        ui_box_sep();
        if (failed == 0)
            ui_box_center("%s%sRESULT: %d/%d PASS%s", C_BOLD, C_GREEN, passed, n_results, C_RESET);
        else
            ui_box_center("%s%sRESULT: %d/%d PASS, %d FAILED%s", C_BOLD, C_RED, passed,
                          n_results, failed, C_RESET);
        ui_box_bottom();
        printf("  %src -1 short  ·  rc -2 auth fail  ·  rc -3 replay/reorder%s\n", C_DIM, C_RESET);
    }
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
