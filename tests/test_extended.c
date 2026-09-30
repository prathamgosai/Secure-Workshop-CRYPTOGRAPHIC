/* Extended tests (beyond the 8 required attack tests): packet parsing, buffer
 * limits, key-file permissions, key wrapping, the session state machine,
 * re-keying and the signed handshake.
 *
 * Usage: ./test_extended          boxed report
 *        ./test_extended --tap    one "ok N - name" line per test
 */
#include "../src/session.h"
#include "../src/wrap.h"
#include "../src/ui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_TESTS 40

typedef struct { const char *group, *name; int ok; } result;
static result results[MAX_TESTS];
static int n_results, passed, failed;
static const char *group = "";

static void check(const char *name, int cond) {
    if (n_results < MAX_TESTS) results[n_results++] = (result){ group, name, cond };
    if (cond) passed++; else failed++;
}

static char tmpdir[64];
static void tmp_path(char *out, size_t cap, const char *name) {
    snprintf(out, cap, "%s/%s", tmpdir, name);
}

static void test_packets(void) {
    group = "packet";
    unsigned char key[KEY_LEN], pkt[PKT_LEN(32)], out[32], b[8];
    size_t ol = 0;
    crypto_aead_chacha20poly1305_ietf_keygen(key);

    store_be64(b, 0x0102030405060708ULL);
    check("big-endian seq encode/decode", b[0] == 1 && b[7] == 8 && load_be64(b) == 0x0102030405060708ULL);

    size_t n = seal(pkt, sizeof pkt, 42, (const unsigned char *)"hello", 5, key);
    check("packet length = 20 header + pt + 16 tag", n == PKT_LEN(5) && n == 41);
    check("seq field holds 42 in clear text", load_be64(pkt) == 42);

    check("seal() refuses an output buffer that is too small",
          seal(pkt, PKT_LEN(5) - 1, 1, (const unsigned char *)"hello", 5, key) == 0);
    check("unseal() refuses a plaintext buffer that is too small (-4)",
          unseal(out, 4, &ol, pkt, n, key, NULL) == SC_ERR_BUFFER);
    check("unseal() rejects an oversized packet (-1)",
          unseal(out, sizeof out, &ol, pkt, PKT_LEN(MAX_PT_LEN) + 1, key, NULL) == SC_ERR_SHORT);

    memset(out, 0xAA, sizeof out);
    pkt[n - 1] ^= 1;
    int rc = unseal(out, sizeof out, &ol, pkt, n, key, NULL);
    check("failed tag: rc -2, no length, output buffer zeroed",
          rc == SC_ERR_AUTH && ol == 0 && sodium_is_zero(out, n - MIN_PKT_LEN));
    sodium_memzero(key, sizeof key);
}

static void test_files(void) {
    group = "keyio";
    char p[128], link[128];
    unsigned mode = 0;
    unsigned char k[32] = {1}, back[32];

    tmp_path(p, sizeof p, "priv.bin");
    check("write_file_0600 creates a 0600 file",
          write_file_0600(p, k, sizeof k) == 0 && file_mode(p, &mode) == 0 && mode == 0600);

    tmp_path(p, sizeof p, "loose.bin");
    write_file_pub(p, k, sizeof k);
    check("existing 0644 file is tightened to 0600",
          write_file_0600(p, k, sizeof k) == 0 && file_mode(p, &mode) == 0 && mode == 0600);

    check("read_file rejects a file of the wrong size", read_file(p, back, 16) != 0);
    check("read_file loads the exact bytes", read_file(p, back, 32) == 0 && memcmp(k, back, 32) == 0);

    tmp_path(link, sizeof link, "link.bin");
    int linked = symlink(p, link) == 0;
    check("private-key write refuses a planted symlink (O_NOFOLLOW)",
          linked && write_file_0600(link, k, sizeof k) != 0);
}

static void test_wrap(void) {
    group = "wrap";
    unsigned char sk[WRAP_SK_LEN], back[WRAP_SK_LEN], box[WRAPPED_LEN], box2[WRAPPED_LEN];
    const char *good = WRAP_TEST_ONLY_GOOD_PASS, *bad = WRAP_TEST_ONLY_BAD_PASS;
    randombytes_buf(sk, sizeof sk);

    int w = wrap_buf(box, sk, good, strlen(good));
    check("correct passphrase unwraps the original key",
          w == 0 && unwrap_buf(back, box, good, strlen(good)) == 0 && memcmp(sk, back, sizeof sk) == 0);

    memset(back, 0xAA, sizeof back);
    check("wrong passphrase rejected and nothing released",
          unwrap_buf(back, box, bad, strlen(bad)) != 0 && sodium_is_zero(back, sizeof back));

    memcpy(box2, box, sizeof box);
    box2[WRAPPED_LEN - 1] ^= 1;
    check("tampered wrapped key rejected", unwrap_buf(back, box2, good, strlen(good)) != 0);

    char p[128];
    unsigned mode = 0;
    tmp_path(p, sizeof p, "sk.wrapped");
    check("wrapped key file is 120 B and 0600",
          wrap_file(p, sk, good, strlen(good)) == 0 && file_mode(p, &mode) == 0 && mode == 0600 &&
          read_file(p, box2, WRAPPED_LEN) == 0);
    sodium_memzero(sk, sizeof sk);
    sodium_memzero(back, sizeof back);
}

static void test_session(void) {
    group = "session";
    session s;
    handshake_result hr;
    unsigned char pkt[PKT_LEN(SESSION_MSG_MAX)], out[SESSION_MSG_MAX];
    size_t n = 0, ol = 0;
    int rk = 0;

    session_init(&s);
    check("starts in INIT", s.state == ST_INIT);
    check("seal refused before handshake (INIT)",
          session_seal(&s, (const unsigned char *)"x", 1, pkt, sizeof pkt, &n, NULL) == SESSION_ERR_STATE);

    check("handshake reaches SECURE with complementary, directional keys",
          session_handshake(&s, NULL, &hr) == SESSION_OK && s.state == ST_SECURE &&
          hr.complementary && hr.directional && hr.signature == -1);

    check("message over 256 B refused",
          session_seal(&s, out, SESSION_MSG_MAX + 1, pkt, sizeof pkt, &n, NULL) == SESSION_ERR_INPUT);

    session_seal(&s, (const unsigned char *)"epoch one", 9, pkt, sizeof pkt, &n, NULL);
    check("round trip in SECURE", session_deliver(&s, pkt, n, out, sizeof out, &ol, NULL) == SC_OK &&
                                  ol == 9 && memcmp(out, "epoch one", 9) == 0);

    unsigned char fa[8], fb[8], fc[8], fd[8], ga[8], gb[8], gc[8], gd[8];
    session_fingerprints(&s, fa, fb, fc, fd);
    check("fingerprints show client_tx == server_rx", memcmp(fa, fd, 8) == 0 && memcmp(fb, fc, 8) == 0);

    unsigned char old_pkt[PKT_LEN(8)];
    size_t old_n = 0;
    session_seal(&s, (const unsigned char *)"pre-key", 7, old_pkt, sizeof old_pkt, &old_n, NULL);
    check("manual re-key advances the epoch", session_rekey(&s) == SESSION_OK && s.epoch == 2);
    session_fingerprints(&s, ga, gb, gc, gd);
    check("re-key replaces keys, sides still match",
          memcmp(fa, ga, 8) != 0 && memcmp(ga, gd, 8) == 0 && memcmp(gb, gc, 8) == 0);
    check("packet sealed under the old key is rejected after re-key",
          session_deliver(&s, old_pkt, old_n, out, sizeof out, &ol, NULL) == SC_ERR_AUTH);
    session_seal(&s, (const unsigned char *)"epoch two", 9, pkt, sizeof pkt, &n, NULL);
    check("new epoch round trip", session_deliver(&s, pkt, n, out, sizeof out, &ol, NULL) == SC_OK);

    s.rekey_every = 2;
    s.in_epoch = 0;
    session_seal(&s, (const unsigned char *)"a", 1, pkt, sizeof pkt, &n, NULL);
    session_deliver(&s, pkt, n, out, sizeof out, &ol, &rk);
    int first = rk;
    session_seal(&s, (const unsigned char *)"b", 1, pkt, sizeof pkt, &n, NULL);
    session_deliver(&s, pkt, n, out, sizeof out, &ol, &rk);
    check("automatic re-key after rekey_every accepted messages", !first && rk && s.epoch == 3);

    session_close(&s);
    check("TERMINATE frees all session keys",
          s.state == ST_TERMINATE && !s.c_tx && !s.c_rx && !s.s_tx && !s.s_rx);
    check("deliver refused after TERMINATE",
          session_deliver(&s, pkt, n, out, sizeof out, &ol, NULL) == SESSION_ERR_STATE);
}

static void test_handshake(void) {
    group = "handshake";
    identity id, other;
    unsigned char spk[32], ssk[32], cpk[32], csk[32], mpk[32], msk[32], sig[SIG_LEN];
    crypto_sign_keypair(id.pk, id.sk);
    crypto_sign_keypair(other.pk, other.sk);
    crypto_kx_keypair(spk, ssk);
    crypto_kx_keypair(cpk, csk);
    crypto_kx_keypair(mpk, msk);
    hs_sign(sig, spk, cpk, id.sk);

    check("signature verifies under the pinned key", hs_verify(sig, spk, cpk, id.pk) == 0);
    check("substituted server key fails verification", hs_verify(sig, mpk, cpk, id.pk) != 0);
    check("different pinned key fails verification", hs_verify(sig, spk, cpk, other.pk) != 0);

    session s;
    handshake_result hr;
    session_init(&s);
    check("signed session handshake reaches SECURE",
          session_handshake(&s, &id, &hr) == SESSION_OK && hr.signature == 1 && s.authenticated);
    session_close(&s);

    mitm_report r;
    mitm_run(&r);
    check("plain crypto_kx: MITM succeeds (documented limitation)", r.plain_read && r.plain_forge);
    check("signed handshake: all MITM variants blocked",
          r.signed_honest && r.blocked_key_swap && r.blocked_own_signature && r.blocked_replayed_sig);

    sodium_memzero(id.sk, sizeof id.sk); sodium_memzero(other.sk, sizeof other.sk);
    sodium_memzero(ssk, 32); sodium_memzero(csk, 32); sodium_memzero(msk, 32);
}

int main(int argc, char **argv) {
    int tap = argc > 1 && strcmp(argv[1], "--tap") == 0;
    ui_init();
    if (sodium_init() < 0) return 1;
    snprintf(tmpdir, sizeof tmpdir, "/tmp/sc_test_XXXXXX");
    if (mkdtemp(tmpdir) == NULL) {
        ui_error("Cannot create temp dir", "/tmp not writable", "Aborting");
        return 1;
    }

    test_packets();
    test_files();
    test_wrap();
    test_session();
    test_handshake();

    char cmd[128];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", tmpdir);
    if (system(cmd) != 0) { /* best effort cleanup */ }

    if (tap) {
        printf("1..%d\n", n_results);
        for (int i = 0; i < n_results; i++)
            printf("%sok %d - [%s] %s\n", results[i].ok ? "" : "not ", i + 1, results[i].group, results[i].name);
    } else {
        ui_banner("EXTENDED TEST SUITE", "packets · files · wrapping · state · re-key · handshake");
        for (int i = 0; i < n_results; i++)
            printf("  %s%s%s %s%-9s%s %s\n", results[i].ok ? C_GREEN : C_RED, results[i].ok ? "✓" : "✗",
                   C_RESET, C_DIM, results[i].group, C_RESET, results[i].name);
        printf("\n");
        ui_box_top();
        ui_box_center("%s%sRESULT: %d/%d PASS%s", C_BOLD, failed ? C_RED : C_GREEN, passed, n_results, C_RESET);
        ui_box_bottom();
    }
    printf("\n%d tests, %d passed, %d failed\n", n_results, passed, failed);
    return failed ? 1 : 0;
}
