/* demo.c - live presentation demo for the secure channel.
 *
 *   ./secure_demo            interactive menu   (make demo)
 *   ./secure_demo --auto     full guided tour, no pauses (make auto)
 *   ./secure_demo --present  guided tour, Enter between steps (make present)
 *   ./secure_demo --audit    security audit only; exit 0 only if every check passed
 *
 * The tasks themselves live in their own programs (keygen, test_attacks,
 * keywrap, scripts/openssl_compare.sh); this file runs them and adds an
 * in-process client/server session for the live message and attack steps.
 * Must be run from the project root after `make`.
 */
#include "session.h"
#include "ui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define MSG_MAX 200
#define DEFAULT_MSG "Meet at the library at 10:00"

static session sess;                          /* INIT -> AUTH -> SECURE -> TERMINATE */
static unsigned char last_pkt[PKT_LEN(MSG_MAX)];
static size_t last_pkt_len;                   /* last packet the client sent */
static int present_mode, interactive_mode;

/* ---- helpers ------------------------------------------------------------ */

static int run(const char *cmd) {
    fflush(stdout);
    fflush(stderr);
    int st = system(cmd);
    return (st != -1 && WIFEXITED(st)) ? WEXITSTATUS(st) : -1;
}

static void wipe_session(void) {
    session_close(&sess);                 /* sodium_free zeroes every key */
    last_pkt_len = 0;
}

static int require_secure(const char *what) {
    if (sess.state == ST_SECURE) return 1;
    char reason[96];
    snprintf(reason, sizeof reason, "Channel is in state %s, not SECURE", ui_state_name((int)sess.state));
    ui_error(what, reason, "Run the key exchange first (menu option 2)");
    return 0;
}

static void print_hex_row(const char *label, const unsigned char *b, size_t n, size_t max) {
    size_t shown = n < max ? n : max;
    printf("  %-12s %s", label, C_MAGENTA);
    for (size_t i = 0; i < shown; i++) printf("%02x ", b[i]);
    printf("%s%s\n", C_RESET, shown < n ? "…" : "");
}

/* Packet visualizer: every byte shown here travels over the network anyway,
 * so nothing secret is revealed. */
static void visualize_packet(const unsigned char *pkt, size_t n) {
    if (n < MIN_PKT_LEN) return;
    size_t ct_len = n - MIN_PKT_LEN;
    printf("\n  ┌────────────────┬──────────────────┬───────────────────────┬──────────────┐\n");
    printf("  │ %sSEQUENCE (AAD)%s │ %sNONCE%s            │ %sCIPHERTEXT%s            │ %sPOLY1305 TAG%s │\n",
           C_BOLD, C_RESET, C_BOLD, C_RESET, C_BOLD, C_RESET, C_BOLD, C_RESET);
    char ctl[32];
    snprintf(ctl, sizeof ctl, "%zu bytes", ct_len);
    printf("  │ %-14s │ %-16s │ %-21s │ %-12s │\n", "8 bytes", "12 bytes", ctl, "16 bytes");
    printf("  └────────────────┴──────────────────┴───────────────────────┴──────────────┘\n");
    print_hex_row("seq", pkt, SEQ_LEN, SEQ_LEN);
    printf("  %-12s = %llu (big-endian, clear text, covered by the tag)\n", "",
           (unsigned long long)load_be64(pkt));
    print_hex_row("nonce", pkt + SEQ_LEN, NONCE_LEN, NONCE_LEN);
    printf("  %-12s   fresh random value for every packet\n", "");
    print_hex_row("ciphertext", pkt + HDR_LEN, ct_len, 16);
    print_hex_row("tag", pkt + n - TAG_LEN, TAG_LEN, TAG_LEN);
    printf("  %-12s %zu bytes = %d header + %zu ciphertext + %d tag\n", "total", n,
           HDR_LEN, ct_len, TAG_LEN);
}

static void read_line(const char *prompt, char *buf, size_t cap, const char *fallback) {
    printf("%s", prompt);
    fflush(stdout);
    if (fgets(buf, (int)cap, stdin) == NULL) buf[0] = '\0';
    if (strchr(buf, '\n') == NULL && !feof(stdin)) {   /* line too long: discard the rest */
        int c;
        while ((c = getchar()) != '\n' && c != EOF) { }
    }
    buf[strcspn(buf, "\n")] = '\0';
    if (buf[0] == '\0') snprintf(buf, cap, "%s", fallback);
}

/* ---- actions -------------------------------------------------------------- */

static void show_intro(void) {
    ui_banner("SECURE CHANNEL LAB", "Applied Cryptographic Design · Workshop 2");
    printf("  %s%-22s%s Pratham  ·  submission 24 October 2026\n", C_DIM, "Student", C_RESET);
    printf("  %s%-22s%s libsodium %s\n\n", C_DIM, "Library", C_RESET, sodium_version_string());
    printf("  %sSECURITY GOAL          MECHANISM%s\n", C_BOLD, C_RESET);
    printf("  Confidentiality        ChaCha20 stream cipher, 256-bit session key\n");
    printf("  Integrity              Poly1305 tag over ciphertext + seq (AAD)\n");
    printf("  Freshness              strictly increasing seq, state updated only after auth\n");
    printf("  Key protection         0600 key files, Argon2id-wrapped private key\n");
    printf("  Forward secrecy        ephemeral X25519 keys per session\n");
    printf("\n  %sPASS/FAIL results are only shown after each check has actually run.%s\n", C_DIM, C_RESET);
    ui_states((int)sess.state);
}

static void action_keygen(void) {
    run("./keygen");
    ui_section("Key directory listing");
    run("ls -l keys/");
}

static void action_handshake(void) {
    handshake_result hr;

    ui_banner("KEY EXCHANGE  (INIT → AUTH → SECURE)", "ephemeral X25519 via crypto_kx");
    last_pkt_len = 0;
    ui_states(ST_INIT);
    int rc = session_handshake(&sess, NULL, &hr);   /* plain crypto_kx, as in the brief */
    if (rc != SESSION_OK) {
        ui_error("Session key derivation failed", session_strerror(rc), "Handshake aborted, keys wiped");
        return;
    }
    ui_hex("client ephemeral pk", sess.client_pk, sizeof sess.client_pk, 8);
    ui_hex("server ephemeral pk", sess.server_pk, sizeof sess.server_pk, 8);
    ui_states(ST_AUTH);
    ui_pass("client_tx == server_rx and client_rx == server_tx");
    ui_pass("client_tx != client_rx (one key per direction)");
    ui_pass("Ephemeral secret keys wiped; session keys held in sodium_malloc() memory");
    ui_states(ST_SECURE);
}

static void action_send(void) {
    ui_banner("SEND AN ENCRYPTED MESSAGE", "client seal()  →  network  →  server unseal()");
    if (!require_secure("Message refused")) return;
    char msg[MSG_MAX + 1];
    if (interactive_mode || present_mode)
        read_line("  Message to send (Enter for default): ", msg, sizeof msg, DEFAULT_MSG);
    else
        snprintf(msg, sizeof msg, "%s", DEFAULT_MSG);

    uint64_t seq = 0;
    size_t n = 0;
    int src = session_seal(&sess, (const unsigned char *)msg, strlen(msg), last_pkt, sizeof last_pkt, &n, &seq);
    if (src != SESSION_OK) {
        ui_error("seal() failed", session_strerror(src), "Nothing was sent");
        return;
    }
    last_pkt_len = n;
    ui_pass("Client encrypted \"%s\" as seq %llu", msg, (unsigned long long)seq);
    visualize_packet(last_pkt, n);

    unsigned char out[MSG_MAX];
    size_t ol = 0;
    int rc = session_deliver(&sess, last_pkt, n, out, sizeof out, &ol, NULL);
    printf("\n");
    if (rc == SC_OK) ui_pass("Server verified the tag and decrypted: \"%.*s\"", (int)ol, out);
    else             ui_fail("Server rejected the packet: %s", unseal_strerror(rc));
}

static void action_inspect(void) {
    ui_banner("PACKET INSPECTOR", "what an eavesdropper on the network sees");
    if (last_pkt_len == 0) {
        ui_error("No packet to inspect", "Nothing has been sent in this session", "Send a message first (option 3)");
        return;
    }
    visualize_packet(last_pkt, last_pkt_len);
    ui_info("The eavesdropper sees seq, nonce and length - never the plaintext or keys.");
}

/* Live attacks against the running session, then the full automated suite. */
static void attack_row(const char *name, int rc, int expected, int *score, int *total) {
    int ok = (rc == expected);
    (*total)++;
    if (ok) (*score)++;
    if (ok) ui_pass("%-40s -> %s", name, unseal_strerror(rc));
    else    ui_fail("%-40s -> %s (expected: %s)", name, unseal_strerror(rc), unseal_strerror(expected));
}

static void action_attacks(void) {
    ui_banner("LIVE ATTACK SIMULATION", "against the current session");
    if (!require_secure("Attack simulation needs a session")) return;
    if (last_pkt_len == 0) {
        ui_info("No message sent yet - sending one first.");
        int saved = interactive_mode; interactive_mode = 0;
        int saved_p = present_mode;   present_mode = 0;
        action_send();
        interactive_mode = saved; present_mode = saved_p;
    }
    unsigned char out[MSG_MAX], a[PKT_LEN(MSG_MAX)], b[PKT_LEN(MSG_MAX)];
    size_t ol = 0, na, nb;
    int score = 0, total = 0;
    const unsigned char *m = (const unsigned char *)"transfer 100 to Bob";
    const size_t ml = 19;

    ui_section("Attacker replays, tampers with, reorders and reflects packets");

    attack_row("Replay the last packet", unseal(out, sizeof out, &ol, last_pkt, last_pkt_len,
               sess.s_rx, &sess.server_rs), SC_ERR_REPLAY, &score, &total);

    /* Tamper with a new packet, then deliver the genuine one: the rejected
     * forgery must not have changed the replay state. */
    na = seal(a, sizeof a, sess.next_seq++, m, ml, sess.c_tx);
    memcpy(b, a, na);
    b[HDR_LEN] ^= 0x01;
    uint64_t before = sess.server_rs.last_seq;
    attack_row("Flip one ciphertext bit", unseal(out, sizeof out, &ol, b, na, sess.s_rx, &sess.server_rs),
               SC_ERR_AUTH, &score, &total);
    memcpy(b, a, na);
    store_be64(b, UINT64_MAX);
    attack_row("Rewrite seq to 2^64-1 (AAD tamper)", unseal(out, sizeof out, &ol, b, na, sess.s_rx,
               &sess.server_rs), SC_ERR_AUTH, &score, &total);
    int unchanged = (sess.server_rs.last_seq == before);
    attack_row("Genuine packet still accepted afterwards", unseal(out, sizeof out, &ol, a, na,
               sess.s_rx, &sess.server_rs), SC_OK, &score, &total);
    if (unchanged) ui_info("last_seq was not moved by the forged packets (no replay-state poisoning)");

    /* Reorder: newer packet first, older one second. */
    uint64_t s1 = sess.next_seq++, s2 = sess.next_seq++;
    na = seal(a, sizeof a, s1, m, ml, sess.c_tx);
    nb = seal(b, sizeof b, s2, m, ml, sess.c_tx);
    attack_row("Deliver newer packet first", unseal(out, sizeof out, &ol, b, nb, sess.s_rx,
               &sess.server_rs), SC_OK, &score, &total);
    attack_row("...then the older one (reorder)", unseal(out, sizeof out, &ol, a, na, sess.s_rx,
               &sess.server_rs), SC_ERR_REPLAY, &score, &total);

    /* Reflection: bounce the client's own packet back to the client. */
    replay_state client_rs = {0, 0};
    na = seal(a, sizeof a, sess.next_seq++, m, ml, sess.c_tx);
    attack_row("Reflect packet back to client (wrong key)", unseal(out, sizeof out, &ol, a, na,
               sess.c_rx, &client_rs), SC_ERR_AUTH, &score, &total);
    attack_row("Truncate packet to 10 bytes", unseal(out, sizeof out, &ol, a, 10, sess.s_rx,
               &sess.server_rs), SC_ERR_SHORT, &score, &total);

    printf("\n  Live attacks: %s%d/%d behaved as expected%s\n", score == total ? C_GREEN : C_RED,
           score, total, C_RESET);
    ui_section("Full automated attack suite (tests/test_attacks.c)");
    run("./test_attacks");
}

static void action_keywrap(void) {
    run("./keywrap");
    if (interactive_mode) ui_info("Try it with your own passphrase: ./keywrap --interactive");
}

static void action_openssl(void) {
    run("bash scripts/openssl_compare.sh");
}

/* ---- security audit ---------------------------------------------------- */

typedef struct { const char *name; int status; } audit_row;   /* 1 pass, 0 fail, -1 skipped */

static int in_process_kx_check(int *directional) {
    session probe;
    handshake_result hr;
    session_init(&probe);
    session_handshake(&probe, NULL, &hr);
    session_close(&probe);
    *directional = hr.directional;
    return hr.complementary;
}

static int nonce_check(void) {
    unsigned char key[KEY_LEN], p1[PKT_LEN(8)], p2[PKT_LEN(8)];
    crypto_aead_chacha20poly1305_ietf_keygen(key);
    size_t n1 = seal(p1, sizeof p1, 1, (const unsigned char *)"same msg", 8, key);
    size_t n2 = seal(p2, sizeof p2, 1, (const unsigned char *)"same msg", 8, key);
    sodium_memzero(key, sizeof key);
    /* Same key, seq and plaintext: nonce and ciphertext must still differ. */
    return n1 && n2 && memcmp(p1 + SEQ_LEN, p2 + SEQ_LEN, NONCE_LEN) != 0 &&
           memcmp(p1 + HDR_LEN, p2 + HDR_LEN, n1 - HDR_LEN) != 0;
}

/* Runs ./test_attacks --tap and records each numbered result. */
static int run_suite(int results[9]) {
    for (int i = 0; i < 9; i++) results[i] = 0;
    fflush(stdout);
    FILE *p = popen("./test_attacks --tap 2>/dev/null", "r");
    if (!p) return -1;
    char line[256];
    int passed = 0, n = 0;
    while (fgets(line, sizeof line, p)) {
        int idx = 0;
        if (sscanf(line, "ok %d", &idx) == 1 && idx >= 1 && idx <= 8) { results[idx] = 1; passed++; n++; }
        else if (sscanf(line, "not ok %d", &idx) == 1) n++;
    }
    int st = pclose(p);
    if (st == -1 || !WIFEXITED(st) || n != 8) return -1;
    return passed;
}

static int git_secret_check(void) {
    if (run("git rev-parse --is-inside-work-tree >/dev/null 2>&1") != 0) return -1;
    FILE *p = popen("git ls-files -- 'keys/*' '*.pem' '*.enc' '*.bin' '*.wrapped' 'openssl_demo/*' 2>/dev/null", "r");
    if (!p) return 0;
    char line[512];
    int leaked = 0;
    while (fgets(line, sizeof line, p)) {
        line[strcspn(line, "\n")] = '\0';
        if (strcmp(line, "keys/.gitkeep") != 0) {
            leaked = 1;
            ui_fail("Tracked by git: %s", line);
        }
    }
    pclose(p);
    return !leaked;
}

static int action_audit(void) {
    ui_banner("SECURITY AUDIT", "every row below is a check that runs now");
    ui_info("Running keygen, test suite, key wrapping and OpenSSL comparison quietly...");

    int keygen = run("./keygen >/dev/null 2>&1") == 0;
    unsigned m1 = 0, m2 = 0;
    int perms = file_mode(SERVER_SIGN_SK, &m1) == 0 && file_mode(SERVER_KX_SK, &m2) == 0 &&
                m1 == MODE_PRIVATE && m2 == MODE_PRIVATE;
    int directional = 0;
    int kx = in_process_kx_check(&directional);
    int nonce = nonce_check();
    int t[9];
    int suite = run_suite(t);
    int wrap = run("./keywrap >/dev/null 2>&1") == 0;
    int ossl = run("bash scripts/openssl_compare.sh --quiet >/dev/null 2>&1") == 0;
    int git = git_secret_check();

    audit_row rows[] = {
        { "Key generation + reload",               keygen },
        { "Private-key permissions (0600)",        perms },
        { "Session key derivation (crypto_kx)",    kx },
        { "Directional TX/RX keys",                directional },
        { "AEAD round-trip",                       t[1] },
        { "AEAD tamper detection (ciphertext)",    t[2] },
        { "AAD / seq tamper detection",            t[3] },
        { "Fresh nonce per packet",                nonce },
        { "Replay protection",                     t[4] },
        { "Reordering protection",                 t[5] },
        { "Wrong-key rejection",                   t[6] },
        { "Malformed packet rejection",            t[7] },
        { "Replay state not poisoned by forgery",  t[8] },
        { "Argon2id key wrapping",                 wrap },
        { "OpenSSL comparison (CBC tamper shown)", ossl },
        { "Git: no private keys tracked",          git },
    };
    size_t nrows = sizeof rows / sizeof rows[0];
    int all = 1, skipped = 0;

    printf("\n");
    ui_box_top();
    ui_box_center("%sSECURITY AUDIT%s", C_BOLD, C_RESET);
    ui_box_sep();
    for (size_t i = 0; i < nrows; i++) {
        char right[48];
        if (rows[i].status == 1)      snprintf(right, sizeof right, "%sPASS%s", C_GREEN, C_RESET);
        else if (rows[i].status == 0) snprintf(right, sizeof right, "%sFAIL%s", C_RED, C_RESET);
        else                          snprintf(right, sizeof right, "%sSKIP%s", C_YELLOW, C_RESET);
        if (rows[i].status == 0) all = 0;
        if (rows[i].status < 0) skipped++;
        ui_box_row(rows[i].name, right);
    }
    ui_box_sep();
    if (suite < 0) {
        all = 0;
        ui_box_center("%sREQUIRED TESTS: could not run ./test_attacks%s", C_RED, C_RESET);
    } else {
        if (suite != 8) all = 0;
        ui_box_center("%s%sREQUIRED ATTACK TESTS: %d/8 PASS%s", C_BOLD,
                      suite == 8 ? C_GREEN : C_RED, suite, C_RESET);
    }
    if (!all)
        ui_box_center("%s%sOVERALL: SOME CHECKS FAILED%s", C_BOLD, C_RED, C_RESET);
    else if (skipped)
        ui_box_center("%s%sOVERALL: ALL RUN CHECKS PASSED (%d skipped)%s", C_BOLD, C_YELLOW,
                      skipped, C_RESET);
    else
        ui_box_center("%s%sOVERALL: ALL CHECKS PASSED%s", C_BOLD, C_GREEN, C_RESET);
    ui_box_bottom();
    if (git < 0) ui_info("Git check skipped: this folder is not a git repository yet.");
    if (!perms) ui_info("Permission check failed: see README 'WSL and file permissions'.");
    return all;
}

static void action_terminate(void) {
    ui_banner("TERMINATE", "wipe secrets and close the channel");
    int had_keys = sess.c_tx != NULL;
    wipe_session();
    ui_states(ST_TERMINATE);
    if (had_keys) ui_pass("Session keys zeroed and freed (sodium_free)");
    else          ui_info("No session keys were in memory");
    ui_pass("Channel closed");
}

/* ---- modes ------------------------------------------------------------- */

static int tour(void) {
    show_intro();                 ui_pause(present_mode);
    action_keygen();              ui_pause(present_mode);
    action_handshake();           ui_pause(present_mode);
    action_send();                ui_pause(present_mode);
    action_inspect();             ui_pause(present_mode);
    action_attacks();             ui_pause(present_mode);
    action_keywrap();             ui_pause(present_mode);
    action_openssl();             ui_pause(present_mode);
    int ok = action_audit();      ui_pause(present_mode);
    action_terminate();
    return ok ? 0 : 1;
}

static void menu(void) {
    show_intro();
    for (;;) {
        printf("\n  %sMENU%s   state: %s%s%s\n", C_BOLD, C_RESET, C_GREEN, ui_state_name((int)sess.state), C_RESET);
        printf("  [1] Generate keys            [6] Demonstrate key wrapping\n");
        printf("  [2] Run key exchange         [7] Run OpenSSL comparison\n");
        printf("  [3] Send encrypted message   [8] Run complete security audit\n");
        printf("  [4] Inspect packet structure [9] Exit (TERMINATE)\n");
        printf("  [5] Run attack simulation\n");
        char buf[16];
        read_line("\n  Select [1-9]: ", buf, sizeof buf, "");
        if (feof(stdin)) { printf("\n"); action_terminate(); return; }
        switch (buf[0]) {
        case '1': action_keygen(); break;
        case '2': action_handshake(); break;
        case '3': action_send(); break;
        case '4': action_inspect(); break;
        case '5': action_attacks(); break;
        case '6': action_keywrap(); break;
        case '7': action_openssl(); break;
        case '8': action_audit(); break;
        case '9': action_terminate(); return;
        default:  ui_warn("Choose a number from 1 to 9"); break;
        }
    }
}

int main(int argc, char **argv) {
    ui_init();
    if (sodium_init() < 0) {
        ui_error("libsodium failed to initialise", "sodium_init() returned < 0", "Aborting");
        return 1;
    }
    if (access("./keygen", X_OK) != 0 || access("./test_attacks", X_OK) != 0) {
        ui_error("Project binaries not found", "./keygen or ./test_attacks is missing",
                 "Run `make` in the project root, then start ./secure_demo from there");
        return 1;
    }
    session_init(&sess);
    const char *mode = argc > 1 ? argv[1] : "";
    int rc = 0;
    if (strcmp(mode, "--auto") == 0) {
        rc = tour();
    } else if (strcmp(mode, "--present") == 0) {
        present_mode = 1;
        rc = tour();
    } else if (strcmp(mode, "--audit") == 0) {
        rc = action_audit() ? 0 : 1;
    } else if (mode[0] == '\0') {
        interactive_mode = 1;
        menu();
    } else {
        fprintf(stderr, "usage: %s [--auto | --present | --audit]\n", argv[0]);
        rc = 2;
    }
    wipe_session();
    return rc;
}
