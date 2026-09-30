/* engine.c - sc_engine: machine-readable front end used by the dashboard.
 *
 * Reads one command per line on stdin and writes one JSON object per line on
 * stdout. It holds a live in-process session (session.c), so every result the
 * dashboard shows comes from seal()/unseal() and the other real functions.
 *
 * Secrets never leave this process: responses contain only public keys,
 * nonces, ciphertext, return codes, file metadata and one-way fingerprints.
 *
 * Commands:
 *   hello | status | vault | mitm | rekey | terminate | reset | quit
 *   handshake plain|signed
 *   send <text>                       (1..256 bytes)
 *   attack normal|tamper|aad|replay|reorder|wrongkey|short|forged
 *   wrap correct|wrong                (TEST-ONLY passphrases, never sent out)
 *   config rekey_every <0..1000>
 */
#include "session.h"
#include "wrap.h"
#include "json.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LINE_CAP   1024
#define OUT_CAP    (256 * 1024)
#define MAX_EVENTS 48
#define MSG_CAP    SESSION_MSG_MAX
#define PKT_CAP    PKT_LEN(MSG_CAP)

typedef struct { long long ts; const char *level; char msg[200]; } event;

static session sess;
static unsigned char last_ok[PKT_CAP];   /* last accepted packet (public bytes) */
static size_t last_ok_len;
static event events[MAX_EVENTS];
static int n_events;
static char out_storage[OUT_CAP];
static json_buf J;

/* ---- helpers ------------------------------------------------------------ */

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
}

static double mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

/* Log messages are built from public data only. */
static void ev(const char *level, const char *fmt, ...) {
    if (n_events >= MAX_EVENTS) return;
    event *e = &events[n_events++];
    e->ts = now_ms();
    e->level = level;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(e->msg, sizeof e->msg, fmt, ap);
    va_end(ap);
}

static void fp_json(const char *key, const unsigned char *data, size_t len) {
    unsigned char fp[FINGERPRINT_LEN];
    char s[32];
    key_fingerprint(fp, data, len);
    fingerprint_str(s, fp);
    json_str(&J, key, s);
}

static const char *verdict(int rc) {
    switch (rc) {
    case SC_OK:         return "ACCEPTED";
    case SC_ERR_SHORT:  return "INVALID PACKET";
    case SC_ERR_AUTH:   return "AUTHENTICATION FAILED";
    case SC_ERR_REPLAY: return "REPLAY DETECTED";
    case SESSION_ERR_STATE: return "NOT IN SECURE STATE";
    default:            return "REJECTED";
    }
}

static void begin(const char *cmd) {
    json_init(&J, out_storage, sizeof out_storage);
    n_events = 0;
    json_obj_begin(&J, NULL);
    json_str(&J, "cmd", cmd);
}

static void session_json(void) {
    json_obj_begin(&J, "session");
    json_str(&J, "state", ((const char *[]){ "INIT", "AUTH", "SECURE", "TERMINATE" })[sess.state]);
    json_int(&J, "epoch", (long long)sess.epoch);
    json_int(&J, "next_seq", (long long)sess.next_seq);
    json_bool(&J, "has_seq", sess.server_rs.has_seq);
    json_int(&J, "last_seq", (long long)sess.server_rs.last_seq);
    json_bool(&J, "authenticated", sess.authenticated);
    json_int(&J, "rekey_every", sess.rekey_every);
    json_int(&J, "in_epoch", sess.in_epoch);
    if (sess.c_tx != NULL) {
        unsigned char a[FINGERPRINT_LEN], b[FINGERPRINT_LEN], c[FINGERPRINT_LEN], d[FINGERPRINT_LEN];
        char s[32];
        session_fingerprints(&sess, a, b, c, d);
        json_obj_begin(&J, "key_fingerprints");
        fingerprint_str(s, a); json_str(&J, "client_tx", s);
        fingerprint_str(s, b); json_str(&J, "client_rx", s);
        fingerprint_str(s, c); json_str(&J, "server_tx", s);
        fingerprint_str(s, d); json_str(&J, "server_rx", s);
        json_obj_end(&J);
    } else {
        json_null(&J, "key_fingerprints");
    }
    json_obj_end(&J);
}

static void finish(int ok, const char *error) {
    json_bool(&J, "ok", ok);
    if (error) json_str(&J, "error", error);
    session_json();
    json_arr_begin(&J, "events");
    for (int i = 0; i < n_events; i++) {
        json_obj_begin(&J, NULL);
        json_int(&J, "ts", events[i].ts);
        json_str(&J, "level", events[i].level);
        json_str(&J, "msg", events[i].msg);
        json_obj_end(&J);
    }
    json_arr_end(&J);
    json_obj_end(&J);
    json_emit(&J);
}

static int need_secure(void) {
    if (sess.state == ST_SECURE) return 1;
    ev("ERROR", "refused: channel is %s, not SECURE", ((const char *[]){ "INIT", "AUTH", "SECURE", "TERMINATE" })[sess.state]);
    finish(0, "Channel is not in SECURE state - run the handshake first");
    return 0;
}

/* Public packet bytes, split into their fields. modified = offset of the byte
 * the attacker changed, or -1. */
static void packet_json(const char *key, const char *role, const unsigned char *pkt,
                        size_t n, int modified) {
    json_obj_begin(&J, key);
    json_str(&J, "role", role);
    json_int(&J, "length", (long long)n);
    json_int(&J, "modified", modified);
    if (n >= SEQ_LEN) {
        char seq[24];
        snprintf(seq, sizeof seq, "%llu", (unsigned long long)load_be64(pkt));
        json_str(&J, "seq", seq);
        json_hex(&J, "seq_hex", pkt, SEQ_LEN);
        json_hex(&J, "aad_hex", pkt, SEQ_LEN);
    }
    if (n >= HDR_LEN) json_hex(&J, "nonce_hex", pkt + SEQ_LEN, NONCE_LEN);
    if (n >= MIN_PKT_LEN) {
        json_int(&J, "ct_len", (long long)(n - MIN_PKT_LEN));
        json_hex(&J, "ct_hex", pkt + HDR_LEN, n - MIN_PKT_LEN);
        json_hex(&J, "tag_hex", pkt + n - TAG_LEN, TAG_LEN);
    } else {
        json_hex(&J, "raw_hex", pkt, n);
    }
    json_obj_end(&J);
}

/* Server-side delivery of one packet, recorded as an attack/send step. */
static int deliver_step(const char *label, const char *role, const unsigned char *pkt,
                        size_t n, int modified) {
    unsigned char pt[MSG_CAP];
    size_t pl = 0;
    int rekeyed = 0;
    uint64_t epoch_before = sess.epoch;
    int rc = session_deliver(&sess, pkt, n, pt, sizeof pt, &pl, &rekeyed);

    json_obj_begin(&J, NULL);
    json_str(&J, "label", label);
    json_int(&J, "rc", rc);
    json_str(&J, "verdict", verdict(rc));
    json_str(&J, "reason", session_strerror(rc));
    packet_json("packet", role, pkt, n, modified);
    json_bool(&J, "rekeyed", rekeyed);
    json_obj_end(&J);

    unsigned long long seq = n >= SEQ_LEN ? (unsigned long long)load_be64(pkt) : 0;
    if (rc == SC_OK) {
        ev("SECURE", "packet seq %llu accepted (%zu B, tag verified)", seq, n);
        if (n <= sizeof last_ok) { memcpy(last_ok, pkt, n); last_ok_len = n; }
    } else if (rc == SC_ERR_REPLAY) {
        ev("BLOCK", "replay/reorder: seq %llu <= last_seq %llu", seq,
           (unsigned long long)sess.server_rs.last_seq);
    } else if (rc == SC_ERR_AUTH) {
        ev("ALERT", "tag verification failed for seq %llu - packet dropped", seq);
    } else if (rc == SC_ERR_SHORT) {
        ev("BLOCK", "malformed packet (%zu B < %d B minimum) dropped", n, MIN_PKT_LEN);
    }
    if (rekeyed)
        ev("AUTH", "re-key: epoch %llu -> %llu, old keys overwritten",
           (unsigned long long)epoch_before, (unsigned long long)sess.epoch);
    sodium_memzero(pt, sizeof pt);
    return rc;
}

static size_t client_seal(const char *text, unsigned char *pkt, size_t cap) {
    size_t n = 0;
    if (session_seal(&sess, (const unsigned char *)text, strlen(text), pkt, cap, &n, NULL) != SESSION_OK)
        return 0;
    return n;
}

/* ---- commands ----------------------------------------------------------- */

static void cmd_hello(void) {
    begin("hello");
    json_str(&J, "libsodium", sodium_version_string());
    json_bool(&J, "aes256gcm_available", crypto_aead_aes256gcm_is_available());
    json_int(&J, "msg_max", MSG_CAP);
    json_obj_begin(&J, "packet_format");
    json_int(&J, "seq", SEQ_LEN);
    json_int(&J, "nonce", NONCE_LEN);
    json_int(&J, "tag", TAG_LEN);
    json_int(&J, "header", HDR_LEN);
    json_int(&J, "min", MIN_PKT_LEN);
    json_obj_end(&J);
    ev("INFO", "libsodium %s initialised", sodium_version_string());
    finish(1, NULL);
}

static void cmd_status(void) {
    begin("status");
    finish(1, NULL);
}

typedef struct {
    const char *path, *algorithm, *kind;
    size_t size;
    unsigned mode;
} key_file;

static void vault_file(const key_file *k) {
    unsigned mode = 0;
    unsigned char buf[WRAPPED_LEN], pk[32];
    int exists = file_mode(k->path, &mode) == 0;
    int loaded = exists && k->size <= sizeof buf && read_file(k->path, buf, k->size) == 0;

    json_obj_begin(&J, NULL);
    json_str(&J, "path", k->path);
    json_str(&J, "algorithm", k->algorithm);
    json_str(&J, "kind", k->kind);
    json_int(&J, "expected_size", (long long)k->size);
    json_bool(&J, "exists", exists);
    json_bool(&J, "loaded", loaded);
    char m[8];
    snprintf(m, sizeof m, "%04o", mode);
    json_str(&J, "mode", exists ? m : NULL);
    snprintf(m, sizeof m, "%04o", k->mode);
    json_str(&J, "expected_mode", m);
    json_bool(&J, "mode_ok", exists && mode == k->mode);

    if (loaded) {
        /* Private keys are identified by the fingerprint of their PUBLIC half. */
        if (strcmp(k->path, SERVER_SIGN_SK) == 0) {
            crypto_sign_ed25519_sk_to_pk(pk, buf);
            fp_json("fingerprint", pk, 32);
            unsigned char file_pk[32], sig[crypto_sign_BYTES];
            static const unsigned char probe[] = "vault self-test";
            int pair = read_file(SERVER_SIGN_PK, file_pk, 32) == 0 &&
                       crypto_sign_detached(sig, NULL, probe, sizeof probe, buf) == 0 &&
                       crypto_sign_verify_detached(sig, probe, sizeof probe, file_pk) == 0;
            json_bool(&J, "pair_ok", pair);
        } else if (strcmp(k->path, SERVER_KX_SK) == 0) {
            unsigned char file_pk[32];
            crypto_scalarmult_base(pk, buf);
            fp_json("fingerprint", pk, 32);
            json_bool(&J, "pair_ok", read_file(SERVER_KX_PK, file_pk, 32) == 0 &&
                                     sodium_memcmp(file_pk, pk, 32) == 0);
        } else {
            fp_json("fingerprint", buf, k->size);   /* public key or ciphertext */
        }
    }
    sodium_memzero(buf, sizeof buf);
    json_obj_end(&J);
}

static void cmd_vault(void) {
    static const key_file files[] = {
        { SERVER_SIGN_PK, "Ed25519", "identity-public",  32, MODE_PUBLIC },
        { SERVER_SIGN_SK, "Ed25519", "identity-private", 64, MODE_PRIVATE },
        { SERVER_KX_PK,   "X25519",  "kx-public",        32, MODE_PUBLIC },
        { SERVER_KX_SK,   "X25519",  "kx-private",       32, MODE_PRIVATE },
        { SERVER_SK_WRAP, "Argon2id + XSalsa20-Poly1305", "wrapped-private", WRAPPED_LEN, MODE_PRIVATE },
    };
    begin("vault");
    unsigned dir_mode = 0;
    char m[8];
    int dir = file_mode(KEY_DIR, &dir_mode) == 0;
    snprintf(m, sizeof m, "%04o", dir_mode);
    json_str(&J, "key_dir_mode", dir ? m : NULL);
    json_arr_begin(&J, "files");
    int all_ok = 1;
    for (size_t i = 0; i < sizeof files / sizeof files[0]; i++) {
        vault_file(&files[i]);
        unsigned mode = 0;
        if (i < 4 && (file_mode(files[i].path, &mode) != 0 || mode != files[i].mode)) all_ok = 0;
    }
    json_arr_end(&J);
    json_bool(&J, "permissions_ok", all_ok);
    ev(all_ok ? "INFO" : "ALERT", "key vault scanned: permissions %s", all_ok ? "0600/0644 verified" : "NOT as expected");
    finish(1, NULL);
}

static void cmd_handshake(const char *arg) {
    int signed_hs = strcmp(arg, "signed") == 0;
    if (!signed_hs && strcmp(arg, "plain") != 0 && arg[0] != '\0') {
        begin("handshake");
        finish(0, "usage: handshake plain|signed");
        return;
    }
    begin("handshake");
    identity id;
    const identity *idp = NULL;
    if (signed_hs) {
        if (identity_load(&id) != 0) {
            ev("ERROR", "signed handshake needs keys/server_pk.bin + server_sk.bin");
            finish(0, "Server identity keys not found - generate keys first");
            return;
        }
        idp = &id;
    }
    double t0 = mono_ms();
    handshake_result hr;
    last_ok_len = 0;
    ev("INFO", "INIT: client and server generate ephemeral X25519 key pairs");
    int rc = session_handshake(&sess, idp, &hr);
    double t1 = mono_ms();

    json_str(&J, "mode", signed_hs ? "signed" : "plain");
    json_hex(&J, "client_pk", sess.client_pk, KX_PK_LEN);
    json_hex(&J, "server_pk", sess.server_pk, KX_PK_LEN);
    fp_json("client_pk_fp", sess.client_pk, KX_PK_LEN);
    fp_json("server_pk_fp", sess.server_pk, KX_PK_LEN);
    json_bool(&J, "complementary", hr.complementary);
    json_bool(&J, "directional", hr.directional);
    json_int(&J, "signature", hr.signature);
    json_num(&J, "elapsed_ms", t1 - t0);
    if (idp) {
        fp_json("identity_fp", id.pk, ID_PK_LEN);
        json_str(&J, "transcript", HS_LABEL " || server_eph_pk || client_eph_pk");
        sodium_memzero(id.sk, sizeof id.sk);
    }
    if (rc != SESSION_OK) {
        ev("ERROR", "handshake failed: %s", session_strerror(rc));
        finish(0, session_strerror(rc));
        return;
    }
    ev("AUTH", "public keys exchanged (client %02x%02x.., server %02x%02x..)",
       sess.client_pk[0], sess.client_pk[1], sess.server_pk[0], sess.server_pk[1]);
    if (signed_hs) ev("AUTH", "server Ed25519 signature over transcript verified by client");
    ev("AUTH", "crypto_kx: rx/tx session keys derived; client_tx == server_rx, client_rx == server_tx");
    ev("WIPE", "ephemeral X25519 secret keys wiped");
    ev("SECURE", "channel SECURE: AEAD + replay window active (epoch 1)");
    finish(1, NULL);
}

static void cmd_send(const char *text) {
    begin("send");
    if (!need_secure()) return;
    size_t len = strlen(text);
    if (len == 0 || len > MSG_CAP) {
        finish(0, "Message must be 1-256 bytes");
        return;
    }
    unsigned char pkt[PKT_CAP];
    size_t n = client_seal(text, pkt, sizeof pkt);
    if (n == 0) { finish(0, "seal() failed"); return; }
    ev("INFO", "client sealed seq %llu: %zu B plaintext -> %zu B packet",
       (unsigned long long)load_be64(pkt), len, n);
    json_arr_begin(&J, "steps");
    int rc = deliver_step("Client -> server", "client", pkt, n, -1);
    json_arr_end(&J);
    json_int(&J, "rc", rc);
    json_bool(&J, "accepted", rc == SC_OK);
    if (rc == SC_OK) json_str(&J, "delivered_text", text);   /* the user's own message */
    finish(1, NULL);
}

/* ---- attack lab --------------------------------------------------------- */

typedef struct {
    const char *id, *title, *network, *verifier;
    int expected_rc;
} attack_info;

static const attack_info ATTACKS[] = {
    { "normal",   "Normal packet",            "Unmodified packet delivered",                       "Length check -> replay window -> Poly1305 tag", SC_OK },
    { "tamper",   "Ciphertext bit flip",      "1 bit flipped in the first ciphertext byte",        "ChaCha20-Poly1305 tag verification",            SC_ERR_AUTH },
    { "aad",      "Sequence / AAD tamper",    "seq field rewritten (+1000) in clear-text header",  "ChaCha20-Poly1305 tag verification (AAD)",      SC_ERR_AUTH },
    { "replay",   "Replay attack",            "Copy of an already-accepted packet re-sent",        "Replay window (seq > last_seq)",                SC_ERR_REPLAY },
    { "reorder",  "Reorder attack",           "Newer packet delivered first, older one held back", "Replay window (seq > last_seq)",                SC_ERR_REPLAY },
    { "wrongkey", "Wrong key (forgery)",      "Packet sealed with an attacker-generated key",      "ChaCha20-Poly1305 tag verification",            SC_ERR_AUTH },
    { "short",    "Short packet",             "Packet truncated to 10 bytes",                      "Length check (minimum 36 B)",                   SC_ERR_SHORT },
    { "forged",   "Forged large sequence",    "seq rewritten to 2^64-1 to poison the replay window", "Tag verification before state update",        SC_ERR_AUTH },
};

static void cmd_attack(const char *type) {
    const attack_info *a = NULL;
    for (size_t i = 0; i < sizeof ATTACKS / sizeof ATTACKS[0]; i++)
        if (strcmp(type, ATTACKS[i].id) == 0) a = &ATTACKS[i];
    begin("attack");
    if (a == NULL) { finish(0, "unknown attack type"); return; }
    if (!need_secure()) return;

    unsigned char p1[PKT_CAP], p2[PKT_CAP];
    size_t n1 = 0, n2 = 0;
    int primary = 0, extra_ok = 1;
    const char *msg = "transfer 100 to Bob";

    ev("INFO", "attack lab: %s", a->title);
    json_arr_begin(&J, "steps");
    if (strcmp(a->id, "normal") == 0) {
        n1 = client_seal(msg, p1, sizeof p1);
        primary = deliver_step("Genuine packet", "client", p1, n1, -1);
    } else if (strcmp(a->id, "tamper") == 0) {
        n1 = client_seal(msg, p1, sizeof p1);
        memcpy(p2, p1, n1);
        p2[HDR_LEN] ^= 0x01;
        replay_state before = sess.server_rs;
        primary = deliver_step("Tampered packet", "attacker", p2, n1, HDR_LEN);
        extra_ok = sess.server_rs.last_seq == before.last_seq && sess.server_rs.has_seq == before.has_seq;
        extra_ok &= deliver_step("Original packet still accepted", "client", p1, n1, -1) == SC_OK;
    } else if (strcmp(a->id, "aad") == 0) {
        n1 = client_seal(msg, p1, sizeof p1);
        memcpy(p2, p1, n1);
        store_be64(p2, load_be64(p1) + 1000);
        primary = deliver_step("seq rewritten", "attacker", p2, n1, SEQ_LEN - 1);
    } else if (strcmp(a->id, "replay") == 0) {
        if (last_ok_len == 0) {
            n1 = client_seal(msg, p1, sizeof p1);
            if (deliver_step("Original packet", "client", p1, n1, -1) != SC_OK) extra_ok = 0;
        }
        memcpy(p2, last_ok, last_ok_len);
        primary = deliver_step("Replayed copy", "attacker", p2, last_ok_len, -1);
    } else if (strcmp(a->id, "reorder") == 0) {
        n1 = client_seal("message #1", p1, sizeof p1);
        n2 = client_seal("message #2", p2, sizeof p2);
        extra_ok = deliver_step("Newer packet (held back one first)", "attacker", p2, n2, -1) == SC_OK;
        primary = deliver_step("Older packet arrives late", "attacker", p1, n1, -1);
    } else if (strcmp(a->id, "wrongkey") == 0) {
        unsigned char k[KEY_LEN];
        crypto_aead_chacha20poly1305_ietf_keygen(k);
        n1 = seal(p1, sizeof p1, sess.next_seq, (const unsigned char *)msg, strlen(msg), k);
        sodium_memzero(k, sizeof k);
        primary = deliver_step("Packet sealed with attacker key", "attacker", p1, n1, -1);
    } else if (strcmp(a->id, "short") == 0) {
        n1 = client_seal(msg, p1, sizeof p1);
        primary = deliver_step("Truncated packet", "attacker", p1, 10, -1);
    } else { /* forged */
        n1 = client_seal(msg, p1, sizeof p1);
        memcpy(p2, p1, n1);
        store_be64(p2, UINT64_MAX);
        replay_state before = sess.server_rs;
        primary = deliver_step("Forged seq = 2^64-1", "attacker", p2, n1, SEQ_LEN - 1);
        extra_ok = sess.server_rs.last_seq == before.last_seq && sess.server_rs.has_seq == before.has_seq;
        json_obj_begin(&J, NULL);
        json_str(&J, "label", "Replay state after forgery");
        json_str(&J, "verdict", extra_ok ? "UNCHANGED" : "CHANGED");
        json_str(&J, "reason", extra_ok ? "last_seq not moved: state updates only after the tag verifies"
                                        : "last_seq was modified by an unauthenticated packet");
        json_obj_end(&J);
        n2 = client_seal("genuine follow-up", p1, sizeof p1);
        extra_ok &= deliver_step("Later genuine packet", "client", p1, n2, -1) == SC_OK;
    }
    json_arr_end(&J);

    int pass = primary == a->expected_rc && extra_ok;
    json_obj_begin(&J, "attack");
    json_str(&J, "id", a->id);
    json_str(&J, "title", a->title);
    json_str(&J, "network", a->network);
    json_str(&J, "verifier", a->verifier);
    json_int(&J, "expected_rc", a->expected_rc);
    json_str(&J, "expected", a->expected_rc == SC_OK ? "ACCEPTED" : "BLOCKED");
    json_int(&J, "rc", primary);
    json_str(&J, "result", primary == SC_OK ? "ACCEPTED" : "BLOCKED");
    json_str(&J, "verdict", verdict(primary));
    json_str(&J, "reason", session_strerror(primary));
    json_bool(&J, "pass", pass);
    json_obj_end(&J);
    ev(pass ? "INFO" : "ERROR", "attack '%s': %s (%s) - %s", a->id,
       primary == SC_OK ? "ACCEPTED" : "BLOCKED", session_strerror(primary),
       pass ? "behaved as expected" : "UNEXPECTED RESULT");
    finish(1, NULL);
}

static void cmd_rekey(void) {
    begin("rekey");
    if (!need_secure()) return;
    unsigned char before[FINGERPRINT_LEN], x[FINGERPRINT_LEN], y[FINGERPRINT_LEN], z[FINGERPRINT_LEN];
    char s[32];
    session_fingerprints(&sess, before, x, y, z);
    uint64_t old_epoch = sess.epoch;
    int rc = session_rekey(&sess);
    fingerprint_str(s, before);
    json_str(&J, "old_client_tx_fp", s);
    json_int(&J, "old_epoch", (long long)old_epoch);
    if (rc != SESSION_OK) { finish(0, session_strerror(rc)); return; }
    ev("AUTH", "re-key: epoch %llu -> %llu via crypto_kdf_derive_from_key(\"%s\")",
       (unsigned long long)old_epoch, (unsigned long long)sess.epoch, REKEY_CONTEXT);
    ev("WIPE", "epoch %llu keys overwritten in place", (unsigned long long)old_epoch);
    finish(1, NULL);
}

static void cmd_config(const char *arg) {
    begin("config");
    char *end = NULL;
    if (strncmp(arg, "rekey_every ", 12) != 0) { finish(0, "usage: config rekey_every <0..1000>"); return; }
    long v = strtol(arg + 12, &end, 10);
    if (end == arg + 12 || *end != '\0' || v < 0 || v > 1000) {
        finish(0, "rekey_every must be 0..1000");
        return;
    }
    sess.rekey_every = (uint32_t)v;
    if (v) ev("INFO", "automatic re-key every %ld accepted messages", v);
    else   ev("INFO", "automatic re-key disabled");
    finish(1, NULL);
}

static void cmd_wrap(const char *which) {
    int correct = strcmp(which, "correct") == 0;
    begin("wrap");
    if (!correct && strcmp(which, "wrong") != 0) { finish(0, "usage: wrap correct|wrong"); return; }

    unsigned char sk[WRAP_SK_LEN], back[WRAP_SK_LEN], file[WRAPPED_LEN];
    if (read_file(SERVER_SIGN_SK, sk, sizeof sk) != 0) {
        ev("ERROR", "no Ed25519 private key to wrap");
        finish(0, "keys/server_sk.bin not found - generate keys first");
        return;
    }
    double t0 = mono_ms();
    int w = wrap_buf(file, sk, WRAP_TEST_ONLY_GOOD_PASS, strlen(WRAP_TEST_ONLY_GOOD_PASS));
    double t1 = mono_ms();
    if (w != 0 || write_file_0600(SERVER_SK_WRAP, file, sizeof file) != 0) {
        sodium_memzero(sk, sizeof sk);
        finish(0, "wrapping failed");
        return;
    }
    ev("INFO", "Argon2id (64 MiB) derived wrapping key in %.0f ms", t1 - t0);
    ev("INFO", "private key sealed with crypto_secretbox -> %s (%d B, 0600)", SERVER_SK_WRAP, WRAPPED_LEN);

    const char *pw = correct ? WRAP_TEST_ONLY_GOOD_PASS : WRAP_TEST_ONLY_BAD_PASS;
    double t2 = mono_ms();
    int u = unwrap_file(SERVER_SK_WRAP, back, pw, strlen(pw));
    double t3 = mono_ms();
    int matches = u == 0 && sodium_memcmp(sk, back, sizeof sk) == 0;
    int zeroed = sodium_is_zero(back, sizeof back);
    unsigned mode = 0;
    file_mode(SERVER_SK_WRAP, &mode);

    json_str(&J, "password", correct ? "correct (test-only value, not shown)" : "wrong (test-only value, not shown)");
    json_str(&J, "kdf", "Argon2id v1.3");
    json_int(&J, "memlimit_mib", (long long)(WRAP_MEMLIMIT / (1024 * 1024)));
    json_int(&J, "opslimit", (long long)WRAP_OPSLIMIT);
    json_hex(&J, "salt_hex", file, WRAP_SALT_LEN);
    json_hex(&J, "nonce_hex", file + WRAP_SALT_LEN, WRAP_NONCE_LEN);
    json_int(&J, "file_size", WRAPPED_LEN);
    char m[8];
    snprintf(m, sizeof m, "%04o", mode);
    json_str(&J, "file_mode", m);
    json_num(&J, "wrap_ms", t1 - t0);
    json_num(&J, "unwrap_ms", t3 - t2);
    json_bool(&J, "mac_verified", u == 0);
    json_bool(&J, "unwrapped", matches);
    json_bool(&J, "secret_released", u == 0);
    json_bool(&J, "output_zeroed", u != 0 && zeroed);
    json_bool(&J, "pass", correct ? matches : (u != 0 && zeroed));

    if (u == 0) ev("INFO", "unwrap successful: MAC verified, key matches original (not displayed)");
    else        ev("BLOCK", "unwrap refused: MAC check failed, no key material released");
    sodium_memzero(sk, sizeof sk);
    sodium_memzero(back, sizeof back);
    ev("WIPE", "private key and derived wrapping key wiped");
    finish(1, NULL);
}

static void cmd_mitm(void) {
    begin("mitm");
    mitm_report r;
    mitm_run(&r);
    json_obj_begin(&J, "plain");
    json_bool(&J, "mallory_read", r.plain_read);
    json_str(&J, "read_text", r.read_text);
    json_bool(&J, "mallory_forged", r.plain_forge);
    json_str(&J, "forged_text", r.forged_text);
    json_obj_end(&J);
    json_obj_begin(&J, "signed");
    json_bool(&J, "task1_identity", r.used_task1_identity);
    json_bool(&J, "honest_ok", r.signed_honest);
    json_bool(&J, "blocked_key_swap", r.blocked_key_swap);
    json_bool(&J, "blocked_own_signature", r.blocked_own_signature);
    json_bool(&J, "blocked_replayed_signature", r.blocked_replayed_sig);
    json_obj_end(&J);
    int shown = r.plain_read && r.plain_forge;
    int fixed = r.signed_honest && r.blocked_key_swap && r.blocked_own_signature && r.blocked_replayed_sig;
    json_bool(&J, "vulnerability_shown", shown);
    json_bool(&J, "extension_blocks_mitm", fixed);
    if (shown) ev("ALERT", "plain crypto_kx: MITM read and rewrote traffic (known limitation)");
    ev(fixed ? "AUTH" : "ERROR", "signed handshake: %s", fixed ? "all 3 MITM variants blocked" : "UNEXPECTED RESULT");
    finish(1, NULL);
}

static void cmd_terminate(void) {
    begin("terminate");
    int had = sess.c_tx != NULL;
    session_close(&sess);
    last_ok_len = 0;
    ev("WIPE", had ? "session keys zeroed and freed (sodium_free)" : "no session keys were in memory");
    ev("INFO", "channel TERMINATED");
    finish(1, NULL);
}

static void cmd_reset(void) {
    begin("reset");
    uint32_t every = sess.rekey_every;
    session_close(&sess);
    session_init(&sess);
    sess.rekey_every = every;
    last_ok_len = 0;
    ev("INFO", "session reset to INIT");
    finish(1, NULL);
}

/* ---- main loop ---------------------------------------------------------- */

int main(void) {
    if (sodium_init() < 0) {
        fputs("{\"cmd\":\"ready\",\"ok\":false,\"error\":\"sodium_init failed\"}\n", stdout);
        return 1;
    }
    session_init(&sess);
    begin("ready");
    json_str(&J, "engine", "sc_engine");
    json_str(&J, "libsodium", sodium_version_string());
    finish(1, NULL);

    char line[LINE_CAP];
    while (fgets(line, sizeof line, stdin) != NULL) {
        if (strchr(line, '\n') == NULL && !feof(stdin)) {   /* over-long line */
            int c;
            while ((c = getchar()) != '\n' && c != EOF) { }
            begin("error");
            finish(0, "command line too long");
            continue;
        }
        line[strcspn(line, "\r\n")] = '\0';
        char *arg = strchr(line, ' ');
        if (arg) *arg++ = '\0';
        else arg = line + strlen(line);

        if      (strcmp(line, "hello") == 0)     cmd_hello();
        else if (strcmp(line, "status") == 0)    cmd_status();
        else if (strcmp(line, "vault") == 0)     cmd_vault();
        else if (strcmp(line, "handshake") == 0) cmd_handshake(arg);
        else if (strcmp(line, "send") == 0)      cmd_send(arg);
        else if (strcmp(line, "attack") == 0)    cmd_attack(arg);
        else if (strcmp(line, "rekey") == 0)     cmd_rekey();
        else if (strcmp(line, "config") == 0)    cmd_config(arg);
        else if (strcmp(line, "wrap") == 0)      cmd_wrap(arg);
        else if (strcmp(line, "mitm") == 0)      cmd_mitm();
        else if (strcmp(line, "terminate") == 0) cmd_terminate();
        else if (strcmp(line, "reset") == 0)     cmd_reset();
        else if (strcmp(line, "quit") == 0)      break;
        else if (line[0] != '\0') { begin("error"); finish(0, "unknown command"); }
    }
    session_close(&sess);
    return 0;
}
