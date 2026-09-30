/* tcp_server.c - sc_server: secure channel over localhost TCP (stretch 1 + 2 + 3).
 *
 *   ./sc_server [--port 7700] [--rekey N]
 *
 * INIT      load the Ed25519 identity (keys/server_*.bin), listen on 127.0.0.1
 * AUTH      receive client ephemeral key, reply with own ephemeral key signed
 *           over (server_eph || client_eph), derive rx/tx with crypto_kx
 * SECURE    unseal DATA frames (replay window), reply with a sealed ACK;
 *           re-key every N accepted messages
 * TERMINATE on BYE / disconnect: session keys zeroed and freed
 */
#include "net.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ROLE "server"

static volatile sig_atomic_t stop_flag;
static void on_signal(int sig) { (void)sig; stop_flag = 1; }

typedef struct {
    unsigned char *rx, *tx;          /* sodium_malloc */
    replay_state rs;
    uint64_t send_seq, epoch;
    uint32_t in_epoch;
} server_keys;

static void keys_free(server_keys *k) {
    sodium_free(k->rx);
    sodium_free(k->tx);
    k->rx = k->tx = NULL;
}

static int handle_client(int fd, const identity *id, uint32_t rekey_every) {
    server_keys k = { NULL, NULL, {0, 0}, 1, 1, 0 };
    unsigned char body[FRAME_MAX], cpk[KX_PK_LEN], spk[KX_PK_LEN], ssk[KX_SK_LEN];
    unsigned char reply[KX_PK_LEN + SIG_LEN + 4];
    uint8_t type = 0;
    size_t len = 0;
    int result = 0;

    net_log(ROLE, "INFO", ST_AUTH, NULL, 0, 0, "client connected - waiting for HELLO");
    if (net_recv_frame(fd, &type, body, sizeof body, &len) != 0 || type != MSG_HELLO || len != KX_PK_LEN) {
        net_log(ROLE, "BLOCK", ST_AUTH, NULL, 0, 0, "malformed HELLO - connection dropped");
        return -1;
    }
    memcpy(cpk, body, KX_PK_LEN);
    crypto_kx_keypair(spk, ssk);
    memcpy(reply, spk, KX_PK_LEN);
    hs_sign(reply + KX_PK_LEN, spk, cpk, id->sk);
    reply[KX_PK_LEN + SIG_LEN + 0] = (unsigned char)(rekey_every >> 24);
    reply[KX_PK_LEN + SIG_LEN + 1] = (unsigned char)(rekey_every >> 16);
    reply[KX_PK_LEN + SIG_LEN + 2] = (unsigned char)(rekey_every >> 8);
    reply[KX_PK_LEN + SIG_LEN + 3] = (unsigned char)rekey_every;

    k.rx = sodium_malloc(SESSION_KEY_LEN);
    k.tx = sodium_malloc(SESSION_KEY_LEN);
    if (!k.rx || !k.tx || crypto_kx_server_session_keys(k.rx, k.tx, spk, ssk, cpk) != 0) {
        sodium_memzero(ssk, sizeof ssk);
        keys_free(&k);
        net_log(ROLE, "ERROR", ST_AUTH, NULL, 0, 0, "session key derivation failed");
        return -1;
    }
    sodium_memzero(ssk, sizeof ssk);
    if (net_send_frame(fd, MSG_SERVER_HELLO, reply, sizeof reply) != 0) {
        keys_free(&k);
        return -1;
    }
    net_log(ROLE, "AUTH", ST_AUTH, NULL, 0, 0,
            "signed SERVER_HELLO sent (Ed25519 over server_eph || client_eph); rx/tx derived");
    net_log(ROLE, "SECURE", ST_SECURE, NULL, 0, 0, "channel SECURE (epoch 1, re-key every %u)", rekey_every);

    while (!stop_flag) {
        int r = net_recv_frame(fd, &type, body, sizeof body, &len);
        if (r == -2) {
            net_log(ROLE, "BLOCK", ST_SECURE, NULL, 0, 0, "oversized/empty frame - connection dropped");
            result = -1;
            break;
        }
        if (r != 0) {
            net_log(ROLE, "INFO", ST_SECURE, NULL, 0, 0, "client disconnected");
            break;
        }
        if (type == MSG_BYE) {
            net_log(ROLE, "INFO", ST_SECURE, NULL, 0, 0, "BYE received");
            break;
        }
        if (type != MSG_DATA) {
            net_log(ROLE, "BLOCK", ST_SECURE, NULL, 0, 0, "unexpected frame type %u ignored", type);
            continue;
        }

        unsigned char pt[SESSION_MSG_MAX];
        size_t pl = 0;
        int rc = unseal(pt, sizeof pt, &pl, body, len, k.rx, &k.rs);
        if (rc != SC_OK) {
            net_log(ROLE, rc == SC_ERR_AUTH ? "ALERT" : "BLOCK", ST_SECURE, body, len, rc,
                    "packet rejected: %s", unseal_strerror(rc));
            unsigned char code = (unsigned char)(-rc);
            if (net_send_frame(fd, MSG_ALERT, &code, 1) != 0) break;
            continue;
        }
        net_log(ROLE, "SECURE", ST_SECURE, body, len, rc, "accepted seq %llu: \"%.*s\"",
                (unsigned long long)load_be64(body), (int)pl, (const char *)pt);
        sodium_memzero(pt, sizeof pt);

        char ack[48];
        int al = snprintf(ack, sizeof ack, "ACK %llu", (unsigned long long)load_be64(body));
        unsigned char out[PKT_LEN(48)];
        size_t n = seal(out, sizeof out, k.send_seq++, (const unsigned char *)ack, (size_t)al, k.tx);
        if (n == 0 || net_send_frame(fd, MSG_DATA, out, n) != 0) break;

        if (rekey_every && ++k.in_epoch >= rekey_every) {
            if (rekey_key(k.rx, k.epoch + 1) != 0 || rekey_key(k.tx, k.epoch + 1) != 0) {
                net_log(ROLE, "ERROR", ST_SECURE, NULL, 0, 0, "re-key failed");
                break;
            }
            k.epoch++;
            k.in_epoch = 0;
            net_log(ROLE, "AUTH", ST_SECURE, NULL, 0, 0, "re-key: now epoch %llu, old keys overwritten",
                    (unsigned long long)k.epoch);
        }
    }
    keys_free(&k);
    net_log(ROLE, "WIPE", ST_TERMINATE, NULL, 0, 0, "session keys zeroed and freed");
    return result;
}

int main(int argc, char **argv) {
    uint16_t port = NET_DEFAULT_PORT;
    uint32_t rekey_every = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            if (parse_port(argv[++i], &port) != 0) { fprintf(stderr, "invalid port\n"); return 2; }
        } else if (strcmp(argv[i], "--rekey") == 0 && i + 1 < argc) {
            long v = strtol(argv[++i], NULL, 10);
            if (v < 0 || v > 1000) { fprintf(stderr, "--rekey must be 0..1000\n"); return 2; }
            rekey_every = (uint32_t)v;
        } else {
            fprintf(stderr, "usage: %s [--port 1024-65535] [--rekey 0-1000]\n", argv[0]);
            return 2;
        }
    }
    if (sodium_init() < 0) return 1;

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;             /* no SA_RESTART: accept()/recv() return EINTR */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    identity id;
    if (identity_load(&id) != 0) {
        net_log(ROLE, "ERROR", ST_INIT, NULL, 0, 0, "no server identity: run ./keygen first");
        return 1;
    }
    int lfd = net_listen(port);
    if (lfd < 0) {
        sodium_memzero(id.sk, sizeof id.sk);
        net_log(ROLE, "ERROR", ST_INIT, NULL, 0, 0, "cannot listen on 127.0.0.1:%u", port);
        return 1;
    }
    net_log(ROLE, "INFO", ST_INIT, NULL, 0, 0, "Ed25519 identity loaded; listening on 127.0.0.1:%u", port);

    while (!stop_flag) {
        int fd = net_accept(lfd);
        if (fd < 0) continue;              /* EINTR on shutdown */
        handle_client(fd, &id, rekey_every);
        close(fd);
        if (!stop_flag) net_log(ROLE, "INFO", ST_INIT, NULL, 0, 0, "waiting for next client");
    }
    close(lfd);
    sodium_memzero(id.sk, sizeof id.sk);
    net_log(ROLE, "WIPE", ST_TERMINATE, NULL, 0, 0, "server stopped; identity key wiped from memory");
    return 0;
}
