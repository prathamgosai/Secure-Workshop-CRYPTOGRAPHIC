/* tcp_client.c - sc_client: connects to sc_server over localhost TCP.
 *
 *   ./sc_client [--port 7700]
 *
 * Commands on stdin (one per line):
 *   send <text>     seal and send a message
 *   tamper <text>   send a message with one ciphertext bit flipped
 *   replay          re-send the last packet the server ACCEPTED (must be rejected)
 *   quit            send BYE, wipe keys, exit (also on end of input)
 *
 * The client pins keys/server_pk.bin: if the server's handshake signature
 * does not verify under that key, the handshake is blocked.
 */
#include "net.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ROLE "client"

typedef struct {
    unsigned char *rx, *tx;           /* sodium_malloc */
    replay_state rs;
    uint64_t send_seq, epoch;
    uint32_t rekey_every, in_epoch;
    unsigned char last_ok[PKT_LEN(SESSION_MSG_MAX)];   /* last packet the server accepted */
    size_t last_ok_len;
} client_state;

static void keys_free(client_state *c) {
    sodium_free(c->rx);
    sodium_free(c->tx);
    c->rx = c->tx = NULL;
}

static int handshake(int fd, client_state *c, const unsigned char pinned[ID_PK_LEN]) {
    unsigned char cpk[KX_PK_LEN], csk[KX_SK_LEN], body[FRAME_MAX];
    uint8_t type = 0;
    size_t len = 0;

    crypto_kx_keypair(cpk, csk);
    if (net_send_frame(fd, MSG_HELLO, cpk, sizeof cpk) != 0) goto fail;
    net_log(ROLE, "AUTH", ST_AUTH, NULL, 0, 0, "HELLO sent (ephemeral X25519 public key)");
    if (net_recv_frame(fd, &type, body, sizeof body, &len) != 0 || type != MSG_SERVER_HELLO ||
        len != KX_PK_LEN + SIG_LEN + 4) {
        net_log(ROLE, "BLOCK", ST_AUTH, NULL, 0, 0, "malformed SERVER_HELLO - handshake blocked");
        goto fail;
    }
    if (hs_verify(body + KX_PK_LEN, body, cpk, pinned) != 0) {
        net_log(ROLE, "BLOCK", ST_AUTH, NULL, 0, 0,
                "server signature does NOT verify under pinned server_pk.bin - HANDSHAKE BLOCKED");
        goto fail;
    }
    net_log(ROLE, "AUTH", ST_AUTH, NULL, 0, 0, "server Ed25519 signature verified with pinned key");
    c->rekey_every = ((uint32_t)body[96] << 24) | ((uint32_t)body[97] << 16) |
                     ((uint32_t)body[98] << 8) | body[99];
    c->rx = sodium_malloc(SESSION_KEY_LEN);
    c->tx = sodium_malloc(SESSION_KEY_LEN);
    if (!c->rx || !c->tx || crypto_kx_client_session_keys(c->rx, c->tx, cpk, csk, body) != 0) {
        net_log(ROLE, "ERROR", ST_AUTH, NULL, 0, 0, "session key derivation failed");
        goto fail;
    }
    sodium_memzero(csk, sizeof csk);
    c->send_seq = 1;
    c->epoch = 1;
    net_log(ROLE, "SECURE", ST_SECURE, NULL, 0, 0, "channel SECURE (epoch 1, re-key every %u)", c->rekey_every);
    return 0;
fail:
    sodium_memzero(csk, sizeof csk);
    keys_free(c);
    return -1;
}

/* Waits for the server's ACK (sealed) or ALERT for the packet just sent.
 * Returns 1 if the server accepted it, 0 if rejected, -1 on connection error. */
static int await_reply(int fd, client_state *c) {
    unsigned char body[FRAME_MAX], pt[64];
    uint8_t type = 0;
    size_t len = 0, pl = 0;
    if (net_recv_frame(fd, &type, body, sizeof body, &len) != 0) {
        net_log(ROLE, "ERROR", ST_SECURE, NULL, 0, 0, "connection lost");
        return -1;
    }
    if (type == MSG_ALERT && len == 1) {
        int rc = -(int)body[0];
        net_log(ROLE, "BLOCK", ST_SECURE, NULL, 0, rc, "server rejected packet: %s", unseal_strerror(rc));
        return 0;
    }
    if (type != MSG_DATA) return 0;
    int rc = unseal(pt, sizeof pt, &pl, body, len, c->rx, &c->rs);
    if (rc != SC_OK) {
        net_log(ROLE, "ALERT", ST_SECURE, body, len, rc, "server reply rejected: %s", unseal_strerror(rc));
        return 0;
    }
    net_log(ROLE, "SECURE", ST_SECURE, body, len, rc, "server reply authenticated: \"%.*s\"", (int)pl, (const char *)pt);
    if (c->rekey_every && ++c->in_epoch >= c->rekey_every) {
        if (rekey_key(c->rx, c->epoch + 1) != 0 || rekey_key(c->tx, c->epoch + 1) != 0) return -1;
        c->epoch++;
        c->in_epoch = 0;
        net_log(ROLE, "AUTH", ST_SECURE, NULL, 0, 0, "re-key: now epoch %llu, old keys overwritten",
                (unsigned long long)c->epoch);
    }
    return 1;
}

static int send_message(int fd, client_state *c, const char *text, int tamper) {
    size_t tl = strlen(text);
    if (tl == 0 || tl > SESSION_MSG_MAX) {
        net_log(ROLE, "ERROR", ST_SECURE, NULL, 0, 0, "message must be 1-%d bytes", SESSION_MSG_MAX);
        return 0;
    }
    unsigned char wire[PKT_LEN(SESSION_MSG_MAX)];
    size_t n = seal(wire, sizeof wire, c->send_seq++, (const unsigned char *)text, tl, c->tx);
    if (n == 0) return -1;
    if (tamper) wire[HDR_LEN] ^= 0x01;
    net_log(ROLE, tamper ? "ALERT" : "INFO", ST_SECURE, wire, n, 0, "%s seq %llu (%zu B)",
            tamper ? "sent TAMPERED packet" : "sent packet", (unsigned long long)load_be64(wire), n);
    if (net_send_frame(fd, MSG_DATA, wire, n) != 0) return -1;
    int r = await_reply(fd, c);
    if (r == 1) {                      /* remember it so `replay` has an accepted packet */
        memcpy(c->last_ok, wire, n);
        c->last_ok_len = n;
    }
    return r < 0 ? -1 : 0;
}

int main(int argc, char **argv) {
    uint16_t port = NET_DEFAULT_PORT;
    if (argc == 3 && strcmp(argv[1], "--port") == 0) {
        if (parse_port(argv[2], &port) != 0) { fprintf(stderr, "invalid port\n"); return 2; }
    } else if (argc != 1) {
        fprintf(stderr, "usage: %s [--port 1024-65535]\n", argv[0]);
        return 2;
    }
    if (sodium_init() < 0) return 1;

    unsigned char pinned[ID_PK_LEN];
    if (read_file(SERVER_SIGN_PK, pinned, sizeof pinned) != 0) {
        net_log(ROLE, "ERROR", ST_INIT, NULL, 0, 0, "no pinned server key: run ./keygen first");
        return 1;
    }
    net_log(ROLE, "INFO", ST_INIT, NULL, 0, 0, "pinned server identity loaded from %s", SERVER_SIGN_PK);
    int fd = net_connect(port);
    if (fd < 0) {
        net_log(ROLE, "ERROR", ST_INIT, NULL, 0, 0, "cannot connect to 127.0.0.1:%u", port);
        return 1;
    }
    net_log(ROLE, "INFO", ST_INIT, NULL, 0, 0, "TCP connected to 127.0.0.1:%u", port);

    client_state c;
    memset(&c, 0, sizeof c);
    if (handshake(fd, &c, pinned) != 0) {
        close(fd);
        net_log(ROLE, "WIPE", ST_TERMINATE, NULL, 0, 0, "handshake aborted; keys wiped");
        return 3;
    }

    char line[SESSION_MSG_MAX + 16];
    int rc = 0;
    while (fgets(line, sizeof line, stdin) != NULL) {
        if (strchr(line, '\n') == NULL && !feof(stdin)) {
            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF) { }
            net_log(ROLE, "ERROR", ST_SECURE, NULL, 0, 0, "input line too long - ignored");
            continue;
        }
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "send ", 5) == 0)        rc = send_message(fd, &c, line + 5, 0);
        else if (strncmp(line, "tamper ", 7) == 0) rc = send_message(fd, &c, line + 7, 1);
        else if (strcmp(line, "replay") == 0) {
            if (c.last_ok_len == 0) { net_log(ROLE, "ERROR", ST_SECURE, NULL, 0, 0, "nothing accepted yet to replay"); continue; }
            net_log(ROLE, "ALERT", ST_SECURE, c.last_ok, c.last_ok_len, 0, "REPLAYED accepted packet seq %llu",
                    (unsigned long long)load_be64(c.last_ok));
            rc = (net_send_frame(fd, MSG_DATA, c.last_ok, c.last_ok_len) == 0 && await_reply(fd, &c) >= 0) ? 0 : -1;
        } else if (strcmp(line, "quit") == 0) break;
        else if (line[0]) net_log(ROLE, "ERROR", ST_SECURE, NULL, 0, 0, "unknown command");
        if (rc != 0) break;
    }
    net_send_frame(fd, MSG_BYE, NULL, 0);
    close(fd);
    keys_free(&c);
    sodium_memzero(&c, sizeof c);
    net_log(ROLE, "WIPE", ST_TERMINATE, NULL, 0, 0, "BYE sent; session keys zeroed and freed");
    return rc == 0 ? 0 : 1;
}
