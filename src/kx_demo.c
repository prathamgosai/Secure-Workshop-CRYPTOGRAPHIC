/* Task 2 - key exchange and session keys (+ Task 3 round-trip checkpoint).
 *
 * Client and server each create an X25519 key pair, exchange only the public
 * keys, and call crypto_kx to derive two 32-byte session keys: rx (receive)
 * and tx (transmit). They are complementary: client_tx == server_rx and
 * client_rx == server_tx. Because each direction has its own key, a packet
 * the client sent can never be reflected back and accepted by the client.
 */
#include "common.h"
#include "ui.h"
#include <stdio.h>
#include <string.h>

#define SK_LEN crypto_kx_SESSIONKEYBYTES   /* 32 */

static const char *yes_no(int v) { return v ? "YES" : "NO"; }

int main(void) {
    ui_init();
    ui_banner("TASK 2 - KEY EXCHANGE & SESSION KEYS",
              "X25519 via crypto_kx  +  Task 3 AEAD round-trip");
    ui_states(ST_INIT);

    if (sodium_init() < 0) {
        ui_error("libsodium failed to initialise", "sodium_init() returned < 0", "Aborting");
        return 1;
    }

    unsigned char cpk[crypto_kx_PUBLICKEYBYTES], csk[crypto_kx_SECRETKEYBYTES];
    unsigned char spk[crypto_kx_PUBLICKEYBYTES], ssk[crypto_kx_SECRETKEYBYTES];
    unsigned char c_rx[SK_LEN], c_tx[SK_LEN], s_rx[SK_LEN], s_tx[SK_LEN];
    int ok = 0;

    ui_section("INIT: each side creates an ephemeral X25519 key pair");
    crypto_kx_keypair(cpk, csk);   /* client ephemeral */
    crypto_kx_keypair(spk, ssk);   /* server ephemeral */
    ui_hex("client public key", cpk, sizeof cpk, 8);
    ui_hex("server public key", spk, sizeof spk, 8);
    ui_info("Only the PUBLIC keys cross the network.");

    ui_states(ST_AUTH);
    ui_section("AUTH: derive direction-specific session keys");
    /* crypto_kx computes BLAKE2b-512(X25519(sk, peer_pk) || client_pk || server_pk)
     * and splits the 64-byte output into rx and tx keys. The client and
     * server take the two halves in opposite order. A failure here means the
     * peer's public key is invalid (e.g. a low-order point). */
    if (crypto_kx_client_session_keys(c_rx, c_tx, cpk, csk, spk) != 0) {
        ui_error("Client key derivation failed", "Server public key rejected", "Handshake aborted");
        goto done;
    }
    if (crypto_kx_server_session_keys(s_rx, s_tx, spk, ssk, cpk) != 0) {
        ui_error("Server key derivation failed", "Client public key rejected", "Handshake aborted");
        goto done;
    }
    /* Ephemeral secrets are no longer needed once session keys exist. */
    sodium_memzero(csk, sizeof csk);
    sodium_memzero(ssk, sizeof ssk);

    /* Constant-time comparisons: memcmp() may leak timing information. */
    int ok1 = sodium_memcmp(c_tx, s_rx, SK_LEN) == 0;
    int ok2 = sodium_memcmp(c_rx, s_tx, SK_LEN) == 0;
    int same = sodium_memcmp(c_tx, c_rx, SK_LEN) == 0;

    printf("client_tx == server_rx : %s\n", yes_no(ok1));
    printf("client_rx == server_tx : %s\n", yes_no(ok2));
    printf("client_tx == client_rx : %s (should be NO)\n", yes_no(same));
    if (ok1) ui_pass("Client->server key agrees on both sides");
    else     ui_fail("Client->server key mismatch");
    if (ok2) ui_pass("Server->client key agrees on both sides");
    else     ui_fail("Server->client key mismatch");
    if (!same) ui_pass("TX and RX keys differ (direction separation)");
    else       ui_fail("TX and RX keys are identical");
    ui_info("Session key bytes are never printed - only compared.");

    ui_states(ST_SECURE);
    ui_section("SECURE: Task 3 round-trip with ChaCha20-Poly1305");
    const char *msg = "hello secure world";
    size_t msg_len = strlen(msg);
    unsigned char pkt[PKT_LEN(64)], out[64];
    size_t out_len = 0;
    replay_state server_rs = {0, 0};

    size_t n = seal(pkt, sizeof pkt, 1, (const unsigned char *)msg, msg_len, c_tx);
    int rc = (n == 0) ? SC_ERR_SHORT : unseal(out, sizeof out, &out_len, pkt, n, s_rx, &server_rs);
    int round_trip = (rc == SC_OK && out_len == msg_len && memcmp(out, msg, msg_len) == 0);
    ui_info("client seals seq=1: %zu B plaintext -> %zu B packet (20 header + %zu ct + 16 tag)",
            msg_len, n, msg_len);
    if (round_trip) {
        printf("Round-trip: \"%.*s\"\n", (int)out_len, out);
        ui_pass("Server decrypted and authenticated the message with server_rx");
    } else {
        ui_fail("Round-trip failed: %s", unseal_strerror(rc));
    }

    /* Reflection: an attacker bounces the client's own packet back to it.
     * The client receives with c_rx, which is not the key it sent with. */
    replay_state client_rs = {0, 0};
    int refl = (n == 0) ? SC_OK : unseal(out, sizeof out, &out_len, pkt, n, c_rx, &client_rs);
    if (refl == SC_ERR_AUTH) ui_pass("Reflection attack: packet bounced back to client -> rejected");
    else                     ui_fail("Reflection attack was not rejected (%s)", unseal_strerror(refl));

    ok = ok1 && ok2 && !same && round_trip && refl == SC_ERR_AUTH;

done:
    ui_states(ST_TERMINATE);
    sodium_memzero(csk, sizeof csk);   sodium_memzero(ssk, sizeof ssk);
    sodium_memzero(c_rx, sizeof c_rx); sodium_memzero(c_tx, sizeof c_tx);
    sodium_memzero(s_rx, sizeof s_rx); sodium_memzero(s_tx, sizeof s_tx);
    ui_pass("TERMINATE: ephemeral secrets and session keys wiped");
    return ok ? 0 : 1;
}
