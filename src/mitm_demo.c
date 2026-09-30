/* Stretch 2 - man-in-the-middle against plain crypto_kx, and the fix.
 *
 * Part A: crypto_kx on its own does not authenticate anyone. Mallory sits
 *         between client and server, runs one exchange with each, and can
 *         read and rewrite every message.
 * Part B: the server signs (label || server_eph_pk || client_eph_pk) with its
 *         long-term Ed25519 key. The client verifies with server_pk.bin, which
 *         it already trusts. Any substituted ephemeral key breaks the signature.
 *
 * The scenario itself lives in handshake.c (mitm_run) so the dashboard runs
 * exactly the same code.
 */
#include "handshake.h"
#include "ui.h"
#include <stdio.h>

int main(void) {
    ui_init();
    ui_banner("STRETCH - MITM ATTACK & SIGNED HANDSHAKE",
              "crypto_kx + crypto_sign_detached / verify_detached");
    if (sodium_init() < 0) {
        ui_error("libsodium failed to initialise", "sodium_init() returned < 0", "Aborting");
        return 1;
    }
    mitm_report r;
    mitm_run(&r);

    ui_section("Part A: plain crypto_kx - no authentication");
    ui_info("Client sends its public key; Mallory replaces it with hers before it reaches the server.");
    ui_info("Server replies with its public key; Mallory replaces that too.");
    if (r.plain_read)  ui_warn("Mallory decrypted the client's message: \"%s\"", r.read_text);
    if (r.plain_forge) ui_warn("Server accepted Mallory's rewritten message: \"%s\"", r.forged_text);
    int a = r.plain_read && r.plain_forge;
    if (a) ui_info("Vulnerability demonstrated: key exchange alone gives confidentiality only against a passive attacker.");
    else   ui_fail("MITM simulation did not behave as expected");

    ui_section("Part B: server signs the handshake with its long-term Ed25519 key");
    if (r.used_task1_identity) ui_info("Using the Task 1 identity: client has pinned %s", SERVER_SIGN_PK);
    else ui_info("No Task 1 keys found - using an in-memory server identity (run ./keygen first)");
    if (r.signed_honest) ui_pass("No attacker: signature verifies, keys agree, message delivered");
    else                 ui_fail("Honest signed handshake failed");
    if (r.blocked_key_swap) ui_pass("MITM swaps server key, forwards real signature -> client ABORTS (bad signature)");
    else                    ui_fail("Substituted key was accepted");
    if (r.blocked_own_signature) ui_pass("MITM signs with her own key -> client ABORTS (not the pinned server key)");
    else                         ui_fail("Mallory's signature was accepted");
    if (r.blocked_replayed_sig) ui_pass("Replayed signature from another session -> ABORTS (client key is in the transcript)");
    else                        ui_fail("Replayed signature was accepted");

    int b = r.signed_honest && r.blocked_key_swap && r.blocked_own_signature && r.blocked_replayed_sig;
    printf("\n");
    ui_box_top();
    ui_box_row("Unauthenticated kx: MITM succeeds (limitation shown)", a ? "SHOWN" : "FAIL");
    ui_box_row("Signed handshake: MITM detected", b ? "PASS" : "FAIL");
    ui_box_bottom();
    return (a && b) ? 0 : 1;
}
