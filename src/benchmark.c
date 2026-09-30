/* Stretch 4 - AEAD benchmark (binary: aead_bench). Encrypts buffers of several
 * sizes and times them with CLOCK_MONOTONIC. Every number is measured here.
 *
 * Usage: ./aead_bench [iterations]        boxed table, 1 KiB, default 100000
 *        ./aead_bench --json [budget_ms]  all sizes, JSON (used by the dashboard)
 */
#include "common.h"
#include "json.h"
#include "ui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_SIZE 16384
static const size_t SIZES[] = { 64, 256, 1024, 4096, 16384 };

typedef enum { ALG_CHACHA, ALG_AESGCM, ALG_SEAL } alg_id;
static const char *ALG_NAMES[] = { "ChaCha20-Poly1305", "AES-256-GCM", "seal() + nonce" };

typedef struct { double secs; unsigned long iters; } result;

static unsigned char msg[MAX_SIZE], ct[MAX_SIZE + 16], pkt[PKT_LEN(MAX_SIZE)];
static unsigned char key[32], nonce12[12], checksum;

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void run_once(alg_id alg, size_t size, uint64_t i) {
    unsigned long long ct_len = 0;
    switch (alg) {
    case ALG_CHACHA:
        sodium_increment(nonce12, sizeof nonce12);   /* never reuse a nonce */
        crypto_aead_chacha20poly1305_ietf_encrypt(ct, &ct_len, msg, size, NULL, 0, NULL, nonce12, key);
        checksum ^= ct[0];
        break;
    case ALG_AESGCM:
        sodium_increment(nonce12, sizeof nonce12);
        crypto_aead_aes256gcm_encrypt(ct, &ct_len, msg, size, NULL, 0, NULL, nonce12, key);
        checksum ^= ct[0];
        break;
    case ALG_SEAL: {
        size_t n = seal(pkt, sizeof pkt, i + 1, msg, size, key);
        checksum ^= pkt[n - 1];
        break;
    }
    }
}

static result bench_iters(alg_id alg, size_t size, unsigned long iters) {
    double t0 = now_sec();
    for (unsigned long i = 0; i < iters; i++) run_once(alg, size, i);
    return (result){ now_sec() - t0, iters };
}

/* Runs for roughly budget_ms (after a short calibration), so large and small
 * messages take similar wall time. */
static result bench_budget(alg_id alg, size_t size, double budget_ms) {
    unsigned long n = 64;
    result r = bench_iters(alg, size, n);
    while (r.secs < 0.02 && n < (1UL << 24)) { n *= 4; r = bench_iters(alg, size, n); }
    unsigned long target = (unsigned long)((double)n * (budget_ms / 1000.0) / (r.secs > 0 ? r.secs : 1e-6));
    if (target < 100) target = 100;
    return bench_iters(alg, size, target);
}

static void report_row(const char *name, result r, size_t size) {
    double us = r.secs * 1e6 / (double)r.iters;
    double mbs = (double)r.iters * (double)size / r.secs / (1024.0 * 1024.0);
    char right[80];
    snprintf(right, sizeof right, "%7.3f s  %6.2f us/op  %8.1f MiB/s", r.secs, us, mbs);
    ui_box_row(name, right);
}

static int table_mode(unsigned long iters) {
    ui_banner("STRETCH - AEAD BENCHMARK", "1 KiB messages, CLOCK_MONOTONIC");
    ui_info("%lu encryptions per algorithm", iters);
    printf("\n");
    ui_box_top();
    ui_box_row("algorithm", "total        per op       throughput");
    ui_box_sep();
    report_row("ChaCha20-Poly1305", bench_iters(ALG_CHACHA, 1024, iters), 1024);
    if (crypto_aead_aes256gcm_is_available())
        report_row("AES-256-GCM", bench_iters(ALG_AESGCM, 1024, iters), 1024);
    else
        ui_box_row("AES-256-GCM", "NOT AVAILABLE ON THIS PLATFORM");
    report_row("seal() + nonce", bench_iters(ALG_SEAL, 1024, iters), 1024);
    ui_box_bottom();
    printf("  %s(checksum %02x - keeps the compiler from skipping work)%s\n", C_DIM, checksum, C_RESET);
    ui_info("Typical: AES-GCM is faster on CPUs with AES-NI; ChaCha20 wins without it.");
    return 0;
}

static int json_mode(double budget_ms) {
    static char storage[16384];
    json_buf j;
    int aes = crypto_aead_aes256gcm_is_available();
    json_init(&j, storage, sizeof storage);
    json_obj_begin(&j, NULL);
    json_bool(&j, "ok", 1);
    json_str(&j, "libsodium", sodium_version_string());
    json_bool(&j, "aes256gcm_available", aes);
    json_num(&j, "budget_ms", budget_ms);
    json_arr_begin(&j, "results");
    for (int a = ALG_CHACHA; a <= ALG_SEAL; a++) {
        if (a == ALG_AESGCM && !aes) continue;
        for (size_t s = 0; s < sizeof SIZES / sizeof SIZES[0]; s++) {
            result r = bench_budget((alg_id)a, SIZES[s], budget_ms);
            json_obj_begin(&j, NULL);
            json_str(&j, "algorithm", ALG_NAMES[a]);
            json_int(&j, "size", (long long)SIZES[s]);
            json_int(&j, "iterations", (long long)r.iters);
            json_num(&j, "seconds", r.secs);
            json_num(&j, "ops_per_sec", (double)r.iters / r.secs);
            json_num(&j, "latency_us", r.secs * 1e6 / (double)r.iters);
            json_num(&j, "mib_per_sec", (double)r.iters * (double)SIZES[s] / r.secs / (1024.0 * 1024.0));
            json_obj_end(&j);
        }
    }
    json_arr_end(&j);
    json_int(&j, "checksum", checksum);
    json_obj_end(&j);
    json_emit(&j);
    return 0;
}

int main(int argc, char **argv) {
    ui_init();
    if (sodium_init() < 0) {
        ui_error("libsodium failed to initialise", "sodium_init() returned < 0", "Aborting");
        return 1;
    }
    randombytes_buf(msg, sizeof msg);
    randombytes_buf(key, sizeof key);
    randombytes_buf(nonce12, sizeof nonce12);

    int rc;
    if (argc > 1 && strcmp(argv[1], "--json") == 0) {
        double budget = argc > 2 ? strtod(argv[2], NULL) : 150.0;
        if (budget < 10 || budget > 5000) budget = 150.0;
        rc = json_mode(budget);
    } else {
        unsigned long iters = 100000;
        if (argc > 1) {
            char *end = NULL;
            unsigned long v = strtoul(argv[1], &end, 10);
            if (end == argv[1] || *end != '\0' || v == 0 || v > 100000000UL) {
                ui_error("Invalid iteration count", argv[1], "Use a number between 1 and 100000000");
                return 1;
            }
            iters = v;
        }
        rc = table_mode(iters);
    }
    sodium_memzero(key, sizeof key);
    return rc;
}
