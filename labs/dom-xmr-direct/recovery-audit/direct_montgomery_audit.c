/* Independent arithmetic audit only. No nodes, keys, factors, proof acceptance,
 * timing admission or protocol integration. Computes U^(2^T) mod N with the
 * SAME number of sequential squarings using OpenSSL Montgomery arithmetic.
 * The caller must independently validate the final plaintext/public point.
 */
#define _POSIX_C_SOURCE 200809L
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int hex_line(char *out, size_t size) {
    if (!fgets(out, (int)size, stdin)) return 0;
    size_t n = strlen(out);
    if (!n || out[n - 1] != '\n') return 0;
    out[--n] = '\0';
    if (!n || n > 512) return 0;
    for (size_t i = 0; i < n; i++) if (!isxdigit((unsigned char)out[i])) return 0;
    return 1;
}
static double elapsed(struct timespec a, struct timespec b) {
    return (double)(b.tv_sec - a.tv_sec) + (double)(b.tv_nsec - a.tv_nsec) / 1e9;
}
int main(int argc, char **argv) {
    if (argc != 2 || !argv[1][0]) return 2;
    for (const char *p = argv[1]; *p; p++) if (!isdigit((unsigned char)*p)) return 2;
    if (strlen(argv[1]) > 8) return 2;
    unsigned long work = strtoul(argv[1], NULL, 10);
    if (!work || work > 10000000UL) return 2;
    char n_hex[514], u_hex[514];
    if (!hex_line(n_hex, sizeof(n_hex)) || !hex_line(u_hex, sizeof(u_hex)) || getchar() != EOF) return 2;
    BIGNUM *n = NULL, *u = NULL, *w = BN_new(), *gcd = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BN_MONT_CTX *mont = BN_MONT_CTX_new();
    if (!w || !gcd || !ctx || !mont || !BN_hex2bn(&n, n_hex) || !BN_hex2bn(&u, u_hex)) return 3;
    if (BN_num_bits(n) != 2048 || !BN_is_odd(n) || BN_is_zero(u) || BN_cmp(u, n) >= 0 ||
        !BN_gcd(gcd, u, n, ctx) || !BN_is_one(gcd)) return 2;
    struct timespec start, end;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) return 3;
    if (!BN_MONT_CTX_set(mont, n, ctx) || !BN_to_montgomery(w, u, mont, ctx)) return 3;
    for (unsigned long i = 0; i < work; i++) {
        if (!BN_mod_mul_montgomery(w, w, w, mont, ctx)) return 3;
    }
    if (!BN_from_montgomery(w, w, mont, ctx) || clock_gettime(CLOCK_MONOTONIC, &end) != 0) return 3;
    char *hex = BN_bn2hex(w);
    if (!hex) return 3;
    printf("{\"work\":%lu,\"sequential_seconds\":%.9f,\"delayed_element_hex\":\"%s\"}\n", work, elapsed(start, end), hex);
    OPENSSL_clear_free(hex, strlen(hex));
    BN_clear_free(w); BN_clear_free(u); BN_free(n); BN_free(gcd);
    BN_MONT_CTX_free(mont); BN_CTX_free(ctx);
    return 0;
}
