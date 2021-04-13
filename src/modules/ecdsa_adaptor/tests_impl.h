/***********************************************************************
 * Copyright (c) 2021 Gene Ferneau                                     *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. *
 ***********************************************************************/

#ifndef _SECP256K1_MODULE_ECDSA_ADAPTOR_TESTS_
#define _SECP256K1_MODULE_ECDSA_ADAPTOR_TESTS_

#include "testrand_impl.h"
#include "secp256k1_ecdsa_adaptor.h"

static void test_fischlin_prove_verify(void) {
    unsigned char rand_buf[32] = {0};
    secp256k1_fischlin_proof proof;
    secp256k1_pubkey pubkey;
    int overflow = 0, valid = 0;
    int32_t ecount = 0;
    size_t i;
    secp256k1_scalar *vs = NULL;

    secp256k1_context *both = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_context_set_error_callback(both, &default_error_callback_fn, &ecount);

    vs = (secp256k1_scalar *)checked_malloc(&both->error_callback, sizeof(secp256k1_scalar) * SECP256K1_FISCHLIN_R);
    CHECK(vs != NULL);

    for (i = 0; i < SECP256K1_FISCHLIN_R; ++i) {
        secp256k1_rand_bytes_test(rand_buf + 2, 30);
        secp256k1_scalar_set_b32(&vs[i], rand_buf, &overflow);
        CHECK(overflow == 0);
    }

    secp256k1_rand_bytes_test(rand_buf, 32);

    CHECK(secp256k1_fischlin_proof_init(&proof) != 0);

    CHECK(secp256k1_fischlin_prove(both, &proof, rand_buf, vs) != 0);

    CHECK(secp256k1_ec_pubkey_create(both, &pubkey, rand_buf) != 0);

    CHECK(secp256k1_fischlin_verify(both, &valid, &pubkey, &proof) != 0);
    CHECK(valid == 1);

    /* Cleanup */
    free(vs);
    secp256k1_context_destroy(both);
    secp256k1_fischlin_proof_destroy(&proof);
}

static void test_ecdsa_pre_sign_verify(void) {
    unsigned char y_buf[32] = {0}, x_buf[32] = {0}, k_buf[32] = {0}, rand_buf[32] = {0};
    secp256k1_fischlin_proof proof;
    secp256k1_ecdsa_pre_signature pre_sig;
    secp256k1_pubkey ypk, xpk;
    int overflow = 0, valid = 0;
    int32_t ecount = 0;
    size_t i;
    secp256k1_scalar *vs = NULL;
    char *msg = "Chancellor on brink of second bailout for banks";

    secp256k1_context *both = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_context_set_error_callback(both, &default_error_callback_fn, &ecount);

    vs = (secp256k1_scalar *)checked_malloc(&both->error_callback, sizeof(secp256k1_scalar) * SECP256K1_FISCHLIN_R);
    CHECK(vs != NULL);

    for (i = 0; i < SECP256K1_FISCHLIN_R; ++i) {
        secp256k1_rand_bytes_test(rand_buf + 2, 30);
        secp256k1_scalar_set_b32(&vs[i], rand_buf, &overflow);
        CHECK(overflow == 0);
    }

    secp256k1_rand_bytes_test(y_buf + 2, 30);
    secp256k1_rand_bytes_test(x_buf + 2, 30);
    secp256k1_rand_bytes_test(k_buf + 2, 30);
    secp256k1_rand_bytes_test(rand_buf + 2, 30);

    CHECK(secp256k1_fischlin_proof_init(&proof) != 0);
    CHECK(secp256k1_fischlin_prove(both, &proof, y_buf, vs) != 0);

    CHECK(secp256k1_ec_pubkey_create(both, &ypk, y_buf) != 0);
    CHECK(secp256k1_ec_pubkey_create(both, &xpk, x_buf) != 0);

    CHECK(secp256k1_ecdsa_pre_sign(both, &pre_sig, (unsigned char *)msg, sizeof(msg) - 1, &ypk, &proof, x_buf, k_buf, rand_buf) != 0);
    CHECK(secp256k1_ecdsa_pre_verify(both, &valid, (unsigned char *)msg, sizeof(msg) - 1, &ypk, &proof, &xpk, &pre_sig) != 0);
    CHECK(valid == 1);

    /* Cleanup */
    free(vs);
    secp256k1_context_destroy(both);
    secp256k1_fischlin_proof_destroy(&proof);
}

static void test_ecdsa_adaptor_malleability(void) {
    unsigned char y_buf[32] = {0}, x_buf[32] = {0}, k_buf[32] = {0}, rand_buf[32] = {0};
    secp256k1_fischlin_proof proof;
    secp256k1_ecdsa_pre_signature pre_sig;
    secp256k1_pubkey ypk, xpk;
    int overflow = 0, valid = 0;
    int32_t ecount = 0;
    size_t i;
    secp256k1_scalar *vs = NULL;
    char *msg = "non-malleable signatures, secure signatures";

    secp256k1_context *both = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_context_set_error_callback(both, &default_error_callback_fn, &ecount);

    vs = (secp256k1_scalar *)checked_malloc(&both->error_callback, sizeof(secp256k1_scalar) * SECP256K1_FISCHLIN_R);
    CHECK(vs != NULL);

    for (i = 0; i < SECP256K1_FISCHLIN_R; ++i) {
        secp256k1_rand_bytes_test(rand_buf + 2, 30);
        secp256k1_scalar_set_b32(&vs[i], rand_buf, &overflow);
        CHECK(overflow == 0);
    }

    secp256k1_rand_bytes_test(y_buf + 2, 30);
    secp256k1_rand_bytes_test(x_buf + 2, 30);
    secp256k1_rand_bytes_test(k_buf + 2, 30);
    secp256k1_rand_bytes_test(rand_buf + 2, 30);

    CHECK(secp256k1_fischlin_proof_init(&proof) != 0);
    CHECK(secp256k1_fischlin_prove(both, &proof, y_buf, vs) != 0);

    CHECK(secp256k1_ec_pubkey_create(both, &ypk, y_buf) != 0);
    CHECK(secp256k1_ec_pubkey_create(both, &xpk, x_buf) != 0);

    CHECK(secp256k1_ecdsa_pre_sign(both, &pre_sig, (unsigned char *)msg, sizeof(msg) - 1, &ypk, &proof, x_buf, k_buf, rand_buf) != 0);
    CHECK(secp256k1_ecdsa_pre_verify(both, &valid, (unsigned char *)msg, sizeof(msg) - 1, &ypk, &proof, &xpk, &pre_sig) != 0);
    CHECK(valid == 1);

    secp256k1_scalar_negate(&pre_sig.s, &pre_sig.s);
    CHECK(secp256k1_ecdsa_pre_verify(both, &valid, (unsigned char *)msg, sizeof(msg) - 1, &ypk, &proof, &xpk, &pre_sig) != 0);
    CHECK(valid == 0);

    /* Cleanup */
    free(vs);
    secp256k1_context_destroy(both);
    secp256k1_fischlin_proof_destroy(&proof);
}

static void test_ecdsa_adapt_extract(void) {
    unsigned char y_buf[32] = {0}, x_buf[32] = {0}, k_buf[32] = {0}, rand_buf[32] = {0}, y_extract[32] = {0};
    secp256k1_fischlin_proof proof;
    secp256k1_ecdsa_pre_signature pre_sig;
    secp256k1_pubkey ypk, xpk;
    secp256k1_scalar r, s;
    int overflow = 0, valid = 0;
    int32_t ecount = 0;
    size_t i;
    secp256k1_scalar *vs = NULL;
    char *msg = "SOME_BTC_SCRIPT spending coin";

    secp256k1_context *both = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_context_set_error_callback(both, &default_error_callback_fn, &ecount);

    vs = (secp256k1_scalar *)checked_malloc(&both->error_callback, sizeof(secp256k1_scalar) * SECP256K1_FISCHLIN_R);
    CHECK(vs != NULL);

    for (i = 0; i < SECP256K1_FISCHLIN_R; ++i) {
        secp256k1_rand_bytes_test(rand_buf + 2, 30);
        secp256k1_scalar_set_b32(&vs[i], rand_buf, &overflow);
        CHECK(overflow == 0);
    }

    secp256k1_rand_bytes_test(y_buf + 2, 30);
    secp256k1_rand_bytes_test(x_buf + 2, 30);
    secp256k1_rand_bytes_test(k_buf + 2, 30);
    secp256k1_rand_bytes_test(rand_buf + 2, 30);

    CHECK(secp256k1_fischlin_proof_init(&proof) != 0);
    CHECK(secp256k1_fischlin_prove(both, &proof, y_buf, vs) != 0);

    CHECK(secp256k1_ec_pubkey_create(both, &ypk, y_buf) != 0);
    CHECK(secp256k1_ec_pubkey_create(both, &xpk, x_buf) != 0);

    CHECK(secp256k1_ecdsa_pre_sign(both, &pre_sig, (unsigned char *)msg, sizeof(msg) - 1, &ypk, &proof, x_buf, k_buf, rand_buf) != 0);
    CHECK(secp256k1_ecdsa_pre_verify(both, &valid, (unsigned char *)msg, sizeof(msg) - 1, &ypk, &proof, &xpk, &pre_sig) != 0);
    CHECK(valid == 1);

    CHECK(secp256k1_ecdsa_adapt(&r, &s, &pre_sig, y_buf) != 0);
    CHECK(secp256k1_ecdsa_extract(both, y_extract, &r, &s, &pre_sig, &proof) != 0);

    CHECK(memcmp(y_extract, y_buf, 32) == 0);

    /* Cleanup */
    free(vs);
    secp256k1_context_destroy(both);
    secp256k1_fischlin_proof_destroy(&proof);
}

static void run_ecdsa_adaptor_tests(void) {
    test_fischlin_prove_verify();
    test_ecdsa_pre_sign_verify();
    test_ecdsa_adaptor_malleability();
    test_ecdsa_adapt_extract();
    /* FIXME: add tests */
}

#endif
