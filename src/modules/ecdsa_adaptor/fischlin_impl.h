/***********************************************************************
 * Copyright (c) 2021 Gene Ferneau                                     *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. *
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ECDSA_ADAPTOR_FISCHLIN
#define SECP256K1_MODULE_ECDSA_ADAPTOR_FISCHLIN

#include "include/secp256k1.h"
#include "include/secp256k1_ecdsa_adaptor.h"

int secp256k1_fischlin_proof_init(secp256k1_fischlin_proof *proof) {
    int ret = 1;
    VERIFY_CHECK(proof != NULL);

    proof->coms = (secp256k1_fischlin_commitment *)checked_malloc(&default_error_callback, sizeof(secp256k1_fischlin_commitment) * SECP256K1_FISCHLIN_R); 
    ret &= proof->coms != NULL;
    proof->chals = (secp256k1_fischlin_challenge *)checked_malloc(&default_error_callback, sizeof(secp256k1_fischlin_challenge) * SECP256K1_FISCHLIN_R);
    ret &= proof->chals != NULL;
    proof->resps = (secp256k1_fischlin_response *)checked_malloc(&default_error_callback, sizeof(secp256k1_fischlin_response) * SECP256K1_FISCHLIN_R);
    ret &= proof->resps != NULL;

    return ret;
}

void secp256k1_fischlin_proof_destroy(secp256k1_fischlin_proof *proof) {
    VERIFY_CHECK(proof != NULL);

    if (proof->coms) {
        free(proof->coms);
    }
    if (proof->chals) {
        free(proof->chals);
    }
    if (proof->resps) {
        free(proof->resps);
    }
}

SECP256K1_INLINE static int secp256k1_fischlin_schnorr_prove(secp256k1_fischlin_response *r, const secp256k1_scalar *seckey, const secp256k1_scalar *rand, const secp256k1_fischlin_challenge *chal) {
    int ret = 1, overflow = 0;
    unsigned char chal_buf[32] = {0};
    memcpy(chal_buf + 28, (unsigned char*)chal, sizeof(*chal));

    secp256k1_scalar_set_b32(r, chal_buf, &overflow);
    ret &= overflow != 0; 

    /* r = rand - sk*c */
    secp256k1_scalar_mul(r, r, seckey);
    secp256k1_scalar_negate(r, r);
    secp256k1_scalar_add(r, r, rand);

    return ret;
}

SECP256K1_INLINE static int secp256k1_fischlin_schnorr_verify(const secp256k1_context *ctx, int *r, const secp256k1_pubkey *pubkey, const secp256k1_fischlin_commitment *com, const secp256k1_fischlin_challenge *chal, const secp256k1_fischlin_response *resp) {
    secp256k1_pubkey commit;
    unsigned char chal_buf[32] = {0};
    unsigned char resp_buf[32];
    int ret = 0;

    memcpy(&commit, pubkey, sizeof(*pubkey));
    memcpy(chal_buf + 28, (unsigned char *)chal, sizeof(*chal));
    secp256k1_scalar_get_b32(resp_buf, resp);

    ret = secp256k1_ec_pubkey_tweak_mul(ctx, &commit, chal_buf);
    ret &= secp256k1_ec_pubkey_tweak_add(ctx, &commit, resp_buf);

    /* V = rG + cX */
    *r = memcmp(com, &commit, sizeof(*com)) == 0;

    return ret;
}

SECP256K1_INLINE static int secp256k1_fischlin_prove_inner(secp256k1_fischlin_proof *proof, const secp256k1_sha256 *proof_sha, secp256k1_fischlin_challenge t, secp256k1_fischlin_challenge *min_chal, secp256k1_fischlin_response *min_resp, secp256k1_fischlin_score *min_score, uint16_t *sum, const secp256k1_scalar *seckey, const secp256k1_scalar *v, size_t i) {
    int ret = 1;
    secp256k1_fischlin_challenge chal;
    secp256k1_fischlin_response resp;
    secp256k1_fischlin_score score = 0;
    unsigned char resp_buf[32];
    unsigned char hash_buf[32];
    secp256k1_sha256 inner_sha;

    for (chal = 1 << t; chal < (secp256k1_fischlin_challenge)(1 << (t + 1)); ++chal) {
        ret &= secp256k1_fischlin_schnorr_prove(&resp, seckey, v, &chal);

        memcpy(&inner_sha, proof_sha, sizeof(*proof_sha));
        secp256k1_sha256_write(&inner_sha, (unsigned char *)&chal + 1, 3);

        secp256k1_scalar_get_b32(resp_buf, &resp);
        secp256k1_sha256_write(&inner_sha, resp_buf, 32);

        secp256k1_sha256_finalize(&inner_sha, hash_buf);
        score = 0;
        memcpy((unsigned char *)&score, hash_buf, 2);

        if (score == 0) {
            proof->chals[i] = chal;
            memcpy(&proof->resps[i], &resp, sizeof(resp));
            secp256k1_scalar_clear(&resp);
            return ret;
        }
        
        if (score < *min_score && score + *sum <= SECP256K1_FISCHLIN_S) {
            *min_score = score;
            *min_chal = chal;
            memcpy(min_resp, &resp, sizeof(resp));
        }
    }

    secp256k1_scalar_clear(&resp);

    return ret;
}

int secp256k1_fischlin_prove(const secp256k1_context *ctx, secp256k1_fischlin_proof *proof, const unsigned char *seckey, const secp256k1_scalar *vs) {
    unsigned char pub_buf[33];
    int ret = 1;
    secp256k1_sha256 sha;
    secp256k1_scalar sec;
    secp256k1_pubkey pubkey;
    size_t pub_len = 33;
    int overflow = 0;

    uint16_t i;
    uint16_t t;
    uint16_t sum = 0;
    unsigned char v_buf[32];
    secp256k1_sha256 proof_sha;

    secp256k1_fischlin_challenge min_chal = 1;
    secp256k1_fischlin_response min_resp;
    secp256k1_fischlin_score min_score;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(proof->coms != NULL);
    ARG_CHECK(proof->chals != NULL);
    ARG_CHECK(proof->resps != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(vs != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));

    secp256k1_sha256_initialize(&sha);

    ret = secp256k1_ec_pubkey_create(ctx, &pubkey, seckey);
    ret &= secp256k1_ec_pubkey_serialize(ctx, pub_buf, &pub_len, &pubkey, SECP256K1_EC_COMPRESSED);
    secp256k1_sha256_write(&sha, pub_buf, pub_len);

    secp256k1_scalar_set_b32(&sec, seckey, &overflow);
    ret &= overflow == 0;

    for (i = 0; i < SECP256K1_FISCHLIN_R; ++i) {
        secp256k1_scalar_get_b32(v_buf, &vs[i]);
        ret &= secp256k1_ec_pubkey_create(ctx, &proof->coms[i], v_buf);
        ret &= secp256k1_ec_pubkey_serialize(ctx, pub_buf, &pub_len, &proof->coms[i], SECP256K1_EC_COMPRESSED);
        secp256k1_sha256_write(&sha, pub_buf, pub_len);
    }

    memset(&min_resp, 0, sizeof(min_resp));

    for (i = 0; i < SECP256K1_FISCHLIN_R; ++i) {
        /* clone the sha engine to not have to recompute constant terms */
        memcpy(&proof_sha, &sha, sizeof(sha)); 

        secp256k1_sha256_write(&proof_sha, (unsigned char *)&i, 2);

        min_score = 255;
        for (t = 0; t < SECP256K1_FISCHLIN_T; ++t) {
            if (secp256k1_fischlin_prove_inner(proof, &proof_sha, t, &min_chal, &min_resp, &min_score, &sum, &sec, &vs[i], i)) {
                break;
            }

            if (t == SECP256K1_FISCHLIN_T - 1) {
                if (min_score + sum <= SECP256K1_FISCHLIN_S) {
                    sum = min_score + sum;
                    proof->chals[i] = min_chal;
                    memcpy(&proof->resps[i], &min_resp, sizeof(min_resp));
                } else {
                    secp256k1_scalar_clear(&sec);
                    secp256k1_scalar_clear(&min_resp);
                    return 0;
                }
            }
        }
    }

    secp256k1_scalar_clear(&sec);
    secp256k1_scalar_clear(&min_resp);

    return ret;
}

int secp256k1_fischlin_verify(const secp256k1_context *ctx, int *r, const secp256k1_pubkey *pubkey, const secp256k1_fischlin_proof *proof) {
    int ret = 0;
    secp256k1_fischlin_score sum = 0;
    size_t pub_len = 33;
    unsigned char pub_buf[33];
    secp256k1_sha256 proof_sha;
    int valid = 0;
    unsigned char resp_buf[32];
    unsigned char hash[32];
    secp256k1_fischlin_score score = 0;
    uint16_t i;
    secp256k1_sha256 inner_proof_sha;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(r != NULL);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(proof->coms != NULL);
    ARG_CHECK(proof->chals != NULL);
    ARG_CHECK(proof->resps != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ret = secp256k1_ec_pubkey_serialize(ctx, pub_buf, &pub_len, pubkey, SECP256K1_EC_COMPRESSED);

    secp256k1_sha256_initialize(&proof_sha);
    secp256k1_sha256_write(&proof_sha, pub_buf, pub_len);

    for (i = 0; i < SECP256K1_FISCHLIN_R; ++i) {
        ret &= secp256k1_ec_pubkey_serialize(ctx, pub_buf, &pub_len, &proof->coms[i], SECP256K1_EC_COMPRESSED);
        secp256k1_sha256_write(&proof_sha, pub_buf, pub_len);
    }

    *r = 1;
    for (i = 0; i < SECP256K1_FISCHLIN_R; ++i) {
        valid = 0;
        ret &= secp256k1_fischlin_schnorr_verify(ctx, &valid, pubkey, &proof->coms[i], &proof->chals[i], &proof->resps[i]);
        *r &= valid;

        memcpy(&inner_proof_sha, &proof_sha, sizeof(proof_sha));

        secp256k1_sha256_write(&inner_proof_sha, (unsigned char *)&i, sizeof(i));
        secp256k1_sha256_write(&inner_proof_sha, (unsigned char *)&proof->chals[i] + 1, 3);

        secp256k1_scalar_get_b32(resp_buf, &proof->resps[i]);
        secp256k1_sha256_write(&inner_proof_sha, resp_buf, 32);

        secp256k1_sha256_finalize(&inner_proof_sha, hash);

        score = 0;
        memcpy((unsigned char *)&score, hash, sizeof(score));

        if (sum + score > SECP256K1_FISCHLIN_S) {
            *r = 0;
        } else {
            sum = sum + score;
        }
    }

    return ret;
}

#endif
