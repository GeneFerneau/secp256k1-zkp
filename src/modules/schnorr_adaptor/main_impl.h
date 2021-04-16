/***********************************************************************
 * Copyright (c) 2021 Gene Ferneau                                     *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. *
 ***********************************************************************/

#ifndef _SECP256K1_MODULE_SCHNORR_ADAPTOR_MAIN_
#define _SECP256K1_MODULE_SCHNORR_ADAPTOR_MAIN_

#include "include/secp256k1.h"
#include "include/secp256k1_schnorr_adaptor.h"

static const unsigned char SCHNORR_ADAPTOR_TAG_AUX[64] = {
    0x95, 0x04, 0xf3, 0x0a, 0xb5, 0x81, 0x06, 0x4d, 0xf2, 0xc7, 0x08, 0xc1, 0xec, 0x6d, 0x7d, 0x16,
    0xfa, 0x5f, 0x3e, 0x11, 0x6c, 0xc0, 0xe2, 0x88, 0x2f, 0x67, 0x49, 0xd6, 0x7b, 0x6e, 0x1c, 0x50,
    0x95, 0x04, 0xf3, 0x0a, 0xb5, 0x81, 0x06, 0x4d, 0xf2, 0xc7, 0x08, 0xc1, 0xec, 0x6d, 0x7d, 0x16,
    0xfa, 0x5f, 0x3e, 0x11, 0x6c, 0xc0, 0xe2, 0x88, 0x2f, 0x67, 0x49, 0xd6, 0x7b, 0x6e, 0x1c, 0x50
};

static const unsigned char SCHNORR_ADAPTOR_TAG_CHALLENGE[64] = {
    0x7d, 0x18, 0xfc, 0x4b, 0x1b, 0xe0, 0xff, 0xf2, 0x4e, 0x23, 0xf4, 0x67, 0x2b, 0x0c, 0x44, 0xf5,
    0x5c, 0x3c, 0xe8, 0xec, 0x0a, 0x83, 0x7f, 0xaf, 0xee, 0x0c, 0x47, 0x4b, 0x27, 0x3f, 0x04, 0x43,
    0x7d, 0x18, 0xfc, 0x4b, 0x1b, 0xe0, 0xff, 0xf2, 0x4e, 0x23, 0xf4, 0x67, 0x2b, 0x0c, 0x44, 0xf5,
    0x5c, 0x3c, 0xe8, 0xec, 0x0a, 0x83, 0x7f, 0xaf, 0xee, 0x0c, 0x47, 0x4b, 0x27, 0x3f, 0x04, 0x43
};

static const unsigned char SCHNORR_ADAPTOR_TAG_NONCE[64] = {
    0xac, 0xf9, 0x6b, 0xcd, 0x21, 0xc1, 0xc5, 0xf0, 0x04, 0xdd, 0x98, 0xff, 0x4a, 0x7c, 0x37, 0xdc,
    0x5a, 0x08, 0x0d, 0x57, 0xfb, 0x28, 0x6a, 0x62, 0x19, 0xb5, 0x66, 0xbb, 0x1b, 0xa4, 0xc5, 0x10,
    0xac, 0xf9, 0x6b, 0xcd, 0x21, 0xc1, 0xc5, 0xf0, 0x04, 0xdd, 0x98, 0xff, 0x4a, 0x7c, 0x37, 0xdc,
    0x5a, 0x08, 0x0d, 0x57, 0xfb, 0x28, 0x6a, 0x62, 0x19, 0xb5, 0x66, 0xbb, 0x1b, 0xa4, 0xc5, 0x10
};

SECP256K1_INLINE static void secp256k1_schnorr_adaptor_tag_aux(secp256k1_sha256 *sha) {
    VERIFY_CHECK(sha != NULL);

    secp256k1_sha256_initialize(sha);
    secp256k1_sha256_write(sha, SCHNORR_ADAPTOR_TAG_AUX, 64);

    printf("aux:\n");
    printf("sha->s[0] = 0x%04luul;\n", sha->s[0]);
    printf("sha->s[1] = 0x%04luul;\n", sha->s[1]);
    printf("sha->s[2] = 0x%04luul;\n", sha->s[2]);
    printf("sha->s[3] = 0x%04luul;\n", sha->s[3]);
    printf("sha->s[4] = 0x%04luul;\n", sha->s[4]);
    printf("sha->s[5] = 0x%04luul;\n", sha->s[5]);
    printf("sha->s[6] = 0x%04luul;\n", sha->s[6]);
    printf("sha->s[7] = 0x%04luul;\n", sha->s[7]);
    printf("sha->bytes = %lu;\n", sha->bytes);
}

SECP256K1_INLINE static void secp256k1_schnorr_adaptor_tag_challenge(secp256k1_sha256 *sha) {
    VERIFY_CHECK(sha != NULL);

    secp256k1_sha256_initialize(sha);
    secp256k1_sha256_write(sha, SCHNORR_ADAPTOR_TAG_CHALLENGE, 64);

    printf("challenge:\n");
    printf("sha->s[0] = 0x%04luul;\n", sha->s[0]);
    printf("sha->s[1] = 0x%04luul;\n", sha->s[1]);
    printf("sha->s[2] = 0x%04luul;\n", sha->s[2]);
    printf("sha->s[3] = 0x%04luul;\n", sha->s[3]);
    printf("sha->s[4] = 0x%04luul;\n", sha->s[4]);
    printf("sha->s[5] = 0x%04luul;\n", sha->s[5]);
    printf("sha->s[6] = 0x%04luul;\n", sha->s[6]);
    printf("sha->s[7] = 0x%04luul;\n", sha->s[7]);
    printf("sha->bytes = %lu;\n", sha->bytes);
}

SECP256K1_INLINE static void secp256k1_schnorr_adaptor_tag_nonce(secp256k1_sha256 *sha) {
    VERIFY_CHECK(sha != NULL);

    secp256k1_sha256_initialize(sha);
    secp256k1_sha256_write(sha, SCHNORR_ADAPTOR_TAG_NONCE, 64);

    printf("nonce:\n");
    printf("sha->s[0] = 0x%04luul;\n", sha->s[0]);
    printf("sha->s[1] = 0x%04luul;\n", sha->s[1]);
    printf("sha->s[2] = 0x%04luul;\n", sha->s[2]);
    printf("sha->s[3] = 0x%04luul;\n", sha->s[3]);
    printf("sha->s[4] = 0x%04luul;\n", sha->s[4]);
    printf("sha->s[5] = 0x%04luul;\n", sha->s[5]);
    printf("sha->s[6] = 0x%04luul;\n", sha->s[6]);
    printf("sha->s[7] = 0x%04luul;\n", sha->s[7]);
    printf("sha->bytes = %lu;\n", sha->bytes);
}

SECP256K1_INLINE static int secp256k1_schnorr_adaptor_nonce(const secp256k1_context *ctx, unsigned char *r, const secp256k1_scalar *a, const secp256k1_pubkey *p, const secp256k1_pubkey *ypk, const secp256k1_scalar *d, const unsigned char *msg, size_t msg_len) {
    secp256k1_sha256 sha;
    secp256k1_pubkey t;
    secp256k1_pubkey pk_sum;
    const secp256k1_pubkey *pk_arr[2];
    unsigned char buf[32] = {0}, xor_buf[32] = {0};
    int i = 0, ret = 1;

    VERIFY_CHECK(r != NULL);
    VERIFY_CHECK(a != NULL);
    VERIFY_CHECK(p != NULL);
    VERIFY_CHECK(ypk != NULL);
    VERIFY_CHECK(d != NULL);
    VERIFY_CHECK(msg != NULL);

    secp256k1_scalar_get_b32(buf, d);
    secp256k1_scalar_get_b32(xor_buf, a);

    secp256k1_schnorr_adaptor_tag_aux(&sha);
    secp256k1_sha256_write(&sha, xor_buf, 32);
    secp256k1_sha256_finalize(&sha, xor_buf);

    /* t = d xor hash[AtomicSchnorrAdaptor/aux](a) */
    for (i = 0; i < 32; ++i) {
        xor_buf[i] ^= buf[i];
    }

    ret &= secp256k1_ec_pubkey_create(ctx, &t, xor_buf);
    pk_arr[0] = &t;
    pk_arr[1] = ypk;
    ret &= secp256k1_ec_pubkey_combine(ctx, &pk_sum, pk_arr, 2);

    /* rand = hash[AtomicSchnorrAdaptor/nonce](m || bytes(t*g + y*g) || bytes(P))  */
    secp256k1_schnorr_adaptor_tag_nonce(&sha);

    secp256k1_pubkey_load(ctx, &p_ge, &pk_sum);
    secp256k1_fe_get_b32(buf, &p_ge.x);
    secp256k1_sha256_write(&sha, buf, 32);

    secp256k1_pubkey_load(ctx, &p_ge, p);
    secp256k1_fe_get_b32(buf, &p_ge.x);
    secp256k1_sha256_write(&sha, buf, 32);

    secp256k1_sha256_write(&sha, msg, msg_len);
    secp256k1_sha256_finalize(&sha, r);

    return ret;
}

SECP256K1_INLINE int secp256k1_schnorr_pre_sign(const secp256k1_context *ctx, unsigned char *sig64, const unsigned char *msg, size_t msg_len, const secp256k1_pubkey *ypk, const unsigned char *sk, const secp256k1_scalar *a) {
    secp256k1_scalar d;
    secp256k1_scalar k;
    secp256k1_scalar e;
    secp256k1_scalar p;
    secp256k1_scalar s;
    secp256k1_pubkey pp;
    secp256k1_pubkey rp;
    secp256k1_ge p_ge;
    secp256k1_ge r_ge;
    secp256k1_gej p_gej;
    secp256k1_gej r_gej;
    secp256k1_sha256 sha;
    unsigned char buf[32] = {0};
    int ret = 1, overflow = 0, pk_len = 33;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(r != NULL);
    ARG_CHECK(s != NULL);
    ARG_CHECK(msg != NULL);
    ARG_CHECK(ypk != NULL);
    ARG_CHECK(sk != NULL);

    ret &= secp2561k_ec_pubkey_create(ctx, &p, sk);
    ret &= secp256k1_pubkey_load(ctx, &p_ge, &p);
    secp256k1_gej_set_ge(&p_gej, &p_ge);

    secp256k1_scalar_set_b32(&d, sk, &overflow);
    ret &= !overflow;

    /* d = d' if has_even_y(P), n - d' otherwise */
    secp256k1_ge_set_gej(&p_ge, &p_gej);
    if (secp256k1_fe_is_odd(&p_ge.y)) {
        secp256k1_scalar_negate(&d, &d);
    }

    /* t = bytes(d) xor hash[AtomicSchnorrAdaptor/aux](a) */
    /* k = hash[AtomicSchnorrAdaptor/nonce](m || bytes(t*g + y*g) || bytes(P))  */
    ret &= secp256k1_schnorr_adaptor_nonce(ctx, buf, a, pp, ypk, d, msg, msg_len);
    secp256k1_scalar_set_b32(&k, buf, &overflow);
    ret &= !overflow & !secp256k1_scalar_is_zero(&k);

    ret &= secp256k1_ec_pubkey_create(ctx, &rp, buf);
    ret &= secp256k1_pubkey_load(ctx, &r_ge, &rp);
    secp256k1_gej_set_ge(&r_gej, &r_ge);

    secp256k1_ge_set_gej(&r_ge, &r_gej);
    if (secp256k1_fe_is_odd(&r_ge.y)) {
        secp256k1_scalar_negate(&k, &k);
    }

    /* e = hash[AtomicSchnorrAdaptor/challenge](m || bytes(R) || bytes(P)) */
    secp256k1_schnorr_adaptor_tag_challenge(&sha);
    secp256k1_sha256_write(&sha, msg, msg_len);
    secp256k1_sha256_finalize(&sha, buf);
    secp256k1_sha256_write(&sha, buf, 32);
    secp256k1_ec_pubkey_load(ctx, &p_ge, &pp);
    secp256k1_fe_get_b32(buf, &p_ge.x);
    secp256k1_sha256_write(&sha, buf, 32);

    secp256k1_scalar_set_b32(&e, buf, &overflow);
    ret &= overflow;

    /* s = k + e*d */
    secp256k1_scalar_mul(s, &e, &d);
    secp256k1_scalar_add(s, s, &k);

    /* r = bytes(R) */
    secp256k1_fe_normalize(&r_ge.x);

    /* sig = r || s */
    secp256k1_fe_get_b32(sig64, &r_ge.x);
    secp256k1_scalar_get_b32(sig64 + 32, &s);

    secp256k1_scalar_clear(&d);
    secp256k1_scalar_clear(&k);
    secp256k1_scalar_clear(&e);
    secp256k1_scalar_clear(&p);
    secp256k1_scalar_clear(&s);

    return ret;
}

#endif
