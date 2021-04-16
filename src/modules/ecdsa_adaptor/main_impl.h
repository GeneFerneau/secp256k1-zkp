/***********************************************************************
 * Copyright (c) 2021 Gene Ferneau                                     *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. *
 ***********************************************************************/

#ifndef _SECP256K1_MODULE_ECDSA_ADAPTOR_MAIN_
#define _SECP256K1_MODULE_ECDSA_ADAPTOR_MAIN_

#include "include/secp256k1.h"
#include "include/secp256k1_ecdsa_adaptor.h"

SECP256K1_INLINE secp256k1_ecdsa_pre_signature* secp256k1_ecdsa_pre_signature_create(void) {
    secp256k1_ecdsa_pre_signature *p = (secp256k1_ecdsa_pre_signature *)checked_malloc(&default_error_callback, sizeof(secp256k1_ecdsa_pre_signature));
    VERIFY_CHECK(p != NULL);
    return p;
}

SECP256K1_INLINE void secp256k1_ecdsa_pre_signature_destroy(secp256k1_ecdsa_pre_signature *pre_sig) {
    VERIFY_CHECK(pre_sig != NULL);
    free(pre_sig);
}

SECP256K1_INLINE static void secp256k1_ecdsa_adaptor_tag_aux(unsigned char *r, unsigned char *msg, size_t msg_len) {
    secp256k1_sha256 sha;

    VERIFY_CHECK(r != NULL);
    VERIFY_CHECK(msg != NULL);

    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, SECP256K1_ECDSA_ADAPTOR_TAG_AUX, 64);
    secp256k1_sha256_write(&sha, msg, msg_len);
    secp256k1_sha256_finalize(&sha, r);
}

SECP256K1_INLINE static void secp256k1_ecdsa_adaptor_tag_challenge(unsigned char *r, unsigned char *msg, size_t msg_len) {
    secp256k1_sha256 sha;

    VERIFY_CHECK(r != NULL);
    VERIFY_CHECK(msg != NULL);

    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, SECP256K1_ECDSA_ADAPTOR_TAG_CHALLENGE, 64);
    secp256k1_sha256_write(&sha, msg, msg_len);
    secp256k1_sha256_finalize(&sha, r);
}

/* Initialize SHA256 to midstate from SHA256(SHA256("ECDSAAtomicAdaptor/consistency") || SHA256("ECDSAAtomicAdaptor/consistency")) */
SECP256K1_INLINE static void secp256k1_ecdsa_adaptor_tag_consistency(secp256k1_sha256 *sha) {
    VERIFY_CHECK(sha != NULL);

    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0xcea9a724ul;
    sha->s[1] = 0x93f5875ful;
    sha->s[2] = 0x64e6f1eful;
    sha->s[3] = 0xeb7d2670ul;
    sha->s[4] = 0x2db7bf99ul;
    sha->s[5] = 0x68e7b8a2ul;
    sha->s[6] = 0x74fe5409ul;
    sha->s[7] = 0x5285e90ful;
    sha->bytes = 64;
}

SECP256K1_INLINE static void secp256k1_ecdsa_adaptor_tag_nonce(unsigned char *r, unsigned char *msg, size_t msg_len) {
    secp256k1_sha256 sha;

    VERIFY_CHECK(r != NULL);
    VERIFY_CHECK(msg != NULL);

    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, SECP256K1_ECDSA_ADAPTOR_TAG_NONCE, 64);
    secp256k1_sha256_write(&sha, msg, msg_len);
    secp256k1_sha256_finalize(&sha, r);
}

SECP256K1_INLINE int secp256k1_ecdsa_consistency_prove(const secp256k1_context *ctx, secp256k1_chaum_pedersen_proof *proof, const secp256k1_pubkey *ypk, const unsigned char *sk, const secp256k1_scalar *rand, const unsigned char *msg, size_t msg_len) {
    int ret = 1, overflow = 0;
    secp256k1_scalar sec, c;
    secp256k1_pubkey kv, kw;
    secp256k1_sha256 sha;
    unsigned char buf[32];
    unsigned char transform_buf[66];
    size_t pub_len = 33;
    size_t transform_len = 66;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(ypk != NULL);
    ARG_CHECK(sk != NULL);
    ARG_CHECK(rand != NULL);
    ARG_CHECK(msg != NULL);

    secp256k1_scalar_set_b32(&sec, sk, &overflow);
    ret = !overflow && !secp256k1_scalar_is_zero(&sec);

    /* kv = k*g */
    ret &= secp256k1_ec_pubkey_create(ctx, &kv, sk);

    /* kw = k*Y */
    memcpy(&kw, ypk, sizeof(*ypk));
    ret &= secp256k1_ec_pubkey_tweak_mul(ctx, &kw, sk);

    ret &= secp256k1_ec_pubkey_serialize(ctx, transform_buf, &pub_len, &kv, SECP256K1_EC_COMPRESSED);
    ret &= secp256k1_ec_pubkey_serialize(ctx, transform_buf + 33, &pub_len, &kw, SECP256K1_EC_COMPRESSED);

    /* c = SHA256(SHA256("ECDSAAtomicAdaptor/consistency") || SHA256("ECDSAAtomicAdaptor/consistency") || kv || kw || msg) */
    secp256k1_ecdsa_adaptor_tag_consistency(&sha);
    secp256k1_sha256_write(&sha, transform_buf, transform_len);
    secp256k1_sha256_write(&sha, msg, msg_len);
    secp256k1_sha256_finalize(&sha, buf);
    secp256k1_scalar_set_b32(&c, buf, &overflow);
    ret &= !overflow;

    /* challenge = rand + sk*c */
    secp256k1_scalar_set_b32(&proof->challenge, sk, &overflow);
    ret &= !overflow;
    secp256k1_scalar_mul(&proof->challenge, &proof->challenge, &c);
    secp256k1_scalar_add(&proof->challenge, &proof->challenge, rand);

    /* nonce_left = rand*g */
    secp256k1_scalar_get_b32(buf, rand);
    ret &= secp256k1_ec_pubkey_create(ctx, &proof->nonce_left, buf);
    /* nonce_right = rand*y*g */
    memcpy(&proof->nonce_right, ypk, sizeof(*ypk));
    ret &= secp256k1_ec_pubkey_tweak_mul(ctx, &proof->nonce_right, buf);

    secp256k1_scalar_clear(&sec);
    secp256k1_scalar_clear(&c);

    return ret;
}

SECP256K1_INLINE int secp256k1_ecdsa_consistency_verify(const secp256k1_context *ctx, int *r, const secp256k1_pubkey *ypk, const secp256k1_pubkey *kp, const secp256k1_pubkey *ky, const secp256k1_chaum_pedersen_proof *proof, const unsigned char *msg, size_t msg_len) {
    int ret = 1;
    secp256k1_pubkey gbz, ubz, vc, wc, vcs, wcs;
    const secp256k1_pubkey *nonce_arr[2];
    secp256k1_ge gbz_ge, ubz_ge, vc_ge, wc_ge;
    secp256k1_sha256 sha;
    unsigned char buf[32];
    unsigned char transform_buf[66];
    size_t pub_len = 33;
    size_t transform_len = 66;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(r != NULL);
    ARG_CHECK(ypk != NULL);
    ARG_CHECK(kp != NULL);
    ARG_CHECK(ky != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(msg != NULL);

    /* gbz = challenge*g */
    secp256k1_scalar_get_b32(buf, &proof->challenge);
    ret &= secp256k1_ec_pubkey_create(ctx, &gbz, buf);

    /* ubz = challenge*y*g */
    memcpy(&ubz, ypk, sizeof(*ypk));
    ret &= secp256k1_ec_pubkey_tweak_mul(ctx, &ubz, buf);

    ret &= secp256k1_ec_pubkey_serialize(ctx, transform_buf, &pub_len, kp, SECP256K1_EC_COMPRESSED);
    ret &= secp256k1_ec_pubkey_serialize(ctx, transform_buf + 33, &pub_len, ky, SECP256K1_EC_COMPRESSED);

    /* c = SHA256(SHA256("ECDSAAtomicAdaptor/consistency") || SHA256("ECDSAAtomicAdaptor/consistency") || kv || kw || msg) */
    secp256k1_ecdsa_adaptor_tag_consistency(&sha);
    secp256k1_sha256_write(&sha, transform_buf, transform_len);
    secp256k1_sha256_write(&sha, msg, msg_len);
    secp256k1_sha256_finalize(&sha, buf);

    /* vc = nonce_left + c*kp */
    memcpy(&vc, kp, sizeof(*kp));
    ret &= secp256k1_ec_pubkey_tweak_mul(ctx, &vc, buf);
    nonce_arr[0] = &vc;
    nonce_arr[1] = &proof->nonce_left;
    ret &= secp256k1_ec_pubkey_combine(ctx, &vcs, nonce_arr, 2);

    /* wc = nonce_right + c*ky */
    memcpy(&wc, ky, sizeof(*ky));
    ret &= secp256k1_ec_pubkey_tweak_mul(ctx, &wc, buf);
    nonce_arr[0] = &wc;
    nonce_arr[1] = &proof->nonce_right;
    ret &= secp256k1_ec_pubkey_combine(ctx, &wcs, nonce_arr, 2);

    secp256k1_pubkey_load(ctx, &gbz_ge, &gbz);
    secp256k1_pubkey_load(ctx, &ubz_ge, &ubz);
    secp256k1_pubkey_load(ctx, &vc_ge, &vcs);
    secp256k1_pubkey_load(ctx, &wc_ge, &wcs);

    secp256k1_fe_normalize_weak(&gbz_ge.x);
    secp256k1_fe_normalize_weak(&vc_ge.x);
    secp256k1_fe_normalize_weak(&ubz_ge.x);
    secp256k1_fe_normalize_weak(&wc_ge.x);
    *r = secp256k1_fe_cmp_var(&gbz_ge.x, &vc_ge.x) == 0 && secp256k1_fe_cmp_var(&ubz_ge.x, &wc_ge.x) == 0;

    return ret;
}

SECP256K1_INLINE int secp256k1_ecdsa_pre_sign(const secp256k1_context *ctx, secp256k1_ecdsa_pre_signature *pre_sig, const unsigned char *msg, size_t msg_len, const secp256k1_pubkey *ypk, const secp256k1_fischlin_proof *y_proof, const unsigned char *xsk, const unsigned char *ksk, const unsigned char *rand) {
    int ret = 1, valid = 0, overflow = 0;
    secp256k1_ge k_ge;
    secp256k1_scalar rx, x, h, k;
    secp256k1_sha256 hsha;
    unsigned char buf[32];

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(msg != NULL);
    ARG_CHECK(ypk != NULL);
    ARG_CHECK(y_proof != NULL);
    ARG_CHECK(xsk != NULL);
    ARG_CHECK(ksk != NULL);
    ARG_CHECK(rand != NULL);

    ret &= secp256k1_fischlin_verify(ctx, &valid, ypk, y_proof);
    ret &= valid;

    /* K = k*y*g */
    memcpy(&pre_sig->k, ypk, sizeof(*ypk));
    ret &= secp256k1_ec_pubkey_tweak_mul(ctx, &pre_sig->k, ksk);

    /* r = f(K) */
    ret &= secp256k1_pubkey_load(ctx, &k_ge, &pre_sig->k);
    secp256k1_fe_get_b32(buf, &k_ge.x);
    secp256k1_scalar_set_b32(&pre_sig->r, buf, &overflow);
    ret &= !overflow;

    /* s~ = k^-1 * (H(m) + r*x) */
    secp256k1_scalar_set_b32(&rx, buf, &overflow);
    ret &= !overflow;
    secp256k1_scalar_set_b32(&x, xsk, &overflow);
    ret &= !overflow;
    secp256k1_scalar_mul(&rx, &rx, &x);

    secp256k1_sha256_initialize(&hsha);
    secp256k1_sha256_write(&hsha, msg, msg_len);
    secp256k1_sha256_finalize(&hsha, buf);

    secp256k1_scalar_set_b32(&h, buf, &overflow);
    ret &= !overflow;

    secp256k1_scalar_add(&rx, &rx, &h);

    secp256k1_scalar_set_b32(&k, ksk, &overflow);
    ret &= !overflow && !secp256k1_scalar_is_zero(&k) && !secp256k1_scalar_is_one(&k);

    secp256k1_scalar_inverse(&k, &k);

    secp256k1_scalar_mul(&pre_sig->s, &rx, &k);

    /* proof = Py((Kp, K), k) */
    secp256k1_scalar_set_b32(&rx, rand, &overflow);
    ret &= !overflow && secp256k1_ecdsa_consistency_prove(ctx, &pre_sig->proof, ypk, ksk, &rx, msg, msg_len);

    secp256k1_scalar_clear(&rx);
    secp256k1_scalar_clear(&x);
    secp256k1_scalar_clear(&h);
    secp256k1_scalar_clear(&k);

    return ret;
}

SECP256K1_INLINE int secp256k1_ecdsa_pre_verify(const secp256k1_context *ctx, int *r, const unsigned char *msg, size_t msg_len, const secp256k1_pubkey *ypk, const secp256k1_fischlin_proof *y_proof, const secp256k1_pubkey *xpk, const secp256k1_ecdsa_pre_signature *pre_sig) {
    int ret = 1, valid = 0, overflow = 0;
    secp256k1_scalar u, v, sinv;
    secp256k1_sha256 hsha;
    secp256k1_pubkey kp;
    secp256k1_ge k_ge;
    secp256k1_fe kr;
    unsigned char buf[32];

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(msg != NULL);
    ARG_CHECK(ypk != NULL);
    ARG_CHECK(y_proof != NULL);
    ARG_CHECK(xpk != NULL);
    ARG_CHECK(pre_sig != NULL);

    ret &= secp256k1_fischlin_verify(ctx, &valid, ypk, y_proof);
    *r = valid;

    /* u = H(m) * s^-1 */
    memcpy(&sinv, &pre_sig->s, sizeof(pre_sig->s));
    secp256k1_scalar_inverse(&sinv, &sinv);

    secp256k1_sha256_initialize(&hsha);
    secp256k1_sha256_write(&hsha, msg, msg_len);
    secp256k1_sha256_finalize(&hsha, buf);

    secp256k1_scalar_set_b32(&u, buf, &overflow);
    ret &= !overflow;

    secp256k1_scalar_mul(&u, &u, &sinv);

    /* v = r * s^-1 */
    memcpy(&v, &pre_sig->r, sizeof(pre_sig->r));
    secp256k1_scalar_mul(&v, &v, &sinv);

    /* K' = u*g + v*x*g */
    secp256k1_scalar_get_b32(buf, &v);
    memcpy(&kp, xpk, sizeof(*xpk));
    ret &= secp256k1_ec_pubkey_tweak_mul(ctx, &kp, buf);
    secp256k1_scalar_get_b32(buf, &u);
    ret &= secp256k1_ec_pubkey_tweak_add(ctx, &kp, buf);

    ret &= secp256k1_pubkey_load(ctx, &k_ge, &pre_sig->k);
    ret &= secp256k1_ecdsa_consistency_verify(ctx, &valid, ypk, &kp, &pre_sig->k, &pre_sig->proof, msg, msg_len);

    secp256k1_scalar_get_b32(buf, &pre_sig->r);
    secp256k1_fe_set_b32(&kr, buf);
    secp256k1_fe_normalize_weak(&kr);
    secp256k1_fe_normalize_weak(&k_ge.x);
    *r &= valid && secp256k1_fe_cmp_var(&kr, &k_ge.x) == 0;

    /* Cleanup */
    secp256k1_scalar_clear(&u);
    secp256k1_scalar_clear(&v);
    secp256k1_scalar_clear(&sinv);

    return ret;
}

SECP256K1_INLINE int secp256k1_ecdsa_adapt(unsigned char *sig64, const secp256k1_ecdsa_pre_signature *pre_sig, const unsigned char *y) {
    secp256k1_scalar s;
    int ret = 1, overflow = 0;

    VERIFY_CHECK(sig64 != NULL);
    VERIFY_CHECK(pre_sig != NULL);
    VERIFY_CHECK(y != NULL);

    secp256k1_scalar_set_b32(&s, y, &overflow);
    ret &= !overflow && !secp256k1_scalar_is_zero(&s) && !secp256k1_scalar_is_one(&s);

    secp256k1_scalar_inverse(&s, &s);
    secp256k1_scalar_mul(&s, &s, &pre_sig->s);
    secp256k1_scalar_cond_negate(&s, secp256k1_scalar_is_high(&s));

    secp256k1_scalar_get_b32(sig64, &pre_sig->r);
    secp256k1_scalar_get_b32(sig64 + 32, &s);

    secp256k1_scalar_clear(&s);

    return ret;
}

SECP256K1_INLINE int secp256k1_ecdsa_extract(const secp256k1_context* ctx, unsigned char *y, const unsigned char *sig64, const secp256k1_ecdsa_pre_signature *pre_sig, const secp256k1_fischlin_proof *proof) {
    secp256k1_scalar yp;
    secp256k1_scalar neg_yp;
    secp256k1_scalar y_inv;
    secp256k1_scalar r;
    secp256k1_scalar s;
    secp256k1_pubkey ypk;
    secp256k1_pubkey neg_ypk;
    int ret = 1, valid = 0, neg_valid = 0, overflow = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(y != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(pre_sig != NULL);
    ARG_CHECK(proof != NULL);

    secp256k1_scalar_set_b32(&r, sig64, &overflow);
    ret &= !overflow && secp256k1_scalar_eq(&r, &pre_sig->r);

    /* high `s` in the adapted signature is invalid */
    secp256k1_scalar_set_b32(&s, sig64 + 32, &overflow);
    ret &= !overflow && !secp256k1_scalar_is_high(&s);

    /* y = s^-1 * s' */
    secp256k1_scalar_inverse(&yp, &s);
    secp256k1_scalar_mul(&yp, &yp, &pre_sig->s);

    secp256k1_scalar_negate(&neg_yp, &yp);

    secp256k1_scalar_get_b32(y, &yp);
    ret &= secp256k1_ec_pubkey_create(ctx, &ypk, y);

    secp256k1_scalar_get_b32(y, &neg_yp);
    ret &= secp256k1_ec_pubkey_create(ctx, &neg_ypk, y);

    /* verify both `Y` and `-Y`, in case `s` was negated during `adapt` phase
     *
     * FIXME:
     *
     * This reduces the security of the scheme by 1-bit, because a brute-force
     * attacker now has half the search space to extract a valid `y`
     *
     * Is there any way to only check for exactly one value, and reject an
     * incorrectly signed pre-sig `s` value?
     *
     * Are there any other security vulnerabilities opened by performing both
     * checks?
     */
    ret &= secp256k1_fischlin_verify(ctx, &valid, &ypk, proof);
    ret &= secp256k1_fischlin_verify(ctx, &neg_valid, &neg_ypk, proof);

    if (valid) {
        secp256k1_scalar_get_b32(y, &yp);
    } else {
        secp256k1_scalar_get_b32(y, &neg_yp);
    }

    secp256k1_scalar_clear(&yp);
    secp256k1_scalar_clear(&neg_yp);
    secp256k1_scalar_clear(&y_inv);
    secp256k1_scalar_clear(&r);
    secp256k1_scalar_clear(&s);

    return ret & (valid | neg_valid);
}

#endif
