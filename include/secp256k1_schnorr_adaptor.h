/***********************************************************************
 * Copyright (c) 2021 Gene Ferneau                                     *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. *
 ***********************************************************************/

#ifndef _SECP256K1_SCHNORR_ADAPTOR_
#define _SECP256K1_SCHNORR_ADAPTOR_

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

SECP256K1_API int secp256k1_schnorr_pre_sign(
    const secp256k1_context *ctx,
    secp256k1_scalar *r,
    secp256k1_scalar *s,
    const unsigned char *msg32,
    const secp256k1_pubkey *ypk,
    const unsigned char *sk,
    const secp256k1_scalar *a
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7) SECP256K1_WARN_UNUSED_RESULT;

SECP256K1_API int secp256k1_schnorr_pre_verify(
    const secp256k1_context *ctx,
    int *r,
    const unsigned char *msg32,
    const secp256k1_pubkey *ypk,
    const secp256k1_scalar *r,
    const secp256k1_scalar *s,
    const secp256k1_pubkey *pk
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7) SECP256K1_WARN_UNUSED_RESULT;

#ifdef __cplusplus
}

#endif
