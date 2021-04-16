#ifndef _SECP256K1_ECDSA_ADAPTOR_
#define _SECP256K1_ECDSA_ADAPTOR_

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Number of repetitions for computing challenges and responses
 */
const size_t SECP256K1_FISCHLIN_R = 16;

/** Bit-size of the challenge hash function
 */
const size_t SECP256K1_FISCHLIN_B = 16;

/** Maximum sum of the challenge hashes
 */
const uint16_t SECP256K1_FISCHLIN_S = 16;

/** Bit-size of the challenges to the inner proof
 */
const uint16_t SECP256K1_FISCHLIN_T = 24;

/** SHA256("ECDSAAtomicAdaptor/aux") || SHA256("ECDSAAtomicAdaptor/aux")
 */
static const unsigned char SECP256K1_ECDSA_ADAPTOR_TAG_AUX[64] = {
    0x88, 0x1c, 0xe6, 0x3c, 0xd1, 0x09, 0xd3, 0x2c, 0xfe, 0x79, 0x75, 0x45, 0xc9, 0x3e, 0xb6, 0xb4,
    0xb7, 0x6e, 0xd1, 0xf8, 0x71, 0x8d, 0x66, 0x56, 0x6b, 0xd0, 0x13, 0xb5, 0x14, 0x1e, 0x6e, 0x9d,
    0x88, 0x1c, 0xe6, 0x3c, 0xd1, 0x09, 0xd3, 0x2c, 0xfe, 0x79, 0x75, 0x45, 0xc9, 0x3e, 0xb6, 0xb4,
    0xb7, 0x6e, 0xd1, 0xf8, 0x71, 0x8d, 0x66, 0x56, 0x6b, 0xd0, 0x13, 0xb5, 0x14, 0x1e, 0x6e, 0x9d
};

/** SHA256("ECDSAAtomicAdaptor/challenge") || SHA256("ECDSAAtomicAdaptor/challenge")
 */
static const unsigned char SECP256K1_ECDSA_ADAPTOR_TAG_CHALLENGE[64] = {
    0xc4, 0x06, 0x4c, 0x5c, 0x3b, 0x71, 0x83, 0x91, 0x5d, 0x97, 0x28, 0xdd, 0x93, 0x2b, 0xa5, 0xc3,
    0x63, 0xa4, 0xea, 0xb9, 0x69, 0xc3, 0x2c, 0xbe, 0xd0, 0xd4, 0x43, 0x3d, 0xd8, 0x3e, 0x6d, 0x82,
    0xc4, 0x06, 0x4c, 0x5c, 0x3b, 0x71, 0x83, 0x91, 0x5d, 0x97, 0x28, 0xdd, 0x93, 0x2b, 0xa5, 0xc3,
    0x63, 0xa4, 0xea, 0xb9, 0x69, 0xc3, 0x2c, 0xbe, 0xd0, 0xd4, 0x43, 0x3d, 0xd8, 0x3e, 0x6d, 0x82
};

/** SHA256("ECDSAAtomicAdaptor/nonce") || SHA256("ECDSAAtomicAdaptor/nonce")
 */
static const unsigned char SECP256K1_ECDSA_ADAPTOR_TAG_NONCE[64] = {
    0x34, 0xc1, 0x5c, 0x62, 0x21, 0xf7, 0xc9, 0xaa, 0x9d, 0xf4, 0x87, 0x24, 0x56, 0x0b, 0x87, 0xa2,
    0x85, 0x00, 0x54, 0x4b, 0xc6, 0x05, 0x8d, 0x52, 0xfb, 0x37, 0x96, 0x9f, 0xa7, 0x4d, 0xa1, 0xc0,
    0x34, 0xc1, 0x5c, 0x62, 0x21, 0xf7, 0xc9, 0xaa, 0x9d, 0xf4, 0x87, 0x24, 0x56, 0x0b, 0x87, 0xa2,
    0x85, 0x00, 0x54, 0x4b, 0xc6, 0x05, 0x8d, 0x52, 0xfb, 0x37, 0x96, 0x9f, 0xa7, 0x4d, 0xa1, 0xc0
};

typedef secp256k1_pubkey secp256k1_fischlin_commitment;
typedef uint32_t secp256k1_fischlin_challenge;
typedef secp256k1_scalar secp256k1_fischlin_response;
typedef uint16_t secp256k1_fischlin_score;

/** Data structure to represent a Fischlin NIZK proof
 *
 * Contains the commitments to randomness, challenges, and responses
 * for each of the R rounds.
 */
typedef struct {
    secp256k1_fischlin_commitment *coms;
    secp256k1_fischlin_challenge *chals;
    secp256k1_fischlin_response *resps;
} secp256k1_fischlin_proof;

/** Data structure to represent a Chaum-Pedersen NIZK proof
 *
 * Used to prove the statement: `Kp = k*g ^ K = k*Y, where Y = y*g`
 */
typedef struct {
    secp256k1_pubkey nonce_left;
    secp256k1_pubkey nonce_right;
    secp256k1_scalar challenge;
} secp256k1_chaum_pedersen_proof;

/** Data structure to represent an ECDSA pre-signature
 *
 * Contains the field element `r`, scalar `s`, public key `K = k*Y`, and a
 * Chaum-Pedersen consistency proof
 */
typedef struct {
    secp256k1_scalar r;
    secp256k1_scalar s;
    secp256k1_pubkey k;
    secp256k1_chaum_pedersen_proof proof;
} secp256k1_ecdsa_pre_signature;

/** Allocate memory for an ECDSA pre-signature
 */
SECP256K1_API secp256k1_ecdsa_pre_signature* secp256k1_ecdsa_pre_signature_create(void) SECP256K1_WARN_UNUSED_RESULT;

/** Destroy an ECDSA pre-signature created with secp256k1_ecdsa_pre_signature_create
 */
SECP256K1_API void secp256k1_ecdsa_pre_signature_destroy(secp256k1_ecdsa_pre_signature *pre_sig) SECP256K1_ARG_NONNULL(1);

/** Allocate memory for a Fischlin NIZK proof
 */
SECP256K1_API secp256k1_fischlin_proof* secp256k1_fischlin_proof_create(void) SECP256K1_WARN_UNUSED_RESULT;

/** Initialize a Fischlin proof with default values
 *
 * Useful if the proof was not created using secp256k1_fischlin_proof_create
 */
SECP256K1_API int secp256k1_fischlin_proof_init(secp256k1_fischlin_proof *proof) SECP256K1_ARG_NONNULL(1) SECP256K1_WARN_UNUSED_RESULT;

/** Free the memory for the inner pointers of the Fischlin proof
 */
SECP256K1_API void secp256k1_fischlin_proof_deinit(secp256k1_fischlin_proof *proof) SECP256K1_ARG_NONNULL(1);

/** Destroy a Fischlin proof created with secp256k1_fischlin_proof_create
 *
 * Frees the inner pointers and the proof pointer
 */
SECP256K1_API void secp256k1_fischlin_proof_destroy(secp256k1_fischlin_proof *proof) SECP256K1_ARG_NONNULL(1);

/** Prove knowledge of exponent using Fischlin NIZK proofs
 *
 * Computes `R` challenge-response pairs over Schnorr proofs of identity
 * by submitting `1, 2, 3, ..., 2^T - 1` as `T`-bit string challenges.
 *
 * The witness, commitment vector, index, challenge, and response are
 * input into a hash function (SHA-256), and the first `B` bits are checked
 * to be equal to zero.
 *
 * If the bits are zero, the tuple (commitment, challenge, response) is accepted as
 * a partial proof. If not, the challenge with the lowest value (`B` bits interpreted
 * as a big-endian integer) without causing the cumulative sum to go over `S` is accepted.
 * 
 * If no valid challenges are found for any given commitment, the proof is invalid, and must
 * be retried with new randomness for the commitments (extremely unlikely).
 *
 * Returns: 0 on error, non-zero on success
 * Args:    ctx: an existing secp256k1_context (cannot be NULL)
 *        proof: Fischlin proof to store the result
 *       seckey: secret key of the prover
 *           vs: vector of random scalars to create the commitments for each round
 */
SECP256K1_API int secp256k1_fischlin_prove(
    const secp256k1_context *ctx,
    secp256k1_fischlin_proof *proof,
    const unsigned char *seckey,
    const secp256k1_scalar *vs
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_WARN_UNUSED_RESULT;

/** Verify Fischlin NIZK proofs of knowledge of exponent for a discrete logarithm
 * 
 * For the prover public key and proof tuples `(commit, challenge, response)`, verify that each
 * Schnorr proof of identity is valid, and:
 * 
 * > Sum[i=0, R-1](Hash(x, commits, i, challenge[i], response[i])[..HashLen-B]) <= S
 *
 * Otherwise, the proof is invalid.
 *
 * Returns: 0 on error, non-zero on success
 * Args:    ctx: an existing secp256k1_context (cannot be NULL)
 *            r: int indicating the validity of the proof, (0=invalid, 1=valid)
 *       pubkey: public key of the prover
 *        proof: Fischlin proof being verified
 */
SECP256K1_API int secp256k1_fischlin_verify(
    const secp256k1_context *ctx,
    int *r,
    const secp256k1_pubkey *pubkey,
    const secp256k1_fischlin_proof *proof
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_WARN_UNUSED_RESULT;

SECP256K1_API int secp256k1_ecdsa_consistency_prove(
    const secp256k1_context *ctx,
    secp256k1_chaum_pedersen_proof *proof,
    const secp256k1_pubkey *ypk,
    const unsigned char *sk,
    const secp256k1_scalar *rand,
    const unsigned char *msg,
    size_t msg_len
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_WARN_UNUSED_RESULT;

SECP256K1_API int secp256k1_ecdsa_consistency_verify(
    const secp256k1_context *ctx,
    int *r,
    const secp256k1_pubkey *ypk,
    const secp256k1_pubkey *kp,
    const secp256k1_pubkey *ky,
    const secp256k1_chaum_pedersen_proof *proof,
    const unsigned char *msg,
    size_t msg_len
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7) SECP256K1_WARN_UNUSED_RESULT;

/** Initial phase of creating an ECDSA adaptor signature
 *
 * Pre-sign a message returning the partial signature, adaptor public key, and a NIZK proof that the
 * same private key was used for the partial signature and public key `K = k*Y`.
 *
 * Returns: 0 on error, non-zero on success
 * Args:     ctx: an existing secp256k1_context (cannot be NULL)
 *       pre_sig: pre-signature result over the provided message
 *           msg: message being signed
 *       msg_len: length of the message being signed
 *           ypk: adaptor public key
 *       y_proof: Fischlin proof that `Y = y*g` being verified
 *           xsk: signer's secret key
 *           ksk: signer's secret random nonce
 *          rand: random nonce for the signer's consistency proof that `Kp = k*g ^ K = k*Y`
 */
SECP256K1_API int secp256k1_ecdsa_pre_sign(
    const secp256k1_context *ctx,
    secp256k1_ecdsa_pre_signature *pre_sig,
    const unsigned char *msg,
    size_t msg_len,
    const secp256k1_pubkey *ypk,
    const secp256k1_fischlin_proof *y_proof,
    const unsigned char *xsk,
    const unsigned char *ksk,
    const unsigned char *rand
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(8) SECP256K1_ARG_NONNULL(9) SECP256K1_WARN_UNUSED_RESULT;

/** Verify a partial ECDSA adaptor signature
 *
 * Returns: 0 on error, non-zero on success
 * Args:     ctx: an existing secp256k1_context (cannot be NULL)
 *             r: return value for the validity of the pre-signature (0 = invalid, 1 = valid)
 *           msg: signed message
 *       msg_len: length of the signed message
 *           ypk: adaptor public key
 *       y_proof: Fischlin proof that `Y = y*g` being verified
 *           xpk: signer's public key
 *       pre_sig: pre-signature over the provided message 
 */
SECP256K1_API int secp256k1_ecdsa_pre_verify(
    const secp256k1_context *ctx,
    int *r,
    const unsigned char *msg,
    size_t msg_len,
    const secp256k1_pubkey *ypk,
    const secp256k1_fischlin_proof *y_proof,
    const secp256k1_pubkey *xpk,
    const secp256k1_ecdsa_pre_signature *pre_sig
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7) SECP256K1_WARN_UNUSED_RESULT;

/** Adapt an ECDSA pre-signature into a full signature, allowing any party
 * with the pre-signature to extract the witness `y`
 *
 * Returns: 0 on error, non-zero on success
 * Args:       r: return `r` scalar of the adapted ECDSA signature
 *             s: return `s` scalar of the adapted ECDSA signature
 *       pre_sig: pre-signature to adapt into a full ECDSA signature
 *             y: adaptor witness to adapt the pre-signature
 */
SECP256K1_API int secp256k1_ecdsa_adapt(
    unsigned char *sig64,
    const secp256k1_ecdsa_pre_signature *pre_sig,
    const unsigned char *y
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_WARN_UNUSED_RESULT;

/** Extract a witness `y` from an adaptor signature and pre-signature
 * 
 * The witness can be used to sign for contracts created under the statement (PublicKey) `Y = g^y`
 *
 * Returns: 0 on error, non-zero on success
 * Args:       y: return adaptor witness
 *             r: return `r` scalar of the adapted ECDSA signature
 *             s: return `s` scalar of the adapted ECDSA signature
 *       pre_sig: pre-signature to adapt into a full ECDSA signature
 *         proof: Fischlin proof that `Y = y*g`
 */
SECP256K1_API int secp256k1_ecdsa_extract(
    const secp256k1_context *ctx,
    unsigned char *y,
    const unsigned char *sig64,
    const secp256k1_ecdsa_pre_signature *pre_sig,
    const secp256k1_fischlin_proof *proof
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_WARN_UNUSED_RESULT;

#ifdef __cplusplus
}
#endif

#endif
