#include "pqclean_nif_sphincs_plus_sha2_256s_robust.h"

#include <crypto_sign/sphincs-sha2-256s-robust/clean/api.h>

/* NIF Function Definitions */

ERL_NIF_TERM
pqclean_nif_sphincs_plus_sha2_256s_robust_info_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
#define RET_MAP_SIZE (6)

    ERL_NIF_TERM map_term;
    ERL_NIF_TERM keys[RET_MAP_SIZE];
    ERL_NIF_TERM vals[RET_MAP_SIZE];
    size_t k = 0;
    size_t v = 0;

    if (argc != 0) {
        return EXCP_BADARG(env, "argc must be 0");
    }

    keys[k++] = enif_make_atom(env, "type");
    vals[v++] = enif_make_atom(env, "sign");
    keys[k++] = enif_make_atom(env, "name");
    vals[v++] = enif_make_string(env, PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_CRYPTO_ALGNAME, ERL_NIF_LATIN1);
    keys[k++] = enif_make_atom(env, "secretkeybytes");
    vals[v++] = enif_make_uint(env, PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES);
    keys[k++] = enif_make_atom(env, "publickeybytes");
    vals[v++] = enif_make_uint(env, PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES);
    keys[k++] = enif_make_atom(env, "signaturebytes");
    vals[v++] = enif_make_uint(env, PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_CRYPTO_BYTES);
    keys[k++] = enif_make_atom(env, "seedbytes");
    vals[v++] = enif_make_uint(env, PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_CRYPTO_SEEDBYTES);

    if (!enif_make_map_from_arrays(env, keys, vals, RET_MAP_SIZE, &map_term)) {
        return EXCP_BADARG(env, "Call to enif_make_map_from_arrays() failed: duplicate keys detected");
    }

    return map_term;

#undef RET_MAP_SIZE
}

ERL_NIF_TERM
pqclean_nif_sphincs_plus_sha2_256s_robust_keypair_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    int retval = -1;
    ERL_NIF_TERM pk_term;
    ERL_NIF_TERM sk_term;
    uint8_t *pk = NULL;
    uint8_t *sk = NULL;

    if (argc != 0) {
        return EXCP_BADARG(env, "argc must be 0");
    }

    pk = enif_make_new_binary(env, PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES, &pk_term);
    if (pk == NULL) {
        return EXCP_BADARG_F(env, "Call to enif_make_new_binary() failed: unable to allocate PublicKey of size %d-bytes",
                             PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES);
    }
    sk = enif_make_new_binary(env, PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES, &sk_term);
    if (sk == NULL) {
        return EXCP_BADARG_F(env, "Call to enif_make_new_binary() failed: unable to allocate SecretKey of size %d-bytes",
                             PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES);
    }

    retval = PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_crypto_sign_keypair(pk, sk);
    if (retval != 0) {
        return EXCP_ERROR(env, "Call to PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_crypto_sign_keypair() failed");
    }
    return enif_make_tuple2(env, pk_term, sk_term);
}

ERL_NIF_TERM
pqclean_nif_sphincs_plus_sha2_256s_robust_keypair_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    int retval = -1;
    ErlNifBinary seed_bin;
    ERL_NIF_TERM pk_term;
    ERL_NIF_TERM sk_term;
    uint8_t *pk = NULL;
    uint8_t *sk = NULL;

    if (argc != 1) {
        return EXCP_BADARG(env, "argc must be 1");
    }
    if (!enif_inspect_binary(env, argv[0], &seed_bin) || seed_bin.size != PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_CRYPTO_SEEDBYTES) {
        return EXCP_BADARG_F(env, "Seed is invalid (must be a binary of size %d-bytes)",
                             PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_CRYPTO_SEEDBYTES);
    }
    pk = enif_make_new_binary(env, PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES, &pk_term);
    if (pk == NULL) {
        return EXCP_BADARG_F(env, "Call to enif_make_new_binary() failed: unable to allocate PublicKey of size %d-bytes",
                             PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES);
    }
    sk = enif_make_new_binary(env, PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES, &sk_term);
    if (sk == NULL) {
        return EXCP_BADARG_F(env, "Call to enif_make_new_binary() failed: unable to allocate SecretKey of size %d-bytes",
                             PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES);
    }

    retval = PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_crypto_sign_seed_keypair(pk, sk, seed_bin.data);
    if (retval != 0) {
        return EXCP_ERROR(env, "Call to PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_crypto_sign_seed_keypair() failed");
    }
    return enif_make_tuple2(env, pk_term, sk_term);
}

ERL_NIF_TERM
pqclean_nif_sphincs_plus_sha2_256s_robust_sign_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    int retval = -1;
    ErlNifBinary m_bin;
    ErlNifBinary sk_bin;
    ERL_NIF_TERM sig_term;
    uint8_t *sig = NULL;
    size_t siglen;

    if (argc != 2) {
        return EXCP_BADARG(env, "argc must be 2");
    }
    if (!enif_inspect_binary(env, argv[0], &m_bin)) {
        return EXCP_BADARG(env, "Message is invalid (must be a binary)");
    }
    if (!enif_inspect_binary(env, argv[1], &sk_bin) || sk_bin.size != PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES) {
        return EXCP_BADARG_F(env, "SecretKey is invalid (must be a binary of size %d-bytes)",
                             PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_CRYPTO_SECRETKEYBYTES);
    }
    sig = enif_make_new_binary(env, PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_CRYPTO_BYTES, &sig_term);
    if (sig == NULL) {
        return EXCP_BADARG_F(env, "Call to enif_make_new_binary() failed: unable to allocate Signature of size %d-bytes",
                             PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_CRYPTO_BYTES);
    }

    retval = PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_crypto_sign_signature(sig, &siglen, m_bin.data, m_bin.size, sk_bin.data);
    if (retval != 0) {
        return EXCP_ERROR(env, "Call to PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_crypto_sign_signature() failed");
    }
    if (siglen < PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_CRYPTO_BYTES) {
        sig_term = enif_make_sub_binary(env, sig_term, 0, siglen);
    }
    return sig_term;
}

ERL_NIF_TERM
pqclean_nif_sphincs_plus_sha2_256s_robust_verify_3(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    int retval = -1;
    ErlNifBinary sig_bin;
    ErlNifBinary m_bin;
    ErlNifBinary pk_bin;

    if (argc != 3) {
        return EXCP_BADARG(env, "argc must be 3");
    }
    if (!enif_inspect_binary(env, argv[0], &sig_bin) || sig_bin.size > PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_CRYPTO_BYTES) {
        return EXCP_BADARG_F(env, "Signature is invalid (must be a binary of size less-than-or-equal-to %d-bytes)",
                             PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_CRYPTO_BYTES);
    }
    if (!enif_inspect_binary(env, argv[1], &m_bin)) {
        return EXCP_BADARG(env, "Message is invalid (must be a binary)");
    }
    if (!enif_inspect_binary(env, argv[2], &pk_bin) || pk_bin.size != PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES) {
        return EXCP_BADARG_F(env, "PublicKey is invalid (must be a binary of size %d-bytes)",
                             PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_CRYPTO_PUBLICKEYBYTES);
    }

    retval =
        PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_crypto_sign_verify(sig_bin.data, sig_bin.size, m_bin.data, m_bin.size, pk_bin.data);
    if (retval != 0) {
        return ATOM(false);
    }
    return ATOM(true);
}