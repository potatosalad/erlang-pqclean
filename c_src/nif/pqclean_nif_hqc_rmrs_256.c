#include "pqclean_nif_hqc_rmrs_256.h"

#include <crypto_kem/hqc-rmrs-256/clean/api.h>

/* NIF Function Definitions */

ERL_NIF_TERM
pqclean_nif_hqc_rmrs_256_info_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
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
    vals[v++] = enif_make_atom(env, "kem");
    keys[k++] = enif_make_atom(env, "name");
    vals[v++] = enif_make_string(env, PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_ALGNAME, ERL_NIF_LATIN1);
    keys[k++] = enif_make_atom(env, "secretkeybytes");
    vals[v++] = enif_make_uint(env, PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_SECRETKEYBYTES);
    keys[k++] = enif_make_atom(env, "publickeybytes");
    vals[v++] = enif_make_uint(env, PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_PUBLICKEYBYTES);
    keys[k++] = enif_make_atom(env, "ciphertextbytes");
    vals[v++] = enif_make_uint(env, PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    keys[k++] = enif_make_atom(env, "sharedsecretbytes");
    vals[v++] = enif_make_uint(env, PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_BYTES);

    if (!enif_make_map_from_arrays(env, keys, vals, RET_MAP_SIZE, &map_term)) {
        return EXCP_BADARG(env, "Call to enif_make_map_from_arrays() failed: duplicate keys detected");
    }

    return map_term;

#undef RET_MAP_SIZE
}

ERL_NIF_TERM
pqclean_nif_hqc_rmrs_256_keypair_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    int retval = -1;
    ERL_NIF_TERM pk_term;
    ERL_NIF_TERM sk_term;
    uint8_t *pk = NULL;
    uint8_t *sk = NULL;

    if (argc != 0) {
        return EXCP_BADARG(env, "argc must be 0");
    }

    pk = enif_make_new_binary(env, PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_PUBLICKEYBYTES, &pk_term);
    if (pk == NULL) {
        return EXCP_BADARG_F(env, "Call to enif_make_new_binary() failed: unable to allocate PublicKey of size %d-bytes",
                             PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_PUBLICKEYBYTES);
    }
    sk = enif_make_new_binary(env, PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_SECRETKEYBYTES, &sk_term);
    if (sk == NULL) {
        return EXCP_BADARG_F(env, "Call to enif_make_new_binary() failed: unable to allocate SecretKey of size %d-bytes",
                             PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_SECRETKEYBYTES);
    }

    retval = PQCLEAN_HQCRMRS256_CLEAN_crypto_kem_keypair(pk, sk);
    if (retval != 0) {
        return EXCP_BADARG(env, "Call to PQCLEAN_HQCRMRS256_CLEAN_crypto_kem_keypair() failed");
    }
    return enif_make_tuple2(env, pk_term, sk_term);
}

ERL_NIF_TERM
pqclean_nif_hqc_rmrs_256_encapsulate_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    int retval = -1;
    ErlNifBinary pk_bin;
    ERL_NIF_TERM ct_term;
    ERL_NIF_TERM ss_term;
    uint8_t *ct = NULL;
    uint8_t *ss = NULL;

    if (argc != 1) {
        return EXCP_BADARG(env, "argc must be 1");
    }
    if (!enif_inspect_binary(env, argv[0], &pk_bin) || pk_bin.size != PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_PUBLICKEYBYTES) {
        return EXCP_BADARG_F(env, "PublicKey is invalid (must be a binary of size %d-bytes)",
                             PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_PUBLICKEYBYTES);
    }
    ct = enif_make_new_binary(env, PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_CIPHERTEXTBYTES, &ct_term);
    if (ct == NULL) {
        return EXCP_BADARG_F(env, "Call to enif_make_new_binary() failed: unable to allocate CipherText of size %d-bytes",
                             PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    }
    ss = enif_make_new_binary(env, PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_BYTES, &ss_term);
    if (ss == NULL) {
        return EXCP_BADARG_F(env, "Call to enif_make_new_binary() failed: unable to allocate SharedSecret of size %d-bytes",
                             PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_BYTES);
    }

    retval = PQCLEAN_HQCRMRS256_CLEAN_crypto_kem_enc(ct, ss, pk_bin.data);
    if (retval != 0) {
        return EXCP_BADARG(env, "Call to PQCLEAN_HQCRMRS256_CLEAN_crypto_kem_enc() failed");
    }
    return enif_make_tuple2(env, ct_term, ss_term);
}

ERL_NIF_TERM
pqclean_nif_hqc_rmrs_256_decapsulate_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    int retval = -1;
    ErlNifBinary ct_bin;
    ErlNifBinary sk_bin;
    ERL_NIF_TERM ss_term;
    uint8_t *ss = NULL;

    if (argc != 2) {
        return EXCP_BADARG(env, "argc must be 2");
    }
    if (!enif_inspect_binary(env, argv[0], &ct_bin) || ct_bin.size != PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_CIPHERTEXTBYTES) {
        return EXCP_BADARG_F(env, "CipherText is invalid (must be a binary of size %d-bytes)",
                             PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    }
    if (!enif_inspect_binary(env, argv[1], &sk_bin) || sk_bin.size != PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_SECRETKEYBYTES) {
        return EXCP_BADARG_F(env, "SecretKey is invalid (must be a binary of size %d-bytes)",
                             PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_SECRETKEYBYTES);
    }
    ss = enif_make_new_binary(env, PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_BYTES, &ss_term);
    if (ss == NULL) {
        return EXCP_BADARG_F(env, "Call to enif_make_new_binary() failed: unable to allocate SharedSecret of size %d-bytes",
                             PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_BYTES);
    }

    retval = PQCLEAN_HQCRMRS256_CLEAN_crypto_kem_dec(ss, ct_bin.data, sk_bin.data);
    if (retval != 0) {
        return EXCP_BADARG(env, "Call to PQCLEAN_HQCRMRS256_CLEAN_crypto_kem_dec() failed");
    }
    return ss_term;
}