#ifndef PQCLEAN_NIF_SPHINCS_PLUS_SHA2_192S_SIMPLE_H
#define PQCLEAN_NIF_SPHINCS_PLUS_SHA2_192S_SIMPLE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "pqclean_nif.h"

/* NIF Function Declarations */

extern ERL_NIF_TERM pqclean_nif_sphincs_plus_sha2_192s_simple_info_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM pqclean_nif_sphincs_plus_sha2_192s_simple_keypair_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM pqclean_nif_sphincs_plus_sha2_192s_simple_keypair_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM pqclean_nif_sphincs_plus_sha2_192s_simple_sign_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM pqclean_nif_sphincs_plus_sha2_192s_simple_verify_3(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

#ifdef __cplusplus
}
#endif

#endif