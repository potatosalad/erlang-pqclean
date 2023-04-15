#ifndef PQCLEAN_NIF_dilithium5aes_H
#define PQCLEAN_NIF_dilithium5aes_H

#ifdef __cplusplus
extern "C" {
#endif

#include "pqclean_nif.h"

/* NIF Function Declarations */

extern ERL_NIF_TERM pqclean_nif_dilithium5aes_info_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM pqclean_nif_dilithium5aes_keypair_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM pqclean_nif_dilithium5aes_sign_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM pqclean_nif_dilithium5aes_verify_3(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

#ifdef __cplusplus
}
#endif

#endif