#ifndef PQCLEAN_NIF_SPHINCS_PLUS_SHAKE_128S_ROBUST_H
#define PQCLEAN_NIF_SPHINCS_PLUS_SHAKE_128S_ROBUST_H

#ifdef __cplusplus
extern "C" {
#endif

#include "pqclean_nif.h"

/* NIF Function Declarations */

extern ERL_NIF_TERM pqclean_nif_sphincs_plus_shake_128s_robust_info_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM pqclean_nif_sphincs_plus_shake_128s_robust_keypair_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM pqclean_nif_sphincs_plus_shake_128s_robust_keypair_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM pqclean_nif_sphincs_plus_shake_128s_robust_sign_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM pqclean_nif_sphincs_plus_shake_128s_robust_verify_3(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

#ifdef __cplusplus
}
#endif

#endif