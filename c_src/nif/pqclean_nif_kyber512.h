#ifndef PQCLEAN_NIF_KYBER512_H
#define PQCLEAN_NIF_KYBER512_H

#ifdef __cplusplus
extern "C" {
#endif

#include "pqclean_nif.h"

/* NIF Function Declarations */

extern ERL_NIF_TERM pqclean_nif_kyber512_info_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM pqclean_nif_kyber512_keypair_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM pqclean_nif_kyber512_encapsulate_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
extern ERL_NIF_TERM pqclean_nif_kyber512_decapsulate_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

#ifdef __cplusplus
}
#endif

#endif