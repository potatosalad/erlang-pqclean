#include "pqclean_nif.h"

#include <errno.h>
#include <stdbool.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <pthread.h>
#elif defined(__FreeBSD__)
#include <pthread.h>
#include <pthread_np.h>
#elif defined(__linux__)
#define _GNU_SOURCE
#include <pthread.h>
#endif

#include "pqclean_nif_hqc_rmrs_128.h"
#include "pqclean_nif_hqc_rmrs_192.h"
#include "pqclean_nif_hqc_rmrs_256.h"
#include "pqclean_nif_kyber512.h"
#include "pqclean_nif_kyber512_90s.h"
#include "pqclean_nif_kyber768.h"
#include "pqclean_nif_kyber768_90s.h"
#include "pqclean_nif_kyber1024.h"
#include "pqclean_nif_kyber1024_90s.h"
#include "pqclean_nif_mceliece348864.h"
#include "pqclean_nif_mceliece348864f.h"
#include "pqclean_nif_mceliece460896.h"
#include "pqclean_nif_mceliece460896f.h"
#include "pqclean_nif_mceliece6688128.h"
#include "pqclean_nif_mceliece6688128f.h"
#include "pqclean_nif_mceliece6960119.h"
#include "pqclean_nif_mceliece6960119f.h"
#include "pqclean_nif_mceliece8192128.h"
#include "pqclean_nif_mceliece8192128f.h"

#include "pqclean_nif_dilithium2.h"
#include "pqclean_nif_dilithium2aes.h"
#include "pqclean_nif_dilithium3.h"
#include "pqclean_nif_dilithium3aes.h"
#include "pqclean_nif_dilithium5.h"
#include "pqclean_nif_dilithium5aes.h"
#include "pqclean_nif_falcon512.h"
#include "pqclean_nif_falcon1024.h"
#include "pqclean_nif_sphincs_plus_haraka_128f_robust.h"
#include "pqclean_nif_sphincs_plus_haraka_128f_simple.h"
#include "pqclean_nif_sphincs_plus_haraka_128s_robust.h"
#include "pqclean_nif_sphincs_plus_haraka_128s_simple.h"
#include "pqclean_nif_sphincs_plus_haraka_192f_robust.h"
#include "pqclean_nif_sphincs_plus_haraka_192f_simple.h"
#include "pqclean_nif_sphincs_plus_haraka_192s_robust.h"
#include "pqclean_nif_sphincs_plus_haraka_192s_simple.h"
#include "pqclean_nif_sphincs_plus_haraka_256f_robust.h"
#include "pqclean_nif_sphincs_plus_haraka_256f_simple.h"
#include "pqclean_nif_sphincs_plus_haraka_256s_robust.h"
#include "pqclean_nif_sphincs_plus_haraka_256s_simple.h"
#include "pqclean_nif_sphincs_plus_sha2_128f_robust.h"
#include "pqclean_nif_sphincs_plus_sha2_128f_simple.h"
#include "pqclean_nif_sphincs_plus_sha2_128s_robust.h"
#include "pqclean_nif_sphincs_plus_sha2_128s_simple.h"
#include "pqclean_nif_sphincs_plus_sha2_192f_robust.h"
#include "pqclean_nif_sphincs_plus_sha2_192f_simple.h"
#include "pqclean_nif_sphincs_plus_sha2_192s_robust.h"
#include "pqclean_nif_sphincs_plus_sha2_192s_simple.h"
#include "pqclean_nif_sphincs_plus_sha2_256f_robust.h"
#include "pqclean_nif_sphincs_plus_sha2_256f_simple.h"
#include "pqclean_nif_sphincs_plus_sha2_256s_robust.h"
#include "pqclean_nif_sphincs_plus_sha2_256s_simple.h"
#include "pqclean_nif_sphincs_plus_shake_128f_robust.h"
#include "pqclean_nif_sphincs_plus_shake_128f_simple.h"
#include "pqclean_nif_sphincs_plus_shake_128s_robust.h"
#include "pqclean_nif_sphincs_plus_shake_128s_simple.h"
#include "pqclean_nif_sphincs_plus_shake_192f_robust.h"
#include "pqclean_nif_sphincs_plus_shake_192f_simple.h"
#include "pqclean_nif_sphincs_plus_shake_192s_robust.h"
#include "pqclean_nif_sphincs_plus_shake_192s_simple.h"
#include "pqclean_nif_sphincs_plus_shake_256f_robust.h"
#include "pqclean_nif_sphincs_plus_shake_256f_simple.h"
#include "pqclean_nif_sphincs_plus_shake_256s_robust.h"
#include "pqclean_nif_sphincs_plus_shake_256s_simple.h"

/* Types */

/* Global Variables */

static pqclean_nif_atom_table_t pqclean_nif_atom_table_internal;
pqclean_nif_atom_table_t *pqclean_nif_atom_table = &pqclean_nif_atom_table_internal;

/* Static Variables */

/* Resource Type Functions (Declarations) */

/* Global Function Definitions */

int
_pqclean_nif_get_thread_stack_size(size_t *stack_sizep, ErlNifEnv *env, ERL_NIF_TERM *error_term)
{
    size_t stack_size = 0;
#if defined(__FreeBSD__) || defined(__linux__)
    pthread_attr_t attr;
    int retval;
    int errnum;
#endif

#if defined(__APPLE__)
    stack_size = (size_t)pthread_get_stacksize_np(pthread_self());
#elif defined(__FreeBSD__)
    retval = pthread_attr_get_np(pthread_self(), &attr);
    if (retval != 0) {
        errnum = errno;
        if (env != NULL && error_term != NULL) {
            *error_term = EXCP_ERROR_F(env, "Call to pthread_attr_get_np() failed: %s", strerror(errnum));
        }
        return -1;
    }
    retval = pthread_attr_getstacksize(&attr, &stack_size);
    if (retval != 0) {
        errnum = errno;
        (void)pthread_attr_destroy(&attr);
        if (env != NULL && error_term != NULL) {
            *error_term = EXCP_ERROR_F(env, "Call to pthread_attr_getstacksize() failed: %s", strerror(errnum));
        }
        return -1;
    }
#elif defined(__linux__)
    retval = pthread_getattr_np(pthread_self(), &attr);
    if (retval != 0) {
        errnum = errno;
        if (env != NULL && error_term != NULL) {
            *error_term = EXCP_ERROR_F(env, "Call to pthread_getattr_np() failed: %s", strerror(errnum));
        }
        return -1;
    }
    retval = pthread_attr_getstacksize(&attr, &stack_size);
    if (retval != 0) {
        errnum = errno;
        (void)pthread_attr_destroy(&attr);
        if (env != NULL && error_term != NULL) {
            *error_term = EXCP_ERROR_F(env, "Call to pthread_attr_getstacksize() failed: %s", strerror(errnum));
        }
        return -1;
    }
#else
    return -1;
#endif
    if (stack_sizep != NULL) {
        *stack_sizep = stack_size;
    }
#if defined(__FreeBSD__) || defined(__linux__)
    (void)pthread_attr_destroy(&attr);
#endif

    return 0;
}

/* NIF Function Declarations */

static ERL_NIF_TERM pqclean_nif_dirty_job_cpu_stack_size_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

/* NIF Function Definitions */

ERL_NIF_TERM
pqclean_nif_dirty_job_cpu_stack_size_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    size_t stack_size = 0;
    ERL_NIF_TERM out_term;

    if (_pqclean_nif_get_thread_stack_size(&stack_size, env, &out_term) != 0) {
        return out_term;
    }

    out_term = enif_make_uint64(env, (ErlNifUInt64)stack_size);
    return out_term;
}

/* NIF Callbacks */

static ErlNifFunc pqclean_nif_funcs[] = {
    {"dirty_job_cpu_stack_size", 0, pqclean_nif_dirty_job_cpu_stack_size_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"hqc_rmrs_128_info", 0, pqclean_nif_hqc_rmrs_128_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"hqc_rmrs_128_keypair", 0, pqclean_nif_hqc_rmrs_128_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"hqc_rmrs_128_encapsulate", 1, pqclean_nif_hqc_rmrs_128_encapsulate_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"hqc_rmrs_128_decapsulate", 2, pqclean_nif_hqc_rmrs_128_decapsulate_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"hqc_rmrs_192_info", 0, pqclean_nif_hqc_rmrs_192_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"hqc_rmrs_192_keypair", 0, pqclean_nif_hqc_rmrs_192_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"hqc_rmrs_192_encapsulate", 1, pqclean_nif_hqc_rmrs_192_encapsulate_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"hqc_rmrs_192_decapsulate", 2, pqclean_nif_hqc_rmrs_192_decapsulate_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"hqc_rmrs_256_info", 0, pqclean_nif_hqc_rmrs_256_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"hqc_rmrs_256_keypair", 0, pqclean_nif_hqc_rmrs_256_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"hqc_rmrs_256_encapsulate", 1, pqclean_nif_hqc_rmrs_256_encapsulate_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"hqc_rmrs_256_decapsulate", 2, pqclean_nif_hqc_rmrs_256_decapsulate_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"kyber512_info", 0, pqclean_nif_kyber512_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"kyber512_keypair", 0, pqclean_nif_kyber512_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"kyber512_encapsulate", 1, pqclean_nif_kyber512_encapsulate_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"kyber512_decapsulate", 2, pqclean_nif_kyber512_decapsulate_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"kyber512_90s_info", 0, pqclean_nif_kyber512_90s_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"kyber512_90s_keypair", 0, pqclean_nif_kyber512_90s_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"kyber512_90s_encapsulate", 1, pqclean_nif_kyber512_90s_encapsulate_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"kyber512_90s_decapsulate", 2, pqclean_nif_kyber512_90s_decapsulate_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"kyber768_info", 0, pqclean_nif_kyber768_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"kyber768_keypair", 0, pqclean_nif_kyber768_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"kyber768_encapsulate", 1, pqclean_nif_kyber768_encapsulate_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"kyber768_decapsulate", 2, pqclean_nif_kyber768_decapsulate_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"kyber768_90s_info", 0, pqclean_nif_kyber768_90s_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"kyber768_90s_keypair", 0, pqclean_nif_kyber768_90s_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"kyber768_90s_encapsulate", 1, pqclean_nif_kyber768_90s_encapsulate_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"kyber768_90s_decapsulate", 2, pqclean_nif_kyber768_90s_decapsulate_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"kyber1024_info", 0, pqclean_nif_kyber1024_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"kyber1024_keypair", 0, pqclean_nif_kyber1024_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"kyber1024_encapsulate", 1, pqclean_nif_kyber1024_encapsulate_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"kyber1024_decapsulate", 2, pqclean_nif_kyber1024_decapsulate_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"kyber1024_90s_info", 0, pqclean_nif_kyber1024_90s_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"kyber1024_90s_keypair", 0, pqclean_nif_kyber1024_90s_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"kyber1024_90s_encapsulate", 1, pqclean_nif_kyber1024_90s_encapsulate_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"kyber1024_90s_decapsulate", 2, pqclean_nif_kyber1024_90s_decapsulate_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece348864_info", 0, pqclean_nif_mceliece348864_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"mceliece348864_keypair", 0, pqclean_nif_mceliece348864_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece348864_encapsulate", 1, pqclean_nif_mceliece348864_encapsulate_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece348864_decapsulate", 2, pqclean_nif_mceliece348864_decapsulate_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece348864f_info", 0, pqclean_nif_mceliece348864f_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"mceliece348864f_keypair", 0, pqclean_nif_mceliece348864f_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece348864f_encapsulate", 1, pqclean_nif_mceliece348864f_encapsulate_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece348864f_decapsulate", 2, pqclean_nif_mceliece348864f_decapsulate_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece460896_info", 0, pqclean_nif_mceliece460896_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"mceliece460896_keypair", 0, pqclean_nif_mceliece460896_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece460896_encapsulate", 1, pqclean_nif_mceliece460896_encapsulate_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece460896_decapsulate", 2, pqclean_nif_mceliece460896_decapsulate_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece460896f_info", 0, pqclean_nif_mceliece460896f_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"mceliece460896f_keypair", 0, pqclean_nif_mceliece460896f_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece460896f_encapsulate", 1, pqclean_nif_mceliece460896f_encapsulate_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece460896f_decapsulate", 2, pqclean_nif_mceliece460896f_decapsulate_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece6688128_info", 0, pqclean_nif_mceliece6688128_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"mceliece6688128_keypair", 0, pqclean_nif_mceliece6688128_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece6688128_encapsulate", 1, pqclean_nif_mceliece6688128_encapsulate_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece6688128_decapsulate", 2, pqclean_nif_mceliece6688128_decapsulate_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece6688128f_info", 0, pqclean_nif_mceliece6688128f_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"mceliece6688128f_keypair", 0, pqclean_nif_mceliece6688128f_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece6688128f_encapsulate", 1, pqclean_nif_mceliece6688128f_encapsulate_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece6688128f_decapsulate", 2, pqclean_nif_mceliece6688128f_decapsulate_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece6960119_info", 0, pqclean_nif_mceliece6960119_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"mceliece6960119_keypair", 0, pqclean_nif_mceliece6960119_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece6960119_encapsulate", 1, pqclean_nif_mceliece6960119_encapsulate_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece6960119_decapsulate", 2, pqclean_nif_mceliece6960119_decapsulate_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece6960119f_info", 0, pqclean_nif_mceliece6960119f_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"mceliece6960119f_keypair", 0, pqclean_nif_mceliece6960119f_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece6960119f_encapsulate", 1, pqclean_nif_mceliece6960119f_encapsulate_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece6960119f_decapsulate", 2, pqclean_nif_mceliece6960119f_decapsulate_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece8192128_info", 0, pqclean_nif_mceliece8192128_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"mceliece8192128_keypair", 0, pqclean_nif_mceliece8192128_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece8192128_encapsulate", 1, pqclean_nif_mceliece8192128_encapsulate_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece8192128_decapsulate", 2, pqclean_nif_mceliece8192128_decapsulate_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece8192128f_info", 0, pqclean_nif_mceliece8192128f_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"mceliece8192128f_keypair", 0, pqclean_nif_mceliece8192128f_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece8192128f_encapsulate", 1, pqclean_nif_mceliece8192128f_encapsulate_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"mceliece8192128f_decapsulate", 2, pqclean_nif_mceliece8192128f_decapsulate_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},

    {"dilithium2_info", 0, pqclean_nif_dilithium2_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"dilithium2_keypair", 0, pqclean_nif_dilithium2_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"dilithium2_sign", 2, pqclean_nif_dilithium2_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"dilithium2_verify", 3, pqclean_nif_dilithium2_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"dilithium2aes_info", 0, pqclean_nif_dilithium2aes_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"dilithium2aes_keypair", 0, pqclean_nif_dilithium2aes_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"dilithium2aes_sign", 2, pqclean_nif_dilithium2aes_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"dilithium2aes_verify", 3, pqclean_nif_dilithium2aes_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"dilithium3_info", 0, pqclean_nif_dilithium3_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"dilithium3_keypair", 0, pqclean_nif_dilithium3_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"dilithium3_sign", 2, pqclean_nif_dilithium3_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"dilithium3_verify", 3, pqclean_nif_dilithium3_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"dilithium3aes_info", 0, pqclean_nif_dilithium3aes_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"dilithium3aes_keypair", 0, pqclean_nif_dilithium3aes_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"dilithium3aes_sign", 2, pqclean_nif_dilithium3aes_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"dilithium3aes_verify", 3, pqclean_nif_dilithium3aes_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"dilithium5_info", 0, pqclean_nif_dilithium5_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"dilithium5_keypair", 0, pqclean_nif_dilithium5_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"dilithium5_sign", 2, pqclean_nif_dilithium5_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"dilithium5_verify", 3, pqclean_nif_dilithium5_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"dilithium5aes_info", 0, pqclean_nif_dilithium5aes_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"dilithium5aes_keypair", 0, pqclean_nif_dilithium5aes_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"dilithium5aes_sign", 2, pqclean_nif_dilithium5aes_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"dilithium5aes_verify", 3, pqclean_nif_dilithium5aes_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"falcon512_info", 0, pqclean_nif_falcon512_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"falcon512_keypair", 0, pqclean_nif_falcon512_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"falcon512_sign", 2, pqclean_nif_falcon512_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"falcon512_verify", 3, pqclean_nif_falcon512_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"falcon1024_info", 0, pqclean_nif_falcon1024_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"falcon1024_keypair", 0, pqclean_nif_falcon1024_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"falcon1024_sign", 2, pqclean_nif_falcon1024_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"falcon1024_verify", 3, pqclean_nif_falcon1024_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_128f_robust_info", 0, pqclean_nif_sphincs_plus_haraka_128f_robust_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_haraka_128f_robust_keypair", 0, pqclean_nif_sphincs_plus_haraka_128f_robust_keypair_0,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_128f_robust_keypair", 1, pqclean_nif_sphincs_plus_haraka_128f_robust_keypair_1,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_128f_robust_sign", 2, pqclean_nif_sphincs_plus_haraka_128f_robust_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_128f_robust_verify", 3, pqclean_nif_sphincs_plus_haraka_128f_robust_verify_3,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_128f_simple_info", 0, pqclean_nif_sphincs_plus_haraka_128f_simple_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_haraka_128f_simple_keypair", 0, pqclean_nif_sphincs_plus_haraka_128f_simple_keypair_0,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_128f_simple_keypair", 1, pqclean_nif_sphincs_plus_haraka_128f_simple_keypair_1,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_128f_simple_sign", 2, pqclean_nif_sphincs_plus_haraka_128f_simple_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_128f_simple_verify", 3, pqclean_nif_sphincs_plus_haraka_128f_simple_verify_3,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_128s_robust_info", 0, pqclean_nif_sphincs_plus_haraka_128s_robust_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_haraka_128s_robust_keypair", 0, pqclean_nif_sphincs_plus_haraka_128s_robust_keypair_0,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_128s_robust_keypair", 1, pqclean_nif_sphincs_plus_haraka_128s_robust_keypair_1,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_128s_robust_sign", 2, pqclean_nif_sphincs_plus_haraka_128s_robust_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_128s_robust_verify", 3, pqclean_nif_sphincs_plus_haraka_128s_robust_verify_3,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_128s_simple_info", 0, pqclean_nif_sphincs_plus_haraka_128s_simple_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_haraka_128s_simple_keypair", 0, pqclean_nif_sphincs_plus_haraka_128s_simple_keypair_0,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_128s_simple_keypair", 1, pqclean_nif_sphincs_plus_haraka_128s_simple_keypair_1,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_128s_simple_sign", 2, pqclean_nif_sphincs_plus_haraka_128s_simple_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_128s_simple_verify", 3, pqclean_nif_sphincs_plus_haraka_128s_simple_verify_3,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_192f_robust_info", 0, pqclean_nif_sphincs_plus_haraka_192f_robust_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_haraka_192f_robust_keypair", 0, pqclean_nif_sphincs_plus_haraka_192f_robust_keypair_0,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_192f_robust_keypair", 1, pqclean_nif_sphincs_plus_haraka_192f_robust_keypair_1,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_192f_robust_sign", 2, pqclean_nif_sphincs_plus_haraka_192f_robust_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_192f_robust_verify", 3, pqclean_nif_sphincs_plus_haraka_192f_robust_verify_3,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_192f_simple_info", 0, pqclean_nif_sphincs_plus_haraka_192f_simple_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_haraka_192f_simple_keypair", 0, pqclean_nif_sphincs_plus_haraka_192f_simple_keypair_0,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_192f_simple_keypair", 1, pqclean_nif_sphincs_plus_haraka_192f_simple_keypair_1,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_192f_simple_sign", 2, pqclean_nif_sphincs_plus_haraka_192f_simple_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_192f_simple_verify", 3, pqclean_nif_sphincs_plus_haraka_192f_simple_verify_3,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_192s_robust_info", 0, pqclean_nif_sphincs_plus_haraka_192s_robust_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_haraka_192s_robust_keypair", 0, pqclean_nif_sphincs_plus_haraka_192s_robust_keypair_0,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_192s_robust_keypair", 1, pqclean_nif_sphincs_plus_haraka_192s_robust_keypair_1,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_192s_robust_sign", 2, pqclean_nif_sphincs_plus_haraka_192s_robust_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_192s_robust_verify", 3, pqclean_nif_sphincs_plus_haraka_192s_robust_verify_3,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_192s_simple_info", 0, pqclean_nif_sphincs_plus_haraka_192s_simple_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_haraka_192s_simple_keypair", 0, pqclean_nif_sphincs_plus_haraka_192s_simple_keypair_0,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_192s_simple_keypair", 1, pqclean_nif_sphincs_plus_haraka_192s_simple_keypair_1,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_192s_simple_sign", 2, pqclean_nif_sphincs_plus_haraka_192s_simple_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_192s_simple_verify", 3, pqclean_nif_sphincs_plus_haraka_192s_simple_verify_3,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_256f_robust_info", 0, pqclean_nif_sphincs_plus_haraka_256f_robust_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_haraka_256f_robust_keypair", 0, pqclean_nif_sphincs_plus_haraka_256f_robust_keypair_0,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_256f_robust_keypair", 1, pqclean_nif_sphincs_plus_haraka_256f_robust_keypair_1,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_256f_robust_sign", 2, pqclean_nif_sphincs_plus_haraka_256f_robust_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_256f_robust_verify", 3, pqclean_nif_sphincs_plus_haraka_256f_robust_verify_3,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_256f_simple_info", 0, pqclean_nif_sphincs_plus_haraka_256f_simple_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_haraka_256f_simple_keypair", 0, pqclean_nif_sphincs_plus_haraka_256f_simple_keypair_0,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_256f_simple_keypair", 1, pqclean_nif_sphincs_plus_haraka_256f_simple_keypair_1,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_256f_simple_sign", 2, pqclean_nif_sphincs_plus_haraka_256f_simple_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_256f_simple_verify", 3, pqclean_nif_sphincs_plus_haraka_256f_simple_verify_3,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_256s_robust_info", 0, pqclean_nif_sphincs_plus_haraka_256s_robust_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_haraka_256s_robust_keypair", 0, pqclean_nif_sphincs_plus_haraka_256s_robust_keypair_0,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_256s_robust_keypair", 1, pqclean_nif_sphincs_plus_haraka_256s_robust_keypair_1,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_256s_robust_sign", 2, pqclean_nif_sphincs_plus_haraka_256s_robust_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_256s_robust_verify", 3, pqclean_nif_sphincs_plus_haraka_256s_robust_verify_3,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_256s_simple_info", 0, pqclean_nif_sphincs_plus_haraka_256s_simple_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_haraka_256s_simple_keypair", 0, pqclean_nif_sphincs_plus_haraka_256s_simple_keypair_0,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_256s_simple_keypair", 1, pqclean_nif_sphincs_plus_haraka_256s_simple_keypair_1,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_256s_simple_sign", 2, pqclean_nif_sphincs_plus_haraka_256s_simple_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_haraka_256s_simple_verify", 3, pqclean_nif_sphincs_plus_haraka_256s_simple_verify_3,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_128f_robust_info", 0, pqclean_nif_sphincs_plus_sha2_128f_robust_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_sha2_128f_robust_keypair", 0, pqclean_nif_sphincs_plus_sha2_128f_robust_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_128f_robust_keypair", 1, pqclean_nif_sphincs_plus_sha2_128f_robust_keypair_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_128f_robust_sign", 2, pqclean_nif_sphincs_plus_sha2_128f_robust_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_128f_robust_verify", 3, pqclean_nif_sphincs_plus_sha2_128f_robust_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_128f_simple_info", 0, pqclean_nif_sphincs_plus_sha2_128f_simple_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_sha2_128f_simple_keypair", 0, pqclean_nif_sphincs_plus_sha2_128f_simple_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_128f_simple_keypair", 1, pqclean_nif_sphincs_plus_sha2_128f_simple_keypair_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_128f_simple_sign", 2, pqclean_nif_sphincs_plus_sha2_128f_simple_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_128f_simple_verify", 3, pqclean_nif_sphincs_plus_sha2_128f_simple_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_128s_robust_info", 0, pqclean_nif_sphincs_plus_sha2_128s_robust_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_sha2_128s_robust_keypair", 0, pqclean_nif_sphincs_plus_sha2_128s_robust_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_128s_robust_keypair", 1, pqclean_nif_sphincs_plus_sha2_128s_robust_keypair_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_128s_robust_sign", 2, pqclean_nif_sphincs_plus_sha2_128s_robust_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_128s_robust_verify", 3, pqclean_nif_sphincs_plus_sha2_128s_robust_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_128s_simple_info", 0, pqclean_nif_sphincs_plus_sha2_128s_simple_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_sha2_128s_simple_keypair", 0, pqclean_nif_sphincs_plus_sha2_128s_simple_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_128s_simple_keypair", 1, pqclean_nif_sphincs_plus_sha2_128s_simple_keypair_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_128s_simple_sign", 2, pqclean_nif_sphincs_plus_sha2_128s_simple_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_128s_simple_verify", 3, pqclean_nif_sphincs_plus_sha2_128s_simple_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_192f_robust_info", 0, pqclean_nif_sphincs_plus_sha2_192f_robust_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_sha2_192f_robust_keypair", 0, pqclean_nif_sphincs_plus_sha2_192f_robust_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_192f_robust_keypair", 1, pqclean_nif_sphincs_plus_sha2_192f_robust_keypair_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_192f_robust_sign", 2, pqclean_nif_sphincs_plus_sha2_192f_robust_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_192f_robust_verify", 3, pqclean_nif_sphincs_plus_sha2_192f_robust_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_192f_simple_info", 0, pqclean_nif_sphincs_plus_sha2_192f_simple_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_sha2_192f_simple_keypair", 0, pqclean_nif_sphincs_plus_sha2_192f_simple_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_192f_simple_keypair", 1, pqclean_nif_sphincs_plus_sha2_192f_simple_keypair_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_192f_simple_sign", 2, pqclean_nif_sphincs_plus_sha2_192f_simple_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_192f_simple_verify", 3, pqclean_nif_sphincs_plus_sha2_192f_simple_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_192s_robust_info", 0, pqclean_nif_sphincs_plus_sha2_192s_robust_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_sha2_192s_robust_keypair", 0, pqclean_nif_sphincs_plus_sha2_192s_robust_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_192s_robust_keypair", 1, pqclean_nif_sphincs_plus_sha2_192s_robust_keypair_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_192s_robust_sign", 2, pqclean_nif_sphincs_plus_sha2_192s_robust_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_192s_robust_verify", 3, pqclean_nif_sphincs_plus_sha2_192s_robust_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_192s_simple_info", 0, pqclean_nif_sphincs_plus_sha2_192s_simple_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_sha2_192s_simple_keypair", 0, pqclean_nif_sphincs_plus_sha2_192s_simple_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_192s_simple_keypair", 1, pqclean_nif_sphincs_plus_sha2_192s_simple_keypair_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_192s_simple_sign", 2, pqclean_nif_sphincs_plus_sha2_192s_simple_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_192s_simple_verify", 3, pqclean_nif_sphincs_plus_sha2_192s_simple_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_256f_robust_info", 0, pqclean_nif_sphincs_plus_sha2_256f_robust_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_sha2_256f_robust_keypair", 0, pqclean_nif_sphincs_plus_sha2_256f_robust_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_256f_robust_keypair", 1, pqclean_nif_sphincs_plus_sha2_256f_robust_keypair_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_256f_robust_sign", 2, pqclean_nif_sphincs_plus_sha2_256f_robust_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_256f_robust_verify", 3, pqclean_nif_sphincs_plus_sha2_256f_robust_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_256f_simple_info", 0, pqclean_nif_sphincs_plus_sha2_256f_simple_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_sha2_256f_simple_keypair", 0, pqclean_nif_sphincs_plus_sha2_256f_simple_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_256f_simple_keypair", 1, pqclean_nif_sphincs_plus_sha2_256f_simple_keypair_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_256f_simple_sign", 2, pqclean_nif_sphincs_plus_sha2_256f_simple_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_256f_simple_verify", 3, pqclean_nif_sphincs_plus_sha2_256f_simple_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_256s_robust_info", 0, pqclean_nif_sphincs_plus_sha2_256s_robust_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_sha2_256s_robust_keypair", 0, pqclean_nif_sphincs_plus_sha2_256s_robust_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_256s_robust_keypair", 1, pqclean_nif_sphincs_plus_sha2_256s_robust_keypair_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_256s_robust_sign", 2, pqclean_nif_sphincs_plus_sha2_256s_robust_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_256s_robust_verify", 3, pqclean_nif_sphincs_plus_sha2_256s_robust_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_256s_simple_info", 0, pqclean_nif_sphincs_plus_sha2_256s_simple_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_sha2_256s_simple_keypair", 0, pqclean_nif_sphincs_plus_sha2_256s_simple_keypair_0, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_256s_simple_keypair", 1, pqclean_nif_sphincs_plus_sha2_256s_simple_keypair_1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_256s_simple_sign", 2, pqclean_nif_sphincs_plus_sha2_256s_simple_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_sha2_256s_simple_verify", 3, pqclean_nif_sphincs_plus_sha2_256s_simple_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_128f_robust_info", 0, pqclean_nif_sphincs_plus_shake_128f_robust_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_shake_128f_robust_keypair", 0, pqclean_nif_sphincs_plus_shake_128f_robust_keypair_0,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_128f_robust_keypair", 1, pqclean_nif_sphincs_plus_shake_128f_robust_keypair_1,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_128f_robust_sign", 2, pqclean_nif_sphincs_plus_shake_128f_robust_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_128f_robust_verify", 3, pqclean_nif_sphincs_plus_shake_128f_robust_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_128f_simple_info", 0, pqclean_nif_sphincs_plus_shake_128f_simple_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_shake_128f_simple_keypair", 0, pqclean_nif_sphincs_plus_shake_128f_simple_keypair_0,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_128f_simple_keypair", 1, pqclean_nif_sphincs_plus_shake_128f_simple_keypair_1,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_128f_simple_sign", 2, pqclean_nif_sphincs_plus_shake_128f_simple_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_128f_simple_verify", 3, pqclean_nif_sphincs_plus_shake_128f_simple_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_128s_robust_info", 0, pqclean_nif_sphincs_plus_shake_128s_robust_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_shake_128s_robust_keypair", 0, pqclean_nif_sphincs_plus_shake_128s_robust_keypair_0,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_128s_robust_keypair", 1, pqclean_nif_sphincs_plus_shake_128s_robust_keypair_1,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_128s_robust_sign", 2, pqclean_nif_sphincs_plus_shake_128s_robust_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_128s_robust_verify", 3, pqclean_nif_sphincs_plus_shake_128s_robust_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_128s_simple_info", 0, pqclean_nif_sphincs_plus_shake_128s_simple_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_shake_128s_simple_keypair", 0, pqclean_nif_sphincs_plus_shake_128s_simple_keypair_0,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_128s_simple_keypair", 1, pqclean_nif_sphincs_plus_shake_128s_simple_keypair_1,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_128s_simple_sign", 2, pqclean_nif_sphincs_plus_shake_128s_simple_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_128s_simple_verify", 3, pqclean_nif_sphincs_plus_shake_128s_simple_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_192f_robust_info", 0, pqclean_nif_sphincs_plus_shake_192f_robust_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_shake_192f_robust_keypair", 0, pqclean_nif_sphincs_plus_shake_192f_robust_keypair_0,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_192f_robust_keypair", 1, pqclean_nif_sphincs_plus_shake_192f_robust_keypair_1,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_192f_robust_sign", 2, pqclean_nif_sphincs_plus_shake_192f_robust_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_192f_robust_verify", 3, pqclean_nif_sphincs_plus_shake_192f_robust_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_192f_simple_info", 0, pqclean_nif_sphincs_plus_shake_192f_simple_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_shake_192f_simple_keypair", 0, pqclean_nif_sphincs_plus_shake_192f_simple_keypair_0,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_192f_simple_keypair", 1, pqclean_nif_sphincs_plus_shake_192f_simple_keypair_1,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_192f_simple_sign", 2, pqclean_nif_sphincs_plus_shake_192f_simple_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_192f_simple_verify", 3, pqclean_nif_sphincs_plus_shake_192f_simple_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_192s_robust_info", 0, pqclean_nif_sphincs_plus_shake_192s_robust_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_shake_192s_robust_keypair", 0, pqclean_nif_sphincs_plus_shake_192s_robust_keypair_0,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_192s_robust_keypair", 1, pqclean_nif_sphincs_plus_shake_192s_robust_keypair_1,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_192s_robust_sign", 2, pqclean_nif_sphincs_plus_shake_192s_robust_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_192s_robust_verify", 3, pqclean_nif_sphincs_plus_shake_192s_robust_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_192s_simple_info", 0, pqclean_nif_sphincs_plus_shake_192s_simple_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_shake_192s_simple_keypair", 0, pqclean_nif_sphincs_plus_shake_192s_simple_keypair_0,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_192s_simple_keypair", 1, pqclean_nif_sphincs_plus_shake_192s_simple_keypair_1,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_192s_simple_sign", 2, pqclean_nif_sphincs_plus_shake_192s_simple_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_192s_simple_verify", 3, pqclean_nif_sphincs_plus_shake_192s_simple_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_256f_robust_info", 0, pqclean_nif_sphincs_plus_shake_256f_robust_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_shake_256f_robust_keypair", 0, pqclean_nif_sphincs_plus_shake_256f_robust_keypair_0,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_256f_robust_keypair", 1, pqclean_nif_sphincs_plus_shake_256f_robust_keypair_1,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_256f_robust_sign", 2, pqclean_nif_sphincs_plus_shake_256f_robust_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_256f_robust_verify", 3, pqclean_nif_sphincs_plus_shake_256f_robust_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_256f_simple_info", 0, pqclean_nif_sphincs_plus_shake_256f_simple_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_shake_256f_simple_keypair", 0, pqclean_nif_sphincs_plus_shake_256f_simple_keypair_0,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_256f_simple_keypair", 1, pqclean_nif_sphincs_plus_shake_256f_simple_keypair_1,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_256f_simple_sign", 2, pqclean_nif_sphincs_plus_shake_256f_simple_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_256f_simple_verify", 3, pqclean_nif_sphincs_plus_shake_256f_simple_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_256s_robust_info", 0, pqclean_nif_sphincs_plus_shake_256s_robust_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_shake_256s_robust_keypair", 0, pqclean_nif_sphincs_plus_shake_256s_robust_keypair_0,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_256s_robust_keypair", 1, pqclean_nif_sphincs_plus_shake_256s_robust_keypair_1,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_256s_robust_sign", 2, pqclean_nif_sphincs_plus_shake_256s_robust_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_256s_robust_verify", 3, pqclean_nif_sphincs_plus_shake_256s_robust_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_256s_simple_info", 0, pqclean_nif_sphincs_plus_shake_256s_simple_info_0, ERL_NIF_NORMAL_JOB_BOUND},
    {"sphincs_plus_shake_256s_simple_keypair", 0, pqclean_nif_sphincs_plus_shake_256s_simple_keypair_0,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_256s_simple_keypair", 1, pqclean_nif_sphincs_plus_shake_256s_simple_keypair_1,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_256s_simple_sign", 2, pqclean_nif_sphincs_plus_shake_256s_simple_sign_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sphincs_plus_shake_256s_simple_verify", 3, pqclean_nif_sphincs_plus_shake_256s_simple_verify_3, ERL_NIF_DIRTY_JOB_CPU_BOUND},
};

static int pqclean_nif_instances = 0;

static void pqclean_nif_make_atoms(ErlNifEnv *env);
static int pqclean_nif_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info);
static int pqclean_nif_upgrade(ErlNifEnv *env, void **new_priv_data, void **old_priv_data, ERL_NIF_TERM load_info);
static void pqclean_nif_unload(ErlNifEnv *env, void *priv_data);

static void
pqclean_nif_make_atoms(ErlNifEnv *env)
{
#define MAKE_ATOM(Id, Value)                                                                                                       \
    {                                                                                                                              \
        pqclean_nif_atom_table->ATOM_##Id = enif_make_atom(env, Value);                                                            \
    }
    MAKE_ATOM(badarg, "badarg");
    MAKE_ATOM(closed, "closed");
    MAKE_ATOM(error, "error");
    MAKE_ATOM(false, "false");
    MAKE_ATOM(latin1, "latin1");
    MAKE_ATOM(nil, "nil");
    MAKE_ATOM(no_context, "no_context");
    MAKE_ATOM(not_owner, "not_owner");
    MAKE_ATOM(notsup, "notsup");
    MAKE_ATOM(ok, "ok");
    MAKE_ATOM(true, "true");
    MAKE_ATOM(undefined, "undefined");
    MAKE_ATOM(utf8, "utf8");
#undef MAKE_ATOM
}

static int
pqclean_nif_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    int retval = 0;

    /* Initialize resource types. */

    /* Initialize private data. */
    (void)priv_data;
    (void)load_info;

    /* Initialize common atoms. */
    (void)pqclean_nif_make_atoms(env);

    pqclean_nif_instances++;

    return retval;
}

static int
pqclean_nif_upgrade(ErlNifEnv *env, void **new_priv_data, void **old_priv_data, ERL_NIF_TERM load_info)
{
    int retval = 0;

    /* Upgrade resource types. */

    /* Upgrade private data. */
    (void)env;
    (void)new_priv_data;
    (void)old_priv_data;
    (void)load_info;

    /* Initialize common atoms */
    (void)pqclean_nif_make_atoms(env);

    pqclean_nif_instances++;

    return retval;
}

static void
pqclean_nif_unload(ErlNifEnv *env, void *priv_data)
{
    (void)env;

    if (pqclean_nif_instances == 1) {
        /* Destroy private data. */
        (void)priv_data;
    }

    pqclean_nif_instances--;

    return;
}

ERL_NIF_INIT(pqclean_nif, pqclean_nif_funcs, pqclean_nif_load, NULL, pqclean_nif_upgrade, pqclean_nif_unload);