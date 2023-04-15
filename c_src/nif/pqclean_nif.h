#ifndef PQCLEAN_NIF_H
#define PQCLEAN_NIF_H

#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <erl_nif.h>

#include "xnif_trace.h"

/* Atom Table */

typedef struct pqclean_nif_atom_table_s pqclean_nif_atom_table_t;

struct pqclean_nif_atom_table_s {
    ERL_NIF_TERM ATOM_badarg;
    ERL_NIF_TERM ATOM_closed;
    ERL_NIF_TERM ATOM_error;
    ERL_NIF_TERM ATOM_false;
    ERL_NIF_TERM ATOM_latin1;
    ERL_NIF_TERM ATOM_nil;
    ERL_NIF_TERM ATOM_no_context;
    ERL_NIF_TERM ATOM_not_owner;
    ERL_NIF_TERM ATOM_notsup;
    ERL_NIF_TERM ATOM_ok;
    ERL_NIF_TERM ATOM_true;
    ERL_NIF_TERM ATOM_undefined;
    ERL_NIF_TERM ATOM_utf8;
};

extern pqclean_nif_atom_table_t *pqclean_nif_atom_table;

#define ATOM(Id) pqclean_nif_atom_table->ATOM_##Id

/* NIF Utility Macros */

#ifndef THE_NON_VALUE
#define THE_NON_VALUE ((ERL_NIF_TERM)0)
#endif

#ifndef ERL_NIF_NORMAL_JOB_BOUND
#define ERL_NIF_NORMAL_JOB_BOUND (0)
#endif

#define REDUCTIONS_UNTIL_YCF_YIELD() (20000)
#define BUMP_ALL_REDS(env)                                                                                                         \
    do {                                                                                                                           \
        (void)enif_consume_timeslice((env), 100);                                                                                  \
    } while (0)
#define BUMP_REMAINING_REDS(env, nr_of_reductions)                                                                                 \
    do {                                                                                                                           \
        (void)enif_consume_timeslice((env),                                                                                        \
                                     (int)((REDUCTIONS_UNTIL_YCF_YIELD() - (nr_of_reductions)) / REDUCTIONS_UNTIL_YCF_YIELD()));   \
    } while (0)

/* All nif functions return a valid value or throws an exception */
#define EXCP(Env, ClassTerm, ReasonString) xnif_raise_exception((Env), __FILE__, __LINE__, (ClassTerm), (ReasonString))

#define EXCP_F(Env, ClassTerm, ReasonFormat, ...)                                                                                  \
    xnif_raise_exception_format((Env), __FILE__, __LINE__, (ClassTerm), (ReasonFormat), __VA_ARGS__)

#define EXCP_NOTSUP(Env, Str) EXCP((Env), ATOM(notsup), (Str))
#define EXCP_BADARG(Env, Str) EXCP((Env), ATOM(badarg), (Str))
#define EXCP_BADARG_F(Env, Fmt, ...) EXCP_F((Env), ATOM(badarg), Fmt, __VA_ARGS__)
#define EXCP_ERROR(Env, Str) EXCP((Env), ATOM(error), (Str))
#define EXCP_ERROR_F(Env, Fmt, ...) EXCP_F((Env), ATOM(error), Fmt, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif
