#ifndef XNIF_TRACE_H
#define XNIF_TRACE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <erl_nif.h>

// #define XNIF_TRACE 1
#ifdef XNIF_TRACE
#define XNIF_TRACE_C(c)                                                                                                            \
    do {                                                                                                                           \
        putchar(c);                                                                                                                \
        fflush(stdout);                                                                                                            \
    } while (0)
#define XNIF_TRACE_S(s)                                                                                                            \
    do {                                                                                                                           \
        fputs((s), stdout);                                                                                                        \
        fflush(stdout);                                                                                                            \
    } while (0)
#define XNIF_TRACE_F(...)                                                                                                          \
    do {                                                                                                                           \
        enif_fprintf(stderr, "[%u.%p] ", getpid(), (void *)enif_thread_self());                                                    \
        enif_fprintf(stderr, __VA_ARGS__);                                                                                         \
        fflush(stderr);                                                                                                            \
    } while (0)
#else
#define XNIF_TRACE_C(c) ((void)(0))
#define XNIF_TRACE_S(s) ((void)(0))
#define XNIF_TRACE_F(...) ((void)(0))
#endif

static ERL_NIF_TERM xnif_make_string_printf(ErlNifEnv *env, const char *format, ...);
static ERL_NIF_TERM xnif_make_string_vprintf(ErlNifEnv *env, const char *format, va_list ap);
static ERL_NIF_TERM xnif_raise_exception(ErlNifEnv *env, const char *file, int line, ERL_NIF_TERM class_term,
                                         const char *reason_string);
static ERL_NIF_TERM xnif_raise_exception_format(ErlNifEnv *env, const char *file, int line, ERL_NIF_TERM class_term,
                                                const char *reason_format, ...);
static ERL_NIF_TERM xnif_raise_exception_vformat(ErlNifEnv *env, const char *file, int line, ERL_NIF_TERM class_term,
                                                 const char *reason_format, va_list ap);

inline ERL_NIF_TERM
xnif_make_string_printf(ErlNifEnv *env, const char *format, ...)
{
    int ret;
    va_list arglist;
    va_start(arglist, format);
    ret = xnif_make_string_vprintf(env, format, arglist);
    va_end(arglist);
    return ret;
}

inline ERL_NIF_TERM
xnif_make_string_vprintf(ErlNifEnv *env, const char *format, va_list ap)
{
#define BUF_SZ 4096
    char buf[BUF_SZ];
    int res;
    size_t buf_len = 0;
    ERL_NIF_TERM buf_term;

    buf[0] = '\0';
    res = enif_vsnprintf(buf, BUF_SZ - 1, format, ap);
    if (res < 0) {
        return enif_raise_exception(env, enif_make_string(env, "Call to xnif_make_string_vprintf() failed", ERL_NIF_LATIN1));
    }
    if (res < BUF_SZ) {
        buf_len = (size_t)res;
    } else {
        buf_len = BUF_SZ;
    }
    buf_term = enif_make_string_len(env, buf, buf_len, ERL_NIF_LATIN1);
    return buf_term;
#undef BUF_SZ
}

inline ERL_NIF_TERM
xnif_raise_exception(ErlNifEnv *env, const char *file, int line, ERL_NIF_TERM class_term, const char *reason_string)
{
    ERL_NIF_TERM stacktrace_term;
    ERL_NIF_TERM reason_term;
    ERL_NIF_TERM error_term;
    stacktrace_term = enif_make_tuple2(env, enif_make_string(env, file, ERL_NIF_LATIN1), enif_make_int(env, line));
    reason_term = enif_make_string(env, reason_string, ERL_NIF_LATIN1);
    error_term = enif_make_tuple3(env, class_term, stacktrace_term, reason_term);
    return enif_raise_exception(env, error_term);
}

inline ERL_NIF_TERM
xnif_raise_exception_format(ErlNifEnv *env, const char *file, int line, ERL_NIF_TERM class_term, const char *reason_format, ...)
{
    ERL_NIF_TERM exception_term;
    va_list arglist;
    va_start(arglist, reason_format);
    exception_term = xnif_raise_exception_vformat(env, file, line, class_term, reason_format, arglist);
    va_end(arglist);
    return exception_term;
}

inline ERL_NIF_TERM
xnif_raise_exception_vformat(ErlNifEnv *env, const char *file, int line, ERL_NIF_TERM class_term, const char *reason_format,
                             va_list ap)
{
    ERL_NIF_TERM stacktrace_term;
    ERL_NIF_TERM reason_term;
    ERL_NIF_TERM error_term;
    stacktrace_term = enif_make_tuple2(env, enif_make_string(env, file, ERL_NIF_LATIN1), enif_make_int(env, line));
    reason_term = xnif_make_string_vprintf(env, reason_format, ap);
    error_term = enif_make_tuple3(env, class_term, stacktrace_term, reason_term);
    return enif_raise_exception(env, error_term);
}

#ifdef __cplusplus
}
#endif

#endif
