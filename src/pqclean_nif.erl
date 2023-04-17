%%% % @format
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2023, Andrew Bennett
%%% @doc <a href="https://en.wikipedia.org/wiki/Post-quantum_cryptography">Post-Quantum Cryptography</a>
%%% NIF based on <a href="https://github.com/PQClean/PQClean">PQClean</a> for Erlang and Elixir.
%%%
%%% See <a href="readme.html">README</a> for more examples and a full list of supported algorithms.
%%%
%%% <h3><a href="https://en.wikipedia.org/wiki/Key_encapsulation_mechanism">Key Encapsulation Mechanism (KEM)</a> Algorithm Example:</h3>
%%% ```
%%% {PK, SK} = pqclean_nif:kyber768_keypair(),
%%% {CT, SS} = pqclean_nif:kyber768_encapsulate(PK),
%%%      SS  = pqclean_nif:kyber768_decapsulate(CT, SK).
%%% '''
%%%
%%% <h3><a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm Example:</h3>
%%% ```
%%% {PK, SK} = pqclean_nif:falcon512_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:falcon512_sign(Msg, SK),
%%% true = pqclean_nif:falcon512_verify(Sig, Msg, PK).
%%% '''
%%%
%%% @end
%%% Created :  15 April 2023 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(pqclean_nif).
-compile(warn_missing_spec).
-author("potatosaladx@gmail.com").

-on_load(init/0).

%% NIF API
-export([
    dirty_job_cpu_stack_size/0,
    hqc_rmrs_128_info/0,
    hqc_rmrs_128_keypair/0,
    hqc_rmrs_128_encapsulate/1,
    hqc_rmrs_128_decapsulate/2,
    hqc_rmrs_192_info/0,
    hqc_rmrs_192_keypair/0,
    hqc_rmrs_192_encapsulate/1,
    hqc_rmrs_192_decapsulate/2,
    hqc_rmrs_256_info/0,
    hqc_rmrs_256_keypair/0,
    hqc_rmrs_256_encapsulate/1,
    hqc_rmrs_256_decapsulate/2,
    kyber512_info/0,
    kyber512_keypair/0,
    kyber512_encapsulate/1,
    kyber512_decapsulate/2,
    kyber512_90s_info/0,
    kyber512_90s_keypair/0,
    kyber512_90s_encapsulate/1,
    kyber512_90s_decapsulate/2,
    kyber768_info/0,
    kyber768_keypair/0,
    kyber768_encapsulate/1,
    kyber768_decapsulate/2,
    kyber768_90s_info/0,
    kyber768_90s_keypair/0,
    kyber768_90s_encapsulate/1,
    kyber768_90s_decapsulate/2,
    kyber1024_info/0,
    kyber1024_keypair/0,
    kyber1024_encapsulate/1,
    kyber1024_decapsulate/2,
    kyber1024_90s_info/0,
    kyber1024_90s_keypair/0,
    kyber1024_90s_encapsulate/1,
    kyber1024_90s_decapsulate/2,
    mceliece348864_info/0,
    mceliece348864_keypair/0,
    mceliece348864_encapsulate/1,
    mceliece348864_decapsulate/2,
    mceliece348864f_info/0,
    mceliece348864f_keypair/0,
    mceliece348864f_encapsulate/1,
    mceliece348864f_decapsulate/2,
    mceliece460896_info/0,
    mceliece460896_keypair/0,
    mceliece460896_encapsulate/1,
    mceliece460896_decapsulate/2,
    mceliece460896f_info/0,
    mceliece460896f_keypair/0,
    mceliece460896f_encapsulate/1,
    mceliece460896f_decapsulate/2,
    mceliece6688128_info/0,
    mceliece6688128_keypair/0,
    mceliece6688128_encapsulate/1,
    mceliece6688128_decapsulate/2,
    mceliece6688128f_info/0,
    mceliece6688128f_keypair/0,
    mceliece6688128f_encapsulate/1,
    mceliece6688128f_decapsulate/2,
    mceliece6960119_info/0,
    mceliece6960119_keypair/0,
    mceliece6960119_encapsulate/1,
    mceliece6960119_decapsulate/2,
    mceliece6960119f_info/0,
    mceliece6960119f_keypair/0,
    mceliece6960119f_encapsulate/1,
    mceliece6960119f_decapsulate/2,
    mceliece8192128_info/0,
    mceliece8192128_keypair/0,
    mceliece8192128_encapsulate/1,
    mceliece8192128_decapsulate/2,
    mceliece8192128f_info/0,
    mceliece8192128f_keypair/0,
    mceliece8192128f_encapsulate/1,
    mceliece8192128f_decapsulate/2,
    dilithium2_info/0,
    dilithium2_keypair/0,
    dilithium2_sign/2,
    dilithium2_verify/3,
    dilithium2aes_info/0,
    dilithium2aes_keypair/0,
    dilithium2aes_sign/2,
    dilithium2aes_verify/3,
    dilithium3_info/0,
    dilithium3_keypair/0,
    dilithium3_sign/2,
    dilithium3_verify/3,
    dilithium3aes_info/0,
    dilithium3aes_keypair/0,
    dilithium3aes_sign/2,
    dilithium3aes_verify/3,
    dilithium5_info/0,
    dilithium5_keypair/0,
    dilithium5_sign/2,
    dilithium5_verify/3,
    dilithium5aes_info/0,
    dilithium5aes_keypair/0,
    dilithium5aes_sign/2,
    dilithium5aes_verify/3,
    falcon512_info/0,
    falcon512_keypair/0,
    falcon512_sign/2,
    falcon512_verify/3,
    falcon1024_info/0,
    falcon1024_keypair/0,
    falcon1024_sign/2,
    falcon1024_verify/3,
    sphincs_plus_haraka_128f_robust_info/0,
    sphincs_plus_haraka_128f_robust_keypair/0,
    sphincs_plus_haraka_128f_robust_keypair/1,
    sphincs_plus_haraka_128f_robust_sign/2,
    sphincs_plus_haraka_128f_robust_verify/3,
    sphincs_plus_haraka_128f_simple_info/0,
    sphincs_plus_haraka_128f_simple_keypair/0,
    sphincs_plus_haraka_128f_simple_keypair/1,
    sphincs_plus_haraka_128f_simple_sign/2,
    sphincs_plus_haraka_128f_simple_verify/3,
    sphincs_plus_haraka_128s_robust_info/0,
    sphincs_plus_haraka_128s_robust_keypair/0,
    sphincs_plus_haraka_128s_robust_keypair/1,
    sphincs_plus_haraka_128s_robust_sign/2,
    sphincs_plus_haraka_128s_robust_verify/3,
    sphincs_plus_haraka_128s_simple_info/0,
    sphincs_plus_haraka_128s_simple_keypair/0,
    sphincs_plus_haraka_128s_simple_keypair/1,
    sphincs_plus_haraka_128s_simple_sign/2,
    sphincs_plus_haraka_128s_simple_verify/3,
    sphincs_plus_haraka_192f_robust_info/0,
    sphincs_plus_haraka_192f_robust_keypair/0,
    sphincs_plus_haraka_192f_robust_keypair/1,
    sphincs_plus_haraka_192f_robust_sign/2,
    sphincs_plus_haraka_192f_robust_verify/3,
    sphincs_plus_haraka_192f_simple_info/0,
    sphincs_plus_haraka_192f_simple_keypair/0,
    sphincs_plus_haraka_192f_simple_keypair/1,
    sphincs_plus_haraka_192f_simple_sign/2,
    sphincs_plus_haraka_192f_simple_verify/3,
    sphincs_plus_haraka_192s_robust_info/0,
    sphincs_plus_haraka_192s_robust_keypair/0,
    sphincs_plus_haraka_192s_robust_keypair/1,
    sphincs_plus_haraka_192s_robust_sign/2,
    sphincs_plus_haraka_192s_robust_verify/3,
    sphincs_plus_haraka_192s_simple_info/0,
    sphincs_plus_haraka_192s_simple_keypair/0,
    sphincs_plus_haraka_192s_simple_keypair/1,
    sphincs_plus_haraka_192s_simple_sign/2,
    sphincs_plus_haraka_192s_simple_verify/3,
    sphincs_plus_haraka_256f_robust_info/0,
    sphincs_plus_haraka_256f_robust_keypair/0,
    sphincs_plus_haraka_256f_robust_keypair/1,
    sphincs_plus_haraka_256f_robust_sign/2,
    sphincs_plus_haraka_256f_robust_verify/3,
    sphincs_plus_haraka_256f_simple_info/0,
    sphincs_plus_haraka_256f_simple_keypair/0,
    sphincs_plus_haraka_256f_simple_keypair/1,
    sphincs_plus_haraka_256f_simple_sign/2,
    sphincs_plus_haraka_256f_simple_verify/3,
    sphincs_plus_haraka_256s_robust_info/0,
    sphincs_plus_haraka_256s_robust_keypair/0,
    sphincs_plus_haraka_256s_robust_keypair/1,
    sphincs_plus_haraka_256s_robust_sign/2,
    sphincs_plus_haraka_256s_robust_verify/3,
    sphincs_plus_haraka_256s_simple_info/0,
    sphincs_plus_haraka_256s_simple_keypair/0,
    sphincs_plus_haraka_256s_simple_keypair/1,
    sphincs_plus_haraka_256s_simple_sign/2,
    sphincs_plus_haraka_256s_simple_verify/3,
    sphincs_plus_sha2_128f_robust_info/0,
    sphincs_plus_sha2_128f_robust_keypair/0,
    sphincs_plus_sha2_128f_robust_keypair/1,
    sphincs_plus_sha2_128f_robust_sign/2,
    sphincs_plus_sha2_128f_robust_verify/3,
    sphincs_plus_sha2_128f_simple_info/0,
    sphincs_plus_sha2_128f_simple_keypair/0,
    sphincs_plus_sha2_128f_simple_keypair/1,
    sphincs_plus_sha2_128f_simple_sign/2,
    sphincs_plus_sha2_128f_simple_verify/3,
    sphincs_plus_sha2_128s_robust_info/0,
    sphincs_plus_sha2_128s_robust_keypair/0,
    sphincs_plus_sha2_128s_robust_keypair/1,
    sphincs_plus_sha2_128s_robust_sign/2,
    sphincs_plus_sha2_128s_robust_verify/3,
    sphincs_plus_sha2_128s_simple_info/0,
    sphincs_plus_sha2_128s_simple_keypair/0,
    sphincs_plus_sha2_128s_simple_keypair/1,
    sphincs_plus_sha2_128s_simple_sign/2,
    sphincs_plus_sha2_128s_simple_verify/3,
    sphincs_plus_sha2_192f_robust_info/0,
    sphincs_plus_sha2_192f_robust_keypair/0,
    sphincs_plus_sha2_192f_robust_keypair/1,
    sphincs_plus_sha2_192f_robust_sign/2,
    sphincs_plus_sha2_192f_robust_verify/3,
    sphincs_plus_sha2_192f_simple_info/0,
    sphincs_plus_sha2_192f_simple_keypair/0,
    sphincs_plus_sha2_192f_simple_keypair/1,
    sphincs_plus_sha2_192f_simple_sign/2,
    sphincs_plus_sha2_192f_simple_verify/3,
    sphincs_plus_sha2_192s_robust_info/0,
    sphincs_plus_sha2_192s_robust_keypair/0,
    sphincs_plus_sha2_192s_robust_keypair/1,
    sphincs_plus_sha2_192s_robust_sign/2,
    sphincs_plus_sha2_192s_robust_verify/3,
    sphincs_plus_sha2_192s_simple_info/0,
    sphincs_plus_sha2_192s_simple_keypair/0,
    sphincs_plus_sha2_192s_simple_keypair/1,
    sphincs_plus_sha2_192s_simple_sign/2,
    sphincs_plus_sha2_192s_simple_verify/3,
    sphincs_plus_sha2_256f_robust_info/0,
    sphincs_plus_sha2_256f_robust_keypair/0,
    sphincs_plus_sha2_256f_robust_keypair/1,
    sphincs_plus_sha2_256f_robust_sign/2,
    sphincs_plus_sha2_256f_robust_verify/3,
    sphincs_plus_sha2_256f_simple_info/0,
    sphincs_plus_sha2_256f_simple_keypair/0,
    sphincs_plus_sha2_256f_simple_keypair/1,
    sphincs_plus_sha2_256f_simple_sign/2,
    sphincs_plus_sha2_256f_simple_verify/3,
    sphincs_plus_sha2_256s_robust_info/0,
    sphincs_plus_sha2_256s_robust_keypair/0,
    sphincs_plus_sha2_256s_robust_keypair/1,
    sphincs_plus_sha2_256s_robust_sign/2,
    sphincs_plus_sha2_256s_robust_verify/3,
    sphincs_plus_sha2_256s_simple_info/0,
    sphincs_plus_sha2_256s_simple_keypair/0,
    sphincs_plus_sha2_256s_simple_keypair/1,
    sphincs_plus_sha2_256s_simple_sign/2,
    sphincs_plus_sha2_256s_simple_verify/3,
    sphincs_plus_shake_128f_robust_info/0,
    sphincs_plus_shake_128f_robust_keypair/0,
    sphincs_plus_shake_128f_robust_keypair/1,
    sphincs_plus_shake_128f_robust_sign/2,
    sphincs_plus_shake_128f_robust_verify/3,
    sphincs_plus_shake_128f_simple_info/0,
    sphincs_plus_shake_128f_simple_keypair/0,
    sphincs_plus_shake_128f_simple_keypair/1,
    sphincs_plus_shake_128f_simple_sign/2,
    sphincs_plus_shake_128f_simple_verify/3,
    sphincs_plus_shake_128s_robust_info/0,
    sphincs_plus_shake_128s_robust_keypair/0,
    sphincs_plus_shake_128s_robust_keypair/1,
    sphincs_plus_shake_128s_robust_sign/2,
    sphincs_plus_shake_128s_robust_verify/3,
    sphincs_plus_shake_128s_simple_info/0,
    sphincs_plus_shake_128s_simple_keypair/0,
    sphincs_plus_shake_128s_simple_keypair/1,
    sphincs_plus_shake_128s_simple_sign/2,
    sphincs_plus_shake_128s_simple_verify/3,
    sphincs_plus_shake_192f_robust_info/0,
    sphincs_plus_shake_192f_robust_keypair/0,
    sphincs_plus_shake_192f_robust_keypair/1,
    sphincs_plus_shake_192f_robust_sign/2,
    sphincs_plus_shake_192f_robust_verify/3,
    sphincs_plus_shake_192f_simple_info/0,
    sphincs_plus_shake_192f_simple_keypair/0,
    sphincs_plus_shake_192f_simple_keypair/1,
    sphincs_plus_shake_192f_simple_sign/2,
    sphincs_plus_shake_192f_simple_verify/3,
    sphincs_plus_shake_192s_robust_info/0,
    sphincs_plus_shake_192s_robust_keypair/0,
    sphincs_plus_shake_192s_robust_keypair/1,
    sphincs_plus_shake_192s_robust_sign/2,
    sphincs_plus_shake_192s_robust_verify/3,
    sphincs_plus_shake_192s_simple_info/0,
    sphincs_plus_shake_192s_simple_keypair/0,
    sphincs_plus_shake_192s_simple_keypair/1,
    sphincs_plus_shake_192s_simple_sign/2,
    sphincs_plus_shake_192s_simple_verify/3,
    sphincs_plus_shake_256f_robust_info/0,
    sphincs_plus_shake_256f_robust_keypair/0,
    sphincs_plus_shake_256f_robust_keypair/1,
    sphincs_plus_shake_256f_robust_sign/2,
    sphincs_plus_shake_256f_robust_verify/3,
    sphincs_plus_shake_256f_simple_info/0,
    sphincs_plus_shake_256f_simple_keypair/0,
    sphincs_plus_shake_256f_simple_keypair/1,
    sphincs_plus_shake_256f_simple_sign/2,
    sphincs_plus_shake_256f_simple_verify/3,
    sphincs_plus_shake_256s_robust_info/0,
    sphincs_plus_shake_256s_robust_keypair/0,
    sphincs_plus_shake_256s_robust_keypair/1,
    sphincs_plus_shake_256s_robust_sign/2,
    sphincs_plus_shake_256s_robust_verify/3,
    sphincs_plus_shake_256s_simple_info/0,
    sphincs_plus_shake_256s_simple_keypair/0,
    sphincs_plus_shake_256s_simple_keypair/1,
    sphincs_plus_shake_256s_simple_sign/2,
    sphincs_plus_shake_256s_simple_verify/3
]).

-nifs([
    dirty_job_cpu_stack_size/0,
    hqc_rmrs_128_info/0,
    hqc_rmrs_128_keypair/0,
    hqc_rmrs_128_encapsulate/1,
    hqc_rmrs_128_decapsulate/2,
    hqc_rmrs_192_info/0,
    hqc_rmrs_192_keypair/0,
    hqc_rmrs_192_encapsulate/1,
    hqc_rmrs_192_decapsulate/2,
    hqc_rmrs_256_info/0,
    hqc_rmrs_256_keypair/0,
    hqc_rmrs_256_encapsulate/1,
    hqc_rmrs_256_decapsulate/2,
    kyber512_info/0,
    kyber512_keypair/0,
    kyber512_encapsulate/1,
    kyber512_decapsulate/2,
    kyber512_90s_info/0,
    kyber512_90s_keypair/0,
    kyber512_90s_encapsulate/1,
    kyber512_90s_decapsulate/2,
    kyber768_info/0,
    kyber768_keypair/0,
    kyber768_encapsulate/1,
    kyber768_decapsulate/2,
    kyber768_90s_info/0,
    kyber768_90s_keypair/0,
    kyber768_90s_encapsulate/1,
    kyber768_90s_decapsulate/2,
    kyber1024_info/0,
    kyber1024_keypair/0,
    kyber1024_encapsulate/1,
    kyber1024_decapsulate/2,
    kyber1024_90s_info/0,
    kyber1024_90s_keypair/0,
    kyber1024_90s_encapsulate/1,
    kyber1024_90s_decapsulate/2,
    mceliece348864_info/0,
    mceliece348864_keypair/0,
    mceliece348864_encapsulate/1,
    mceliece348864_decapsulate/2,
    mceliece348864f_info/0,
    mceliece348864f_keypair/0,
    mceliece348864f_encapsulate/1,
    mceliece348864f_decapsulate/2,
    mceliece460896_info/0,
    mceliece460896_keypair/0,
    mceliece460896_encapsulate/1,
    mceliece460896_decapsulate/2,
    mceliece460896f_info/0,
    mceliece460896f_keypair/0,
    mceliece460896f_encapsulate/1,
    mceliece460896f_decapsulate/2,
    mceliece6688128_info/0,
    mceliece6688128_keypair/0,
    mceliece6688128_encapsulate/1,
    mceliece6688128_decapsulate/2,
    mceliece6688128f_info/0,
    mceliece6688128f_keypair/0,
    mceliece6688128f_encapsulate/1,
    mceliece6688128f_decapsulate/2,
    mceliece6960119_info/0,
    mceliece6960119_keypair/0,
    mceliece6960119_encapsulate/1,
    mceliece6960119_decapsulate/2,
    mceliece6960119f_info/0,
    mceliece6960119f_keypair/0,
    mceliece6960119f_encapsulate/1,
    mceliece6960119f_decapsulate/2,
    mceliece8192128_info/0,
    mceliece8192128_keypair/0,
    mceliece8192128_encapsulate/1,
    mceliece8192128_decapsulate/2,
    mceliece8192128f_info/0,
    mceliece8192128f_keypair/0,
    mceliece8192128f_encapsulate/1,
    mceliece8192128f_decapsulate/2,
    dilithium2_info/0,
    dilithium2_keypair/0,
    dilithium2_sign/2,
    dilithium2_verify/3,
    dilithium2aes_info/0,
    dilithium2aes_keypair/0,
    dilithium2aes_sign/2,
    dilithium2aes_verify/3,
    dilithium3_info/0,
    dilithium3_keypair/0,
    dilithium3_sign/2,
    dilithium3_verify/3,
    dilithium3aes_info/0,
    dilithium3aes_keypair/0,
    dilithium3aes_sign/2,
    dilithium3aes_verify/3,
    dilithium5_info/0,
    dilithium5_keypair/0,
    dilithium5_sign/2,
    dilithium5_verify/3,
    dilithium5aes_info/0,
    dilithium5aes_keypair/0,
    dilithium5aes_sign/2,
    dilithium5aes_verify/3,
    falcon512_info/0,
    falcon512_keypair/0,
    falcon512_sign/2,
    falcon512_verify/3,
    falcon1024_info/0,
    falcon1024_keypair/0,
    falcon1024_sign/2,
    falcon1024_verify/3,
    sphincs_plus_haraka_128f_robust_info/0,
    sphincs_plus_haraka_128f_robust_keypair/0,
    sphincs_plus_haraka_128f_robust_keypair/1,
    sphincs_plus_haraka_128f_robust_sign/2,
    sphincs_plus_haraka_128f_robust_verify/3,
    sphincs_plus_haraka_128f_simple_info/0,
    sphincs_plus_haraka_128f_simple_keypair/0,
    sphincs_plus_haraka_128f_simple_keypair/1,
    sphincs_plus_haraka_128f_simple_sign/2,
    sphincs_plus_haraka_128f_simple_verify/3,
    sphincs_plus_haraka_128s_robust_info/0,
    sphincs_plus_haraka_128s_robust_keypair/0,
    sphincs_plus_haraka_128s_robust_keypair/1,
    sphincs_plus_haraka_128s_robust_sign/2,
    sphincs_plus_haraka_128s_robust_verify/3,
    sphincs_plus_haraka_128s_simple_info/0,
    sphincs_plus_haraka_128s_simple_keypair/0,
    sphincs_plus_haraka_128s_simple_keypair/1,
    sphincs_plus_haraka_128s_simple_sign/2,
    sphincs_plus_haraka_128s_simple_verify/3,
    sphincs_plus_haraka_192f_robust_info/0,
    sphincs_plus_haraka_192f_robust_keypair/0,
    sphincs_plus_haraka_192f_robust_keypair/1,
    sphincs_plus_haraka_192f_robust_sign/2,
    sphincs_plus_haraka_192f_robust_verify/3,
    sphincs_plus_haraka_192f_simple_info/0,
    sphincs_plus_haraka_192f_simple_keypair/0,
    sphincs_plus_haraka_192f_simple_keypair/1,
    sphincs_plus_haraka_192f_simple_sign/2,
    sphincs_plus_haraka_192f_simple_verify/3,
    sphincs_plus_haraka_192s_robust_info/0,
    sphincs_plus_haraka_192s_robust_keypair/0,
    sphincs_plus_haraka_192s_robust_keypair/1,
    sphincs_plus_haraka_192s_robust_sign/2,
    sphincs_plus_haraka_192s_robust_verify/3,
    sphincs_plus_haraka_192s_simple_info/0,
    sphincs_plus_haraka_192s_simple_keypair/0,
    sphincs_plus_haraka_192s_simple_keypair/1,
    sphincs_plus_haraka_192s_simple_sign/2,
    sphincs_plus_haraka_192s_simple_verify/3,
    sphincs_plus_haraka_256f_robust_info/0,
    sphincs_plus_haraka_256f_robust_keypair/0,
    sphincs_plus_haraka_256f_robust_keypair/1,
    sphincs_plus_haraka_256f_robust_sign/2,
    sphincs_plus_haraka_256f_robust_verify/3,
    sphincs_plus_haraka_256f_simple_info/0,
    sphincs_plus_haraka_256f_simple_keypair/0,
    sphincs_plus_haraka_256f_simple_keypair/1,
    sphincs_plus_haraka_256f_simple_sign/2,
    sphincs_plus_haraka_256f_simple_verify/3,
    sphincs_plus_haraka_256s_robust_info/0,
    sphincs_plus_haraka_256s_robust_keypair/0,
    sphincs_plus_haraka_256s_robust_keypair/1,
    sphincs_plus_haraka_256s_robust_sign/2,
    sphincs_plus_haraka_256s_robust_verify/3,
    sphincs_plus_haraka_256s_simple_info/0,
    sphincs_plus_haraka_256s_simple_keypair/0,
    sphincs_plus_haraka_256s_simple_keypair/1,
    sphincs_plus_haraka_256s_simple_sign/2,
    sphincs_plus_haraka_256s_simple_verify/3,
    sphincs_plus_sha2_128f_robust_info/0,
    sphincs_plus_sha2_128f_robust_keypair/0,
    sphincs_plus_sha2_128f_robust_keypair/1,
    sphincs_plus_sha2_128f_robust_sign/2,
    sphincs_plus_sha2_128f_robust_verify/3,
    sphincs_plus_sha2_128f_simple_info/0,
    sphincs_plus_sha2_128f_simple_keypair/0,
    sphincs_plus_sha2_128f_simple_keypair/1,
    sphincs_plus_sha2_128f_simple_sign/2,
    sphincs_plus_sha2_128f_simple_verify/3,
    sphincs_plus_sha2_128s_robust_info/0,
    sphincs_plus_sha2_128s_robust_keypair/0,
    sphincs_plus_sha2_128s_robust_keypair/1,
    sphincs_plus_sha2_128s_robust_sign/2,
    sphincs_plus_sha2_128s_robust_verify/3,
    sphincs_plus_sha2_128s_simple_info/0,
    sphincs_plus_sha2_128s_simple_keypair/0,
    sphincs_plus_sha2_128s_simple_keypair/1,
    sphincs_plus_sha2_128s_simple_sign/2,
    sphincs_plus_sha2_128s_simple_verify/3,
    sphincs_plus_sha2_192f_robust_info/0,
    sphincs_plus_sha2_192f_robust_keypair/0,
    sphincs_plus_sha2_192f_robust_keypair/1,
    sphincs_plus_sha2_192f_robust_sign/2,
    sphincs_plus_sha2_192f_robust_verify/3,
    sphincs_plus_sha2_192f_simple_info/0,
    sphincs_plus_sha2_192f_simple_keypair/0,
    sphincs_plus_sha2_192f_simple_keypair/1,
    sphincs_plus_sha2_192f_simple_sign/2,
    sphincs_plus_sha2_192f_simple_verify/3,
    sphincs_plus_sha2_192s_robust_info/0,
    sphincs_plus_sha2_192s_robust_keypair/0,
    sphincs_plus_sha2_192s_robust_keypair/1,
    sphincs_plus_sha2_192s_robust_sign/2,
    sphincs_plus_sha2_192s_robust_verify/3,
    sphincs_plus_sha2_192s_simple_info/0,
    sphincs_plus_sha2_192s_simple_keypair/0,
    sphincs_plus_sha2_192s_simple_keypair/1,
    sphincs_plus_sha2_192s_simple_sign/2,
    sphincs_plus_sha2_192s_simple_verify/3,
    sphincs_plus_sha2_256f_robust_info/0,
    sphincs_plus_sha2_256f_robust_keypair/0,
    sphincs_plus_sha2_256f_robust_keypair/1,
    sphincs_plus_sha2_256f_robust_sign/2,
    sphincs_plus_sha2_256f_robust_verify/3,
    sphincs_plus_sha2_256f_simple_info/0,
    sphincs_plus_sha2_256f_simple_keypair/0,
    sphincs_plus_sha2_256f_simple_keypair/1,
    sphincs_plus_sha2_256f_simple_sign/2,
    sphincs_plus_sha2_256f_simple_verify/3,
    sphincs_plus_sha2_256s_robust_info/0,
    sphincs_plus_sha2_256s_robust_keypair/0,
    sphincs_plus_sha2_256s_robust_keypair/1,
    sphincs_plus_sha2_256s_robust_sign/2,
    sphincs_plus_sha2_256s_robust_verify/3,
    sphincs_plus_sha2_256s_simple_info/0,
    sphincs_plus_sha2_256s_simple_keypair/0,
    sphincs_plus_sha2_256s_simple_keypair/1,
    sphincs_plus_sha2_256s_simple_sign/2,
    sphincs_plus_sha2_256s_simple_verify/3,
    sphincs_plus_shake_128f_robust_info/0,
    sphincs_plus_shake_128f_robust_keypair/0,
    sphincs_plus_shake_128f_robust_keypair/1,
    sphincs_plus_shake_128f_robust_sign/2,
    sphincs_plus_shake_128f_robust_verify/3,
    sphincs_plus_shake_128f_simple_info/0,
    sphincs_plus_shake_128f_simple_keypair/0,
    sphincs_plus_shake_128f_simple_keypair/1,
    sphincs_plus_shake_128f_simple_sign/2,
    sphincs_plus_shake_128f_simple_verify/3,
    sphincs_plus_shake_128s_robust_info/0,
    sphincs_plus_shake_128s_robust_keypair/0,
    sphincs_plus_shake_128s_robust_keypair/1,
    sphincs_plus_shake_128s_robust_sign/2,
    sphincs_plus_shake_128s_robust_verify/3,
    sphincs_plus_shake_128s_simple_info/0,
    sphincs_plus_shake_128s_simple_keypair/0,
    sphincs_plus_shake_128s_simple_keypair/1,
    sphincs_plus_shake_128s_simple_sign/2,
    sphincs_plus_shake_128s_simple_verify/3,
    sphincs_plus_shake_192f_robust_info/0,
    sphincs_plus_shake_192f_robust_keypair/0,
    sphincs_plus_shake_192f_robust_keypair/1,
    sphincs_plus_shake_192f_robust_sign/2,
    sphincs_plus_shake_192f_robust_verify/3,
    sphincs_plus_shake_192f_simple_info/0,
    sphincs_plus_shake_192f_simple_keypair/0,
    sphincs_plus_shake_192f_simple_keypair/1,
    sphincs_plus_shake_192f_simple_sign/2,
    sphincs_plus_shake_192f_simple_verify/3,
    sphincs_plus_shake_192s_robust_info/0,
    sphincs_plus_shake_192s_robust_keypair/0,
    sphincs_plus_shake_192s_robust_keypair/1,
    sphincs_plus_shake_192s_robust_sign/2,
    sphincs_plus_shake_192s_robust_verify/3,
    sphincs_plus_shake_192s_simple_info/0,
    sphincs_plus_shake_192s_simple_keypair/0,
    sphincs_plus_shake_192s_simple_keypair/1,
    sphincs_plus_shake_192s_simple_sign/2,
    sphincs_plus_shake_192s_simple_verify/3,
    sphincs_plus_shake_256f_robust_info/0,
    sphincs_plus_shake_256f_robust_keypair/0,
    sphincs_plus_shake_256f_robust_keypair/1,
    sphincs_plus_shake_256f_robust_sign/2,
    sphincs_plus_shake_256f_robust_verify/3,
    sphincs_plus_shake_256f_simple_info/0,
    sphincs_plus_shake_256f_simple_keypair/0,
    sphincs_plus_shake_256f_simple_keypair/1,
    sphincs_plus_shake_256f_simple_sign/2,
    sphincs_plus_shake_256f_simple_verify/3,
    sphincs_plus_shake_256s_robust_info/0,
    sphincs_plus_shake_256s_robust_keypair/0,
    sphincs_plus_shake_256s_robust_keypair/1,
    sphincs_plus_shake_256s_robust_sign/2,
    sphincs_plus_shake_256s_robust_verify/3,
    sphincs_plus_shake_256s_simple_info/0,
    sphincs_plus_shake_256s_simple_keypair/0,
    sphincs_plus_shake_256s_simple_keypair/1,
    sphincs_plus_shake_256s_simple_sign/2,
    sphincs_plus_shake_256s_simple_verify/3
]).

%% Internal NIF API
-export([
    init/0
]).

%% Types
-type crypto_kem_info() :: #{
    type := kem,
    name := string(),
    secretkeybytes := non_neg_integer(),
    publickeybytes := non_neg_integer(),
    ciphertextbytes := non_neg_integer(),
    sharedsecretbytes := non_neg_integer()
}.
%%% Map representation for a <a href="https://en.wikipedia.org/wiki/Key_encapsulation_mechanism">Key Encapsulation Mechanism (KEM)</a> Algorithm.
%%%
%%% The following functions return this type:
%%%
%%% <ul>
%%%   <li>{@link hqc_rmrs_128_info/0}</li>
%%%   <li>{@link hqc_rmrs_192_info/0}</li>
%%%   <li>{@link hqc_rmrs_256_info/0}</li>
%%%   <li>{@link kyber512_info/0}</li>
%%%   <li>{@link kyber512_90s_info/0}</li>
%%%   <li>{@link kyber768_info/0}</li>
%%%   <li>{@link kyber768_90s_info/0}</li>
%%%   <li>{@link kyber1024_info/0}</li>
%%%   <li>{@link kyber1024_90s_info/0}</li>
%%%   <li>{@link mceliece348864_info/0}</li>
%%%   <li>{@link mceliece348864f_info/0}</li>
%%%   <li>{@link mceliece460896_info/0}</li>
%%%   <li>{@link mceliece460896f_info/0}</li>
%%%   <li>{@link mceliece6688128_info/0}</li>
%%%   <li>{@link mceliece6688128f_info/0}</li>
%%%   <li>{@link mceliece6960119_info/0}</li>
%%%   <li>{@link mceliece6960119f_info/0}</li>
%%%   <li>{@link mceliece8192128_info/0}</li>
%%%   <li>{@link mceliece8192128f_info/0}</li>
%%% </ul>

-type crypto_sign_info() :: #{
    type := sign,
    name := string(),
    secretkeybytes := non_neg_integer(),
    publickeybytes := non_neg_integer(),
    signaturebytes := non_neg_integer(),
    seedbytes => non_neg_integer()
}.
%%% Map representation for a <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% The following functions return this type:
%%%
%%% <ul>
%%%   <li>{@link dilithium2_info/0}</li>
%%%   <li>{@link dilithium2aes_info/0}</li>
%%%   <li>{@link dilithium3_info/0}</li>
%%%   <li>{@link dilithium3aes_info/0}</li>
%%%   <li>{@link dilithium5_info/0}</li>
%%%   <li>{@link dilithium5aes_info/0}</li>
%%%   <li>{@link falcon512_info/0}</li>
%%%   <li>{@link falcon1024_info/0}</li>
%%%   <li>{@link sphincs_plus_haraka_128f_robust_info/0}</li>
%%%   <li>{@link sphincs_plus_haraka_128f_simple_info/0}</li>
%%%   <li>{@link sphincs_plus_haraka_128s_robust_info/0}</li>
%%%   <li>{@link sphincs_plus_haraka_128s_simple_info/0}</li>
%%%   <li>{@link sphincs_plus_haraka_192f_robust_info/0}</li>
%%%   <li>{@link sphincs_plus_haraka_192f_simple_info/0}</li>
%%%   <li>{@link sphincs_plus_haraka_192s_robust_info/0}</li>
%%%   <li>{@link sphincs_plus_haraka_192s_simple_info/0}</li>
%%%   <li>{@link sphincs_plus_haraka_256f_robust_info/0}</li>
%%%   <li>{@link sphincs_plus_haraka_256f_simple_info/0}</li>
%%%   <li>{@link sphincs_plus_haraka_256s_robust_info/0}</li>
%%%   <li>{@link sphincs_plus_haraka_256s_simple_info/0}</li>
%%%   <li>{@link sphincs_plus_sha2_128f_robust_info/0}</li>
%%%   <li>{@link sphincs_plus_sha2_128f_simple_info/0}</li>
%%%   <li>{@link sphincs_plus_sha2_128s_robust_info/0}</li>
%%%   <li>{@link sphincs_plus_sha2_128s_simple_info/0}</li>
%%%   <li>{@link sphincs_plus_sha2_192f_robust_info/0}</li>
%%%   <li>{@link sphincs_plus_sha2_192f_simple_info/0}</li>
%%%   <li>{@link sphincs_plus_sha2_192s_robust_info/0}</li>
%%%   <li>{@link sphincs_plus_sha2_192s_simple_info/0}</li>
%%%   <li>{@link sphincs_plus_sha2_256f_robust_info/0}</li>
%%%   <li>{@link sphincs_plus_sha2_256f_simple_info/0}</li>
%%%   <li>{@link sphincs_plus_sha2_256s_robust_info/0}</li>
%%%   <li>{@link sphincs_plus_sha2_256s_simple_info/0}</li>
%%%   <li>{@link sphincs_plus_shake_128f_robust_info/0}</li>
%%%   <li>{@link sphincs_plus_shake_128f_simple_info/0}</li>
%%%   <li>{@link sphincs_plus_shake_128s_robust_info/0}</li>
%%%   <li>{@link sphincs_plus_shake_128s_simple_info/0}</li>
%%%   <li>{@link sphincs_plus_shake_192f_robust_info/0}</li>
%%%   <li>{@link sphincs_plus_shake_192f_simple_info/0}</li>
%%%   <li>{@link sphincs_plus_shake_192s_robust_info/0}</li>
%%%   <li>{@link sphincs_plus_shake_192s_simple_info/0}</li>
%%%   <li>{@link sphincs_plus_shake_256f_robust_info/0}</li>
%%%   <li>{@link sphincs_plus_shake_256f_simple_info/0}</li>
%%%   <li>{@link sphincs_plus_shake_256s_robust_info/0}</li>
%%%   <li>{@link sphincs_plus_shake_256s_simple_info/0}</li>
%%% </ul>

-export_type([
    crypto_kem_info/0,
    crypto_sign_info/0
]).

-type hqc_rmrs_128_secret_key() :: <<_:18312>>.
%%% Binary representation of a `SecretKey' for the HQC-RMRS-128 KEM Algorithm (2,289-bytes).
-type hqc_rmrs_128_public_key() :: <<_:17992>>.
%%% Binary representation of a `PublicKey' for the HQC-RMRS-128 KEM Algorithm (2,249-bytes).
-type hqc_rmrs_128_cipher_text() :: <<_:35848>>.
%%% Binary representation of a `CipherText' for the HQC-RMRS-128 KEM Algorithm (4,481-bytes).
-type hqc_rmrs_128_shared_secret() :: <<_:512>>.
%%% Binary representation of a `SharedSecret' for the HQC-RMRS-128 KEM Algorithm (64-bytes).

-export_type([
    hqc_rmrs_128_secret_key/0,
    hqc_rmrs_128_public_key/0,
    hqc_rmrs_128_cipher_text/0,
    hqc_rmrs_128_shared_secret/0
]).

-type hqc_rmrs_192_secret_key() :: <<_:36496>>.
%%% Binary representation of a `SecretKey' for the HQC-RMRS-192 KEM Algorithm (4,562-bytes).
-type hqc_rmrs_192_public_key() :: <<_:36176>>.
%%% Binary representation of a `PublicKey' for the HQC-RMRS-192 KEM Algorithm (4,522-bytes).
-type hqc_rmrs_192_cipher_text() :: <<_:72208>>.
%%% Binary representation of a `CipherText' for the HQC-RMRS-192 KEM Algorithm (9,026-bytes).
-type hqc_rmrs_192_shared_secret() :: <<_:512>>.
%%% Binary representation of a `SharedSecret' for the HQC-RMRS-192 KEM Algorithm (64-bytes).

-export_type([
    hqc_rmrs_192_secret_key/0,
    hqc_rmrs_192_public_key/0,
    hqc_rmrs_192_cipher_text/0,
    hqc_rmrs_192_shared_secret/0
]).

-type hqc_rmrs_256_secret_key() :: <<_:58280>>.
%%% Binary representation of a `SecretKey' for the HQC-RMRS-256 KEM Algorithm (7,285-bytes).
-type hqc_rmrs_256_public_key() :: <<_:57960>>.
%%% Binary representation of a `PublicKey' for the HQC-RMRS-256 KEM Algorithm (7,245-bytes).
-type hqc_rmrs_256_cipher_text() :: <<_:115752>>.
%%% Binary representation of a `CipherText' for the HQC-RMRS-256 KEM Algorithm (14,469-bytes).
-type hqc_rmrs_256_shared_secret() :: <<_:512>>.
%%% Binary representation of a `SharedSecret' for the HQC-RMRS-256 KEM Algorithm (64-bytes).

-export_type([
    hqc_rmrs_256_secret_key/0,
    hqc_rmrs_256_public_key/0,
    hqc_rmrs_256_cipher_text/0,
    hqc_rmrs_256_shared_secret/0
]).

-type kyber512_secret_key() :: <<_:13056>>.
%%% Binary representation of a `SecretKey' for the Kyber512 KEM Algorithm (1,632-bytes).
-type kyber512_public_key() :: <<_:6400>>.
%%% Binary representation of a `PublicKey' for the Kyber512 KEM Algorithm (800-bytes).
-type kyber512_cipher_text() :: <<_:6144>>.
%%% Binary representation of a `CipherText' for the Kyber512 KEM Algorithm (768-bytes).
-type kyber512_shared_secret() :: <<_:256>>.
%%% Binary representation of a `SharedSecret' for the Kyber512 KEM Algorithm (32-bytes).

-export_type([
    kyber512_secret_key/0,
    kyber512_public_key/0,
    kyber512_cipher_text/0,
    kyber512_shared_secret/0
]).

-type kyber512_90s_secret_key() :: <<_:13056>>.
%%% Binary representation of a `SecretKey' for the Kyber512-90s KEM Algorithm (1,632-bytes).
-type kyber512_90s_public_key() :: <<_:6400>>.
%%% Binary representation of a `PublicKey' for the Kyber512-90s KEM Algorithm (800-bytes).
-type kyber512_90s_cipher_text() :: <<_:6144>>.
%%% Binary representation of a `CipherText' for the Kyber512-90s KEM Algorithm (768-bytes).
-type kyber512_90s_shared_secret() :: <<_:256>>.
%%% Binary representation of a `SharedSecret' for the Kyber512-90s KEM Algorithm (32-bytes).

-export_type([
    kyber512_90s_secret_key/0,
    kyber512_90s_public_key/0,
    kyber512_90s_cipher_text/0,
    kyber512_90s_shared_secret/0
]).

-type kyber768_secret_key() :: <<_:19200>>.
%%% Binary representation of a `SecretKey' for the Kyber768 KEM Algorithm (2,400-bytes).
-type kyber768_public_key() :: <<_:9472>>.
%%% Binary representation of a `PublicKey' for the Kyber768 KEM Algorithm (1,184-bytes).
-type kyber768_cipher_text() :: <<_:8704>>.
%%% Binary representation of a `CipherText' for the Kyber768 KEM Algorithm (1,088-bytes).
-type kyber768_shared_secret() :: <<_:256>>.
%%% Binary representation of a `SharedSecret' for the Kyber768 KEM Algorithm (32-bytes).

-export_type([
    kyber768_secret_key/0,
    kyber768_public_key/0,
    kyber768_cipher_text/0,
    kyber768_shared_secret/0
]).

-type kyber768_90s_secret_key() :: <<_:19200>>.
%%% Binary representation of a `SecretKey' for the Kyber768-90s KEM Algorithm (2,400-bytes).
-type kyber768_90s_public_key() :: <<_:9472>>.
%%% Binary representation of a `PublicKey' for the Kyber768-90s KEM Algorithm (1,184-bytes).
-type kyber768_90s_cipher_text() :: <<_:8704>>.
%%% Binary representation of a `CipherText' for the Kyber768-90s KEM Algorithm (1,088-bytes).
-type kyber768_90s_shared_secret() :: <<_:256>>.
%%% Binary representation of a `SharedSecret' for the Kyber768-90s KEM Algorithm (32-bytes).

-export_type([
    kyber768_90s_secret_key/0,
    kyber768_90s_public_key/0,
    kyber768_90s_cipher_text/0,
    kyber768_90s_shared_secret/0
]).

-type kyber1024_secret_key() :: <<_:25344>>.
%%% Binary representation of a `SecretKey' for the Kyber1024 KEM Algorithm (3,168-bytes).
-type kyber1024_public_key() :: <<_:12544>>.
%%% Binary representation of a `PublicKey' for the Kyber1024 KEM Algorithm (1,568-bytes).
-type kyber1024_cipher_text() :: <<_:12544>>.
%%% Binary representation of a `CipherText' for the Kyber1024 KEM Algorithm (1,568-bytes).
-type kyber1024_shared_secret() :: <<_:256>>.
%%% Binary representation of a `SharedSecret' for the Kyber1024 KEM Algorithm (32-bytes).

-export_type([
    kyber1024_secret_key/0,
    kyber1024_public_key/0,
    kyber1024_cipher_text/0,
    kyber1024_shared_secret/0
]).

-type kyber1024_90s_secret_key() :: <<_:25344>>.
%%% Binary representation of a `SecretKey' for the Kyber1024-90s KEM Algorithm (3,168-bytes).
-type kyber1024_90s_public_key() :: <<_:12544>>.
%%% Binary representation of a `PublicKey' for the Kyber1024-90s KEM Algorithm (1,568-bytes).
-type kyber1024_90s_cipher_text() :: <<_:12544>>.
%%% Binary representation of a `CipherText' for the Kyber1024-90s KEM Algorithm (1,568-bytes).
-type kyber1024_90s_shared_secret() :: <<_:256>>.
%%% Binary representation of a `SharedSecret' for the Kyber1024-90s KEM Algorithm (32-bytes).

-export_type([
    kyber1024_90s_secret_key/0,
    kyber1024_90s_public_key/0,
    kyber1024_90s_cipher_text/0,
    kyber1024_90s_shared_secret/0
]).

-type mceliece348864_secret_key() :: <<_:51616>>.
%%% Binary representation of a `SecretKey' for the Classic McEliece 348864 KEM Algorithm (6,452-bytes).
-type mceliece348864_public_key() :: <<_:2088960>>.
%%% Binary representation of a `PublicKey' for the Classic McEliece 348864 KEM Algorithm (261,120-bytes).
-type mceliece348864_cipher_text() :: <<_:1024>>.
%%% Binary representation of a `CipherText' for the Classic McEliece 348864 KEM Algorithm (128-bytes).
-type mceliece348864_shared_secret() :: <<_:256>>.
%%% Binary representation of a `SharedSecret' for the Classic McEliece 348864 KEM Algorithm (32-bytes).

-export_type([
    mceliece348864_secret_key/0,
    mceliece348864_public_key/0,
    mceliece348864_cipher_text/0,
    mceliece348864_shared_secret/0
]).

-type mceliece348864f_secret_key() :: <<_:51616>>.
%%% Binary representation of a `SecretKey' for the Classic McEliece 348864f KEM Algorithm (6,452-bytes).
-type mceliece348864f_public_key() :: <<_:2088960>>.
%%% Binary representation of a `PublicKey' for the Classic McEliece 348864f KEM Algorithm (261,120-bytes).
-type mceliece348864f_cipher_text() :: <<_:1024>>.
%%% Binary representation of a `CipherText' for the Classic McEliece 348864f KEM Algorithm (128-bytes).
-type mceliece348864f_shared_secret() :: <<_:256>>.
%%% Binary representation of a `SharedSecret' for the Classic McEliece 348864f KEM Algorithm (32-bytes).

-export_type([
    mceliece348864f_secret_key/0,
    mceliece348864f_public_key/0,
    mceliece348864f_cipher_text/0,
    mceliece348864f_shared_secret/0
]).

-type mceliece460896_secret_key() :: <<_:108544>>.
%%% Binary representation of a `SecretKey' for the Classic McEliece 460896 KEM Algorithm (13,568-bytes).
-type mceliece460896_public_key() :: <<_:4193280>>.
%%% Binary representation of a `PublicKey' for the Classic McEliece 460896 KEM Algorithm (524,160-bytes).
-type mceliece460896_cipher_text() :: <<_:1504>>.
%%% Binary representation of a `CipherText' for the Classic McEliece 460896 KEM Algorithm (188-bytes).
-type mceliece460896_shared_secret() :: <<_:256>>.
%%% Binary representation of a `SharedSecret' for the Classic McEliece 460896 KEM Algorithm (32-bytes).

-export_type([
    mceliece460896_secret_key/0,
    mceliece460896_public_key/0,
    mceliece460896_cipher_text/0,
    mceliece460896_shared_secret/0
]).

-type mceliece460896f_secret_key() :: <<_:108544>>.
%%% Binary representation of a `SecretKey' for the Classic McEliece 460896f KEM Algorithm (13,568-bytes).
-type mceliece460896f_public_key() :: <<_:4193280>>.
%%% Binary representation of a `PublicKey' for the Classic McEliece 460896f KEM Algorithm (524,160-bytes).
-type mceliece460896f_cipher_text() :: <<_:1504>>.
%%% Binary representation of a `CipherText' for the Classic McEliece 460896f KEM Algorithm (188-bytes).
-type mceliece460896f_shared_secret() :: <<_:256>>.
%%% Binary representation of a `SharedSecret' for the Classic McEliece 460896f KEM Algorithm (32-bytes).

-export_type([
    mceliece460896f_secret_key/0,
    mceliece460896f_public_key/0,
    mceliece460896f_cipher_text/0,
    mceliece460896f_shared_secret/0
]).

-type mceliece6688128_secret_key() :: <<_:111136>>.
%%% Binary representation of a `SecretKey' for the Classic McEliece 6688128 KEM Algorithm (13,892-bytes).
-type mceliece6688128_public_key() :: <<_:8359936>>.
%%% Binary representation of a `PublicKey' for the Classic McEliece 6688128 KEM Algorithm (1,044,992-bytes).
-type mceliece6688128_cipher_text() :: <<_:1920>>.
%%% Binary representation of a `CipherText' for the Classic McEliece 6688128 KEM Algorithm (240-bytes).
-type mceliece6688128_shared_secret() :: <<_:256>>.
%%% Binary representation of a `SharedSecret' for the Classic McEliece 6688128 KEM Algorithm (32-bytes).

-export_type([
    mceliece6688128_secret_key/0,
    mceliece6688128_public_key/0,
    mceliece6688128_cipher_text/0,
    mceliece6688128_shared_secret/0
]).

-type mceliece6688128f_secret_key() :: <<_:111136>>.
%%% Binary representation of a `SecretKey' for the Classic McEliece 6688128 KEM Algorithm (13,892-bytes).
-type mceliece6688128f_public_key() :: <<_:8359936>>.
%%% Binary representation of a `PublicKey' for the Classic McEliece 6688128 KEM Algorithm (1,044,992-bytes).
-type mceliece6688128f_cipher_text() :: <<_:1920>>.
%%% Binary representation of a `CipherText' for the Classic McEliece 6688128 KEM Algorithm (240-bytes).
-type mceliece6688128f_shared_secret() :: <<_:256>>.
%%% Binary representation of a `SharedSecret' for the Classic McEliece 6688128 KEM Algorithm (32-bytes).

-export_type([
    mceliece6688128f_secret_key/0,
    mceliece6688128f_public_key/0,
    mceliece6688128f_cipher_text/0,
    mceliece6688128f_shared_secret/0
]).

-type mceliece6960119_secret_key() :: <<_:111264>>.
%%% Binary representation of a `SecretKey' for the Classic McEliece 6960119 KEM Algorithm (13,908-bytes).
-type mceliece6960119_public_key() :: <<_:8378552>>.
%%% Binary representation of a `PublicKey' for the Classic McEliece 6960119 KEM Algorithm (1,047,319-bytes).
-type mceliece6960119_cipher_text() :: <<_:1808>>.
%%% Binary representation of a `CipherText' for the Classic McEliece 6960119 KEM Algorithm (226-bytes).
-type mceliece6960119_shared_secret() :: <<_:256>>.
%%% Binary representation of a `SharedSecret' for the Classic McEliece 6960119 KEM Algorithm (32-bytes).

-export_type([
    mceliece6960119_secret_key/0,
    mceliece6960119_public_key/0,
    mceliece6960119_cipher_text/0,
    mceliece6960119_shared_secret/0
]).

-type mceliece6960119f_secret_key() :: <<_:111264>>.
%%% Binary representation of a `SecretKey' for the Classic McEliece 6960119f KEM Algorithm (13,908-bytes).
-type mceliece6960119f_public_key() :: <<_:8378552>>.
%%% Binary representation of a `PublicKey' for the Classic McEliece 6960119f KEM Algorithm (1,047,319-bytes).
-type mceliece6960119f_cipher_text() :: <<_:1808>>.
%%% Binary representation of a `CipherText' for the Classic McEliece 6960119f KEM Algorithm (226-bytes).
-type mceliece6960119f_shared_secret() :: <<_:256>>.
%%% Binary representation of a `SharedSecret' for the Classic McEliece 6960119f KEM Algorithm (32-bytes).

-export_type([
    mceliece6960119f_secret_key/0,
    mceliece6960119f_public_key/0,
    mceliece6960119f_cipher_text/0,
    mceliece6960119f_shared_secret/0
]).

-type mceliece8192128_secret_key() :: <<_:112640>>.
%%% Binary representation of a `SecretKey' for the Classic McEliece 8192128 KEM Algorithm (14,080-bytes).
-type mceliece8192128_public_key() :: <<_:10862592>>.
%%% Binary representation of a `PublicKey' for the Classic McEliece 8192128 KEM Algorithm (1,357,824-bytes).
-type mceliece8192128_cipher_text() :: <<_:1920>>.
%%% Binary representation of a `CipherText' for the Classic McEliece 8192128 KEM Algorithm (240-bytes).
-type mceliece8192128_shared_secret() :: <<_:256>>.
%%% Binary representation of a `SharedSecret' for the Classic McEliece 8192128 KEM Algorithm (32-bytes).

-export_type([
    mceliece8192128_secret_key/0,
    mceliece8192128_public_key/0,
    mceliece8192128_cipher_text/0,
    mceliece8192128_shared_secret/0
]).

-type mceliece8192128f_secret_key() :: <<_:112640>>.
%%% Binary representation of a `SecretKey' for the Classic McEliece 8192128f KEM Algorithm (14,080-bytes).
-type mceliece8192128f_public_key() :: <<_:10862592>>.
%%% Binary representation of a `PublicKey' for the Classic McEliece 8192128f KEM Algorithm (1,357,824-bytes).
-type mceliece8192128f_cipher_text() :: <<_:1920>>.
%%% Binary representation of a `CipherText' for the Classic McEliece 8192128f KEM Algorithm (240-bytes).
-type mceliece8192128f_shared_secret() :: <<_:256>>.
%%% Binary representation of a `SharedSecret' for the Classic McEliece 8192128f KEM Algorithm (32-bytes).

-export_type([
    mceliece8192128f_secret_key/0,
    mceliece8192128f_public_key/0,
    mceliece8192128f_cipher_text/0,
    mceliece8192128f_shared_secret/0
]).

-type dilithium2_secret_key() :: <<_:20224>>.
%%% Binary representation of a `SecretKey' for the Dilithium2 Signature Algorithm (2,528-bytes).
-type dilithium2_public_key() :: <<_:10496>>.
%%% Binary representation of a `PublicKey' for the Dilithium2 Signature Algorithm (1,312-bytes).
-type dilithium2_message() :: binary().
%%% Binary representation of a `Message' for the Dilithium2 Signature Algorithm.
-type dilithium2_signature() :: <<_:19360>> | binary().
%%% Binary representation of a `Signature' for the Dilithium2 Signature Algorithm (maximum of 2,420-bytes).
-type dilithium2_verification() :: boolean().
%%% Boolean representation of a `Verification' for the Dilithium2 Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    dilithium2_secret_key/0,
    dilithium2_public_key/0,
    dilithium2_message/0,
    dilithium2_signature/0,
    dilithium2_verification/0
]).

-type dilithium2aes_secret_key() :: <<_:20224>>.
%%% Binary representation of a `SecretKey' for the Dilithium2-AES Signature Algorithm (2,528-bytes).
-type dilithium2aes_public_key() :: <<_:10496>>.
%%% Binary representation of a `PublicKey' for the Dilithium2-AES Signature Algorithm (1,312-bytes).
-type dilithium2aes_message() :: binary().
%%% Binary representation of a `Message' for the Dilithium2-AES Signature Algorithm.
-type dilithium2aes_signature() :: <<_:19360>> | binary().
%%% Binary representation of a `Signature' for the Dilithium2-AES Signature Algorithm (maximum of 2,420-bytes).
-type dilithium2aes_verification() :: boolean().
%%% Boolean representation of a `Verification' for the Dilithium2-AES Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    dilithium2aes_secret_key/0,
    dilithium2aes_public_key/0,
    dilithium2aes_message/0,
    dilithium2aes_signature/0,
    dilithium2aes_verification/0
]).

-type dilithium3_secret_key() :: <<_:32000>>.
%%% Binary representation of a `SecretKey' for the Dilithium3 Signature Algorithm (4,000-bytes).
-type dilithium3_public_key() :: <<_:15616>>.
%%% Binary representation of a `PublicKey' for the Dilithium3 Signature Algorithm (1,952-bytes).
-type dilithium3_message() :: binary().
%%% Binary representation of a `Message' for the Dilithium3 Signature Algorithm.
-type dilithium3_signature() :: <<_:26344>> | binary().
%%% Binary representation of a `Signature' for the Dilithium3 Signature Algorithm (maximum of 3,293-bytes).
-type dilithium3_verification() :: boolean().
%%% Boolean representation of a `Verification' for the Dilithium3 Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    dilithium3_secret_key/0,
    dilithium3_public_key/0,
    dilithium3_message/0,
    dilithium3_signature/0,
    dilithium3_verification/0
]).

-type dilithium3aes_secret_key() :: <<_:32000>>.
%%% Binary representation of a `SecretKey' for the Dilithium3-AES Signature Algorithm (4,000-bytes).
-type dilithium3aes_public_key() :: <<_:15616>>.
%%% Binary representation of a `PublicKey' for the Dilithium3-AES Signature Algorithm (1,952-bytes).
-type dilithium3aes_message() :: binary().
%%% Binary representation of a `Message' for the Dilithium3-AES Signature Algorithm.
-type dilithium3aes_signature() :: <<_:26344>> | binary().
%%% Binary representation of a `Signature' for the Dilithium3-AES Signature Algorithm (maximum of 3,293-bytes).
-type dilithium3aes_verification() :: boolean().
%%% Boolean representation of a `Verification' for the Dilithium3-AES Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    dilithium3aes_secret_key/0,
    dilithium3aes_public_key/0,
    dilithium3aes_message/0,
    dilithium3aes_signature/0,
    dilithium3aes_verification/0
]).

-type dilithium5_secret_key() :: <<_:38912>>.
%%% Binary representation of a `SecretKey' for the Dilithium5 Signature Algorithm (4,864-bytes).
-type dilithium5_public_key() :: <<_:20736>>.
%%% Binary representation of a `PublicKey' for the Dilithium5 Signature Algorithm (2,592-bytes).
-type dilithium5_message() :: binary().
%%% Binary representation of a `Message' for the Dilithium5 Signature Algorithm.
-type dilithium5_signature() :: <<_:36760>> | binary().
%%% Binary representation of a `Signature' for the Dilithium5 Signature Algorithm (maximum of 4,595-bytes).
-type dilithium5_verification() :: boolean().
%%% Boolean representation of a `Verification' for the Dilithium5 Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    dilithium5_secret_key/0,
    dilithium5_public_key/0,
    dilithium5_message/0,
    dilithium5_signature/0,
    dilithium5_verification/0
]).

-type dilithium5aes_secret_key() :: <<_:38912>>.
%%% Binary representation of a `SecretKey' for the Dilithium5-AES Signature Algorithm (4,864-bytes).
-type dilithium5aes_public_key() :: <<_:20736>>.
%%% Binary representation of a `PublicKey' for the Dilithium5-AES Signature Algorithm (2,592-bytes).
-type dilithium5aes_message() :: binary().
%%% Binary representation of a `Message' for the Dilithium5-AES Signature Algorithm.
-type dilithium5aes_signature() :: <<_:36760>> | binary().
%%% Binary representation of a `Signature' for the Dilithium5-AES Signature Algorithm (maximum of 4,595-bytes).
-type dilithium5aes_verification() :: boolean().
%%% Boolean representation of a `Verification' for the Dilithium5-AES Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    dilithium5aes_secret_key/0,
    dilithium5aes_public_key/0,
    dilithium5aes_message/0,
    dilithium5aes_signature/0,
    dilithium5aes_verification/0
]).

-type falcon512_secret_key() :: <<_:10248>>.
%%% Binary representation of a `SecretKey' for the Falcon-512 Signature Algorithm (1,281-bytes).
-type falcon512_public_key() :: <<_:7176>>.
%%% Binary representation of a `PublicKey' for the Falcon-512 Signature Algorithm (897-bytes).
-type falcon512_message() :: binary().
%%% Binary representation of a `Message' for the Falcon-512 Signature Algorithm.
-type falcon512_signature() :: <<_:5328>> | binary().
%%% Binary representation of a `Signature' for the Falcon-512 Signature Algorithm (maximum of 666-bytes).
-type falcon512_verification() :: boolean().
%%% Boolean representation of a `Verification' for the Falcon-512 Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    falcon512_secret_key/0,
    falcon512_public_key/0,
    falcon512_message/0,
    falcon512_signature/0,
    falcon512_verification/0
]).

-type falcon1024_secret_key() :: <<_:18440>>.
%%% Binary representation of a `SecretKey' for the Falcon-1024 Signature Algorithm (2,305-bytes).
-type falcon1024_public_key() :: <<_:14344>>.
%%% Binary representation of a `PublicKey' for the Falcon-1024 Signature Algorithm (1,793-bytes).
-type falcon1024_message() :: binary().
%%% Binary representation of a `Message' for the Falcon-1024 Signature Algorithm.
-type falcon1024_signature() :: <<_:10240>> | binary().
%%% Binary representation of a `Signature' for the Falcon-1024 Signature Algorithm (maximum of 1,280-bytes).
-type falcon1024_verification() :: boolean().
%%% Boolean representation of a `Verification' for the Falcon-1024 Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    falcon1024_secret_key/0,
    falcon1024_public_key/0,
    falcon1024_message/0,
    falcon1024_signature/0,
    falcon1024_verification/0
]).

-type sphincs_plus_haraka_128f_robust_secret_key() :: <<_:512>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-haraka-128f-robust Signature Algorithm (64-bytes).
-type sphincs_plus_haraka_128f_robust_public_key() :: <<_:256>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-haraka-128f-robust Signature Algorithm (32-bytes).
-type sphincs_plus_haraka_128f_robust_seed() :: <<_:384>>.
%%% Binary representation of a `Seed' for the SPHINCS+-haraka-128f-robust Signature Algorithm (48-bytes).
-type sphincs_plus_haraka_128f_robust_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-haraka-128f-robust Signature Algorithm.
-type sphincs_plus_haraka_128f_robust_signature() :: <<_:136704>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-haraka-128f-robust Signature Algorithm (maximum of 17,088-bytes).
-type sphincs_plus_haraka_128f_robust_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-haraka-128f-robust Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_haraka_128f_robust_secret_key/0,
    sphincs_plus_haraka_128f_robust_public_key/0,
    sphincs_plus_haraka_128f_robust_seed/0,
    sphincs_plus_haraka_128f_robust_message/0,
    sphincs_plus_haraka_128f_robust_signature/0,
    sphincs_plus_haraka_128f_robust_verification/0
]).

-type sphincs_plus_haraka_128f_simple_secret_key() :: <<_:512>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-haraka-128f-simple Signature Algorithm (64-bytes).
-type sphincs_plus_haraka_128f_simple_public_key() :: <<_:256>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-haraka-128f-simple Signature Algorithm (32-bytes).
-type sphincs_plus_haraka_128f_simple_seed() :: <<_:384>>.
%%% Binary representation of a `Seed' for the SPHINCS+-haraka-128f-simple Signature Algorithm (48-bytes).
-type sphincs_plus_haraka_128f_simple_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-haraka-128f-simple Signature Algorithm.
-type sphincs_plus_haraka_128f_simple_signature() :: <<_:136704>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-haraka-128f-simple Signature Algorithm (maximum of 17,088-bytes).
-type sphincs_plus_haraka_128f_simple_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-haraka-128f-simple Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_haraka_128f_simple_secret_key/0,
    sphincs_plus_haraka_128f_simple_public_key/0,
    sphincs_plus_haraka_128f_simple_seed/0,
    sphincs_plus_haraka_128f_simple_message/0,
    sphincs_plus_haraka_128f_simple_signature/0,
    sphincs_plus_haraka_128f_simple_verification/0
]).

-type sphincs_plus_haraka_128s_robust_secret_key() :: <<_:512>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-haraka-128s-robust Signature Algorithm (64-bytes).
-type sphincs_plus_haraka_128s_robust_public_key() :: <<_:256>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-haraka-128s-robust Signature Algorithm (32-bytes).
-type sphincs_plus_haraka_128s_robust_seed() :: <<_:384>>.
%%% Binary representation of a `Seed' for the SPHINCS+-haraka-128s-robust Signature Algorithm (48-bytes).
-type sphincs_plus_haraka_128s_robust_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-haraka-128s-robust Signature Algorithm.
-type sphincs_plus_haraka_128s_robust_signature() :: <<_:62848>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-haraka-128s-robust Signature Algorithm (maximum of 7,856-bytes).
-type sphincs_plus_haraka_128s_robust_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-haraka-128s-robust Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_haraka_128s_robust_secret_key/0,
    sphincs_plus_haraka_128s_robust_public_key/0,
    sphincs_plus_haraka_128s_robust_seed/0,
    sphincs_plus_haraka_128s_robust_message/0,
    sphincs_plus_haraka_128s_robust_signature/0,
    sphincs_plus_haraka_128s_robust_verification/0
]).

-type sphincs_plus_haraka_128s_simple_secret_key() :: <<_:512>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-haraka-128s-simple Signature Algorithm (64-bytes).
-type sphincs_plus_haraka_128s_simple_public_key() :: <<_:256>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-haraka-128s-simple Signature Algorithm (32-bytes).
-type sphincs_plus_haraka_128s_simple_seed() :: <<_:384>>.
%%% Binary representation of a `Seed' for the SPHINCS+-haraka-128s-simple Signature Algorithm (48-bytes).
-type sphincs_plus_haraka_128s_simple_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-haraka-128s-simple Signature Algorithm.
-type sphincs_plus_haraka_128s_simple_signature() :: <<_:62848>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-haraka-128s-simple Signature Algorithm (maximum of 7,856-bytes).
-type sphincs_plus_haraka_128s_simple_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-haraka-128s-simple Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_haraka_128s_simple_secret_key/0,
    sphincs_plus_haraka_128s_simple_public_key/0,
    sphincs_plus_haraka_128s_simple_seed/0,
    sphincs_plus_haraka_128s_simple_message/0,
    sphincs_plus_haraka_128s_simple_signature/0,
    sphincs_plus_haraka_128s_simple_verification/0
]).

-type sphincs_plus_haraka_192f_robust_secret_key() :: <<_:768>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-haraka-192f-robust Signature Algorithm (96-bytes).
-type sphincs_plus_haraka_192f_robust_public_key() :: <<_:384>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-haraka-192f-robust Signature Algorithm (48-bytes).
-type sphincs_plus_haraka_192f_robust_seed() :: <<_:576>>.
%%% Binary representation of a `Seed' for the SPHINCS+-haraka-192f-robust Signature Algorithm (72-bytes).
-type sphincs_plus_haraka_192f_robust_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-haraka-192f-robust Signature Algorithm.
-type sphincs_plus_haraka_192f_robust_signature() :: <<_:285312>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-haraka-192f-robust Signature Algorithm (maximum of 35,664-bytes).
-type sphincs_plus_haraka_192f_robust_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-haraka-192f-robust Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_haraka_192f_robust_secret_key/0,
    sphincs_plus_haraka_192f_robust_public_key/0,
    sphincs_plus_haraka_192f_robust_seed/0,
    sphincs_plus_haraka_192f_robust_message/0,
    sphincs_plus_haraka_192f_robust_signature/0,
    sphincs_plus_haraka_192f_robust_verification/0
]).

-type sphincs_plus_haraka_192f_simple_secret_key() :: <<_:768>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-haraka-192f-simple Signature Algorithm (96-bytes).
-type sphincs_plus_haraka_192f_simple_public_key() :: <<_:384>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-haraka-192f-simple Signature Algorithm (48-bytes).
-type sphincs_plus_haraka_192f_simple_seed() :: <<_:576>>.
%%% Binary representation of a `Seed' for the SPHINCS+-haraka-192f-simple Signature Algorithm (72-bytes).
-type sphincs_plus_haraka_192f_simple_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-haraka-192f-simple Signature Algorithm.
-type sphincs_plus_haraka_192f_simple_signature() :: <<_:285312>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-haraka-192f-simple Signature Algorithm (maximum of 35,664-bytes).
-type sphincs_plus_haraka_192f_simple_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-haraka-192f-simple Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_haraka_192f_simple_secret_key/0,
    sphincs_plus_haraka_192f_simple_public_key/0,
    sphincs_plus_haraka_192f_simple_seed/0,
    sphincs_plus_haraka_192f_simple_message/0,
    sphincs_plus_haraka_192f_simple_signature/0,
    sphincs_plus_haraka_192f_simple_verification/0
]).

-type sphincs_plus_haraka_192s_robust_secret_key() :: <<_:768>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-haraka-192s-robust Signature Algorithm (96-bytes).
-type sphincs_plus_haraka_192s_robust_public_key() :: <<_:384>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-haraka-192s-robust Signature Algorithm (48-bytes).
-type sphincs_plus_haraka_192s_robust_seed() :: <<_:576>>.
%%% Binary representation of a `Seed' for the SPHINCS+-haraka-192s-robust Signature Algorithm (72-bytes).
-type sphincs_plus_haraka_192s_robust_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-haraka-192s-robust Signature Algorithm.
-type sphincs_plus_haraka_192s_robust_signature() :: <<_:129792>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-haraka-192s-robust Signature Algorithm (maximum of 16,224-bytes).
-type sphincs_plus_haraka_192s_robust_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-haraka-192s-robust Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_haraka_192s_robust_secret_key/0,
    sphincs_plus_haraka_192s_robust_public_key/0,
    sphincs_plus_haraka_192s_robust_seed/0,
    sphincs_plus_haraka_192s_robust_message/0,
    sphincs_plus_haraka_192s_robust_signature/0,
    sphincs_plus_haraka_192s_robust_verification/0
]).

-type sphincs_plus_haraka_192s_simple_secret_key() :: <<_:768>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-haraka-192s-simple Signature Algorithm (96-bytes).
-type sphincs_plus_haraka_192s_simple_public_key() :: <<_:384>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-haraka-192s-simple Signature Algorithm (48-bytes).
-type sphincs_plus_haraka_192s_simple_seed() :: <<_:576>>.
%%% Binary representation of a `Seed' for the SPHINCS+-haraka-192s-simple Signature Algorithm (72-bytes).
-type sphincs_plus_haraka_192s_simple_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-haraka-192s-simple Signature Algorithm.
-type sphincs_plus_haraka_192s_simple_signature() :: <<_:129792>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-haraka-192s-simple Signature Algorithm (maximum of 16,224-bytes).
-type sphincs_plus_haraka_192s_simple_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-haraka-192s-simple Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_haraka_192s_simple_secret_key/0,
    sphincs_plus_haraka_192s_simple_public_key/0,
    sphincs_plus_haraka_192s_simple_seed/0,
    sphincs_plus_haraka_192s_simple_message/0,
    sphincs_plus_haraka_192s_simple_signature/0,
    sphincs_plus_haraka_192s_simple_verification/0
]).

-type sphincs_plus_haraka_256f_robust_secret_key() :: <<_:1024>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-haraka-256f-robust Signature Algorithm (128-bytes).
-type sphincs_plus_haraka_256f_robust_public_key() :: <<_:512>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-haraka-256f-robust Signature Algorithm (64-bytes).
-type sphincs_plus_haraka_256f_robust_seed() :: <<_:768>>.
%%% Binary representation of a `Seed' for the SPHINCS+-haraka-256f-robust Signature Algorithm (96-bytes).
-type sphincs_plus_haraka_256f_robust_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-haraka-256f-robust Signature Algorithm.
-type sphincs_plus_haraka_256f_robust_signature() :: <<_:398848>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-haraka-256f-robust Signature Algorithm (maximum of 49,856-bytes).
-type sphincs_plus_haraka_256f_robust_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-haraka-256f-robust Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_haraka_256f_robust_secret_key/0,
    sphincs_plus_haraka_256f_robust_public_key/0,
    sphincs_plus_haraka_256f_robust_seed/0,
    sphincs_plus_haraka_256f_robust_message/0,
    sphincs_plus_haraka_256f_robust_signature/0,
    sphincs_plus_haraka_256f_robust_verification/0
]).

-type sphincs_plus_haraka_256f_simple_secret_key() :: <<_:1024>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-haraka-256f-simple Signature Algorithm (128-bytes).
-type sphincs_plus_haraka_256f_simple_public_key() :: <<_:512>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-haraka-256f-simple Signature Algorithm (64-bytes).
-type sphincs_plus_haraka_256f_simple_seed() :: <<_:768>>.
%%% Binary representation of a `Seed' for the SPHINCS+-haraka-256f-simple Signature Algorithm (96-bytes).
-type sphincs_plus_haraka_256f_simple_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-haraka-256f-simple Signature Algorithm.
-type sphincs_plus_haraka_256f_simple_signature() :: <<_:398848>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-haraka-256f-simple Signature Algorithm (maximum of 49,856-bytes).
-type sphincs_plus_haraka_256f_simple_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-haraka-256f-simple Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_haraka_256f_simple_secret_key/0,
    sphincs_plus_haraka_256f_simple_public_key/0,
    sphincs_plus_haraka_256f_simple_seed/0,
    sphincs_plus_haraka_256f_simple_message/0,
    sphincs_plus_haraka_256f_simple_signature/0,
    sphincs_plus_haraka_256f_simple_verification/0
]).

-type sphincs_plus_haraka_256s_robust_secret_key() :: <<_:1024>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-haraka-256s-robust Signature Algorithm (128-bytes).
-type sphincs_plus_haraka_256s_robust_public_key() :: <<_:512>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-haraka-256s-robust Signature Algorithm (64-bytes).
-type sphincs_plus_haraka_256s_robust_seed() :: <<_:768>>.
%%% Binary representation of a `Seed' for the SPHINCS+-haraka-256s-robust Signature Algorithm (96-bytes).
-type sphincs_plus_haraka_256s_robust_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-haraka-256s-robust Signature Algorithm.
-type sphincs_plus_haraka_256s_robust_signature() :: <<_:238336>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-haraka-256s-robust Signature Algorithm (maximum of 29,792-bytes).
-type sphincs_plus_haraka_256s_robust_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-haraka-256s-robust Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_haraka_256s_robust_secret_key/0,
    sphincs_plus_haraka_256s_robust_public_key/0,
    sphincs_plus_haraka_256s_robust_seed/0,
    sphincs_plus_haraka_256s_robust_message/0,
    sphincs_plus_haraka_256s_robust_signature/0,
    sphincs_plus_haraka_256s_robust_verification/0
]).

-type sphincs_plus_haraka_256s_simple_secret_key() :: <<_:1024>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-haraka-256s-simple Signature Algorithm (128-bytes).
-type sphincs_plus_haraka_256s_simple_public_key() :: <<_:512>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-haraka-256s-simple Signature Algorithm (64-bytes).
-type sphincs_plus_haraka_256s_simple_seed() :: <<_:768>>.
%%% Binary representation of a `Seed' for the SPHINCS+-haraka-256s-simple Signature Algorithm (96-bytes).
-type sphincs_plus_haraka_256s_simple_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-haraka-256s-simple Signature Algorithm.
-type sphincs_plus_haraka_256s_simple_signature() :: <<_:238336>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-haraka-256s-simple Signature Algorithm (maximum of 29,792-bytes).
-type sphincs_plus_haraka_256s_simple_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-haraka-256s-simple Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_haraka_256s_simple_secret_key/0,
    sphincs_plus_haraka_256s_simple_public_key/0,
    sphincs_plus_haraka_256s_simple_seed/0,
    sphincs_plus_haraka_256s_simple_message/0,
    sphincs_plus_haraka_256s_simple_signature/0,
    sphincs_plus_haraka_256s_simple_verification/0
]).

-type sphincs_plus_sha2_128f_robust_secret_key() :: <<_:512>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-sha2-128f-robust Signature Algorithm (64-bytes).
-type sphincs_plus_sha2_128f_robust_public_key() :: <<_:256>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-sha2-128f-robust Signature Algorithm (32-bytes).
-type sphincs_plus_sha2_128f_robust_seed() :: <<_:384>>.
%%% Binary representation of a `Seed' for the SPHINCS+-sha2-128f-robust Signature Algorithm (48-bytes).
-type sphincs_plus_sha2_128f_robust_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-sha2-128f-robust Signature Algorithm.
-type sphincs_plus_sha2_128f_robust_signature() :: <<_:136704>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-sha2-128f-robust Signature Algorithm (maximum of 17,088-bytes).
-type sphincs_plus_sha2_128f_robust_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-sha2-128f-robust Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_sha2_128f_robust_secret_key/0,
    sphincs_plus_sha2_128f_robust_public_key/0,
    sphincs_plus_sha2_128f_robust_seed/0,
    sphincs_plus_sha2_128f_robust_message/0,
    sphincs_plus_sha2_128f_robust_signature/0,
    sphincs_plus_sha2_128f_robust_verification/0
]).

-type sphincs_plus_sha2_128f_simple_secret_key() :: <<_:512>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-sha2-128f-simple Signature Algorithm (64-bytes).
-type sphincs_plus_sha2_128f_simple_public_key() :: <<_:256>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-sha2-128f-simple Signature Algorithm (32-bytes).
-type sphincs_plus_sha2_128f_simple_seed() :: <<_:384>>.
%%% Binary representation of a `Seed' for the SPHINCS+-sha2-128f-simple Signature Algorithm (48-bytes).
-type sphincs_plus_sha2_128f_simple_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-sha2-128f-simple Signature Algorithm.
-type sphincs_plus_sha2_128f_simple_signature() :: <<_:136704>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-sha2-128f-simple Signature Algorithm (maximum of 17,088-bytes).
-type sphincs_plus_sha2_128f_simple_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-sha2-128f-simple Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_sha2_128f_simple_secret_key/0,
    sphincs_plus_sha2_128f_simple_public_key/0,
    sphincs_plus_sha2_128f_simple_seed/0,
    sphincs_plus_sha2_128f_simple_message/0,
    sphincs_plus_sha2_128f_simple_signature/0,
    sphincs_plus_sha2_128f_simple_verification/0
]).

-type sphincs_plus_sha2_128s_robust_secret_key() :: <<_:512>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-sha2-128s-robust Signature Algorithm (64-bytes).
-type sphincs_plus_sha2_128s_robust_public_key() :: <<_:256>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-sha2-128s-robust Signature Algorithm (32-bytes).
-type sphincs_plus_sha2_128s_robust_seed() :: <<_:384>>.
%%% Binary representation of a `Seed' for the SPHINCS+-sha2-128s-robust Signature Algorithm (48-bytes).
-type sphincs_plus_sha2_128s_robust_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-sha2-128s-robust Signature Algorithm.
-type sphincs_plus_sha2_128s_robust_signature() :: <<_:62848>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-sha2-128s-robust Signature Algorithm (maximum of 7,856-bytes).
-type sphincs_plus_sha2_128s_robust_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-sha2-128s-robust Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_sha2_128s_robust_secret_key/0,
    sphincs_plus_sha2_128s_robust_public_key/0,
    sphincs_plus_sha2_128s_robust_seed/0,
    sphincs_plus_sha2_128s_robust_message/0,
    sphincs_plus_sha2_128s_robust_signature/0,
    sphincs_plus_sha2_128s_robust_verification/0
]).

-type sphincs_plus_sha2_128s_simple_secret_key() :: <<_:512>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-sha2-128s-simple Signature Algorithm (64-bytes).
-type sphincs_plus_sha2_128s_simple_public_key() :: <<_:256>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-sha2-128s-simple Signature Algorithm (32-bytes).
-type sphincs_plus_sha2_128s_simple_seed() :: <<_:384>>.
%%% Binary representation of a `Seed' for the SPHINCS+-sha2-128s-simple Signature Algorithm (48-bytes).
-type sphincs_plus_sha2_128s_simple_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-sha2-128s-simple Signature Algorithm.
-type sphincs_plus_sha2_128s_simple_signature() :: <<_:62848>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-sha2-128s-simple Signature Algorithm (maximum of 7,856-bytes).
-type sphincs_plus_sha2_128s_simple_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-sha2-128s-simple Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_sha2_128s_simple_secret_key/0,
    sphincs_plus_sha2_128s_simple_public_key/0,
    sphincs_plus_sha2_128s_simple_seed/0,
    sphincs_plus_sha2_128s_simple_message/0,
    sphincs_plus_sha2_128s_simple_signature/0,
    sphincs_plus_sha2_128s_simple_verification/0
]).

-type sphincs_plus_sha2_192f_robust_secret_key() :: <<_:768>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-sha2-192f-robust Signature Algorithm (96-bytes).
-type sphincs_plus_sha2_192f_robust_public_key() :: <<_:384>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-sha2-192f-robust Signature Algorithm (48-bytes).
-type sphincs_plus_sha2_192f_robust_seed() :: <<_:576>>.
%%% Binary representation of a `Seed' for the SPHINCS+-sha2-192f-robust Signature Algorithm (72-bytes).
-type sphincs_plus_sha2_192f_robust_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-sha2-192f-robust Signature Algorithm.
-type sphincs_plus_sha2_192f_robust_signature() :: <<_:285312>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-sha2-192f-robust Signature Algorithm (maximum of 35,664-bytes).
-type sphincs_plus_sha2_192f_robust_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-sha2-192f-robust Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_sha2_192f_robust_secret_key/0,
    sphincs_plus_sha2_192f_robust_public_key/0,
    sphincs_plus_sha2_192f_robust_seed/0,
    sphincs_plus_sha2_192f_robust_message/0,
    sphincs_plus_sha2_192f_robust_signature/0,
    sphincs_plus_sha2_192f_robust_verification/0
]).

-type sphincs_plus_sha2_192f_simple_secret_key() :: <<_:768>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-sha2-192f-simple Signature Algorithm (96-bytes).
-type sphincs_plus_sha2_192f_simple_public_key() :: <<_:384>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-sha2-192f-simple Signature Algorithm (48-bytes).
-type sphincs_plus_sha2_192f_simple_seed() :: <<_:576>>.
%%% Binary representation of a `Seed' for the SPHINCS+-sha2-192f-simple Signature Algorithm (72-bytes).
-type sphincs_plus_sha2_192f_simple_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-sha2-192f-simple Signature Algorithm.
-type sphincs_plus_sha2_192f_simple_signature() :: <<_:285312>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-sha2-192f-simple Signature Algorithm (maximum of 35,664-bytes).
-type sphincs_plus_sha2_192f_simple_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-sha2-192f-simple Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_sha2_192f_simple_secret_key/0,
    sphincs_plus_sha2_192f_simple_public_key/0,
    sphincs_plus_sha2_192f_simple_seed/0,
    sphincs_plus_sha2_192f_simple_message/0,
    sphincs_plus_sha2_192f_simple_signature/0,
    sphincs_plus_sha2_192f_simple_verification/0
]).

-type sphincs_plus_sha2_192s_robust_secret_key() :: <<_:768>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-sha2-192s-robust Signature Algorithm (96-bytes).
-type sphincs_plus_sha2_192s_robust_public_key() :: <<_:384>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-sha2-192s-robust Signature Algorithm (48-bytes).
-type sphincs_plus_sha2_192s_robust_seed() :: <<_:576>>.
%%% Binary representation of a `Seed' for the SPHINCS+-sha2-192s-robust Signature Algorithm (72-bytes).
-type sphincs_plus_sha2_192s_robust_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-sha2-192s-robust Signature Algorithm.
-type sphincs_plus_sha2_192s_robust_signature() :: <<_:129792>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-sha2-192s-robust Signature Algorithm (maximum of 16,224-bytes).
-type sphincs_plus_sha2_192s_robust_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-sha2-192s-robust Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_sha2_192s_robust_secret_key/0,
    sphincs_plus_sha2_192s_robust_public_key/0,
    sphincs_plus_sha2_192s_robust_seed/0,
    sphincs_plus_sha2_192s_robust_message/0,
    sphincs_plus_sha2_192s_robust_signature/0,
    sphincs_plus_sha2_192s_robust_verification/0
]).

-type sphincs_plus_sha2_192s_simple_secret_key() :: <<_:768>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-sha2-192s-simple Signature Algorithm (96-bytes).
-type sphincs_plus_sha2_192s_simple_public_key() :: <<_:384>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-sha2-192s-simple Signature Algorithm (48-bytes).
-type sphincs_plus_sha2_192s_simple_seed() :: <<_:576>>.
%%% Binary representation of a `Seed' for the SPHINCS+-sha2-192s-simple Signature Algorithm (72-bytes).
-type sphincs_plus_sha2_192s_simple_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-sha2-192s-simple Signature Algorithm.
-type sphincs_plus_sha2_192s_simple_signature() :: <<_:129792>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-sha2-192s-simple Signature Algorithm (maximum of 16,224-bytes).
-type sphincs_plus_sha2_192s_simple_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-sha2-192s-simple Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_sha2_192s_simple_secret_key/0,
    sphincs_plus_sha2_192s_simple_public_key/0,
    sphincs_plus_sha2_192s_simple_seed/0,
    sphincs_plus_sha2_192s_simple_message/0,
    sphincs_plus_sha2_192s_simple_signature/0,
    sphincs_plus_sha2_192s_simple_verification/0
]).

-type sphincs_plus_sha2_256f_robust_secret_key() :: <<_:1024>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-sha2-256f-robust Signature Algorithm (128-bytes).
-type sphincs_plus_sha2_256f_robust_public_key() :: <<_:512>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-sha2-256f-robust Signature Algorithm (64-bytes).
-type sphincs_plus_sha2_256f_robust_seed() :: <<_:768>>.
%%% Binary representation of a `Seed' for the SPHINCS+-sha2-256f-robust Signature Algorithm (96-bytes).
-type sphincs_plus_sha2_256f_robust_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-sha2-256f-robust Signature Algorithm.
-type sphincs_plus_sha2_256f_robust_signature() :: <<_:398848>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-sha2-256f-robust Signature Algorithm (maximum of 49,856-bytes).
-type sphincs_plus_sha2_256f_robust_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-sha2-256f-robust Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_sha2_256f_robust_secret_key/0,
    sphincs_plus_sha2_256f_robust_public_key/0,
    sphincs_plus_sha2_256f_robust_seed/0,
    sphincs_plus_sha2_256f_robust_message/0,
    sphincs_plus_sha2_256f_robust_signature/0,
    sphincs_plus_sha2_256f_robust_verification/0
]).

-type sphincs_plus_sha2_256f_simple_secret_key() :: <<_:1024>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-sha2-256f-simple Signature Algorithm (128-bytes).
-type sphincs_plus_sha2_256f_simple_public_key() :: <<_:512>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-sha2-256f-simple Signature Algorithm (64-bytes).
-type sphincs_plus_sha2_256f_simple_seed() :: <<_:768>>.
%%% Binary representation of a `Seed' for the SPHINCS+-sha2-256f-simple Signature Algorithm (96-bytes).
-type sphincs_plus_sha2_256f_simple_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-sha2-256f-simple Signature Algorithm.
-type sphincs_plus_sha2_256f_simple_signature() :: <<_:398848>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-sha2-256f-simple Signature Algorithm (maximum of 49,856-bytes).
-type sphincs_plus_sha2_256f_simple_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-sha2-256f-simple Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_sha2_256f_simple_secret_key/0,
    sphincs_plus_sha2_256f_simple_public_key/0,
    sphincs_plus_sha2_256f_simple_seed/0,
    sphincs_plus_sha2_256f_simple_message/0,
    sphincs_plus_sha2_256f_simple_signature/0,
    sphincs_plus_sha2_256f_simple_verification/0
]).

-type sphincs_plus_sha2_256s_robust_secret_key() :: <<_:1024>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-sha2-256s-robust Signature Algorithm (128-bytes).
-type sphincs_plus_sha2_256s_robust_public_key() :: <<_:512>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-sha2-256s-robust Signature Algorithm (64-bytes).
-type sphincs_plus_sha2_256s_robust_seed() :: <<_:768>>.
%%% Binary representation of a `Seed' for the SPHINCS+-sha2-256s-robust Signature Algorithm (96-bytes).
-type sphincs_plus_sha2_256s_robust_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-sha2-256s-robust Signature Algorithm.
-type sphincs_plus_sha2_256s_robust_signature() :: <<_:238336>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-sha2-256s-robust Signature Algorithm (maximum of 29,792-bytes).
-type sphincs_plus_sha2_256s_robust_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-sha2-256s-robust Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_sha2_256s_robust_secret_key/0,
    sphincs_plus_sha2_256s_robust_public_key/0,
    sphincs_plus_sha2_256s_robust_seed/0,
    sphincs_plus_sha2_256s_robust_message/0,
    sphincs_plus_sha2_256s_robust_signature/0,
    sphincs_plus_sha2_256s_robust_verification/0
]).

-type sphincs_plus_sha2_256s_simple_secret_key() :: <<_:1024>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-sha2-256s-simple Signature Algorithm (128-bytes).
-type sphincs_plus_sha2_256s_simple_public_key() :: <<_:512>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-sha2-256s-simple Signature Algorithm (64-bytes).
-type sphincs_plus_sha2_256s_simple_seed() :: <<_:768>>.
%%% Binary representation of a `Seed' for the SPHINCS+-sha2-256s-simple Signature Algorithm (96-bytes).
-type sphincs_plus_sha2_256s_simple_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-sha2-256s-simple Signature Algorithm.
-type sphincs_plus_sha2_256s_simple_signature() :: <<_:238336>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-sha2-256s-simple Signature Algorithm (maximum of 29,792-bytes).
-type sphincs_plus_sha2_256s_simple_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-sha2-256s-simple Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_sha2_256s_simple_secret_key/0,
    sphincs_plus_sha2_256s_simple_public_key/0,
    sphincs_plus_sha2_256s_simple_seed/0,
    sphincs_plus_sha2_256s_simple_message/0,
    sphincs_plus_sha2_256s_simple_signature/0,
    sphincs_plus_sha2_256s_simple_verification/0
]).

-type sphincs_plus_shake_128f_robust_secret_key() :: <<_:512>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-shake-128f-robust Signature Algorithm (64-bytes).
-type sphincs_plus_shake_128f_robust_public_key() :: <<_:256>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-shake-128f-robust Signature Algorithm (32-bytes).
-type sphincs_plus_shake_128f_robust_seed() :: <<_:384>>.
%%% Binary representation of a `Seed' for the SPHINCS+-shake-128f-robust Signature Algorithm (48-bytes).
-type sphincs_plus_shake_128f_robust_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-shake-128f-robust Signature Algorithm.
-type sphincs_plus_shake_128f_robust_signature() :: <<_:136704>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-shake-128f-robust Signature Algorithm (maximum of 17,088-bytes).
-type sphincs_plus_shake_128f_robust_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-shake-128f-robust Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_shake_128f_robust_secret_key/0,
    sphincs_plus_shake_128f_robust_public_key/0,
    sphincs_plus_shake_128f_robust_seed/0,
    sphincs_plus_shake_128f_robust_message/0,
    sphincs_plus_shake_128f_robust_signature/0,
    sphincs_plus_shake_128f_robust_verification/0
]).

-type sphincs_plus_shake_128f_simple_secret_key() :: <<_:512>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-shake-128f-simple Signature Algorithm (64-bytes).
-type sphincs_plus_shake_128f_simple_public_key() :: <<_:256>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-shake-128f-simple Signature Algorithm (32-bytes).
-type sphincs_plus_shake_128f_simple_seed() :: <<_:384>>.
%%% Binary representation of a `Seed' for the SPHINCS+-shake-128f-simple Signature Algorithm (48-bytes).
-type sphincs_plus_shake_128f_simple_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-shake-128f-simple Signature Algorithm.
-type sphincs_plus_shake_128f_simple_signature() :: <<_:136704>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-shake-128f-simple Signature Algorithm (maximum of 17,088-bytes).
-type sphincs_plus_shake_128f_simple_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-shake-128f-simple Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_shake_128f_simple_secret_key/0,
    sphincs_plus_shake_128f_simple_public_key/0,
    sphincs_plus_shake_128f_simple_seed/0,
    sphincs_plus_shake_128f_simple_message/0,
    sphincs_plus_shake_128f_simple_signature/0,
    sphincs_plus_shake_128f_simple_verification/0
]).

-type sphincs_plus_shake_128s_robust_secret_key() :: <<_:512>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-shake-128s-robust Signature Algorithm (64-bytes).
-type sphincs_plus_shake_128s_robust_public_key() :: <<_:256>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-shake-128s-robust Signature Algorithm (32-bytes).
-type sphincs_plus_shake_128s_robust_seed() :: <<_:384>>.
%%% Binary representation of a `Seed' for the SPHINCS+-shake-128s-robust Signature Algorithm (48-bytes).
-type sphincs_plus_shake_128s_robust_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-shake-128s-robust Signature Algorithm.
-type sphincs_plus_shake_128s_robust_signature() :: <<_:62848>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-shake-128s-robust Signature Algorithm (maximum of 7,856-bytes).
-type sphincs_plus_shake_128s_robust_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-shake-128s-robust Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_shake_128s_robust_secret_key/0,
    sphincs_plus_shake_128s_robust_public_key/0,
    sphincs_plus_shake_128s_robust_seed/0,
    sphincs_plus_shake_128s_robust_message/0,
    sphincs_plus_shake_128s_robust_signature/0,
    sphincs_plus_shake_128s_robust_verification/0
]).

-type sphincs_plus_shake_128s_simple_secret_key() :: <<_:512>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-shake-128s-simple Signature Algorithm (64-bytes).
-type sphincs_plus_shake_128s_simple_public_key() :: <<_:256>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-shake-128s-simple Signature Algorithm (32-bytes).
-type sphincs_plus_shake_128s_simple_seed() :: <<_:384>>.
%%% Binary representation of a `Seed' for the SPHINCS+-shake-128s-simple Signature Algorithm (48-bytes).
-type sphincs_plus_shake_128s_simple_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-shake-128s-simple Signature Algorithm.
-type sphincs_plus_shake_128s_simple_signature() :: <<_:62848>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-shake-128s-simple Signature Algorithm (maximum of 7,856-bytes).
-type sphincs_plus_shake_128s_simple_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-shake-128s-simple Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_shake_128s_simple_secret_key/0,
    sphincs_plus_shake_128s_simple_public_key/0,
    sphincs_plus_shake_128s_simple_seed/0,
    sphincs_plus_shake_128s_simple_message/0,
    sphincs_plus_shake_128s_simple_signature/0,
    sphincs_plus_shake_128s_simple_verification/0
]).

-type sphincs_plus_shake_192f_robust_secret_key() :: <<_:768>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-shake-192f-robust Signature Algorithm (96-bytes).
-type sphincs_plus_shake_192f_robust_public_key() :: <<_:384>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-shake-192f-robust Signature Algorithm (48-bytes).
-type sphincs_plus_shake_192f_robust_seed() :: <<_:576>>.
%%% Binary representation of a `Seed' for the SPHINCS+-shake-192f-robust Signature Algorithm (72-bytes).
-type sphincs_plus_shake_192f_robust_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-shake-192f-robust Signature Algorithm.
-type sphincs_plus_shake_192f_robust_signature() :: <<_:285312>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-shake-192f-robust Signature Algorithm (maximum of 35,664-bytes).
-type sphincs_plus_shake_192f_robust_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-shake-192f-robust Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_shake_192f_robust_secret_key/0,
    sphincs_plus_shake_192f_robust_public_key/0,
    sphincs_plus_shake_192f_robust_seed/0,
    sphincs_plus_shake_192f_robust_message/0,
    sphincs_plus_shake_192f_robust_signature/0,
    sphincs_plus_shake_192f_robust_verification/0
]).

-type sphincs_plus_shake_192f_simple_secret_key() :: <<_:768>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-shake-192f-simple Signature Algorithm (96-bytes).
-type sphincs_plus_shake_192f_simple_public_key() :: <<_:384>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-shake-192f-simple Signature Algorithm (48-bytes).
-type sphincs_plus_shake_192f_simple_seed() :: <<_:576>>.
%%% Binary representation of a `Seed' for the SPHINCS+-shake-192f-simple Signature Algorithm (72-bytes).
-type sphincs_plus_shake_192f_simple_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-shake-192f-simple Signature Algorithm.
-type sphincs_plus_shake_192f_simple_signature() :: <<_:285312>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-shake-192f-simple Signature Algorithm (maximum of 35,664-bytes).
-type sphincs_plus_shake_192f_simple_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-shake-192f-simple Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_shake_192f_simple_secret_key/0,
    sphincs_plus_shake_192f_simple_public_key/0,
    sphincs_plus_shake_192f_simple_seed/0,
    sphincs_plus_shake_192f_simple_message/0,
    sphincs_plus_shake_192f_simple_signature/0,
    sphincs_plus_shake_192f_simple_verification/0
]).

-type sphincs_plus_shake_192s_robust_secret_key() :: <<_:768>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-shake-192s-robust Signature Algorithm (96-bytes).
-type sphincs_plus_shake_192s_robust_public_key() :: <<_:384>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-shake-192s-robust Signature Algorithm (48-bytes).
-type sphincs_plus_shake_192s_robust_seed() :: <<_:576>>.
%%% Binary representation of a `Seed' for the SPHINCS+-shake-192s-robust Signature Algorithm (72-bytes).
-type sphincs_plus_shake_192s_robust_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-shake-192s-robust Signature Algorithm.
-type sphincs_plus_shake_192s_robust_signature() :: <<_:129792>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-shake-192s-robust Signature Algorithm (maximum of 16,224-bytes).
-type sphincs_plus_shake_192s_robust_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-shake-192s-robust Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_shake_192s_robust_secret_key/0,
    sphincs_plus_shake_192s_robust_public_key/0,
    sphincs_plus_shake_192s_robust_seed/0,
    sphincs_plus_shake_192s_robust_message/0,
    sphincs_plus_shake_192s_robust_signature/0,
    sphincs_plus_shake_192s_robust_verification/0
]).

-type sphincs_plus_shake_192s_simple_secret_key() :: <<_:768>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-shake-192s-simple Signature Algorithm (96-bytes).
-type sphincs_plus_shake_192s_simple_public_key() :: <<_:384>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-shake-192s-simple Signature Algorithm (48-bytes).
-type sphincs_plus_shake_192s_simple_seed() :: <<_:576>>.
%%% Binary representation of a `Seed' for the SPHINCS+-shake-192s-simple Signature Algorithm (72-bytes).
-type sphincs_plus_shake_192s_simple_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-shake-192s-simple Signature Algorithm.
-type sphincs_plus_shake_192s_simple_signature() :: <<_:129792>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-shake-192s-simple Signature Algorithm (maximum of 16,224-bytes).
-type sphincs_plus_shake_192s_simple_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-shake-192s-simple Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_shake_192s_simple_secret_key/0,
    sphincs_plus_shake_192s_simple_public_key/0,
    sphincs_plus_shake_192s_simple_seed/0,
    sphincs_plus_shake_192s_simple_message/0,
    sphincs_plus_shake_192s_simple_signature/0,
    sphincs_plus_shake_192s_simple_verification/0
]).

-type sphincs_plus_shake_256f_robust_secret_key() :: <<_:1024>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-shake-256f-robust Signature Algorithm (128-bytes).
-type sphincs_plus_shake_256f_robust_public_key() :: <<_:512>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-shake-256f-robust Signature Algorithm (64-bytes).
-type sphincs_plus_shake_256f_robust_seed() :: <<_:768>>.
%%% Binary representation of a `Seed' for the SPHINCS+-shake-256f-robust Signature Algorithm (96-bytes).
-type sphincs_plus_shake_256f_robust_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-shake-256f-robust Signature Algorithm.
-type sphincs_plus_shake_256f_robust_signature() :: <<_:398848>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-shake-256f-robust Signature Algorithm (maximum of 49,856-bytes).
-type sphincs_plus_shake_256f_robust_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-shake-256f-robust Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_shake_256f_robust_secret_key/0,
    sphincs_plus_shake_256f_robust_public_key/0,
    sphincs_plus_shake_256f_robust_seed/0,
    sphincs_plus_shake_256f_robust_message/0,
    sphincs_plus_shake_256f_robust_signature/0,
    sphincs_plus_shake_256f_robust_verification/0
]).

-type sphincs_plus_shake_256f_simple_secret_key() :: <<_:1024>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-shake-256f-simple Signature Algorithm (128-bytes).
-type sphincs_plus_shake_256f_simple_public_key() :: <<_:512>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-shake-256f-simple Signature Algorithm (64-bytes).
-type sphincs_plus_shake_256f_simple_seed() :: <<_:768>>.
%%% Binary representation of a `Seed' for the SPHINCS+-shake-256f-simple Signature Algorithm (96-bytes).
-type sphincs_plus_shake_256f_simple_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-shake-256f-simple Signature Algorithm.
-type sphincs_plus_shake_256f_simple_signature() :: <<_:398848>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-shake-256f-simple Signature Algorithm (maximum of 49,856-bytes).
-type sphincs_plus_shake_256f_simple_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-shake-256f-simple Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_shake_256f_simple_secret_key/0,
    sphincs_plus_shake_256f_simple_public_key/0,
    sphincs_plus_shake_256f_simple_seed/0,
    sphincs_plus_shake_256f_simple_message/0,
    sphincs_plus_shake_256f_simple_signature/0,
    sphincs_plus_shake_256f_simple_verification/0
]).

-type sphincs_plus_shake_256s_robust_secret_key() :: <<_:1024>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-shake-256s-robust Signature Algorithm (128-bytes).
-type sphincs_plus_shake_256s_robust_public_key() :: <<_:512>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-shake-256s-robust Signature Algorithm (64-bytes).
-type sphincs_plus_shake_256s_robust_seed() :: <<_:768>>.
%%% Binary representation of a `Seed' for the SPHINCS+-shake-256s-robust Signature Algorithm (96-bytes).
-type sphincs_plus_shake_256s_robust_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-shake-256s-robust Signature Algorithm.
-type sphincs_plus_shake_256s_robust_signature() :: <<_:238336>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-shake-256s-robust Signature Algorithm (maximum of 29,792-bytes).
-type sphincs_plus_shake_256s_robust_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-shake-256s-robust Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_shake_256s_robust_secret_key/0,
    sphincs_plus_shake_256s_robust_public_key/0,
    sphincs_plus_shake_256s_robust_seed/0,
    sphincs_plus_shake_256s_robust_message/0,
    sphincs_plus_shake_256s_robust_signature/0,
    sphincs_plus_shake_256s_robust_verification/0
]).

-type sphincs_plus_shake_256s_simple_secret_key() :: <<_:1024>>.
%%% Binary representation of a `SecretKey' for the SPHINCS+-shake-256s-simple Signature Algorithm (128-bytes).
-type sphincs_plus_shake_256s_simple_public_key() :: <<_:512>>.
%%% Binary representation of a `PublicKey' for the SPHINCS+-shake-256s-simple Signature Algorithm (64-bytes).
-type sphincs_plus_shake_256s_simple_seed() :: <<_:768>>.
%%% Binary representation of a `Seed' for the SPHINCS+-shake-256s-simple Signature Algorithm (96-bytes).
-type sphincs_plus_shake_256s_simple_message() :: binary().
%%% Binary representation of a `Message' for the SPHINCS+-shake-256s-simple Signature Algorithm.
-type sphincs_plus_shake_256s_simple_signature() :: <<_:238336>> | binary().
%%% Binary representation of a `Signature' for the SPHINCS+-shake-256s-simple Signature Algorithm (maximum of 29,792-bytes).
-type sphincs_plus_shake_256s_simple_verification() :: boolean().
%%% Boolean representation of a `Verification' for the SPHINCS+-shake-256s-simple Signature Algorithm (`true' if verification was successful, `false' otherwise).

-export_type([
    sphincs_plus_shake_256s_simple_secret_key/0,
    sphincs_plus_shake_256s_simple_public_key/0,
    sphincs_plus_shake_256s_simple_seed/0,
    sphincs_plus_shake_256s_simple_message/0,
    sphincs_plus_shake_256s_simple_signature/0,
    sphincs_plus_shake_256s_simple_verification/0
]).

%%%=============================================================================
%%% NIF API functions
%%%=============================================================================

%%% @doc
%%% Returns the number of bytes of the stack size currently set for the Dirty Job CPU Thread.
%%% @end
-spec dirty_job_cpu_stack_size() -> StackSize :: non_neg_integer().
dirty_job_cpu_stack_size() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the HQC-RMRS-128
%%% <a href="https://en.wikipedia.org/wiki/Key_encapsulation_mechanism">Key Encapsulation Mechanism (KEM)</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := kem,
%%%     name := "HQC-RMRS-128",
%%%     secretkeybytes := 2289,
%%%     publickeybytes := 2249,
%%%     ciphertextbytes := 4481,
%%%     sharedsecretbytes := 64
%%% } = pqclean_nif:hqc_rmrs_128_info()
%%% '''
%%%
%%% @see hqc_rmrs_128_keypair/0
%%% @see hqc_rmrs_128_encapsulate/1
%%% @see hqc_rmrs_128_decapsulate/2
%%% @end
-spec hqc_rmrs_128_info() -> crypto_kem_info().
hqc_rmrs_128_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the HQC-RMRS-128 KEM Algorithm.
%%%
%%% `PublicKey' is a binary of size 2,249-bytes.
%%%
%%% `SecretKey' is a binary of size 2,289-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:hqc_rmrs_128_keypair().
%%% '''
%%%
%%%
%%% @see hqc_rmrs_128_encapsulate/1
%%% @see hqc_rmrs_128_decapsulate/2
%%% @end
-spec hqc_rmrs_128_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: hqc_rmrs_128_public_key(), SecretKey :: hqc_rmrs_128_secret_key().
hqc_rmrs_128_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Encapsulates a new `SharedSecret' for `PublicKey' using the HQC-RMRS-128 KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `CipherText' is a binary of size 4,481-bytes.
%%%
%%% `SharedSecret' is a binary of size 64-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:hqc_rmrs_128_keypair(),
%%% {CT, SS} = pqclean_nif:hqc_rmrs_128_encapsulate(PK).
%%% '''
%%%
%%% @see hqc_rmrs_128_decapsulate/2
%%% @end
-spec hqc_rmrs_128_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: hqc_rmrs_128_public_key(), CipherText :: hqc_rmrs_128_cipher_text(), SharedSecret :: hqc_rmrs_128_shared_secret().
hqc_rmrs_128_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Decapsulates a `SharedSecret' for from a `CipherText' and `SecretKey' using the HQC-RMRS-128 KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `SharedSecret' is a binary of size 64-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:hqc_rmrs_128_keypair(),
%%% {CT, SS} = pqclean_nif:hqc_rmrs_128_encapsulate(PK),
%%%      SS  = pqclean_nif:hqc_rmrs_128_decapsulate(CT, SK).
%%% '''
%%%
%%% @see hqc_rmrs_128_encapsulate/1
%%% @end
-spec hqc_rmrs_128_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: hqc_rmrs_128_cipher_text(), SecretKey :: hqc_rmrs_128_secret_key(), SharedSecret :: hqc_rmrs_128_shared_secret().
hqc_rmrs_128_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the HQC-RMRS-192
%%% <a href="https://en.wikipedia.org/wiki/Key_encapsulation_mechanism">Key Encapsulation Mechanism (KEM)</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := kem,
%%%     name := "HQC-RMRS-192",
%%%     secretkeybytes := 4562,
%%%     publickeybytes := 4522,
%%%     ciphertextbytes := 9026,
%%%     sharedsecretbytes := 64
%%% } = pqclean_nif:hqc_rmrs_192_info()
%%% '''
%%%
%%% @see hqc_rmrs_192_keypair/0
%%% @see hqc_rmrs_192_encapsulate/1
%%% @see hqc_rmrs_192_decapsulate/2
%%% @end
-spec hqc_rmrs_192_info() -> crypto_kem_info().
hqc_rmrs_192_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the HQC-RMRS-192 KEM Algorithm.
%%%
%%% `PublicKey' is a binary of size 4,522-bytes.
%%%
%%% `SecretKey' is a binary of size 4,562-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:hqc_rmrs_192_keypair().
%%% '''
%%%
%%%
%%% @see hqc_rmrs_192_encapsulate/1
%%% @see hqc_rmrs_192_decapsulate/2
%%% @end
-spec hqc_rmrs_192_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: hqc_rmrs_192_public_key(), SecretKey :: hqc_rmrs_192_secret_key().
hqc_rmrs_192_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Encapsulates a new `SharedSecret' for `PublicKey' using the HQC-RMRS-192 KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `CipherText' is a binary of size 9,026-bytes.
%%%
%%% `SharedSecret' is a binary of size 64-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:hqc_rmrs_192_keypair(),
%%% {CT, SS} = pqclean_nif:hqc_rmrs_192_encapsulate(PK).
%%% '''
%%%
%%% @see hqc_rmrs_192_decapsulate/2
%%% @end
-spec hqc_rmrs_192_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: hqc_rmrs_192_public_key(), CipherText :: hqc_rmrs_192_cipher_text(), SharedSecret :: hqc_rmrs_192_shared_secret().
hqc_rmrs_192_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Decapsulates a `SharedSecret' for from a `CipherText' and `SecretKey' using the HQC-RMRS-192 KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `SharedSecret' is a binary of size 64-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:hqc_rmrs_192_keypair(),
%%% {CT, SS} = pqclean_nif:hqc_rmrs_192_encapsulate(PK),
%%%      SS  = pqclean_nif:hqc_rmrs_192_decapsulate(CT, SK).
%%% '''
%%%
%%% @see hqc_rmrs_192_encapsulate/1
%%% @end
-spec hqc_rmrs_192_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: hqc_rmrs_192_cipher_text(), SecretKey :: hqc_rmrs_192_secret_key(), SharedSecret :: hqc_rmrs_192_shared_secret().
hqc_rmrs_192_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the HQC-RMRS-256
%%% <a href="https://en.wikipedia.org/wiki/Key_encapsulation_mechanism">Key Encapsulation Mechanism (KEM)</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := kem,
%%%     name := "HQC-RMRS-256",
%%%     secretkeybytes := 7285,
%%%     publickeybytes := 7245,
%%%     ciphertextbytes := 14469,
%%%     sharedsecretbytes := 64
%%% } = pqclean_nif:hqc_rmrs_256_info()
%%% '''
%%%
%%% @see hqc_rmrs_256_keypair/0
%%% @see hqc_rmrs_256_encapsulate/1
%%% @see hqc_rmrs_256_decapsulate/2
%%% @end
-spec hqc_rmrs_256_info() -> crypto_kem_info().
hqc_rmrs_256_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the HQC-RMRS-256 KEM Algorithm.
%%%
%%% `PublicKey' is a binary of size 7,245-bytes.
%%%
%%% `SecretKey' is a binary of size 7,285-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:hqc_rmrs_256_keypair().
%%% '''
%%%
%%%
%%% @see hqc_rmrs_256_encapsulate/1
%%% @see hqc_rmrs_256_decapsulate/2
%%% @end
-spec hqc_rmrs_256_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: hqc_rmrs_256_public_key(), SecretKey :: hqc_rmrs_256_secret_key().
hqc_rmrs_256_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Encapsulates a new `SharedSecret' for `PublicKey' using the HQC-RMRS-256 KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `CipherText' is a binary of size 14,469-bytes.
%%%
%%% `SharedSecret' is a binary of size 64-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:hqc_rmrs_256_keypair(),
%%% {CT, SS} = pqclean_nif:hqc_rmrs_256_encapsulate(PK).
%%% '''
%%%
%%% @see hqc_rmrs_256_decapsulate/2
%%% @end
-spec hqc_rmrs_256_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: hqc_rmrs_256_public_key(), CipherText :: hqc_rmrs_256_cipher_text(), SharedSecret :: hqc_rmrs_256_shared_secret().
hqc_rmrs_256_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Decapsulates a `SharedSecret' for from a `CipherText' and `SecretKey' using the HQC-RMRS-256 KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `SharedSecret' is a binary of size 64-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:hqc_rmrs_256_keypair(),
%%% {CT, SS} = pqclean_nif:hqc_rmrs_256_encapsulate(PK),
%%%      SS  = pqclean_nif:hqc_rmrs_256_decapsulate(CT, SK).
%%% '''
%%%
%%% @see hqc_rmrs_256_encapsulate/1
%%% @end
-spec hqc_rmrs_256_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: hqc_rmrs_256_cipher_text(), SecretKey :: hqc_rmrs_256_secret_key(), SharedSecret :: hqc_rmrs_256_shared_secret().
hqc_rmrs_256_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the Kyber512
%%% <a href="https://en.wikipedia.org/wiki/Key_encapsulation_mechanism">Key Encapsulation Mechanism (KEM)</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := kem,
%%%     name := "Kyber512",
%%%     secretkeybytes := 1632,
%%%     publickeybytes := 800,
%%%     ciphertextbytes := 768,
%%%     sharedsecretbytes := 32
%%% } = pqclean_nif:kyber512_info()
%%% '''
%%%
%%% @see kyber512_keypair/0
%%% @see kyber512_encapsulate/1
%%% @see kyber512_decapsulate/2
%%% @end
-spec kyber512_info() -> crypto_kem_info().
kyber512_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the Kyber512 KEM Algorithm.
%%%
%%% `PublicKey' is a binary of size 800-bytes.
%%%
%%% `SecretKey' is a binary of size 1,632-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:kyber512_keypair().
%%% '''
%%%
%%%
%%% @see kyber512_encapsulate/1
%%% @see kyber512_decapsulate/2
%%% @end
-spec kyber512_keypair() -> {PublicKey, SecretKey} when PublicKey :: kyber512_public_key(), SecretKey :: kyber512_secret_key().
kyber512_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Encapsulates a new `SharedSecret' for `PublicKey' using the Kyber512 KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `CipherText' is a binary of size 768-bytes.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:kyber512_keypair(),
%%% {CT, SS} = pqclean_nif:kyber512_encapsulate(PK).
%%% '''
%%%
%%% @see kyber512_decapsulate/2
%%% @end
-spec kyber512_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: kyber512_public_key(), CipherText :: kyber512_cipher_text(), SharedSecret :: kyber512_shared_secret().
kyber512_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Decapsulates a `SharedSecret' for from a `CipherText' and `SecretKey' using the Kyber512 KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:kyber512_keypair(),
%%% {CT, SS} = pqclean_nif:kyber512_encapsulate(PK),
%%%      SS  = pqclean_nif:kyber512_decapsulate(CT, SK).
%%% '''
%%%
%%% @see kyber512_encapsulate/1
%%% @end
-spec kyber512_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: kyber512_cipher_text(), SecretKey :: kyber512_secret_key(), SharedSecret :: kyber512_shared_secret().
kyber512_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the Kyber512-90s
%%% <a href="https://en.wikipedia.org/wiki/Key_encapsulation_mechanism">Key Encapsulation Mechanism (KEM)</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := kem,
%%%     name := "Kyber512-90s",
%%%     secretkeybytes := 1632,
%%%     publickeybytes := 800,
%%%     ciphertextbytes := 768,
%%%     sharedsecretbytes := 32
%%% } = pqclean_nif:kyber512_90s_info()
%%% '''
%%%
%%% @see kyber512_90s_keypair/0
%%% @see kyber512_90s_encapsulate/1
%%% @see kyber512_90s_decapsulate/2
%%% @end
-spec kyber512_90s_info() -> crypto_kem_info().
kyber512_90s_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the Kyber512-90s KEM Algorithm.
%%%
%%% `PublicKey' is a binary of size 800-bytes.
%%%
%%% `SecretKey' is a binary of size 1,632-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:kyber512_90s_keypair().
%%% '''
%%%
%%%
%%% @see kyber512_90s_encapsulate/1
%%% @see kyber512_90s_decapsulate/2
%%% @end
-spec kyber512_90s_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: kyber512_90s_public_key(), SecretKey :: kyber512_90s_secret_key().
kyber512_90s_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Encapsulates a new `SharedSecret' for `PublicKey' using the Kyber512-90s KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `CipherText' is a binary of size 768-bytes.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:kyber512_90s_keypair(),
%%% {CT, SS} = pqclean_nif:kyber512_90s_encapsulate(PK).
%%% '''
%%%
%%% @see kyber512_90s_decapsulate/2
%%% @end
-spec kyber512_90s_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: kyber512_90s_public_key(), CipherText :: kyber512_90s_cipher_text(), SharedSecret :: kyber512_90s_shared_secret().
kyber512_90s_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Decapsulates a `SharedSecret' for from a `CipherText' and `SecretKey' using the Kyber512-90s KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:kyber512_90s_keypair(),
%%% {CT, SS} = pqclean_nif:kyber512_90s_encapsulate(PK),
%%%      SS  = pqclean_nif:kyber512_90s_decapsulate(CT, SK).
%%% '''
%%%
%%% @see kyber512_90s_encapsulate/1
%%% @end
-spec kyber512_90s_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: kyber512_90s_cipher_text(), SecretKey :: kyber512_90s_secret_key(), SharedSecret :: kyber512_90s_shared_secret().
kyber512_90s_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the Kyber768
%%% <a href="https://en.wikipedia.org/wiki/Key_encapsulation_mechanism">Key Encapsulation Mechanism (KEM)</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := kem,
%%%     name := "Kyber768",
%%%     secretkeybytes := 2400,
%%%     publickeybytes := 1184,
%%%     ciphertextbytes := 1088,
%%%     sharedsecretbytes := 32
%%% } = pqclean_nif:kyber768_info()
%%% '''
%%%
%%% @see kyber768_keypair/0
%%% @see kyber768_encapsulate/1
%%% @see kyber768_decapsulate/2
%%% @end
-spec kyber768_info() -> crypto_kem_info().
kyber768_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the Kyber768 KEM Algorithm.
%%%
%%% `PublicKey' is a binary of size 1,184-bytes.
%%%
%%% `SecretKey' is a binary of size 2,400-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:kyber768_keypair().
%%% '''
%%%
%%%
%%% @see kyber768_encapsulate/1
%%% @see kyber768_decapsulate/2
%%% @end
-spec kyber768_keypair() -> {PublicKey, SecretKey} when PublicKey :: kyber768_public_key(), SecretKey :: kyber768_secret_key().
kyber768_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Encapsulates a new `SharedSecret' for `PublicKey' using the Kyber768 KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `CipherText' is a binary of size 1,088-bytes.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:kyber768_keypair(),
%%% {CT, SS} = pqclean_nif:kyber768_encapsulate(PK).
%%% '''
%%%
%%% @see kyber768_decapsulate/2
%%% @end
-spec kyber768_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: kyber768_public_key(), CipherText :: kyber768_cipher_text(), SharedSecret :: kyber768_shared_secret().
kyber768_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Decapsulates a `SharedSecret' for from a `CipherText' and `SecretKey' using the Kyber768 KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:kyber768_keypair(),
%%% {CT, SS} = pqclean_nif:kyber768_encapsulate(PK),
%%%      SS  = pqclean_nif:kyber768_decapsulate(CT, SK).
%%% '''
%%%
%%% @see kyber768_encapsulate/1
%%% @end
-spec kyber768_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: kyber768_cipher_text(), SecretKey :: kyber768_secret_key(), SharedSecret :: kyber768_shared_secret().
kyber768_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the Kyber768-90s
%%% <a href="https://en.wikipedia.org/wiki/Key_encapsulation_mechanism">Key Encapsulation Mechanism (KEM)</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := kem,
%%%     name := "Kyber768-90s",
%%%     secretkeybytes := 2400,
%%%     publickeybytes := 1184,
%%%     ciphertextbytes := 1088,
%%%     sharedsecretbytes := 32
%%% } = pqclean_nif:kyber768_90s_info()
%%% '''
%%%
%%% @see kyber768_90s_keypair/0
%%% @see kyber768_90s_encapsulate/1
%%% @see kyber768_90s_decapsulate/2
%%% @end
-spec kyber768_90s_info() -> crypto_kem_info().
kyber768_90s_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the Kyber768-90s KEM Algorithm.
%%%
%%% `PublicKey' is a binary of size 1,184-bytes.
%%%
%%% `SecretKey' is a binary of size 2,400-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:kyber768_90s_keypair().
%%% '''
%%%
%%%
%%% @see kyber768_90s_encapsulate/1
%%% @see kyber768_90s_decapsulate/2
%%% @end
-spec kyber768_90s_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: kyber768_90s_public_key(), SecretKey :: kyber768_90s_secret_key().
kyber768_90s_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Encapsulates a new `SharedSecret' for `PublicKey' using the Kyber768-90s KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `CipherText' is a binary of size 1,088-bytes.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:kyber768_90s_keypair(),
%%% {CT, SS} = pqclean_nif:kyber768_90s_encapsulate(PK).
%%% '''
%%%
%%% @see kyber768_90s_decapsulate/2
%%% @end
-spec kyber768_90s_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: kyber768_90s_public_key(), CipherText :: kyber768_90s_cipher_text(), SharedSecret :: kyber768_90s_shared_secret().
kyber768_90s_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Decapsulates a `SharedSecret' for from a `CipherText' and `SecretKey' using the Kyber768-90s KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:kyber768_90s_keypair(),
%%% {CT, SS} = pqclean_nif:kyber768_90s_encapsulate(PK),
%%%      SS  = pqclean_nif:kyber768_90s_decapsulate(CT, SK).
%%% '''
%%%
%%% @see kyber768_90s_encapsulate/1
%%% @end
-spec kyber768_90s_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: kyber768_90s_cipher_text(), SecretKey :: kyber768_90s_secret_key(), SharedSecret :: kyber768_90s_shared_secret().
kyber768_90s_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the Kyber1024
%%% <a href="https://en.wikipedia.org/wiki/Key_encapsulation_mechanism">Key Encapsulation Mechanism (KEM)</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := kem,
%%%     name := "Kyber1024",
%%%     secretkeybytes := 3168,
%%%     publickeybytes := 1568,
%%%     ciphertextbytes := 1568,
%%%     sharedsecretbytes := 32
%%% } = pqclean_nif:kyber1024_info()
%%% '''
%%%
%%% @see kyber1024_keypair/0
%%% @see kyber1024_encapsulate/1
%%% @see kyber1024_decapsulate/2
%%% @end
-spec kyber1024_info() -> crypto_kem_info().
kyber1024_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the Kyber1024 KEM Algorithm.
%%%
%%% `PublicKey' is a binary of size 1,568-bytes.
%%%
%%% `SecretKey' is a binary of size 3,168-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:kyber1024_keypair().
%%% '''
%%%
%%%
%%% @see kyber1024_encapsulate/1
%%% @see kyber1024_decapsulate/2
%%% @end
-spec kyber1024_keypair() -> {PublicKey, SecretKey} when PublicKey :: kyber1024_public_key(), SecretKey :: kyber1024_secret_key().
kyber1024_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Encapsulates a new `SharedSecret' for `PublicKey' using the Kyber1024 KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `CipherText' is a binary of size 1,568-bytes.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:kyber1024_keypair(),
%%% {CT, SS} = pqclean_nif:kyber1024_encapsulate(PK).
%%% '''
%%%
%%% @see kyber1024_decapsulate/2
%%% @end
-spec kyber1024_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: kyber1024_public_key(), CipherText :: kyber1024_cipher_text(), SharedSecret :: kyber1024_shared_secret().
kyber1024_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Decapsulates a `SharedSecret' for from a `CipherText' and `SecretKey' using the Kyber1024 KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:kyber1024_keypair(),
%%% {CT, SS} = pqclean_nif:kyber1024_encapsulate(PK),
%%%      SS  = pqclean_nif:kyber1024_decapsulate(CT, SK).
%%% '''
%%%
%%% @see kyber1024_encapsulate/1
%%% @end
-spec kyber1024_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: kyber1024_cipher_text(), SecretKey :: kyber1024_secret_key(), SharedSecret :: kyber1024_shared_secret().
kyber1024_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the Kyber1024-90s
%%% <a href="https://en.wikipedia.org/wiki/Key_encapsulation_mechanism">Key Encapsulation Mechanism (KEM)</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := kem,
%%%     name := "Kyber1024-90s",
%%%     secretkeybytes := 3168,
%%%     publickeybytes := 1568,
%%%     ciphertextbytes := 1568,
%%%     sharedsecretbytes := 32
%%% } = pqclean_nif:kyber1024_90s_info()
%%% '''
%%%
%%% @see kyber1024_90s_keypair/0
%%% @see kyber1024_90s_encapsulate/1
%%% @see kyber1024_90s_decapsulate/2
%%% @end
-spec kyber1024_90s_info() -> crypto_kem_info().
kyber1024_90s_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the Kyber1024-90s KEM Algorithm.
%%%
%%% `PublicKey' is a binary of size 1,568-bytes.
%%%
%%% `SecretKey' is a binary of size 3,168-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:kyber1024_90s_keypair().
%%% '''
%%%
%%%
%%% @see kyber1024_90s_encapsulate/1
%%% @see kyber1024_90s_decapsulate/2
%%% @end
-spec kyber1024_90s_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: kyber1024_90s_public_key(), SecretKey :: kyber1024_90s_secret_key().
kyber1024_90s_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Encapsulates a new `SharedSecret' for `PublicKey' using the Kyber1024-90s KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `CipherText' is a binary of size 1,568-bytes.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:kyber1024_90s_keypair(),
%%% {CT, SS} = pqclean_nif:kyber1024_90s_encapsulate(PK).
%%% '''
%%%
%%% @see kyber1024_90s_decapsulate/2
%%% @end
-spec kyber1024_90s_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: kyber1024_90s_public_key(),
    CipherText :: kyber1024_90s_cipher_text(),
    SharedSecret :: kyber1024_90s_shared_secret().
kyber1024_90s_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Decapsulates a `SharedSecret' for from a `CipherText' and `SecretKey' using the Kyber1024-90s KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:kyber1024_90s_keypair(),
%%% {CT, SS} = pqclean_nif:kyber1024_90s_encapsulate(PK),
%%%      SS  = pqclean_nif:kyber1024_90s_decapsulate(CT, SK).
%%% '''
%%%
%%% @see kyber1024_90s_encapsulate/1
%%% @end
-spec kyber1024_90s_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: kyber1024_90s_cipher_text(),
    SecretKey :: kyber1024_90s_secret_key(),
    SharedSecret :: kyber1024_90s_shared_secret().
kyber1024_90s_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the Classic McEliece 348864
%%% <a href="https://en.wikipedia.org/wiki/Key_encapsulation_mechanism">Key Encapsulation Mechanism (KEM)</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := kem,
%%%     name := "Classic McEliece 348864",
%%%     secretkeybytes := 6452,
%%%     publickeybytes := 261120,
%%%     ciphertextbytes := 128,
%%%     sharedsecretbytes := 32
%%% } = pqclean_nif:mceliece348864_info()
%%% '''
%%%
%%% @see mceliece348864_keypair/0
%%% @see mceliece348864_encapsulate/1
%%% @see mceliece348864_decapsulate/2
%%% @end
-spec mceliece348864_info() -> crypto_kem_info().
mceliece348864_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the Classic McEliece 348864 KEM Algorithm.
%%%
%%% `PublicKey' is a binary of size 261,120-bytes.
%%%
%%% `SecretKey' is a binary of size 6,452-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece348864_keypair().
%%% '''
%%%
%%% <strong>WARNING:</strong> Classic McEliece 348864 requires a large stack (>= 8MB).
%%%
%%% See <a href="readme.html#large-stack-support">Large Stack Support in the README</a> for more information.
%%%
%%% @see mceliece348864_encapsulate/1
%%% @see mceliece348864_decapsulate/2
%%% @end
-spec mceliece348864_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: mceliece348864_public_key(), SecretKey :: mceliece348864_secret_key().
mceliece348864_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Encapsulates a new `SharedSecret' for `PublicKey' using the Classic McEliece 348864 KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `CipherText' is a binary of size 128-bytes.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece348864_keypair(),
%%% {CT, SS} = pqclean_nif:mceliece348864_encapsulate(PK).
%%% '''
%%%
%%% @see mceliece348864_decapsulate/2
%%% @end
-spec mceliece348864_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: mceliece348864_public_key(),
    CipherText :: mceliece348864_cipher_text(),
    SharedSecret :: mceliece348864_shared_secret().
mceliece348864_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Decapsulates a `SharedSecret' for from a `CipherText' and `SecretKey' using the Classic McEliece 348864 KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece348864_keypair(),
%%% {CT, SS} = pqclean_nif:mceliece348864_encapsulate(PK),
%%%      SS  = pqclean_nif:mceliece348864_decapsulate(CT, SK).
%%% '''
%%%
%%% @see mceliece348864_encapsulate/1
%%% @end
-spec mceliece348864_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: mceliece348864_cipher_text(),
    SecretKey :: mceliece348864_secret_key(),
    SharedSecret :: mceliece348864_shared_secret().
mceliece348864_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the Classic McEliece 348864f
%%% <a href="https://en.wikipedia.org/wiki/Key_encapsulation_mechanism">Key Encapsulation Mechanism (KEM)</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := kem,
%%%     name := "Classic McEliece 348864f",
%%%     secretkeybytes := 6452,
%%%     publickeybytes := 261120,
%%%     ciphertextbytes := 128,
%%%     sharedsecretbytes := 32
%%% } = pqclean_nif:mceliece348864f_info()
%%% '''
%%%
%%% @see mceliece348864f_keypair/0
%%% @see mceliece348864f_encapsulate/1
%%% @see mceliece348864f_decapsulate/2
%%% @end
-spec mceliece348864f_info() -> crypto_kem_info().
mceliece348864f_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the Classic McEliece 348864f KEM Algorithm.
%%%
%%% `PublicKey' is a binary of size 261,120-bytes.
%%%
%%% `SecretKey' is a binary of size 6,452-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece348864f_keypair().
%%% '''
%%%
%%% <strong>WARNING:</strong> Classic McEliece 348864f requires a large stack (>= 8MB).
%%%
%%% See <a href="readme.html#large-stack-support">Large Stack Support in the README</a> for more information.
%%%
%%% @see mceliece348864f_encapsulate/1
%%% @see mceliece348864f_decapsulate/2
%%% @end
-spec mceliece348864f_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: mceliece348864f_public_key(), SecretKey :: mceliece348864f_secret_key().
mceliece348864f_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Encapsulates a new `SharedSecret' for `PublicKey' using the Classic McEliece 348864f KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `CipherText' is a binary of size 128-bytes.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece348864f_keypair(),
%%% {CT, SS} = pqclean_nif:mceliece348864f_encapsulate(PK).
%%% '''
%%%
%%% @see mceliece348864f_decapsulate/2
%%% @end
-spec mceliece348864f_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: mceliece348864f_public_key(),
    CipherText :: mceliece348864f_cipher_text(),
    SharedSecret :: mceliece348864f_shared_secret().
mceliece348864f_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Decapsulates a `SharedSecret' for from a `CipherText' and `SecretKey' using the Classic McEliece 348864f KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece348864f_keypair(),
%%% {CT, SS} = pqclean_nif:mceliece348864f_encapsulate(PK),
%%%      SS  = pqclean_nif:mceliece348864f_decapsulate(CT, SK).
%%% '''
%%%
%%% @see mceliece348864f_encapsulate/1
%%% @end
-spec mceliece348864f_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: mceliece348864f_cipher_text(),
    SecretKey :: mceliece348864f_secret_key(),
    SharedSecret :: mceliece348864f_shared_secret().
mceliece348864f_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the Classic McEliece 460896
%%% <a href="https://en.wikipedia.org/wiki/Key_encapsulation_mechanism">Key Encapsulation Mechanism (KEM)</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := kem,
%%%     name := "Classic McEliece 460896",
%%%     secretkeybytes := 13568,
%%%     publickeybytes := 524160,
%%%     ciphertextbytes := 188,
%%%     sharedsecretbytes := 32
%%% } = pqclean_nif:mceliece460896_info()
%%% '''
%%%
%%% @see mceliece460896_keypair/0
%%% @see mceliece460896_encapsulate/1
%%% @see mceliece460896_decapsulate/2
%%% @end
-spec mceliece460896_info() -> crypto_kem_info().
mceliece460896_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the Classic McEliece 460896 KEM Algorithm.
%%%
%%% `PublicKey' is a binary of size 524,160-bytes.
%%%
%%% `SecretKey' is a binary of size 13,568-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece460896_keypair().
%%% '''
%%%
%%% <strong>WARNING:</strong> Classic McEliece 460896 requires a large stack (>= 8MB).
%%%
%%% See <a href="readme.html#large-stack-support">Large Stack Support in the README</a> for more information.
%%%
%%% @see mceliece460896_encapsulate/1
%%% @see mceliece460896_decapsulate/2
%%% @end
-spec mceliece460896_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: mceliece460896_public_key(), SecretKey :: mceliece460896_secret_key().
mceliece460896_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Encapsulates a new `SharedSecret' for `PublicKey' using the Classic McEliece 460896 KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `CipherText' is a binary of size 188-bytes.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece460896_keypair(),
%%% {CT, SS} = pqclean_nif:mceliece460896_encapsulate(PK).
%%% '''
%%%
%%% @see mceliece460896_decapsulate/2
%%% @end
-spec mceliece460896_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: mceliece460896_public_key(),
    CipherText :: mceliece460896_cipher_text(),
    SharedSecret :: mceliece460896_shared_secret().
mceliece460896_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Decapsulates a `SharedSecret' for from a `CipherText' and `SecretKey' using the Classic McEliece 460896 KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece460896_keypair(),
%%% {CT, SS} = pqclean_nif:mceliece460896_encapsulate(PK),
%%%      SS  = pqclean_nif:mceliece460896_decapsulate(CT, SK).
%%% '''
%%%
%%% @see mceliece460896_encapsulate/1
%%% @end
-spec mceliece460896_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: mceliece460896_cipher_text(),
    SecretKey :: mceliece460896_secret_key(),
    SharedSecret :: mceliece460896_shared_secret().
mceliece460896_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the Classic McEliece 460896f
%%% <a href="https://en.wikipedia.org/wiki/Key_encapsulation_mechanism">Key Encapsulation Mechanism (KEM)</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := kem,
%%%     name := "Classic McEliece 460896f",
%%%     secretkeybytes := 13568,
%%%     publickeybytes := 524160,
%%%     ciphertextbytes := 188,
%%%     sharedsecretbytes := 32
%%% } = pqclean_nif:mceliece460896f_info()
%%% '''
%%%
%%% @see mceliece460896f_keypair/0
%%% @see mceliece460896f_encapsulate/1
%%% @see mceliece460896f_decapsulate/2
%%% @end
-spec mceliece460896f_info() -> crypto_kem_info().
mceliece460896f_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the Classic McEliece 460896f KEM Algorithm.
%%%
%%% `PublicKey' is a binary of size 524,160-bytes.
%%%
%%% `SecretKey' is a binary of size 13,568-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece460896f_keypair().
%%% '''
%%%
%%% <strong>WARNING:</strong> Classic McEliece 460896f requires a large stack (>= 8MB).
%%%
%%% See <a href="readme.html#large-stack-support">Large Stack Support in the README</a> for more information.
%%%
%%% @see mceliece460896f_encapsulate/1
%%% @see mceliece460896f_decapsulate/2
%%% @end
-spec mceliece460896f_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: mceliece460896f_public_key(), SecretKey :: mceliece460896f_secret_key().
mceliece460896f_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Encapsulates a new `SharedSecret' for `PublicKey' using the Classic McEliece 460896f KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `CipherText' is a binary of size 188-bytes.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece460896f_keypair(),
%%% {CT, SS} = pqclean_nif:mceliece460896f_encapsulate(PK).
%%% '''
%%%
%%% @see mceliece460896f_decapsulate/2
%%% @end
-spec mceliece460896f_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: mceliece460896f_public_key(),
    CipherText :: mceliece460896f_cipher_text(),
    SharedSecret :: mceliece460896f_shared_secret().
mceliece460896f_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Decapsulates a `SharedSecret' for from a `CipherText' and `SecretKey' using the Classic McEliece 460896f KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece460896f_keypair(),
%%% {CT, SS} = pqclean_nif:mceliece460896f_encapsulate(PK),
%%%      SS  = pqclean_nif:mceliece460896f_decapsulate(CT, SK).
%%% '''
%%%
%%% @see mceliece460896f_encapsulate/1
%%% @end
-spec mceliece460896f_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: mceliece460896f_cipher_text(),
    SecretKey :: mceliece460896f_secret_key(),
    SharedSecret :: mceliece460896f_shared_secret().
mceliece460896f_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the Classic McEliece 6688128
%%% <a href="https://en.wikipedia.org/wiki/Key_encapsulation_mechanism">Key Encapsulation Mechanism (KEM)</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := kem,
%%%     name := "Classic McEliece 6688128",
%%%     secretkeybytes := 13892,
%%%     publickeybytes := 1044992,
%%%     ciphertextbytes := 240,
%%%     sharedsecretbytes := 32
%%% } = pqclean_nif:mceliece6688128_info()
%%% '''
%%%
%%% @see mceliece6688128_keypair/0
%%% @see mceliece6688128_encapsulate/1
%%% @see mceliece6688128_decapsulate/2
%%% @end
-spec mceliece6688128_info() -> crypto_kem_info().
mceliece6688128_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the Classic McEliece 6688128 KEM Algorithm.
%%%
%%% `PublicKey' is a binary of size 1,044,992-bytes.
%%%
%%% `SecretKey' is a binary of size 13,892-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece6688128_keypair().
%%% '''
%%%
%%% <strong>WARNING:</strong> Classic McEliece 6688128 requires a large stack (>= 8MB).
%%%
%%% See <a href="readme.html#large-stack-support">Large Stack Support in the README</a> for more information.
%%%
%%% @see mceliece6688128_encapsulate/1
%%% @see mceliece6688128_decapsulate/2
%%% @end
-spec mceliece6688128_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: mceliece6688128_public_key(), SecretKey :: mceliece6688128_secret_key().
mceliece6688128_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Encapsulates a new `SharedSecret' for `PublicKey' using the Classic McEliece 6688128 KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `CipherText' is a binary of size 240-bytes.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece6688128_keypair(),
%%% {CT, SS} = pqclean_nif:mceliece6688128_encapsulate(PK).
%%% '''
%%%
%%% @see mceliece6688128_decapsulate/2
%%% @end
-spec mceliece6688128_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: mceliece6688128_public_key(),
    CipherText :: mceliece6688128_cipher_text(),
    SharedSecret :: mceliece6688128_shared_secret().
mceliece6688128_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Decapsulates a `SharedSecret' for from a `CipherText' and `SecretKey' using the Classic McEliece 6688128 KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece6688128_keypair(),
%%% {CT, SS} = pqclean_nif:mceliece6688128_encapsulate(PK),
%%%      SS  = pqclean_nif:mceliece6688128_decapsulate(CT, SK).
%%% '''
%%%
%%% @see mceliece6688128_encapsulate/1
%%% @end
-spec mceliece6688128_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: mceliece6688128_cipher_text(),
    SecretKey :: mceliece6688128_secret_key(),
    SharedSecret :: mceliece6688128_shared_secret().
mceliece6688128_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the Classic McEliece 6688128
%%% <a href="https://en.wikipedia.org/wiki/Key_encapsulation_mechanism">Key Encapsulation Mechanism (KEM)</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := kem,
%%%     name := "Classic McEliece 6688128",
%%%     secretkeybytes := 13892,
%%%     publickeybytes := 1044992,
%%%     ciphertextbytes := 240,
%%%     sharedsecretbytes := 32
%%% } = pqclean_nif:mceliece6688128f_info()
%%% '''
%%%
%%% @see mceliece6688128f_keypair/0
%%% @see mceliece6688128f_encapsulate/1
%%% @see mceliece6688128f_decapsulate/2
%%% @end
-spec mceliece6688128f_info() -> crypto_kem_info().
mceliece6688128f_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the Classic McEliece 6688128 KEM Algorithm.
%%%
%%% `PublicKey' is a binary of size 1,044,992-bytes.
%%%
%%% `SecretKey' is a binary of size 13,892-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece6688128f_keypair().
%%% '''
%%%
%%% <strong>WARNING:</strong> Classic McEliece 6688128 requires a large stack (>= 8MB).
%%%
%%% See <a href="readme.html#large-stack-support">Large Stack Support in the README</a> for more information.
%%%
%%% @see mceliece6688128f_encapsulate/1
%%% @see mceliece6688128f_decapsulate/2
%%% @end
-spec mceliece6688128f_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: mceliece6688128f_public_key(), SecretKey :: mceliece6688128f_secret_key().
mceliece6688128f_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Encapsulates a new `SharedSecret' for `PublicKey' using the Classic McEliece 6688128 KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `CipherText' is a binary of size 240-bytes.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece6688128f_keypair(),
%%% {CT, SS} = pqclean_nif:mceliece6688128f_encapsulate(PK).
%%% '''
%%%
%%% @see mceliece6688128f_decapsulate/2
%%% @end
-spec mceliece6688128f_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: mceliece6688128f_public_key(),
    CipherText :: mceliece6688128f_cipher_text(),
    SharedSecret :: mceliece6688128f_shared_secret().
mceliece6688128f_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Decapsulates a `SharedSecret' for from a `CipherText' and `SecretKey' using the Classic McEliece 6688128 KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece6688128f_keypair(),
%%% {CT, SS} = pqclean_nif:mceliece6688128f_encapsulate(PK),
%%%      SS  = pqclean_nif:mceliece6688128f_decapsulate(CT, SK).
%%% '''
%%%
%%% @see mceliece6688128f_encapsulate/1
%%% @end
-spec mceliece6688128f_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: mceliece6688128f_cipher_text(),
    SecretKey :: mceliece6688128f_secret_key(),
    SharedSecret :: mceliece6688128f_shared_secret().
mceliece6688128f_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the Classic McEliece 6960119
%%% <a href="https://en.wikipedia.org/wiki/Key_encapsulation_mechanism">Key Encapsulation Mechanism (KEM)</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := kem,
%%%     name := "Classic McEliece 6960119",
%%%     secretkeybytes := 13908,
%%%     publickeybytes := 1047319,
%%%     ciphertextbytes := 226,
%%%     sharedsecretbytes := 32
%%% } = pqclean_nif:mceliece6960119_info()
%%% '''
%%%
%%% @see mceliece6960119_keypair/0
%%% @see mceliece6960119_encapsulate/1
%%% @see mceliece6960119_decapsulate/2
%%% @end
-spec mceliece6960119_info() -> crypto_kem_info().
mceliece6960119_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the Classic McEliece 6960119 KEM Algorithm.
%%%
%%% `PublicKey' is a binary of size 1,047,319-bytes.
%%%
%%% `SecretKey' is a binary of size 13,908-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece6960119_keypair().
%%% '''
%%%
%%% <strong>WARNING:</strong> Classic McEliece 6960119 requires a large stack (>= 8MB).
%%%
%%% See <a href="readme.html#large-stack-support">Large Stack Support in the README</a> for more information.
%%%
%%% @see mceliece6960119_encapsulate/1
%%% @see mceliece6960119_decapsulate/2
%%% @end
-spec mceliece6960119_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: mceliece6960119_public_key(), SecretKey :: mceliece6960119_secret_key().
mceliece6960119_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Encapsulates a new `SharedSecret' for `PublicKey' using the Classic McEliece 6960119 KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `CipherText' is a binary of size 226-bytes.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece6960119_keypair(),
%%% {CT, SS} = pqclean_nif:mceliece6960119_encapsulate(PK).
%%% '''
%%%
%%% @see mceliece6960119_decapsulate/2
%%% @end
-spec mceliece6960119_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: mceliece6960119_public_key(),
    CipherText :: mceliece6960119_cipher_text(),
    SharedSecret :: mceliece6960119_shared_secret().
mceliece6960119_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Decapsulates a `SharedSecret' for from a `CipherText' and `SecretKey' using the Classic McEliece 6960119 KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece6960119_keypair(),
%%% {CT, SS} = pqclean_nif:mceliece6960119_encapsulate(PK),
%%%      SS  = pqclean_nif:mceliece6960119_decapsulate(CT, SK).
%%% '''
%%%
%%% @see mceliece6960119_encapsulate/1
%%% @end
-spec mceliece6960119_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: mceliece6960119_cipher_text(),
    SecretKey :: mceliece6960119_secret_key(),
    SharedSecret :: mceliece6960119_shared_secret().
mceliece6960119_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the Classic McEliece 6960119f
%%% <a href="https://en.wikipedia.org/wiki/Key_encapsulation_mechanism">Key Encapsulation Mechanism (KEM)</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := kem,
%%%     name := "Classic McEliece 6960119f",
%%%     secretkeybytes := 13908,
%%%     publickeybytes := 1047319,
%%%     ciphertextbytes := 226,
%%%     sharedsecretbytes := 32
%%% } = pqclean_nif:mceliece6960119f_info()
%%% '''
%%%
%%% @see mceliece6960119f_keypair/0
%%% @see mceliece6960119f_encapsulate/1
%%% @see mceliece6960119f_decapsulate/2
%%% @end
-spec mceliece6960119f_info() -> crypto_kem_info().
mceliece6960119f_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the Classic McEliece 6960119f KEM Algorithm.
%%%
%%% `PublicKey' is a binary of size 1,047,319-bytes.
%%%
%%% `SecretKey' is a binary of size 13,908-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece6960119f_keypair().
%%% '''
%%%
%%% <strong>WARNING:</strong> Classic McEliece 6960119f requires a large stack (>= 8MB).
%%%
%%% See <a href="readme.html#large-stack-support">Large Stack Support in the README</a> for more information.
%%%
%%% @see mceliece6960119f_encapsulate/1
%%% @see mceliece6960119f_decapsulate/2
%%% @end
-spec mceliece6960119f_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: mceliece6960119f_public_key(), SecretKey :: mceliece6960119f_secret_key().
mceliece6960119f_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Encapsulates a new `SharedSecret' for `PublicKey' using the Classic McEliece 6960119f KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `CipherText' is a binary of size 226-bytes.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece6960119f_keypair(),
%%% {CT, SS} = pqclean_nif:mceliece6960119f_encapsulate(PK).
%%% '''
%%%
%%% @see mceliece6960119f_decapsulate/2
%%% @end
-spec mceliece6960119f_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: mceliece6960119f_public_key(),
    CipherText :: mceliece6960119f_cipher_text(),
    SharedSecret :: mceliece6960119f_shared_secret().
mceliece6960119f_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Decapsulates a `SharedSecret' for from a `CipherText' and `SecretKey' using the Classic McEliece 6960119f KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece6960119f_keypair(),
%%% {CT, SS} = pqclean_nif:mceliece6960119f_encapsulate(PK),
%%%      SS  = pqclean_nif:mceliece6960119f_decapsulate(CT, SK).
%%% '''
%%%
%%% @see mceliece6960119f_encapsulate/1
%%% @end
-spec mceliece6960119f_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: mceliece6960119f_cipher_text(),
    SecretKey :: mceliece6960119f_secret_key(),
    SharedSecret :: mceliece6960119f_shared_secret().
mceliece6960119f_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the Classic McEliece 8192128
%%% <a href="https://en.wikipedia.org/wiki/Key_encapsulation_mechanism">Key Encapsulation Mechanism (KEM)</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := kem,
%%%     name := "Classic McEliece 8192128",
%%%     secretkeybytes := 14080,
%%%     publickeybytes := 1357824,
%%%     ciphertextbytes := 240,
%%%     sharedsecretbytes := 32
%%% } = pqclean_nif:mceliece8192128_info()
%%% '''
%%%
%%% @see mceliece8192128_keypair/0
%%% @see mceliece8192128_encapsulate/1
%%% @see mceliece8192128_decapsulate/2
%%% @end
-spec mceliece8192128_info() -> crypto_kem_info().
mceliece8192128_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the Classic McEliece 8192128 KEM Algorithm.
%%%
%%% `PublicKey' is a binary of size 1,357,824-bytes.
%%%
%%% `SecretKey' is a binary of size 14,080-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece8192128_keypair().
%%% '''
%%%
%%% <strong>WARNING:</strong> Classic McEliece 8192128 requires a large stack (>= 8MB).
%%%
%%% See <a href="readme.html#large-stack-support">Large Stack Support in the README</a> for more information.
%%%
%%% @see mceliece8192128_encapsulate/1
%%% @see mceliece8192128_decapsulate/2
%%% @end
-spec mceliece8192128_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: mceliece8192128_public_key(), SecretKey :: mceliece8192128_secret_key().
mceliece8192128_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Encapsulates a new `SharedSecret' for `PublicKey' using the Classic McEliece 8192128 KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `CipherText' is a binary of size 240-bytes.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece8192128_keypair(),
%%% {CT, SS} = pqclean_nif:mceliece8192128_encapsulate(PK).
%%% '''
%%%
%%% @see mceliece8192128_decapsulate/2
%%% @end
-spec mceliece8192128_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: mceliece8192128_public_key(),
    CipherText :: mceliece8192128_cipher_text(),
    SharedSecret :: mceliece8192128_shared_secret().
mceliece8192128_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Decapsulates a `SharedSecret' for from a `CipherText' and `SecretKey' using the Classic McEliece 8192128 KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece8192128_keypair(),
%%% {CT, SS} = pqclean_nif:mceliece8192128_encapsulate(PK),
%%%      SS  = pqclean_nif:mceliece8192128_decapsulate(CT, SK).
%%% '''
%%%
%%% @see mceliece8192128_encapsulate/1
%%% @end
-spec mceliece8192128_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: mceliece8192128_cipher_text(),
    SecretKey :: mceliece8192128_secret_key(),
    SharedSecret :: mceliece8192128_shared_secret().
mceliece8192128_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the Classic McEliece 8192128f
%%% <a href="https://en.wikipedia.org/wiki/Key_encapsulation_mechanism">Key Encapsulation Mechanism (KEM)</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := kem,
%%%     name := "Classic McEliece 8192128f",
%%%     secretkeybytes := 14080,
%%%     publickeybytes := 1357824,
%%%     ciphertextbytes := 240,
%%%     sharedsecretbytes := 32
%%% } = pqclean_nif:mceliece8192128f_info()
%%% '''
%%%
%%% @see mceliece8192128f_keypair/0
%%% @see mceliece8192128f_encapsulate/1
%%% @see mceliece8192128f_decapsulate/2
%%% @end
-spec mceliece8192128f_info() -> crypto_kem_info().
mceliece8192128f_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the Classic McEliece 8192128f KEM Algorithm.
%%%
%%% `PublicKey' is a binary of size 1,357,824-bytes.
%%%
%%% `SecretKey' is a binary of size 14,080-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece8192128f_keypair().
%%% '''
%%%
%%% <strong>WARNING:</strong> Classic McEliece 8192128f requires a large stack (>= 8MB).
%%%
%%% See <a href="readme.html#large-stack-support">Large Stack Support in the README</a> for more information.
%%%
%%% @see mceliece8192128f_encapsulate/1
%%% @see mceliece8192128f_decapsulate/2
%%% @end
-spec mceliece8192128f_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: mceliece8192128f_public_key(), SecretKey :: mceliece8192128f_secret_key().
mceliece8192128f_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Encapsulates a new `SharedSecret' for `PublicKey' using the Classic McEliece 8192128f KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `CipherText' is a binary of size 240-bytes.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece8192128f_keypair(),
%%% {CT, SS} = pqclean_nif:mceliece8192128f_encapsulate(PK).
%%% '''
%%%
%%% @see mceliece8192128f_decapsulate/2
%%% @end
-spec mceliece8192128f_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: mceliece8192128f_public_key(),
    CipherText :: mceliece8192128f_cipher_text(),
    SharedSecret :: mceliece8192128f_shared_secret().
mceliece8192128f_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Decapsulates a `SharedSecret' for from a `CipherText' and `SecretKey' using the Classic McEliece 8192128f KEM Algorithm.
%%%
%%% Anyone can encapsulate a new `SharedSecret' using the `PublicKey'.
%%%
%%% Only the owner of the corresponding `SecretKey' will be able to decapsulate the `SharedSecret'.
%%%
%%% `SharedSecret' is a binary of size 32-bytes.
%%%
%%% <strong>NOTE:</strong> Only `PublicKey' and `CipherText' are safe to share publicly, whereas `SecretKey' and `SharedSecret' are to be kept private.
%%% ```
%%% {PK, SK} = pqclean_nif:mceliece8192128f_keypair(),
%%% {CT, SS} = pqclean_nif:mceliece8192128f_encapsulate(PK),
%%%      SS  = pqclean_nif:mceliece8192128f_decapsulate(CT, SK).
%%% '''
%%%
%%% @see mceliece8192128f_encapsulate/1
%%% @end
-spec mceliece8192128f_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: mceliece8192128f_cipher_text(),
    SecretKey :: mceliece8192128f_secret_key(),
    SharedSecret :: mceliece8192128f_shared_secret().
mceliece8192128f_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the Dilithium2
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "Dilithium2",
%%%     secretkeybytes := 2528,
%%%     publickeybytes := 1312,
%%%     signaturebytes := 2420
%%% } = pqclean_nif:dilithium2_info()
%%% '''
%%%
%%% @see dilithium2_keypair/0
%%% @see dilithium2_sign/2
%%% @see dilithium2_verify/3
%%% @end
-spec dilithium2_info() -> crypto_sign_info().
dilithium2_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the Dilithium2 Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 1,312-bytes.
%%%
%%% `SecretKey' is a binary of size 2,528-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:dilithium2_keypair().
%%% '''
%%%
%%% @see dilithium2_sign/2
%%% @see dilithium2_verify/3
%%% @end
-spec dilithium2_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: dilithium2_public_key(), SecretKey :: dilithium2_secret_key().
dilithium2_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the Dilithium2 Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 2,528-bytes generated from `dilithium2_keypair/0'.
%%%
%%% `Signature' is a binary of maximum size 2,420-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:dilithium2_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:dilithium2_sign(Msg, SK).
%%% '''
%%%
%%% @see dilithium2_verify/3
%%% @end
-spec dilithium2_sign(Message, SecretKey) -> Signature when
    Message :: dilithium2_message(), SecretKey :: dilithium2_secret_key(), Signature :: dilithium2_signature().
dilithium2_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the Dilithium2 Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 2,420-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 1,312-bytes generated from `dilithium2_keypair/0'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:dilithium2_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:dilithium2_sign(Msg, SK),
%%% true = pqclean_nif:dilithium2_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:dilithium2_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see dilithium2_sign/2
%%% @end
-spec dilithium2_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: dilithium2_signature(),
    Message :: dilithium2_message(),
    PublicKey :: dilithium2_public_key(),
    Verification :: dilithium2_verification().
dilithium2_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the Dilithium2-AES
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "Dilithium2-AES",
%%%     secretkeybytes := 2528,
%%%     publickeybytes := 1312,
%%%     signaturebytes := 2420
%%% } = pqclean_nif:dilithium2aes_info()
%%% '''
%%%
%%% @see dilithium2aes_keypair/0
%%% @see dilithium2aes_sign/2
%%% @see dilithium2aes_verify/3
%%% @end
-spec dilithium2aes_info() -> crypto_sign_info().
dilithium2aes_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the Dilithium2-AES Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 1,312-bytes.
%%%
%%% `SecretKey' is a binary of size 2,528-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:dilithium2aes_keypair().
%%% '''
%%%
%%% @see dilithium2aes_sign/2
%%% @see dilithium2aes_verify/3
%%% @end
-spec dilithium2aes_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: dilithium2aes_public_key(), SecretKey :: dilithium2aes_secret_key().
dilithium2aes_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the Dilithium2-AES Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 2,528-bytes generated from `dilithium2aes_keypair/0'.
%%%
%%% `Signature' is a binary of maximum size 2,420-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:dilithium2aes_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:dilithium2aes_sign(Msg, SK).
%%% '''
%%%
%%% @see dilithium2aes_verify/3
%%% @end
-spec dilithium2aes_sign(Message, SecretKey) -> Signature when
    Message :: dilithium2aes_message(), SecretKey :: dilithium2aes_secret_key(), Signature :: dilithium2aes_signature().
dilithium2aes_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the Dilithium2-AES Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 2,420-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 1,312-bytes generated from `dilithium2aes_keypair/0'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:dilithium2aes_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:dilithium2aes_sign(Msg, SK),
%%% true = pqclean_nif:dilithium2aes_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:dilithium2aes_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see dilithium2aes_sign/2
%%% @end
-spec dilithium2aes_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: dilithium2aes_signature(),
    Message :: dilithium2aes_message(),
    PublicKey :: dilithium2aes_public_key(),
    Verification :: dilithium2aes_verification().
dilithium2aes_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the Dilithium3
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "Dilithium3",
%%%     secretkeybytes := 4000,
%%%     publickeybytes := 1952,
%%%     signaturebytes := 3293
%%% } = pqclean_nif:dilithium3_info()
%%% '''
%%%
%%% @see dilithium3_keypair/0
%%% @see dilithium3_sign/2
%%% @see dilithium3_verify/3
%%% @end
-spec dilithium3_info() -> crypto_sign_info().
dilithium3_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the Dilithium3 Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 1,952-bytes.
%%%
%%% `SecretKey' is a binary of size 4,000-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:dilithium3_keypair().
%%% '''
%%%
%%% @see dilithium3_sign/2
%%% @see dilithium3_verify/3
%%% @end
-spec dilithium3_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: dilithium3_public_key(), SecretKey :: dilithium3_secret_key().
dilithium3_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the Dilithium3 Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 4,000-bytes generated from `dilithium3_keypair/0'.
%%%
%%% `Signature' is a binary of maximum size 3,293-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:dilithium3_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:dilithium3_sign(Msg, SK).
%%% '''
%%%
%%% @see dilithium3_verify/3
%%% @end
-spec dilithium3_sign(Message, SecretKey) -> Signature when
    Message :: dilithium3_message(), SecretKey :: dilithium3_secret_key(), Signature :: dilithium3_signature().
dilithium3_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the Dilithium3 Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 3,293-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 1,952-bytes generated from `dilithium3_keypair/0'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:dilithium3_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:dilithium3_sign(Msg, SK),
%%% true = pqclean_nif:dilithium3_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:dilithium3_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see dilithium3_sign/2
%%% @end
-spec dilithium3_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: dilithium3_signature(),
    Message :: dilithium3_message(),
    PublicKey :: dilithium3_public_key(),
    Verification :: dilithium3_verification().
dilithium3_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the Dilithium3-AES
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "Dilithium3-AES",
%%%     secretkeybytes := 4000,
%%%     publickeybytes := 1952,
%%%     signaturebytes := 3293
%%% } = pqclean_nif:dilithium3aes_info()
%%% '''
%%%
%%% @see dilithium3aes_keypair/0
%%% @see dilithium3aes_sign/2
%%% @see dilithium3aes_verify/3
%%% @end
-spec dilithium3aes_info() -> crypto_sign_info().
dilithium3aes_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the Dilithium3-AES Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 1,952-bytes.
%%%
%%% `SecretKey' is a binary of size 4,000-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:dilithium3aes_keypair().
%%% '''
%%%
%%% @see dilithium3aes_sign/2
%%% @see dilithium3aes_verify/3
%%% @end
-spec dilithium3aes_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: dilithium3aes_public_key(), SecretKey :: dilithium3aes_secret_key().
dilithium3aes_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the Dilithium3-AES Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 4,000-bytes generated from `dilithium3aes_keypair/0'.
%%%
%%% `Signature' is a binary of maximum size 3,293-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:dilithium3aes_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:dilithium3aes_sign(Msg, SK).
%%% '''
%%%
%%% @see dilithium3aes_verify/3
%%% @end
-spec dilithium3aes_sign(Message, SecretKey) -> Signature when
    Message :: dilithium3aes_message(), SecretKey :: dilithium3aes_secret_key(), Signature :: dilithium3aes_signature().
dilithium3aes_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the Dilithium3-AES Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 3,293-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 1,952-bytes generated from `dilithium3aes_keypair/0'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:dilithium3aes_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:dilithium3aes_sign(Msg, SK),
%%% true = pqclean_nif:dilithium3aes_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:dilithium3aes_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see dilithium3aes_sign/2
%%% @end
-spec dilithium3aes_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: dilithium3aes_signature(),
    Message :: dilithium3aes_message(),
    PublicKey :: dilithium3aes_public_key(),
    Verification :: dilithium3aes_verification().
dilithium3aes_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the Dilithium5
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "Dilithium5",
%%%     secretkeybytes := 4864,
%%%     publickeybytes := 2592,
%%%     signaturebytes := 4595
%%% } = pqclean_nif:dilithium5_info()
%%% '''
%%%
%%% @see dilithium5_keypair/0
%%% @see dilithium5_sign/2
%%% @see dilithium5_verify/3
%%% @end
-spec dilithium5_info() -> crypto_sign_info().
dilithium5_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the Dilithium5 Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 2,592-bytes.
%%%
%%% `SecretKey' is a binary of size 4,864-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:dilithium5_keypair().
%%% '''
%%%
%%% @see dilithium5_sign/2
%%% @see dilithium5_verify/3
%%% @end
-spec dilithium5_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: dilithium5_public_key(), SecretKey :: dilithium5_secret_key().
dilithium5_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the Dilithium5 Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 4,864-bytes generated from `dilithium5_keypair/0'.
%%%
%%% `Signature' is a binary of maximum size 4,595-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:dilithium5_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:dilithium5_sign(Msg, SK).
%%% '''
%%%
%%% @see dilithium5_verify/3
%%% @end
-spec dilithium5_sign(Message, SecretKey) -> Signature when
    Message :: dilithium5_message(), SecretKey :: dilithium5_secret_key(), Signature :: dilithium5_signature().
dilithium5_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the Dilithium5 Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 4,595-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 2,592-bytes generated from `dilithium5_keypair/0'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:dilithium5_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:dilithium5_sign(Msg, SK),
%%% true = pqclean_nif:dilithium5_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:dilithium5_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see dilithium5_sign/2
%%% @end
-spec dilithium5_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: dilithium5_signature(),
    Message :: dilithium5_message(),
    PublicKey :: dilithium5_public_key(),
    Verification :: dilithium5_verification().
dilithium5_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the Dilithium5-AES
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "Dilithium5-AES",
%%%     secretkeybytes := 4864,
%%%     publickeybytes := 2592,
%%%     signaturebytes := 4595
%%% } = pqclean_nif:dilithium5aes_info()
%%% '''
%%%
%%% @see dilithium5aes_keypair/0
%%% @see dilithium5aes_sign/2
%%% @see dilithium5aes_verify/3
%%% @end
-spec dilithium5aes_info() -> crypto_sign_info().
dilithium5aes_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the Dilithium5-AES Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 2,592-bytes.
%%%
%%% `SecretKey' is a binary of size 4,864-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:dilithium5aes_keypair().
%%% '''
%%%
%%% @see dilithium5aes_sign/2
%%% @see dilithium5aes_verify/3
%%% @end
-spec dilithium5aes_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: dilithium5aes_public_key(), SecretKey :: dilithium5aes_secret_key().
dilithium5aes_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the Dilithium5-AES Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 4,864-bytes generated from `dilithium5aes_keypair/0'.
%%%
%%% `Signature' is a binary of maximum size 4,595-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:dilithium5aes_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:dilithium5aes_sign(Msg, SK).
%%% '''
%%%
%%% @see dilithium5aes_verify/3
%%% @end
-spec dilithium5aes_sign(Message, SecretKey) -> Signature when
    Message :: dilithium5aes_message(), SecretKey :: dilithium5aes_secret_key(), Signature :: dilithium5aes_signature().
dilithium5aes_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the Dilithium5-AES Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 4,595-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 2,592-bytes generated from `dilithium5aes_keypair/0'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:dilithium5aes_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:dilithium5aes_sign(Msg, SK),
%%% true = pqclean_nif:dilithium5aes_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:dilithium5aes_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see dilithium5aes_sign/2
%%% @end
-spec dilithium5aes_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: dilithium5aes_signature(),
    Message :: dilithium5aes_message(),
    PublicKey :: dilithium5aes_public_key(),
    Verification :: dilithium5aes_verification().
dilithium5aes_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the Falcon-512
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "Falcon-512",
%%%     secretkeybytes := 1281,
%%%     publickeybytes := 897,
%%%     signaturebytes := 666
%%% } = pqclean_nif:falcon512_info()
%%% '''
%%%
%%% @see falcon512_keypair/0
%%% @see falcon512_sign/2
%%% @see falcon512_verify/3
%%% @end
-spec falcon512_info() -> crypto_sign_info().
falcon512_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the Falcon-512 Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 897-bytes.
%%%
%%% `SecretKey' is a binary of size 1,281-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:falcon512_keypair().
%%% '''
%%%
%%% @see falcon512_sign/2
%%% @see falcon512_verify/3
%%% @end
-spec falcon512_keypair() -> {PublicKey, SecretKey} when PublicKey :: falcon512_public_key(), SecretKey :: falcon512_secret_key().
falcon512_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the Falcon-512 Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 1,281-bytes generated from `falcon512_keypair/0'.
%%%
%%% `Signature' is a binary of maximum size 666-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:falcon512_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:falcon512_sign(Msg, SK).
%%% '''
%%%
%%% @see falcon512_verify/3
%%% @end
-spec falcon512_sign(Message, SecretKey) -> Signature when
    Message :: falcon512_message(), SecretKey :: falcon512_secret_key(), Signature :: falcon512_signature().
falcon512_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the Falcon-512 Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 666-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 897-bytes generated from `falcon512_keypair/0'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:falcon512_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:falcon512_sign(Msg, SK),
%%% true = pqclean_nif:falcon512_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:falcon512_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see falcon512_sign/2
%%% @end
-spec falcon512_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: falcon512_signature(),
    Message :: falcon512_message(),
    PublicKey :: falcon512_public_key(),
    Verification :: falcon512_verification().
falcon512_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the Falcon-1024
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "Falcon-1024",
%%%     secretkeybytes := 2305,
%%%     publickeybytes := 1793,
%%%     signaturebytes := 1280
%%% } = pqclean_nif:falcon1024_info()
%%% '''
%%%
%%% @see falcon1024_keypair/0
%%% @see falcon1024_sign/2
%%% @see falcon1024_verify/3
%%% @end
-spec falcon1024_info() -> crypto_sign_info().
falcon1024_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the Falcon-1024 Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 1,793-bytes.
%%%
%%% `SecretKey' is a binary of size 2,305-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:falcon1024_keypair().
%%% '''
%%%
%%% @see falcon1024_sign/2
%%% @see falcon1024_verify/3
%%% @end
-spec falcon1024_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: falcon1024_public_key(), SecretKey :: falcon1024_secret_key().
falcon1024_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the Falcon-1024 Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 2,305-bytes generated from `falcon1024_keypair/0'.
%%%
%%% `Signature' is a binary of maximum size 1,280-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:falcon1024_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:falcon1024_sign(Msg, SK).
%%% '''
%%%
%%% @see falcon1024_verify/3
%%% @end
-spec falcon1024_sign(Message, SecretKey) -> Signature when
    Message :: falcon1024_message(), SecretKey :: falcon1024_secret_key(), Signature :: falcon1024_signature().
falcon1024_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the Falcon-1024 Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 1,280-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 1,793-bytes generated from `falcon1024_keypair/0'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:falcon1024_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:falcon1024_sign(Msg, SK),
%%% true = pqclean_nif:falcon1024_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:falcon1024_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see falcon1024_sign/2
%%% @end
-spec falcon1024_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: falcon1024_signature(),
    Message :: falcon1024_message(),
    PublicKey :: falcon1024_public_key(),
    Verification :: falcon1024_verification().
falcon1024_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-haraka-128f-robust
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-haraka-128f-robust",
%%%     secretkeybytes := 64,
%%%     publickeybytes := 32,
%%%     signaturebytes := 17088,
%%%     seedbytes := 48
%%% } = pqclean_nif:sphincs_plus_haraka_128f_robust_info()
%%% '''
%%%
%%% @see sphincs_plus_haraka_128f_robust_keypair/0
%%% @see sphincs_plus_haraka_128f_robust_keypair/1
%%% @see sphincs_plus_haraka_128f_robust_sign/2
%%% @see sphincs_plus_haraka_128f_robust_verify/3
%%% @end
-spec sphincs_plus_haraka_128f_robust_info() -> crypto_sign_info().
sphincs_plus_haraka_128f_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-haraka-128f-robust Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 32-bytes.
%%%
%%% `SecretKey' is a binary of size 64-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_128f_robust_keypair().
%%% '''
%%%
%%% @see sphincs_plus_haraka_128f_robust_keypair/1
%%% @see sphincs_plus_haraka_128f_robust_sign/2
%%% @see sphincs_plus_haraka_128f_robust_verify/3
%%% @end
-spec sphincs_plus_haraka_128f_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_haraka_128f_robust_public_key(), SecretKey :: sphincs_plus_haraka_128f_robust_secret_key().
sphincs_plus_haraka_128f_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-haraka-128f-robust Signature Algorithm.
%%%
%%% `Seed' is a binary of size 48-bytes.
%%%
%%% `PublicKey' is a binary of size 32-bytes.
%%%
%%% `SecretKey' is a binary of size 64-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_haraka_128f_robust_keypair(<<0:(48 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(48),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_haraka_128f_robust_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_haraka_128f_robust_keypair/0
%%% @see sphincs_plus_haraka_128f_robust_sign/2
%%% @see sphincs_plus_haraka_128f_robust_verify/3
%%% @end
-spec sphincs_plus_haraka_128f_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_haraka_128f_robust_seed(),
    PublicKey :: sphincs_plus_haraka_128f_robust_public_key(),
    SecretKey :: sphincs_plus_haraka_128f_robust_secret_key().
sphincs_plus_haraka_128f_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-haraka-128f-robust Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 64-bytes generated from `sphincs_plus_haraka_128f_robust_keypair/0' or `sphincs_plus_haraka_128f_robust_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 17,088-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_128f_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_haraka_128f_robust_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_haraka_128f_robust_verify/3
%%% @end
-spec sphincs_plus_haraka_128f_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_haraka_128f_robust_message(),
    SecretKey :: sphincs_plus_haraka_128f_robust_secret_key(),
    Signature :: sphincs_plus_haraka_128f_robust_signature().
sphincs_plus_haraka_128f_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-haraka-128f-robust Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 17,088-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 32-bytes generated from `sphincs_plus_haraka_128f_robust_keypair/0' or `sphincs_plus_haraka_128f_robust_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_128f_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_haraka_128f_robust_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_haraka_128f_robust_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_haraka_128f_robust_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_haraka_128f_robust_sign/2
%%% @end
-spec sphincs_plus_haraka_128f_robust_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_haraka_128f_robust_signature(),
    Message :: sphincs_plus_haraka_128f_robust_message(),
    PublicKey :: sphincs_plus_haraka_128f_robust_public_key(),
    Verification :: sphincs_plus_haraka_128f_robust_verification().
sphincs_plus_haraka_128f_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-haraka-128f-simple
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-haraka-128f-simple",
%%%     secretkeybytes := 64,
%%%     publickeybytes := 32,
%%%     signaturebytes := 17088,
%%%     seedbytes := 48
%%% } = pqclean_nif:sphincs_plus_haraka_128f_simple_info()
%%% '''
%%%
%%% @see sphincs_plus_haraka_128f_simple_keypair/0
%%% @see sphincs_plus_haraka_128f_simple_keypair/1
%%% @see sphincs_plus_haraka_128f_simple_sign/2
%%% @see sphincs_plus_haraka_128f_simple_verify/3
%%% @end
-spec sphincs_plus_haraka_128f_simple_info() -> crypto_sign_info().
sphincs_plus_haraka_128f_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-haraka-128f-simple Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 32-bytes.
%%%
%%% `SecretKey' is a binary of size 64-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_128f_simple_keypair().
%%% '''
%%%
%%% @see sphincs_plus_haraka_128f_simple_keypair/1
%%% @see sphincs_plus_haraka_128f_simple_sign/2
%%% @see sphincs_plus_haraka_128f_simple_verify/3
%%% @end
-spec sphincs_plus_haraka_128f_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_haraka_128f_simple_public_key(), SecretKey :: sphincs_plus_haraka_128f_simple_secret_key().
sphincs_plus_haraka_128f_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-haraka-128f-simple Signature Algorithm.
%%%
%%% `Seed' is a binary of size 48-bytes.
%%%
%%% `PublicKey' is a binary of size 32-bytes.
%%%
%%% `SecretKey' is a binary of size 64-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_haraka_128f_simple_keypair(<<0:(48 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(48),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_haraka_128f_simple_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_haraka_128f_simple_keypair/0
%%% @see sphincs_plus_haraka_128f_simple_sign/2
%%% @see sphincs_plus_haraka_128f_simple_verify/3
%%% @end
-spec sphincs_plus_haraka_128f_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_haraka_128f_simple_seed(),
    PublicKey :: sphincs_plus_haraka_128f_simple_public_key(),
    SecretKey :: sphincs_plus_haraka_128f_simple_secret_key().
sphincs_plus_haraka_128f_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-haraka-128f-simple Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 64-bytes generated from `sphincs_plus_haraka_128f_simple_keypair/0' or `sphincs_plus_haraka_128f_simple_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 17,088-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_128f_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_haraka_128f_simple_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_haraka_128f_simple_verify/3
%%% @end
-spec sphincs_plus_haraka_128f_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_haraka_128f_simple_message(),
    SecretKey :: sphincs_plus_haraka_128f_simple_secret_key(),
    Signature :: sphincs_plus_haraka_128f_simple_signature().
sphincs_plus_haraka_128f_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-haraka-128f-simple Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 17,088-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 32-bytes generated from `sphincs_plus_haraka_128f_simple_keypair/0' or `sphincs_plus_haraka_128f_simple_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_128f_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_haraka_128f_simple_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_haraka_128f_simple_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_haraka_128f_simple_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_haraka_128f_simple_sign/2
%%% @end
-spec sphincs_plus_haraka_128f_simple_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_haraka_128f_simple_signature(),
    Message :: sphincs_plus_haraka_128f_simple_message(),
    PublicKey :: sphincs_plus_haraka_128f_simple_public_key(),
    Verification :: sphincs_plus_haraka_128f_simple_verification().
sphincs_plus_haraka_128f_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-haraka-128s-robust
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-haraka-128s-robust",
%%%     secretkeybytes := 64,
%%%     publickeybytes := 32,
%%%     signaturebytes := 7856,
%%%     seedbytes := 48
%%% } = pqclean_nif:sphincs_plus_haraka_128s_robust_info()
%%% '''
%%%
%%% @see sphincs_plus_haraka_128s_robust_keypair/0
%%% @see sphincs_plus_haraka_128s_robust_keypair/1
%%% @see sphincs_plus_haraka_128s_robust_sign/2
%%% @see sphincs_plus_haraka_128s_robust_verify/3
%%% @end
-spec sphincs_plus_haraka_128s_robust_info() -> crypto_sign_info().
sphincs_plus_haraka_128s_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-haraka-128s-robust Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 32-bytes.
%%%
%%% `SecretKey' is a binary of size 64-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_128s_robust_keypair().
%%% '''
%%%
%%% @see sphincs_plus_haraka_128s_robust_keypair/1
%%% @see sphincs_plus_haraka_128s_robust_sign/2
%%% @see sphincs_plus_haraka_128s_robust_verify/3
%%% @end
-spec sphincs_plus_haraka_128s_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_haraka_128s_robust_public_key(), SecretKey :: sphincs_plus_haraka_128s_robust_secret_key().
sphincs_plus_haraka_128s_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-haraka-128s-robust Signature Algorithm.
%%%
%%% `Seed' is a binary of size 48-bytes.
%%%
%%% `PublicKey' is a binary of size 32-bytes.
%%%
%%% `SecretKey' is a binary of size 64-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_haraka_128s_robust_keypair(<<0:(48 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(48),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_haraka_128s_robust_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_haraka_128s_robust_keypair/0
%%% @see sphincs_plus_haraka_128s_robust_sign/2
%%% @see sphincs_plus_haraka_128s_robust_verify/3
%%% @end
-spec sphincs_plus_haraka_128s_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_haraka_128s_robust_seed(),
    PublicKey :: sphincs_plus_haraka_128s_robust_public_key(),
    SecretKey :: sphincs_plus_haraka_128s_robust_secret_key().
sphincs_plus_haraka_128s_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-haraka-128s-robust Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 64-bytes generated from `sphincs_plus_haraka_128s_robust_keypair/0' or `sphincs_plus_haraka_128s_robust_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 7,856-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_128s_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_haraka_128s_robust_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_haraka_128s_robust_verify/3
%%% @end
-spec sphincs_plus_haraka_128s_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_haraka_128s_robust_message(),
    SecretKey :: sphincs_plus_haraka_128s_robust_secret_key(),
    Signature :: sphincs_plus_haraka_128s_robust_signature().
sphincs_plus_haraka_128s_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-haraka-128s-robust Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 7,856-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 32-bytes generated from `sphincs_plus_haraka_128s_robust_keypair/0' or `sphincs_plus_haraka_128s_robust_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_128s_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_haraka_128s_robust_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_haraka_128s_robust_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_haraka_128s_robust_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_haraka_128s_robust_sign/2
%%% @end
-spec sphincs_plus_haraka_128s_robust_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_haraka_128s_robust_signature(),
    Message :: sphincs_plus_haraka_128s_robust_message(),
    PublicKey :: sphincs_plus_haraka_128s_robust_public_key(),
    Verification :: sphincs_plus_haraka_128s_robust_verification().
sphincs_plus_haraka_128s_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-haraka-128s-simple
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-haraka-128s-simple",
%%%     secretkeybytes := 64,
%%%     publickeybytes := 32,
%%%     signaturebytes := 7856,
%%%     seedbytes := 48
%%% } = pqclean_nif:sphincs_plus_haraka_128s_simple_info()
%%% '''
%%%
%%% @see sphincs_plus_haraka_128s_simple_keypair/0
%%% @see sphincs_plus_haraka_128s_simple_keypair/1
%%% @see sphincs_plus_haraka_128s_simple_sign/2
%%% @see sphincs_plus_haraka_128s_simple_verify/3
%%% @end
-spec sphincs_plus_haraka_128s_simple_info() -> crypto_sign_info().
sphincs_plus_haraka_128s_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-haraka-128s-simple Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 32-bytes.
%%%
%%% `SecretKey' is a binary of size 64-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_128s_simple_keypair().
%%% '''
%%%
%%% @see sphincs_plus_haraka_128s_simple_keypair/1
%%% @see sphincs_plus_haraka_128s_simple_sign/2
%%% @see sphincs_plus_haraka_128s_simple_verify/3
%%% @end
-spec sphincs_plus_haraka_128s_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_haraka_128s_simple_public_key(), SecretKey :: sphincs_plus_haraka_128s_simple_secret_key().
sphincs_plus_haraka_128s_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-haraka-128s-simple Signature Algorithm.
%%%
%%% `Seed' is a binary of size 48-bytes.
%%%
%%% `PublicKey' is a binary of size 32-bytes.
%%%
%%% `SecretKey' is a binary of size 64-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_haraka_128s_simple_keypair(<<0:(48 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(48),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_haraka_128s_simple_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_haraka_128s_simple_keypair/0
%%% @see sphincs_plus_haraka_128s_simple_sign/2
%%% @see sphincs_plus_haraka_128s_simple_verify/3
%%% @end
-spec sphincs_plus_haraka_128s_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_haraka_128s_simple_seed(),
    PublicKey :: sphincs_plus_haraka_128s_simple_public_key(),
    SecretKey :: sphincs_plus_haraka_128s_simple_secret_key().
sphincs_plus_haraka_128s_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-haraka-128s-simple Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 64-bytes generated from `sphincs_plus_haraka_128s_simple_keypair/0' or `sphincs_plus_haraka_128s_simple_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 7,856-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_128s_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_haraka_128s_simple_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_haraka_128s_simple_verify/3
%%% @end
-spec sphincs_plus_haraka_128s_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_haraka_128s_simple_message(),
    SecretKey :: sphincs_plus_haraka_128s_simple_secret_key(),
    Signature :: sphincs_plus_haraka_128s_simple_signature().
sphincs_plus_haraka_128s_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-haraka-128s-simple Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 7,856-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 32-bytes generated from `sphincs_plus_haraka_128s_simple_keypair/0' or `sphincs_plus_haraka_128s_simple_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_128s_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_haraka_128s_simple_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_haraka_128s_simple_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_haraka_128s_simple_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_haraka_128s_simple_sign/2
%%% @end
-spec sphincs_plus_haraka_128s_simple_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_haraka_128s_simple_signature(),
    Message :: sphincs_plus_haraka_128s_simple_message(),
    PublicKey :: sphincs_plus_haraka_128s_simple_public_key(),
    Verification :: sphincs_plus_haraka_128s_simple_verification().
sphincs_plus_haraka_128s_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-haraka-192f-robust
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-haraka-192f-robust",
%%%     secretkeybytes := 96,
%%%     publickeybytes := 48,
%%%     signaturebytes := 35664,
%%%     seedbytes := 72
%%% } = pqclean_nif:sphincs_plus_haraka_192f_robust_info()
%%% '''
%%%
%%% @see sphincs_plus_haraka_192f_robust_keypair/0
%%% @see sphincs_plus_haraka_192f_robust_keypair/1
%%% @see sphincs_plus_haraka_192f_robust_sign/2
%%% @see sphincs_plus_haraka_192f_robust_verify/3
%%% @end
-spec sphincs_plus_haraka_192f_robust_info() -> crypto_sign_info().
sphincs_plus_haraka_192f_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-haraka-192f-robust Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 48-bytes.
%%%
%%% `SecretKey' is a binary of size 96-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_192f_robust_keypair().
%%% '''
%%%
%%% @see sphincs_plus_haraka_192f_robust_keypair/1
%%% @see sphincs_plus_haraka_192f_robust_sign/2
%%% @see sphincs_plus_haraka_192f_robust_verify/3
%%% @end
-spec sphincs_plus_haraka_192f_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_haraka_192f_robust_public_key(), SecretKey :: sphincs_plus_haraka_192f_robust_secret_key().
sphincs_plus_haraka_192f_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-haraka-192f-robust Signature Algorithm.
%%%
%%% `Seed' is a binary of size 72-bytes.
%%%
%%% `PublicKey' is a binary of size 48-bytes.
%%%
%%% `SecretKey' is a binary of size 96-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_haraka_192f_robust_keypair(<<0:(72 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(72),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_haraka_192f_robust_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_haraka_192f_robust_keypair/0
%%% @see sphincs_plus_haraka_192f_robust_sign/2
%%% @see sphincs_plus_haraka_192f_robust_verify/3
%%% @end
-spec sphincs_plus_haraka_192f_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_haraka_192f_robust_seed(),
    PublicKey :: sphincs_plus_haraka_192f_robust_public_key(),
    SecretKey :: sphincs_plus_haraka_192f_robust_secret_key().
sphincs_plus_haraka_192f_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-haraka-192f-robust Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 96-bytes generated from `sphincs_plus_haraka_192f_robust_keypair/0' or `sphincs_plus_haraka_192f_robust_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 35,664-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_192f_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_haraka_192f_robust_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_haraka_192f_robust_verify/3
%%% @end
-spec sphincs_plus_haraka_192f_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_haraka_192f_robust_message(),
    SecretKey :: sphincs_plus_haraka_192f_robust_secret_key(),
    Signature :: sphincs_plus_haraka_192f_robust_signature().
sphincs_plus_haraka_192f_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-haraka-192f-robust Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 35,664-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 48-bytes generated from `sphincs_plus_haraka_192f_robust_keypair/0' or `sphincs_plus_haraka_192f_robust_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_192f_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_haraka_192f_robust_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_haraka_192f_robust_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_haraka_192f_robust_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_haraka_192f_robust_sign/2
%%% @end
-spec sphincs_plus_haraka_192f_robust_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_haraka_192f_robust_signature(),
    Message :: sphincs_plus_haraka_192f_robust_message(),
    PublicKey :: sphincs_plus_haraka_192f_robust_public_key(),
    Verification :: sphincs_plus_haraka_192f_robust_verification().
sphincs_plus_haraka_192f_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-haraka-192f-simple
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-haraka-192f-simple",
%%%     secretkeybytes := 96,
%%%     publickeybytes := 48,
%%%     signaturebytes := 35664,
%%%     seedbytes := 72
%%% } = pqclean_nif:sphincs_plus_haraka_192f_simple_info()
%%% '''
%%%
%%% @see sphincs_plus_haraka_192f_simple_keypair/0
%%% @see sphincs_plus_haraka_192f_simple_keypair/1
%%% @see sphincs_plus_haraka_192f_simple_sign/2
%%% @see sphincs_plus_haraka_192f_simple_verify/3
%%% @end
-spec sphincs_plus_haraka_192f_simple_info() -> crypto_sign_info().
sphincs_plus_haraka_192f_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-haraka-192f-simple Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 48-bytes.
%%%
%%% `SecretKey' is a binary of size 96-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_192f_simple_keypair().
%%% '''
%%%
%%% @see sphincs_plus_haraka_192f_simple_keypair/1
%%% @see sphincs_plus_haraka_192f_simple_sign/2
%%% @see sphincs_plus_haraka_192f_simple_verify/3
%%% @end
-spec sphincs_plus_haraka_192f_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_haraka_192f_simple_public_key(), SecretKey :: sphincs_plus_haraka_192f_simple_secret_key().
sphincs_plus_haraka_192f_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-haraka-192f-simple Signature Algorithm.
%%%
%%% `Seed' is a binary of size 72-bytes.
%%%
%%% `PublicKey' is a binary of size 48-bytes.
%%%
%%% `SecretKey' is a binary of size 96-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_haraka_192f_simple_keypair(<<0:(72 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(72),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_haraka_192f_simple_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_haraka_192f_simple_keypair/0
%%% @see sphincs_plus_haraka_192f_simple_sign/2
%%% @see sphincs_plus_haraka_192f_simple_verify/3
%%% @end
-spec sphincs_plus_haraka_192f_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_haraka_192f_simple_seed(),
    PublicKey :: sphincs_plus_haraka_192f_simple_public_key(),
    SecretKey :: sphincs_plus_haraka_192f_simple_secret_key().
sphincs_plus_haraka_192f_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-haraka-192f-simple Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 96-bytes generated from `sphincs_plus_haraka_192f_simple_keypair/0' or `sphincs_plus_haraka_192f_simple_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 35,664-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_192f_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_haraka_192f_simple_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_haraka_192f_simple_verify/3
%%% @end
-spec sphincs_plus_haraka_192f_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_haraka_192f_simple_message(),
    SecretKey :: sphincs_plus_haraka_192f_simple_secret_key(),
    Signature :: sphincs_plus_haraka_192f_simple_signature().
sphincs_plus_haraka_192f_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-haraka-192f-simple Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 35,664-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 48-bytes generated from `sphincs_plus_haraka_192f_simple_keypair/0' or `sphincs_plus_haraka_192f_simple_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_192f_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_haraka_192f_simple_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_haraka_192f_simple_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_haraka_192f_simple_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_haraka_192f_simple_sign/2
%%% @end
-spec sphincs_plus_haraka_192f_simple_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_haraka_192f_simple_signature(),
    Message :: sphincs_plus_haraka_192f_simple_message(),
    PublicKey :: sphincs_plus_haraka_192f_simple_public_key(),
    Verification :: sphincs_plus_haraka_192f_simple_verification().
sphincs_plus_haraka_192f_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-haraka-192s-robust
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-haraka-192s-robust",
%%%     secretkeybytes := 96,
%%%     publickeybytes := 48,
%%%     signaturebytes := 16224,
%%%     seedbytes := 72
%%% } = pqclean_nif:sphincs_plus_haraka_192s_robust_info()
%%% '''
%%%
%%% @see sphincs_plus_haraka_192s_robust_keypair/0
%%% @see sphincs_plus_haraka_192s_robust_keypair/1
%%% @see sphincs_plus_haraka_192s_robust_sign/2
%%% @see sphincs_plus_haraka_192s_robust_verify/3
%%% @end
-spec sphincs_plus_haraka_192s_robust_info() -> crypto_sign_info().
sphincs_plus_haraka_192s_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-haraka-192s-robust Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 48-bytes.
%%%
%%% `SecretKey' is a binary of size 96-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_192s_robust_keypair().
%%% '''
%%%
%%% @see sphincs_plus_haraka_192s_robust_keypair/1
%%% @see sphincs_plus_haraka_192s_robust_sign/2
%%% @see sphincs_plus_haraka_192s_robust_verify/3
%%% @end
-spec sphincs_plus_haraka_192s_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_haraka_192s_robust_public_key(), SecretKey :: sphincs_plus_haraka_192s_robust_secret_key().
sphincs_plus_haraka_192s_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-haraka-192s-robust Signature Algorithm.
%%%
%%% `Seed' is a binary of size 72-bytes.
%%%
%%% `PublicKey' is a binary of size 48-bytes.
%%%
%%% `SecretKey' is a binary of size 96-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_haraka_192s_robust_keypair(<<0:(72 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(72),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_haraka_192s_robust_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_haraka_192s_robust_keypair/0
%%% @see sphincs_plus_haraka_192s_robust_sign/2
%%% @see sphincs_plus_haraka_192s_robust_verify/3
%%% @end
-spec sphincs_plus_haraka_192s_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_haraka_192s_robust_seed(),
    PublicKey :: sphincs_plus_haraka_192s_robust_public_key(),
    SecretKey :: sphincs_plus_haraka_192s_robust_secret_key().
sphincs_plus_haraka_192s_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-haraka-192s-robust Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 96-bytes generated from `sphincs_plus_haraka_192s_robust_keypair/0' or `sphincs_plus_haraka_192s_robust_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 16,224-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_192s_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_haraka_192s_robust_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_haraka_192s_robust_verify/3
%%% @end
-spec sphincs_plus_haraka_192s_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_haraka_192s_robust_message(),
    SecretKey :: sphincs_plus_haraka_192s_robust_secret_key(),
    Signature :: sphincs_plus_haraka_192s_robust_signature().
sphincs_plus_haraka_192s_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-haraka-192s-robust Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 16,224-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 48-bytes generated from `sphincs_plus_haraka_192s_robust_keypair/0' or `sphincs_plus_haraka_192s_robust_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_192s_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_haraka_192s_robust_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_haraka_192s_robust_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_haraka_192s_robust_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_haraka_192s_robust_sign/2
%%% @end
-spec sphincs_plus_haraka_192s_robust_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_haraka_192s_robust_signature(),
    Message :: sphincs_plus_haraka_192s_robust_message(),
    PublicKey :: sphincs_plus_haraka_192s_robust_public_key(),
    Verification :: sphincs_plus_haraka_192s_robust_verification().
sphincs_plus_haraka_192s_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-haraka-192s-simple
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-haraka-192s-simple",
%%%     secretkeybytes := 96,
%%%     publickeybytes := 48,
%%%     signaturebytes := 16224,
%%%     seedbytes := 72
%%% } = pqclean_nif:sphincs_plus_haraka_192s_simple_info()
%%% '''
%%%
%%% @see sphincs_plus_haraka_192s_simple_keypair/0
%%% @see sphincs_plus_haraka_192s_simple_keypair/1
%%% @see sphincs_plus_haraka_192s_simple_sign/2
%%% @see sphincs_plus_haraka_192s_simple_verify/3
%%% @end
-spec sphincs_plus_haraka_192s_simple_info() -> crypto_sign_info().
sphincs_plus_haraka_192s_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-haraka-192s-simple Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 48-bytes.
%%%
%%% `SecretKey' is a binary of size 96-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_192s_simple_keypair().
%%% '''
%%%
%%% @see sphincs_plus_haraka_192s_simple_keypair/1
%%% @see sphincs_plus_haraka_192s_simple_sign/2
%%% @see sphincs_plus_haraka_192s_simple_verify/3
%%% @end
-spec sphincs_plus_haraka_192s_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_haraka_192s_simple_public_key(), SecretKey :: sphincs_plus_haraka_192s_simple_secret_key().
sphincs_plus_haraka_192s_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-haraka-192s-simple Signature Algorithm.
%%%
%%% `Seed' is a binary of size 72-bytes.
%%%
%%% `PublicKey' is a binary of size 48-bytes.
%%%
%%% `SecretKey' is a binary of size 96-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_haraka_192s_simple_keypair(<<0:(72 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(72),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_haraka_192s_simple_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_haraka_192s_simple_keypair/0
%%% @see sphincs_plus_haraka_192s_simple_sign/2
%%% @see sphincs_plus_haraka_192s_simple_verify/3
%%% @end
-spec sphincs_plus_haraka_192s_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_haraka_192s_simple_seed(),
    PublicKey :: sphincs_plus_haraka_192s_simple_public_key(),
    SecretKey :: sphincs_plus_haraka_192s_simple_secret_key().
sphincs_plus_haraka_192s_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-haraka-192s-simple Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 96-bytes generated from `sphincs_plus_haraka_192s_simple_keypair/0' or `sphincs_plus_haraka_192s_simple_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 16,224-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_192s_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_haraka_192s_simple_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_haraka_192s_simple_verify/3
%%% @end
-spec sphincs_plus_haraka_192s_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_haraka_192s_simple_message(),
    SecretKey :: sphincs_plus_haraka_192s_simple_secret_key(),
    Signature :: sphincs_plus_haraka_192s_simple_signature().
sphincs_plus_haraka_192s_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-haraka-192s-simple Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 16,224-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 48-bytes generated from `sphincs_plus_haraka_192s_simple_keypair/0' or `sphincs_plus_haraka_192s_simple_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_192s_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_haraka_192s_simple_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_haraka_192s_simple_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_haraka_192s_simple_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_haraka_192s_simple_sign/2
%%% @end
-spec sphincs_plus_haraka_192s_simple_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_haraka_192s_simple_signature(),
    Message :: sphincs_plus_haraka_192s_simple_message(),
    PublicKey :: sphincs_plus_haraka_192s_simple_public_key(),
    Verification :: sphincs_plus_haraka_192s_simple_verification().
sphincs_plus_haraka_192s_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-haraka-256f-robust
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-haraka-256f-robust",
%%%     secretkeybytes := 128,
%%%     publickeybytes := 64,
%%%     signaturebytes := 49856,
%%%     seedbytes := 96
%%% } = pqclean_nif:sphincs_plus_haraka_256f_robust_info()
%%% '''
%%%
%%% @see sphincs_plus_haraka_256f_robust_keypair/0
%%% @see sphincs_plus_haraka_256f_robust_keypair/1
%%% @see sphincs_plus_haraka_256f_robust_sign/2
%%% @see sphincs_plus_haraka_256f_robust_verify/3
%%% @end
-spec sphincs_plus_haraka_256f_robust_info() -> crypto_sign_info().
sphincs_plus_haraka_256f_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-haraka-256f-robust Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 64-bytes.
%%%
%%% `SecretKey' is a binary of size 128-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_256f_robust_keypair().
%%% '''
%%%
%%% @see sphincs_plus_haraka_256f_robust_keypair/1
%%% @see sphincs_plus_haraka_256f_robust_sign/2
%%% @see sphincs_plus_haraka_256f_robust_verify/3
%%% @end
-spec sphincs_plus_haraka_256f_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_haraka_256f_robust_public_key(), SecretKey :: sphincs_plus_haraka_256f_robust_secret_key().
sphincs_plus_haraka_256f_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-haraka-256f-robust Signature Algorithm.
%%%
%%% `Seed' is a binary of size 96-bytes.
%%%
%%% `PublicKey' is a binary of size 64-bytes.
%%%
%%% `SecretKey' is a binary of size 128-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_haraka_256f_robust_keypair(<<0:(96 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(96),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_haraka_256f_robust_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_haraka_256f_robust_keypair/0
%%% @see sphincs_plus_haraka_256f_robust_sign/2
%%% @see sphincs_plus_haraka_256f_robust_verify/3
%%% @end
-spec sphincs_plus_haraka_256f_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_haraka_256f_robust_seed(),
    PublicKey :: sphincs_plus_haraka_256f_robust_public_key(),
    SecretKey :: sphincs_plus_haraka_256f_robust_secret_key().
sphincs_plus_haraka_256f_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-haraka-256f-robust Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 128-bytes generated from `sphincs_plus_haraka_256f_robust_keypair/0' or `sphincs_plus_haraka_256f_robust_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 49,856-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_256f_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_haraka_256f_robust_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_haraka_256f_robust_verify/3
%%% @end
-spec sphincs_plus_haraka_256f_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_haraka_256f_robust_message(),
    SecretKey :: sphincs_plus_haraka_256f_robust_secret_key(),
    Signature :: sphincs_plus_haraka_256f_robust_signature().
sphincs_plus_haraka_256f_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-haraka-256f-robust Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 49,856-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 64-bytes generated from `sphincs_plus_haraka_256f_robust_keypair/0' or `sphincs_plus_haraka_256f_robust_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_256f_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_haraka_256f_robust_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_haraka_256f_robust_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_haraka_256f_robust_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_haraka_256f_robust_sign/2
%%% @end
-spec sphincs_plus_haraka_256f_robust_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_haraka_256f_robust_signature(),
    Message :: sphincs_plus_haraka_256f_robust_message(),
    PublicKey :: sphincs_plus_haraka_256f_robust_public_key(),
    Verification :: sphincs_plus_haraka_256f_robust_verification().
sphincs_plus_haraka_256f_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-haraka-256f-simple
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-haraka-256f-simple",
%%%     secretkeybytes := 128,
%%%     publickeybytes := 64,
%%%     signaturebytes := 49856,
%%%     seedbytes := 96
%%% } = pqclean_nif:sphincs_plus_haraka_256f_simple_info()
%%% '''
%%%
%%% @see sphincs_plus_haraka_256f_simple_keypair/0
%%% @see sphincs_plus_haraka_256f_simple_keypair/1
%%% @see sphincs_plus_haraka_256f_simple_sign/2
%%% @see sphincs_plus_haraka_256f_simple_verify/3
%%% @end
-spec sphincs_plus_haraka_256f_simple_info() -> crypto_sign_info().
sphincs_plus_haraka_256f_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-haraka-256f-simple Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 64-bytes.
%%%
%%% `SecretKey' is a binary of size 128-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_256f_simple_keypair().
%%% '''
%%%
%%% @see sphincs_plus_haraka_256f_simple_keypair/1
%%% @see sphincs_plus_haraka_256f_simple_sign/2
%%% @see sphincs_plus_haraka_256f_simple_verify/3
%%% @end
-spec sphincs_plus_haraka_256f_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_haraka_256f_simple_public_key(), SecretKey :: sphincs_plus_haraka_256f_simple_secret_key().
sphincs_plus_haraka_256f_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-haraka-256f-simple Signature Algorithm.
%%%
%%% `Seed' is a binary of size 96-bytes.
%%%
%%% `PublicKey' is a binary of size 64-bytes.
%%%
%%% `SecretKey' is a binary of size 128-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_haraka_256f_simple_keypair(<<0:(96 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(96),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_haraka_256f_simple_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_haraka_256f_simple_keypair/0
%%% @see sphincs_plus_haraka_256f_simple_sign/2
%%% @see sphincs_plus_haraka_256f_simple_verify/3
%%% @end
-spec sphincs_plus_haraka_256f_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_haraka_256f_simple_seed(),
    PublicKey :: sphincs_plus_haraka_256f_simple_public_key(),
    SecretKey :: sphincs_plus_haraka_256f_simple_secret_key().
sphincs_plus_haraka_256f_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-haraka-256f-simple Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 128-bytes generated from `sphincs_plus_haraka_256f_simple_keypair/0' or `sphincs_plus_haraka_256f_simple_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 49,856-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_256f_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_haraka_256f_simple_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_haraka_256f_simple_verify/3
%%% @end
-spec sphincs_plus_haraka_256f_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_haraka_256f_simple_message(),
    SecretKey :: sphincs_plus_haraka_256f_simple_secret_key(),
    Signature :: sphincs_plus_haraka_256f_simple_signature().
sphincs_plus_haraka_256f_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-haraka-256f-simple Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 49,856-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 64-bytes generated from `sphincs_plus_haraka_256f_simple_keypair/0' or `sphincs_plus_haraka_256f_simple_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_256f_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_haraka_256f_simple_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_haraka_256f_simple_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_haraka_256f_simple_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_haraka_256f_simple_sign/2
%%% @end
-spec sphincs_plus_haraka_256f_simple_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_haraka_256f_simple_signature(),
    Message :: sphincs_plus_haraka_256f_simple_message(),
    PublicKey :: sphincs_plus_haraka_256f_simple_public_key(),
    Verification :: sphincs_plus_haraka_256f_simple_verification().
sphincs_plus_haraka_256f_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-haraka-256s-robust
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-haraka-256s-robust",
%%%     secretkeybytes := 128,
%%%     publickeybytes := 64,
%%%     signaturebytes := 29792,
%%%     seedbytes := 96
%%% } = pqclean_nif:sphincs_plus_haraka_256s_robust_info()
%%% '''
%%%
%%% @see sphincs_plus_haraka_256s_robust_keypair/0
%%% @see sphincs_plus_haraka_256s_robust_keypair/1
%%% @see sphincs_plus_haraka_256s_robust_sign/2
%%% @see sphincs_plus_haraka_256s_robust_verify/3
%%% @end
-spec sphincs_plus_haraka_256s_robust_info() -> crypto_sign_info().
sphincs_plus_haraka_256s_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-haraka-256s-robust Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 64-bytes.
%%%
%%% `SecretKey' is a binary of size 128-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_256s_robust_keypair().
%%% '''
%%%
%%% @see sphincs_plus_haraka_256s_robust_keypair/1
%%% @see sphincs_plus_haraka_256s_robust_sign/2
%%% @see sphincs_plus_haraka_256s_robust_verify/3
%%% @end
-spec sphincs_plus_haraka_256s_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_haraka_256s_robust_public_key(), SecretKey :: sphincs_plus_haraka_256s_robust_secret_key().
sphincs_plus_haraka_256s_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-haraka-256s-robust Signature Algorithm.
%%%
%%% `Seed' is a binary of size 96-bytes.
%%%
%%% `PublicKey' is a binary of size 64-bytes.
%%%
%%% `SecretKey' is a binary of size 128-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_haraka_256s_robust_keypair(<<0:(96 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(96),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_haraka_256s_robust_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_haraka_256s_robust_keypair/0
%%% @see sphincs_plus_haraka_256s_robust_sign/2
%%% @see sphincs_plus_haraka_256s_robust_verify/3
%%% @end
-spec sphincs_plus_haraka_256s_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_haraka_256s_robust_seed(),
    PublicKey :: sphincs_plus_haraka_256s_robust_public_key(),
    SecretKey :: sphincs_plus_haraka_256s_robust_secret_key().
sphincs_plus_haraka_256s_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-haraka-256s-robust Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 128-bytes generated from `sphincs_plus_haraka_256s_robust_keypair/0' or `sphincs_plus_haraka_256s_robust_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 29,792-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_256s_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_haraka_256s_robust_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_haraka_256s_robust_verify/3
%%% @end
-spec sphincs_plus_haraka_256s_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_haraka_256s_robust_message(),
    SecretKey :: sphincs_plus_haraka_256s_robust_secret_key(),
    Signature :: sphincs_plus_haraka_256s_robust_signature().
sphincs_plus_haraka_256s_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-haraka-256s-robust Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 29,792-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 64-bytes generated from `sphincs_plus_haraka_256s_robust_keypair/0' or `sphincs_plus_haraka_256s_robust_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_256s_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_haraka_256s_robust_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_haraka_256s_robust_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_haraka_256s_robust_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_haraka_256s_robust_sign/2
%%% @end
-spec sphincs_plus_haraka_256s_robust_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_haraka_256s_robust_signature(),
    Message :: sphincs_plus_haraka_256s_robust_message(),
    PublicKey :: sphincs_plus_haraka_256s_robust_public_key(),
    Verification :: sphincs_plus_haraka_256s_robust_verification().
sphincs_plus_haraka_256s_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-haraka-256s-simple
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-haraka-256s-simple",
%%%     secretkeybytes := 128,
%%%     publickeybytes := 64,
%%%     signaturebytes := 29792,
%%%     seedbytes := 96
%%% } = pqclean_nif:sphincs_plus_haraka_256s_simple_info()
%%% '''
%%%
%%% @see sphincs_plus_haraka_256s_simple_keypair/0
%%% @see sphincs_plus_haraka_256s_simple_keypair/1
%%% @see sphincs_plus_haraka_256s_simple_sign/2
%%% @see sphincs_plus_haraka_256s_simple_verify/3
%%% @end
-spec sphincs_plus_haraka_256s_simple_info() -> crypto_sign_info().
sphincs_plus_haraka_256s_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-haraka-256s-simple Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 64-bytes.
%%%
%%% `SecretKey' is a binary of size 128-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_256s_simple_keypair().
%%% '''
%%%
%%% @see sphincs_plus_haraka_256s_simple_keypair/1
%%% @see sphincs_plus_haraka_256s_simple_sign/2
%%% @see sphincs_plus_haraka_256s_simple_verify/3
%%% @end
-spec sphincs_plus_haraka_256s_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_haraka_256s_simple_public_key(), SecretKey :: sphincs_plus_haraka_256s_simple_secret_key().
sphincs_plus_haraka_256s_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-haraka-256s-simple Signature Algorithm.
%%%
%%% `Seed' is a binary of size 96-bytes.
%%%
%%% `PublicKey' is a binary of size 64-bytes.
%%%
%%% `SecretKey' is a binary of size 128-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_haraka_256s_simple_keypair(<<0:(96 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(96),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_haraka_256s_simple_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_haraka_256s_simple_keypair/0
%%% @see sphincs_plus_haraka_256s_simple_sign/2
%%% @see sphincs_plus_haraka_256s_simple_verify/3
%%% @end
-spec sphincs_plus_haraka_256s_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_haraka_256s_simple_seed(),
    PublicKey :: sphincs_plus_haraka_256s_simple_public_key(),
    SecretKey :: sphincs_plus_haraka_256s_simple_secret_key().
sphincs_plus_haraka_256s_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-haraka-256s-simple Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 128-bytes generated from `sphincs_plus_haraka_256s_simple_keypair/0' or `sphincs_plus_haraka_256s_simple_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 29,792-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_256s_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_haraka_256s_simple_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_haraka_256s_simple_verify/3
%%% @end
-spec sphincs_plus_haraka_256s_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_haraka_256s_simple_message(),
    SecretKey :: sphincs_plus_haraka_256s_simple_secret_key(),
    Signature :: sphincs_plus_haraka_256s_simple_signature().
sphincs_plus_haraka_256s_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-haraka-256s-simple Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 29,792-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 64-bytes generated from `sphincs_plus_haraka_256s_simple_keypair/0' or `sphincs_plus_haraka_256s_simple_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_haraka_256s_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_haraka_256s_simple_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_haraka_256s_simple_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_haraka_256s_simple_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_haraka_256s_simple_sign/2
%%% @end
-spec sphincs_plus_haraka_256s_simple_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_haraka_256s_simple_signature(),
    Message :: sphincs_plus_haraka_256s_simple_message(),
    PublicKey :: sphincs_plus_haraka_256s_simple_public_key(),
    Verification :: sphincs_plus_haraka_256s_simple_verification().
sphincs_plus_haraka_256s_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-sha2-128f-robust
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-sha2-128f-robust",
%%%     secretkeybytes := 64,
%%%     publickeybytes := 32,
%%%     signaturebytes := 17088,
%%%     seedbytes := 48
%%% } = pqclean_nif:sphincs_plus_sha2_128f_robust_info()
%%% '''
%%%
%%% @see sphincs_plus_sha2_128f_robust_keypair/0
%%% @see sphincs_plus_sha2_128f_robust_keypair/1
%%% @see sphincs_plus_sha2_128f_robust_sign/2
%%% @see sphincs_plus_sha2_128f_robust_verify/3
%%% @end
-spec sphincs_plus_sha2_128f_robust_info() -> crypto_sign_info().
sphincs_plus_sha2_128f_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-sha2-128f-robust Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 32-bytes.
%%%
%%% `SecretKey' is a binary of size 64-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_128f_robust_keypair().
%%% '''
%%%
%%% @see sphincs_plus_sha2_128f_robust_keypair/1
%%% @see sphincs_plus_sha2_128f_robust_sign/2
%%% @see sphincs_plus_sha2_128f_robust_verify/3
%%% @end
-spec sphincs_plus_sha2_128f_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_sha2_128f_robust_public_key(), SecretKey :: sphincs_plus_sha2_128f_robust_secret_key().
sphincs_plus_sha2_128f_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-sha2-128f-robust Signature Algorithm.
%%%
%%% `Seed' is a binary of size 48-bytes.
%%%
%%% `PublicKey' is a binary of size 32-bytes.
%%%
%%% `SecretKey' is a binary of size 64-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_sha2_128f_robust_keypair(<<0:(48 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(48),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_sha2_128f_robust_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_sha2_128f_robust_keypair/0
%%% @see sphincs_plus_sha2_128f_robust_sign/2
%%% @see sphincs_plus_sha2_128f_robust_verify/3
%%% @end
-spec sphincs_plus_sha2_128f_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_sha2_128f_robust_seed(),
    PublicKey :: sphincs_plus_sha2_128f_robust_public_key(),
    SecretKey :: sphincs_plus_sha2_128f_robust_secret_key().
sphincs_plus_sha2_128f_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-sha2-128f-robust Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 64-bytes generated from `sphincs_plus_sha2_128f_robust_keypair/0' or `sphincs_plus_sha2_128f_robust_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 17,088-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_128f_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_sha2_128f_robust_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_sha2_128f_robust_verify/3
%%% @end
-spec sphincs_plus_sha2_128f_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_sha2_128f_robust_message(),
    SecretKey :: sphincs_plus_sha2_128f_robust_secret_key(),
    Signature :: sphincs_plus_sha2_128f_robust_signature().
sphincs_plus_sha2_128f_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-sha2-128f-robust Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 17,088-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 32-bytes generated from `sphincs_plus_sha2_128f_robust_keypair/0' or `sphincs_plus_sha2_128f_robust_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_128f_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_sha2_128f_robust_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_sha2_128f_robust_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_sha2_128f_robust_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_sha2_128f_robust_sign/2
%%% @end
-spec sphincs_plus_sha2_128f_robust_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_sha2_128f_robust_signature(),
    Message :: sphincs_plus_sha2_128f_robust_message(),
    PublicKey :: sphincs_plus_sha2_128f_robust_public_key(),
    Verification :: sphincs_plus_sha2_128f_robust_verification().
sphincs_plus_sha2_128f_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-sha2-128f-simple
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-sha2-128f-simple",
%%%     secretkeybytes := 64,
%%%     publickeybytes := 32,
%%%     signaturebytes := 17088,
%%%     seedbytes := 48
%%% } = pqclean_nif:sphincs_plus_sha2_128f_simple_info()
%%% '''
%%%
%%% @see sphincs_plus_sha2_128f_simple_keypair/0
%%% @see sphincs_plus_sha2_128f_simple_keypair/1
%%% @see sphincs_plus_sha2_128f_simple_sign/2
%%% @see sphincs_plus_sha2_128f_simple_verify/3
%%% @end
-spec sphincs_plus_sha2_128f_simple_info() -> crypto_sign_info().
sphincs_plus_sha2_128f_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-sha2-128f-simple Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 32-bytes.
%%%
%%% `SecretKey' is a binary of size 64-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_128f_simple_keypair().
%%% '''
%%%
%%% @see sphincs_plus_sha2_128f_simple_keypair/1
%%% @see sphincs_plus_sha2_128f_simple_sign/2
%%% @see sphincs_plus_sha2_128f_simple_verify/3
%%% @end
-spec sphincs_plus_sha2_128f_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_sha2_128f_simple_public_key(), SecretKey :: sphincs_plus_sha2_128f_simple_secret_key().
sphincs_plus_sha2_128f_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-sha2-128f-simple Signature Algorithm.
%%%
%%% `Seed' is a binary of size 48-bytes.
%%%
%%% `PublicKey' is a binary of size 32-bytes.
%%%
%%% `SecretKey' is a binary of size 64-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_sha2_128f_simple_keypair(<<0:(48 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(48),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_sha2_128f_simple_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_sha2_128f_simple_keypair/0
%%% @see sphincs_plus_sha2_128f_simple_sign/2
%%% @see sphincs_plus_sha2_128f_simple_verify/3
%%% @end
-spec sphincs_plus_sha2_128f_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_sha2_128f_simple_seed(),
    PublicKey :: sphincs_plus_sha2_128f_simple_public_key(),
    SecretKey :: sphincs_plus_sha2_128f_simple_secret_key().
sphincs_plus_sha2_128f_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-sha2-128f-simple Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 64-bytes generated from `sphincs_plus_sha2_128f_simple_keypair/0' or `sphincs_plus_sha2_128f_simple_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 17,088-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_128f_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_sha2_128f_simple_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_sha2_128f_simple_verify/3
%%% @end
-spec sphincs_plus_sha2_128f_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_sha2_128f_simple_message(),
    SecretKey :: sphincs_plus_sha2_128f_simple_secret_key(),
    Signature :: sphincs_plus_sha2_128f_simple_signature().
sphincs_plus_sha2_128f_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-sha2-128f-simple Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 17,088-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 32-bytes generated from `sphincs_plus_sha2_128f_simple_keypair/0' or `sphincs_plus_sha2_128f_simple_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_128f_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_sha2_128f_simple_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_sha2_128f_simple_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_sha2_128f_simple_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_sha2_128f_simple_sign/2
%%% @end
-spec sphincs_plus_sha2_128f_simple_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_sha2_128f_simple_signature(),
    Message :: sphincs_plus_sha2_128f_simple_message(),
    PublicKey :: sphincs_plus_sha2_128f_simple_public_key(),
    Verification :: sphincs_plus_sha2_128f_simple_verification().
sphincs_plus_sha2_128f_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-sha2-128s-robust
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-sha2-128s-robust",
%%%     secretkeybytes := 64,
%%%     publickeybytes := 32,
%%%     signaturebytes := 7856,
%%%     seedbytes := 48
%%% } = pqclean_nif:sphincs_plus_sha2_128s_robust_info()
%%% '''
%%%
%%% @see sphincs_plus_sha2_128s_robust_keypair/0
%%% @see sphincs_plus_sha2_128s_robust_keypair/1
%%% @see sphincs_plus_sha2_128s_robust_sign/2
%%% @see sphincs_plus_sha2_128s_robust_verify/3
%%% @end
-spec sphincs_plus_sha2_128s_robust_info() -> crypto_sign_info().
sphincs_plus_sha2_128s_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-sha2-128s-robust Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 32-bytes.
%%%
%%% `SecretKey' is a binary of size 64-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_128s_robust_keypair().
%%% '''
%%%
%%% @see sphincs_plus_sha2_128s_robust_keypair/1
%%% @see sphincs_plus_sha2_128s_robust_sign/2
%%% @see sphincs_plus_sha2_128s_robust_verify/3
%%% @end
-spec sphincs_plus_sha2_128s_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_sha2_128s_robust_public_key(), SecretKey :: sphincs_plus_sha2_128s_robust_secret_key().
sphincs_plus_sha2_128s_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-sha2-128s-robust Signature Algorithm.
%%%
%%% `Seed' is a binary of size 48-bytes.
%%%
%%% `PublicKey' is a binary of size 32-bytes.
%%%
%%% `SecretKey' is a binary of size 64-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_sha2_128s_robust_keypair(<<0:(48 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(48),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_sha2_128s_robust_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_sha2_128s_robust_keypair/0
%%% @see sphincs_plus_sha2_128s_robust_sign/2
%%% @see sphincs_plus_sha2_128s_robust_verify/3
%%% @end
-spec sphincs_plus_sha2_128s_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_sha2_128s_robust_seed(),
    PublicKey :: sphincs_plus_sha2_128s_robust_public_key(),
    SecretKey :: sphincs_plus_sha2_128s_robust_secret_key().
sphincs_plus_sha2_128s_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-sha2-128s-robust Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 64-bytes generated from `sphincs_plus_sha2_128s_robust_keypair/0' or `sphincs_plus_sha2_128s_robust_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 7,856-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_128s_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_sha2_128s_robust_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_sha2_128s_robust_verify/3
%%% @end
-spec sphincs_plus_sha2_128s_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_sha2_128s_robust_message(),
    SecretKey :: sphincs_plus_sha2_128s_robust_secret_key(),
    Signature :: sphincs_plus_sha2_128s_robust_signature().
sphincs_plus_sha2_128s_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-sha2-128s-robust Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 7,856-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 32-bytes generated from `sphincs_plus_sha2_128s_robust_keypair/0' or `sphincs_plus_sha2_128s_robust_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_128s_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_sha2_128s_robust_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_sha2_128s_robust_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_sha2_128s_robust_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_sha2_128s_robust_sign/2
%%% @end
-spec sphincs_plus_sha2_128s_robust_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_sha2_128s_robust_signature(),
    Message :: sphincs_plus_sha2_128s_robust_message(),
    PublicKey :: sphincs_plus_sha2_128s_robust_public_key(),
    Verification :: sphincs_plus_sha2_128s_robust_verification().
sphincs_plus_sha2_128s_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-sha2-128s-simple
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-sha2-128s-simple",
%%%     secretkeybytes := 64,
%%%     publickeybytes := 32,
%%%     signaturebytes := 7856,
%%%     seedbytes := 48
%%% } = pqclean_nif:sphincs_plus_sha2_128s_simple_info()
%%% '''
%%%
%%% @see sphincs_plus_sha2_128s_simple_keypair/0
%%% @see sphincs_plus_sha2_128s_simple_keypair/1
%%% @see sphincs_plus_sha2_128s_simple_sign/2
%%% @see sphincs_plus_sha2_128s_simple_verify/3
%%% @end
-spec sphincs_plus_sha2_128s_simple_info() -> crypto_sign_info().
sphincs_plus_sha2_128s_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-sha2-128s-simple Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 32-bytes.
%%%
%%% `SecretKey' is a binary of size 64-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_128s_simple_keypair().
%%% '''
%%%
%%% @see sphincs_plus_sha2_128s_simple_keypair/1
%%% @see sphincs_plus_sha2_128s_simple_sign/2
%%% @see sphincs_plus_sha2_128s_simple_verify/3
%%% @end
-spec sphincs_plus_sha2_128s_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_sha2_128s_simple_public_key(), SecretKey :: sphincs_plus_sha2_128s_simple_secret_key().
sphincs_plus_sha2_128s_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-sha2-128s-simple Signature Algorithm.
%%%
%%% `Seed' is a binary of size 48-bytes.
%%%
%%% `PublicKey' is a binary of size 32-bytes.
%%%
%%% `SecretKey' is a binary of size 64-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_sha2_128s_simple_keypair(<<0:(48 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(48),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_sha2_128s_simple_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_sha2_128s_simple_keypair/0
%%% @see sphincs_plus_sha2_128s_simple_sign/2
%%% @see sphincs_plus_sha2_128s_simple_verify/3
%%% @end
-spec sphincs_plus_sha2_128s_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_sha2_128s_simple_seed(),
    PublicKey :: sphincs_plus_sha2_128s_simple_public_key(),
    SecretKey :: sphincs_plus_sha2_128s_simple_secret_key().
sphincs_plus_sha2_128s_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-sha2-128s-simple Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 64-bytes generated from `sphincs_plus_sha2_128s_simple_keypair/0' or `sphincs_plus_sha2_128s_simple_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 7,856-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_128s_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_sha2_128s_simple_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_sha2_128s_simple_verify/3
%%% @end
-spec sphincs_plus_sha2_128s_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_sha2_128s_simple_message(),
    SecretKey :: sphincs_plus_sha2_128s_simple_secret_key(),
    Signature :: sphincs_plus_sha2_128s_simple_signature().
sphincs_plus_sha2_128s_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-sha2-128s-simple Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 7,856-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 32-bytes generated from `sphincs_plus_sha2_128s_simple_keypair/0' or `sphincs_plus_sha2_128s_simple_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_128s_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_sha2_128s_simple_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_sha2_128s_simple_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_sha2_128s_simple_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_sha2_128s_simple_sign/2
%%% @end
-spec sphincs_plus_sha2_128s_simple_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_sha2_128s_simple_signature(),
    Message :: sphincs_plus_sha2_128s_simple_message(),
    PublicKey :: sphincs_plus_sha2_128s_simple_public_key(),
    Verification :: sphincs_plus_sha2_128s_simple_verification().
sphincs_plus_sha2_128s_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-sha2-192f-robust
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-sha2-192f-robust",
%%%     secretkeybytes := 96,
%%%     publickeybytes := 48,
%%%     signaturebytes := 35664,
%%%     seedbytes := 72
%%% } = pqclean_nif:sphincs_plus_sha2_192f_robust_info()
%%% '''
%%%
%%% @see sphincs_plus_sha2_192f_robust_keypair/0
%%% @see sphincs_plus_sha2_192f_robust_keypair/1
%%% @see sphincs_plus_sha2_192f_robust_sign/2
%%% @see sphincs_plus_sha2_192f_robust_verify/3
%%% @end
-spec sphincs_plus_sha2_192f_robust_info() -> crypto_sign_info().
sphincs_plus_sha2_192f_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-sha2-192f-robust Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 48-bytes.
%%%
%%% `SecretKey' is a binary of size 96-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_192f_robust_keypair().
%%% '''
%%%
%%% @see sphincs_plus_sha2_192f_robust_keypair/1
%%% @see sphincs_plus_sha2_192f_robust_sign/2
%%% @see sphincs_plus_sha2_192f_robust_verify/3
%%% @end
-spec sphincs_plus_sha2_192f_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_sha2_192f_robust_public_key(), SecretKey :: sphincs_plus_sha2_192f_robust_secret_key().
sphincs_plus_sha2_192f_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-sha2-192f-robust Signature Algorithm.
%%%
%%% `Seed' is a binary of size 72-bytes.
%%%
%%% `PublicKey' is a binary of size 48-bytes.
%%%
%%% `SecretKey' is a binary of size 96-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_sha2_192f_robust_keypair(<<0:(72 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(72),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_sha2_192f_robust_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_sha2_192f_robust_keypair/0
%%% @see sphincs_plus_sha2_192f_robust_sign/2
%%% @see sphincs_plus_sha2_192f_robust_verify/3
%%% @end
-spec sphincs_plus_sha2_192f_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_sha2_192f_robust_seed(),
    PublicKey :: sphincs_plus_sha2_192f_robust_public_key(),
    SecretKey :: sphincs_plus_sha2_192f_robust_secret_key().
sphincs_plus_sha2_192f_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-sha2-192f-robust Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 96-bytes generated from `sphincs_plus_sha2_192f_robust_keypair/0' or `sphincs_plus_sha2_192f_robust_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 35,664-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_192f_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_sha2_192f_robust_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_sha2_192f_robust_verify/3
%%% @end
-spec sphincs_plus_sha2_192f_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_sha2_192f_robust_message(),
    SecretKey :: sphincs_plus_sha2_192f_robust_secret_key(),
    Signature :: sphincs_plus_sha2_192f_robust_signature().
sphincs_plus_sha2_192f_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-sha2-192f-robust Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 35,664-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 48-bytes generated from `sphincs_plus_sha2_192f_robust_keypair/0' or `sphincs_plus_sha2_192f_robust_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_192f_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_sha2_192f_robust_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_sha2_192f_robust_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_sha2_192f_robust_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_sha2_192f_robust_sign/2
%%% @end
-spec sphincs_plus_sha2_192f_robust_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_sha2_192f_robust_signature(),
    Message :: sphincs_plus_sha2_192f_robust_message(),
    PublicKey :: sphincs_plus_sha2_192f_robust_public_key(),
    Verification :: sphincs_plus_sha2_192f_robust_verification().
sphincs_plus_sha2_192f_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-sha2-192f-simple
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-sha2-192f-simple",
%%%     secretkeybytes := 96,
%%%     publickeybytes := 48,
%%%     signaturebytes := 35664,
%%%     seedbytes := 72
%%% } = pqclean_nif:sphincs_plus_sha2_192f_simple_info()
%%% '''
%%%
%%% @see sphincs_plus_sha2_192f_simple_keypair/0
%%% @see sphincs_plus_sha2_192f_simple_keypair/1
%%% @see sphincs_plus_sha2_192f_simple_sign/2
%%% @see sphincs_plus_sha2_192f_simple_verify/3
%%% @end
-spec sphincs_plus_sha2_192f_simple_info() -> crypto_sign_info().
sphincs_plus_sha2_192f_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-sha2-192f-simple Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 48-bytes.
%%%
%%% `SecretKey' is a binary of size 96-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_192f_simple_keypair().
%%% '''
%%%
%%% @see sphincs_plus_sha2_192f_simple_keypair/1
%%% @see sphincs_plus_sha2_192f_simple_sign/2
%%% @see sphincs_plus_sha2_192f_simple_verify/3
%%% @end
-spec sphincs_plus_sha2_192f_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_sha2_192f_simple_public_key(), SecretKey :: sphincs_plus_sha2_192f_simple_secret_key().
sphincs_plus_sha2_192f_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-sha2-192f-simple Signature Algorithm.
%%%
%%% `Seed' is a binary of size 72-bytes.
%%%
%%% `PublicKey' is a binary of size 48-bytes.
%%%
%%% `SecretKey' is a binary of size 96-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_sha2_192f_simple_keypair(<<0:(72 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(72),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_sha2_192f_simple_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_sha2_192f_simple_keypair/0
%%% @see sphincs_plus_sha2_192f_simple_sign/2
%%% @see sphincs_plus_sha2_192f_simple_verify/3
%%% @end
-spec sphincs_plus_sha2_192f_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_sha2_192f_simple_seed(),
    PublicKey :: sphincs_plus_sha2_192f_simple_public_key(),
    SecretKey :: sphincs_plus_sha2_192f_simple_secret_key().
sphincs_plus_sha2_192f_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-sha2-192f-simple Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 96-bytes generated from `sphincs_plus_sha2_192f_simple_keypair/0' or `sphincs_plus_sha2_192f_simple_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 35,664-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_192f_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_sha2_192f_simple_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_sha2_192f_simple_verify/3
%%% @end
-spec sphincs_plus_sha2_192f_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_sha2_192f_simple_message(),
    SecretKey :: sphincs_plus_sha2_192f_simple_secret_key(),
    Signature :: sphincs_plus_sha2_192f_simple_signature().
sphincs_plus_sha2_192f_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-sha2-192f-simple Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 35,664-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 48-bytes generated from `sphincs_plus_sha2_192f_simple_keypair/0' or `sphincs_plus_sha2_192f_simple_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_192f_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_sha2_192f_simple_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_sha2_192f_simple_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_sha2_192f_simple_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_sha2_192f_simple_sign/2
%%% @end
-spec sphincs_plus_sha2_192f_simple_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_sha2_192f_simple_signature(),
    Message :: sphincs_plus_sha2_192f_simple_message(),
    PublicKey :: sphincs_plus_sha2_192f_simple_public_key(),
    Verification :: sphincs_plus_sha2_192f_simple_verification().
sphincs_plus_sha2_192f_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-sha2-192s-robust
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-sha2-192s-robust",
%%%     secretkeybytes := 96,
%%%     publickeybytes := 48,
%%%     signaturebytes := 16224,
%%%     seedbytes := 72
%%% } = pqclean_nif:sphincs_plus_sha2_192s_robust_info()
%%% '''
%%%
%%% @see sphincs_plus_sha2_192s_robust_keypair/0
%%% @see sphincs_plus_sha2_192s_robust_keypair/1
%%% @see sphincs_plus_sha2_192s_robust_sign/2
%%% @see sphincs_plus_sha2_192s_robust_verify/3
%%% @end
-spec sphincs_plus_sha2_192s_robust_info() -> crypto_sign_info().
sphincs_plus_sha2_192s_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-sha2-192s-robust Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 48-bytes.
%%%
%%% `SecretKey' is a binary of size 96-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_192s_robust_keypair().
%%% '''
%%%
%%% @see sphincs_plus_sha2_192s_robust_keypair/1
%%% @see sphincs_plus_sha2_192s_robust_sign/2
%%% @see sphincs_plus_sha2_192s_robust_verify/3
%%% @end
-spec sphincs_plus_sha2_192s_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_sha2_192s_robust_public_key(), SecretKey :: sphincs_plus_sha2_192s_robust_secret_key().
sphincs_plus_sha2_192s_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-sha2-192s-robust Signature Algorithm.
%%%
%%% `Seed' is a binary of size 72-bytes.
%%%
%%% `PublicKey' is a binary of size 48-bytes.
%%%
%%% `SecretKey' is a binary of size 96-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_sha2_192s_robust_keypair(<<0:(72 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(72),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_sha2_192s_robust_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_sha2_192s_robust_keypair/0
%%% @see sphincs_plus_sha2_192s_robust_sign/2
%%% @see sphincs_plus_sha2_192s_robust_verify/3
%%% @end
-spec sphincs_plus_sha2_192s_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_sha2_192s_robust_seed(),
    PublicKey :: sphincs_plus_sha2_192s_robust_public_key(),
    SecretKey :: sphincs_plus_sha2_192s_robust_secret_key().
sphincs_plus_sha2_192s_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-sha2-192s-robust Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 96-bytes generated from `sphincs_plus_sha2_192s_robust_keypair/0' or `sphincs_plus_sha2_192s_robust_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 16,224-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_192s_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_sha2_192s_robust_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_sha2_192s_robust_verify/3
%%% @end
-spec sphincs_plus_sha2_192s_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_sha2_192s_robust_message(),
    SecretKey :: sphincs_plus_sha2_192s_robust_secret_key(),
    Signature :: sphincs_plus_sha2_192s_robust_signature().
sphincs_plus_sha2_192s_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-sha2-192s-robust Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 16,224-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 48-bytes generated from `sphincs_plus_sha2_192s_robust_keypair/0' or `sphincs_plus_sha2_192s_robust_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_192s_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_sha2_192s_robust_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_sha2_192s_robust_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_sha2_192s_robust_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_sha2_192s_robust_sign/2
%%% @end
-spec sphincs_plus_sha2_192s_robust_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_sha2_192s_robust_signature(),
    Message :: sphincs_plus_sha2_192s_robust_message(),
    PublicKey :: sphincs_plus_sha2_192s_robust_public_key(),
    Verification :: sphincs_plus_sha2_192s_robust_verification().
sphincs_plus_sha2_192s_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-sha2-192s-simple
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-sha2-192s-simple",
%%%     secretkeybytes := 96,
%%%     publickeybytes := 48,
%%%     signaturebytes := 16224,
%%%     seedbytes := 72
%%% } = pqclean_nif:sphincs_plus_sha2_192s_simple_info()
%%% '''
%%%
%%% @see sphincs_plus_sha2_192s_simple_keypair/0
%%% @see sphincs_plus_sha2_192s_simple_keypair/1
%%% @see sphincs_plus_sha2_192s_simple_sign/2
%%% @see sphincs_plus_sha2_192s_simple_verify/3
%%% @end
-spec sphincs_plus_sha2_192s_simple_info() -> crypto_sign_info().
sphincs_plus_sha2_192s_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-sha2-192s-simple Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 48-bytes.
%%%
%%% `SecretKey' is a binary of size 96-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_192s_simple_keypair().
%%% '''
%%%
%%% @see sphincs_plus_sha2_192s_simple_keypair/1
%%% @see sphincs_plus_sha2_192s_simple_sign/2
%%% @see sphincs_plus_sha2_192s_simple_verify/3
%%% @end
-spec sphincs_plus_sha2_192s_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_sha2_192s_simple_public_key(), SecretKey :: sphincs_plus_sha2_192s_simple_secret_key().
sphincs_plus_sha2_192s_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-sha2-192s-simple Signature Algorithm.
%%%
%%% `Seed' is a binary of size 72-bytes.
%%%
%%% `PublicKey' is a binary of size 48-bytes.
%%%
%%% `SecretKey' is a binary of size 96-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_sha2_192s_simple_keypair(<<0:(72 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(72),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_sha2_192s_simple_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_sha2_192s_simple_keypair/0
%%% @see sphincs_plus_sha2_192s_simple_sign/2
%%% @see sphincs_plus_sha2_192s_simple_verify/3
%%% @end
-spec sphincs_plus_sha2_192s_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_sha2_192s_simple_seed(),
    PublicKey :: sphincs_plus_sha2_192s_simple_public_key(),
    SecretKey :: sphincs_plus_sha2_192s_simple_secret_key().
sphincs_plus_sha2_192s_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-sha2-192s-simple Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 96-bytes generated from `sphincs_plus_sha2_192s_simple_keypair/0' or `sphincs_plus_sha2_192s_simple_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 16,224-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_192s_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_sha2_192s_simple_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_sha2_192s_simple_verify/3
%%% @end
-spec sphincs_plus_sha2_192s_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_sha2_192s_simple_message(),
    SecretKey :: sphincs_plus_sha2_192s_simple_secret_key(),
    Signature :: sphincs_plus_sha2_192s_simple_signature().
sphincs_plus_sha2_192s_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-sha2-192s-simple Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 16,224-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 48-bytes generated from `sphincs_plus_sha2_192s_simple_keypair/0' or `sphincs_plus_sha2_192s_simple_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_192s_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_sha2_192s_simple_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_sha2_192s_simple_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_sha2_192s_simple_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_sha2_192s_simple_sign/2
%%% @end
-spec sphincs_plus_sha2_192s_simple_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_sha2_192s_simple_signature(),
    Message :: sphincs_plus_sha2_192s_simple_message(),
    PublicKey :: sphincs_plus_sha2_192s_simple_public_key(),
    Verification :: sphincs_plus_sha2_192s_simple_verification().
sphincs_plus_sha2_192s_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-sha2-256f-robust
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-sha2-256f-robust",
%%%     secretkeybytes := 128,
%%%     publickeybytes := 64,
%%%     signaturebytes := 49856,
%%%     seedbytes := 96
%%% } = pqclean_nif:sphincs_plus_sha2_256f_robust_info()
%%% '''
%%%
%%% @see sphincs_plus_sha2_256f_robust_keypair/0
%%% @see sphincs_plus_sha2_256f_robust_keypair/1
%%% @see sphincs_plus_sha2_256f_robust_sign/2
%%% @see sphincs_plus_sha2_256f_robust_verify/3
%%% @end
-spec sphincs_plus_sha2_256f_robust_info() -> crypto_sign_info().
sphincs_plus_sha2_256f_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-sha2-256f-robust Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 64-bytes.
%%%
%%% `SecretKey' is a binary of size 128-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_256f_robust_keypair().
%%% '''
%%%
%%% @see sphincs_plus_sha2_256f_robust_keypair/1
%%% @see sphincs_plus_sha2_256f_robust_sign/2
%%% @see sphincs_plus_sha2_256f_robust_verify/3
%%% @end
-spec sphincs_plus_sha2_256f_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_sha2_256f_robust_public_key(), SecretKey :: sphincs_plus_sha2_256f_robust_secret_key().
sphincs_plus_sha2_256f_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-sha2-256f-robust Signature Algorithm.
%%%
%%% `Seed' is a binary of size 96-bytes.
%%%
%%% `PublicKey' is a binary of size 64-bytes.
%%%
%%% `SecretKey' is a binary of size 128-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_sha2_256f_robust_keypair(<<0:(96 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(96),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_sha2_256f_robust_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_sha2_256f_robust_keypair/0
%%% @see sphincs_plus_sha2_256f_robust_sign/2
%%% @see sphincs_plus_sha2_256f_robust_verify/3
%%% @end
-spec sphincs_plus_sha2_256f_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_sha2_256f_robust_seed(),
    PublicKey :: sphincs_plus_sha2_256f_robust_public_key(),
    SecretKey :: sphincs_plus_sha2_256f_robust_secret_key().
sphincs_plus_sha2_256f_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-sha2-256f-robust Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 128-bytes generated from `sphincs_plus_sha2_256f_robust_keypair/0' or `sphincs_plus_sha2_256f_robust_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 49,856-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_256f_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_sha2_256f_robust_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_sha2_256f_robust_verify/3
%%% @end
-spec sphincs_plus_sha2_256f_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_sha2_256f_robust_message(),
    SecretKey :: sphincs_plus_sha2_256f_robust_secret_key(),
    Signature :: sphincs_plus_sha2_256f_robust_signature().
sphincs_plus_sha2_256f_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-sha2-256f-robust Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 49,856-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 64-bytes generated from `sphincs_plus_sha2_256f_robust_keypair/0' or `sphincs_plus_sha2_256f_robust_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_256f_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_sha2_256f_robust_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_sha2_256f_robust_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_sha2_256f_robust_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_sha2_256f_robust_sign/2
%%% @end
-spec sphincs_plus_sha2_256f_robust_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_sha2_256f_robust_signature(),
    Message :: sphincs_plus_sha2_256f_robust_message(),
    PublicKey :: sphincs_plus_sha2_256f_robust_public_key(),
    Verification :: sphincs_plus_sha2_256f_robust_verification().
sphincs_plus_sha2_256f_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-sha2-256f-simple
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-sha2-256f-simple",
%%%     secretkeybytes := 128,
%%%     publickeybytes := 64,
%%%     signaturebytes := 49856,
%%%     seedbytes := 96
%%% } = pqclean_nif:sphincs_plus_sha2_256f_simple_info()
%%% '''
%%%
%%% @see sphincs_plus_sha2_256f_simple_keypair/0
%%% @see sphincs_plus_sha2_256f_simple_keypair/1
%%% @see sphincs_plus_sha2_256f_simple_sign/2
%%% @see sphincs_plus_sha2_256f_simple_verify/3
%%% @end
-spec sphincs_plus_sha2_256f_simple_info() -> crypto_sign_info().
sphincs_plus_sha2_256f_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-sha2-256f-simple Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 64-bytes.
%%%
%%% `SecretKey' is a binary of size 128-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_256f_simple_keypair().
%%% '''
%%%
%%% @see sphincs_plus_sha2_256f_simple_keypair/1
%%% @see sphincs_plus_sha2_256f_simple_sign/2
%%% @see sphincs_plus_sha2_256f_simple_verify/3
%%% @end
-spec sphincs_plus_sha2_256f_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_sha2_256f_simple_public_key(), SecretKey :: sphincs_plus_sha2_256f_simple_secret_key().
sphincs_plus_sha2_256f_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-sha2-256f-simple Signature Algorithm.
%%%
%%% `Seed' is a binary of size 96-bytes.
%%%
%%% `PublicKey' is a binary of size 64-bytes.
%%%
%%% `SecretKey' is a binary of size 128-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_sha2_256f_simple_keypair(<<0:(96 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(96),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_sha2_256f_simple_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_sha2_256f_simple_keypair/0
%%% @see sphincs_plus_sha2_256f_simple_sign/2
%%% @see sphincs_plus_sha2_256f_simple_verify/3
%%% @end
-spec sphincs_plus_sha2_256f_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_sha2_256f_simple_seed(),
    PublicKey :: sphincs_plus_sha2_256f_simple_public_key(),
    SecretKey :: sphincs_plus_sha2_256f_simple_secret_key().
sphincs_plus_sha2_256f_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-sha2-256f-simple Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 128-bytes generated from `sphincs_plus_sha2_256f_simple_keypair/0' or `sphincs_plus_sha2_256f_simple_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 49,856-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_256f_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_sha2_256f_simple_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_sha2_256f_simple_verify/3
%%% @end
-spec sphincs_plus_sha2_256f_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_sha2_256f_simple_message(),
    SecretKey :: sphincs_plus_sha2_256f_simple_secret_key(),
    Signature :: sphincs_plus_sha2_256f_simple_signature().
sphincs_plus_sha2_256f_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-sha2-256f-simple Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 49,856-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 64-bytes generated from `sphincs_plus_sha2_256f_simple_keypair/0' or `sphincs_plus_sha2_256f_simple_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_256f_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_sha2_256f_simple_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_sha2_256f_simple_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_sha2_256f_simple_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_sha2_256f_simple_sign/2
%%% @end
-spec sphincs_plus_sha2_256f_simple_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_sha2_256f_simple_signature(),
    Message :: sphincs_plus_sha2_256f_simple_message(),
    PublicKey :: sphincs_plus_sha2_256f_simple_public_key(),
    Verification :: sphincs_plus_sha2_256f_simple_verification().
sphincs_plus_sha2_256f_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-sha2-256s-robust
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-sha2-256s-robust",
%%%     secretkeybytes := 128,
%%%     publickeybytes := 64,
%%%     signaturebytes := 29792,
%%%     seedbytes := 96
%%% } = pqclean_nif:sphincs_plus_sha2_256s_robust_info()
%%% '''
%%%
%%% @see sphincs_plus_sha2_256s_robust_keypair/0
%%% @see sphincs_plus_sha2_256s_robust_keypair/1
%%% @see sphincs_plus_sha2_256s_robust_sign/2
%%% @see sphincs_plus_sha2_256s_robust_verify/3
%%% @end
-spec sphincs_plus_sha2_256s_robust_info() -> crypto_sign_info().
sphincs_plus_sha2_256s_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-sha2-256s-robust Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 64-bytes.
%%%
%%% `SecretKey' is a binary of size 128-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_256s_robust_keypair().
%%% '''
%%%
%%% @see sphincs_plus_sha2_256s_robust_keypair/1
%%% @see sphincs_plus_sha2_256s_robust_sign/2
%%% @see sphincs_plus_sha2_256s_robust_verify/3
%%% @end
-spec sphincs_plus_sha2_256s_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_sha2_256s_robust_public_key(), SecretKey :: sphincs_plus_sha2_256s_robust_secret_key().
sphincs_plus_sha2_256s_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-sha2-256s-robust Signature Algorithm.
%%%
%%% `Seed' is a binary of size 96-bytes.
%%%
%%% `PublicKey' is a binary of size 64-bytes.
%%%
%%% `SecretKey' is a binary of size 128-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_sha2_256s_robust_keypair(<<0:(96 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(96),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_sha2_256s_robust_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_sha2_256s_robust_keypair/0
%%% @see sphincs_plus_sha2_256s_robust_sign/2
%%% @see sphincs_plus_sha2_256s_robust_verify/3
%%% @end
-spec sphincs_plus_sha2_256s_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_sha2_256s_robust_seed(),
    PublicKey :: sphincs_plus_sha2_256s_robust_public_key(),
    SecretKey :: sphincs_plus_sha2_256s_robust_secret_key().
sphincs_plus_sha2_256s_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-sha2-256s-robust Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 128-bytes generated from `sphincs_plus_sha2_256s_robust_keypair/0' or `sphincs_plus_sha2_256s_robust_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 29,792-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_256s_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_sha2_256s_robust_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_sha2_256s_robust_verify/3
%%% @end
-spec sphincs_plus_sha2_256s_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_sha2_256s_robust_message(),
    SecretKey :: sphincs_plus_sha2_256s_robust_secret_key(),
    Signature :: sphincs_plus_sha2_256s_robust_signature().
sphincs_plus_sha2_256s_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-sha2-256s-robust Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 29,792-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 64-bytes generated from `sphincs_plus_sha2_256s_robust_keypair/0' or `sphincs_plus_sha2_256s_robust_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_256s_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_sha2_256s_robust_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_sha2_256s_robust_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_sha2_256s_robust_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_sha2_256s_robust_sign/2
%%% @end
-spec sphincs_plus_sha2_256s_robust_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_sha2_256s_robust_signature(),
    Message :: sphincs_plus_sha2_256s_robust_message(),
    PublicKey :: sphincs_plus_sha2_256s_robust_public_key(),
    Verification :: sphincs_plus_sha2_256s_robust_verification().
sphincs_plus_sha2_256s_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-sha2-256s-simple
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-sha2-256s-simple",
%%%     secretkeybytes := 128,
%%%     publickeybytes := 64,
%%%     signaturebytes := 29792,
%%%     seedbytes := 96
%%% } = pqclean_nif:sphincs_plus_sha2_256s_simple_info()
%%% '''
%%%
%%% @see sphincs_plus_sha2_256s_simple_keypair/0
%%% @see sphincs_plus_sha2_256s_simple_keypair/1
%%% @see sphincs_plus_sha2_256s_simple_sign/2
%%% @see sphincs_plus_sha2_256s_simple_verify/3
%%% @end
-spec sphincs_plus_sha2_256s_simple_info() -> crypto_sign_info().
sphincs_plus_sha2_256s_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-sha2-256s-simple Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 64-bytes.
%%%
%%% `SecretKey' is a binary of size 128-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_256s_simple_keypair().
%%% '''
%%%
%%% @see sphincs_plus_sha2_256s_simple_keypair/1
%%% @see sphincs_plus_sha2_256s_simple_sign/2
%%% @see sphincs_plus_sha2_256s_simple_verify/3
%%% @end
-spec sphincs_plus_sha2_256s_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_sha2_256s_simple_public_key(), SecretKey :: sphincs_plus_sha2_256s_simple_secret_key().
sphincs_plus_sha2_256s_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-sha2-256s-simple Signature Algorithm.
%%%
%%% `Seed' is a binary of size 96-bytes.
%%%
%%% `PublicKey' is a binary of size 64-bytes.
%%%
%%% `SecretKey' is a binary of size 128-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_sha2_256s_simple_keypair(<<0:(96 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(96),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_sha2_256s_simple_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_sha2_256s_simple_keypair/0
%%% @see sphincs_plus_sha2_256s_simple_sign/2
%%% @see sphincs_plus_sha2_256s_simple_verify/3
%%% @end
-spec sphincs_plus_sha2_256s_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_sha2_256s_simple_seed(),
    PublicKey :: sphincs_plus_sha2_256s_simple_public_key(),
    SecretKey :: sphincs_plus_sha2_256s_simple_secret_key().
sphincs_plus_sha2_256s_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-sha2-256s-simple Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 128-bytes generated from `sphincs_plus_sha2_256s_simple_keypair/0' or `sphincs_plus_sha2_256s_simple_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 29,792-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_256s_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_sha2_256s_simple_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_sha2_256s_simple_verify/3
%%% @end
-spec sphincs_plus_sha2_256s_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_sha2_256s_simple_message(),
    SecretKey :: sphincs_plus_sha2_256s_simple_secret_key(),
    Signature :: sphincs_plus_sha2_256s_simple_signature().
sphincs_plus_sha2_256s_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-sha2-256s-simple Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 29,792-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 64-bytes generated from `sphincs_plus_sha2_256s_simple_keypair/0' or `sphincs_plus_sha2_256s_simple_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_sha2_256s_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_sha2_256s_simple_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_sha2_256s_simple_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_sha2_256s_simple_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_sha2_256s_simple_sign/2
%%% @end
-spec sphincs_plus_sha2_256s_simple_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_sha2_256s_simple_signature(),
    Message :: sphincs_plus_sha2_256s_simple_message(),
    PublicKey :: sphincs_plus_sha2_256s_simple_public_key(),
    Verification :: sphincs_plus_sha2_256s_simple_verification().
sphincs_plus_sha2_256s_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-shake-128f-robust
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-shake-128f-robust",
%%%     secretkeybytes := 64,
%%%     publickeybytes := 32,
%%%     signaturebytes := 17088,
%%%     seedbytes := 48
%%% } = pqclean_nif:sphincs_plus_shake_128f_robust_info()
%%% '''
%%%
%%% @see sphincs_plus_shake_128f_robust_keypair/0
%%% @see sphincs_plus_shake_128f_robust_keypair/1
%%% @see sphincs_plus_shake_128f_robust_sign/2
%%% @see sphincs_plus_shake_128f_robust_verify/3
%%% @end
-spec sphincs_plus_shake_128f_robust_info() -> crypto_sign_info().
sphincs_plus_shake_128f_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-shake-128f-robust Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 32-bytes.
%%%
%%% `SecretKey' is a binary of size 64-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_128f_robust_keypair().
%%% '''
%%%
%%% @see sphincs_plus_shake_128f_robust_keypair/1
%%% @see sphincs_plus_shake_128f_robust_sign/2
%%% @see sphincs_plus_shake_128f_robust_verify/3
%%% @end
-spec sphincs_plus_shake_128f_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_shake_128f_robust_public_key(), SecretKey :: sphincs_plus_shake_128f_robust_secret_key().
sphincs_plus_shake_128f_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-shake-128f-robust Signature Algorithm.
%%%
%%% `Seed' is a binary of size 48-bytes.
%%%
%%% `PublicKey' is a binary of size 32-bytes.
%%%
%%% `SecretKey' is a binary of size 64-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_shake_128f_robust_keypair(<<0:(48 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(48),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_shake_128f_robust_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_shake_128f_robust_keypair/0
%%% @see sphincs_plus_shake_128f_robust_sign/2
%%% @see sphincs_plus_shake_128f_robust_verify/3
%%% @end
-spec sphincs_plus_shake_128f_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_shake_128f_robust_seed(),
    PublicKey :: sphincs_plus_shake_128f_robust_public_key(),
    SecretKey :: sphincs_plus_shake_128f_robust_secret_key().
sphincs_plus_shake_128f_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-shake-128f-robust Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 64-bytes generated from `sphincs_plus_shake_128f_robust_keypair/0' or `sphincs_plus_shake_128f_robust_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 17,088-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_128f_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_shake_128f_robust_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_shake_128f_robust_verify/3
%%% @end
-spec sphincs_plus_shake_128f_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_shake_128f_robust_message(),
    SecretKey :: sphincs_plus_shake_128f_robust_secret_key(),
    Signature :: sphincs_plus_shake_128f_robust_signature().
sphincs_plus_shake_128f_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-shake-128f-robust Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 17,088-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 32-bytes generated from `sphincs_plus_shake_128f_robust_keypair/0' or `sphincs_plus_shake_128f_robust_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_128f_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_shake_128f_robust_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_shake_128f_robust_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_shake_128f_robust_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_shake_128f_robust_sign/2
%%% @end
-spec sphincs_plus_shake_128f_robust_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_shake_128f_robust_signature(),
    Message :: sphincs_plus_shake_128f_robust_message(),
    PublicKey :: sphincs_plus_shake_128f_robust_public_key(),
    Verification :: sphincs_plus_shake_128f_robust_verification().
sphincs_plus_shake_128f_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-shake-128f-simple
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-shake-128f-simple",
%%%     secretkeybytes := 64,
%%%     publickeybytes := 32,
%%%     signaturebytes := 17088,
%%%     seedbytes := 48
%%% } = pqclean_nif:sphincs_plus_shake_128f_simple_info()
%%% '''
%%%
%%% @see sphincs_plus_shake_128f_simple_keypair/0
%%% @see sphincs_plus_shake_128f_simple_keypair/1
%%% @see sphincs_plus_shake_128f_simple_sign/2
%%% @see sphincs_plus_shake_128f_simple_verify/3
%%% @end
-spec sphincs_plus_shake_128f_simple_info() -> crypto_sign_info().
sphincs_plus_shake_128f_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-shake-128f-simple Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 32-bytes.
%%%
%%% `SecretKey' is a binary of size 64-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_128f_simple_keypair().
%%% '''
%%%
%%% @see sphincs_plus_shake_128f_simple_keypair/1
%%% @see sphincs_plus_shake_128f_simple_sign/2
%%% @see sphincs_plus_shake_128f_simple_verify/3
%%% @end
-spec sphincs_plus_shake_128f_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_shake_128f_simple_public_key(), SecretKey :: sphincs_plus_shake_128f_simple_secret_key().
sphincs_plus_shake_128f_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-shake-128f-simple Signature Algorithm.
%%%
%%% `Seed' is a binary of size 48-bytes.
%%%
%%% `PublicKey' is a binary of size 32-bytes.
%%%
%%% `SecretKey' is a binary of size 64-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_shake_128f_simple_keypair(<<0:(48 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(48),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_shake_128f_simple_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_shake_128f_simple_keypair/0
%%% @see sphincs_plus_shake_128f_simple_sign/2
%%% @see sphincs_plus_shake_128f_simple_verify/3
%%% @end
-spec sphincs_plus_shake_128f_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_shake_128f_simple_seed(),
    PublicKey :: sphincs_plus_shake_128f_simple_public_key(),
    SecretKey :: sphincs_plus_shake_128f_simple_secret_key().
sphincs_plus_shake_128f_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-shake-128f-simple Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 64-bytes generated from `sphincs_plus_shake_128f_simple_keypair/0' or `sphincs_plus_shake_128f_simple_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 17,088-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_128f_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_shake_128f_simple_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_shake_128f_simple_verify/3
%%% @end
-spec sphincs_plus_shake_128f_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_shake_128f_simple_message(),
    SecretKey :: sphincs_plus_shake_128f_simple_secret_key(),
    Signature :: sphincs_plus_shake_128f_simple_signature().
sphincs_plus_shake_128f_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-shake-128f-simple Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 17,088-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 32-bytes generated from `sphincs_plus_shake_128f_simple_keypair/0' or `sphincs_plus_shake_128f_simple_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_128f_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_shake_128f_simple_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_shake_128f_simple_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_shake_128f_simple_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_shake_128f_simple_sign/2
%%% @end
-spec sphincs_plus_shake_128f_simple_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_shake_128f_simple_signature(),
    Message :: sphincs_plus_shake_128f_simple_message(),
    PublicKey :: sphincs_plus_shake_128f_simple_public_key(),
    Verification :: sphincs_plus_shake_128f_simple_verification().
sphincs_plus_shake_128f_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-shake-128s-robust
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-shake-128s-robust",
%%%     secretkeybytes := 64,
%%%     publickeybytes := 32,
%%%     signaturebytes := 7856,
%%%     seedbytes := 48
%%% } = pqclean_nif:sphincs_plus_shake_128s_robust_info()
%%% '''
%%%
%%% @see sphincs_plus_shake_128s_robust_keypair/0
%%% @see sphincs_plus_shake_128s_robust_keypair/1
%%% @see sphincs_plus_shake_128s_robust_sign/2
%%% @see sphincs_plus_shake_128s_robust_verify/3
%%% @end
-spec sphincs_plus_shake_128s_robust_info() -> crypto_sign_info().
sphincs_plus_shake_128s_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-shake-128s-robust Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 32-bytes.
%%%
%%% `SecretKey' is a binary of size 64-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_128s_robust_keypair().
%%% '''
%%%
%%% @see sphincs_plus_shake_128s_robust_keypair/1
%%% @see sphincs_plus_shake_128s_robust_sign/2
%%% @see sphincs_plus_shake_128s_robust_verify/3
%%% @end
-spec sphincs_plus_shake_128s_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_shake_128s_robust_public_key(), SecretKey :: sphincs_plus_shake_128s_robust_secret_key().
sphincs_plus_shake_128s_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-shake-128s-robust Signature Algorithm.
%%%
%%% `Seed' is a binary of size 48-bytes.
%%%
%%% `PublicKey' is a binary of size 32-bytes.
%%%
%%% `SecretKey' is a binary of size 64-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_shake_128s_robust_keypair(<<0:(48 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(48),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_shake_128s_robust_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_shake_128s_robust_keypair/0
%%% @see sphincs_plus_shake_128s_robust_sign/2
%%% @see sphincs_plus_shake_128s_robust_verify/3
%%% @end
-spec sphincs_plus_shake_128s_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_shake_128s_robust_seed(),
    PublicKey :: sphincs_plus_shake_128s_robust_public_key(),
    SecretKey :: sphincs_plus_shake_128s_robust_secret_key().
sphincs_plus_shake_128s_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-shake-128s-robust Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 64-bytes generated from `sphincs_plus_shake_128s_robust_keypair/0' or `sphincs_plus_shake_128s_robust_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 7,856-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_128s_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_shake_128s_robust_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_shake_128s_robust_verify/3
%%% @end
-spec sphincs_plus_shake_128s_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_shake_128s_robust_message(),
    SecretKey :: sphincs_plus_shake_128s_robust_secret_key(),
    Signature :: sphincs_plus_shake_128s_robust_signature().
sphincs_plus_shake_128s_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-shake-128s-robust Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 7,856-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 32-bytes generated from `sphincs_plus_shake_128s_robust_keypair/0' or `sphincs_plus_shake_128s_robust_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_128s_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_shake_128s_robust_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_shake_128s_robust_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_shake_128s_robust_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_shake_128s_robust_sign/2
%%% @end
-spec sphincs_plus_shake_128s_robust_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_shake_128s_robust_signature(),
    Message :: sphincs_plus_shake_128s_robust_message(),
    PublicKey :: sphincs_plus_shake_128s_robust_public_key(),
    Verification :: sphincs_plus_shake_128s_robust_verification().
sphincs_plus_shake_128s_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-shake-128s-simple
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-shake-128s-simple",
%%%     secretkeybytes := 64,
%%%     publickeybytes := 32,
%%%     signaturebytes := 7856,
%%%     seedbytes := 48
%%% } = pqclean_nif:sphincs_plus_shake_128s_simple_info()
%%% '''
%%%
%%% @see sphincs_plus_shake_128s_simple_keypair/0
%%% @see sphincs_plus_shake_128s_simple_keypair/1
%%% @see sphincs_plus_shake_128s_simple_sign/2
%%% @see sphincs_plus_shake_128s_simple_verify/3
%%% @end
-spec sphincs_plus_shake_128s_simple_info() -> crypto_sign_info().
sphincs_plus_shake_128s_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-shake-128s-simple Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 32-bytes.
%%%
%%% `SecretKey' is a binary of size 64-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_128s_simple_keypair().
%%% '''
%%%
%%% @see sphincs_plus_shake_128s_simple_keypair/1
%%% @see sphincs_plus_shake_128s_simple_sign/2
%%% @see sphincs_plus_shake_128s_simple_verify/3
%%% @end
-spec sphincs_plus_shake_128s_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_shake_128s_simple_public_key(), SecretKey :: sphincs_plus_shake_128s_simple_secret_key().
sphincs_plus_shake_128s_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-shake-128s-simple Signature Algorithm.
%%%
%%% `Seed' is a binary of size 48-bytes.
%%%
%%% `PublicKey' is a binary of size 32-bytes.
%%%
%%% `SecretKey' is a binary of size 64-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_shake_128s_simple_keypair(<<0:(48 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(48),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_shake_128s_simple_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_shake_128s_simple_keypair/0
%%% @see sphincs_plus_shake_128s_simple_sign/2
%%% @see sphincs_plus_shake_128s_simple_verify/3
%%% @end
-spec sphincs_plus_shake_128s_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_shake_128s_simple_seed(),
    PublicKey :: sphincs_plus_shake_128s_simple_public_key(),
    SecretKey :: sphincs_plus_shake_128s_simple_secret_key().
sphincs_plus_shake_128s_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-shake-128s-simple Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 64-bytes generated from `sphincs_plus_shake_128s_simple_keypair/0' or `sphincs_plus_shake_128s_simple_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 7,856-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_128s_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_shake_128s_simple_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_shake_128s_simple_verify/3
%%% @end
-spec sphincs_plus_shake_128s_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_shake_128s_simple_message(),
    SecretKey :: sphincs_plus_shake_128s_simple_secret_key(),
    Signature :: sphincs_plus_shake_128s_simple_signature().
sphincs_plus_shake_128s_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-shake-128s-simple Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 7,856-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 32-bytes generated from `sphincs_plus_shake_128s_simple_keypair/0' or `sphincs_plus_shake_128s_simple_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_128s_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_shake_128s_simple_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_shake_128s_simple_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_shake_128s_simple_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_shake_128s_simple_sign/2
%%% @end
-spec sphincs_plus_shake_128s_simple_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_shake_128s_simple_signature(),
    Message :: sphincs_plus_shake_128s_simple_message(),
    PublicKey :: sphincs_plus_shake_128s_simple_public_key(),
    Verification :: sphincs_plus_shake_128s_simple_verification().
sphincs_plus_shake_128s_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-shake-192f-robust
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-shake-192f-robust",
%%%     secretkeybytes := 96,
%%%     publickeybytes := 48,
%%%     signaturebytes := 35664,
%%%     seedbytes := 72
%%% } = pqclean_nif:sphincs_plus_shake_192f_robust_info()
%%% '''
%%%
%%% @see sphincs_plus_shake_192f_robust_keypair/0
%%% @see sphincs_plus_shake_192f_robust_keypair/1
%%% @see sphincs_plus_shake_192f_robust_sign/2
%%% @see sphincs_plus_shake_192f_robust_verify/3
%%% @end
-spec sphincs_plus_shake_192f_robust_info() -> crypto_sign_info().
sphincs_plus_shake_192f_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-shake-192f-robust Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 48-bytes.
%%%
%%% `SecretKey' is a binary of size 96-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_192f_robust_keypair().
%%% '''
%%%
%%% @see sphincs_plus_shake_192f_robust_keypair/1
%%% @see sphincs_plus_shake_192f_robust_sign/2
%%% @see sphincs_plus_shake_192f_robust_verify/3
%%% @end
-spec sphincs_plus_shake_192f_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_shake_192f_robust_public_key(), SecretKey :: sphincs_plus_shake_192f_robust_secret_key().
sphincs_plus_shake_192f_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-shake-192f-robust Signature Algorithm.
%%%
%%% `Seed' is a binary of size 72-bytes.
%%%
%%% `PublicKey' is a binary of size 48-bytes.
%%%
%%% `SecretKey' is a binary of size 96-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_shake_192f_robust_keypair(<<0:(72 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(72),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_shake_192f_robust_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_shake_192f_robust_keypair/0
%%% @see sphincs_plus_shake_192f_robust_sign/2
%%% @see sphincs_plus_shake_192f_robust_verify/3
%%% @end
-spec sphincs_plus_shake_192f_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_shake_192f_robust_seed(),
    PublicKey :: sphincs_plus_shake_192f_robust_public_key(),
    SecretKey :: sphincs_plus_shake_192f_robust_secret_key().
sphincs_plus_shake_192f_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-shake-192f-robust Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 96-bytes generated from `sphincs_plus_shake_192f_robust_keypair/0' or `sphincs_plus_shake_192f_robust_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 35,664-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_192f_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_shake_192f_robust_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_shake_192f_robust_verify/3
%%% @end
-spec sphincs_plus_shake_192f_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_shake_192f_robust_message(),
    SecretKey :: sphincs_plus_shake_192f_robust_secret_key(),
    Signature :: sphincs_plus_shake_192f_robust_signature().
sphincs_plus_shake_192f_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-shake-192f-robust Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 35,664-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 48-bytes generated from `sphincs_plus_shake_192f_robust_keypair/0' or `sphincs_plus_shake_192f_robust_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_192f_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_shake_192f_robust_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_shake_192f_robust_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_shake_192f_robust_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_shake_192f_robust_sign/2
%%% @end
-spec sphincs_plus_shake_192f_robust_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_shake_192f_robust_signature(),
    Message :: sphincs_plus_shake_192f_robust_message(),
    PublicKey :: sphincs_plus_shake_192f_robust_public_key(),
    Verification :: sphincs_plus_shake_192f_robust_verification().
sphincs_plus_shake_192f_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-shake-192f-simple
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-shake-192f-simple",
%%%     secretkeybytes := 96,
%%%     publickeybytes := 48,
%%%     signaturebytes := 35664,
%%%     seedbytes := 72
%%% } = pqclean_nif:sphincs_plus_shake_192f_simple_info()
%%% '''
%%%
%%% @see sphincs_plus_shake_192f_simple_keypair/0
%%% @see sphincs_plus_shake_192f_simple_keypair/1
%%% @see sphincs_plus_shake_192f_simple_sign/2
%%% @see sphincs_plus_shake_192f_simple_verify/3
%%% @end
-spec sphincs_plus_shake_192f_simple_info() -> crypto_sign_info().
sphincs_plus_shake_192f_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-shake-192f-simple Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 48-bytes.
%%%
%%% `SecretKey' is a binary of size 96-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_192f_simple_keypair().
%%% '''
%%%
%%% @see sphincs_plus_shake_192f_simple_keypair/1
%%% @see sphincs_plus_shake_192f_simple_sign/2
%%% @see sphincs_plus_shake_192f_simple_verify/3
%%% @end
-spec sphincs_plus_shake_192f_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_shake_192f_simple_public_key(), SecretKey :: sphincs_plus_shake_192f_simple_secret_key().
sphincs_plus_shake_192f_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-shake-192f-simple Signature Algorithm.
%%%
%%% `Seed' is a binary of size 72-bytes.
%%%
%%% `PublicKey' is a binary of size 48-bytes.
%%%
%%% `SecretKey' is a binary of size 96-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_shake_192f_simple_keypair(<<0:(72 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(72),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_shake_192f_simple_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_shake_192f_simple_keypair/0
%%% @see sphincs_plus_shake_192f_simple_sign/2
%%% @see sphincs_plus_shake_192f_simple_verify/3
%%% @end
-spec sphincs_plus_shake_192f_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_shake_192f_simple_seed(),
    PublicKey :: sphincs_plus_shake_192f_simple_public_key(),
    SecretKey :: sphincs_plus_shake_192f_simple_secret_key().
sphincs_plus_shake_192f_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-shake-192f-simple Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 96-bytes generated from `sphincs_plus_shake_192f_simple_keypair/0' or `sphincs_plus_shake_192f_simple_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 35,664-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_192f_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_shake_192f_simple_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_shake_192f_simple_verify/3
%%% @end
-spec sphincs_plus_shake_192f_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_shake_192f_simple_message(),
    SecretKey :: sphincs_plus_shake_192f_simple_secret_key(),
    Signature :: sphincs_plus_shake_192f_simple_signature().
sphincs_plus_shake_192f_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-shake-192f-simple Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 35,664-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 48-bytes generated from `sphincs_plus_shake_192f_simple_keypair/0' or `sphincs_plus_shake_192f_simple_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_192f_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_shake_192f_simple_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_shake_192f_simple_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_shake_192f_simple_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_shake_192f_simple_sign/2
%%% @end
-spec sphincs_plus_shake_192f_simple_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_shake_192f_simple_signature(),
    Message :: sphincs_plus_shake_192f_simple_message(),
    PublicKey :: sphincs_plus_shake_192f_simple_public_key(),
    Verification :: sphincs_plus_shake_192f_simple_verification().
sphincs_plus_shake_192f_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-shake-192s-robust
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-shake-192s-robust",
%%%     secretkeybytes := 96,
%%%     publickeybytes := 48,
%%%     signaturebytes := 16224,
%%%     seedbytes := 72
%%% } = pqclean_nif:sphincs_plus_shake_192s_robust_info()
%%% '''
%%%
%%% @see sphincs_plus_shake_192s_robust_keypair/0
%%% @see sphincs_plus_shake_192s_robust_keypair/1
%%% @see sphincs_plus_shake_192s_robust_sign/2
%%% @see sphincs_plus_shake_192s_robust_verify/3
%%% @end
-spec sphincs_plus_shake_192s_robust_info() -> crypto_sign_info().
sphincs_plus_shake_192s_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-shake-192s-robust Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 48-bytes.
%%%
%%% `SecretKey' is a binary of size 96-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_192s_robust_keypair().
%%% '''
%%%
%%% @see sphincs_plus_shake_192s_robust_keypair/1
%%% @see sphincs_plus_shake_192s_robust_sign/2
%%% @see sphincs_plus_shake_192s_robust_verify/3
%%% @end
-spec sphincs_plus_shake_192s_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_shake_192s_robust_public_key(), SecretKey :: sphincs_plus_shake_192s_robust_secret_key().
sphincs_plus_shake_192s_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-shake-192s-robust Signature Algorithm.
%%%
%%% `Seed' is a binary of size 72-bytes.
%%%
%%% `PublicKey' is a binary of size 48-bytes.
%%%
%%% `SecretKey' is a binary of size 96-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_shake_192s_robust_keypair(<<0:(72 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(72),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_shake_192s_robust_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_shake_192s_robust_keypair/0
%%% @see sphincs_plus_shake_192s_robust_sign/2
%%% @see sphincs_plus_shake_192s_robust_verify/3
%%% @end
-spec sphincs_plus_shake_192s_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_shake_192s_robust_seed(),
    PublicKey :: sphincs_plus_shake_192s_robust_public_key(),
    SecretKey :: sphincs_plus_shake_192s_robust_secret_key().
sphincs_plus_shake_192s_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-shake-192s-robust Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 96-bytes generated from `sphincs_plus_shake_192s_robust_keypair/0' or `sphincs_plus_shake_192s_robust_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 16,224-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_192s_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_shake_192s_robust_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_shake_192s_robust_verify/3
%%% @end
-spec sphincs_plus_shake_192s_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_shake_192s_robust_message(),
    SecretKey :: sphincs_plus_shake_192s_robust_secret_key(),
    Signature :: sphincs_plus_shake_192s_robust_signature().
sphincs_plus_shake_192s_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-shake-192s-robust Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 16,224-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 48-bytes generated from `sphincs_plus_shake_192s_robust_keypair/0' or `sphincs_plus_shake_192s_robust_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_192s_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_shake_192s_robust_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_shake_192s_robust_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_shake_192s_robust_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_shake_192s_robust_sign/2
%%% @end
-spec sphincs_plus_shake_192s_robust_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_shake_192s_robust_signature(),
    Message :: sphincs_plus_shake_192s_robust_message(),
    PublicKey :: sphincs_plus_shake_192s_robust_public_key(),
    Verification :: sphincs_plus_shake_192s_robust_verification().
sphincs_plus_shake_192s_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-shake-192s-simple
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-shake-192s-simple",
%%%     secretkeybytes := 96,
%%%     publickeybytes := 48,
%%%     signaturebytes := 16224,
%%%     seedbytes := 72
%%% } = pqclean_nif:sphincs_plus_shake_192s_simple_info()
%%% '''
%%%
%%% @see sphincs_plus_shake_192s_simple_keypair/0
%%% @see sphincs_plus_shake_192s_simple_keypair/1
%%% @see sphincs_plus_shake_192s_simple_sign/2
%%% @see sphincs_plus_shake_192s_simple_verify/3
%%% @end
-spec sphincs_plus_shake_192s_simple_info() -> crypto_sign_info().
sphincs_plus_shake_192s_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-shake-192s-simple Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 48-bytes.
%%%
%%% `SecretKey' is a binary of size 96-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_192s_simple_keypair().
%%% '''
%%%
%%% @see sphincs_plus_shake_192s_simple_keypair/1
%%% @see sphincs_plus_shake_192s_simple_sign/2
%%% @see sphincs_plus_shake_192s_simple_verify/3
%%% @end
-spec sphincs_plus_shake_192s_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_shake_192s_simple_public_key(), SecretKey :: sphincs_plus_shake_192s_simple_secret_key().
sphincs_plus_shake_192s_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-shake-192s-simple Signature Algorithm.
%%%
%%% `Seed' is a binary of size 72-bytes.
%%%
%%% `PublicKey' is a binary of size 48-bytes.
%%%
%%% `SecretKey' is a binary of size 96-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_shake_192s_simple_keypair(<<0:(72 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(72),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_shake_192s_simple_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_shake_192s_simple_keypair/0
%%% @see sphincs_plus_shake_192s_simple_sign/2
%%% @see sphincs_plus_shake_192s_simple_verify/3
%%% @end
-spec sphincs_plus_shake_192s_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_shake_192s_simple_seed(),
    PublicKey :: sphincs_plus_shake_192s_simple_public_key(),
    SecretKey :: sphincs_plus_shake_192s_simple_secret_key().
sphincs_plus_shake_192s_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-shake-192s-simple Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 96-bytes generated from `sphincs_plus_shake_192s_simple_keypair/0' or `sphincs_plus_shake_192s_simple_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 16,224-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_192s_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_shake_192s_simple_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_shake_192s_simple_verify/3
%%% @end
-spec sphincs_plus_shake_192s_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_shake_192s_simple_message(),
    SecretKey :: sphincs_plus_shake_192s_simple_secret_key(),
    Signature :: sphincs_plus_shake_192s_simple_signature().
sphincs_plus_shake_192s_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-shake-192s-simple Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 16,224-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 48-bytes generated from `sphincs_plus_shake_192s_simple_keypair/0' or `sphincs_plus_shake_192s_simple_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_192s_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_shake_192s_simple_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_shake_192s_simple_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_shake_192s_simple_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_shake_192s_simple_sign/2
%%% @end
-spec sphincs_plus_shake_192s_simple_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_shake_192s_simple_signature(),
    Message :: sphincs_plus_shake_192s_simple_message(),
    PublicKey :: sphincs_plus_shake_192s_simple_public_key(),
    Verification :: sphincs_plus_shake_192s_simple_verification().
sphincs_plus_shake_192s_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-shake-256f-robust
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-shake-256f-robust",
%%%     secretkeybytes := 128,
%%%     publickeybytes := 64,
%%%     signaturebytes := 49856,
%%%     seedbytes := 96
%%% } = pqclean_nif:sphincs_plus_shake_256f_robust_info()
%%% '''
%%%
%%% @see sphincs_plus_shake_256f_robust_keypair/0
%%% @see sphincs_plus_shake_256f_robust_keypair/1
%%% @see sphincs_plus_shake_256f_robust_sign/2
%%% @see sphincs_plus_shake_256f_robust_verify/3
%%% @end
-spec sphincs_plus_shake_256f_robust_info() -> crypto_sign_info().
sphincs_plus_shake_256f_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-shake-256f-robust Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 64-bytes.
%%%
%%% `SecretKey' is a binary of size 128-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_256f_robust_keypair().
%%% '''
%%%
%%% @see sphincs_plus_shake_256f_robust_keypair/1
%%% @see sphincs_plus_shake_256f_robust_sign/2
%%% @see sphincs_plus_shake_256f_robust_verify/3
%%% @end
-spec sphincs_plus_shake_256f_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_shake_256f_robust_public_key(), SecretKey :: sphincs_plus_shake_256f_robust_secret_key().
sphincs_plus_shake_256f_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-shake-256f-robust Signature Algorithm.
%%%
%%% `Seed' is a binary of size 96-bytes.
%%%
%%% `PublicKey' is a binary of size 64-bytes.
%%%
%%% `SecretKey' is a binary of size 128-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_shake_256f_robust_keypair(<<0:(96 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(96),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_shake_256f_robust_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_shake_256f_robust_keypair/0
%%% @see sphincs_plus_shake_256f_robust_sign/2
%%% @see sphincs_plus_shake_256f_robust_verify/3
%%% @end
-spec sphincs_plus_shake_256f_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_shake_256f_robust_seed(),
    PublicKey :: sphincs_plus_shake_256f_robust_public_key(),
    SecretKey :: sphincs_plus_shake_256f_robust_secret_key().
sphincs_plus_shake_256f_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-shake-256f-robust Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 128-bytes generated from `sphincs_plus_shake_256f_robust_keypair/0' or `sphincs_plus_shake_256f_robust_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 49,856-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_256f_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_shake_256f_robust_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_shake_256f_robust_verify/3
%%% @end
-spec sphincs_plus_shake_256f_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_shake_256f_robust_message(),
    SecretKey :: sphincs_plus_shake_256f_robust_secret_key(),
    Signature :: sphincs_plus_shake_256f_robust_signature().
sphincs_plus_shake_256f_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-shake-256f-robust Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 49,856-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 64-bytes generated from `sphincs_plus_shake_256f_robust_keypair/0' or `sphincs_plus_shake_256f_robust_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_256f_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_shake_256f_robust_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_shake_256f_robust_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_shake_256f_robust_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_shake_256f_robust_sign/2
%%% @end
-spec sphincs_plus_shake_256f_robust_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_shake_256f_robust_signature(),
    Message :: sphincs_plus_shake_256f_robust_message(),
    PublicKey :: sphincs_plus_shake_256f_robust_public_key(),
    Verification :: sphincs_plus_shake_256f_robust_verification().
sphincs_plus_shake_256f_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-shake-256f-simple
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-shake-256f-simple",
%%%     secretkeybytes := 128,
%%%     publickeybytes := 64,
%%%     signaturebytes := 49856,
%%%     seedbytes := 96
%%% } = pqclean_nif:sphincs_plus_shake_256f_simple_info()
%%% '''
%%%
%%% @see sphincs_plus_shake_256f_simple_keypair/0
%%% @see sphincs_plus_shake_256f_simple_keypair/1
%%% @see sphincs_plus_shake_256f_simple_sign/2
%%% @see sphincs_plus_shake_256f_simple_verify/3
%%% @end
-spec sphincs_plus_shake_256f_simple_info() -> crypto_sign_info().
sphincs_plus_shake_256f_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-shake-256f-simple Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 64-bytes.
%%%
%%% `SecretKey' is a binary of size 128-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_256f_simple_keypair().
%%% '''
%%%
%%% @see sphincs_plus_shake_256f_simple_keypair/1
%%% @see sphincs_plus_shake_256f_simple_sign/2
%%% @see sphincs_plus_shake_256f_simple_verify/3
%%% @end
-spec sphincs_plus_shake_256f_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_shake_256f_simple_public_key(), SecretKey :: sphincs_plus_shake_256f_simple_secret_key().
sphincs_plus_shake_256f_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-shake-256f-simple Signature Algorithm.
%%%
%%% `Seed' is a binary of size 96-bytes.
%%%
%%% `PublicKey' is a binary of size 64-bytes.
%%%
%%% `SecretKey' is a binary of size 128-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_shake_256f_simple_keypair(<<0:(96 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(96),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_shake_256f_simple_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_shake_256f_simple_keypair/0
%%% @see sphincs_plus_shake_256f_simple_sign/2
%%% @see sphincs_plus_shake_256f_simple_verify/3
%%% @end
-spec sphincs_plus_shake_256f_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_shake_256f_simple_seed(),
    PublicKey :: sphincs_plus_shake_256f_simple_public_key(),
    SecretKey :: sphincs_plus_shake_256f_simple_secret_key().
sphincs_plus_shake_256f_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-shake-256f-simple Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 128-bytes generated from `sphincs_plus_shake_256f_simple_keypair/0' or `sphincs_plus_shake_256f_simple_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 49,856-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_256f_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_shake_256f_simple_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_shake_256f_simple_verify/3
%%% @end
-spec sphincs_plus_shake_256f_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_shake_256f_simple_message(),
    SecretKey :: sphincs_plus_shake_256f_simple_secret_key(),
    Signature :: sphincs_plus_shake_256f_simple_signature().
sphincs_plus_shake_256f_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-shake-256f-simple Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 49,856-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 64-bytes generated from `sphincs_plus_shake_256f_simple_keypair/0' or `sphincs_plus_shake_256f_simple_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_256f_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_shake_256f_simple_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_shake_256f_simple_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_shake_256f_simple_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_shake_256f_simple_sign/2
%%% @end
-spec sphincs_plus_shake_256f_simple_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_shake_256f_simple_signature(),
    Message :: sphincs_plus_shake_256f_simple_message(),
    PublicKey :: sphincs_plus_shake_256f_simple_public_key(),
    Verification :: sphincs_plus_shake_256f_simple_verification().
sphincs_plus_shake_256f_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-shake-256s-robust
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-shake-256s-robust",
%%%     secretkeybytes := 128,
%%%     publickeybytes := 64,
%%%     signaturebytes := 29792,
%%%     seedbytes := 96
%%% } = pqclean_nif:sphincs_plus_shake_256s_robust_info()
%%% '''
%%%
%%% @see sphincs_plus_shake_256s_robust_keypair/0
%%% @see sphincs_plus_shake_256s_robust_keypair/1
%%% @see sphincs_plus_shake_256s_robust_sign/2
%%% @see sphincs_plus_shake_256s_robust_verify/3
%%% @end
-spec sphincs_plus_shake_256s_robust_info() -> crypto_sign_info().
sphincs_plus_shake_256s_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-shake-256s-robust Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 64-bytes.
%%%
%%% `SecretKey' is a binary of size 128-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_256s_robust_keypair().
%%% '''
%%%
%%% @see sphincs_plus_shake_256s_robust_keypair/1
%%% @see sphincs_plus_shake_256s_robust_sign/2
%%% @see sphincs_plus_shake_256s_robust_verify/3
%%% @end
-spec sphincs_plus_shake_256s_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_shake_256s_robust_public_key(), SecretKey :: sphincs_plus_shake_256s_robust_secret_key().
sphincs_plus_shake_256s_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-shake-256s-robust Signature Algorithm.
%%%
%%% `Seed' is a binary of size 96-bytes.
%%%
%%% `PublicKey' is a binary of size 64-bytes.
%%%
%%% `SecretKey' is a binary of size 128-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_shake_256s_robust_keypair(<<0:(96 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(96),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_shake_256s_robust_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_shake_256s_robust_keypair/0
%%% @see sphincs_plus_shake_256s_robust_sign/2
%%% @see sphincs_plus_shake_256s_robust_verify/3
%%% @end
-spec sphincs_plus_shake_256s_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_shake_256s_robust_seed(),
    PublicKey :: sphincs_plus_shake_256s_robust_public_key(),
    SecretKey :: sphincs_plus_shake_256s_robust_secret_key().
sphincs_plus_shake_256s_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-shake-256s-robust Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 128-bytes generated from `sphincs_plus_shake_256s_robust_keypair/0' or `sphincs_plus_shake_256s_robust_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 29,792-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_256s_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_shake_256s_robust_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_shake_256s_robust_verify/3
%%% @end
-spec sphincs_plus_shake_256s_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_shake_256s_robust_message(),
    SecretKey :: sphincs_plus_shake_256s_robust_secret_key(),
    Signature :: sphincs_plus_shake_256s_robust_signature().
sphincs_plus_shake_256s_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-shake-256s-robust Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 29,792-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 64-bytes generated from `sphincs_plus_shake_256s_robust_keypair/0' or `sphincs_plus_shake_256s_robust_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_256s_robust_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_shake_256s_robust_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_shake_256s_robust_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_shake_256s_robust_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_shake_256s_robust_sign/2
%%% @end
-spec sphincs_plus_shake_256s_robust_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_shake_256s_robust_signature(),
    Message :: sphincs_plus_shake_256s_robust_message(),
    PublicKey :: sphincs_plus_shake_256s_robust_public_key(),
    Verification :: sphincs_plus_shake_256s_robust_verification().
sphincs_plus_shake_256s_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Returns information about the SPHINCS+-shake-256s-simple
%%% <a href="https://en.wikipedia.org/wiki/Digital_signature">Signature</a> Algorithm.
%%%
%%% ```
%%% #{
%%%     type := sign,
%%%     name := "SPHINCS+-shake-256s-simple",
%%%     secretkeybytes := 128,
%%%     publickeybytes := 64,
%%%     signaturebytes := 29792,
%%%     seedbytes := 96
%%% } = pqclean_nif:sphincs_plus_shake_256s_simple_info()
%%% '''
%%%
%%% @see sphincs_plus_shake_256s_simple_keypair/0
%%% @see sphincs_plus_shake_256s_simple_keypair/1
%%% @see sphincs_plus_shake_256s_simple_sign/2
%%% @see sphincs_plus_shake_256s_simple_verify/3
%%% @end
-spec sphincs_plus_shake_256s_simple_info() -> crypto_sign_info().
sphincs_plus_shake_256s_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Randomly generates a new `PublicKey' and `SecretKey' keypair for the SPHINCS+-shake-256s-simple Signature Algorithm.
%%%
%%% `PublicKey' is a binary of size 64-bytes.
%%%
%%% `SecretKey' is a binary of size 128-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_256s_simple_keypair().
%%% '''
%%%
%%% @see sphincs_plus_shake_256s_simple_keypair/1
%%% @see sphincs_plus_shake_256s_simple_sign/2
%%% @see sphincs_plus_shake_256s_simple_verify/3
%%% @end
-spec sphincs_plus_shake_256s_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_shake_256s_simple_public_key(), SecretKey :: sphincs_plus_shake_256s_simple_secret_key().
sphincs_plus_shake_256s_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Derives a `PublicKey' and `SecretKey' keypair based on `Seed' for the SPHINCS+-shake-256s-simple Signature Algorithm.
%%%
%%% `Seed' is a binary of size 96-bytes.
%%%
%%% `PublicKey' is a binary of size 64-bytes.
%%%
%%% `SecretKey' is a binary of size 128-bytes.
%%% ```
%%% % WARNING: Example only, NEVER use an all-zero Seed!
%%% {ZeroPK, ZeroSK} = pqclean_nif:sphincs_plus_shake_256s_simple_keypair(<<0:(96 * 8)>>).
%%%
%%% % Randomly generated Seed:
%%% Seed = crypto:strong_rand_bytes(96),
%%% {SeedPK, SeedSK} = pqclean_nif:sphincs_plus_shake_256s_simple_keypair(Seed).
%%% '''
%%%
%%% @see sphincs_plus_shake_256s_simple_keypair/0
%%% @see sphincs_plus_shake_256s_simple_sign/2
%%% @see sphincs_plus_shake_256s_simple_verify/3
%%% @end
-spec sphincs_plus_shake_256s_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_shake_256s_simple_seed(),
    PublicKey :: sphincs_plus_shake_256s_simple_public_key(),
    SecretKey :: sphincs_plus_shake_256s_simple_secret_key().
sphincs_plus_shake_256s_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Signs a `Message' with `SecretKey' and returns a `Signature' using the SPHINCS+-shake-256s-simple Signature Algorithm.
%%%
%%% `Message' is a binary.
%%%
%%% `SecretKey' is a binary of size 128-bytes generated from `sphincs_plus_shake_256s_simple_keypair/0' or `sphincs_plus_shake_256s_simple_keypair/1'.
%%%
%%% `Signature' is a binary of maximum size 29,792-bytes.
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_256s_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_shake_256s_simple_sign(Msg, SK).
%%% '''
%%%
%%% @see sphincs_plus_shake_256s_simple_verify/3
%%% @end
-spec sphincs_plus_shake_256s_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_shake_256s_simple_message(),
    SecretKey :: sphincs_plus_shake_256s_simple_secret_key(),
    Signature :: sphincs_plus_shake_256s_simple_signature().
sphincs_plus_shake_256s_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%% @doc
%%% Verifies a `Signature' and `Message' with `PublicKey' and returns a `Verification' using the SPHINCS+-shake-256s-simple Signature Algorithm.
%%%
%%% `Signature' is a binary of maximum size 29,792-bytes.
%%%
%%% `Message' is a binary.
%%%
%%% `PublicKey' is a binary of size 64-bytes generated from `sphincs_plus_shake_256s_simple_keypair/0' or `sphincs_plus_shake_256s_simple_keypair/1'.
%%%
%%% `Verification' is a boolean (`true' if the `Signature' and `Message' are verified, `false' otherwise).
%%%
%%% ```
%%% {PK, SK} = pqclean_nif:sphincs_plus_shake_256s_simple_keypair(),
%%% Msg = <<"message">>,
%%% Sig = pqclean_nif:sphincs_plus_shake_256s_simple_sign(Msg, SK),
%%% true = pqclean_nif:sphincs_plus_shake_256s_simple_verify(Sig, Msg, PK).
%%%
%%% % Example of corrupted message:
%%% BadMsg = <<"messag0">>,
%%% false = pqclean_nif:sphincs_plus_shake_256s_simple_verify(Sig, BadMsg, PK).
%%% '''
%%%
%%% @see sphincs_plus_shake_256s_simple_sign/2
%%% @end
-spec sphincs_plus_shake_256s_simple_verify(Signature, Message, PublicKey) -> Verification when
    Signature :: sphincs_plus_shake_256s_simple_signature(),
    Message :: sphincs_plus_shake_256s_simple_message(),
    PublicKey :: sphincs_plus_shake_256s_simple_public_key(),
    Verification :: sphincs_plus_shake_256s_simple_verification().
sphincs_plus_shake_256s_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------

%% @private
-spec init() -> ok | Error when
    Error :: {error, {Reason, Text :: string()}},
    Reason :: load_failed | bad_lib | load | reload | upgrade | old_code.
init() ->
    SoName = filename:join([pqclean:priv_dir(), ?MODULE_STRING]),
    erlang:load_nif(SoName, 0).
