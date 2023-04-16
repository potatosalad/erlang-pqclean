%%% % @format
-module(pqclean_nif_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-behaviour(ct_suite).

%% ct callbacks
-export([
    all/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2
]).

%% Tests.
-export([
    test_hqc_rmrs_128_info_0/1,
    test_hqc_rmrs_128_keypair_0/1,
    test_hqc_rmrs_128_encapsulate_1/1,
    test_hqc_rmrs_128_decapsulate_2/1,
    test_hqc_rmrs_192_info_0/1,
    test_hqc_rmrs_192_keypair_0/1,
    test_hqc_rmrs_192_encapsulate_1/1,
    test_hqc_rmrs_192_decapsulate_2/1,
    test_hqc_rmrs_256_info_0/1,
    test_hqc_rmrs_256_keypair_0/1,
    test_hqc_rmrs_256_encapsulate_1/1,
    test_hqc_rmrs_256_decapsulate_2/1,
    test_kyber512_info_0/1,
    test_kyber512_keypair_0/1,
    test_kyber512_encapsulate_1/1,
    test_kyber512_decapsulate_2/1,
    test_kyber512_90s_info_0/1,
    test_kyber512_90s_keypair_0/1,
    test_kyber512_90s_encapsulate_1/1,
    test_kyber512_90s_decapsulate_2/1,
    test_kyber768_info_0/1,
    test_kyber768_keypair_0/1,
    test_kyber768_encapsulate_1/1,
    test_kyber768_decapsulate_2/1,
    test_kyber768_90s_info_0/1,
    test_kyber768_90s_keypair_0/1,
    test_kyber768_90s_encapsulate_1/1,
    test_kyber768_90s_decapsulate_2/1,
    test_kyber1024_info_0/1,
    test_kyber1024_keypair_0/1,
    test_kyber1024_encapsulate_1/1,
    test_kyber1024_decapsulate_2/1,
    test_kyber1024_90s_info_0/1,
    test_kyber1024_90s_keypair_0/1,
    test_kyber1024_90s_encapsulate_1/1,
    test_kyber1024_90s_decapsulate_2/1,
    test_dilithium2_info_0/1,
    test_dilithium2_keypair_0/1,
    test_dilithium2_sign_2/1,
    test_dilithium2_verify_3/1,
    test_dilithium2aes_info_0/1,
    test_dilithium2aes_keypair_0/1,
    test_dilithium2aes_sign_2/1,
    test_dilithium2aes_verify_3/1,
    test_dilithium3_info_0/1,
    test_dilithium3_keypair_0/1,
    test_dilithium3_sign_2/1,
    test_dilithium3_verify_3/1,
    test_dilithium3aes_info_0/1,
    test_dilithium3aes_keypair_0/1,
    test_dilithium3aes_sign_2/1,
    test_dilithium3aes_verify_3/1,
    test_dilithium5_info_0/1,
    test_dilithium5_keypair_0/1,
    test_dilithium5_sign_2/1,
    test_dilithium5_verify_3/1,
    test_dilithium5aes_info_0/1,
    test_dilithium5aes_keypair_0/1,
    test_dilithium5aes_sign_2/1,
    test_dilithium5aes_verify_3/1,
    test_falcon512_info_0/1,
    test_falcon512_keypair_0/1,
    test_falcon512_sign_2/1,
    test_falcon512_verify_3/1,
    test_falcon1024_info_0/1,
    test_falcon1024_keypair_0/1,
    test_falcon1024_sign_2/1,
    test_falcon1024_verify_3/1,
    test_sphincs_plus_haraka_128f_robust_info_0/1,
    test_sphincs_plus_haraka_128f_robust_keypair_0/1,
    test_sphincs_plus_haraka_128f_robust_keypair_1/1,
    test_sphincs_plus_haraka_128f_robust_sign_2/1,
    test_sphincs_plus_haraka_128f_robust_verify_3/1,
    test_sphincs_plus_haraka_128f_simple_info_0/1,
    test_sphincs_plus_haraka_128f_simple_keypair_0/1,
    test_sphincs_plus_haraka_128f_simple_keypair_1/1,
    test_sphincs_plus_haraka_128f_simple_sign_2/1,
    test_sphincs_plus_haraka_128f_simple_verify_3/1,
    test_sphincs_plus_haraka_128s_robust_info_0/1,
    test_sphincs_plus_haraka_128s_robust_keypair_0/1,
    test_sphincs_plus_haraka_128s_robust_keypair_1/1,
    test_sphincs_plus_haraka_128s_robust_sign_2/1,
    test_sphincs_plus_haraka_128s_robust_verify_3/1,
    test_sphincs_plus_haraka_128s_simple_info_0/1,
    test_sphincs_plus_haraka_128s_simple_keypair_0/1,
    test_sphincs_plus_haraka_128s_simple_keypair_1/1,
    test_sphincs_plus_haraka_128s_simple_sign_2/1,
    test_sphincs_plus_haraka_128s_simple_verify_3/1,
    test_sphincs_plus_haraka_192f_robust_info_0/1,
    test_sphincs_plus_haraka_192f_robust_keypair_0/1,
    test_sphincs_plus_haraka_192f_robust_keypair_1/1,
    test_sphincs_plus_haraka_192f_robust_sign_2/1,
    test_sphincs_plus_haraka_192f_robust_verify_3/1,
    test_sphincs_plus_haraka_192f_simple_info_0/1,
    test_sphincs_plus_haraka_192f_simple_keypair_0/1,
    test_sphincs_plus_haraka_192f_simple_keypair_1/1,
    test_sphincs_plus_haraka_192f_simple_sign_2/1,
    test_sphincs_plus_haraka_192f_simple_verify_3/1,
    test_sphincs_plus_haraka_192s_robust_info_0/1,
    test_sphincs_plus_haraka_192s_robust_keypair_0/1,
    test_sphincs_plus_haraka_192s_robust_keypair_1/1,
    test_sphincs_plus_haraka_192s_robust_sign_2/1,
    test_sphincs_plus_haraka_192s_robust_verify_3/1,
    test_sphincs_plus_haraka_192s_simple_info_0/1,
    test_sphincs_plus_haraka_192s_simple_keypair_0/1,
    test_sphincs_plus_haraka_192s_simple_keypair_1/1,
    test_sphincs_plus_haraka_192s_simple_sign_2/1,
    test_sphincs_plus_haraka_192s_simple_verify_3/1,
    test_sphincs_plus_haraka_256f_robust_info_0/1,
    test_sphincs_plus_haraka_256f_robust_keypair_0/1,
    test_sphincs_plus_haraka_256f_robust_keypair_1/1,
    test_sphincs_plus_haraka_256f_robust_sign_2/1,
    test_sphincs_plus_haraka_256f_robust_verify_3/1,
    test_sphincs_plus_haraka_256f_simple_info_0/1,
    test_sphincs_plus_haraka_256f_simple_keypair_0/1,
    test_sphincs_plus_haraka_256f_simple_keypair_1/1,
    test_sphincs_plus_haraka_256f_simple_sign_2/1,
    test_sphincs_plus_haraka_256f_simple_verify_3/1,
    test_sphincs_plus_haraka_256s_robust_info_0/1,
    test_sphincs_plus_haraka_256s_robust_keypair_0/1,
    test_sphincs_plus_haraka_256s_robust_keypair_1/1,
    test_sphincs_plus_haraka_256s_robust_sign_2/1,
    test_sphincs_plus_haraka_256s_robust_verify_3/1,
    test_sphincs_plus_haraka_256s_simple_info_0/1,
    test_sphincs_plus_haraka_256s_simple_keypair_0/1,
    test_sphincs_plus_haraka_256s_simple_keypair_1/1,
    test_sphincs_plus_haraka_256s_simple_sign_2/1,
    test_sphincs_plus_haraka_256s_simple_verify_3/1,
    test_sphincs_plus_sha2_128f_robust_info_0/1,
    test_sphincs_plus_sha2_128f_robust_keypair_0/1,
    test_sphincs_plus_sha2_128f_robust_keypair_1/1,
    test_sphincs_plus_sha2_128f_robust_sign_2/1,
    test_sphincs_plus_sha2_128f_robust_verify_3/1,
    test_sphincs_plus_sha2_128f_simple_info_0/1,
    test_sphincs_plus_sha2_128f_simple_keypair_0/1,
    test_sphincs_plus_sha2_128f_simple_keypair_1/1,
    test_sphincs_plus_sha2_128f_simple_sign_2/1,
    test_sphincs_plus_sha2_128f_simple_verify_3/1,
    test_sphincs_plus_sha2_128s_robust_info_0/1,
    test_sphincs_plus_sha2_128s_robust_keypair_0/1,
    test_sphincs_plus_sha2_128s_robust_keypair_1/1,
    test_sphincs_plus_sha2_128s_robust_sign_2/1,
    test_sphincs_plus_sha2_128s_robust_verify_3/1,
    test_sphincs_plus_sha2_128s_simple_info_0/1,
    test_sphincs_plus_sha2_128s_simple_keypair_0/1,
    test_sphincs_plus_sha2_128s_simple_keypair_1/1,
    test_sphincs_plus_sha2_128s_simple_sign_2/1,
    test_sphincs_plus_sha2_128s_simple_verify_3/1,
    test_sphincs_plus_sha2_192f_robust_info_0/1,
    test_sphincs_plus_sha2_192f_robust_keypair_0/1,
    test_sphincs_plus_sha2_192f_robust_keypair_1/1,
    test_sphincs_plus_sha2_192f_robust_sign_2/1,
    test_sphincs_plus_sha2_192f_robust_verify_3/1,
    test_sphincs_plus_sha2_192f_simple_info_0/1,
    test_sphincs_plus_sha2_192f_simple_keypair_0/1,
    test_sphincs_plus_sha2_192f_simple_keypair_1/1,
    test_sphincs_plus_sha2_192f_simple_sign_2/1,
    test_sphincs_plus_sha2_192f_simple_verify_3/1,
    test_sphincs_plus_sha2_192s_robust_info_0/1,
    test_sphincs_plus_sha2_192s_robust_keypair_0/1,
    test_sphincs_plus_sha2_192s_robust_keypair_1/1,
    test_sphincs_plus_sha2_192s_robust_sign_2/1,
    test_sphincs_plus_sha2_192s_robust_verify_3/1,
    test_sphincs_plus_sha2_192s_simple_info_0/1,
    test_sphincs_plus_sha2_192s_simple_keypair_0/1,
    test_sphincs_plus_sha2_192s_simple_keypair_1/1,
    test_sphincs_plus_sha2_192s_simple_sign_2/1,
    test_sphincs_plus_sha2_192s_simple_verify_3/1,
    test_sphincs_plus_sha2_256f_robust_info_0/1,
    test_sphincs_plus_sha2_256f_robust_keypair_0/1,
    test_sphincs_plus_sha2_256f_robust_keypair_1/1,
    test_sphincs_plus_sha2_256f_robust_sign_2/1,
    test_sphincs_plus_sha2_256f_robust_verify_3/1,
    test_sphincs_plus_sha2_256f_simple_info_0/1,
    test_sphincs_plus_sha2_256f_simple_keypair_0/1,
    test_sphincs_plus_sha2_256f_simple_keypair_1/1,
    test_sphincs_plus_sha2_256f_simple_sign_2/1,
    test_sphincs_plus_sha2_256f_simple_verify_3/1,
    test_sphincs_plus_sha2_256s_robust_info_0/1,
    test_sphincs_plus_sha2_256s_robust_keypair_0/1,
    test_sphincs_plus_sha2_256s_robust_keypair_1/1,
    test_sphincs_plus_sha2_256s_robust_sign_2/1,
    test_sphincs_plus_sha2_256s_robust_verify_3/1,
    test_sphincs_plus_sha2_256s_simple_info_0/1,
    test_sphincs_plus_sha2_256s_simple_keypair_0/1,
    test_sphincs_plus_sha2_256s_simple_keypair_1/1,
    test_sphincs_plus_sha2_256s_simple_sign_2/1,
    test_sphincs_plus_sha2_256s_simple_verify_3/1,
    test_sphincs_plus_shake_128f_robust_info_0/1,
    test_sphincs_plus_shake_128f_robust_keypair_0/1,
    test_sphincs_plus_shake_128f_robust_keypair_1/1,
    test_sphincs_plus_shake_128f_robust_sign_2/1,
    test_sphincs_plus_shake_128f_robust_verify_3/1,
    test_sphincs_plus_shake_128f_simple_info_0/1,
    test_sphincs_plus_shake_128f_simple_keypair_0/1,
    test_sphincs_plus_shake_128f_simple_keypair_1/1,
    test_sphincs_plus_shake_128f_simple_sign_2/1,
    test_sphincs_plus_shake_128f_simple_verify_3/1,
    test_sphincs_plus_shake_128s_robust_info_0/1,
    test_sphincs_plus_shake_128s_robust_keypair_0/1,
    test_sphincs_plus_shake_128s_robust_keypair_1/1,
    test_sphincs_plus_shake_128s_robust_sign_2/1,
    test_sphincs_plus_shake_128s_robust_verify_3/1,
    test_sphincs_plus_shake_128s_simple_info_0/1,
    test_sphincs_plus_shake_128s_simple_keypair_0/1,
    test_sphincs_plus_shake_128s_simple_keypair_1/1,
    test_sphincs_plus_shake_128s_simple_sign_2/1,
    test_sphincs_plus_shake_128s_simple_verify_3/1,
    test_sphincs_plus_shake_192f_robust_info_0/1,
    test_sphincs_plus_shake_192f_robust_keypair_0/1,
    test_sphincs_plus_shake_192f_robust_keypair_1/1,
    test_sphincs_plus_shake_192f_robust_sign_2/1,
    test_sphincs_plus_shake_192f_robust_verify_3/1,
    test_sphincs_plus_shake_192f_simple_info_0/1,
    test_sphincs_plus_shake_192f_simple_keypair_0/1,
    test_sphincs_plus_shake_192f_simple_keypair_1/1,
    test_sphincs_plus_shake_192f_simple_sign_2/1,
    test_sphincs_plus_shake_192f_simple_verify_3/1,
    test_sphincs_plus_shake_192s_robust_info_0/1,
    test_sphincs_plus_shake_192s_robust_keypair_0/1,
    test_sphincs_plus_shake_192s_robust_keypair_1/1,
    test_sphincs_plus_shake_192s_robust_sign_2/1,
    test_sphincs_plus_shake_192s_robust_verify_3/1,
    test_sphincs_plus_shake_192s_simple_info_0/1,
    test_sphincs_plus_shake_192s_simple_keypair_0/1,
    test_sphincs_plus_shake_192s_simple_keypair_1/1,
    test_sphincs_plus_shake_192s_simple_sign_2/1,
    test_sphincs_plus_shake_192s_simple_verify_3/1,
    test_sphincs_plus_shake_256f_robust_info_0/1,
    test_sphincs_plus_shake_256f_robust_keypair_0/1,
    test_sphincs_plus_shake_256f_robust_keypair_1/1,
    test_sphincs_plus_shake_256f_robust_sign_2/1,
    test_sphincs_plus_shake_256f_robust_verify_3/1,
    test_sphincs_plus_shake_256f_simple_info_0/1,
    test_sphincs_plus_shake_256f_simple_keypair_0/1,
    test_sphincs_plus_shake_256f_simple_keypair_1/1,
    test_sphincs_plus_shake_256f_simple_sign_2/1,
    test_sphincs_plus_shake_256f_simple_verify_3/1,
    test_sphincs_plus_shake_256s_robust_info_0/1,
    test_sphincs_plus_shake_256s_robust_keypair_0/1,
    test_sphincs_plus_shake_256s_robust_keypair_1/1,
    test_sphincs_plus_shake_256s_robust_sign_2/1,
    test_sphincs_plus_shake_256s_robust_verify_3/1,
    test_sphincs_plus_shake_256s_simple_info_0/1,
    test_sphincs_plus_shake_256s_simple_keypair_0/1,
    test_sphincs_plus_shake_256s_simple_keypair_1/1,
    test_sphincs_plus_shake_256s_simple_sign_2/1,
    test_sphincs_plus_shake_256s_simple_verify_3/1
]).

all() ->
    [
        {group, kem},
        {group, sign}
    ].

groups() ->
    [
        {kem, [parallel], [
            test_hqc_rmrs_128_info_0,
            test_hqc_rmrs_128_keypair_0,
            test_hqc_rmrs_128_encapsulate_1,
            test_hqc_rmrs_128_decapsulate_2,
            test_hqc_rmrs_192_info_0,
            test_hqc_rmrs_192_keypair_0,
            test_hqc_rmrs_192_encapsulate_1,
            test_hqc_rmrs_192_decapsulate_2,
            test_hqc_rmrs_256_info_0,
            test_hqc_rmrs_256_keypair_0,
            test_hqc_rmrs_256_encapsulate_1,
            test_hqc_rmrs_256_decapsulate_2,
            test_kyber512_info_0,
            test_kyber512_keypair_0,
            test_kyber512_encapsulate_1,
            test_kyber512_decapsulate_2,
            test_kyber512_90s_info_0,
            test_kyber512_90s_keypair_0,
            test_kyber512_90s_encapsulate_1,
            test_kyber512_90s_decapsulate_2,
            test_kyber768_info_0,
            test_kyber768_keypair_0,
            test_kyber768_encapsulate_1,
            test_kyber768_decapsulate_2,
            test_kyber768_90s_info_0,
            test_kyber768_90s_keypair_0,
            test_kyber768_90s_encapsulate_1,
            test_kyber768_90s_decapsulate_2,
            test_kyber1024_info_0,
            test_kyber1024_keypair_0,
            test_kyber1024_encapsulate_1,
            test_kyber1024_decapsulate_2,
            test_kyber1024_90s_info_0,
            test_kyber1024_90s_keypair_0,
            test_kyber1024_90s_encapsulate_1,
            test_kyber1024_90s_decapsulate_2
        ]},
        {sign, [parallel], [
            test_dilithium2_info_0,
            test_dilithium2_keypair_0,
            test_dilithium2_sign_2,
            test_dilithium2_verify_3,
            test_dilithium2aes_info_0,
            test_dilithium2aes_keypair_0,
            test_dilithium2aes_sign_2,
            test_dilithium2aes_verify_3,
            test_dilithium3_info_0,
            test_dilithium3_keypair_0,
            test_dilithium3_sign_2,
            test_dilithium3_verify_3,
            test_dilithium3aes_info_0,
            test_dilithium3aes_keypair_0,
            test_dilithium3aes_sign_2,
            test_dilithium3aes_verify_3,
            test_dilithium5_info_0,
            test_dilithium5_keypair_0,
            test_dilithium5_sign_2,
            test_dilithium5_verify_3,
            test_dilithium5aes_info_0,
            test_dilithium5aes_keypair_0,
            test_dilithium5aes_sign_2,
            test_dilithium5aes_verify_3,
            test_falcon512_info_0,
            test_falcon512_keypair_0,
            test_falcon512_sign_2,
            test_falcon512_verify_3,
            test_falcon1024_info_0,
            test_falcon1024_keypair_0,
            test_falcon1024_sign_2,
            test_falcon1024_verify_3,
            test_sphincs_plus_haraka_128f_robust_info_0,
            test_sphincs_plus_haraka_128f_robust_keypair_0,
            test_sphincs_plus_haraka_128f_robust_keypair_1,
            test_sphincs_plus_haraka_128f_robust_sign_2,
            test_sphincs_plus_haraka_128f_robust_verify_3,
            test_sphincs_plus_haraka_128f_simple_info_0,
            test_sphincs_plus_haraka_128f_simple_keypair_0,
            test_sphincs_plus_haraka_128f_simple_keypair_1,
            test_sphincs_plus_haraka_128f_simple_sign_2,
            test_sphincs_plus_haraka_128f_simple_verify_3,
            test_sphincs_plus_haraka_128s_robust_info_0,
            test_sphincs_plus_haraka_128s_robust_keypair_0,
            test_sphincs_plus_haraka_128s_robust_keypair_1,
            test_sphincs_plus_haraka_128s_robust_sign_2,
            test_sphincs_plus_haraka_128s_robust_verify_3,
            test_sphincs_plus_haraka_128s_simple_info_0,
            test_sphincs_plus_haraka_128s_simple_keypair_0,
            test_sphincs_plus_haraka_128s_simple_keypair_1,
            test_sphincs_plus_haraka_128s_simple_sign_2,
            test_sphincs_plus_haraka_128s_simple_verify_3,
            test_sphincs_plus_haraka_192f_robust_info_0,
            test_sphincs_plus_haraka_192f_robust_keypair_0,
            test_sphincs_plus_haraka_192f_robust_keypair_1,
            test_sphincs_plus_haraka_192f_robust_sign_2,
            test_sphincs_plus_haraka_192f_robust_verify_3,
            test_sphincs_plus_haraka_192f_simple_info_0,
            test_sphincs_plus_haraka_192f_simple_keypair_0,
            test_sphincs_plus_haraka_192f_simple_keypair_1,
            test_sphincs_plus_haraka_192f_simple_sign_2,
            test_sphincs_plus_haraka_192f_simple_verify_3,
            test_sphincs_plus_haraka_192s_robust_info_0,
            test_sphincs_plus_haraka_192s_robust_keypair_0,
            test_sphincs_plus_haraka_192s_robust_keypair_1,
            test_sphincs_plus_haraka_192s_robust_sign_2,
            test_sphincs_plus_haraka_192s_robust_verify_3,
            test_sphincs_plus_haraka_192s_simple_info_0,
            test_sphincs_plus_haraka_192s_simple_keypair_0,
            test_sphincs_plus_haraka_192s_simple_keypair_1,
            test_sphincs_plus_haraka_192s_simple_sign_2,
            test_sphincs_plus_haraka_192s_simple_verify_3,
            test_sphincs_plus_haraka_256f_robust_info_0,
            test_sphincs_plus_haraka_256f_robust_keypair_0,
            test_sphincs_plus_haraka_256f_robust_keypair_1,
            test_sphincs_plus_haraka_256f_robust_sign_2,
            test_sphincs_plus_haraka_256f_robust_verify_3,
            test_sphincs_plus_haraka_256f_simple_info_0,
            test_sphincs_plus_haraka_256f_simple_keypair_0,
            test_sphincs_plus_haraka_256f_simple_keypair_1,
            test_sphincs_plus_haraka_256f_simple_sign_2,
            test_sphincs_plus_haraka_256f_simple_verify_3,
            test_sphincs_plus_haraka_256s_robust_info_0,
            test_sphincs_plus_haraka_256s_robust_keypair_0,
            test_sphincs_plus_haraka_256s_robust_keypair_1,
            test_sphincs_plus_haraka_256s_robust_sign_2,
            test_sphincs_plus_haraka_256s_robust_verify_3,
            test_sphincs_plus_haraka_256s_simple_info_0,
            test_sphincs_plus_haraka_256s_simple_keypair_0,
            test_sphincs_plus_haraka_256s_simple_keypair_1,
            test_sphincs_plus_haraka_256s_simple_sign_2,
            test_sphincs_plus_haraka_256s_simple_verify_3,
            test_sphincs_plus_sha2_128f_robust_info_0,
            test_sphincs_plus_sha2_128f_robust_keypair_0,
            test_sphincs_plus_sha2_128f_robust_keypair_1,
            test_sphincs_plus_sha2_128f_robust_sign_2,
            test_sphincs_plus_sha2_128f_robust_verify_3,
            test_sphincs_plus_sha2_128f_simple_info_0,
            test_sphincs_plus_sha2_128f_simple_keypair_0,
            test_sphincs_plus_sha2_128f_simple_keypair_1,
            test_sphincs_plus_sha2_128f_simple_sign_2,
            test_sphincs_plus_sha2_128f_simple_verify_3,
            test_sphincs_plus_sha2_128s_robust_info_0,
            test_sphincs_plus_sha2_128s_robust_keypair_0,
            test_sphincs_plus_sha2_128s_robust_keypair_1,
            test_sphincs_plus_sha2_128s_robust_sign_2,
            test_sphincs_plus_sha2_128s_robust_verify_3,
            test_sphincs_plus_sha2_128s_simple_info_0,
            test_sphincs_plus_sha2_128s_simple_keypair_0,
            test_sphincs_plus_sha2_128s_simple_keypair_1,
            test_sphincs_plus_sha2_128s_simple_sign_2,
            test_sphincs_plus_sha2_128s_simple_verify_3,
            test_sphincs_plus_sha2_192f_robust_info_0,
            test_sphincs_plus_sha2_192f_robust_keypair_0,
            test_sphincs_plus_sha2_192f_robust_keypair_1,
            test_sphincs_plus_sha2_192f_robust_sign_2,
            test_sphincs_plus_sha2_192f_robust_verify_3,
            test_sphincs_plus_sha2_192f_simple_info_0,
            test_sphincs_plus_sha2_192f_simple_keypair_0,
            test_sphincs_plus_sha2_192f_simple_keypair_1,
            test_sphincs_plus_sha2_192f_simple_sign_2,
            test_sphincs_plus_sha2_192f_simple_verify_3,
            test_sphincs_plus_sha2_192s_robust_info_0,
            test_sphincs_plus_sha2_192s_robust_keypair_0,
            test_sphincs_plus_sha2_192s_robust_keypair_1,
            test_sphincs_plus_sha2_192s_robust_sign_2,
            test_sphincs_plus_sha2_192s_robust_verify_3,
            test_sphincs_plus_sha2_192s_simple_info_0,
            test_sphincs_plus_sha2_192s_simple_keypair_0,
            test_sphincs_plus_sha2_192s_simple_keypair_1,
            test_sphincs_plus_sha2_192s_simple_sign_2,
            test_sphincs_plus_sha2_192s_simple_verify_3,
            test_sphincs_plus_sha2_256f_robust_info_0,
            test_sphincs_plus_sha2_256f_robust_keypair_0,
            test_sphincs_plus_sha2_256f_robust_keypair_1,
            test_sphincs_plus_sha2_256f_robust_sign_2,
            test_sphincs_plus_sha2_256f_robust_verify_3,
            test_sphincs_plus_sha2_256f_simple_info_0,
            test_sphincs_plus_sha2_256f_simple_keypair_0,
            test_sphincs_plus_sha2_256f_simple_keypair_1,
            test_sphincs_plus_sha2_256f_simple_sign_2,
            test_sphincs_plus_sha2_256f_simple_verify_3,
            test_sphincs_plus_sha2_256s_robust_info_0,
            test_sphincs_plus_sha2_256s_robust_keypair_0,
            test_sphincs_plus_sha2_256s_robust_keypair_1,
            test_sphincs_plus_sha2_256s_robust_sign_2,
            test_sphincs_plus_sha2_256s_robust_verify_3,
            test_sphincs_plus_sha2_256s_simple_info_0,
            test_sphincs_plus_sha2_256s_simple_keypair_0,
            test_sphincs_plus_sha2_256s_simple_keypair_1,
            test_sphincs_plus_sha2_256s_simple_sign_2,
            test_sphincs_plus_sha2_256s_simple_verify_3,
            test_sphincs_plus_shake_128f_robust_info_0,
            test_sphincs_plus_shake_128f_robust_keypair_0,
            test_sphincs_plus_shake_128f_robust_keypair_1,
            test_sphincs_plus_shake_128f_robust_sign_2,
            test_sphincs_plus_shake_128f_robust_verify_3,
            test_sphincs_plus_shake_128f_simple_info_0,
            test_sphincs_plus_shake_128f_simple_keypair_0,
            test_sphincs_plus_shake_128f_simple_keypair_1,
            test_sphincs_plus_shake_128f_simple_sign_2,
            test_sphincs_plus_shake_128f_simple_verify_3,
            test_sphincs_plus_shake_128s_robust_info_0,
            test_sphincs_plus_shake_128s_robust_keypair_0,
            test_sphincs_plus_shake_128s_robust_keypair_1,
            test_sphincs_plus_shake_128s_robust_sign_2,
            test_sphincs_plus_shake_128s_robust_verify_3,
            test_sphincs_plus_shake_128s_simple_info_0,
            test_sphincs_plus_shake_128s_simple_keypair_0,
            test_sphincs_plus_shake_128s_simple_keypair_1,
            test_sphincs_plus_shake_128s_simple_sign_2,
            test_sphincs_plus_shake_128s_simple_verify_3,
            test_sphincs_plus_shake_192f_robust_info_0,
            test_sphincs_plus_shake_192f_robust_keypair_0,
            test_sphincs_plus_shake_192f_robust_keypair_1,
            test_sphincs_plus_shake_192f_robust_sign_2,
            test_sphincs_plus_shake_192f_robust_verify_3,
            test_sphincs_plus_shake_192f_simple_info_0,
            test_sphincs_plus_shake_192f_simple_keypair_0,
            test_sphincs_plus_shake_192f_simple_keypair_1,
            test_sphincs_plus_shake_192f_simple_sign_2,
            test_sphincs_plus_shake_192f_simple_verify_3,
            test_sphincs_plus_shake_192s_robust_info_0,
            test_sphincs_plus_shake_192s_robust_keypair_0,
            test_sphincs_plus_shake_192s_robust_keypair_1,
            test_sphincs_plus_shake_192s_robust_sign_2,
            test_sphincs_plus_shake_192s_robust_verify_3,
            test_sphincs_plus_shake_192s_simple_info_0,
            test_sphincs_plus_shake_192s_simple_keypair_0,
            test_sphincs_plus_shake_192s_simple_keypair_1,
            test_sphincs_plus_shake_192s_simple_sign_2,
            test_sphincs_plus_shake_192s_simple_verify_3,
            test_sphincs_plus_shake_256f_robust_info_0,
            test_sphincs_plus_shake_256f_robust_keypair_0,
            test_sphincs_plus_shake_256f_robust_keypair_1,
            test_sphincs_plus_shake_256f_robust_sign_2,
            test_sphincs_plus_shake_256f_robust_verify_3,
            test_sphincs_plus_shake_256f_simple_info_0,
            test_sphincs_plus_shake_256f_simple_keypair_0,
            test_sphincs_plus_shake_256f_simple_keypair_1,
            test_sphincs_plus_shake_256f_simple_sign_2,
            test_sphincs_plus_shake_256f_simple_verify_3,
            test_sphincs_plus_shake_256s_robust_info_0,
            test_sphincs_plus_shake_256s_robust_keypair_0,
            test_sphincs_plus_shake_256s_robust_keypair_1,
            test_sphincs_plus_shake_256s_robust_sign_2,
            test_sphincs_plus_shake_256s_robust_verify_3,
            test_sphincs_plus_shake_256s_simple_info_0,
            test_sphincs_plus_shake_256s_simple_keypair_0,
            test_sphincs_plus_shake_256s_simple_keypair_1,
            test_sphincs_plus_shake_256s_simple_sign_2,
            test_sphincs_plus_shake_256s_simple_verify_3
        ]}
    ].

init_per_suite(Config) ->
    _ = application:ensure_all_started(pqclean),
    Config.

end_per_suite(_Config) ->
    _ = application:stop(pqclean),
    ok.

init_per_group(_Group, Config) ->
    Config.

end_per_group(_Group, _Config) ->
    % libdecaf_ct:stop(Config),
    ok.

%%====================================================================
%% Tests
%%====================================================================

test_hqc_rmrs_128_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := kem,
            name := "HQC-RMRS-128",
            secretkeybytes := 2289,
            publickeybytes := 2249,
            ciphertextbytes := 4481,
            sharedsecretbytes := 64
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:hqc_rmrs_128_info()
    ),
    ok.

test_hqc_rmrs_128_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:2249/bytes>>, <<_SK:2289/bytes>>},
        pqclean_nif:hqc_rmrs_128_keypair()
    ),
    ok.

test_hqc_rmrs_128_encapsulate_1(_Config) ->
    {<<PK:2249/bytes>>, <<_SK:2289/bytes>>} = pqclean_nif:hqc_rmrs_128_keypair(),
    ?assertMatch(
        {<<_CT:4481/bytes>>, <<_SS:64/bytes>>},
        pqclean_nif:hqc_rmrs_128_encapsulate(PK)
    ),
    ok.

test_hqc_rmrs_128_decapsulate_2(_Config) ->
    {<<PK:2249/bytes>>, <<SK:2289/bytes>>} = pqclean_nif:hqc_rmrs_128_keypair(),
    {<<CT:4481/bytes>>, <<SS:64/bytes>>} = pqclean_nif:hqc_rmrs_128_encapsulate(PK),
    ?assertEqual(SS, pqclean_nif:hqc_rmrs_128_decapsulate(CT, SK)),
    ok.

test_hqc_rmrs_192_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := kem,
            name := "HQC-RMRS-192",
            secretkeybytes := 4562,
            publickeybytes := 4522,
            ciphertextbytes := 9026,
            sharedsecretbytes := 64
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:hqc_rmrs_192_info()
    ),
    ok.

test_hqc_rmrs_192_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:4522/bytes>>, <<_SK:4562/bytes>>},
        pqclean_nif:hqc_rmrs_192_keypair()
    ),
    ok.

test_hqc_rmrs_192_encapsulate_1(_Config) ->
    {<<PK:4522/bytes>>, <<_SK:4562/bytes>>} = pqclean_nif:hqc_rmrs_192_keypair(),
    ?assertMatch(
        {<<_CT:9026/bytes>>, <<_SS:64/bytes>>},
        pqclean_nif:hqc_rmrs_192_encapsulate(PK)
    ),
    ok.

test_hqc_rmrs_192_decapsulate_2(_Config) ->
    {<<PK:4522/bytes>>, <<SK:4562/bytes>>} = pqclean_nif:hqc_rmrs_192_keypair(),
    {<<CT:9026/bytes>>, <<SS:64/bytes>>} = pqclean_nif:hqc_rmrs_192_encapsulate(PK),
    ?assertEqual(SS, pqclean_nif:hqc_rmrs_192_decapsulate(CT, SK)),
    ok.

test_hqc_rmrs_256_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := kem,
            name := "HQC-RMRS-256",
            secretkeybytes := 7285,
            publickeybytes := 7245,
            ciphertextbytes := 14469,
            sharedsecretbytes := 64
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:hqc_rmrs_256_info()
    ),
    ok.

test_hqc_rmrs_256_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:7245/bytes>>, <<_SK:7285/bytes>>},
        pqclean_nif:hqc_rmrs_256_keypair()
    ),
    ok.

test_hqc_rmrs_256_encapsulate_1(_Config) ->
    {<<PK:7245/bytes>>, <<_SK:7285/bytes>>} = pqclean_nif:hqc_rmrs_256_keypair(),
    ?assertMatch(
        {<<_CT:14469/bytes>>, <<_SS:64/bytes>>},
        pqclean_nif:hqc_rmrs_256_encapsulate(PK)
    ),
    ok.

test_hqc_rmrs_256_decapsulate_2(_Config) ->
    {<<PK:7245/bytes>>, <<SK:7285/bytes>>} = pqclean_nif:hqc_rmrs_256_keypair(),
    {<<CT:14469/bytes>>, <<SS:64/bytes>>} = pqclean_nif:hqc_rmrs_256_encapsulate(PK),
    ?assertEqual(SS, pqclean_nif:hqc_rmrs_256_decapsulate(CT, SK)),
    ok.

test_kyber512_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := kem,
            name := "Kyber512",
            secretkeybytes := 1632,
            publickeybytes := 800,
            ciphertextbytes := 768,
            sharedsecretbytes := 32
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:kyber512_info()
    ),
    ok.

test_kyber512_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:800/bytes>>, <<_SK:1632/bytes>>},
        pqclean_nif:kyber512_keypair()
    ),
    ok.

test_kyber512_encapsulate_1(_Config) ->
    {<<PK:800/bytes>>, <<_SK:1632/bytes>>} = pqclean_nif:kyber512_keypair(),
    ?assertMatch(
        {<<_CT:768/bytes>>, <<_SS:32/bytes>>},
        pqclean_nif:kyber512_encapsulate(PK)
    ),
    ok.

test_kyber512_decapsulate_2(_Config) ->
    {<<PK:800/bytes>>, <<SK:1632/bytes>>} = pqclean_nif:kyber512_keypair(),
    {<<CT:768/bytes>>, <<SS:32/bytes>>} = pqclean_nif:kyber512_encapsulate(PK),
    ?assertEqual(SS, pqclean_nif:kyber512_decapsulate(CT, SK)),
    ok.

test_kyber512_90s_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := kem,
            name := "Kyber512-90s",
            secretkeybytes := 1632,
            publickeybytes := 800,
            ciphertextbytes := 768,
            sharedsecretbytes := 32
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:kyber512_90s_info()
    ),
    ok.

test_kyber512_90s_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:800/bytes>>, <<_SK:1632/bytes>>},
        pqclean_nif:kyber512_90s_keypair()
    ),
    ok.

test_kyber512_90s_encapsulate_1(_Config) ->
    {<<PK:800/bytes>>, <<_SK:1632/bytes>>} = pqclean_nif:kyber512_90s_keypair(),
    ?assertMatch(
        {<<_CT:768/bytes>>, <<_SS:32/bytes>>},
        pqclean_nif:kyber512_90s_encapsulate(PK)
    ),
    ok.

test_kyber512_90s_decapsulate_2(_Config) ->
    {<<PK:800/bytes>>, <<SK:1632/bytes>>} = pqclean_nif:kyber512_90s_keypair(),
    {<<CT:768/bytes>>, <<SS:32/bytes>>} = pqclean_nif:kyber512_90s_encapsulate(PK),
    ?assertEqual(SS, pqclean_nif:kyber512_90s_decapsulate(CT, SK)),
    ok.

test_kyber768_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := kem,
            name := "Kyber768",
            secretkeybytes := 2400,
            publickeybytes := 1184,
            ciphertextbytes := 1088,
            sharedsecretbytes := 32
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:kyber768_info()
    ),
    ok.

test_kyber768_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:1184/bytes>>, <<_SK:2400/bytes>>},
        pqclean_nif:kyber768_keypair()
    ),
    ok.

test_kyber768_encapsulate_1(_Config) ->
    {<<PK:1184/bytes>>, <<_SK:2400/bytes>>} = pqclean_nif:kyber768_keypair(),
    ?assertMatch(
        {<<_CT:1088/bytes>>, <<_SS:32/bytes>>},
        pqclean_nif:kyber768_encapsulate(PK)
    ),
    ok.

test_kyber768_decapsulate_2(_Config) ->
    {<<PK:1184/bytes>>, <<SK:2400/bytes>>} = pqclean_nif:kyber768_keypair(),
    {<<CT:1088/bytes>>, <<SS:32/bytes>>} = pqclean_nif:kyber768_encapsulate(PK),
    ?assertEqual(SS, pqclean_nif:kyber768_decapsulate(CT, SK)),
    ok.

test_kyber768_90s_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := kem,
            name := "Kyber768-90s",
            secretkeybytes := 2400,
            publickeybytes := 1184,
            ciphertextbytes := 1088,
            sharedsecretbytes := 32
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:kyber768_90s_info()
    ),
    ok.

test_kyber768_90s_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:1184/bytes>>, <<_SK:2400/bytes>>},
        pqclean_nif:kyber768_90s_keypair()
    ),
    ok.

test_kyber768_90s_encapsulate_1(_Config) ->
    {<<PK:1184/bytes>>, <<_SK:2400/bytes>>} = pqclean_nif:kyber768_90s_keypair(),
    ?assertMatch(
        {<<_CT:1088/bytes>>, <<_SS:32/bytes>>},
        pqclean_nif:kyber768_90s_encapsulate(PK)
    ),
    ok.

test_kyber768_90s_decapsulate_2(_Config) ->
    {<<PK:1184/bytes>>, <<SK:2400/bytes>>} = pqclean_nif:kyber768_90s_keypair(),
    {<<CT:1088/bytes>>, <<SS:32/bytes>>} = pqclean_nif:kyber768_90s_encapsulate(PK),
    ?assertEqual(SS, pqclean_nif:kyber768_90s_decapsulate(CT, SK)),
    ok.

test_kyber1024_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := kem,
            name := "Kyber1024",
            secretkeybytes := 3168,
            publickeybytes := 1568,
            ciphertextbytes := 1568,
            sharedsecretbytes := 32
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:kyber1024_info()
    ),
    ok.

test_kyber1024_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:1568/bytes>>, <<_SK:3168/bytes>>},
        pqclean_nif:kyber1024_keypair()
    ),
    ok.

test_kyber1024_encapsulate_1(_Config) ->
    {<<PK:1568/bytes>>, <<_SK:3168/bytes>>} = pqclean_nif:kyber1024_keypair(),
    ?assertMatch(
        {<<_CT:1568/bytes>>, <<_SS:32/bytes>>},
        pqclean_nif:kyber1024_encapsulate(PK)
    ),
    ok.

test_kyber1024_decapsulate_2(_Config) ->
    {<<PK:1568/bytes>>, <<SK:3168/bytes>>} = pqclean_nif:kyber1024_keypair(),
    {<<CT:1568/bytes>>, <<SS:32/bytes>>} = pqclean_nif:kyber1024_encapsulate(PK),
    ?assertEqual(SS, pqclean_nif:kyber1024_decapsulate(CT, SK)),
    ok.

test_kyber1024_90s_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := kem,
            name := "Kyber1024-90s",
            secretkeybytes := 3168,
            publickeybytes := 1568,
            ciphertextbytes := 1568,
            sharedsecretbytes := 32
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:kyber1024_90s_info()
    ),
    ok.

test_kyber1024_90s_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:1568/bytes>>, <<_SK:3168/bytes>>},
        pqclean_nif:kyber1024_90s_keypair()
    ),
    ok.

test_kyber1024_90s_encapsulate_1(_Config) ->
    {<<PK:1568/bytes>>, <<_SK:3168/bytes>>} = pqclean_nif:kyber1024_90s_keypair(),
    ?assertMatch(
        {<<_CT:1568/bytes>>, <<_SS:32/bytes>>},
        pqclean_nif:kyber1024_90s_encapsulate(PK)
    ),
    ok.

test_kyber1024_90s_decapsulate_2(_Config) ->
    {<<PK:1568/bytes>>, <<SK:3168/bytes>>} = pqclean_nif:kyber1024_90s_keypair(),
    {<<CT:1568/bytes>>, <<SS:32/bytes>>} = pqclean_nif:kyber1024_90s_encapsulate(PK),
    ?assertEqual(SS, pqclean_nif:kyber1024_90s_decapsulate(CT, SK)),
    ok.

test_dilithium2_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "Dilithium2",
            secretkeybytes := 2528,
            publickeybytes := 1312,
            signaturebytes := 2420
        } when map_size(CryptoKemInfo) =:= 5,
        pqclean_nif:dilithium2_info()
    ),
    ok.

test_dilithium2_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:1312/bytes>>, <<_SK:2528/bytes>>},
        pqclean_nif:dilithium2_keypair()
    ),
    ok.

test_dilithium2_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:1312/bytes>>, <<SK:2528/bytes>>} = pqclean_nif:dilithium2_keypair(),
    ?assertMatch(<<_Sig:2420/bytes>>, pqclean_nif:dilithium2_sign(M, SK)),
    ok.

test_dilithium2_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:1312/bytes>>, <<SK:2528/bytes>>} = pqclean_nif:dilithium2_keypair(),
    <<Sig:2420/bytes>> = pqclean_nif:dilithium2_sign(M, SK),
    ?assertEqual(true, pqclean_nif:dilithium2_verify(Sig, M, PK)),
    ok.

test_dilithium2aes_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "Dilithium2-AES",
            secretkeybytes := 2528,
            publickeybytes := 1312,
            signaturebytes := 2420
        } when map_size(CryptoKemInfo) =:= 5,
        pqclean_nif:dilithium2aes_info()
    ),
    ok.

test_dilithium2aes_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:1312/bytes>>, <<_SK:2528/bytes>>},
        pqclean_nif:dilithium2aes_keypair()
    ),
    ok.

test_dilithium2aes_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:1312/bytes>>, <<SK:2528/bytes>>} = pqclean_nif:dilithium2aes_keypair(),
    ?assertMatch(<<_Sig:2420/bytes>>, pqclean_nif:dilithium2aes_sign(M, SK)),
    ok.

test_dilithium2aes_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:1312/bytes>>, <<SK:2528/bytes>>} = pqclean_nif:dilithium2aes_keypair(),
    <<Sig:2420/bytes>> = pqclean_nif:dilithium2aes_sign(M, SK),
    ?assertEqual(true, pqclean_nif:dilithium2aes_verify(Sig, M, PK)),
    ok.

test_dilithium3_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "Dilithium3",
            secretkeybytes := 4000,
            publickeybytes := 1952,
            signaturebytes := 3293
        } when map_size(CryptoKemInfo) =:= 5,
        pqclean_nif:dilithium3_info()
    ),
    ok.

test_dilithium3_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:1952/bytes>>, <<_SK:4000/bytes>>},
        pqclean_nif:dilithium3_keypair()
    ),
    ok.

test_dilithium3_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:1952/bytes>>, <<SK:4000/bytes>>} = pqclean_nif:dilithium3_keypair(),
    ?assertMatch(<<_Sig:3293/bytes>>, pqclean_nif:dilithium3_sign(M, SK)),
    ok.

test_dilithium3_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:1952/bytes>>, <<SK:4000/bytes>>} = pqclean_nif:dilithium3_keypair(),
    <<Sig:3293/bytes>> = pqclean_nif:dilithium3_sign(M, SK),
    ?assertEqual(true, pqclean_nif:dilithium3_verify(Sig, M, PK)),
    ok.

test_dilithium3aes_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "Dilithium3-AES",
            secretkeybytes := 4000,
            publickeybytes := 1952,
            signaturebytes := 3293
        } when map_size(CryptoKemInfo) =:= 5,
        pqclean_nif:dilithium3aes_info()
    ),
    ok.

test_dilithium3aes_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:1952/bytes>>, <<_SK:4000/bytes>>},
        pqclean_nif:dilithium3aes_keypair()
    ),
    ok.

test_dilithium3aes_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:1952/bytes>>, <<SK:4000/bytes>>} = pqclean_nif:dilithium3aes_keypair(),
    ?assertMatch(<<_Sig:3293/bytes>>, pqclean_nif:dilithium3aes_sign(M, SK)),
    ok.

test_dilithium3aes_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:1952/bytes>>, <<SK:4000/bytes>>} = pqclean_nif:dilithium3aes_keypair(),
    <<Sig:3293/bytes>> = pqclean_nif:dilithium3aes_sign(M, SK),
    ?assertEqual(true, pqclean_nif:dilithium3aes_verify(Sig, M, PK)),
    ok.

test_dilithium5_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "Dilithium5",
            secretkeybytes := 4864,
            publickeybytes := 2592,
            signaturebytes := 4595
        } when map_size(CryptoKemInfo) =:= 5,
        pqclean_nif:dilithium5_info()
    ),
    ok.

test_dilithium5_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:2592/bytes>>, <<_SK:4864/bytes>>},
        pqclean_nif:dilithium5_keypair()
    ),
    ok.

test_dilithium5_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:2592/bytes>>, <<SK:4864/bytes>>} = pqclean_nif:dilithium5_keypair(),
    ?assertMatch(<<_Sig:4595/bytes>>, pqclean_nif:dilithium5_sign(M, SK)),
    ok.

test_dilithium5_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:2592/bytes>>, <<SK:4864/bytes>>} = pqclean_nif:dilithium5_keypair(),
    <<Sig:4595/bytes>> = pqclean_nif:dilithium5_sign(M, SK),
    ?assertEqual(true, pqclean_nif:dilithium5_verify(Sig, M, PK)),
    ok.

test_dilithium5aes_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "Dilithium5-AES",
            secretkeybytes := 4864,
            publickeybytes := 2592,
            signaturebytes := 4595
        } when map_size(CryptoKemInfo) =:= 5,
        pqclean_nif:dilithium5aes_info()
    ),
    ok.

test_dilithium5aes_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:2592/bytes>>, <<_SK:4864/bytes>>},
        pqclean_nif:dilithium5aes_keypair()
    ),
    ok.

test_dilithium5aes_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:2592/bytes>>, <<SK:4864/bytes>>} = pqclean_nif:dilithium5aes_keypair(),
    ?assertMatch(<<_Sig:4595/bytes>>, pqclean_nif:dilithium5aes_sign(M, SK)),
    ok.

test_dilithium5aes_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:2592/bytes>>, <<SK:4864/bytes>>} = pqclean_nif:dilithium5aes_keypair(),
    <<Sig:4595/bytes>> = pqclean_nif:dilithium5aes_sign(M, SK),
    ?assertEqual(true, pqclean_nif:dilithium5aes_verify(Sig, M, PK)),
    ok.

test_falcon512_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "Falcon-512",
            secretkeybytes := 1281,
            publickeybytes := 897,
            signaturebytes := 666
        } when map_size(CryptoKemInfo) =:= 5,
        pqclean_nif:falcon512_info()
    ),
    ok.

test_falcon512_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:897/bytes>>, <<_SK:1281/bytes>>},
        pqclean_nif:falcon512_keypair()
    ),
    ok.

test_falcon512_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:897/bytes>>, <<SK:1281/bytes>>} = pqclean_nif:falcon512_keypair(),
    ?assertMatch(Sig when is_binary(Sig) andalso byte_size(Sig) =< 666, pqclean_nif:falcon512_sign(M, SK)),
    ok.

test_falcon512_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:897/bytes>>, <<SK:1281/bytes>>} = pqclean_nif:falcon512_keypair(),
    <<Sig/bytes>> = pqclean_nif:falcon512_sign(M, SK),
    ?assertEqual(true, pqclean_nif:falcon512_verify(Sig, M, PK)),
    ok.

test_falcon1024_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "Falcon-1024",
            secretkeybytes := 2305,
            publickeybytes := 1793,
            signaturebytes := 1280
        } when map_size(CryptoKemInfo) =:= 5,
        pqclean_nif:falcon1024_info()
    ),
    ok.

test_falcon1024_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:1793/bytes>>, <<_SK:2305/bytes>>},
        pqclean_nif:falcon1024_keypair()
    ),
    ok.

test_falcon1024_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:1793/bytes>>, <<SK:2305/bytes>>} = pqclean_nif:falcon1024_keypair(),
    ?assertMatch(Sig when is_binary(Sig) andalso byte_size(Sig) =< 1280, pqclean_nif:falcon1024_sign(M, SK)),
    ok.

test_falcon1024_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:1793/bytes>>, <<SK:2305/bytes>>} = pqclean_nif:falcon1024_keypair(),
    <<Sig/bytes>> = pqclean_nif:falcon1024_sign(M, SK),
    ?assertEqual(true, pqclean_nif:falcon1024_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_haraka_128f_robust_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-haraka-128f-robust",
            secretkeybytes := 64,
            publickeybytes := 32,
            signaturebytes := 17088,
            seedbytes := 48
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_haraka_128f_robust_info()
    ),
    ok.

test_sphincs_plus_haraka_128f_robust_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:32/bytes>>, <<_SK:64/bytes>>},
        pqclean_nif:sphincs_plus_haraka_128f_robust_keypair()
    ),
    ok.

test_sphincs_plus_haraka_128f_robust_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:32/bytes>>, <<_SK:64/bytes>>},
        pqclean_nif:sphincs_plus_haraka_128f_robust_keypair(<<0:384>>)
    ),
    ok.

test_sphincs_plus_haraka_128f_robust_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:32/bytes>>, <<SK:64/bytes>>} = pqclean_nif:sphincs_plus_haraka_128f_robust_keypair(),
    ?assertMatch(<<_Sig:17088/bytes>>, pqclean_nif:sphincs_plus_haraka_128f_robust_sign(M, SK)),
    ok.

test_sphincs_plus_haraka_128f_robust_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:32/bytes>>, <<SK:64/bytes>>} = pqclean_nif:sphincs_plus_haraka_128f_robust_keypair(),
    <<Sig:17088/bytes>> = pqclean_nif:sphincs_plus_haraka_128f_robust_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_haraka_128f_robust_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_haraka_128f_simple_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-haraka-128f-simple",
            secretkeybytes := 64,
            publickeybytes := 32,
            signaturebytes := 17088,
            seedbytes := 48
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_haraka_128f_simple_info()
    ),
    ok.

test_sphincs_plus_haraka_128f_simple_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:32/bytes>>, <<_SK:64/bytes>>},
        pqclean_nif:sphincs_plus_haraka_128f_simple_keypair()
    ),
    ok.

test_sphincs_plus_haraka_128f_simple_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:32/bytes>>, <<_SK:64/bytes>>},
        pqclean_nif:sphincs_plus_haraka_128f_simple_keypair(<<0:384>>)
    ),
    ok.

test_sphincs_plus_haraka_128f_simple_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:32/bytes>>, <<SK:64/bytes>>} = pqclean_nif:sphincs_plus_haraka_128f_simple_keypair(),
    ?assertMatch(<<_Sig:17088/bytes>>, pqclean_nif:sphincs_plus_haraka_128f_simple_sign(M, SK)),
    ok.

test_sphincs_plus_haraka_128f_simple_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:32/bytes>>, <<SK:64/bytes>>} = pqclean_nif:sphincs_plus_haraka_128f_simple_keypair(),
    <<Sig:17088/bytes>> = pqclean_nif:sphincs_plus_haraka_128f_simple_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_haraka_128f_simple_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_haraka_128s_robust_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-haraka-128s-robust",
            secretkeybytes := 64,
            publickeybytes := 32,
            signaturebytes := 7856,
            seedbytes := 48
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_haraka_128s_robust_info()
    ),
    ok.

test_sphincs_plus_haraka_128s_robust_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:32/bytes>>, <<_SK:64/bytes>>},
        pqclean_nif:sphincs_plus_haraka_128s_robust_keypair()
    ),
    ok.

test_sphincs_plus_haraka_128s_robust_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:32/bytes>>, <<_SK:64/bytes>>},
        pqclean_nif:sphincs_plus_haraka_128s_robust_keypair(<<0:384>>)
    ),
    ok.

test_sphincs_plus_haraka_128s_robust_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:32/bytes>>, <<SK:64/bytes>>} = pqclean_nif:sphincs_plus_haraka_128s_robust_keypair(),
    ?assertMatch(<<_Sig:7856/bytes>>, pqclean_nif:sphincs_plus_haraka_128s_robust_sign(M, SK)),
    ok.

test_sphincs_plus_haraka_128s_robust_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:32/bytes>>, <<SK:64/bytes>>} = pqclean_nif:sphincs_plus_haraka_128s_robust_keypair(),
    <<Sig:7856/bytes>> = pqclean_nif:sphincs_plus_haraka_128s_robust_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_haraka_128s_robust_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_haraka_128s_simple_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-haraka-128s-simple",
            secretkeybytes := 64,
            publickeybytes := 32,
            signaturebytes := 7856,
            seedbytes := 48
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_haraka_128s_simple_info()
    ),
    ok.

test_sphincs_plus_haraka_128s_simple_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:32/bytes>>, <<_SK:64/bytes>>},
        pqclean_nif:sphincs_plus_haraka_128s_simple_keypair()
    ),
    ok.

test_sphincs_plus_haraka_128s_simple_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:32/bytes>>, <<_SK:64/bytes>>},
        pqclean_nif:sphincs_plus_haraka_128s_simple_keypair(<<0:384>>)
    ),
    ok.

test_sphincs_plus_haraka_128s_simple_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:32/bytes>>, <<SK:64/bytes>>} = pqclean_nif:sphincs_plus_haraka_128s_simple_keypair(),
    ?assertMatch(<<_Sig:7856/bytes>>, pqclean_nif:sphincs_plus_haraka_128s_simple_sign(M, SK)),
    ok.

test_sphincs_plus_haraka_128s_simple_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:32/bytes>>, <<SK:64/bytes>>} = pqclean_nif:sphincs_plus_haraka_128s_simple_keypair(),
    <<Sig:7856/bytes>> = pqclean_nif:sphincs_plus_haraka_128s_simple_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_haraka_128s_simple_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_haraka_192f_robust_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-haraka-192f-robust",
            secretkeybytes := 96,
            publickeybytes := 48,
            signaturebytes := 35664,
            seedbytes := 72
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_haraka_192f_robust_info()
    ),
    ok.

test_sphincs_plus_haraka_192f_robust_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:48/bytes>>, <<_SK:96/bytes>>},
        pqclean_nif:sphincs_plus_haraka_192f_robust_keypair()
    ),
    ok.

test_sphincs_plus_haraka_192f_robust_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:48/bytes>>, <<_SK:96/bytes>>},
        pqclean_nif:sphincs_plus_haraka_192f_robust_keypair(<<0:576>>)
    ),
    ok.

test_sphincs_plus_haraka_192f_robust_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:48/bytes>>, <<SK:96/bytes>>} = pqclean_nif:sphincs_plus_haraka_192f_robust_keypair(),
    ?assertMatch(<<_Sig:35664/bytes>>, pqclean_nif:sphincs_plus_haraka_192f_robust_sign(M, SK)),
    ok.

test_sphincs_plus_haraka_192f_robust_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:48/bytes>>, <<SK:96/bytes>>} = pqclean_nif:sphincs_plus_haraka_192f_robust_keypair(),
    <<Sig:35664/bytes>> = pqclean_nif:sphincs_plus_haraka_192f_robust_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_haraka_192f_robust_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_haraka_192f_simple_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-haraka-192f-simple",
            secretkeybytes := 96,
            publickeybytes := 48,
            signaturebytes := 35664,
            seedbytes := 72
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_haraka_192f_simple_info()
    ),
    ok.

test_sphincs_plus_haraka_192f_simple_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:48/bytes>>, <<_SK:96/bytes>>},
        pqclean_nif:sphincs_plus_haraka_192f_simple_keypair()
    ),
    ok.

test_sphincs_plus_haraka_192f_simple_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:48/bytes>>, <<_SK:96/bytes>>},
        pqclean_nif:sphincs_plus_haraka_192f_simple_keypair(<<0:576>>)
    ),
    ok.

test_sphincs_plus_haraka_192f_simple_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:48/bytes>>, <<SK:96/bytes>>} = pqclean_nif:sphincs_plus_haraka_192f_simple_keypair(),
    ?assertMatch(<<_Sig:35664/bytes>>, pqclean_nif:sphincs_plus_haraka_192f_simple_sign(M, SK)),
    ok.

test_sphincs_plus_haraka_192f_simple_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:48/bytes>>, <<SK:96/bytes>>} = pqclean_nif:sphincs_plus_haraka_192f_simple_keypair(),
    <<Sig:35664/bytes>> = pqclean_nif:sphincs_plus_haraka_192f_simple_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_haraka_192f_simple_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_haraka_192s_robust_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-haraka-192s-robust",
            secretkeybytes := 96,
            publickeybytes := 48,
            signaturebytes := 16224,
            seedbytes := 72
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_haraka_192s_robust_info()
    ),
    ok.

test_sphincs_plus_haraka_192s_robust_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:48/bytes>>, <<_SK:96/bytes>>},
        pqclean_nif:sphincs_plus_haraka_192s_robust_keypair()
    ),
    ok.

test_sphincs_plus_haraka_192s_robust_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:48/bytes>>, <<_SK:96/bytes>>},
        pqclean_nif:sphincs_plus_haraka_192s_robust_keypair(<<0:576>>)
    ),
    ok.

test_sphincs_plus_haraka_192s_robust_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:48/bytes>>, <<SK:96/bytes>>} = pqclean_nif:sphincs_plus_haraka_192s_robust_keypair(),
    ?assertMatch(<<_Sig:16224/bytes>>, pqclean_nif:sphincs_plus_haraka_192s_robust_sign(M, SK)),
    ok.

test_sphincs_plus_haraka_192s_robust_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:48/bytes>>, <<SK:96/bytes>>} = pqclean_nif:sphincs_plus_haraka_192s_robust_keypair(),
    <<Sig:16224/bytes>> = pqclean_nif:sphincs_plus_haraka_192s_robust_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_haraka_192s_robust_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_haraka_192s_simple_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-haraka-192s-simple",
            secretkeybytes := 96,
            publickeybytes := 48,
            signaturebytes := 16224,
            seedbytes := 72
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_haraka_192s_simple_info()
    ),
    ok.

test_sphincs_plus_haraka_192s_simple_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:48/bytes>>, <<_SK:96/bytes>>},
        pqclean_nif:sphincs_plus_haraka_192s_simple_keypair()
    ),
    ok.

test_sphincs_plus_haraka_192s_simple_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:48/bytes>>, <<_SK:96/bytes>>},
        pqclean_nif:sphincs_plus_haraka_192s_simple_keypair(<<0:576>>)
    ),
    ok.

test_sphincs_plus_haraka_192s_simple_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:48/bytes>>, <<SK:96/bytes>>} = pqclean_nif:sphincs_plus_haraka_192s_simple_keypair(),
    ?assertMatch(<<_Sig:16224/bytes>>, pqclean_nif:sphincs_plus_haraka_192s_simple_sign(M, SK)),
    ok.

test_sphincs_plus_haraka_192s_simple_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:48/bytes>>, <<SK:96/bytes>>} = pqclean_nif:sphincs_plus_haraka_192s_simple_keypair(),
    <<Sig:16224/bytes>> = pqclean_nif:sphincs_plus_haraka_192s_simple_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_haraka_192s_simple_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_haraka_256f_robust_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-haraka-256f-robust",
            secretkeybytes := 128,
            publickeybytes := 64,
            signaturebytes := 49856,
            seedbytes := 96
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_haraka_256f_robust_info()
    ),
    ok.

test_sphincs_plus_haraka_256f_robust_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:64/bytes>>, <<_SK:128/bytes>>},
        pqclean_nif:sphincs_plus_haraka_256f_robust_keypair()
    ),
    ok.

test_sphincs_plus_haraka_256f_robust_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:64/bytes>>, <<_SK:128/bytes>>},
        pqclean_nif:sphincs_plus_haraka_256f_robust_keypair(<<0:768>>)
    ),
    ok.

test_sphincs_plus_haraka_256f_robust_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:64/bytes>>, <<SK:128/bytes>>} = pqclean_nif:sphincs_plus_haraka_256f_robust_keypair(),
    ?assertMatch(<<_Sig:49856/bytes>>, pqclean_nif:sphincs_plus_haraka_256f_robust_sign(M, SK)),
    ok.

test_sphincs_plus_haraka_256f_robust_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:64/bytes>>, <<SK:128/bytes>>} = pqclean_nif:sphincs_plus_haraka_256f_robust_keypair(),
    <<Sig:49856/bytes>> = pqclean_nif:sphincs_plus_haraka_256f_robust_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_haraka_256f_robust_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_haraka_256f_simple_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-haraka-256f-simple",
            secretkeybytes := 128,
            publickeybytes := 64,
            signaturebytes := 49856,
            seedbytes := 96
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_haraka_256f_simple_info()
    ),
    ok.

test_sphincs_plus_haraka_256f_simple_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:64/bytes>>, <<_SK:128/bytes>>},
        pqclean_nif:sphincs_plus_haraka_256f_simple_keypair()
    ),
    ok.

test_sphincs_plus_haraka_256f_simple_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:64/bytes>>, <<_SK:128/bytes>>},
        pqclean_nif:sphincs_plus_haraka_256f_simple_keypair(<<0:768>>)
    ),
    ok.

test_sphincs_plus_haraka_256f_simple_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:64/bytes>>, <<SK:128/bytes>>} = pqclean_nif:sphincs_plus_haraka_256f_simple_keypair(),
    ?assertMatch(<<_Sig:49856/bytes>>, pqclean_nif:sphincs_plus_haraka_256f_simple_sign(M, SK)),
    ok.

test_sphincs_plus_haraka_256f_simple_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:64/bytes>>, <<SK:128/bytes>>} = pqclean_nif:sphincs_plus_haraka_256f_simple_keypair(),
    <<Sig:49856/bytes>> = pqclean_nif:sphincs_plus_haraka_256f_simple_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_haraka_256f_simple_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_haraka_256s_robust_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-haraka-256s-robust",
            secretkeybytes := 128,
            publickeybytes := 64,
            signaturebytes := 29792,
            seedbytes := 96
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_haraka_256s_robust_info()
    ),
    ok.

test_sphincs_plus_haraka_256s_robust_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:64/bytes>>, <<_SK:128/bytes>>},
        pqclean_nif:sphincs_plus_haraka_256s_robust_keypair()
    ),
    ok.

test_sphincs_plus_haraka_256s_robust_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:64/bytes>>, <<_SK:128/bytes>>},
        pqclean_nif:sphincs_plus_haraka_256s_robust_keypair(<<0:768>>)
    ),
    ok.

test_sphincs_plus_haraka_256s_robust_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:64/bytes>>, <<SK:128/bytes>>} = pqclean_nif:sphincs_plus_haraka_256s_robust_keypair(),
    ?assertMatch(<<_Sig:29792/bytes>>, pqclean_nif:sphincs_plus_haraka_256s_robust_sign(M, SK)),
    ok.

test_sphincs_plus_haraka_256s_robust_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:64/bytes>>, <<SK:128/bytes>>} = pqclean_nif:sphincs_plus_haraka_256s_robust_keypair(),
    <<Sig:29792/bytes>> = pqclean_nif:sphincs_plus_haraka_256s_robust_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_haraka_256s_robust_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_haraka_256s_simple_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-haraka-256s-simple",
            secretkeybytes := 128,
            publickeybytes := 64,
            signaturebytes := 29792,
            seedbytes := 96
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_haraka_256s_simple_info()
    ),
    ok.

test_sphincs_plus_haraka_256s_simple_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:64/bytes>>, <<_SK:128/bytes>>},
        pqclean_nif:sphincs_plus_haraka_256s_simple_keypair()
    ),
    ok.

test_sphincs_plus_haraka_256s_simple_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:64/bytes>>, <<_SK:128/bytes>>},
        pqclean_nif:sphincs_plus_haraka_256s_simple_keypair(<<0:768>>)
    ),
    ok.

test_sphincs_plus_haraka_256s_simple_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:64/bytes>>, <<SK:128/bytes>>} = pqclean_nif:sphincs_plus_haraka_256s_simple_keypair(),
    ?assertMatch(<<_Sig:29792/bytes>>, pqclean_nif:sphincs_plus_haraka_256s_simple_sign(M, SK)),
    ok.

test_sphincs_plus_haraka_256s_simple_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:64/bytes>>, <<SK:128/bytes>>} = pqclean_nif:sphincs_plus_haraka_256s_simple_keypair(),
    <<Sig:29792/bytes>> = pqclean_nif:sphincs_plus_haraka_256s_simple_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_haraka_256s_simple_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_sha2_128f_robust_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-sha2-128f-robust",
            secretkeybytes := 64,
            publickeybytes := 32,
            signaturebytes := 17088,
            seedbytes := 48
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_sha2_128f_robust_info()
    ),
    ok.

test_sphincs_plus_sha2_128f_robust_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:32/bytes>>, <<_SK:64/bytes>>},
        pqclean_nif:sphincs_plus_sha2_128f_robust_keypair()
    ),
    ok.

test_sphincs_plus_sha2_128f_robust_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:32/bytes>>, <<_SK:64/bytes>>},
        pqclean_nif:sphincs_plus_sha2_128f_robust_keypair(<<0:384>>)
    ),
    ok.

test_sphincs_plus_sha2_128f_robust_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:32/bytes>>, <<SK:64/bytes>>} = pqclean_nif:sphincs_plus_sha2_128f_robust_keypair(),
    ?assertMatch(<<_Sig:17088/bytes>>, pqclean_nif:sphincs_plus_sha2_128f_robust_sign(M, SK)),
    ok.

test_sphincs_plus_sha2_128f_robust_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:32/bytes>>, <<SK:64/bytes>>} = pqclean_nif:sphincs_plus_sha2_128f_robust_keypair(),
    <<Sig:17088/bytes>> = pqclean_nif:sphincs_plus_sha2_128f_robust_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_sha2_128f_robust_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_sha2_128f_simple_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-sha2-128f-simple",
            secretkeybytes := 64,
            publickeybytes := 32,
            signaturebytes := 17088,
            seedbytes := 48
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_sha2_128f_simple_info()
    ),
    ok.

test_sphincs_plus_sha2_128f_simple_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:32/bytes>>, <<_SK:64/bytes>>},
        pqclean_nif:sphincs_plus_sha2_128f_simple_keypair()
    ),
    ok.

test_sphincs_plus_sha2_128f_simple_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:32/bytes>>, <<_SK:64/bytes>>},
        pqclean_nif:sphincs_plus_sha2_128f_simple_keypair(<<0:384>>)
    ),
    ok.

test_sphincs_plus_sha2_128f_simple_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:32/bytes>>, <<SK:64/bytes>>} = pqclean_nif:sphincs_plus_sha2_128f_simple_keypair(),
    ?assertMatch(<<_Sig:17088/bytes>>, pqclean_nif:sphincs_plus_sha2_128f_simple_sign(M, SK)),
    ok.

test_sphincs_plus_sha2_128f_simple_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:32/bytes>>, <<SK:64/bytes>>} = pqclean_nif:sphincs_plus_sha2_128f_simple_keypair(),
    <<Sig:17088/bytes>> = pqclean_nif:sphincs_plus_sha2_128f_simple_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_sha2_128f_simple_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_sha2_128s_robust_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-sha2-128s-robust",
            secretkeybytes := 64,
            publickeybytes := 32,
            signaturebytes := 7856,
            seedbytes := 48
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_sha2_128s_robust_info()
    ),
    ok.

test_sphincs_plus_sha2_128s_robust_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:32/bytes>>, <<_SK:64/bytes>>},
        pqclean_nif:sphincs_plus_sha2_128s_robust_keypair()
    ),
    ok.

test_sphincs_plus_sha2_128s_robust_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:32/bytes>>, <<_SK:64/bytes>>},
        pqclean_nif:sphincs_plus_sha2_128s_robust_keypair(<<0:384>>)
    ),
    ok.

test_sphincs_plus_sha2_128s_robust_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:32/bytes>>, <<SK:64/bytes>>} = pqclean_nif:sphincs_plus_sha2_128s_robust_keypair(),
    ?assertMatch(<<_Sig:7856/bytes>>, pqclean_nif:sphincs_plus_sha2_128s_robust_sign(M, SK)),
    ok.

test_sphincs_plus_sha2_128s_robust_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:32/bytes>>, <<SK:64/bytes>>} = pqclean_nif:sphincs_plus_sha2_128s_robust_keypair(),
    <<Sig:7856/bytes>> = pqclean_nif:sphincs_plus_sha2_128s_robust_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_sha2_128s_robust_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_sha2_128s_simple_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-sha2-128s-simple",
            secretkeybytes := 64,
            publickeybytes := 32,
            signaturebytes := 7856,
            seedbytes := 48
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_sha2_128s_simple_info()
    ),
    ok.

test_sphincs_plus_sha2_128s_simple_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:32/bytes>>, <<_SK:64/bytes>>},
        pqclean_nif:sphincs_plus_sha2_128s_simple_keypair()
    ),
    ok.

test_sphincs_plus_sha2_128s_simple_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:32/bytes>>, <<_SK:64/bytes>>},
        pqclean_nif:sphincs_plus_sha2_128s_simple_keypair(<<0:384>>)
    ),
    ok.

test_sphincs_plus_sha2_128s_simple_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:32/bytes>>, <<SK:64/bytes>>} = pqclean_nif:sphincs_plus_sha2_128s_simple_keypair(),
    ?assertMatch(<<_Sig:7856/bytes>>, pqclean_nif:sphincs_plus_sha2_128s_simple_sign(M, SK)),
    ok.

test_sphincs_plus_sha2_128s_simple_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:32/bytes>>, <<SK:64/bytes>>} = pqclean_nif:sphincs_plus_sha2_128s_simple_keypair(),
    <<Sig:7856/bytes>> = pqclean_nif:sphincs_plus_sha2_128s_simple_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_sha2_128s_simple_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_sha2_192f_robust_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-sha2-192f-robust",
            secretkeybytes := 96,
            publickeybytes := 48,
            signaturebytes := 35664,
            seedbytes := 72
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_sha2_192f_robust_info()
    ),
    ok.

test_sphincs_plus_sha2_192f_robust_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:48/bytes>>, <<_SK:96/bytes>>},
        pqclean_nif:sphincs_plus_sha2_192f_robust_keypair()
    ),
    ok.

test_sphincs_plus_sha2_192f_robust_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:48/bytes>>, <<_SK:96/bytes>>},
        pqclean_nif:sphincs_plus_sha2_192f_robust_keypair(<<0:576>>)
    ),
    ok.

test_sphincs_plus_sha2_192f_robust_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:48/bytes>>, <<SK:96/bytes>>} = pqclean_nif:sphincs_plus_sha2_192f_robust_keypair(),
    ?assertMatch(<<_Sig:35664/bytes>>, pqclean_nif:sphincs_plus_sha2_192f_robust_sign(M, SK)),
    ok.

test_sphincs_plus_sha2_192f_robust_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:48/bytes>>, <<SK:96/bytes>>} = pqclean_nif:sphincs_plus_sha2_192f_robust_keypair(),
    <<Sig:35664/bytes>> = pqclean_nif:sphincs_plus_sha2_192f_robust_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_sha2_192f_robust_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_sha2_192f_simple_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-sha2-192f-simple",
            secretkeybytes := 96,
            publickeybytes := 48,
            signaturebytes := 35664,
            seedbytes := 72
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_sha2_192f_simple_info()
    ),
    ok.

test_sphincs_plus_sha2_192f_simple_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:48/bytes>>, <<_SK:96/bytes>>},
        pqclean_nif:sphincs_plus_sha2_192f_simple_keypair()
    ),
    ok.

test_sphincs_plus_sha2_192f_simple_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:48/bytes>>, <<_SK:96/bytes>>},
        pqclean_nif:sphincs_plus_sha2_192f_simple_keypair(<<0:576>>)
    ),
    ok.

test_sphincs_plus_sha2_192f_simple_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:48/bytes>>, <<SK:96/bytes>>} = pqclean_nif:sphincs_plus_sha2_192f_simple_keypair(),
    ?assertMatch(<<_Sig:35664/bytes>>, pqclean_nif:sphincs_plus_sha2_192f_simple_sign(M, SK)),
    ok.

test_sphincs_plus_sha2_192f_simple_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:48/bytes>>, <<SK:96/bytes>>} = pqclean_nif:sphincs_plus_sha2_192f_simple_keypair(),
    <<Sig:35664/bytes>> = pqclean_nif:sphincs_plus_sha2_192f_simple_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_sha2_192f_simple_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_sha2_192s_robust_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-sha2-192s-robust",
            secretkeybytes := 96,
            publickeybytes := 48,
            signaturebytes := 16224,
            seedbytes := 72
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_sha2_192s_robust_info()
    ),
    ok.

test_sphincs_plus_sha2_192s_robust_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:48/bytes>>, <<_SK:96/bytes>>},
        pqclean_nif:sphincs_plus_sha2_192s_robust_keypair()
    ),
    ok.

test_sphincs_plus_sha2_192s_robust_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:48/bytes>>, <<_SK:96/bytes>>},
        pqclean_nif:sphincs_plus_sha2_192s_robust_keypair(<<0:576>>)
    ),
    ok.

test_sphincs_plus_sha2_192s_robust_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:48/bytes>>, <<SK:96/bytes>>} = pqclean_nif:sphincs_plus_sha2_192s_robust_keypair(),
    ?assertMatch(<<_Sig:16224/bytes>>, pqclean_nif:sphincs_plus_sha2_192s_robust_sign(M, SK)),
    ok.

test_sphincs_plus_sha2_192s_robust_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:48/bytes>>, <<SK:96/bytes>>} = pqclean_nif:sphincs_plus_sha2_192s_robust_keypair(),
    <<Sig:16224/bytes>> = pqclean_nif:sphincs_plus_sha2_192s_robust_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_sha2_192s_robust_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_sha2_192s_simple_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-sha2-192s-simple",
            secretkeybytes := 96,
            publickeybytes := 48,
            signaturebytes := 16224,
            seedbytes := 72
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_sha2_192s_simple_info()
    ),
    ok.

test_sphincs_plus_sha2_192s_simple_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:48/bytes>>, <<_SK:96/bytes>>},
        pqclean_nif:sphincs_plus_sha2_192s_simple_keypair()
    ),
    ok.

test_sphincs_plus_sha2_192s_simple_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:48/bytes>>, <<_SK:96/bytes>>},
        pqclean_nif:sphincs_plus_sha2_192s_simple_keypair(<<0:576>>)
    ),
    ok.

test_sphincs_plus_sha2_192s_simple_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:48/bytes>>, <<SK:96/bytes>>} = pqclean_nif:sphincs_plus_sha2_192s_simple_keypair(),
    ?assertMatch(<<_Sig:16224/bytes>>, pqclean_nif:sphincs_plus_sha2_192s_simple_sign(M, SK)),
    ok.

test_sphincs_plus_sha2_192s_simple_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:48/bytes>>, <<SK:96/bytes>>} = pqclean_nif:sphincs_plus_sha2_192s_simple_keypair(),
    <<Sig:16224/bytes>> = pqclean_nif:sphincs_plus_sha2_192s_simple_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_sha2_192s_simple_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_sha2_256f_robust_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-sha2-256f-robust",
            secretkeybytes := 128,
            publickeybytes := 64,
            signaturebytes := 49856,
            seedbytes := 96
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_sha2_256f_robust_info()
    ),
    ok.

test_sphincs_plus_sha2_256f_robust_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:64/bytes>>, <<_SK:128/bytes>>},
        pqclean_nif:sphincs_plus_sha2_256f_robust_keypair()
    ),
    ok.

test_sphincs_plus_sha2_256f_robust_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:64/bytes>>, <<_SK:128/bytes>>},
        pqclean_nif:sphincs_plus_sha2_256f_robust_keypair(<<0:768>>)
    ),
    ok.

test_sphincs_plus_sha2_256f_robust_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:64/bytes>>, <<SK:128/bytes>>} = pqclean_nif:sphincs_plus_sha2_256f_robust_keypair(),
    ?assertMatch(<<_Sig:49856/bytes>>, pqclean_nif:sphincs_plus_sha2_256f_robust_sign(M, SK)),
    ok.

test_sphincs_plus_sha2_256f_robust_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:64/bytes>>, <<SK:128/bytes>>} = pqclean_nif:sphincs_plus_sha2_256f_robust_keypair(),
    <<Sig:49856/bytes>> = pqclean_nif:sphincs_plus_sha2_256f_robust_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_sha2_256f_robust_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_sha2_256f_simple_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-sha2-256f-simple",
            secretkeybytes := 128,
            publickeybytes := 64,
            signaturebytes := 49856,
            seedbytes := 96
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_sha2_256f_simple_info()
    ),
    ok.

test_sphincs_plus_sha2_256f_simple_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:64/bytes>>, <<_SK:128/bytes>>},
        pqclean_nif:sphincs_plus_sha2_256f_simple_keypair()
    ),
    ok.

test_sphincs_plus_sha2_256f_simple_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:64/bytes>>, <<_SK:128/bytes>>},
        pqclean_nif:sphincs_plus_sha2_256f_simple_keypair(<<0:768>>)
    ),
    ok.

test_sphincs_plus_sha2_256f_simple_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:64/bytes>>, <<SK:128/bytes>>} = pqclean_nif:sphincs_plus_sha2_256f_simple_keypair(),
    ?assertMatch(<<_Sig:49856/bytes>>, pqclean_nif:sphincs_plus_sha2_256f_simple_sign(M, SK)),
    ok.

test_sphincs_plus_sha2_256f_simple_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:64/bytes>>, <<SK:128/bytes>>} = pqclean_nif:sphincs_plus_sha2_256f_simple_keypair(),
    <<Sig:49856/bytes>> = pqclean_nif:sphincs_plus_sha2_256f_simple_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_sha2_256f_simple_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_sha2_256s_robust_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-sha2-256s-robust",
            secretkeybytes := 128,
            publickeybytes := 64,
            signaturebytes := 29792,
            seedbytes := 96
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_sha2_256s_robust_info()
    ),
    ok.

test_sphincs_plus_sha2_256s_robust_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:64/bytes>>, <<_SK:128/bytes>>},
        pqclean_nif:sphincs_plus_sha2_256s_robust_keypair()
    ),
    ok.

test_sphincs_plus_sha2_256s_robust_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:64/bytes>>, <<_SK:128/bytes>>},
        pqclean_nif:sphincs_plus_sha2_256s_robust_keypair(<<0:768>>)
    ),
    ok.

test_sphincs_plus_sha2_256s_robust_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:64/bytes>>, <<SK:128/bytes>>} = pqclean_nif:sphincs_plus_sha2_256s_robust_keypair(),
    ?assertMatch(<<_Sig:29792/bytes>>, pqclean_nif:sphincs_plus_sha2_256s_robust_sign(M, SK)),
    ok.

test_sphincs_plus_sha2_256s_robust_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:64/bytes>>, <<SK:128/bytes>>} = pqclean_nif:sphincs_plus_sha2_256s_robust_keypair(),
    <<Sig:29792/bytes>> = pqclean_nif:sphincs_plus_sha2_256s_robust_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_sha2_256s_robust_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_sha2_256s_simple_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-sha2-256s-simple",
            secretkeybytes := 128,
            publickeybytes := 64,
            signaturebytes := 29792,
            seedbytes := 96
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_sha2_256s_simple_info()
    ),
    ok.

test_sphincs_plus_sha2_256s_simple_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:64/bytes>>, <<_SK:128/bytes>>},
        pqclean_nif:sphincs_plus_sha2_256s_simple_keypair()
    ),
    ok.

test_sphincs_plus_sha2_256s_simple_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:64/bytes>>, <<_SK:128/bytes>>},
        pqclean_nif:sphincs_plus_sha2_256s_simple_keypair(<<0:768>>)
    ),
    ok.

test_sphincs_plus_sha2_256s_simple_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:64/bytes>>, <<SK:128/bytes>>} = pqclean_nif:sphincs_plus_sha2_256s_simple_keypair(),
    ?assertMatch(<<_Sig:29792/bytes>>, pqclean_nif:sphincs_plus_sha2_256s_simple_sign(M, SK)),
    ok.

test_sphincs_plus_sha2_256s_simple_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:64/bytes>>, <<SK:128/bytes>>} = pqclean_nif:sphincs_plus_sha2_256s_simple_keypair(),
    <<Sig:29792/bytes>> = pqclean_nif:sphincs_plus_sha2_256s_simple_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_sha2_256s_simple_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_shake_128f_robust_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-shake-128f-robust",
            secretkeybytes := 64,
            publickeybytes := 32,
            signaturebytes := 17088,
            seedbytes := 48
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_shake_128f_robust_info()
    ),
    ok.

test_sphincs_plus_shake_128f_robust_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:32/bytes>>, <<_SK:64/bytes>>},
        pqclean_nif:sphincs_plus_shake_128f_robust_keypair()
    ),
    ok.

test_sphincs_plus_shake_128f_robust_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:32/bytes>>, <<_SK:64/bytes>>},
        pqclean_nif:sphincs_plus_shake_128f_robust_keypair(<<0:384>>)
    ),
    ok.

test_sphincs_plus_shake_128f_robust_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:32/bytes>>, <<SK:64/bytes>>} = pqclean_nif:sphincs_plus_shake_128f_robust_keypair(),
    ?assertMatch(<<_Sig:17088/bytes>>, pqclean_nif:sphincs_plus_shake_128f_robust_sign(M, SK)),
    ok.

test_sphincs_plus_shake_128f_robust_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:32/bytes>>, <<SK:64/bytes>>} = pqclean_nif:sphincs_plus_shake_128f_robust_keypair(),
    <<Sig:17088/bytes>> = pqclean_nif:sphincs_plus_shake_128f_robust_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_shake_128f_robust_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_shake_128f_simple_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-shake-128f-simple",
            secretkeybytes := 64,
            publickeybytes := 32,
            signaturebytes := 17088,
            seedbytes := 48
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_shake_128f_simple_info()
    ),
    ok.

test_sphincs_plus_shake_128f_simple_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:32/bytes>>, <<_SK:64/bytes>>},
        pqclean_nif:sphincs_plus_shake_128f_simple_keypair()
    ),
    ok.

test_sphincs_plus_shake_128f_simple_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:32/bytes>>, <<_SK:64/bytes>>},
        pqclean_nif:sphincs_plus_shake_128f_simple_keypair(<<0:384>>)
    ),
    ok.

test_sphincs_plus_shake_128f_simple_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:32/bytes>>, <<SK:64/bytes>>} = pqclean_nif:sphincs_plus_shake_128f_simple_keypair(),
    ?assertMatch(<<_Sig:17088/bytes>>, pqclean_nif:sphincs_plus_shake_128f_simple_sign(M, SK)),
    ok.

test_sphincs_plus_shake_128f_simple_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:32/bytes>>, <<SK:64/bytes>>} = pqclean_nif:sphincs_plus_shake_128f_simple_keypair(),
    <<Sig:17088/bytes>> = pqclean_nif:sphincs_plus_shake_128f_simple_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_shake_128f_simple_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_shake_128s_robust_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-shake-128s-robust",
            secretkeybytes := 64,
            publickeybytes := 32,
            signaturebytes := 7856,
            seedbytes := 48
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_shake_128s_robust_info()
    ),
    ok.

test_sphincs_plus_shake_128s_robust_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:32/bytes>>, <<_SK:64/bytes>>},
        pqclean_nif:sphincs_plus_shake_128s_robust_keypair()
    ),
    ok.

test_sphincs_plus_shake_128s_robust_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:32/bytes>>, <<_SK:64/bytes>>},
        pqclean_nif:sphincs_plus_shake_128s_robust_keypair(<<0:384>>)
    ),
    ok.

test_sphincs_plus_shake_128s_robust_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:32/bytes>>, <<SK:64/bytes>>} = pqclean_nif:sphincs_plus_shake_128s_robust_keypair(),
    ?assertMatch(<<_Sig:7856/bytes>>, pqclean_nif:sphincs_plus_shake_128s_robust_sign(M, SK)),
    ok.

test_sphincs_plus_shake_128s_robust_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:32/bytes>>, <<SK:64/bytes>>} = pqclean_nif:sphincs_plus_shake_128s_robust_keypair(),
    <<Sig:7856/bytes>> = pqclean_nif:sphincs_plus_shake_128s_robust_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_shake_128s_robust_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_shake_128s_simple_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-shake-128s-simple",
            secretkeybytes := 64,
            publickeybytes := 32,
            signaturebytes := 7856,
            seedbytes := 48
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_shake_128s_simple_info()
    ),
    ok.

test_sphincs_plus_shake_128s_simple_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:32/bytes>>, <<_SK:64/bytes>>},
        pqclean_nif:sphincs_plus_shake_128s_simple_keypair()
    ),
    ok.

test_sphincs_plus_shake_128s_simple_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:32/bytes>>, <<_SK:64/bytes>>},
        pqclean_nif:sphincs_plus_shake_128s_simple_keypair(<<0:384>>)
    ),
    ok.

test_sphincs_plus_shake_128s_simple_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:32/bytes>>, <<SK:64/bytes>>} = pqclean_nif:sphincs_plus_shake_128s_simple_keypair(),
    ?assertMatch(<<_Sig:7856/bytes>>, pqclean_nif:sphincs_plus_shake_128s_simple_sign(M, SK)),
    ok.

test_sphincs_plus_shake_128s_simple_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:32/bytes>>, <<SK:64/bytes>>} = pqclean_nif:sphincs_plus_shake_128s_simple_keypair(),
    <<Sig:7856/bytes>> = pqclean_nif:sphincs_plus_shake_128s_simple_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_shake_128s_simple_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_shake_192f_robust_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-shake-192f-robust",
            secretkeybytes := 96,
            publickeybytes := 48,
            signaturebytes := 35664,
            seedbytes := 72
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_shake_192f_robust_info()
    ),
    ok.

test_sphincs_plus_shake_192f_robust_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:48/bytes>>, <<_SK:96/bytes>>},
        pqclean_nif:sphincs_plus_shake_192f_robust_keypair()
    ),
    ok.

test_sphincs_plus_shake_192f_robust_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:48/bytes>>, <<_SK:96/bytes>>},
        pqclean_nif:sphincs_plus_shake_192f_robust_keypair(<<0:576>>)
    ),
    ok.

test_sphincs_plus_shake_192f_robust_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:48/bytes>>, <<SK:96/bytes>>} = pqclean_nif:sphincs_plus_shake_192f_robust_keypair(),
    ?assertMatch(<<_Sig:35664/bytes>>, pqclean_nif:sphincs_plus_shake_192f_robust_sign(M, SK)),
    ok.

test_sphincs_plus_shake_192f_robust_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:48/bytes>>, <<SK:96/bytes>>} = pqclean_nif:sphincs_plus_shake_192f_robust_keypair(),
    <<Sig:35664/bytes>> = pqclean_nif:sphincs_plus_shake_192f_robust_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_shake_192f_robust_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_shake_192f_simple_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-shake-192f-simple",
            secretkeybytes := 96,
            publickeybytes := 48,
            signaturebytes := 35664,
            seedbytes := 72
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_shake_192f_simple_info()
    ),
    ok.

test_sphincs_plus_shake_192f_simple_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:48/bytes>>, <<_SK:96/bytes>>},
        pqclean_nif:sphincs_plus_shake_192f_simple_keypair()
    ),
    ok.

test_sphincs_plus_shake_192f_simple_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:48/bytes>>, <<_SK:96/bytes>>},
        pqclean_nif:sphincs_plus_shake_192f_simple_keypair(<<0:576>>)
    ),
    ok.

test_sphincs_plus_shake_192f_simple_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:48/bytes>>, <<SK:96/bytes>>} = pqclean_nif:sphincs_plus_shake_192f_simple_keypair(),
    ?assertMatch(<<_Sig:35664/bytes>>, pqclean_nif:sphincs_plus_shake_192f_simple_sign(M, SK)),
    ok.

test_sphincs_plus_shake_192f_simple_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:48/bytes>>, <<SK:96/bytes>>} = pqclean_nif:sphincs_plus_shake_192f_simple_keypair(),
    <<Sig:35664/bytes>> = pqclean_nif:sphincs_plus_shake_192f_simple_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_shake_192f_simple_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_shake_192s_robust_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-shake-192s-robust",
            secretkeybytes := 96,
            publickeybytes := 48,
            signaturebytes := 16224,
            seedbytes := 72
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_shake_192s_robust_info()
    ),
    ok.

test_sphincs_plus_shake_192s_robust_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:48/bytes>>, <<_SK:96/bytes>>},
        pqclean_nif:sphincs_plus_shake_192s_robust_keypair()
    ),
    ok.

test_sphincs_plus_shake_192s_robust_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:48/bytes>>, <<_SK:96/bytes>>},
        pqclean_nif:sphincs_plus_shake_192s_robust_keypair(<<0:576>>)
    ),
    ok.

test_sphincs_plus_shake_192s_robust_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:48/bytes>>, <<SK:96/bytes>>} = pqclean_nif:sphincs_plus_shake_192s_robust_keypair(),
    ?assertMatch(<<_Sig:16224/bytes>>, pqclean_nif:sphincs_plus_shake_192s_robust_sign(M, SK)),
    ok.

test_sphincs_plus_shake_192s_robust_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:48/bytes>>, <<SK:96/bytes>>} = pqclean_nif:sphincs_plus_shake_192s_robust_keypair(),
    <<Sig:16224/bytes>> = pqclean_nif:sphincs_plus_shake_192s_robust_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_shake_192s_robust_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_shake_192s_simple_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-shake-192s-simple",
            secretkeybytes := 96,
            publickeybytes := 48,
            signaturebytes := 16224,
            seedbytes := 72
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_shake_192s_simple_info()
    ),
    ok.

test_sphincs_plus_shake_192s_simple_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:48/bytes>>, <<_SK:96/bytes>>},
        pqclean_nif:sphincs_plus_shake_192s_simple_keypair()
    ),
    ok.

test_sphincs_plus_shake_192s_simple_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:48/bytes>>, <<_SK:96/bytes>>},
        pqclean_nif:sphincs_plus_shake_192s_simple_keypair(<<0:576>>)
    ),
    ok.

test_sphincs_plus_shake_192s_simple_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:48/bytes>>, <<SK:96/bytes>>} = pqclean_nif:sphincs_plus_shake_192s_simple_keypair(),
    ?assertMatch(<<_Sig:16224/bytes>>, pqclean_nif:sphincs_plus_shake_192s_simple_sign(M, SK)),
    ok.

test_sphincs_plus_shake_192s_simple_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:48/bytes>>, <<SK:96/bytes>>} = pqclean_nif:sphincs_plus_shake_192s_simple_keypair(),
    <<Sig:16224/bytes>> = pqclean_nif:sphincs_plus_shake_192s_simple_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_shake_192s_simple_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_shake_256f_robust_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-shake-256f-robust",
            secretkeybytes := 128,
            publickeybytes := 64,
            signaturebytes := 49856,
            seedbytes := 96
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_shake_256f_robust_info()
    ),
    ok.

test_sphincs_plus_shake_256f_robust_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:64/bytes>>, <<_SK:128/bytes>>},
        pqclean_nif:sphincs_plus_shake_256f_robust_keypair()
    ),
    ok.

test_sphincs_plus_shake_256f_robust_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:64/bytes>>, <<_SK:128/bytes>>},
        pqclean_nif:sphincs_plus_shake_256f_robust_keypair(<<0:768>>)
    ),
    ok.

test_sphincs_plus_shake_256f_robust_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:64/bytes>>, <<SK:128/bytes>>} = pqclean_nif:sphincs_plus_shake_256f_robust_keypair(),
    ?assertMatch(<<_Sig:49856/bytes>>, pqclean_nif:sphincs_plus_shake_256f_robust_sign(M, SK)),
    ok.

test_sphincs_plus_shake_256f_robust_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:64/bytes>>, <<SK:128/bytes>>} = pqclean_nif:sphincs_plus_shake_256f_robust_keypair(),
    <<Sig:49856/bytes>> = pqclean_nif:sphincs_plus_shake_256f_robust_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_shake_256f_robust_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_shake_256f_simple_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-shake-256f-simple",
            secretkeybytes := 128,
            publickeybytes := 64,
            signaturebytes := 49856,
            seedbytes := 96
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_shake_256f_simple_info()
    ),
    ok.

test_sphincs_plus_shake_256f_simple_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:64/bytes>>, <<_SK:128/bytes>>},
        pqclean_nif:sphincs_plus_shake_256f_simple_keypair()
    ),
    ok.

test_sphincs_plus_shake_256f_simple_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:64/bytes>>, <<_SK:128/bytes>>},
        pqclean_nif:sphincs_plus_shake_256f_simple_keypair(<<0:768>>)
    ),
    ok.

test_sphincs_plus_shake_256f_simple_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:64/bytes>>, <<SK:128/bytes>>} = pqclean_nif:sphincs_plus_shake_256f_simple_keypair(),
    ?assertMatch(<<_Sig:49856/bytes>>, pqclean_nif:sphincs_plus_shake_256f_simple_sign(M, SK)),
    ok.

test_sphincs_plus_shake_256f_simple_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:64/bytes>>, <<SK:128/bytes>>} = pqclean_nif:sphincs_plus_shake_256f_simple_keypair(),
    <<Sig:49856/bytes>> = pqclean_nif:sphincs_plus_shake_256f_simple_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_shake_256f_simple_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_shake_256s_robust_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-shake-256s-robust",
            secretkeybytes := 128,
            publickeybytes := 64,
            signaturebytes := 29792,
            seedbytes := 96
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_shake_256s_robust_info()
    ),
    ok.

test_sphincs_plus_shake_256s_robust_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:64/bytes>>, <<_SK:128/bytes>>},
        pqclean_nif:sphincs_plus_shake_256s_robust_keypair()
    ),
    ok.

test_sphincs_plus_shake_256s_robust_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:64/bytes>>, <<_SK:128/bytes>>},
        pqclean_nif:sphincs_plus_shake_256s_robust_keypair(<<0:768>>)
    ),
    ok.

test_sphincs_plus_shake_256s_robust_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:64/bytes>>, <<SK:128/bytes>>} = pqclean_nif:sphincs_plus_shake_256s_robust_keypair(),
    ?assertMatch(<<_Sig:29792/bytes>>, pqclean_nif:sphincs_plus_shake_256s_robust_sign(M, SK)),
    ok.

test_sphincs_plus_shake_256s_robust_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:64/bytes>>, <<SK:128/bytes>>} = pqclean_nif:sphincs_plus_shake_256s_robust_keypair(),
    <<Sig:29792/bytes>> = pqclean_nif:sphincs_plus_shake_256s_robust_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_shake_256s_robust_verify(Sig, M, PK)),
    ok.

test_sphincs_plus_shake_256s_simple_info_0(_Config) ->
    ?assertMatch(
        CryptoKemInfo = #{
            type := sign,
            name := "SPHINCS+-shake-256s-simple",
            secretkeybytes := 128,
            publickeybytes := 64,
            signaturebytes := 29792,
            seedbytes := 96
        } when map_size(CryptoKemInfo) =:= 6,
        pqclean_nif:sphincs_plus_shake_256s_simple_info()
    ),
    ok.

test_sphincs_plus_shake_256s_simple_keypair_0(_Config) ->
    ?assertMatch(
        {<<_PK:64/bytes>>, <<_SK:128/bytes>>},
        pqclean_nif:sphincs_plus_shake_256s_simple_keypair()
    ),
    ok.

test_sphincs_plus_shake_256s_simple_keypair_1(_Config) ->
    ?assertMatch(
        {<<_PK:64/bytes>>, <<_SK:128/bytes>>},
        pqclean_nif:sphincs_plus_shake_256s_simple_keypair(<<0:768>>)
    ),
    ok.

test_sphincs_plus_shake_256s_simple_sign_2(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<_PK:64/bytes>>, <<SK:128/bytes>>} = pqclean_nif:sphincs_plus_shake_256s_simple_keypair(),
    ?assertMatch(<<_Sig:29792/bytes>>, pqclean_nif:sphincs_plus_shake_256s_simple_sign(M, SK)),
    ok.

test_sphincs_plus_shake_256s_simple_verify_3(_Config) ->
    M = crypto:strong_rand_bytes(rand:uniform(128)),
    {<<PK:64/bytes>>, <<SK:128/bytes>>} = pqclean_nif:sphincs_plus_shake_256s_simple_keypair(),
    <<Sig:29792/bytes>> = pqclean_nif:sphincs_plus_shake_256s_simple_sign(M, SK),
    ?assertEqual(true, pqclean_nif:sphincs_plus_shake_256s_simple_verify(Sig, M, PK)),
    ok.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
