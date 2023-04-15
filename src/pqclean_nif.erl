%%% % @format
-module(pqclean_nif).
-compile(warn_missing_spec).
-author("potatosaladx@gmail.com").

-on_load(init/0).

%% NIF API
-export([
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

-type crypto_sign_info() :: #{
    type := sign,
    name := string(),
    secretkeybytes := non_neg_integer(),
    publickeybytes := non_neg_integer(),
    signaturebytes := non_neg_integer(),
    seedbytes => non_neg_integer()
}.

-export_type([
    crypto_kem_info/0,
    crypto_sign_info/0
]).

-type hqc_rmrs_128_secret_key() :: <<_:18312>>.
-type hqc_rmrs_128_public_key() :: <<_:17992>>.
-type hqc_rmrs_128_cipher_text() :: <<_:35848>>.
-type hqc_rmrs_128_shared_secret() :: <<_:512>>.

-export_type([
    hqc_rmrs_128_secret_key/0,
    hqc_rmrs_128_public_key/0,
    hqc_rmrs_128_cipher_text/0,
    hqc_rmrs_128_shared_secret/0
]).

-type hqc_rmrs_192_secret_key() :: <<_:36496>>.
-type hqc_rmrs_192_public_key() :: <<_:36176>>.
-type hqc_rmrs_192_cipher_text() :: <<_:72208>>.
-type hqc_rmrs_192_shared_secret() :: <<_:512>>.

-export_type([
    hqc_rmrs_192_secret_key/0,
    hqc_rmrs_192_public_key/0,
    hqc_rmrs_192_cipher_text/0,
    hqc_rmrs_192_shared_secret/0
]).

-type hqc_rmrs_256_secret_key() :: <<_:58280>>.
-type hqc_rmrs_256_public_key() :: <<_:57960>>.
-type hqc_rmrs_256_cipher_text() :: <<_:115752>>.
-type hqc_rmrs_256_shared_secret() :: <<_:512>>.

-export_type([
    hqc_rmrs_256_secret_key/0,
    hqc_rmrs_256_public_key/0,
    hqc_rmrs_256_cipher_text/0,
    hqc_rmrs_256_shared_secret/0
]).

-type kyber512_secret_key() :: <<_:13056>>.
-type kyber512_public_key() :: <<_:6400>>.
-type kyber512_cipher_text() :: <<_:6144>>.
-type kyber512_shared_secret() :: <<_:256>>.

-export_type([
    kyber512_secret_key/0,
    kyber512_public_key/0,
    kyber512_cipher_text/0,
    kyber512_shared_secret/0
]).

-type kyber512_90s_secret_key() :: <<_:13056>>.
-type kyber512_90s_public_key() :: <<_:6400>>.
-type kyber512_90s_cipher_text() :: <<_:6144>>.
-type kyber512_90s_shared_secret() :: <<_:256>>.

-export_type([
    kyber512_90s_secret_key/0,
    kyber512_90s_public_key/0,
    kyber512_90s_cipher_text/0,
    kyber512_90s_shared_secret/0
]).

-type kyber768_secret_key() :: <<_:19200>>.
-type kyber768_public_key() :: <<_:9472>>.
-type kyber768_cipher_text() :: <<_:8704>>.
-type kyber768_shared_secret() :: <<_:256>>.

-export_type([
    kyber768_secret_key/0,
    kyber768_public_key/0,
    kyber768_cipher_text/0,
    kyber768_shared_secret/0
]).

-type kyber768_90s_secret_key() :: <<_:19200>>.
-type kyber768_90s_public_key() :: <<_:9472>>.
-type kyber768_90s_cipher_text() :: <<_:8704>>.
-type kyber768_90s_shared_secret() :: <<_:256>>.

-export_type([
    kyber768_90s_secret_key/0,
    kyber768_90s_public_key/0,
    kyber768_90s_cipher_text/0,
    kyber768_90s_shared_secret/0
]).

-type kyber1024_secret_key() :: <<_:25344>>.
-type kyber1024_public_key() :: <<_:12544>>.
-type kyber1024_cipher_text() :: <<_:12544>>.
-type kyber1024_shared_secret() :: <<_:256>>.

-export_type([
    kyber1024_secret_key/0,
    kyber1024_public_key/0,
    kyber1024_cipher_text/0,
    kyber1024_shared_secret/0
]).

-type kyber1024_90s_secret_key() :: <<_:25344>>.
-type kyber1024_90s_public_key() :: <<_:12544>>.
-type kyber1024_90s_cipher_text() :: <<_:12544>>.
-type kyber1024_90s_shared_secret() :: <<_:256>>.

-export_type([
    kyber1024_90s_secret_key/0,
    kyber1024_90s_public_key/0,
    kyber1024_90s_cipher_text/0,
    kyber1024_90s_shared_secret/0
]).

-type dilithium2_secret_key() :: <<_:20224>>.
-type dilithium2_public_key() :: <<_:10496>>.
-type dilithium2_message() :: binary().
-type dilithium2_signature() :: <<_:19360>> | binary().

-export_type([
    dilithium2_secret_key/0,
    dilithium2_public_key/0,
    dilithium2_message/0,
    dilithium2_signature/0
]).

-type dilithium2aes_secret_key() :: <<_:20224>>.
-type dilithium2aes_public_key() :: <<_:10496>>.
-type dilithium2aes_message() :: binary().
-type dilithium2aes_signature() :: <<_:19360>> | binary().

-export_type([
    dilithium2aes_secret_key/0,
    dilithium2aes_public_key/0,
    dilithium2aes_message/0,
    dilithium2aes_signature/0
]).

-type dilithium3_secret_key() :: <<_:32000>>.
-type dilithium3_public_key() :: <<_:15616>>.
-type dilithium3_message() :: binary().
-type dilithium3_signature() :: <<_:26344>> | binary().

-export_type([
    dilithium3_secret_key/0,
    dilithium3_public_key/0,
    dilithium3_message/0,
    dilithium3_signature/0
]).

-type dilithium3aes_secret_key() :: <<_:32000>>.
-type dilithium3aes_public_key() :: <<_:15616>>.
-type dilithium3aes_message() :: binary().
-type dilithium3aes_signature() :: <<_:26344>> | binary().

-export_type([
    dilithium3aes_secret_key/0,
    dilithium3aes_public_key/0,
    dilithium3aes_message/0,
    dilithium3aes_signature/0
]).

-type dilithium5_secret_key() :: <<_:38912>>.
-type dilithium5_public_key() :: <<_:20736>>.
-type dilithium5_message() :: binary().
-type dilithium5_signature() :: <<_:36760>> | binary().

-export_type([
    dilithium5_secret_key/0,
    dilithium5_public_key/0,
    dilithium5_message/0,
    dilithium5_signature/0
]).

-type dilithium5aes_secret_key() :: <<_:38912>>.
-type dilithium5aes_public_key() :: <<_:20736>>.
-type dilithium5aes_message() :: binary().
-type dilithium5aes_signature() :: <<_:36760>> | binary().

-export_type([
    dilithium5aes_secret_key/0,
    dilithium5aes_public_key/0,
    dilithium5aes_message/0,
    dilithium5aes_signature/0
]).

-type falcon512_secret_key() :: <<_:10248>>.
-type falcon512_public_key() :: <<_:7176>>.
-type falcon512_message() :: binary().
-type falcon512_signature() :: <<_:5328>> | binary().

-export_type([
    falcon512_secret_key/0,
    falcon512_public_key/0,
    falcon512_message/0,
    falcon512_signature/0
]).

-type falcon1024_secret_key() :: <<_:18440>>.
-type falcon1024_public_key() :: <<_:14344>>.
-type falcon1024_message() :: binary().
-type falcon1024_signature() :: <<_:10240>> | binary().

-export_type([
    falcon1024_secret_key/0,
    falcon1024_public_key/0,
    falcon1024_message/0,
    falcon1024_signature/0
]).

-type sphincs_plus_haraka_128f_robust_secret_key() :: <<_:512>>.
-type sphincs_plus_haraka_128f_robust_public_key() :: <<_:256>>.
-type sphincs_plus_haraka_128f_robust_seed() :: <<_:384>>.
-type sphincs_plus_haraka_128f_robust_message() :: binary().
-type sphincs_plus_haraka_128f_robust_signature() :: <<_:136704>> | binary().

-export_type([
    sphincs_plus_haraka_128f_robust_secret_key/0,
    sphincs_plus_haraka_128f_robust_public_key/0,
    sphincs_plus_haraka_128f_robust_seed/0,
    sphincs_plus_haraka_128f_robust_message/0,
    sphincs_plus_haraka_128f_robust_signature/0
]).

-type sphincs_plus_haraka_128f_simple_secret_key() :: <<_:512>>.
-type sphincs_plus_haraka_128f_simple_public_key() :: <<_:256>>.
-type sphincs_plus_haraka_128f_simple_seed() :: <<_:384>>.
-type sphincs_plus_haraka_128f_simple_message() :: binary().
-type sphincs_plus_haraka_128f_simple_signature() :: <<_:136704>> | binary().

-export_type([
    sphincs_plus_haraka_128f_simple_secret_key/0,
    sphincs_plus_haraka_128f_simple_public_key/0,
    sphincs_plus_haraka_128f_simple_seed/0,
    sphincs_plus_haraka_128f_simple_message/0,
    sphincs_plus_haraka_128f_simple_signature/0
]).

-type sphincs_plus_haraka_128s_robust_secret_key() :: <<_:512>>.
-type sphincs_plus_haraka_128s_robust_public_key() :: <<_:256>>.
-type sphincs_plus_haraka_128s_robust_seed() :: <<_:384>>.
-type sphincs_plus_haraka_128s_robust_message() :: binary().
-type sphincs_plus_haraka_128s_robust_signature() :: <<_:62848>> | binary().

-export_type([
    sphincs_plus_haraka_128s_robust_secret_key/0,
    sphincs_plus_haraka_128s_robust_public_key/0,
    sphincs_plus_haraka_128s_robust_seed/0,
    sphincs_plus_haraka_128s_robust_message/0,
    sphincs_plus_haraka_128s_robust_signature/0
]).

-type sphincs_plus_haraka_128s_simple_secret_key() :: <<_:512>>.
-type sphincs_plus_haraka_128s_simple_public_key() :: <<_:256>>.
-type sphincs_plus_haraka_128s_simple_seed() :: <<_:384>>.
-type sphincs_plus_haraka_128s_simple_message() :: binary().
-type sphincs_plus_haraka_128s_simple_signature() :: <<_:62848>> | binary().

-export_type([
    sphincs_plus_haraka_128s_simple_secret_key/0,
    sphincs_plus_haraka_128s_simple_public_key/0,
    sphincs_plus_haraka_128s_simple_seed/0,
    sphincs_plus_haraka_128s_simple_message/0,
    sphincs_plus_haraka_128s_simple_signature/0
]).

-type sphincs_plus_haraka_192f_robust_secret_key() :: <<_:768>>.
-type sphincs_plus_haraka_192f_robust_public_key() :: <<_:384>>.
-type sphincs_plus_haraka_192f_robust_seed() :: <<_:576>>.
-type sphincs_plus_haraka_192f_robust_message() :: binary().
-type sphincs_plus_haraka_192f_robust_signature() :: <<_:285312>> | binary().

-export_type([
    sphincs_plus_haraka_192f_robust_secret_key/0,
    sphincs_plus_haraka_192f_robust_public_key/0,
    sphincs_plus_haraka_192f_robust_seed/0,
    sphincs_plus_haraka_192f_robust_message/0,
    sphincs_plus_haraka_192f_robust_signature/0
]).

-type sphincs_plus_haraka_192f_simple_secret_key() :: <<_:768>>.
-type sphincs_plus_haraka_192f_simple_public_key() :: <<_:384>>.
-type sphincs_plus_haraka_192f_simple_seed() :: <<_:576>>.
-type sphincs_plus_haraka_192f_simple_message() :: binary().
-type sphincs_plus_haraka_192f_simple_signature() :: <<_:285312>> | binary().

-export_type([
    sphincs_plus_haraka_192f_simple_secret_key/0,
    sphincs_plus_haraka_192f_simple_public_key/0,
    sphincs_plus_haraka_192f_simple_seed/0,
    sphincs_plus_haraka_192f_simple_message/0,
    sphincs_plus_haraka_192f_simple_signature/0
]).

-type sphincs_plus_haraka_192s_robust_secret_key() :: <<_:768>>.
-type sphincs_plus_haraka_192s_robust_public_key() :: <<_:384>>.
-type sphincs_plus_haraka_192s_robust_seed() :: <<_:576>>.
-type sphincs_plus_haraka_192s_robust_message() :: binary().
-type sphincs_plus_haraka_192s_robust_signature() :: <<_:129792>> | binary().

-export_type([
    sphincs_plus_haraka_192s_robust_secret_key/0,
    sphincs_plus_haraka_192s_robust_public_key/0,
    sphincs_plus_haraka_192s_robust_seed/0,
    sphincs_plus_haraka_192s_robust_message/0,
    sphincs_plus_haraka_192s_robust_signature/0
]).

-type sphincs_plus_haraka_192s_simple_secret_key() :: <<_:768>>.
-type sphincs_plus_haraka_192s_simple_public_key() :: <<_:384>>.
-type sphincs_plus_haraka_192s_simple_seed() :: <<_:576>>.
-type sphincs_plus_haraka_192s_simple_message() :: binary().
-type sphincs_plus_haraka_192s_simple_signature() :: <<_:129792>> | binary().

-export_type([
    sphincs_plus_haraka_192s_simple_secret_key/0,
    sphincs_plus_haraka_192s_simple_public_key/0,
    sphincs_plus_haraka_192s_simple_seed/0,
    sphincs_plus_haraka_192s_simple_message/0,
    sphincs_plus_haraka_192s_simple_signature/0
]).

-type sphincs_plus_haraka_256f_robust_secret_key() :: <<_:1024>>.
-type sphincs_plus_haraka_256f_robust_public_key() :: <<_:512>>.
-type sphincs_plus_haraka_256f_robust_seed() :: <<_:768>>.
-type sphincs_plus_haraka_256f_robust_message() :: binary().
-type sphincs_plus_haraka_256f_robust_signature() :: <<_:398848>> | binary().

-export_type([
    sphincs_plus_haraka_256f_robust_secret_key/0,
    sphincs_plus_haraka_256f_robust_public_key/0,
    sphincs_plus_haraka_256f_robust_seed/0,
    sphincs_plus_haraka_256f_robust_message/0,
    sphincs_plus_haraka_256f_robust_signature/0
]).

-type sphincs_plus_haraka_256f_simple_secret_key() :: <<_:1024>>.
-type sphincs_plus_haraka_256f_simple_public_key() :: <<_:512>>.
-type sphincs_plus_haraka_256f_simple_seed() :: <<_:768>>.
-type sphincs_plus_haraka_256f_simple_message() :: binary().
-type sphincs_plus_haraka_256f_simple_signature() :: <<_:398848>> | binary().

-export_type([
    sphincs_plus_haraka_256f_simple_secret_key/0,
    sphincs_plus_haraka_256f_simple_public_key/0,
    sphincs_plus_haraka_256f_simple_seed/0,
    sphincs_plus_haraka_256f_simple_message/0,
    sphincs_plus_haraka_256f_simple_signature/0
]).

-type sphincs_plus_haraka_256s_robust_secret_key() :: <<_:1024>>.
-type sphincs_plus_haraka_256s_robust_public_key() :: <<_:512>>.
-type sphincs_plus_haraka_256s_robust_seed() :: <<_:768>>.
-type sphincs_plus_haraka_256s_robust_message() :: binary().
-type sphincs_plus_haraka_256s_robust_signature() :: <<_:238336>> | binary().

-export_type([
    sphincs_plus_haraka_256s_robust_secret_key/0,
    sphincs_plus_haraka_256s_robust_public_key/0,
    sphincs_plus_haraka_256s_robust_seed/0,
    sphincs_plus_haraka_256s_robust_message/0,
    sphincs_plus_haraka_256s_robust_signature/0
]).

-type sphincs_plus_haraka_256s_simple_secret_key() :: <<_:1024>>.
-type sphincs_plus_haraka_256s_simple_public_key() :: <<_:512>>.
-type sphincs_plus_haraka_256s_simple_seed() :: <<_:768>>.
-type sphincs_plus_haraka_256s_simple_message() :: binary().
-type sphincs_plus_haraka_256s_simple_signature() :: <<_:238336>> | binary().

-export_type([
    sphincs_plus_haraka_256s_simple_secret_key/0,
    sphincs_plus_haraka_256s_simple_public_key/0,
    sphincs_plus_haraka_256s_simple_seed/0,
    sphincs_plus_haraka_256s_simple_message/0,
    sphincs_plus_haraka_256s_simple_signature/0
]).

-type sphincs_plus_sha2_128f_robust_secret_key() :: <<_:512>>.
-type sphincs_plus_sha2_128f_robust_public_key() :: <<_:256>>.
-type sphincs_plus_sha2_128f_robust_seed() :: <<_:384>>.
-type sphincs_plus_sha2_128f_robust_message() :: binary().
-type sphincs_plus_sha2_128f_robust_signature() :: <<_:136704>> | binary().

-export_type([
    sphincs_plus_sha2_128f_robust_secret_key/0,
    sphincs_plus_sha2_128f_robust_public_key/0,
    sphincs_plus_sha2_128f_robust_seed/0,
    sphincs_plus_sha2_128f_robust_message/0,
    sphincs_plus_sha2_128f_robust_signature/0
]).

-type sphincs_plus_sha2_128f_simple_secret_key() :: <<_:512>>.
-type sphincs_plus_sha2_128f_simple_public_key() :: <<_:256>>.
-type sphincs_plus_sha2_128f_simple_seed() :: <<_:384>>.
-type sphincs_plus_sha2_128f_simple_message() :: binary().
-type sphincs_plus_sha2_128f_simple_signature() :: <<_:136704>> | binary().

-export_type([
    sphincs_plus_sha2_128f_simple_secret_key/0,
    sphincs_plus_sha2_128f_simple_public_key/0,
    sphincs_plus_sha2_128f_simple_seed/0,
    sphincs_plus_sha2_128f_simple_message/0,
    sphincs_plus_sha2_128f_simple_signature/0
]).

-type sphincs_plus_sha2_128s_robust_secret_key() :: <<_:512>>.
-type sphincs_plus_sha2_128s_robust_public_key() :: <<_:256>>.
-type sphincs_plus_sha2_128s_robust_seed() :: <<_:384>>.
-type sphincs_plus_sha2_128s_robust_message() :: binary().
-type sphincs_plus_sha2_128s_robust_signature() :: <<_:62848>> | binary().

-export_type([
    sphincs_plus_sha2_128s_robust_secret_key/0,
    sphincs_plus_sha2_128s_robust_public_key/0,
    sphincs_plus_sha2_128s_robust_seed/0,
    sphincs_plus_sha2_128s_robust_message/0,
    sphincs_plus_sha2_128s_robust_signature/0
]).

-type sphincs_plus_sha2_128s_simple_secret_key() :: <<_:512>>.
-type sphincs_plus_sha2_128s_simple_public_key() :: <<_:256>>.
-type sphincs_plus_sha2_128s_simple_seed() :: <<_:384>>.
-type sphincs_plus_sha2_128s_simple_message() :: binary().
-type sphincs_plus_sha2_128s_simple_signature() :: <<_:62848>> | binary().

-export_type([
    sphincs_plus_sha2_128s_simple_secret_key/0,
    sphincs_plus_sha2_128s_simple_public_key/0,
    sphincs_plus_sha2_128s_simple_seed/0,
    sphincs_plus_sha2_128s_simple_message/0,
    sphincs_plus_sha2_128s_simple_signature/0
]).

-type sphincs_plus_sha2_192f_robust_secret_key() :: <<_:768>>.
-type sphincs_plus_sha2_192f_robust_public_key() :: <<_:384>>.
-type sphincs_plus_sha2_192f_robust_seed() :: <<_:576>>.
-type sphincs_plus_sha2_192f_robust_message() :: binary().
-type sphincs_plus_sha2_192f_robust_signature() :: <<_:285312>> | binary().

-export_type([
    sphincs_plus_sha2_192f_robust_secret_key/0,
    sphincs_plus_sha2_192f_robust_public_key/0,
    sphincs_plus_sha2_192f_robust_seed/0,
    sphincs_plus_sha2_192f_robust_message/0,
    sphincs_plus_sha2_192f_robust_signature/0
]).

-type sphincs_plus_sha2_192f_simple_secret_key() :: <<_:768>>.
-type sphincs_plus_sha2_192f_simple_public_key() :: <<_:384>>.
-type sphincs_plus_sha2_192f_simple_seed() :: <<_:576>>.
-type sphincs_plus_sha2_192f_simple_message() :: binary().
-type sphincs_plus_sha2_192f_simple_signature() :: <<_:285312>> | binary().

-export_type([
    sphincs_plus_sha2_192f_simple_secret_key/0,
    sphincs_plus_sha2_192f_simple_public_key/0,
    sphincs_plus_sha2_192f_simple_seed/0,
    sphincs_plus_sha2_192f_simple_message/0,
    sphincs_plus_sha2_192f_simple_signature/0
]).

-type sphincs_plus_sha2_192s_robust_secret_key() :: <<_:768>>.
-type sphincs_plus_sha2_192s_robust_public_key() :: <<_:384>>.
-type sphincs_plus_sha2_192s_robust_seed() :: <<_:576>>.
-type sphincs_plus_sha2_192s_robust_message() :: binary().
-type sphincs_plus_sha2_192s_robust_signature() :: <<_:129792>> | binary().

-export_type([
    sphincs_plus_sha2_192s_robust_secret_key/0,
    sphincs_plus_sha2_192s_robust_public_key/0,
    sphincs_plus_sha2_192s_robust_seed/0,
    sphincs_plus_sha2_192s_robust_message/0,
    sphincs_plus_sha2_192s_robust_signature/0
]).

-type sphincs_plus_sha2_192s_simple_secret_key() :: <<_:768>>.
-type sphincs_plus_sha2_192s_simple_public_key() :: <<_:384>>.
-type sphincs_plus_sha2_192s_simple_seed() :: <<_:576>>.
-type sphincs_plus_sha2_192s_simple_message() :: binary().
-type sphincs_plus_sha2_192s_simple_signature() :: <<_:129792>> | binary().

-export_type([
    sphincs_plus_sha2_192s_simple_secret_key/0,
    sphincs_plus_sha2_192s_simple_public_key/0,
    sphincs_plus_sha2_192s_simple_seed/0,
    sphincs_plus_sha2_192s_simple_message/0,
    sphincs_plus_sha2_192s_simple_signature/0
]).

-type sphincs_plus_sha2_256f_robust_secret_key() :: <<_:1024>>.
-type sphincs_plus_sha2_256f_robust_public_key() :: <<_:512>>.
-type sphincs_plus_sha2_256f_robust_seed() :: <<_:768>>.
-type sphincs_plus_sha2_256f_robust_message() :: binary().
-type sphincs_plus_sha2_256f_robust_signature() :: <<_:398848>> | binary().

-export_type([
    sphincs_plus_sha2_256f_robust_secret_key/0,
    sphincs_plus_sha2_256f_robust_public_key/0,
    sphincs_plus_sha2_256f_robust_seed/0,
    sphincs_plus_sha2_256f_robust_message/0,
    sphincs_plus_sha2_256f_robust_signature/0
]).

-type sphincs_plus_sha2_256f_simple_secret_key() :: <<_:1024>>.
-type sphincs_plus_sha2_256f_simple_public_key() :: <<_:512>>.
-type sphincs_plus_sha2_256f_simple_seed() :: <<_:768>>.
-type sphincs_plus_sha2_256f_simple_message() :: binary().
-type sphincs_plus_sha2_256f_simple_signature() :: <<_:398848>> | binary().

-export_type([
    sphincs_plus_sha2_256f_simple_secret_key/0,
    sphincs_plus_sha2_256f_simple_public_key/0,
    sphincs_plus_sha2_256f_simple_seed/0,
    sphincs_plus_sha2_256f_simple_message/0,
    sphincs_plus_sha2_256f_simple_signature/0
]).

-type sphincs_plus_sha2_256s_robust_secret_key() :: <<_:1024>>.
-type sphincs_plus_sha2_256s_robust_public_key() :: <<_:512>>.
-type sphincs_plus_sha2_256s_robust_seed() :: <<_:768>>.
-type sphincs_plus_sha2_256s_robust_message() :: binary().
-type sphincs_plus_sha2_256s_robust_signature() :: <<_:238336>> | binary().

-export_type([
    sphincs_plus_sha2_256s_robust_secret_key/0,
    sphincs_plus_sha2_256s_robust_public_key/0,
    sphincs_plus_sha2_256s_robust_seed/0,
    sphincs_plus_sha2_256s_robust_message/0,
    sphincs_plus_sha2_256s_robust_signature/0
]).

-type sphincs_plus_sha2_256s_simple_secret_key() :: <<_:1024>>.
-type sphincs_plus_sha2_256s_simple_public_key() :: <<_:512>>.
-type sphincs_plus_sha2_256s_simple_seed() :: <<_:768>>.
-type sphincs_plus_sha2_256s_simple_message() :: binary().
-type sphincs_plus_sha2_256s_simple_signature() :: <<_:238336>> | binary().

-export_type([
    sphincs_plus_sha2_256s_simple_secret_key/0,
    sphincs_plus_sha2_256s_simple_public_key/0,
    sphincs_plus_sha2_256s_simple_seed/0,
    sphincs_plus_sha2_256s_simple_message/0,
    sphincs_plus_sha2_256s_simple_signature/0
]).

-type sphincs_plus_shake_128f_robust_secret_key() :: <<_:512>>.
-type sphincs_plus_shake_128f_robust_public_key() :: <<_:256>>.
-type sphincs_plus_shake_128f_robust_seed() :: <<_:384>>.
-type sphincs_plus_shake_128f_robust_message() :: binary().
-type sphincs_plus_shake_128f_robust_signature() :: <<_:136704>> | binary().

-export_type([
    sphincs_plus_shake_128f_robust_secret_key/0,
    sphincs_plus_shake_128f_robust_public_key/0,
    sphincs_plus_shake_128f_robust_seed/0,
    sphincs_plus_shake_128f_robust_message/0,
    sphincs_plus_shake_128f_robust_signature/0
]).

-type sphincs_plus_shake_128f_simple_secret_key() :: <<_:512>>.
-type sphincs_plus_shake_128f_simple_public_key() :: <<_:256>>.
-type sphincs_plus_shake_128f_simple_seed() :: <<_:384>>.
-type sphincs_plus_shake_128f_simple_message() :: binary().
-type sphincs_plus_shake_128f_simple_signature() :: <<_:136704>> | binary().

-export_type([
    sphincs_plus_shake_128f_simple_secret_key/0,
    sphincs_plus_shake_128f_simple_public_key/0,
    sphincs_plus_shake_128f_simple_seed/0,
    sphincs_plus_shake_128f_simple_message/0,
    sphincs_plus_shake_128f_simple_signature/0
]).

-type sphincs_plus_shake_128s_robust_secret_key() :: <<_:512>>.
-type sphincs_plus_shake_128s_robust_public_key() :: <<_:256>>.
-type sphincs_plus_shake_128s_robust_seed() :: <<_:384>>.
-type sphincs_plus_shake_128s_robust_message() :: binary().
-type sphincs_plus_shake_128s_robust_signature() :: <<_:62848>> | binary().

-export_type([
    sphincs_plus_shake_128s_robust_secret_key/0,
    sphincs_plus_shake_128s_robust_public_key/0,
    sphincs_plus_shake_128s_robust_seed/0,
    sphincs_plus_shake_128s_robust_message/0,
    sphincs_plus_shake_128s_robust_signature/0
]).

-type sphincs_plus_shake_128s_simple_secret_key() :: <<_:512>>.
-type sphincs_plus_shake_128s_simple_public_key() :: <<_:256>>.
-type sphincs_plus_shake_128s_simple_seed() :: <<_:384>>.
-type sphincs_plus_shake_128s_simple_message() :: binary().
-type sphincs_plus_shake_128s_simple_signature() :: <<_:62848>> | binary().

-export_type([
    sphincs_plus_shake_128s_simple_secret_key/0,
    sphincs_plus_shake_128s_simple_public_key/0,
    sphincs_plus_shake_128s_simple_seed/0,
    sphincs_plus_shake_128s_simple_message/0,
    sphincs_plus_shake_128s_simple_signature/0
]).

-type sphincs_plus_shake_192f_robust_secret_key() :: <<_:768>>.
-type sphincs_plus_shake_192f_robust_public_key() :: <<_:384>>.
-type sphincs_plus_shake_192f_robust_seed() :: <<_:576>>.
-type sphincs_plus_shake_192f_robust_message() :: binary().
-type sphincs_plus_shake_192f_robust_signature() :: <<_:285312>> | binary().

-export_type([
    sphincs_plus_shake_192f_robust_secret_key/0,
    sphincs_plus_shake_192f_robust_public_key/0,
    sphincs_plus_shake_192f_robust_seed/0,
    sphincs_plus_shake_192f_robust_message/0,
    sphincs_plus_shake_192f_robust_signature/0
]).

-type sphincs_plus_shake_192f_simple_secret_key() :: <<_:768>>.
-type sphincs_plus_shake_192f_simple_public_key() :: <<_:384>>.
-type sphincs_plus_shake_192f_simple_seed() :: <<_:576>>.
-type sphincs_plus_shake_192f_simple_message() :: binary().
-type sphincs_plus_shake_192f_simple_signature() :: <<_:285312>> | binary().

-export_type([
    sphincs_plus_shake_192f_simple_secret_key/0,
    sphincs_plus_shake_192f_simple_public_key/0,
    sphincs_plus_shake_192f_simple_seed/0,
    sphincs_plus_shake_192f_simple_message/0,
    sphincs_plus_shake_192f_simple_signature/0
]).

-type sphincs_plus_shake_192s_robust_secret_key() :: <<_:768>>.
-type sphincs_plus_shake_192s_robust_public_key() :: <<_:384>>.
-type sphincs_plus_shake_192s_robust_seed() :: <<_:576>>.
-type sphincs_plus_shake_192s_robust_message() :: binary().
-type sphincs_plus_shake_192s_robust_signature() :: <<_:129792>> | binary().

-export_type([
    sphincs_plus_shake_192s_robust_secret_key/0,
    sphincs_plus_shake_192s_robust_public_key/0,
    sphincs_plus_shake_192s_robust_seed/0,
    sphincs_plus_shake_192s_robust_message/0,
    sphincs_plus_shake_192s_robust_signature/0
]).

-type sphincs_plus_shake_192s_simple_secret_key() :: <<_:768>>.
-type sphincs_plus_shake_192s_simple_public_key() :: <<_:384>>.
-type sphincs_plus_shake_192s_simple_seed() :: <<_:576>>.
-type sphincs_plus_shake_192s_simple_message() :: binary().
-type sphincs_plus_shake_192s_simple_signature() :: <<_:129792>> | binary().

-export_type([
    sphincs_plus_shake_192s_simple_secret_key/0,
    sphincs_plus_shake_192s_simple_public_key/0,
    sphincs_plus_shake_192s_simple_seed/0,
    sphincs_plus_shake_192s_simple_message/0,
    sphincs_plus_shake_192s_simple_signature/0
]).

-type sphincs_plus_shake_256f_robust_secret_key() :: <<_:1024>>.
-type sphincs_plus_shake_256f_robust_public_key() :: <<_:512>>.
-type sphincs_plus_shake_256f_robust_seed() :: <<_:768>>.
-type sphincs_plus_shake_256f_robust_message() :: binary().
-type sphincs_plus_shake_256f_robust_signature() :: <<_:398848>> | binary().

-export_type([
    sphincs_plus_shake_256f_robust_secret_key/0,
    sphincs_plus_shake_256f_robust_public_key/0,
    sphincs_plus_shake_256f_robust_seed/0,
    sphincs_plus_shake_256f_robust_message/0,
    sphincs_plus_shake_256f_robust_signature/0
]).

-type sphincs_plus_shake_256f_simple_secret_key() :: <<_:1024>>.
-type sphincs_plus_shake_256f_simple_public_key() :: <<_:512>>.
-type sphincs_plus_shake_256f_simple_seed() :: <<_:768>>.
-type sphincs_plus_shake_256f_simple_message() :: binary().
-type sphincs_plus_shake_256f_simple_signature() :: <<_:398848>> | binary().

-export_type([
    sphincs_plus_shake_256f_simple_secret_key/0,
    sphincs_plus_shake_256f_simple_public_key/0,
    sphincs_plus_shake_256f_simple_seed/0,
    sphincs_plus_shake_256f_simple_message/0,
    sphincs_plus_shake_256f_simple_signature/0
]).

-type sphincs_plus_shake_256s_robust_secret_key() :: <<_:1024>>.
-type sphincs_plus_shake_256s_robust_public_key() :: <<_:512>>.
-type sphincs_plus_shake_256s_robust_seed() :: <<_:768>>.
-type sphincs_plus_shake_256s_robust_message() :: binary().
-type sphincs_plus_shake_256s_robust_signature() :: <<_:238336>> | binary().

-export_type([
    sphincs_plus_shake_256s_robust_secret_key/0,
    sphincs_plus_shake_256s_robust_public_key/0,
    sphincs_plus_shake_256s_robust_seed/0,
    sphincs_plus_shake_256s_robust_message/0,
    sphincs_plus_shake_256s_robust_signature/0
]).

-type sphincs_plus_shake_256s_simple_secret_key() :: <<_:1024>>.
-type sphincs_plus_shake_256s_simple_public_key() :: <<_:512>>.
-type sphincs_plus_shake_256s_simple_seed() :: <<_:768>>.
-type sphincs_plus_shake_256s_simple_message() :: binary().
-type sphincs_plus_shake_256s_simple_signature() :: <<_:238336>> | binary().

-export_type([
    sphincs_plus_shake_256s_simple_secret_key/0,
    sphincs_plus_shake_256s_simple_public_key/0,
    sphincs_plus_shake_256s_simple_seed/0,
    sphincs_plus_shake_256s_simple_message/0,
    sphincs_plus_shake_256s_simple_signature/0
]).

%%%=============================================================================
%%% NIF API functions
%%%=============================================================================

-spec hqc_rmrs_128_info() -> crypto_kem_info().
hqc_rmrs_128_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec hqc_rmrs_128_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: hqc_rmrs_128_public_key(), SecretKey :: hqc_rmrs_128_secret_key().
hqc_rmrs_128_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec hqc_rmrs_128_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: hqc_rmrs_128_public_key(), CipherText :: hqc_rmrs_128_cipher_text(), SharedSecret :: hqc_rmrs_128_shared_secret().
hqc_rmrs_128_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec hqc_rmrs_128_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: hqc_rmrs_128_cipher_text(), SecretKey :: hqc_rmrs_128_secret_key(), SharedSecret :: hqc_rmrs_128_shared_secret().
hqc_rmrs_128_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec hqc_rmrs_192_info() -> crypto_kem_info().
hqc_rmrs_192_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec hqc_rmrs_192_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: hqc_rmrs_192_public_key(), SecretKey :: hqc_rmrs_192_secret_key().
hqc_rmrs_192_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec hqc_rmrs_192_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: hqc_rmrs_192_public_key(), CipherText :: hqc_rmrs_192_cipher_text(), SharedSecret :: hqc_rmrs_192_shared_secret().
hqc_rmrs_192_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec hqc_rmrs_192_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: hqc_rmrs_192_cipher_text(), SecretKey :: hqc_rmrs_192_secret_key(), SharedSecret :: hqc_rmrs_192_shared_secret().
hqc_rmrs_192_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec hqc_rmrs_256_info() -> crypto_kem_info().
hqc_rmrs_256_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec hqc_rmrs_256_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: hqc_rmrs_256_public_key(), SecretKey :: hqc_rmrs_256_secret_key().
hqc_rmrs_256_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec hqc_rmrs_256_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: hqc_rmrs_256_public_key(), CipherText :: hqc_rmrs_256_cipher_text(), SharedSecret :: hqc_rmrs_256_shared_secret().
hqc_rmrs_256_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec hqc_rmrs_256_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: hqc_rmrs_256_cipher_text(), SecretKey :: hqc_rmrs_256_secret_key(), SharedSecret :: hqc_rmrs_256_shared_secret().
hqc_rmrs_256_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec kyber512_info() -> crypto_kem_info().
kyber512_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec kyber512_keypair() -> {PublicKey, SecretKey} when PublicKey :: kyber512_public_key(), SecretKey :: kyber512_secret_key().
kyber512_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec kyber512_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: kyber512_public_key(), CipherText :: kyber512_cipher_text(), SharedSecret :: kyber512_shared_secret().
kyber512_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec kyber512_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: kyber512_cipher_text(), SecretKey :: kyber512_secret_key(), SharedSecret :: kyber512_shared_secret().
kyber512_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec kyber512_90s_info() -> crypto_kem_info().
kyber512_90s_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec kyber512_90s_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: kyber512_90s_public_key(), SecretKey :: kyber512_90s_secret_key().
kyber512_90s_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec kyber512_90s_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: kyber512_90s_public_key(), CipherText :: kyber512_90s_cipher_text(), SharedSecret :: kyber512_90s_shared_secret().
kyber512_90s_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec kyber512_90s_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: kyber512_90s_cipher_text(), SecretKey :: kyber512_90s_secret_key(), SharedSecret :: kyber512_90s_shared_secret().
kyber512_90s_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec kyber768_info() -> crypto_kem_info().
kyber768_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec kyber768_keypair() -> {PublicKey, SecretKey} when PublicKey :: kyber768_public_key(), SecretKey :: kyber768_secret_key().
kyber768_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec kyber768_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: kyber768_public_key(), CipherText :: kyber768_cipher_text(), SharedSecret :: kyber768_shared_secret().
kyber768_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec kyber768_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: kyber768_cipher_text(), SecretKey :: kyber768_secret_key(), SharedSecret :: kyber768_shared_secret().
kyber768_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec kyber768_90s_info() -> crypto_kem_info().
kyber768_90s_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec kyber768_90s_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: kyber768_90s_public_key(), SecretKey :: kyber768_90s_secret_key().
kyber768_90s_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec kyber768_90s_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: kyber768_90s_public_key(), CipherText :: kyber768_90s_cipher_text(), SharedSecret :: kyber768_90s_shared_secret().
kyber768_90s_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec kyber768_90s_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: kyber768_90s_cipher_text(), SecretKey :: kyber768_90s_secret_key(), SharedSecret :: kyber768_90s_shared_secret().
kyber768_90s_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec kyber1024_info() -> crypto_kem_info().
kyber1024_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec kyber1024_keypair() -> {PublicKey, SecretKey} when PublicKey :: kyber1024_public_key(), SecretKey :: kyber1024_secret_key().
kyber1024_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec kyber1024_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: kyber1024_public_key(), CipherText :: kyber1024_cipher_text(), SharedSecret :: kyber1024_shared_secret().
kyber1024_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec kyber1024_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: kyber1024_cipher_text(), SecretKey :: kyber1024_secret_key(), SharedSecret :: kyber1024_shared_secret().
kyber1024_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec kyber1024_90s_info() -> crypto_kem_info().
kyber1024_90s_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec kyber1024_90s_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: kyber1024_90s_public_key(), SecretKey :: kyber1024_90s_secret_key().
kyber1024_90s_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec kyber1024_90s_encapsulate(PublicKey) -> {CipherText, SharedSecret} when
    PublicKey :: kyber1024_90s_public_key(),
    CipherText :: kyber1024_90s_cipher_text(),
    SharedSecret :: kyber1024_90s_shared_secret().
kyber1024_90s_encapsulate(_PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec kyber1024_90s_decapsulate(CipherText, SecretKey) -> SharedSecret when
    CipherText :: kyber1024_90s_cipher_text(),
    SecretKey :: kyber1024_90s_secret_key(),
    SharedSecret :: kyber1024_90s_shared_secret().
kyber1024_90s_decapsulate(_CipherText, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec dilithium2_info() -> crypto_sign_info().
dilithium2_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec dilithium2_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: dilithium2_public_key(), SecretKey :: dilithium2_secret_key().
dilithium2_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec dilithium2_sign(Message, SecretKey) -> Signature when
    Message :: dilithium2_message(), SecretKey :: dilithium2_secret_key(), Signature :: dilithium2_signature().
dilithium2_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec dilithium2_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: dilithium2_signature(), Message :: dilithium2_message(), PublicKey :: dilithium2_public_key().
dilithium2_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec dilithium2aes_info() -> crypto_sign_info().
dilithium2aes_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec dilithium2aes_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: dilithium2aes_public_key(), SecretKey :: dilithium2aes_secret_key().
dilithium2aes_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec dilithium2aes_sign(Message, SecretKey) -> Signature when
    Message :: dilithium2aes_message(), SecretKey :: dilithium2aes_secret_key(), Signature :: dilithium2aes_signature().
dilithium2aes_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec dilithium2aes_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: dilithium2aes_signature(), Message :: dilithium2aes_message(), PublicKey :: dilithium2aes_public_key().
dilithium2aes_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec dilithium3_info() -> crypto_sign_info().
dilithium3_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec dilithium3_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: dilithium3_public_key(), SecretKey :: dilithium3_secret_key().
dilithium3_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec dilithium3_sign(Message, SecretKey) -> Signature when
    Message :: dilithium3_message(), SecretKey :: dilithium3_secret_key(), Signature :: dilithium3_signature().
dilithium3_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec dilithium3_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: dilithium3_signature(), Message :: dilithium3_message(), PublicKey :: dilithium3_public_key().
dilithium3_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec dilithium3aes_info() -> crypto_sign_info().
dilithium3aes_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec dilithium3aes_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: dilithium3aes_public_key(), SecretKey :: dilithium3aes_secret_key().
dilithium3aes_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec dilithium3aes_sign(Message, SecretKey) -> Signature when
    Message :: dilithium3aes_message(), SecretKey :: dilithium3aes_secret_key(), Signature :: dilithium3aes_signature().
dilithium3aes_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec dilithium3aes_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: dilithium3aes_signature(), Message :: dilithium3aes_message(), PublicKey :: dilithium3aes_public_key().
dilithium3aes_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec dilithium5_info() -> crypto_sign_info().
dilithium5_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec dilithium5_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: dilithium5_public_key(), SecretKey :: dilithium5_secret_key().
dilithium5_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec dilithium5_sign(Message, SecretKey) -> Signature when
    Message :: dilithium5_message(), SecretKey :: dilithium5_secret_key(), Signature :: dilithium5_signature().
dilithium5_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec dilithium5_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: dilithium5_signature(), Message :: dilithium5_message(), PublicKey :: dilithium5_public_key().
dilithium5_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec dilithium5aes_info() -> crypto_sign_info().
dilithium5aes_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec dilithium5aes_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: dilithium5aes_public_key(), SecretKey :: dilithium5aes_secret_key().
dilithium5aes_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec dilithium5aes_sign(Message, SecretKey) -> Signature when
    Message :: dilithium5aes_message(), SecretKey :: dilithium5aes_secret_key(), Signature :: dilithium5aes_signature().
dilithium5aes_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec dilithium5aes_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: dilithium5aes_signature(), Message :: dilithium5aes_message(), PublicKey :: dilithium5aes_public_key().
dilithium5aes_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec falcon512_info() -> crypto_sign_info().
falcon512_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec falcon512_keypair() -> {PublicKey, SecretKey} when PublicKey :: falcon512_public_key(), SecretKey :: falcon512_secret_key().
falcon512_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec falcon512_sign(Message, SecretKey) -> Signature when
    Message :: falcon512_message(), SecretKey :: falcon512_secret_key(), Signature :: falcon512_signature().
falcon512_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec falcon512_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: falcon512_signature(), Message :: falcon512_message(), PublicKey :: falcon512_public_key().
falcon512_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec falcon1024_info() -> crypto_sign_info().
falcon1024_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec falcon1024_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: falcon1024_public_key(), SecretKey :: falcon1024_secret_key().
falcon1024_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec falcon1024_sign(Message, SecretKey) -> Signature when
    Message :: falcon1024_message(), SecretKey :: falcon1024_secret_key(), Signature :: falcon1024_signature().
falcon1024_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec falcon1024_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: falcon1024_signature(), Message :: falcon1024_message(), PublicKey :: falcon1024_public_key().
falcon1024_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_128f_robust_info() -> crypto_sign_info().
sphincs_plus_haraka_128f_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_128f_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_haraka_128f_robust_public_key(), SecretKey :: sphincs_plus_haraka_128f_robust_secret_key().
sphincs_plus_haraka_128f_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_128f_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_haraka_128f_robust_seed(),
    PublicKey :: sphincs_plus_haraka_128f_robust_public_key(),
    SecretKey :: sphincs_plus_haraka_128f_robust_secret_key().
sphincs_plus_haraka_128f_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_128f_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_haraka_128f_robust_message(),
    SecretKey :: sphincs_plus_haraka_128f_robust_secret_key(),
    Signature :: sphincs_plus_haraka_128f_robust_signature().
sphincs_plus_haraka_128f_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_128f_robust_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_haraka_128f_robust_signature(),
    Message :: sphincs_plus_haraka_128f_robust_message(),
    PublicKey :: sphincs_plus_haraka_128f_robust_public_key().
sphincs_plus_haraka_128f_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_128f_simple_info() -> crypto_sign_info().
sphincs_plus_haraka_128f_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_128f_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_haraka_128f_simple_public_key(), SecretKey :: sphincs_plus_haraka_128f_simple_secret_key().
sphincs_plus_haraka_128f_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_128f_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_haraka_128f_simple_seed(),
    PublicKey :: sphincs_plus_haraka_128f_simple_public_key(),
    SecretKey :: sphincs_plus_haraka_128f_simple_secret_key().
sphincs_plus_haraka_128f_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_128f_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_haraka_128f_simple_message(),
    SecretKey :: sphincs_plus_haraka_128f_simple_secret_key(),
    Signature :: sphincs_plus_haraka_128f_simple_signature().
sphincs_plus_haraka_128f_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_128f_simple_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_haraka_128f_simple_signature(),
    Message :: sphincs_plus_haraka_128f_simple_message(),
    PublicKey :: sphincs_plus_haraka_128f_simple_public_key().
sphincs_plus_haraka_128f_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_128s_robust_info() -> crypto_sign_info().
sphincs_plus_haraka_128s_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_128s_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_haraka_128s_robust_public_key(), SecretKey :: sphincs_plus_haraka_128s_robust_secret_key().
sphincs_plus_haraka_128s_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_128s_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_haraka_128s_robust_seed(),
    PublicKey :: sphincs_plus_haraka_128s_robust_public_key(),
    SecretKey :: sphincs_plus_haraka_128s_robust_secret_key().
sphincs_plus_haraka_128s_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_128s_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_haraka_128s_robust_message(),
    SecretKey :: sphincs_plus_haraka_128s_robust_secret_key(),
    Signature :: sphincs_plus_haraka_128s_robust_signature().
sphincs_plus_haraka_128s_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_128s_robust_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_haraka_128s_robust_signature(),
    Message :: sphincs_plus_haraka_128s_robust_message(),
    PublicKey :: sphincs_plus_haraka_128s_robust_public_key().
sphincs_plus_haraka_128s_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_128s_simple_info() -> crypto_sign_info().
sphincs_plus_haraka_128s_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_128s_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_haraka_128s_simple_public_key(), SecretKey :: sphincs_plus_haraka_128s_simple_secret_key().
sphincs_plus_haraka_128s_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_128s_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_haraka_128s_simple_seed(),
    PublicKey :: sphincs_plus_haraka_128s_simple_public_key(),
    SecretKey :: sphincs_plus_haraka_128s_simple_secret_key().
sphincs_plus_haraka_128s_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_128s_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_haraka_128s_simple_message(),
    SecretKey :: sphincs_plus_haraka_128s_simple_secret_key(),
    Signature :: sphincs_plus_haraka_128s_simple_signature().
sphincs_plus_haraka_128s_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_128s_simple_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_haraka_128s_simple_signature(),
    Message :: sphincs_plus_haraka_128s_simple_message(),
    PublicKey :: sphincs_plus_haraka_128s_simple_public_key().
sphincs_plus_haraka_128s_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_192f_robust_info() -> crypto_sign_info().
sphincs_plus_haraka_192f_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_192f_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_haraka_192f_robust_public_key(), SecretKey :: sphincs_plus_haraka_192f_robust_secret_key().
sphincs_plus_haraka_192f_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_192f_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_haraka_192f_robust_seed(),
    PublicKey :: sphincs_plus_haraka_192f_robust_public_key(),
    SecretKey :: sphincs_plus_haraka_192f_robust_secret_key().
sphincs_plus_haraka_192f_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_192f_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_haraka_192f_robust_message(),
    SecretKey :: sphincs_plus_haraka_192f_robust_secret_key(),
    Signature :: sphincs_plus_haraka_192f_robust_signature().
sphincs_plus_haraka_192f_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_192f_robust_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_haraka_192f_robust_signature(),
    Message :: sphincs_plus_haraka_192f_robust_message(),
    PublicKey :: sphincs_plus_haraka_192f_robust_public_key().
sphincs_plus_haraka_192f_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_192f_simple_info() -> crypto_sign_info().
sphincs_plus_haraka_192f_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_192f_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_haraka_192f_simple_public_key(), SecretKey :: sphincs_plus_haraka_192f_simple_secret_key().
sphincs_plus_haraka_192f_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_192f_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_haraka_192f_simple_seed(),
    PublicKey :: sphincs_plus_haraka_192f_simple_public_key(),
    SecretKey :: sphincs_plus_haraka_192f_simple_secret_key().
sphincs_plus_haraka_192f_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_192f_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_haraka_192f_simple_message(),
    SecretKey :: sphincs_plus_haraka_192f_simple_secret_key(),
    Signature :: sphincs_plus_haraka_192f_simple_signature().
sphincs_plus_haraka_192f_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_192f_simple_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_haraka_192f_simple_signature(),
    Message :: sphincs_plus_haraka_192f_simple_message(),
    PublicKey :: sphincs_plus_haraka_192f_simple_public_key().
sphincs_plus_haraka_192f_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_192s_robust_info() -> crypto_sign_info().
sphincs_plus_haraka_192s_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_192s_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_haraka_192s_robust_public_key(), SecretKey :: sphincs_plus_haraka_192s_robust_secret_key().
sphincs_plus_haraka_192s_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_192s_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_haraka_192s_robust_seed(),
    PublicKey :: sphincs_plus_haraka_192s_robust_public_key(),
    SecretKey :: sphincs_plus_haraka_192s_robust_secret_key().
sphincs_plus_haraka_192s_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_192s_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_haraka_192s_robust_message(),
    SecretKey :: sphincs_plus_haraka_192s_robust_secret_key(),
    Signature :: sphincs_plus_haraka_192s_robust_signature().
sphincs_plus_haraka_192s_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_192s_robust_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_haraka_192s_robust_signature(),
    Message :: sphincs_plus_haraka_192s_robust_message(),
    PublicKey :: sphincs_plus_haraka_192s_robust_public_key().
sphincs_plus_haraka_192s_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_192s_simple_info() -> crypto_sign_info().
sphincs_plus_haraka_192s_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_192s_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_haraka_192s_simple_public_key(), SecretKey :: sphincs_plus_haraka_192s_simple_secret_key().
sphincs_plus_haraka_192s_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_192s_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_haraka_192s_simple_seed(),
    PublicKey :: sphincs_plus_haraka_192s_simple_public_key(),
    SecretKey :: sphincs_plus_haraka_192s_simple_secret_key().
sphincs_plus_haraka_192s_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_192s_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_haraka_192s_simple_message(),
    SecretKey :: sphincs_plus_haraka_192s_simple_secret_key(),
    Signature :: sphincs_plus_haraka_192s_simple_signature().
sphincs_plus_haraka_192s_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_192s_simple_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_haraka_192s_simple_signature(),
    Message :: sphincs_plus_haraka_192s_simple_message(),
    PublicKey :: sphincs_plus_haraka_192s_simple_public_key().
sphincs_plus_haraka_192s_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_256f_robust_info() -> crypto_sign_info().
sphincs_plus_haraka_256f_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_256f_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_haraka_256f_robust_public_key(), SecretKey :: sphincs_plus_haraka_256f_robust_secret_key().
sphincs_plus_haraka_256f_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_256f_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_haraka_256f_robust_seed(),
    PublicKey :: sphincs_plus_haraka_256f_robust_public_key(),
    SecretKey :: sphincs_plus_haraka_256f_robust_secret_key().
sphincs_plus_haraka_256f_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_256f_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_haraka_256f_robust_message(),
    SecretKey :: sphincs_plus_haraka_256f_robust_secret_key(),
    Signature :: sphincs_plus_haraka_256f_robust_signature().
sphincs_plus_haraka_256f_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_256f_robust_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_haraka_256f_robust_signature(),
    Message :: sphincs_plus_haraka_256f_robust_message(),
    PublicKey :: sphincs_plus_haraka_256f_robust_public_key().
sphincs_plus_haraka_256f_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_256f_simple_info() -> crypto_sign_info().
sphincs_plus_haraka_256f_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_256f_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_haraka_256f_simple_public_key(), SecretKey :: sphincs_plus_haraka_256f_simple_secret_key().
sphincs_plus_haraka_256f_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_256f_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_haraka_256f_simple_seed(),
    PublicKey :: sphincs_plus_haraka_256f_simple_public_key(),
    SecretKey :: sphincs_plus_haraka_256f_simple_secret_key().
sphincs_plus_haraka_256f_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_256f_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_haraka_256f_simple_message(),
    SecretKey :: sphincs_plus_haraka_256f_simple_secret_key(),
    Signature :: sphincs_plus_haraka_256f_simple_signature().
sphincs_plus_haraka_256f_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_256f_simple_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_haraka_256f_simple_signature(),
    Message :: sphincs_plus_haraka_256f_simple_message(),
    PublicKey :: sphincs_plus_haraka_256f_simple_public_key().
sphincs_plus_haraka_256f_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_256s_robust_info() -> crypto_sign_info().
sphincs_plus_haraka_256s_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_256s_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_haraka_256s_robust_public_key(), SecretKey :: sphincs_plus_haraka_256s_robust_secret_key().
sphincs_plus_haraka_256s_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_256s_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_haraka_256s_robust_seed(),
    PublicKey :: sphincs_plus_haraka_256s_robust_public_key(),
    SecretKey :: sphincs_plus_haraka_256s_robust_secret_key().
sphincs_plus_haraka_256s_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_256s_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_haraka_256s_robust_message(),
    SecretKey :: sphincs_plus_haraka_256s_robust_secret_key(),
    Signature :: sphincs_plus_haraka_256s_robust_signature().
sphincs_plus_haraka_256s_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_256s_robust_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_haraka_256s_robust_signature(),
    Message :: sphincs_plus_haraka_256s_robust_message(),
    PublicKey :: sphincs_plus_haraka_256s_robust_public_key().
sphincs_plus_haraka_256s_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_256s_simple_info() -> crypto_sign_info().
sphincs_plus_haraka_256s_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_256s_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_haraka_256s_simple_public_key(), SecretKey :: sphincs_plus_haraka_256s_simple_secret_key().
sphincs_plus_haraka_256s_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_256s_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_haraka_256s_simple_seed(),
    PublicKey :: sphincs_plus_haraka_256s_simple_public_key(),
    SecretKey :: sphincs_plus_haraka_256s_simple_secret_key().
sphincs_plus_haraka_256s_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_256s_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_haraka_256s_simple_message(),
    SecretKey :: sphincs_plus_haraka_256s_simple_secret_key(),
    Signature :: sphincs_plus_haraka_256s_simple_signature().
sphincs_plus_haraka_256s_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_haraka_256s_simple_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_haraka_256s_simple_signature(),
    Message :: sphincs_plus_haraka_256s_simple_message(),
    PublicKey :: sphincs_plus_haraka_256s_simple_public_key().
sphincs_plus_haraka_256s_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_128f_robust_info() -> crypto_sign_info().
sphincs_plus_sha2_128f_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_128f_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_sha2_128f_robust_public_key(), SecretKey :: sphincs_plus_sha2_128f_robust_secret_key().
sphincs_plus_sha2_128f_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_128f_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_sha2_128f_robust_seed(),
    PublicKey :: sphincs_plus_sha2_128f_robust_public_key(),
    SecretKey :: sphincs_plus_sha2_128f_robust_secret_key().
sphincs_plus_sha2_128f_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_128f_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_sha2_128f_robust_message(),
    SecretKey :: sphincs_plus_sha2_128f_robust_secret_key(),
    Signature :: sphincs_plus_sha2_128f_robust_signature().
sphincs_plus_sha2_128f_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_128f_robust_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_sha2_128f_robust_signature(),
    Message :: sphincs_plus_sha2_128f_robust_message(),
    PublicKey :: sphincs_plus_sha2_128f_robust_public_key().
sphincs_plus_sha2_128f_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_128f_simple_info() -> crypto_sign_info().
sphincs_plus_sha2_128f_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_128f_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_sha2_128f_simple_public_key(), SecretKey :: sphincs_plus_sha2_128f_simple_secret_key().
sphincs_plus_sha2_128f_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_128f_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_sha2_128f_simple_seed(),
    PublicKey :: sphincs_plus_sha2_128f_simple_public_key(),
    SecretKey :: sphincs_plus_sha2_128f_simple_secret_key().
sphincs_plus_sha2_128f_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_128f_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_sha2_128f_simple_message(),
    SecretKey :: sphincs_plus_sha2_128f_simple_secret_key(),
    Signature :: sphincs_plus_sha2_128f_simple_signature().
sphincs_plus_sha2_128f_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_128f_simple_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_sha2_128f_simple_signature(),
    Message :: sphincs_plus_sha2_128f_simple_message(),
    PublicKey :: sphincs_plus_sha2_128f_simple_public_key().
sphincs_plus_sha2_128f_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_128s_robust_info() -> crypto_sign_info().
sphincs_plus_sha2_128s_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_128s_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_sha2_128s_robust_public_key(), SecretKey :: sphincs_plus_sha2_128s_robust_secret_key().
sphincs_plus_sha2_128s_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_128s_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_sha2_128s_robust_seed(),
    PublicKey :: sphincs_plus_sha2_128s_robust_public_key(),
    SecretKey :: sphincs_plus_sha2_128s_robust_secret_key().
sphincs_plus_sha2_128s_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_128s_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_sha2_128s_robust_message(),
    SecretKey :: sphincs_plus_sha2_128s_robust_secret_key(),
    Signature :: sphincs_plus_sha2_128s_robust_signature().
sphincs_plus_sha2_128s_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_128s_robust_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_sha2_128s_robust_signature(),
    Message :: sphincs_plus_sha2_128s_robust_message(),
    PublicKey :: sphincs_plus_sha2_128s_robust_public_key().
sphincs_plus_sha2_128s_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_128s_simple_info() -> crypto_sign_info().
sphincs_plus_sha2_128s_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_128s_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_sha2_128s_simple_public_key(), SecretKey :: sphincs_plus_sha2_128s_simple_secret_key().
sphincs_plus_sha2_128s_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_128s_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_sha2_128s_simple_seed(),
    PublicKey :: sphincs_plus_sha2_128s_simple_public_key(),
    SecretKey :: sphincs_plus_sha2_128s_simple_secret_key().
sphincs_plus_sha2_128s_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_128s_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_sha2_128s_simple_message(),
    SecretKey :: sphincs_plus_sha2_128s_simple_secret_key(),
    Signature :: sphincs_plus_sha2_128s_simple_signature().
sphincs_plus_sha2_128s_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_128s_simple_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_sha2_128s_simple_signature(),
    Message :: sphincs_plus_sha2_128s_simple_message(),
    PublicKey :: sphincs_plus_sha2_128s_simple_public_key().
sphincs_plus_sha2_128s_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_192f_robust_info() -> crypto_sign_info().
sphincs_plus_sha2_192f_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_192f_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_sha2_192f_robust_public_key(), SecretKey :: sphincs_plus_sha2_192f_robust_secret_key().
sphincs_plus_sha2_192f_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_192f_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_sha2_192f_robust_seed(),
    PublicKey :: sphincs_plus_sha2_192f_robust_public_key(),
    SecretKey :: sphincs_plus_sha2_192f_robust_secret_key().
sphincs_plus_sha2_192f_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_192f_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_sha2_192f_robust_message(),
    SecretKey :: sphincs_plus_sha2_192f_robust_secret_key(),
    Signature :: sphincs_plus_sha2_192f_robust_signature().
sphincs_plus_sha2_192f_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_192f_robust_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_sha2_192f_robust_signature(),
    Message :: sphincs_plus_sha2_192f_robust_message(),
    PublicKey :: sphincs_plus_sha2_192f_robust_public_key().
sphincs_plus_sha2_192f_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_192f_simple_info() -> crypto_sign_info().
sphincs_plus_sha2_192f_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_192f_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_sha2_192f_simple_public_key(), SecretKey :: sphincs_plus_sha2_192f_simple_secret_key().
sphincs_plus_sha2_192f_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_192f_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_sha2_192f_simple_seed(),
    PublicKey :: sphincs_plus_sha2_192f_simple_public_key(),
    SecretKey :: sphincs_plus_sha2_192f_simple_secret_key().
sphincs_plus_sha2_192f_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_192f_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_sha2_192f_simple_message(),
    SecretKey :: sphincs_plus_sha2_192f_simple_secret_key(),
    Signature :: sphincs_plus_sha2_192f_simple_signature().
sphincs_plus_sha2_192f_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_192f_simple_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_sha2_192f_simple_signature(),
    Message :: sphincs_plus_sha2_192f_simple_message(),
    PublicKey :: sphincs_plus_sha2_192f_simple_public_key().
sphincs_plus_sha2_192f_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_192s_robust_info() -> crypto_sign_info().
sphincs_plus_sha2_192s_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_192s_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_sha2_192s_robust_public_key(), SecretKey :: sphincs_plus_sha2_192s_robust_secret_key().
sphincs_plus_sha2_192s_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_192s_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_sha2_192s_robust_seed(),
    PublicKey :: sphincs_plus_sha2_192s_robust_public_key(),
    SecretKey :: sphincs_plus_sha2_192s_robust_secret_key().
sphincs_plus_sha2_192s_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_192s_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_sha2_192s_robust_message(),
    SecretKey :: sphincs_plus_sha2_192s_robust_secret_key(),
    Signature :: sphincs_plus_sha2_192s_robust_signature().
sphincs_plus_sha2_192s_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_192s_robust_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_sha2_192s_robust_signature(),
    Message :: sphincs_plus_sha2_192s_robust_message(),
    PublicKey :: sphincs_plus_sha2_192s_robust_public_key().
sphincs_plus_sha2_192s_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_192s_simple_info() -> crypto_sign_info().
sphincs_plus_sha2_192s_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_192s_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_sha2_192s_simple_public_key(), SecretKey :: sphincs_plus_sha2_192s_simple_secret_key().
sphincs_plus_sha2_192s_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_192s_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_sha2_192s_simple_seed(),
    PublicKey :: sphincs_plus_sha2_192s_simple_public_key(),
    SecretKey :: sphincs_plus_sha2_192s_simple_secret_key().
sphincs_plus_sha2_192s_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_192s_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_sha2_192s_simple_message(),
    SecretKey :: sphincs_plus_sha2_192s_simple_secret_key(),
    Signature :: sphincs_plus_sha2_192s_simple_signature().
sphincs_plus_sha2_192s_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_192s_simple_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_sha2_192s_simple_signature(),
    Message :: sphincs_plus_sha2_192s_simple_message(),
    PublicKey :: sphincs_plus_sha2_192s_simple_public_key().
sphincs_plus_sha2_192s_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_256f_robust_info() -> crypto_sign_info().
sphincs_plus_sha2_256f_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_256f_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_sha2_256f_robust_public_key(), SecretKey :: sphincs_plus_sha2_256f_robust_secret_key().
sphincs_plus_sha2_256f_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_256f_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_sha2_256f_robust_seed(),
    PublicKey :: sphincs_plus_sha2_256f_robust_public_key(),
    SecretKey :: sphincs_plus_sha2_256f_robust_secret_key().
sphincs_plus_sha2_256f_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_256f_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_sha2_256f_robust_message(),
    SecretKey :: sphincs_plus_sha2_256f_robust_secret_key(),
    Signature :: sphincs_plus_sha2_256f_robust_signature().
sphincs_plus_sha2_256f_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_256f_robust_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_sha2_256f_robust_signature(),
    Message :: sphincs_plus_sha2_256f_robust_message(),
    PublicKey :: sphincs_plus_sha2_256f_robust_public_key().
sphincs_plus_sha2_256f_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_256f_simple_info() -> crypto_sign_info().
sphincs_plus_sha2_256f_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_256f_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_sha2_256f_simple_public_key(), SecretKey :: sphincs_plus_sha2_256f_simple_secret_key().
sphincs_plus_sha2_256f_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_256f_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_sha2_256f_simple_seed(),
    PublicKey :: sphincs_plus_sha2_256f_simple_public_key(),
    SecretKey :: sphincs_plus_sha2_256f_simple_secret_key().
sphincs_plus_sha2_256f_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_256f_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_sha2_256f_simple_message(),
    SecretKey :: sphincs_plus_sha2_256f_simple_secret_key(),
    Signature :: sphincs_plus_sha2_256f_simple_signature().
sphincs_plus_sha2_256f_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_256f_simple_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_sha2_256f_simple_signature(),
    Message :: sphincs_plus_sha2_256f_simple_message(),
    PublicKey :: sphincs_plus_sha2_256f_simple_public_key().
sphincs_plus_sha2_256f_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_256s_robust_info() -> crypto_sign_info().
sphincs_plus_sha2_256s_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_256s_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_sha2_256s_robust_public_key(), SecretKey :: sphincs_plus_sha2_256s_robust_secret_key().
sphincs_plus_sha2_256s_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_256s_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_sha2_256s_robust_seed(),
    PublicKey :: sphincs_plus_sha2_256s_robust_public_key(),
    SecretKey :: sphincs_plus_sha2_256s_robust_secret_key().
sphincs_plus_sha2_256s_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_256s_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_sha2_256s_robust_message(),
    SecretKey :: sphincs_plus_sha2_256s_robust_secret_key(),
    Signature :: sphincs_plus_sha2_256s_robust_signature().
sphincs_plus_sha2_256s_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_256s_robust_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_sha2_256s_robust_signature(),
    Message :: sphincs_plus_sha2_256s_robust_message(),
    PublicKey :: sphincs_plus_sha2_256s_robust_public_key().
sphincs_plus_sha2_256s_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_256s_simple_info() -> crypto_sign_info().
sphincs_plus_sha2_256s_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_256s_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_sha2_256s_simple_public_key(), SecretKey :: sphincs_plus_sha2_256s_simple_secret_key().
sphincs_plus_sha2_256s_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_256s_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_sha2_256s_simple_seed(),
    PublicKey :: sphincs_plus_sha2_256s_simple_public_key(),
    SecretKey :: sphincs_plus_sha2_256s_simple_secret_key().
sphincs_plus_sha2_256s_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_256s_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_sha2_256s_simple_message(),
    SecretKey :: sphincs_plus_sha2_256s_simple_secret_key(),
    Signature :: sphincs_plus_sha2_256s_simple_signature().
sphincs_plus_sha2_256s_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_sha2_256s_simple_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_sha2_256s_simple_signature(),
    Message :: sphincs_plus_sha2_256s_simple_message(),
    PublicKey :: sphincs_plus_sha2_256s_simple_public_key().
sphincs_plus_sha2_256s_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_128f_robust_info() -> crypto_sign_info().
sphincs_plus_shake_128f_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_128f_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_shake_128f_robust_public_key(), SecretKey :: sphincs_plus_shake_128f_robust_secret_key().
sphincs_plus_shake_128f_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_128f_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_shake_128f_robust_seed(),
    PublicKey :: sphincs_plus_shake_128f_robust_public_key(),
    SecretKey :: sphincs_plus_shake_128f_robust_secret_key().
sphincs_plus_shake_128f_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_128f_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_shake_128f_robust_message(),
    SecretKey :: sphincs_plus_shake_128f_robust_secret_key(),
    Signature :: sphincs_plus_shake_128f_robust_signature().
sphincs_plus_shake_128f_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_128f_robust_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_shake_128f_robust_signature(),
    Message :: sphincs_plus_shake_128f_robust_message(),
    PublicKey :: sphincs_plus_shake_128f_robust_public_key().
sphincs_plus_shake_128f_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_128f_simple_info() -> crypto_sign_info().
sphincs_plus_shake_128f_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_128f_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_shake_128f_simple_public_key(), SecretKey :: sphincs_plus_shake_128f_simple_secret_key().
sphincs_plus_shake_128f_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_128f_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_shake_128f_simple_seed(),
    PublicKey :: sphincs_plus_shake_128f_simple_public_key(),
    SecretKey :: sphincs_plus_shake_128f_simple_secret_key().
sphincs_plus_shake_128f_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_128f_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_shake_128f_simple_message(),
    SecretKey :: sphincs_plus_shake_128f_simple_secret_key(),
    Signature :: sphincs_plus_shake_128f_simple_signature().
sphincs_plus_shake_128f_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_128f_simple_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_shake_128f_simple_signature(),
    Message :: sphincs_plus_shake_128f_simple_message(),
    PublicKey :: sphincs_plus_shake_128f_simple_public_key().
sphincs_plus_shake_128f_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_128s_robust_info() -> crypto_sign_info().
sphincs_plus_shake_128s_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_128s_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_shake_128s_robust_public_key(), SecretKey :: sphincs_plus_shake_128s_robust_secret_key().
sphincs_plus_shake_128s_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_128s_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_shake_128s_robust_seed(),
    PublicKey :: sphincs_plus_shake_128s_robust_public_key(),
    SecretKey :: sphincs_plus_shake_128s_robust_secret_key().
sphincs_plus_shake_128s_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_128s_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_shake_128s_robust_message(),
    SecretKey :: sphincs_plus_shake_128s_robust_secret_key(),
    Signature :: sphincs_plus_shake_128s_robust_signature().
sphincs_plus_shake_128s_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_128s_robust_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_shake_128s_robust_signature(),
    Message :: sphincs_plus_shake_128s_robust_message(),
    PublicKey :: sphincs_plus_shake_128s_robust_public_key().
sphincs_plus_shake_128s_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_128s_simple_info() -> crypto_sign_info().
sphincs_plus_shake_128s_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_128s_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_shake_128s_simple_public_key(), SecretKey :: sphincs_plus_shake_128s_simple_secret_key().
sphincs_plus_shake_128s_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_128s_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_shake_128s_simple_seed(),
    PublicKey :: sphincs_plus_shake_128s_simple_public_key(),
    SecretKey :: sphincs_plus_shake_128s_simple_secret_key().
sphincs_plus_shake_128s_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_128s_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_shake_128s_simple_message(),
    SecretKey :: sphincs_plus_shake_128s_simple_secret_key(),
    Signature :: sphincs_plus_shake_128s_simple_signature().
sphincs_plus_shake_128s_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_128s_simple_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_shake_128s_simple_signature(),
    Message :: sphincs_plus_shake_128s_simple_message(),
    PublicKey :: sphincs_plus_shake_128s_simple_public_key().
sphincs_plus_shake_128s_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_192f_robust_info() -> crypto_sign_info().
sphincs_plus_shake_192f_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_192f_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_shake_192f_robust_public_key(), SecretKey :: sphincs_plus_shake_192f_robust_secret_key().
sphincs_plus_shake_192f_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_192f_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_shake_192f_robust_seed(),
    PublicKey :: sphincs_plus_shake_192f_robust_public_key(),
    SecretKey :: sphincs_plus_shake_192f_robust_secret_key().
sphincs_plus_shake_192f_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_192f_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_shake_192f_robust_message(),
    SecretKey :: sphincs_plus_shake_192f_robust_secret_key(),
    Signature :: sphincs_plus_shake_192f_robust_signature().
sphincs_plus_shake_192f_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_192f_robust_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_shake_192f_robust_signature(),
    Message :: sphincs_plus_shake_192f_robust_message(),
    PublicKey :: sphincs_plus_shake_192f_robust_public_key().
sphincs_plus_shake_192f_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_192f_simple_info() -> crypto_sign_info().
sphincs_plus_shake_192f_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_192f_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_shake_192f_simple_public_key(), SecretKey :: sphincs_plus_shake_192f_simple_secret_key().
sphincs_plus_shake_192f_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_192f_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_shake_192f_simple_seed(),
    PublicKey :: sphincs_plus_shake_192f_simple_public_key(),
    SecretKey :: sphincs_plus_shake_192f_simple_secret_key().
sphincs_plus_shake_192f_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_192f_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_shake_192f_simple_message(),
    SecretKey :: sphincs_plus_shake_192f_simple_secret_key(),
    Signature :: sphincs_plus_shake_192f_simple_signature().
sphincs_plus_shake_192f_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_192f_simple_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_shake_192f_simple_signature(),
    Message :: sphincs_plus_shake_192f_simple_message(),
    PublicKey :: sphincs_plus_shake_192f_simple_public_key().
sphincs_plus_shake_192f_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_192s_robust_info() -> crypto_sign_info().
sphincs_plus_shake_192s_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_192s_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_shake_192s_robust_public_key(), SecretKey :: sphincs_plus_shake_192s_robust_secret_key().
sphincs_plus_shake_192s_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_192s_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_shake_192s_robust_seed(),
    PublicKey :: sphincs_plus_shake_192s_robust_public_key(),
    SecretKey :: sphincs_plus_shake_192s_robust_secret_key().
sphincs_plus_shake_192s_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_192s_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_shake_192s_robust_message(),
    SecretKey :: sphincs_plus_shake_192s_robust_secret_key(),
    Signature :: sphincs_plus_shake_192s_robust_signature().
sphincs_plus_shake_192s_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_192s_robust_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_shake_192s_robust_signature(),
    Message :: sphincs_plus_shake_192s_robust_message(),
    PublicKey :: sphincs_plus_shake_192s_robust_public_key().
sphincs_plus_shake_192s_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_192s_simple_info() -> crypto_sign_info().
sphincs_plus_shake_192s_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_192s_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_shake_192s_simple_public_key(), SecretKey :: sphincs_plus_shake_192s_simple_secret_key().
sphincs_plus_shake_192s_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_192s_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_shake_192s_simple_seed(),
    PublicKey :: sphincs_plus_shake_192s_simple_public_key(),
    SecretKey :: sphincs_plus_shake_192s_simple_secret_key().
sphincs_plus_shake_192s_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_192s_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_shake_192s_simple_message(),
    SecretKey :: sphincs_plus_shake_192s_simple_secret_key(),
    Signature :: sphincs_plus_shake_192s_simple_signature().
sphincs_plus_shake_192s_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_192s_simple_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_shake_192s_simple_signature(),
    Message :: sphincs_plus_shake_192s_simple_message(),
    PublicKey :: sphincs_plus_shake_192s_simple_public_key().
sphincs_plus_shake_192s_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_256f_robust_info() -> crypto_sign_info().
sphincs_plus_shake_256f_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_256f_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_shake_256f_robust_public_key(), SecretKey :: sphincs_plus_shake_256f_robust_secret_key().
sphincs_plus_shake_256f_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_256f_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_shake_256f_robust_seed(),
    PublicKey :: sphincs_plus_shake_256f_robust_public_key(),
    SecretKey :: sphincs_plus_shake_256f_robust_secret_key().
sphincs_plus_shake_256f_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_256f_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_shake_256f_robust_message(),
    SecretKey :: sphincs_plus_shake_256f_robust_secret_key(),
    Signature :: sphincs_plus_shake_256f_robust_signature().
sphincs_plus_shake_256f_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_256f_robust_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_shake_256f_robust_signature(),
    Message :: sphincs_plus_shake_256f_robust_message(),
    PublicKey :: sphincs_plus_shake_256f_robust_public_key().
sphincs_plus_shake_256f_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_256f_simple_info() -> crypto_sign_info().
sphincs_plus_shake_256f_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_256f_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_shake_256f_simple_public_key(), SecretKey :: sphincs_plus_shake_256f_simple_secret_key().
sphincs_plus_shake_256f_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_256f_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_shake_256f_simple_seed(),
    PublicKey :: sphincs_plus_shake_256f_simple_public_key(),
    SecretKey :: sphincs_plus_shake_256f_simple_secret_key().
sphincs_plus_shake_256f_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_256f_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_shake_256f_simple_message(),
    SecretKey :: sphincs_plus_shake_256f_simple_secret_key(),
    Signature :: sphincs_plus_shake_256f_simple_signature().
sphincs_plus_shake_256f_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_256f_simple_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_shake_256f_simple_signature(),
    Message :: sphincs_plus_shake_256f_simple_message(),
    PublicKey :: sphincs_plus_shake_256f_simple_public_key().
sphincs_plus_shake_256f_simple_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_256s_robust_info() -> crypto_sign_info().
sphincs_plus_shake_256s_robust_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_256s_robust_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_shake_256s_robust_public_key(), SecretKey :: sphincs_plus_shake_256s_robust_secret_key().
sphincs_plus_shake_256s_robust_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_256s_robust_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_shake_256s_robust_seed(),
    PublicKey :: sphincs_plus_shake_256s_robust_public_key(),
    SecretKey :: sphincs_plus_shake_256s_robust_secret_key().
sphincs_plus_shake_256s_robust_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_256s_robust_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_shake_256s_robust_message(),
    SecretKey :: sphincs_plus_shake_256s_robust_secret_key(),
    Signature :: sphincs_plus_shake_256s_robust_signature().
sphincs_plus_shake_256s_robust_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_256s_robust_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_shake_256s_robust_signature(),
    Message :: sphincs_plus_shake_256s_robust_message(),
    PublicKey :: sphincs_plus_shake_256s_robust_public_key().
sphincs_plus_shake_256s_robust_verify(_Signature, _Message, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_256s_simple_info() -> crypto_sign_info().
sphincs_plus_shake_256s_simple_info() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_256s_simple_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: sphincs_plus_shake_256s_simple_public_key(), SecretKey :: sphincs_plus_shake_256s_simple_secret_key().
sphincs_plus_shake_256s_simple_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_256s_simple_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: sphincs_plus_shake_256s_simple_seed(),
    PublicKey :: sphincs_plus_shake_256s_simple_public_key(),
    SecretKey :: sphincs_plus_shake_256s_simple_secret_key().
sphincs_plus_shake_256s_simple_keypair(_Seed) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_256s_simple_sign(Message, SecretKey) -> Signature when
    Message :: sphincs_plus_shake_256s_simple_message(),
    SecretKey :: sphincs_plus_shake_256s_simple_secret_key(),
    Signature :: sphincs_plus_shake_256s_simple_signature().
sphincs_plus_shake_256s_simple_sign(_Message, _SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

-spec sphincs_plus_shake_256s_simple_verify(Signature, Message, PublicKey) -> Signature when
    Signature :: sphincs_plus_shake_256s_simple_signature(),
    Message :: sphincs_plus_shake_256s_simple_message(),
    PublicKey :: sphincs_plus_shake_256s_simple_public_key().
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
