# pqclean NIF

[![Build Status](https://github.com/potatosalad/erlang-pqclean/actions/workflows/main.yml/badge.svg?branch=main)](https://github.com/potatosalad/erlang-pqclean/actions) [![Hex.pm](https://img.shields.io/hexpm/v/pqclean.svg)](https://hex.pm/packages/pqclean)

[Post-Quantum Cryptography](https://en.wikipedia.org/wiki/Post-quantum_cryptography) NIF based on [PQClean](https://github.com/PQClean/PQClean) for Erlang and Elixir.

See documentation for the `pqclean_nif` module for the full list of types and functions provided.

## Installation

Add `pqclean` to your project's dependencies in `mix.exs`

```elixir
defp deps do
  [
    {:pqclean, "~> 0.0.3"}
  ]
end
```

Add `pqclean` to your project's dependencies in your `Makefile` for [`erlang.mk`](https://github.com/ninenines/erlang.mk) or the following to your `rebar.config`

```erlang
{deps, [
    {pqclean, "0.0.3"}
]}.
```

## Examples

### [Key Encapsulation Mechanism (KEM)](https://en.wikipedia.org/wiki/Key_encapsulation_mechanism) Algorithm Example

```erlang
{PK, SK} = pqclean_nif:kyber768_keypair(),
{CT, SS} = pqclean_nif:kyber768_encapsulate(PK),
     SS  = pqclean_nif:kyber768_decapsulate(CT, SK).
```

#### KEM with Encryption Example

```erlang
% Alice and Bob want to exchange an encrypted messages.
% Alice wants to send Bob the message "a2b".
% Bob wants to send Alice the message "b2a".

% Helper functions (encrypt/decrypt with AES-256-GCM):
Encrypt = fun(K, N, PTxt) ->
    crypto:crypto_one_time_aead(aes_256_gcm, K, <<N:96>>, PTxt, <<>>, true)
end,
Decrypt = fun(K, N, CTxt, CTag) ->
    crypto:crypto_one_time_aead(aes_256_gcm, K, <<N:96>>, CTxt, <<>>, CTag, false)
end.

% Alice generates a new ephemeral keypair using Kyber-768:
{PKa, SKa} = pqclean_nif:kyber768_keypair().

% Alice sends `PKa' to Bob.

% Bob generates a new ephemeral keypair using Kyber-768:
{PKb, SKb} = pqclean_nif:kyber768_keypair(),
% Bob encapsulates a shared-secret `SSb2a' against Alice's `PKa' with
% an ephemeral KEM cipher-text `CTb2a' using Kyber-768:
{CTb2a, SSb2a} = pqclean_nif:kyber768_encapsulate(PKa),
% Bob encrypts plain-text `PKb' with shared-secret `SSb2a' and nonce `0'
% into cipher-text `CTxt_PKb' and cipher-tag `CTag_PKb':
{CTxt_PKb, CTag_PKb} = Encrypt(SSb2a, 0, PKb),
% Bob encrypts plain-text "b2a" with shared-secret `SSb2a' and nonce `1'
% into cipher-text `CTxt_PKb' and cipher-tag `CTag_PKb':
{CTxt_Mb, CTag_Mb} = Encrypt(SSb2a, 1, <<"b2a">>).

% Bob sends `CTb2a', `CTxt_PKb', `CTag_PKb', `CTxt_Mb', and `CTag_Mb' to Alice.

% Alice decapsulates Bob's `CTb2a' using secret-key `SKa' which
% results in shared-secret `SSb2a' using Kyber-768:
SSb2a = pqclean_nif:kyber768_decapsulate(CTb2a, SKa),
% Alice decrypts `PKb' with shared-secret `SSb2a':
PKb = Decrypt(SSb2a, 0, CTxt_PKb, CTag_PKb),
% Alice decrypts Bob's message "b2a" using shared-secret `SSb2a':
<<"b2a">> = Decrypt(SSb2a, 1, CTxt_Mb, CTag_Mb),
% Alice encapsulates a shared-secret `SSa2b' against Bob's `PKb' with
% an ephemeral KEM cipher-text `CTa2b' using Kyber-768:
{CTa2b, SSa2b} = pqclean_nif:kyber768_encapsulate(PKb),
% Alice encrypts plain-text "a2b" with shared-secret `SSa2b' and nonce `0'
% into cipher-text `CTxt_Ma' and cipher-tag `CTag_Ma':
{CTxt_Ma, CTag_Ma} = Encrypt(SSa2b, 0, <<"a2b">>).

% Alice sends `CTa2b', `CTxt_Ma', and `CTag_Ma' to Bob.

% Bob decapsulates Alice's `CTa2b' using secret-key `SKb' which
% results in shared-secret `SSa2b' using Kyber-768:
SSa2b = pqclean_nif:kyber768_decapsulate(CTa2b, SKb),
% Bob decrypts Alice's message "a2b" using shared-secret `SSa2b':
<<"a2b">> = Decrypt(SSa2b, 0, CTxt_Ma, CTag_Ma).

% Alice sends Bob a total of 2,291-bytes.
% Bob sends Alice a total of 2,307-bytes.
```

See [PQNoise](https://eprint.iacr.org/2022/539.pdf) for more in-depth examples.

### [Signature](https://en.wikipedia.org/wiki/Digital_signature) Algorithm Example

```erlang
{PK, SK} = pqclean_nif:falcon512_keypair(),
Msg = <<"message">>,
Sig = pqclean_nif:falcon512_sign(Msg, SK),
true = pqclean_nif:falcon512_verify(Sig, Msg, PK).
```

## KEM Algorithm Support

| KEM Algorithm | NIST Level | Public Key | Secret Key | Cipher Text | Shared Secret |
| ------------- | ----------:| ----------:| ----------:| -----------:| -------------:|
| `HQC-RMRS-128` | 1 | 2,249 | 2,289 | 4,481 | 64 |
| `HQC-RMRS-192` | 3 | 4,522 | 4,562 | 9,026 | 64 |
| `HQC-RMRS-256` | 5 | 7,245 | 7,285 | 14,469 | 64 |
| `Kyber512` | 1 | 800 | 1,632 | 768 | 32 |
| `Kyber512-90s` | 1 | 800 | 1,632 | 768 | 32 |
| `Kyber768` | 3 | 1,184 | 2,400 | 1,088 | 32 |
| `Kyber768-90s` | 3 | 1,184 | 2,400 | 1,088 | 32 |
| `Kyber1024` | 5 | 1,568 | 3,168 | 1,568 | 32 |
| `Kyber1024-90s` | 5 | 1,568 | 3,168 | 1,568 | 32 |
| `Classic McEliece 348864`† | 1 | 261,120 | 6,452 | 128 | 32 |
| `Classic McEliece 348864f`† | 1 | 261,120 | 6,452 | 128 | 32 |
| `Classic McEliece 460896`† | 3 | 524,160 | 13,568 | 188 | 32 |
| `Classic McEliece 460896f`† | 3 | 524,160 | 13,568 | 188 | 32 |
| `Classic McEliece 6688128`† | 5 | 1,044,992 | 13,892 | 240 | 32 |
| `Classic McEliece 6688128`† | 5 | 1,044,992 | 13,892 | 240 | 32 |
| `Classic McEliece 6960119`† | 5 | 1,047,319 | 13,908 | 226 | 32 |
| `Classic McEliece 6960119f`† | 5 | 1,047,319 | 13,908 | 226 | 32 |
| `Classic McEliece 8192128`† | 5 | 1,357,824 | 14,080 | 240 | 32 |
| `Classic McEliece 8192128f`† | 5 | 1,357,824 | 14,080 | 240 | 32 |

**WARNING:** Algorithms marked with a dagger (†) require a large stack for key generation.  See below for more information.

### Large Stack Support

When generating keys for "large stack" algorithms, an exception will be raised if the detected stack size is below 8MB:

```erl
1> try pqclean_nif:mceliece348864_keypair() catch error:{badarg, {_File, _Line}, Reason} -> Reason end.
"Key generation for Classic McEliece 348864 requires a large stack (>= 8MB): "
"please restart the BEAM with `erl +sssdcpu 1024` on 64-bit machines "
"(or `erl +sssdcpu 2048` on 32-bit machines); current setting is `erl +sssdcpu 41`"
```

Restarting the BEAM with `erl +sssdcpu 1024` on 64-bit systems will allow key generation for these algorithms to be supported.

_NOTE:_ If using an `escript`, `rebar3`, `elixir`, etc: it may be simpler to use the environment variable `ERL_AFLAGS="+sssdcpu 1024"` instead.

```bash
$ erl +sssdcpu 1024
```

```erl
1> {PK, SK} = pqclean_nif:mceliece348864_keypair().
{<<38,72,183,62,48,9,8,23,83,149,228,233,255,143,120,71,
   113,143,14,95,28,157,43,73,51,99,6,79,...>>,
 <<116,53,239,220,26,165,236,199,7,246,124,172,167,182,
   154,60,152,213,9,243,206,191,24,129,129,73,132,...>>}
```

## Signature Algorithm Support

| Signature Algorithm | NIST Level | Public Key | Secret Key | Signature | Seed |
| ------------------- | ----------:| ----------:| ----------:| ---------:| ----:|
| `Dilithium2` | 2 | 1,312 | 2,528 | 2,420 | — |
| `Dilithium2-AES` | 2 | 1,312 | 2,528 | 2,420 | — |
| `Dilithium3` | 3 | 1,952 | 4,000 | 3,293 | — |
| `Dilithium3-AES` | 3 | 1,952 | 4,000 | 3,293 | — |
| `Dilithium5` | 5 | 2,592 | 4,864 | 4,595 | — |
| `Dilithium5-AES` | 5 | 2,592 | 4,864 | 4,595 | — |
| `Falcon-512` | 1 | 897 | 1,281 | 666 | — |
| `Falcon-1024` | 5 | 1,793 | 2,305 | 1,280 | — |
| `SPHINCS+-haraka-128f-robust` | 1 | 32 | 64 | 17,088 | 48 |
| `SPHINCS+-haraka-128f-simple` | 1 | 32 | 64 | 17,088 | 48 |
| `SPHINCS+-haraka-128s-robust` | 1 | 32 | 64 | 7,856 | 48 |
| `SPHINCS+-haraka-128s-simple` | 1 | 32 | 64 | 7,856 | 48 |
| `SPHINCS+-haraka-192f-robust` | 2 | 48 | 96 | 35,664 | 72 |
| `SPHINCS+-haraka-192f-simple` | 2 | 48 | 96 | 35,664 | 72 |
| `SPHINCS+-haraka-192s-robust` | 2 | 48 | 96 | 16,224 | 72 |
| `SPHINCS+-haraka-192s-simple` | 2 | 48 | 96 | 16,224 | 72 |
| `SPHINCS+-haraka-256f-robust` | 2 | 64 | 128 | 49,856 | 96 |
| `SPHINCS+-haraka-256f-simple` | 2 | 64 | 128 | 49,856 | 96 |
| `SPHINCS+-haraka-256s-robust` | 2 | 64 | 128 | 29,792 | 96 |
| `SPHINCS+-haraka-256s-simple` | 2 | 64 | 128 | 29,792 | 96 |
| `SPHINCS+-sha2-128f-robust` | 1 | 32 | 64 | 17,088 | 48 |
| `SPHINCS+-sha2-128f-simple` | 1 | 32 | 64 | 17,088 | 48 |
| `SPHINCS+-sha2-128s-robust` | 1 | 32 | 64 | 7,856 | 48 |
| `SPHINCS+-sha2-128s-simple` | 1 | 32 | 64 | 7,856 | 48 |
| `SPHINCS+-sha2-192f-robust` | 3 | 48 | 96 | 35,664 | 72 |
| `SPHINCS+-sha2-192f-simple` | 3 | 48 | 96 | 35,664 | 72 |
| `SPHINCS+-sha2-192s-robust` | 3 | 48 | 96 | 16,224 | 72 |
| `SPHINCS+-sha2-192s-simple` | 3 | 48 | 96 | 16,224 | 72 |
| `SPHINCS+-sha2-256f-robust` | 5 | 64 | 128 | 49,856 | 96 |
| `SPHINCS+-sha2-256f-simple` | 5 | 64 | 128 | 49,856 | 96 |
| `SPHINCS+-sha2-256s-robust` | 5 | 64 | 128 | 29,792 | 96 |
| `SPHINCS+-sha2-256s-simple` | 5 | 64 | 128 | 29,792 | 96 |
| `SPHINCS+-shake-128f-robust` | 1 | 32 | 64 | 17,088 | 48 |
| `SPHINCS+-shake-128f-simple` | 1 | 32 | 64 | 17,088 | 48 |
| `SPHINCS+-shake-128s-robust` | 1 | 32 | 64 | 7,856 | 48 |
| `SPHINCS+-shake-128s-simple` | 1 | 32 | 64 | 7,856 | 48 |
| `SPHINCS+-shake-192f-robust` | 3 | 48 | 96 | 35,664 | 72 |
| `SPHINCS+-shake-192f-simple` | 3 | 48 | 96 | 35,664 | 72 |
| `SPHINCS+-shake-192s-robust` | 3 | 48 | 96 | 16,224 | 72 |
| `SPHINCS+-shake-192s-simple` | 3 | 48 | 96 | 16,224 | 72 |
| `SPHINCS+-shake-256f-robust` | 5 | 64 | 128 | 49,856 | 96 |
| `SPHINCS+-shake-256f-simple` | 5 | 64 | 128 | 49,856 | 96 |
| `SPHINCS+-shake-256s-robust` | 5 | 64 | 128 | 29,792 | 96 |
| `SPHINCS+-shake-256s-simple` | 5 | 64 | 128 | 29,792 | 96 |
