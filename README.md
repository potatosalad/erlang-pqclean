# pqclean NIF

Work-in-Progress

## KEM Algorithm Support

| KEM Algorithm               | NIST Level    | Public Key | Secret Key | Cipher Text | Shared Secret |
| --------------------------- | -------------:| ----------:| ----------:| -----------:| -------------:|
| HQC-RMRS-128 | 1 | 2249 | 2289 | 4481 | 64 |
| HQC-RMRS-192 | 3 | 4522 | 4562 | 9026 | 64 |
| HQC-RMRS-256 | 5 | 7245 | 7285 | 14469 | 64 |
| Kyber512 | 1 | 800 | 1632 | 768 | 32 |
| Kyber512-90s | 1 | 800 | 1632 | 768 | 32 |
| Kyber768 | 3 | 1184 | 2400 | 1088 | 32 |
| Kyber768-90s | 3 | 1184 | 2400 | 1088 | 32 |
| Kyber1024 | 5 | 1568 | 3168 | 1568 | 32 |
| Kyber1024-90s | 5 | 1568 | 3168 | 1568 | 32 |

## Signature Algorithm Support

| Signature Algorithm         | NIST Level    | Public Key | Secret Key | Signature | Seed |
| --------------------------- | -------------:| ----------:| ----------:| ---------:| ----:|
| Dilithium2 | 2 | 1312 | 2528 | 2420 |  |
| Dilithium2-AES | 2 | 1312 | 2528 | 2420 |  |
| Dilithium3 | 3 | 1952 | 4000 | 3293 |  |
| Dilithium3-AES | 3 | 1952 | 4000 | 3293 |  |
| Dilithium5 | 5 | 2592 | 4864 | 4595 |  |
| Dilithium5-AES | 5 | 2592 | 4864 | 4595 |  |
| Falcon-512 | 1 | 897 | 1281 | 666 |  |
| Falcon-1024 | 5 | 1793 | 2305 | 1280 |  |
| SPHINCS+-haraka-128f-robust | 1 | 32 | 64 | 17088 | 48 |
| SPHINCS+-haraka-128f-simple | 1 | 32 | 64 | 17088 | 48 |
| SPHINCS+-haraka-128s-robust | 1 | 32 | 64 | 7856 | 48 |
| SPHINCS+-haraka-128s-simple | 1 | 32 | 64 | 7856 | 48 |
| SPHINCS+-haraka-192f-robust | 2 | 48 | 96 | 35664 | 72 |
| SPHINCS+-haraka-192f-simple | 2 | 48 | 96 | 35664 | 72 |
| SPHINCS+-haraka-192s-robust | 2 | 48 | 96 | 16224 | 72 |
| SPHINCS+-haraka-192s-simple | 2 | 48 | 96 | 16224 | 72 |
| SPHINCS+-haraka-256f-robust | 2 | 64 | 128 | 49856 | 96 |
| SPHINCS+-haraka-256f-simple | 2 | 64 | 128 | 49856 | 96 |
| SPHINCS+-haraka-256s-robust | 2 | 64 | 128 | 29792 | 96 |
| SPHINCS+-haraka-256s-simple | 2 | 64 | 128 | 29792 | 96 |
| SPHINCS+-sha2-128f-robust | 1 | 32 | 64 | 17088 | 48 |
| SPHINCS+-sha2-128f-simple | 1 | 32 | 64 | 17088 | 48 |
| SPHINCS+-sha2-128s-robust | 1 | 32 | 64 | 7856 | 48 |
| SPHINCS+-sha2-128s-simple | 1 | 32 | 64 | 7856 | 48 |
| SPHINCS+-sha2-192f-robust | 3 | 48 | 96 | 35664 | 72 |
| SPHINCS+-sha2-192f-simple | 3 | 48 | 96 | 35664 | 72 |
| SPHINCS+-sha2-192s-robust | 3 | 48 | 96 | 16224 | 72 |
| SPHINCS+-sha2-192s-simple | 3 | 48 | 96 | 16224 | 72 |
| SPHINCS+-sha2-256f-robust | 5 | 64 | 128 | 49856 | 96 |
| SPHINCS+-sha2-256f-simple | 5 | 64 | 128 | 49856 | 96 |
| SPHINCS+-sha2-256s-robust | 5 | 64 | 128 | 29792 | 96 |
| SPHINCS+-sha2-256s-simple | 5 | 64 | 128 | 29792 | 96 |
| SPHINCS+-shake-128f-robust | 1 | 32 | 64 | 17088 | 48 |
| SPHINCS+-shake-128f-simple | 1 | 32 | 64 | 17088 | 48 |
| SPHINCS+-shake-128s-robust | 1 | 32 | 64 | 7856 | 48 |
| SPHINCS+-shake-128s-simple | 1 | 32 | 64 | 7856 | 48 |
| SPHINCS+-shake-192f-robust | 3 | 48 | 96 | 35664 | 72 |
| SPHINCS+-shake-192f-simple | 3 | 48 | 96 | 35664 | 72 |
| SPHINCS+-shake-192s-robust | 3 | 48 | 96 | 16224 | 72 |
| SPHINCS+-shake-192s-simple | 3 | 48 | 96 | 16224 | 72 |
| SPHINCS+-shake-256f-robust | 5 | 64 | 128 | 49856 | 96 |
| SPHINCS+-shake-256f-simple | 5 | 64 | 128 | 49856 | 96 |
| SPHINCS+-shake-256s-robust | 5 | 64 | 128 | 29792 | 96 |
| SPHINCS+-shake-256s-simple | 5 | 64 | 128 | 29792 | 96 |
