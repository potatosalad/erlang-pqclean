# pqclean NIF

Work-in-Progress

## KEM Algorithm Support

| KEM Algorithm | NIST Level | Public Key | Secret Key | Cipher Text | Shared Secret |
| ------------- | ----------:| ----------:| ----------:| -----------:| -------------:|
| HQC-RMRS-128 | 1 | 2,249 | 2,289 | 4,481 | 64 |
| HQC-RMRS-192 | 3 | 4,522 | 4,562 | 9,026 | 64 |
| HQC-RMRS-256 | 5 | 7,245 | 7,285 | 14,469 | 64 |
| Kyber512 | 1 | 800 | 1,632 | 768 | 32 |
| Kyber512-90s | 1 | 800 | 1,632 | 768 | 32 |
| Kyber768 | 3 | 1,184 | 2,400 | 1,088 | 32 |
| Kyber768-90s | 3 | 1,184 | 2,400 | 1,088 | 32 |
| Kyber1024 | 5 | 1,568 | 3,168 | 1,568 | 32 |
| Kyber1024-90s | 5 | 1,568 | 3,168 | 1,568 | 32 |

## Signature Algorithm Support

| Signature Algorithm | NIST Level | Public Key | Secret Key | Signature | Seed |
| ------------------- | ----------:| ----------:| ----------:| ---------:| ----:|
| Dilithium2 | 2 | 1,312 | 2,528 | 2,420 | &mdash; |
| Dilithium2-AES | 2 | 1,312 | 2,528 | 2,420 | &mdash; |
| Dilithium3 | 3 | 1,952 | 4,000 | 3,293 | &mdash; |
| Dilithium3-AES | 3 | 1,952 | 4,000 | 3,293 | &mdash; |
| Dilithium5 | 5 | 2,592 | 4,864 | 4,595 | &mdash; |
| Dilithium5-AES | 5 | 2,592 | 4,864 | 4,595 | &mdash; |
| Falcon-512 | 1 | 897 | 1,281 | 666 | &mdash; |
| Falcon-1024 | 5 | 1,793 | 2,305 | 1,280 | &mdash; |
| SPHINCS+-haraka-128f-robust | 1 | 32 | 64 | 17,088 | 48 |
| SPHINCS+-haraka-128f-simple | 1 | 32 | 64 | 17,088 | 48 |
| SPHINCS+-haraka-128s-robust | 1 | 32 | 64 | 7,856 | 48 |
| SPHINCS+-haraka-128s-simple | 1 | 32 | 64 | 7,856 | 48 |
| SPHINCS+-haraka-192f-robust | 2 | 48 | 96 | 35,664 | 72 |
| SPHINCS+-haraka-192f-simple | 2 | 48 | 96 | 35,664 | 72 |
| SPHINCS+-haraka-192s-robust | 2 | 48 | 96 | 16,224 | 72 |
| SPHINCS+-haraka-192s-simple | 2 | 48 | 96 | 16,224 | 72 |
| SPHINCS+-haraka-256f-robust | 2 | 64 | 128 | 49,856 | 96 |
| SPHINCS+-haraka-256f-simple | 2 | 64 | 128 | 49,856 | 96 |
| SPHINCS+-haraka-256s-robust | 2 | 64 | 128 | 29,792 | 96 |
| SPHINCS+-haraka-256s-simple | 2 | 64 | 128 | 29,792 | 96 |
| SPHINCS+-sha2-128f-robust | 1 | 32 | 64 | 17,088 | 48 |
| SPHINCS+-sha2-128f-simple | 1 | 32 | 64 | 17,088 | 48 |
| SPHINCS+-sha2-128s-robust | 1 | 32 | 64 | 7,856 | 48 |
| SPHINCS+-sha2-128s-simple | 1 | 32 | 64 | 7,856 | 48 |
| SPHINCS+-sha2-192f-robust | 3 | 48 | 96 | 35,664 | 72 |
| SPHINCS+-sha2-192f-simple | 3 | 48 | 96 | 35,664 | 72 |
| SPHINCS+-sha2-192s-robust | 3 | 48 | 96 | 16,224 | 72 |
| SPHINCS+-sha2-192s-simple | 3 | 48 | 96 | 16,224 | 72 |
| SPHINCS+-sha2-256f-robust | 5 | 64 | 128 | 49,856 | 96 |
| SPHINCS+-sha2-256f-simple | 5 | 64 | 128 | 49,856 | 96 |
| SPHINCS+-sha2-256s-robust | 5 | 64 | 128 | 29,792 | 96 |
| SPHINCS+-sha2-256s-simple | 5 | 64 | 128 | 29,792 | 96 |
| SPHINCS+-shake-128f-robust | 1 | 32 | 64 | 17,088 | 48 |
| SPHINCS+-shake-128f-simple | 1 | 32 | 64 | 17,088 | 48 |
| SPHINCS+-shake-128s-robust | 1 | 32 | 64 | 7,856 | 48 |
| SPHINCS+-shake-128s-simple | 1 | 32 | 64 | 7,856 | 48 |
| SPHINCS+-shake-192f-robust | 3 | 48 | 96 | 35,664 | 72 |
| SPHINCS+-shake-192f-simple | 3 | 48 | 96 | 35,664 | 72 |
| SPHINCS+-shake-192s-robust | 3 | 48 | 96 | 16,224 | 72 |
| SPHINCS+-shake-192s-simple | 3 | 48 | 96 | 16,224 | 72 |
| SPHINCS+-shake-256f-robust | 5 | 64 | 128 | 49,856 | 96 |
| SPHINCS+-shake-256f-simple | 5 | 64 | 128 | 49,856 | 96 |
| SPHINCS+-shake-256s-robust | 5 | 64 | 128 | 29,792 | 96 |
| SPHINCS+-shake-256s-simple | 5 | 64 | 128 | 29,792 | 96 |
