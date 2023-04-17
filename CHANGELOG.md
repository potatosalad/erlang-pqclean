# Changelog

## 0.0.3 (2023-04-17)

* Add support for the various "Classic McEliece" KEM algorithms by checking the current stack size setting and raising an exception if it is less than 8MB during key generation.

## 0.0.2 (2023-04-17)

* Change `Makefile` to compile and link sources directly to the NIF output.

## 0.0.1 (2023-04-16)

* Initial Release
