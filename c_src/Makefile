# Based on c_src.mk from erlang.mk by Loic Hoguin <essen@ninenines.eu>

CURDIR := $(shell pwd)
BASEDIR := $(abspath $(CURDIR)/..)

PROJECT = pqclean

# Configuration.

C_SRC_DIR ?= $(CURDIR)
C_SRC_ENV ?= $(C_SRC_DIR)/env.mk
C_SRC_OUTPUT ?= $(BASEDIR)/priv/$(PROJECT)_nif
C_SRC_TYPE ?= shared

C_DEPS_DIR ?= $(BASEDIR)/c_deps

# "erl" command.

ERL_CMD ?= erl
ERL = $(ERL_CMD) +A1 -noinput -boot no_dot_erlang

# Platform detection.

ifeq ($(PLATFORM),)
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
PLATFORM = linux
else ifeq ($(UNAME_S),Darwin)
PLATFORM = darwin
else ifeq ($(UNAME_S),SunOS)
PLATFORM = solaris
else ifeq ($(UNAME_S),GNU)
PLATFORM = gnu
else ifeq ($(UNAME_S),FreeBSD)
PLATFORM = freebsd
else ifeq ($(UNAME_S),NetBSD)
PLATFORM = netbsd
else ifeq ($(UNAME_S),OpenBSD)
PLATFORM = openbsd
else ifeq ($(UNAME_S),DragonFly)
PLATFORM = dragonfly
else ifeq ($(shell uname -o),Msys)
PLATFORM = msys2
else
$(error Unable to detect platform. Please open a ticket with the output of uname -a.)
endif

export PLATFORM
endif

# System type and C compiler/flags.

ifeq ($(PLATFORM),msys2)
	C_SRC_OUTPUT_EXECUTABLE_EXTENSION ?= .exe
	C_SRC_OUTPUT_SHARED_EXTENSION ?= .dll
else
	C_SRC_OUTPUT_EXECUTABLE_EXTENSION ?=
	C_SRC_OUTPUT_SHARED_EXTENSION ?= .so
endif

ifeq ($(C_SRC_TYPE),shared)
	C_SRC_OUTPUT_FILE = $(C_SRC_OUTPUT)$(C_SRC_OUTPUT_SHARED_EXTENSION)
else
	C_SRC_OUTPUT_FILE = $(C_SRC_OUTPUT)$(C_SRC_OUTPUT_EXECUTABLE_EXTENSION)
endif

ifeq ($(PLATFORM),msys2)
# We hardcode the compiler used on MSYS2. The default CC=cc does
# not produce working code. The "gcc" MSYS2 package also doesn't.
	CC = /mingw64/bin/gcc
	export CC
	CXX = /mingw64/bin/g++
	export CXX
	CFLAGS ?= -O2 -g -ggdb -std=c2x -finline-functions -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O2 -g -ggdb -std=c++20 -finline-functions -Wall
else ifeq ($(PLATFORM),darwin)
	CC ?= cc
	CXX ?= c++
	CFLAGS ?= -O2 -g -ggdb -std=c2x -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O2 -g -ggdb -std=c++20 -Wall
	LDFLAGS ?= -flat_namespace -undefined suppress
else ifeq ($(PLATFORM),freebsd)
	CC ?= cc
	CXX ?= c++
	CFLAGS ?= -O2 -g -ggdb -std=c2x -finline-functions -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O2 -g -ggdb -std=c++20 -finline-functions -Wall
else ifeq ($(PLATFORM),linux)
	CC ?= gcc
	CXX ?= g++
	CFLAGS ?= -O2 -g -ggdb -std=c2x -finline-functions -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O2 -g -ggdb -std=c++20 -finline-functions -Wall
else ifeq ($(PLATFORM),solaris)
	CC ?= cc
	CXX ?= c++
	CFLAGS ?= -O2 -g -ggdb -std=c2x -finline-functions -fstack-protector -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O2 -g -ggdb -std=c++20 -finline-functions -fstack-protector -Wall
endif

ifneq ($(PLATFORM),msys2)
	CFLAGS += -fPIC
	CXXFLAGS += -fPIC
endif

ifneq ($(CROSSCOMPILER),)
	CC = $(CROSSCOMPILER)gcc
	CXX = $(CROSSCOMPILER)g++
endif

CFLAGS += -fno-omit-frame-pointer \
	-I"$(ERTS_INCLUDE_DIR)" -I"$(ERL_INTERFACE_INCLUDE_DIR)" \
	-I"$(PQCLEAN_SRC_DIR)"
CXXFLAGS += -fno-omit-frame-pointer \
	-I"$(ERTS_INCLUDE_DIR)" -I"$(ERL_INTERFACE_INCLUDE_DIR)" \
	-I"$(PQCLEAN_SRC_DIR)"

LDLIBS += -L"$(ERL_INTERFACE_LIB_DIR)" \
	-L"$(dir $(PQCLEAN_COMMON_OUTPUT))" -lpqclean_common \
	-L"$(dir $(PQCLEAN_HQCRMRS128_CLEAN_OUTPUT))" -lhqc-rmrs-128_clean \
	-L"$(dir $(PQCLEAN_HQCRMRS192_CLEAN_OUTPUT))" -lhqc-rmrs-192_clean \
	-L"$(dir $(PQCLEAN_HQCRMRS256_CLEAN_OUTPUT))" -lhqc-rmrs-256_clean \
	-L"$(dir $(PQCLEAN_KYBER512_CLEAN_OUTPUT))" -lkyber512_clean \
	-L"$(dir $(PQCLEAN_KYBER51290S_CLEAN_OUTPUT))" -lkyber512-90s_clean \
	-L"$(dir $(PQCLEAN_KYBER768_CLEAN_OUTPUT))" -lkyber768_clean \
	-L"$(dir $(PQCLEAN_KYBER76890S_CLEAN_OUTPUT))" -lkyber768-90s_clean \
	-L"$(dir $(PQCLEAN_KYBER1024_CLEAN_OUTPUT))" -lkyber1024_clean \
	-L"$(dir $(PQCLEAN_KYBER102490S_CLEAN_OUTPUT))" -lkyber1024-90s_clean \
	-L"$(dir $(PQCLEAN_DILITHIUM2_CLEAN_OUTPUT))" -ldilithium2_clean \
	-L"$(dir $(PQCLEAN_DILITHIUM2AES_CLEAN_OUTPUT))" -ldilithium2aes_clean \
	-L"$(dir $(PQCLEAN_DILITHIUM3_CLEAN_OUTPUT))" -ldilithium3_clean \
	-L"$(dir $(PQCLEAN_DILITHIUM3AES_CLEAN_OUTPUT))" -ldilithium3aes_clean \
	-L"$(dir $(PQCLEAN_DILITHIUM5_CLEAN_OUTPUT))" -ldilithium5_clean \
	-L"$(dir $(PQCLEAN_DILITHIUM5AES_CLEAN_OUTPUT))" -ldilithium5aes_clean \
	-L"$(dir $(PQCLEAN_FALCON512_CLEAN_OUTPUT))" -lfalcon-512_clean \
	-L"$(dir $(PQCLEAN_FALCON1024_CLEAN_OUTPUT))" -lfalcon-1024_clean \
	-L"$(dir $(PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_OUTPUT))" -lsphincs-haraka-128f-robust_clean \
	-L"$(dir $(PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_OUTPUT))" -lsphincs-haraka-128f-simple_clean \
	-L"$(dir $(PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_OUTPUT))" -lsphincs-haraka-128s-robust_clean \
	-L"$(dir $(PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_OUTPUT))" -lsphincs-haraka-128s-simple_clean \
	-L"$(dir $(PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_OUTPUT))" -lsphincs-haraka-192f-robust_clean \
	-L"$(dir $(PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_OUTPUT))" -lsphincs-haraka-192f-simple_clean \
	-L"$(dir $(PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_OUTPUT))" -lsphincs-haraka-192s-robust_clean \
	-L"$(dir $(PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_OUTPUT))" -lsphincs-haraka-192s-simple_clean \
	-L"$(dir $(PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_OUTPUT))" -lsphincs-haraka-256f-robust_clean \
	-L"$(dir $(PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_OUTPUT))" -lsphincs-haraka-256f-simple_clean \
	-L"$(dir $(PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_OUTPUT))" -lsphincs-haraka-256s-robust_clean \
	-L"$(dir $(PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_OUTPUT))" -lsphincs-haraka-256s-simple_clean \
	-L"$(dir $(PQCLEAN_SPHINCSSHA2128FROBUST_CLEAN_OUTPUT))" -lsphincs-sha2-128f-robust_clean \
	-L"$(dir $(PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_OUTPUT))" -lsphincs-sha2-128f-simple_clean \
	-L"$(dir $(PQCLEAN_SPHINCSSHA2128SROBUST_CLEAN_OUTPUT))" -lsphincs-sha2-128s-robust_clean \
	-L"$(dir $(PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_OUTPUT))" -lsphincs-sha2-128s-simple_clean \
	-L"$(dir $(PQCLEAN_SPHINCSSHA2192FROBUST_CLEAN_OUTPUT))" -lsphincs-sha2-192f-robust_clean \
	-L"$(dir $(PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_OUTPUT))" -lsphincs-sha2-192f-simple_clean \
	-L"$(dir $(PQCLEAN_SPHINCSSHA2192SROBUST_CLEAN_OUTPUT))" -lsphincs-sha2-192s-robust_clean \
	-L"$(dir $(PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_OUTPUT))" -lsphincs-sha2-192s-simple_clean \
	-L"$(dir $(PQCLEAN_SPHINCSSHA2256FROBUST_CLEAN_OUTPUT))" -lsphincs-sha2-256f-robust_clean \
	-L"$(dir $(PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_OUTPUT))" -lsphincs-sha2-256f-simple_clean \
	-L"$(dir $(PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_OUTPUT))" -lsphincs-sha2-256s-robust_clean \
	-L"$(dir $(PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_OUTPUT))" -lsphincs-sha2-256s-simple_clean \
	-L"$(dir $(PQCLEAN_SPHINCSSHAKE128FROBUST_CLEAN_OUTPUT))" -lsphincs-shake-128f-robust_clean \
	-L"$(dir $(PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_OUTPUT))" -lsphincs-shake-128f-simple_clean \
	-L"$(dir $(PQCLEAN_SPHINCSSHAKE128SROBUST_CLEAN_OUTPUT))" -lsphincs-shake-128s-robust_clean \
	-L"$(dir $(PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_OUTPUT))" -lsphincs-shake-128s-simple_clean \
	-L"$(dir $(PQCLEAN_SPHINCSSHAKE192FROBUST_CLEAN_OUTPUT))" -lsphincs-shake-192f-robust_clean \
	-L"$(dir $(PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_OUTPUT))" -lsphincs-shake-192f-simple_clean \
	-L"$(dir $(PQCLEAN_SPHINCSSHAKE192SROBUST_CLEAN_OUTPUT))" -lsphincs-shake-192s-robust_clean \
	-L"$(dir $(PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_OUTPUT))" -lsphincs-shake-192s-simple_clean \
	-L"$(dir $(PQCLEAN_SPHINCSSHAKE256FROBUST_CLEAN_OUTPUT))" -lsphincs-shake-256f-robust_clean \
	-L"$(dir $(PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_OUTPUT))" -lsphincs-shake-256f-simple_clean \
	-L"$(dir $(PQCLEAN_SPHINCSSHAKE256SROBUST_CLEAN_OUTPUT))" -lsphincs-shake-256s-robust_clean \
	-L"$(dir $(PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_OUTPUT))" -lsphincs-shake-256s-simple_clean

# Dependencies.

PQCLEAN_VSN ?= c1b19a865de329e87e9b3e9152362fcb709da8ab
PQCLEAN_GIT ?= https://github.com/PQClean/PQClean.git
PQCLEAN_SRC_DIR ?= $(C_DEPS_DIR)/PQClean
PQCLEAN_COMMON_OUTPUT ?= $(PQCLEAN_SRC_DIR)/common/libpqclean_common.a
PQCLEAN_MAKE_FILE ?= $(PQCLEAN_SRC_DIR)/Makefile
PQCLEAN_HQCRMRS128_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-128/clean/libhqc-rmrs-128_clean.a
PQCLEAN_HQCRMRS192_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-192/clean/libhqc-rmrs-192_clean.a
PQCLEAN_HQCRMRS256_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-256/clean/libhqc-rmrs-256_clean.a
PQCLEAN_KYBER512_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_kem/kyber512/clean/libkyber512_clean.a
PQCLEAN_KYBER51290S_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_kem/kyber512-90s/clean/libkyber512-90s_clean.a
PQCLEAN_KYBER768_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_kem/kyber768/clean/libkyber768_clean.a
PQCLEAN_KYBER76890S_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_kem/kyber768-90s/clean/libkyber768-90s_clean.a
PQCLEAN_KYBER1024_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_kem/kyber1024/clean/libkyber1024_clean.a
PQCLEAN_KYBER102490S_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_kem/kyber1024-90s/clean/libkyber1024-90s_clean.a
PQCLEAN_DILITHIUM2_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/dilithium2/clean/libdilithium2_clean.a
PQCLEAN_DILITHIUM2AES_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/dilithium2aes/clean/libdilithium2aes_clean.a
PQCLEAN_DILITHIUM3_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/dilithium3/clean/libdilithium3_clean.a
PQCLEAN_DILITHIUM3AES_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/dilithium3aes/clean/libdilithium3aes_clean.a
PQCLEAN_DILITHIUM5_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/dilithium5/clean/libdilithium5_clean.a
PQCLEAN_DILITHIUM5AES_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/dilithium5aes/clean/libdilithium5aes_clean.a
PQCLEAN_FALCON512_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/falcon-512/clean/libfalcon-512_clean.a
PQCLEAN_FALCON1024_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/falcon-1024/clean/libfalcon-1024_clean.a
PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-robust/clean/libsphincs-haraka-128f-robust_clean.a
PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-simple/clean/libsphincs-haraka-128f-simple_clean.a
PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-robust/clean/libsphincs-haraka-128s-robust_clean.a
PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-simple/clean/libsphincs-haraka-128s-simple_clean.a
PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-robust/clean/libsphincs-haraka-192f-robust_clean.a
PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-simple/clean/libsphincs-haraka-192f-simple_clean.a
PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-robust/clean/libsphincs-haraka-192s-robust_clean.a
PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-simple/clean/libsphincs-haraka-192s-simple_clean.a
PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-robust/clean/libsphincs-haraka-256f-robust_clean.a
PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-simple/clean/libsphincs-haraka-256f-simple_clean.a
PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-robust/clean/libsphincs-haraka-256s-robust_clean.a
PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-simple/clean/libsphincs-haraka-256s-simple_clean.a
PQCLEAN_SPHINCSSHA2128FROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-robust/clean/libsphincs-sha2-128f-robust_clean.a
PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-simple/clean/libsphincs-sha2-128f-simple_clean.a
PQCLEAN_SPHINCSSHA2128SROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-robust/clean/libsphincs-sha2-128s-robust_clean.a
PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-simple/clean/libsphincs-sha2-128s-simple_clean.a
PQCLEAN_SPHINCSSHA2192FROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-robust/clean/libsphincs-sha2-192f-robust_clean.a
PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-simple/clean/libsphincs-sha2-192f-simple_clean.a
PQCLEAN_SPHINCSSHA2192SROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-robust/clean/libsphincs-sha2-192s-robust_clean.a
PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-simple/clean/libsphincs-sha2-192s-simple_clean.a
PQCLEAN_SPHINCSSHA2256FROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-robust/clean/libsphincs-sha2-256f-robust_clean.a
PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-simple/clean/libsphincs-sha2-256f-simple_clean.a
PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-robust/clean/libsphincs-sha2-256s-robust_clean.a
PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-simple/clean/libsphincs-sha2-256s-simple_clean.a
PQCLEAN_SPHINCSSHAKE128FROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-robust/clean/libsphincs-shake-128f-robust_clean.a
PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-simple/clean/libsphincs-shake-128f-simple_clean.a
PQCLEAN_SPHINCSSHAKE128SROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-robust/clean/libsphincs-shake-128s-robust_clean.a
PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-simple/clean/libsphincs-shake-128s-simple_clean.a
PQCLEAN_SPHINCSSHAKE192FROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-robust/clean/libsphincs-shake-192f-robust_clean.a
PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-simple/clean/libsphincs-shake-192f-simple_clean.a
PQCLEAN_SPHINCSSHAKE192SROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-robust/clean/libsphincs-shake-192s-robust_clean.a
PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-simple/clean/libsphincs-shake-192s-simple_clean.a
PQCLEAN_SPHINCSSHAKE256FROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-robust/clean/libsphincs-shake-256f-robust_clean.a
PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-simple/clean/libsphincs-shake-256f-simple_clean.a
PQCLEAN_SPHINCSSHAKE256SROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-robust/clean/libsphincs-shake-256s-robust_clean.a
PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-simple/clean/libsphincs-shake-256s-simple_clean.a

ALL_DEPS_OUTPUT ?= \
	$(PQCLEAN_COMMON_OUTPUT) \
	$(PQCLEAN_HQCRMRS128_CLEAN_OUTPUT) \
	$(PQCLEAN_HQCRMRS192_CLEAN_OUTPUT) \
	$(PQCLEAN_HQCRMRS256_CLEAN_OUTPUT) \
	$(PQCLEAN_KYBER512_CLEAN_OUTPUT) \
	$(PQCLEAN_KYBER51290S_CLEAN_OUTPUT) \
	$(PQCLEAN_KYBER768_CLEAN_OUTPUT) \
	$(PQCLEAN_KYBER76890S_CLEAN_OUTPUT) \
	$(PQCLEAN_KYBER1024_CLEAN_OUTPUT) \
	$(PQCLEAN_KYBER102490S_CLEAN_OUTPUT) \
	$(PQCLEAN_DILITHIUM2_CLEAN_OUTPUT) \
	$(PQCLEAN_DILITHIUM2AES_CLEAN_OUTPUT) \
	$(PQCLEAN_DILITHIUM3_CLEAN_OUTPUT) \
	$(PQCLEAN_DILITHIUM3AES_CLEAN_OUTPUT) \
	$(PQCLEAN_DILITHIUM5_CLEAN_OUTPUT) \
	$(PQCLEAN_DILITHIUM5AES_CLEAN_OUTPUT) \
	$(PQCLEAN_FALCON512_CLEAN_OUTPUT) \
	$(PQCLEAN_FALCON1024_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSSHA2128FROBUST_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSSHA2128SROBUST_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSSHA2192FROBUST_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSSHA2192SROBUST_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSSHA2256FROBUST_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSSHAKE128FROBUST_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSSHAKE128SROBUST_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSSHAKE192FROBUST_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSSHAKE192SROBUST_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSSHAKE256FROBUST_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSSHAKE256SROBUST_CLEAN_OUTPUT) \
	$(PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_OUTPUT)

# Verbosity.

V ?= 0

verbose_0 = @
verbose_2 = set -x;
verbose = $(verbose_$(V))

ifeq ($(V),3)
SHELL := $(SHELL) -x
endif

gen_verbose_0 = @echo " GEN   " $@;
gen_verbose_2 = set -x;
gen_verbose = $(gen_verbose_$(V))

gen_verbose_esc_0 = @echo " GEN   " $$@;
gen_verbose_esc_2 = set -x;
gen_verbose_esc = $(gen_verbose_esc_$(V))

c_verbose_0 = @echo " C     " $(filter-out $(notdir $(MAKEFILE_LIST) $(C_SRC_ENV)),$(^F));
c_verbose = $(c_verbose_$(V))

cpp_verbose_0 = @echo " CPP   " $(filter-out $(notdir $(MAKEFILE_LIST) $(C_SRC_ENV)),$(^F));
cpp_verbose = $(cpp_verbose_$(V))

link_verbose_0 = @echo " LD    " $(@F);
link_verbose = $(link_verbose_$(V))

# Targets.

ifeq ($(PLATFORM),msys2)
core_native_path = $(shell cygpath -m $1)
else
core_native_path = $1
endif

# We skip files that contain spaces because they end up causing issues.
core_find = $(if $(wildcard $1),$(shell find $(1:%/=%) \( -type l -o -type f \) -name $(subst *,\*,$2) | grep -v " "))

ifeq ($(SOURCES),)
SOURCES := $(sort $(foreach pat,*.c *.C *.cc *.cpp,$(call core_find,$(C_SRC_DIR)/nif/,$(pat))))
endif
OBJECTS = $(addsuffix .o, $(basename $(SOURCES)))

ifeq ($(FORMAT_SOURCES),)
FORMAT_SOURCES := $(shell find $(C_SRC_DIR)/nif \( -type l -o -type f \) \( -name '*.c' -o -name '*.C' -o -name '*.cc' -o -name '*.cpp' -o -name '*.h' -o -name '*.c.h' -o -name '*.hpp' \) | grep -v " ")
endif

COMPILE_C = $(c_verbose) $(CC) $(CFLAGS) $(CPPFLAGS) -c
COMPILE_CPP = $(cpp_verbose) $(CXX) $(CXXFLAGS) $(CPPFLAGS) -c

all:: deps app

app:: $(C_SRC_ENV) $(C_SRC_OUTPUT_FILE)

ifeq ($(filter $(foreach p,$(ALL_DEPS_OUTPUT),$(if $(wildcard $(p)),,x)), x),)

deps::

else

deps:: $(ALL_DEPS_OUTPUT)

endif

test-build:: $(C_SRC_ENV) $(C_SRC_OUTPUT_FILE)

$(C_DEPS_DIR):
	$(verbose) mkdir -p $(C_DEPS_DIR)

$(PQCLEAN_SRC_DIR):
	$(verbose) if [ ! -f $(PQCLEAN_SRC_DIR)/requirements.txt ]; then \
		git clone -n $(PQCLEAN_GIT) $(PQCLEAN_SRC_DIR) && \
		(cd $(PQCLEAN_SRC_DIR) && git checkout -q $(PQCLEAN_VSN)); \
	else \
		true; \
	fi

PQCLEAN_COMMON_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/common/aes.o \
	$(PQCLEAN_SRC_DIR)/common/fips202.o \
	$(PQCLEAN_SRC_DIR)/common/nistseedexpander.o \
	$(PQCLEAN_SRC_DIR)/common/randombytes.o \
	$(PQCLEAN_SRC_DIR)/common/sha2.o \
	$(PQCLEAN_SRC_DIR)/common/sp800-185.o

$(PQCLEAN_COMMON_OUTPUT): $(PQCLEAN_SRC_DIR) $(PQCLEAN_COMMON_OBJECTS)
	$(AR) -r $@ $(PQCLEAN_COMMON_OBJECTS)

$(PQCLEAN_HQCRMRS128_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_HQCRMRS192_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_HQCRMRS256_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_KYBER512_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_KYBER51290S_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_KYBER768_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_KYBER76890S_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_KYBER1024_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_KYBER102490S_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_DILITHIUM2_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_DILITHIUM2AES_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_DILITHIUM3_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_DILITHIUM3AES_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_DILITHIUM5_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_DILITHIUM5AES_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_FALCON512_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_FALCON1024_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSSHA2128FROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSSHA2128SROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSSHA2192FROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSSHA2192SROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSSHA2256FROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSSHAKE128FROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSSHAKE128SROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSSHAKE192FROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSSHAKE192SROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSSHAKE256FROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSSHAKE256SROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

$(PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"


$(C_SRC_OUTPUT_FILE): deps $(OBJECTS)
	$(verbose) mkdir -p $(dir $@)
	$(link_verbose) $(CC) $(OBJECTS) \
		$(LDFLAGS) $(if $(filter $(C_SRC_TYPE),shared),-shared) $(LDLIBS) \
		-o $(C_SRC_OUTPUT_FILE)

$(OBJECTS): $(MAKEFILE_LIST) $(C_SRC_ENV)

%.o: %.c
	$(COMPILE_C) $(OUTPUT_OPTION) $<

%.o: %.cc
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

%.o: %.C
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

%.o: %.cpp
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

clean:: clean-c_src clean-deps

clean-c_src:
	$(gen_verbose) rm -f $(C_SRC_OUTPUT_FILE) $(OBJECTS)

clean-deps:
	$(gen_verbose) rm -f $(PQCLEAN_COMMON_OUTPUT)
	$(gen_verbose) rm -f $(PQCLEAN_COMMON_OBJECTS)
	$(MAKE) -C $(dir $(PQCLEAN_HQCRMRS128_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_HQCRMRS192_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_HQCRMRS256_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_KYBER512_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_KYBER51290S_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_KYBER768_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_KYBER76890S_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_KYBER1024_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_KYBER102490S_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_DILITHIUM2_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_DILITHIUM2AES_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_DILITHIUM3_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_DILITHIUM3AES_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_DILITHIUM5_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_DILITHIUM5AES_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_FALCON512_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_FALCON1024_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSSHA2128FROBUST_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSSHA2128SROBUST_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSSHA2192FROBUST_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSSHA2192SROBUST_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSSHA2256FROBUST_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSSHAKE128FROBUST_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSSHAKE128SROBUST_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSSHAKE192FROBUST_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSSHAKE192SROBUST_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSSHAKE256FROBUST_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSSHAKE256SROBUST_CLEAN_OUTPUT)) clean
	$(MAKE) -C $(dir $(PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_OUTPUT)) clean

distclean:: distclean-c_src-env

distclean-c_src-env:
	$(gen_verbose) rm -f $(C_SRC_ENV)

format:
	$(gen_verbose) clang-format -i $(FORMAT_SOURCES)

ifneq ($(wildcard $(C_SRC_DIR)),)
ERL_ERTS_DIR = $(shell $(ERL) -eval 'io:format("~s~n", [code:lib_dir(erts)]), halt().')

$(C_SRC_ENV):
	$(verbose) $(ERL) -eval "file:write_file(\"$(call core_native_path,$(C_SRC_ENV))\", \
		io_lib:format( \
			\"# Generated by Erlang.mk. Edit at your own risk!~n~n\" \
			\"ERTS_INCLUDE_DIR ?= ~s/erts-~s/include/~n\" \
			\"ERL_INTERFACE_INCLUDE_DIR ?= ~s~n\" \
			\"ERL_INTERFACE_LIB_DIR ?= ~s~n\" \
			\"ERTS_DIR ?= $(ERL_ERTS_DIR)~n\" \
			\"ERTS_BIN_DIR ?= ~s/erts-~s/bin~n\", \
			[code:root_dir(), erlang:system_info(version), \
			code:lib_dir(erl_interface, include), \
			code:lib_dir(erl_interface, lib), \
			code:root_dir(), erlang:system_info(version)])), \
		halt()."

-include $(C_SRC_ENV)

ifneq ($(ERL_ERTS_DIR),$(ERTS_DIR))
$(shell rm -f $(C_SRC_ENV))
endif
endif