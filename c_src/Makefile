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
	-I"$(PQCLEAN_SRC_DIR)/common" \
	-I"$(PQCLEAN_SRC_DIR)"
CXXFLAGS += -fno-omit-frame-pointer \
	-I"$(ERTS_INCLUDE_DIR)" -I"$(ERL_INTERFACE_INCLUDE_DIR)" \
	-I"$(PQCLEAN_SRC_DIR)/common" \
	-I"$(PQCLEAN_SRC_DIR)"

LDLIBS += -L"$(ERL_INTERFACE_LIB_DIR)"

# LDLIBS += -L"$(ERL_INTERFACE_LIB_DIR)" \
# 	-L"$(dir $(PQCLEAN_COMMON_OUTPUT))" -lpqclean_common \
# # 	-L"$(dir $(PQCLEAN_HQCRMRS128_CLEAN_OUTPUT))" -lhqc-rmrs-128_clean \
# 	# # 	-L"$(dir $(PQCLEAN_HQCRMRS192_CLEAN_OUTPUT))" -lhqc-rmrs-192_clean \
# 	# # 	-L"$(dir $(PQCLEAN_HQCRMRS256_CLEAN_OUTPUT))" -lhqc-rmrs-256_clean \
# 	# # 	-L"$(dir $(PQCLEAN_KYBER512_CLEAN_OUTPUT))" -lkyber512_clean \
# 	# # 	-L"$(dir $(PQCLEAN_KYBER51290S_CLEAN_OUTPUT))" -lkyber512-90s_clean \
# 	# # 	-L"$(dir $(PQCLEAN_KYBER768_CLEAN_OUTPUT))" -lkyber768_clean \
# 	# # 	-L"$(dir $(PQCLEAN_KYBER76890S_CLEAN_OUTPUT))" -lkyber768-90s_clean \
# 	# # 	-L"$(dir $(PQCLEAN_KYBER1024_CLEAN_OUTPUT))" -lkyber1024_clean \
# 	# # 	-L"$(dir $(PQCLEAN_KYBER102490S_CLEAN_OUTPUT))" -lkyber1024-90s_clean \
# 	# # 	-L"$(dir $(PQCLEAN_DILITHIUM2_CLEAN_OUTPUT))" -ldilithium2_clean \
# 	# # 	-L"$(dir $(PQCLEAN_DILITHIUM2AES_CLEAN_OUTPUT))" -ldilithium2aes_clean \
# 	# # 	-L"$(dir $(PQCLEAN_DILITHIUM3_CLEAN_OUTPUT))" -ldilithium3_clean \
# 	# # 	-L"$(dir $(PQCLEAN_DILITHIUM3AES_CLEAN_OUTPUT))" -ldilithium3aes_clean \
# 	# # 	-L"$(dir $(PQCLEAN_DILITHIUM5_CLEAN_OUTPUT))" -ldilithium5_clean \
# 	# # 	-L"$(dir $(PQCLEAN_DILITHIUM5AES_CLEAN_OUTPUT))" -ldilithium5aes_clean \
# 	# # 	-L"$(dir $(PQCLEAN_FALCON512_CLEAN_OUTPUT))" -lfalcon-512_clean \
# 	# # 	-L"$(dir $(PQCLEAN_FALCON1024_CLEAN_OUTPUT))" -lfalcon-1024_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_OUTPUT))" -lsphincs-haraka-128f-robust_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_OUTPUT))" -lsphincs-haraka-128f-simple_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_OUTPUT))" -lsphincs-haraka-128s-robust_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_OUTPUT))" -lsphincs-haraka-128s-simple_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_OUTPUT))" -lsphincs-haraka-192f-robust_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_OUTPUT))" -lsphincs-haraka-192f-simple_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_OUTPUT))" -lsphincs-haraka-192s-robust_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_OUTPUT))" -lsphincs-haraka-192s-simple_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_OUTPUT))" -lsphincs-haraka-256f-robust_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_OUTPUT))" -lsphincs-haraka-256f-simple_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_OUTPUT))" -lsphincs-haraka-256s-robust_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_OUTPUT))" -lsphincs-haraka-256s-simple_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSSHA2128FROBUST_CLEAN_OUTPUT))" -lsphincs-sha2-128f-robust_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_OUTPUT))" -lsphincs-sha2-128f-simple_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSSHA2128SROBUST_CLEAN_OUTPUT))" -lsphincs-sha2-128s-robust_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_OUTPUT))" -lsphincs-sha2-128s-simple_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSSHA2192FROBUST_CLEAN_OUTPUT))" -lsphincs-sha2-192f-robust_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_OUTPUT))" -lsphincs-sha2-192f-simple_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSSHA2192SROBUST_CLEAN_OUTPUT))" -lsphincs-sha2-192s-robust_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_OUTPUT))" -lsphincs-sha2-192s-simple_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSSHA2256FROBUST_CLEAN_OUTPUT))" -lsphincs-sha2-256f-robust_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_OUTPUT))" -lsphincs-sha2-256f-simple_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_OUTPUT))" -lsphincs-sha2-256s-robust_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_OUTPUT))" -lsphincs-sha2-256s-simple_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSSHAKE128FROBUST_CLEAN_OUTPUT))" -lsphincs-shake-128f-robust_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_OUTPUT))" -lsphincs-shake-128f-simple_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSSHAKE128SROBUST_CLEAN_OUTPUT))" -lsphincs-shake-128s-robust_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_OUTPUT))" -lsphincs-shake-128s-simple_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSSHAKE192FROBUST_CLEAN_OUTPUT))" -lsphincs-shake-192f-robust_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_OUTPUT))" -lsphincs-shake-192f-simple_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSSHAKE192SROBUST_CLEAN_OUTPUT))" -lsphincs-shake-192s-robust_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_OUTPUT))" -lsphincs-shake-192s-simple_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSSHAKE256FROBUST_CLEAN_OUTPUT))" -lsphincs-shake-256f-robust_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_OUTPUT))" -lsphincs-shake-256f-simple_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSSHAKE256SROBUST_CLEAN_OUTPUT))" -lsphincs-shake-256s-robust_clean \
# 	# # 	-L"$(dir $(PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_OUTPUT))" -lsphincs-shake-256s-simple_clean# 

# Dependencies.

PQCLEAN_VSN ?= c1b19a865de329e87e9b3e9152362fcb709da8ab
PQCLEAN_GIT ?= https://github.com/PQClean/PQClean.git
PQCLEAN_SRC_DIR ?= $(C_DEPS_DIR)/PQClean
PQCLEAN_COMMON_OUTPUT ?= $(PQCLEAN_SRC_DIR)/common/libpqclean_common.a
PQCLEAN_MAKE_FILE ?= $(PQCLEAN_SRC_DIR)/Makefile
# # PQCLEAN_HQCRMRS128_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-128/clean/libhqc-rmrs-128_clean.a
# # PQCLEAN_HQCRMRS192_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-192/clean/libhqc-rmrs-192_clean.a
# # PQCLEAN_HQCRMRS256_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-256/clean/libhqc-rmrs-256_clean.a
# # PQCLEAN_KYBER512_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_kem/kyber512/clean/libkyber512_clean.a
# # PQCLEAN_KYBER51290S_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_kem/kyber512-90s/clean/libkyber512-90s_clean.a
# # PQCLEAN_KYBER768_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_kem/kyber768/clean/libkyber768_clean.a
# # PQCLEAN_KYBER76890S_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_kem/kyber768-90s/clean/libkyber768-90s_clean.a
# # PQCLEAN_KYBER1024_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_kem/kyber1024/clean/libkyber1024_clean.a
# # PQCLEAN_KYBER102490S_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_kem/kyber1024-90s/clean/libkyber1024-90s_clean.a
# # PQCLEAN_DILITHIUM2_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/dilithium2/clean/libdilithium2_clean.a
# # PQCLEAN_DILITHIUM2AES_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/dilithium2aes/clean/libdilithium2aes_clean.a
# # PQCLEAN_DILITHIUM3_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/dilithium3/clean/libdilithium3_clean.a
# # PQCLEAN_DILITHIUM3AES_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/dilithium3aes/clean/libdilithium3aes_clean.a
# # PQCLEAN_DILITHIUM5_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/dilithium5/clean/libdilithium5_clean.a
# # PQCLEAN_DILITHIUM5AES_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/dilithium5aes/clean/libdilithium5aes_clean.a
# # PQCLEAN_FALCON512_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/falcon-512/clean/libfalcon-512_clean.a
# # PQCLEAN_FALCON1024_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/falcon-1024/clean/libfalcon-1024_clean.a
# # PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-robust/clean/libsphincs-haraka-128f-robust_clean.a
# # PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-simple/clean/libsphincs-haraka-128f-simple_clean.a
# # PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-robust/clean/libsphincs-haraka-128s-robust_clean.a
# # PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-simple/clean/libsphincs-haraka-128s-simple_clean.a
# # PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-robust/clean/libsphincs-haraka-192f-robust_clean.a
# # PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-simple/clean/libsphincs-haraka-192f-simple_clean.a
# # PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-robust/clean/libsphincs-haraka-192s-robust_clean.a
# # PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-simple/clean/libsphincs-haraka-192s-simple_clean.a
# # PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-robust/clean/libsphincs-haraka-256f-robust_clean.a
# # PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-simple/clean/libsphincs-haraka-256f-simple_clean.a
# # PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-robust/clean/libsphincs-haraka-256s-robust_clean.a
# # PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-simple/clean/libsphincs-haraka-256s-simple_clean.a
# # PQCLEAN_SPHINCSSHA2128FROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-robust/clean/libsphincs-sha2-128f-robust_clean.a
# # PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-simple/clean/libsphincs-sha2-128f-simple_clean.a
# # PQCLEAN_SPHINCSSHA2128SROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-robust/clean/libsphincs-sha2-128s-robust_clean.a
# # PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-simple/clean/libsphincs-sha2-128s-simple_clean.a
# # PQCLEAN_SPHINCSSHA2192FROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-robust/clean/libsphincs-sha2-192f-robust_clean.a
# # PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-simple/clean/libsphincs-sha2-192f-simple_clean.a
# # PQCLEAN_SPHINCSSHA2192SROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-robust/clean/libsphincs-sha2-192s-robust_clean.a
# # PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-simple/clean/libsphincs-sha2-192s-simple_clean.a
# # PQCLEAN_SPHINCSSHA2256FROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-robust/clean/libsphincs-sha2-256f-robust_clean.a
# # PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-simple/clean/libsphincs-sha2-256f-simple_clean.a
# # PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-robust/clean/libsphincs-sha2-256s-robust_clean.a
# # PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-simple/clean/libsphincs-sha2-256s-simple_clean.a
# # PQCLEAN_SPHINCSSHAKE128FROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-robust/clean/libsphincs-shake-128f-robust_clean.a
# # PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-simple/clean/libsphincs-shake-128f-simple_clean.a
# # PQCLEAN_SPHINCSSHAKE128SROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-robust/clean/libsphincs-shake-128s-robust_clean.a
# # PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-simple/clean/libsphincs-shake-128s-simple_clean.a
# # PQCLEAN_SPHINCSSHAKE192FROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-robust/clean/libsphincs-shake-192f-robust_clean.a
# # PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-simple/clean/libsphincs-shake-192f-simple_clean.a
# # PQCLEAN_SPHINCSSHAKE192SROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-robust/clean/libsphincs-shake-192s-robust_clean.a
# # PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-simple/clean/libsphincs-shake-192s-simple_clean.a
# # PQCLEAN_SPHINCSSHAKE256FROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-robust/clean/libsphincs-shake-256f-robust_clean.a
# # PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-simple/clean/libsphincs-shake-256f-simple_clean.a
# # PQCLEAN_SPHINCSSHAKE256SROBUST_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-robust/clean/libsphincs-shake-256s-robust_clean.a
# # PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_OUTPUT ?= $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-simple/clean/libsphincs-shake-256s-simple_clean.a
# 
# ALL_DEPS_OUTPUT ?= \
# 	$(PQCLEAN_COMMON_OUTPUT) \
# # 	$(PQCLEAN_HQCRMRS128_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_HQCRMRS192_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_HQCRMRS256_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_KYBER512_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_KYBER51290S_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_KYBER768_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_KYBER76890S_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_KYBER1024_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_KYBER102490S_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_DILITHIUM2_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_DILITHIUM2AES_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_DILITHIUM3_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_DILITHIUM3AES_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_DILITHIUM5_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_DILITHIUM5AES_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_FALCON512_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_FALCON1024_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSSHA2128FROBUST_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSSHA2128SROBUST_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSSHA2192FROBUST_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSSHA2192SROBUST_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSSHA2256FROBUST_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSSHAKE128FROBUST_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSSHAKE128SROBUST_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSSHAKE192FROBUST_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSSHAKE192SROBUST_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSSHAKE256FROBUST_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSSHAKE256SROBUST_CLEAN_OUTPUT) \
# 	# # 	$(PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_OUTPUT)# 

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

ar_verbose_0 = @echo " AR    " $(@F);
ar_verbose = $(ar_verbose_$(V))

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

all:: app

# all:: deps app

app:: $(C_SRC_ENV) $(C_SRC_OUTPUT_FILE)

# ifeq ($(filter $(foreach p,$(ALL_DEPS_OUTPUT),$(if $(wildcard $(p)),,x)), x),)

# deps::

# else

# deps:: $(ALL_DEPS_OUTPUT)

# endif

test-build:: $(C_SRC_ENV) $(C_SRC_OUTPUT_FILE)

$(C_DEPS_DIR):
	$(verbose) mkdir -p $(C_DEPS_DIR)

$(PQCLEAN_SRC_DIR): $(C_DEPS_DIR)
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

# $(PQCLEAN_COMMON_OUTPUT): $(PQCLEAN_SRC_DIR) $(PQCLEAN_COMMON_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_COMMON_OBJECTS)

PQCLEAN_HQCRMRS128_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-128/clean/code.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-128/clean/fft.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-128/clean/gf2x.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-128/clean/gf.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-128/clean/hqc.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-128/clean/kem.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-128/clean/parsing.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-128/clean/reed_muller.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-128/clean/reed_solomon.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-128/clean/vector.o

# $(PQCLEAN_HQCRMRS128_CLEAN_OUTPUT): $(PQCLEAN_HQCRMRS128_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_HQCRMRS128_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_HQCRMRS128_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_HQCRMRS192_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-192/clean/code.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-192/clean/fft.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-192/clean/gf2x.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-192/clean/gf.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-192/clean/hqc.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-192/clean/kem.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-192/clean/parsing.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-192/clean/reed_muller.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-192/clean/reed_solomon.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-192/clean/vector.o

# $(PQCLEAN_HQCRMRS192_CLEAN_OUTPUT): $(PQCLEAN_HQCRMRS192_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_HQCRMRS192_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_HQCRMRS192_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_HQCRMRS256_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-256/clean/code.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-256/clean/fft.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-256/clean/gf2x.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-256/clean/gf.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-256/clean/hqc.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-256/clean/kem.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-256/clean/parsing.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-256/clean/reed_muller.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-256/clean/reed_solomon.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-256/clean/vector.o

# $(PQCLEAN_HQCRMRS256_CLEAN_OUTPUT): $(PQCLEAN_HQCRMRS256_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_HQCRMRS256_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_HQCRMRS256_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_KYBER512_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber512/clean/cbd.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber512/clean/indcpa.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber512/clean/kem.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber512/clean/ntt.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber512/clean/poly.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber512/clean/polyvec.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber512/clean/reduce.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber512/clean/symmetric-shake.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber512/clean/verify.o

# $(PQCLEAN_KYBER512_CLEAN_OUTPUT): $(PQCLEAN_KYBER512_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_KYBER512_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_KYBER512_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_KYBER51290S_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber512-90s/clean/cbd.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber512-90s/clean/indcpa.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber512-90s/clean/kem.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber512-90s/clean/ntt.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber512-90s/clean/poly.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber512-90s/clean/polyvec.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber512-90s/clean/reduce.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber512-90s/clean/symmetric-aes.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber512-90s/clean/verify.o

# $(PQCLEAN_KYBER51290S_CLEAN_OUTPUT): $(PQCLEAN_KYBER51290S_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_KYBER51290S_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_KYBER51290S_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_KYBER768_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber768/clean/cbd.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber768/clean/indcpa.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber768/clean/kem.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber768/clean/ntt.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber768/clean/poly.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber768/clean/polyvec.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber768/clean/reduce.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber768/clean/symmetric-shake.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber768/clean/verify.o

# $(PQCLEAN_KYBER768_CLEAN_OUTPUT): $(PQCLEAN_KYBER768_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_KYBER768_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_KYBER768_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_KYBER76890S_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber768-90s/clean/cbd.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber768-90s/clean/indcpa.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber768-90s/clean/kem.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber768-90s/clean/ntt.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber768-90s/clean/poly.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber768-90s/clean/polyvec.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber768-90s/clean/reduce.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber768-90s/clean/symmetric-aes.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber768-90s/clean/verify.o

# $(PQCLEAN_KYBER76890S_CLEAN_OUTPUT): $(PQCLEAN_KYBER76890S_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_KYBER76890S_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_KYBER76890S_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_KYBER1024_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber1024/clean/cbd.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber1024/clean/indcpa.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber1024/clean/kem.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber1024/clean/ntt.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber1024/clean/poly.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber1024/clean/polyvec.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber1024/clean/reduce.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber1024/clean/symmetric-shake.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber1024/clean/verify.o

# $(PQCLEAN_KYBER1024_CLEAN_OUTPUT): $(PQCLEAN_KYBER1024_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_KYBER1024_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_KYBER1024_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_KYBER102490S_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber1024-90s/clean/cbd.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber1024-90s/clean/indcpa.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber1024-90s/clean/kem.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber1024-90s/clean/ntt.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber1024-90s/clean/poly.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber1024-90s/clean/polyvec.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber1024-90s/clean/reduce.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber1024-90s/clean/symmetric-aes.o \
	$(PQCLEAN_SRC_DIR)/crypto_kem/kyber1024-90s/clean/verify.o

# $(PQCLEAN_KYBER102490S_CLEAN_OUTPUT): $(PQCLEAN_KYBER102490S_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_KYBER102490S_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_KYBER102490S_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_DILITHIUM2_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium2/clean/ntt.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium2/clean/packing.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium2/clean/poly.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium2/clean/polyvec.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium2/clean/reduce.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium2/clean/rounding.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium2/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium2/clean/symmetric-shake.o

# $(PQCLEAN_DILITHIUM2_CLEAN_OUTPUT): $(PQCLEAN_DILITHIUM2_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_DILITHIUM2_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_DILITHIUM2_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_DILITHIUM2AES_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium2aes/clean/aes256ctr.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium2aes/clean/ntt.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium2aes/clean/packing.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium2aes/clean/poly.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium2aes/clean/polyvec.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium2aes/clean/reduce.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium2aes/clean/rounding.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium2aes/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium2aes/clean/symmetric-aes.o

# $(PQCLEAN_DILITHIUM2AES_CLEAN_OUTPUT): $(PQCLEAN_DILITHIUM2AES_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_DILITHIUM2AES_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_DILITHIUM2AES_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_DILITHIUM3_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium3/clean/ntt.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium3/clean/packing.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium3/clean/poly.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium3/clean/polyvec.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium3/clean/reduce.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium3/clean/rounding.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium3/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium3/clean/symmetric-shake.o

# $(PQCLEAN_DILITHIUM3_CLEAN_OUTPUT): $(PQCLEAN_DILITHIUM3_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_DILITHIUM3_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_DILITHIUM3_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_DILITHIUM3AES_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium3aes/clean/aes256ctr.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium3aes/clean/ntt.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium3aes/clean/packing.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium3aes/clean/poly.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium3aes/clean/polyvec.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium3aes/clean/reduce.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium3aes/clean/rounding.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium3aes/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium3aes/clean/symmetric-aes.o

# $(PQCLEAN_DILITHIUM3AES_CLEAN_OUTPUT): $(PQCLEAN_DILITHIUM3AES_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_DILITHIUM3AES_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_DILITHIUM3AES_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_DILITHIUM5_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium5/clean/ntt.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium5/clean/packing.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium5/clean/poly.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium5/clean/polyvec.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium5/clean/reduce.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium5/clean/rounding.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium5/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium5/clean/symmetric-shake.o

# $(PQCLEAN_DILITHIUM5_CLEAN_OUTPUT): $(PQCLEAN_DILITHIUM5_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_DILITHIUM5_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_DILITHIUM5_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_DILITHIUM5AES_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium5aes/clean/aes256ctr.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium5aes/clean/ntt.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium5aes/clean/packing.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium5aes/clean/poly.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium5aes/clean/polyvec.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium5aes/clean/reduce.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium5aes/clean/rounding.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium5aes/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/dilithium5aes/clean/symmetric-aes.o

# $(PQCLEAN_DILITHIUM5AES_CLEAN_OUTPUT): $(PQCLEAN_DILITHIUM5AES_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_DILITHIUM5AES_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_DILITHIUM5AES_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_FALCON512_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/falcon-512/clean/codec.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/falcon-512/clean/common.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/falcon-512/clean/fft.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/falcon-512/clean/fpr.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/falcon-512/clean/keygen.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/falcon-512/clean/pqclean.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/falcon-512/clean/rng.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/falcon-512/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/falcon-512/clean/vrfy.o

# $(PQCLEAN_FALCON512_CLEAN_OUTPUT): $(PQCLEAN_FALCON512_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_FALCON512_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_FALCON512_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_FALCON1024_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/falcon-1024/clean/codec.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/falcon-1024/clean/common.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/falcon-1024/clean/fft.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/falcon-1024/clean/fpr.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/falcon-1024/clean/keygen.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/falcon-1024/clean/pqclean.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/falcon-1024/clean/rng.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/falcon-1024/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/falcon-1024/clean/vrfy.o

# $(PQCLEAN_FALCON1024_CLEAN_OUTPUT): $(PQCLEAN_FALCON1024_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_FALCON1024_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_FALCON1024_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-robust/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-robust/clean/context_haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-robust/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-robust/clean/haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-robust/clean/hash_haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-robust/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-robust/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-robust/clean/thash_haraka_robust.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-robust/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-robust/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-robust/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-robust/clean/wotsx1.o

# $(PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-simple/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-simple/clean/context_haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-simple/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-simple/clean/haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-simple/clean/hash_haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-simple/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-simple/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-simple/clean/thash_haraka_simple.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-simple/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-simple/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-simple/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-simple/clean/wotsx1.o

# $(PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-robust/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-robust/clean/context_haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-robust/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-robust/clean/haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-robust/clean/hash_haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-robust/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-robust/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-robust/clean/thash_haraka_robust.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-robust/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-robust/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-robust/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-robust/clean/wotsx1.o

# $(PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-simple/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-simple/clean/context_haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-simple/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-simple/clean/haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-simple/clean/hash_haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-simple/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-simple/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-simple/clean/thash_haraka_simple.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-simple/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-simple/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-simple/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-simple/clean/wotsx1.o

# $(PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-robust/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-robust/clean/context_haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-robust/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-robust/clean/haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-robust/clean/hash_haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-robust/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-robust/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-robust/clean/thash_haraka_robust.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-robust/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-robust/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-robust/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-robust/clean/wotsx1.o

# $(PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-simple/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-simple/clean/context_haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-simple/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-simple/clean/haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-simple/clean/hash_haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-simple/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-simple/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-simple/clean/thash_haraka_simple.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-simple/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-simple/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-simple/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-simple/clean/wotsx1.o

# $(PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-robust/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-robust/clean/context_haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-robust/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-robust/clean/haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-robust/clean/hash_haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-robust/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-robust/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-robust/clean/thash_haraka_robust.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-robust/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-robust/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-robust/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-robust/clean/wotsx1.o

# $(PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-simple/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-simple/clean/context_haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-simple/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-simple/clean/haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-simple/clean/hash_haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-simple/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-simple/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-simple/clean/thash_haraka_simple.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-simple/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-simple/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-simple/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-simple/clean/wotsx1.o

# $(PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-robust/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-robust/clean/context_haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-robust/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-robust/clean/haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-robust/clean/hash_haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-robust/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-robust/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-robust/clean/thash_haraka_robust.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-robust/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-robust/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-robust/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-robust/clean/wotsx1.o

# $(PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-simple/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-simple/clean/context_haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-simple/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-simple/clean/haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-simple/clean/hash_haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-simple/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-simple/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-simple/clean/thash_haraka_simple.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-simple/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-simple/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-simple/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-simple/clean/wotsx1.o

# $(PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-robust/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-robust/clean/context_haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-robust/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-robust/clean/haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-robust/clean/hash_haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-robust/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-robust/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-robust/clean/thash_haraka_robust.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-robust/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-robust/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-robust/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-robust/clean/wotsx1.o

# $(PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-simple/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-simple/clean/context_haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-simple/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-simple/clean/haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-simple/clean/hash_haraka.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-simple/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-simple/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-simple/clean/thash_haraka_simple.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-simple/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-simple/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-simple/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-simple/clean/wotsx1.o

# $(PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSSHA2128FROBUST_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-robust/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-robust/clean/context_sha2.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-robust/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-robust/clean/hash_sha2.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-robust/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-robust/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-robust/clean/thash_sha2_robust.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-robust/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-robust/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-robust/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-robust/clean/wotsx1.o

# $(PQCLEAN_SPHINCSSHA2128FROBUST_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSSHA2128FROBUST_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSSHA2128FROBUST_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSSHA2128FROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-simple/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-simple/clean/context_sha2.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-simple/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-simple/clean/hash_sha2.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-simple/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-simple/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-simple/clean/thash_sha2_simple.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-simple/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-simple/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-simple/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-simple/clean/wotsx1.o

# $(PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSSHA2128SROBUST_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-robust/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-robust/clean/context_sha2.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-robust/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-robust/clean/hash_sha2.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-robust/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-robust/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-robust/clean/thash_sha2_robust.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-robust/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-robust/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-robust/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-robust/clean/wotsx1.o

# $(PQCLEAN_SPHINCSSHA2128SROBUST_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSSHA2128SROBUST_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSSHA2128SROBUST_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSSHA2128SROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-simple/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-simple/clean/context_sha2.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-simple/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-simple/clean/hash_sha2.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-simple/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-simple/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-simple/clean/thash_sha2_simple.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-simple/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-simple/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-simple/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-simple/clean/wotsx1.o

# $(PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSSHA2192FROBUST_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-robust/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-robust/clean/context_sha2.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-robust/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-robust/clean/hash_sha2.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-robust/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-robust/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-robust/clean/thash_sha2_robust.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-robust/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-robust/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-robust/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-robust/clean/wotsx1.o

# $(PQCLEAN_SPHINCSSHA2192FROBUST_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSSHA2192FROBUST_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSSHA2192FROBUST_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSSHA2192FROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-simple/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-simple/clean/context_sha2.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-simple/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-simple/clean/hash_sha2.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-simple/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-simple/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-simple/clean/thash_sha2_simple.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-simple/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-simple/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-simple/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-simple/clean/wotsx1.o

# $(PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSSHA2192SROBUST_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-robust/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-robust/clean/context_sha2.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-robust/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-robust/clean/hash_sha2.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-robust/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-robust/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-robust/clean/thash_sha2_robust.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-robust/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-robust/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-robust/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-robust/clean/wotsx1.o

# $(PQCLEAN_SPHINCSSHA2192SROBUST_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSSHA2192SROBUST_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSSHA2192SROBUST_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSSHA2192SROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-simple/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-simple/clean/context_sha2.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-simple/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-simple/clean/hash_sha2.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-simple/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-simple/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-simple/clean/thash_sha2_simple.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-simple/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-simple/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-simple/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-simple/clean/wotsx1.o

# $(PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSSHA2256FROBUST_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-robust/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-robust/clean/context_sha2.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-robust/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-robust/clean/hash_sha2.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-robust/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-robust/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-robust/clean/thash_sha2_robust.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-robust/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-robust/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-robust/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-robust/clean/wotsx1.o

# $(PQCLEAN_SPHINCSSHA2256FROBUST_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSSHA2256FROBUST_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSSHA2256FROBUST_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSSHA2256FROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-simple/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-simple/clean/context_sha2.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-simple/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-simple/clean/hash_sha2.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-simple/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-simple/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-simple/clean/thash_sha2_simple.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-simple/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-simple/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-simple/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-simple/clean/wotsx1.o

# $(PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-robust/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-robust/clean/context_sha2.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-robust/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-robust/clean/hash_sha2.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-robust/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-robust/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-robust/clean/thash_sha2_robust.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-robust/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-robust/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-robust/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-robust/clean/wotsx1.o

# $(PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-simple/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-simple/clean/context_sha2.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-simple/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-simple/clean/hash_sha2.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-simple/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-simple/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-simple/clean/thash_sha2_simple.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-simple/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-simple/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-simple/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-simple/clean/wotsx1.o

# $(PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSSHAKE128FROBUST_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-robust/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-robust/clean/context_shake.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-robust/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-robust/clean/hash_shake.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-robust/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-robust/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-robust/clean/thash_shake_robust.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-robust/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-robust/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-robust/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-robust/clean/wotsx1.o

# $(PQCLEAN_SPHINCSSHAKE128FROBUST_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSSHAKE128FROBUST_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSSHAKE128FROBUST_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSSHAKE128FROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-simple/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-simple/clean/context_shake.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-simple/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-simple/clean/hash_shake.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-simple/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-simple/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-simple/clean/thash_shake_simple.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-simple/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-simple/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-simple/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-simple/clean/wotsx1.o

# $(PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSSHAKE128SROBUST_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-robust/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-robust/clean/context_shake.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-robust/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-robust/clean/hash_shake.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-robust/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-robust/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-robust/clean/thash_shake_robust.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-robust/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-robust/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-robust/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-robust/clean/wotsx1.o

# $(PQCLEAN_SPHINCSSHAKE128SROBUST_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSSHAKE128SROBUST_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSSHAKE128SROBUST_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSSHAKE128SROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-simple/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-simple/clean/context_shake.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-simple/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-simple/clean/hash_shake.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-simple/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-simple/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-simple/clean/thash_shake_simple.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-simple/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-simple/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-simple/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-simple/clean/wotsx1.o

# $(PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSSHAKE192FROBUST_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-robust/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-robust/clean/context_shake.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-robust/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-robust/clean/hash_shake.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-robust/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-robust/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-robust/clean/thash_shake_robust.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-robust/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-robust/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-robust/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-robust/clean/wotsx1.o

# $(PQCLEAN_SPHINCSSHAKE192FROBUST_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSSHAKE192FROBUST_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSSHAKE192FROBUST_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSSHAKE192FROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-simple/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-simple/clean/context_shake.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-simple/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-simple/clean/hash_shake.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-simple/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-simple/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-simple/clean/thash_shake_simple.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-simple/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-simple/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-simple/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-simple/clean/wotsx1.o

# $(PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSSHAKE192SROBUST_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-robust/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-robust/clean/context_shake.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-robust/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-robust/clean/hash_shake.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-robust/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-robust/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-robust/clean/thash_shake_robust.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-robust/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-robust/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-robust/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-robust/clean/wotsx1.o

# $(PQCLEAN_SPHINCSSHAKE192SROBUST_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSSHAKE192SROBUST_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSSHAKE192SROBUST_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSSHAKE192SROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-simple/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-simple/clean/context_shake.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-simple/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-simple/clean/hash_shake.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-simple/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-simple/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-simple/clean/thash_shake_simple.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-simple/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-simple/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-simple/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-simple/clean/wotsx1.o

# $(PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSSHAKE256FROBUST_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-robust/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-robust/clean/context_shake.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-robust/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-robust/clean/hash_shake.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-robust/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-robust/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-robust/clean/thash_shake_robust.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-robust/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-robust/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-robust/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-robust/clean/wotsx1.o

# $(PQCLEAN_SPHINCSSHAKE256FROBUST_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSSHAKE256FROBUST_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSSHAKE256FROBUST_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSSHAKE256FROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-simple/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-simple/clean/context_shake.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-simple/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-simple/clean/hash_shake.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-simple/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-simple/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-simple/clean/thash_shake_simple.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-simple/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-simple/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-simple/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-simple/clean/wotsx1.o

# $(PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSSHAKE256SROBUST_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-robust/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-robust/clean/context_shake.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-robust/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-robust/clean/hash_shake.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-robust/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-robust/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-robust/clean/thash_shake_robust.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-robust/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-robust/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-robust/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-robust/clean/wotsx1.o

# $(PQCLEAN_SPHINCSSHAKE256SROBUST_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSSHAKE256SROBUST_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSSHAKE256SROBUST_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSSHAKE256SROBUST_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"

PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_OUTPUT_OBJECTS = \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-simple/clean/address.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-simple/clean/context_shake.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-simple/clean/fors.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-simple/clean/hash_shake.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-simple/clean/merkle.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-simple/clean/sign.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-simple/clean/thash_shake_simple.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-simple/clean/utils.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-simple/clean/utilsx1.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-simple/clean/wots.o \
	$(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-simple/clean/wotsx1.o

# $(PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_OUTPUT_OBJECTS)
# 	$(ar_verbose) $(AR) -r $@ $(PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_OUTPUT_OBJECTS)

# $(PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_OUTPUT): $(PQCLEAN_SRC_DIR)
# 	$(MAKE) -j -C $(dir $@) EXTRAFLAGS="-fPIC"


DEPS_OBJECTS = \
	$(PQCLEAN_COMMON_OBJECTS) \
	$(PQCLEAN_HQCRMRS128_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_HQCRMRS192_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_HQCRMRS256_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_KYBER512_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_KYBER51290S_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_KYBER768_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_KYBER76890S_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_KYBER1024_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_KYBER102490S_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_DILITHIUM2_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_DILITHIUM2AES_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_DILITHIUM3_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_DILITHIUM3AES_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_DILITHIUM5_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_DILITHIUM5AES_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_FALCON512_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_FALCON1024_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSHARAKA128FROBUST_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSHARAKA128FSIMPLE_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSHARAKA128SROBUST_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSHARAKA128SSIMPLE_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSHARAKA192FROBUST_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSHARAKA192FSIMPLE_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSHARAKA192SROBUST_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSHARAKA192SSIMPLE_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSHARAKA256FROBUST_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSHARAKA256FSIMPLE_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSHARAKA256SROBUST_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSSHA2128FROBUST_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSSHA2128SROBUST_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSSHA2192FROBUST_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSSHA2192SROBUST_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSSHA2256FROBUST_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSSHA2256SROBUST_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSSHAKE128FROBUST_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSSHAKE128SROBUST_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSSHAKE192FROBUST_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSSHAKE192SROBUST_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSSHAKE256FROBUST_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSSHAKE256SROBUST_CLEAN_OUTPUT_OBJECTS) \
	$(PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_OUTPUT_OBJECTS)

$(DEPS_OBJECTS): $(PQCLEAN_SRC_DIR)

$(C_SRC_OUTPUT_FILE): $(DEPS_OBJECTS) $(OBJECTS)
	$(verbose) mkdir -p $(dir $@)
	$(link_verbose) $(CC) $(DEPS_OBJECTS) $(OBJECTS) \
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
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-128/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-192/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_kem/hqc-rmrs-256/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_kem/kyber512/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_kem/kyber512-90s/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_kem/kyber768/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_kem/kyber768-90s/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_kem/kyber1024/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_kem/kyber1024-90s/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/dilithium2/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/dilithium2aes/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/dilithium3/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/dilithium3aes/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/dilithium5/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/dilithium5aes/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/falcon-512/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/falcon-1024/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-robust/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128f-simple/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-robust/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-128s-simple/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-robust/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192f-simple/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-robust/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-192s-simple/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-robust/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256f-simple/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-robust/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-haraka-256s-simple/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-robust/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128f-simple/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-robust/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-128s-simple/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-robust/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192f-simple/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-robust/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-192s-simple/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-robust/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256f-simple/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-robust/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-sha2-256s-simple/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-robust/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128f-simple/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-robust/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-128s-simple/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-robust/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192f-simple/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-robust/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-192s-simple/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-robust/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256f-simple/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-robust/clean clean
	$(gen_verbose) $(MAKE) -C $(PQCLEAN_SRC_DIR)/crypto_sign/sphincs-shake-256s-simple/clean clean

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