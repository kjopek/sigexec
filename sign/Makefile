SRCS =	sign.c uECC.c
PROG =	sign
CFLAGS += -DuECC_PLATFORM=uECC_x86_64 -DuECC_CURVE=uECC_secp256k1
LDFLAGS += -lmd

NO_MAN =	yes
.include <bsd.prog.mk>
