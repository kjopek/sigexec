SRCS = vnode_if.h sigexec.c uECC.c
KMOD = sigexec
CFLAGS += -DuECC_PLATFORM=uECC_x86_64 -DuECC_CURVE=uECC_secp256k1
.include <bsd.kmod.mk>
