global-incdirs-y += include
global-incdirs-y += include/dice/config/mbedtls_ecdsa_p256

cppflags-y += -DMBEDTLS_ALLOW_PRIVATE_ACCESS

srcs-y += dice.c
srcs-y += clear_memory.c
srcs-y += mbedtls_ops.c
srcs-y += cose.c
srcs-y += utils.c
srcs-y += dice_uds.c
