global-incdirs-y += cbor

srcs-y += cbor.c
srcs-y += allocators.c 
srcs-y += cbor/streaming.c
srcs-y += cbor/internal/encoders.c
srcs-y += cbor/internal/builder_callbacks.c
srcs-y += cbor/internal/loaders.c
srcs-y += cbor/internal/memory_utils.c
srcs-y += cbor/internal/stack.c
srcs-y += cbor/internal/unicode.c
srcs-y += cbor/encoding.c
srcs-y += cbor/serialization.c
srcs-y += cbor/arrays.c
srcs-y += cbor/common.c
srcs-y += cbor/floats_ctrls.c
srcs-y += cbor/bytestrings.c
srcs-y += cbor/callbacks.c
srcs-y += cbor/strings.c
srcs-y += cbor/maps.c
srcs-y += cbor/tags.c
srcs-y += cbor/ints.c

cflags-lib-y += -Wno-redundant-decls
cflags-lib-y += -Wno-switch-default
cflags-lib-y += -Wno-declaration-after-statement
cflags-lib-y += -Wno-unused-function

