/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2016, Linaro Limited
 */

#include <asm.S>


/* uint32_t atomic_inc32(uint32_t *v); */
//TODO: will consider SMP later
FUNC atomic_inc32 , :
    incl (%rdi)
    movl (%rdi), %eax
    retq
END_FUNC atomic_inc32

/* uint32_t atomic_dec32(uint32_t *v); */
//TODO: will consider SMP later
FUNC atomic_dec32 , :
    decl (%rdi)
    movl (%rdi), %eax
    retq
END_FUNC atomic_dec32

