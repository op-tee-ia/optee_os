/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Intel Corporation
 */

#include <asm.S>

/* uint32_t atomic_inc32(uint32_t *v); */
FUNC atomic_inc32 , :
    movl $1, %eax
    lock xaddl %eax, (%rdi)
    incl %eax
    ret
END_FUNC atomic_inc32

/* uint32_t atomic_dec32(uint32_t *v); */
FUNC atomic_dec32 , :
    movl $-1, %eax
    lock xaddl %eax, (%rdi)
    decl %eax
    ret
END_FUNC atomic_dec32

