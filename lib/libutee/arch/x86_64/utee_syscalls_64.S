/* SPDX-License-Identifier: BSD-2-Clause */
/*
 *  Copyright (c) 2021 Intel Corporation
 */

#include <tee_syscall_numbers.h>
#include <asm.S>

.section .text

.macro UTEE_SYSCALL name, scn, num_args
FUNC \name , :

    .if \num_args > TEE_SVC_MAX_ARGS
    .error "Too many arguments for syscall"
    .endif

    pushfq
    pushq %rbp
    pushq %rbx
    pushq %r15
    pushq %r13
    pushq %r12

    movq $(\scn), %rax

    /* Return Addr and stack */
    leaq 1f(%rip), %rbx
    movq %rsp, %rbp
    /* save the 7th arg */
    movq 56(%rsp), %r12
    /* save the 8th arg */
    movq 64(%rsp), %r13

    sysenter

1:  popq %r12
    popq %r13
    popq %r15
    popq %rbx
    popq %rbp
    popfq

    retq
END_FUNC \name
.endm

#include "utee_syscalls_asm.S"
