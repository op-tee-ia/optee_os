/* SPDX-License-Identifier: BSD-2-Clause */
/*
 *  Copyright (c) 2021 Intel Corporation
 */

#include <asm.S>

.section .text

.macro LDELF_SYSCALL name, scn, num_args
FUNC \name , :

    .if \num_args > 8
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

FUNC _ldelf_panic, :
    call __ldelf_panic
    /* Not reached */
END_FUNC _ldelf_panic

#include "syscalls_asm.S"
