// SPDX-License-Identifier: BSD-2-Clause
/*
 *  Copyright (c) 2022 Intel Corporation
 */

#include <asm.S>

.macro tdcall_op
.byte 0x66, 0x0f, 0x01, 0xcc
.endm

.macro tdcall_push_regs
    pushq %rbx
    pushq %rbp
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
.endm

.macro tdcall_pop_regs
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %rbp
    popq %rbx
.endm

/* uint64_t tdcall(uint64_t leaf, uint64_t *out, uint64_t para0, uint64_t para1,
        uint64_t para2) */
FUNC tdcall , :
    tdcall_push_regs

    movq %rdi, %rax

    tdcall_op

    test %rax, %rax
    jnz  .Lexit

    movq %rcx, 0x00(%rsi)
    movq %rdx, 0x08(%rsi)
    movq %r8,  0x10(%rsi)
    movq %r9,  0x18(%rsi)
    movq %r10, 0x20(%rsi)
    movq %r11, 0x28(%rsi)

.Lexit:
    tdcall_pop_regs
    retq
END_FUNC tdcall