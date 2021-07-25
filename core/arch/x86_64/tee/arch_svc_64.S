/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, intel Corporation
 */

#include <asm.S>
#include <tee_api_defines.h>
#include <generated/asm-defines.h>

.section .text.arch_svc_asm

FUNC __syscall_sys_return , :
    movq %rdi, %rax
    movq %rsi, %rsp
    popq %r8
    movl $0, (%r8)  /* panic_code = 0 */
    popq %rcx
    movl $0, (%rcx) /* panic = false */
    popq %rbp
    popfq
    retq
END_FUNC __syscall_sys_return

FUNC __syscall_panic , :
    movq %rdi, %rax
    movq %rsi, %rsp
    popq %r8
    movl %eax, (%r8)  /* panic_code */
    popq %rcx
    movl $1, (%rcx) /* panic = true */
    movq $TEE_ERROR_TARGET_DEAD, %rax /* return value */
    popq %rbp
    popfq
    retq
END_FUNC __syscall_panic

#define SYSCALL_ENTRY_SIZE    0x08

FUNC tee_syscall , :
    sti
    pushq %rbx /* Ring 3 return address */
    pushq %rbp /* Ring 3 rsp */

    pushq %r15
    pushq %r14
    pushq %r11
    pushq %r10
    pushq %r9
    pushq %r8
    pushq %rcx
    pushq %rdx
    pushq %rbx
    pushq %rbp
    pushq %rsi
    pushq %rdi
    pushq %r13
    pushq %r12

    movq %rdx,%r13
    /*
     * Arranging params to pass to sysenter handling
     * syscall table is long. Multiplication to find offset.
     */
    movq $SYSCALL_ENTRY_SIZE, %r15
    /* Result is stored in rax. Before multiplication rax contains syscall No */

    mul %r15
    movq $tee_syscall_table, %r14
    add %r14, %rax
    movq %r13,%rdx
    call *(%rax)

    popq %r12
    popq %r13
    popq %rdi
    popq %rsi
    popq %rbp
    popq %rbx
    popq %rdx
    popq %rcx
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r14
    popq %r15

    popq %rcx /* pop rsp */
    popq %rdx /* pop rip */
    rex.W sysexit

END_FUNC tee_syscall

FUNC ldelf_syscall , :
    sti
    pushq %rbx /* Ring 3 return address */
    pushq %rbp /* Ring 3 rsp */

    pushq %r15
    pushq %r14
    pushq %r11
    pushq %r10
    pushq %r9
    pushq %r8
    pushq %rcx
    pushq %rdx
    pushq %rbx
    pushq %rbp
    pushq %rsi
    pushq %rdi
    pushq %r13
    pushq %r12

    movq %rdx,%r13
    /*
     * Arranging params to pass to sysenter handling
     * syscall table is long. Multiplication to find offset.
     */
    movq $SYSCALL_ENTRY_SIZE, %r15
    /* Result is stored in rax. Before multiplication rax contains syscall No */

    mul %r15
    movq $ldelf_syscall_table, %r14
    add %r14, %rax
    movq %r13,%rdx
    call *(%rax)

    popq %r12
    popq %r13
    popq %rdi
    popq %rsi
    popq %rbp
    popq %rbx
    popq %rdx
    popq %rcx
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r14
    popq %r15

    popq %rcx /* pop rsp */
    popq %rdx /* pop rip */
    rex.W sysexit

END_FUNC ldelf_syscall
