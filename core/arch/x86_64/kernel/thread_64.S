/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Intel Corporation
 */

#include <generated/asm-defines.h>
#include <asm.S>
#include <keep.h>
#include <kernel/thread_defs.h>
#include <sm/optee_smc.h>
#include <sm/teesmc_opteed.h>
#include <sm/teesmc_opteed_macros.h>

#include "thread_private.h"

.section .text.thread_asm

/* void thread_resume(struct thread_ctx_regs *regs, struct thread_smc_args *args,
 *                      vaddr_t tmp_stack)
 */

FUNC thread_resume , :
    pushfq
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rbp
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    pushq %rdi
    pushq %rsi

    movq %rsp, (%rdx)

    movq %rdi, %rsp

    popfq

    retq
END_FUNC thread_resume

/* void thread_rpc_resume(vaddr_t sp, struct thread_smc_args *args,
 *						vaddr_t tmp_stack)
 */
FUNC thread_rpc_resume , :
    pushfq
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rbp
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    pushq %rdi
    pushq %rsi

    movq %rsp, (%rdx)

    movq %rdi, %rsp

    popq %rdi

    movq (%rsi), %rbx
    movl %ebx, (%rdi)

    movq 8(%rsi), %rbx
    movl %ebx, 4(%rdi)

    movq 16(%rsi), %rbx
    movl %ebx, 8(%rdi)

    movq 24(%rsi), %rbx
    movl %ebx, 12(%rdi)

    movq 32(%rsi), %rbx
    movl %ebx, 16(%rdi)

    movq 40(%rsi), %rbx
    movl %ebx, 20(%rdi)

    popq %rax
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %rbp
    popq %rbx
    popq %r9
    popq %r8
    popq %rcx
    popq %rdx
    popq %rsi
    popfq

    retq
END_FUNC thread_rpc_resume

/*void foreign_intr_resume(vaddr_t sp, struct thread_smc_args *args, vaddr_t abt_stack);*/
FUNC foreign_intr_resume , :
    pushfq
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rbp
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    pushq %rdi
    pushq %rsi

    movq %rsp, (%rdx)

    movq %rdi, %rsp

    popq %rdi
    popq %rax
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %rbp
    popq %rbx
    popq %r9
    popq %r8
    popq %rcx
    popq %rdx
    popq %rsi
    popfq

    retq
END_FUNC foreign_intr_resume

FUNC thread_std_smc_entry , :
    movq %rsp, %rdi

    call __thread_std_smc_entry

    popq %r10
    popq %r11
    popq %r12
    popq %r13
    popq %r14
    popq %r15

    cli
    call thread_state_free

    call thread_get_tmp_sp

    movq (%rax), %rsp

    popq %rsi

    movq %r10, (%rsi)
    movq %r11, 8(%rsi)
    movq %r12, 16(%rsi)
    movq %r13, 24(%rsi)
    movq %r14, 32(%rsi)
    movq %r15, 40(%rsi)

    popq %rdi
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbp
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    popfq

    retq
END_FUNC thread_std_smc_entry

/* void thread_rpc(uint32_t rv[THREAD_RPC_NUM_ARGS]) */
FUNC thread_rpc , :
    pushfq
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %r8
    pushq %r9
    pushq %rbx
    pushq %rbp
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    pushq %rax
    pushq %rdi

    xorq %rax, %rax

    movl (%rdi), %eax
    movq %rax, %r10

    movl 4(%rdi), %eax
    movq %rax, %r11

    movl 8(%rdi), %eax
    movq %rax, %r12

    movq $THREAD_FLAGS_COPY_ARGS_ON_RETURN, %rdi

    movq %rsp, %rsi

    cli
    call thread_state_suspend

    movq %rax, %r13

    call thread_get_tmp_sp

    movq (%rax), %rsp

    popq %rsi

    movq %r10, (%rsi)
    movq %r11, 8(%rsi)
    movq %r12, 16(%rsi)
    movq %r13, 24(%rsi)
    movq %r14, 32(%rsi)
    movq %r15, 40(%rsi)

    popq %rdi
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbp
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    popfq

    retq
END_FUNC thread_rpc

FUNC foreign_intr_handle , :
    pushfq
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %r8
    pushq %r9
    pushq %rbx
    pushq %rbp
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    pushq %rax
    pushq %rdi

    movq $OPTEE_SMC_RETURN_RPC_FOREIGN_INTR, %r10

    movq %rdi, %r11

    movq $0x0, %r12

    movq $THREAD_FLAGS_EXIT_ON_FOREIGN_INTR, %rdi

    movq %rsp, %rsi

    cli
    call thread_state_suspend

    movq %rax, %r13

    call thread_get_tmp_sp

    movq (%rax), %rsp

    popq %rsi

    movq %r10, (%rsi)
    movq %r11, 8(%rsi)
    movq %r12, 16(%rsi)
    movq %r13, 24(%rsi)
    movq %r14, 32(%rsi)
    movq %r15, 40(%rsi)

    popq %rdi
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbp
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    popfq

    retq
END_FUNC foreign_intr_handle

/*
 * uint32_t __thread_enter_user_mode(struct thread_ctx_regs *regs,
 *				  uint32_t *exit_status0,
 *				  uint32_t *exit_status1);
 */
FUNC __thread_enter_user_mode , :
    pushfq

    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    pushq %rdi

    movq  56(%rdi), %r15  //kern_sp
    pushq %r15

    pushq %rsi

    pushq %rdx

    movq %rdi, %r13

    movq %rsp, %rdi

    cli
    call thread_state_save

    pushq $0x5b           //USER_DATA_64_SELECTOR | USER_RPL
    movq  48(%r13), %r14  //user_sp
    pushq %r14
    pushq $0x3202         //IOPL_MASK | IF_MASK | EFLAGS_RESERVED
    pushq $0x53           //USER_CODE_64_SELECTOR | USER_RPL
    movq  8(%r13), %r15   //entry_func
    pushq %r15
    pushq $0x5b           //USER_DATA_64_SELECTOR | USER_RPL
    popq %rax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs

    movq 16(%r13), %rdi
    movq 24(%r13), %rsi
    movq 32(%r13), %rdx
    movq 40(%r13), %rcx

    xorq %rax, %rax
    xorq %rbx, %rbx
    xorq %rbp, %rbp
    xorq %r8, %r8
    xorq %r9, %r9
    xorq %r10, %r10
    xorq %r11, %r11
    xorq %r12, %r12
    xorq %r13, %r13
    xorq %r14, %r14
    xorq %r15, %r15

    iretq
END_FUNC __thread_enter_user_mode
