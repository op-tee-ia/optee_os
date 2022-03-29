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

/* void thread_resume(struct thread_ctx_regs *regs) */

FUNC thread_resume , :
    pushfq
    pushq %rax
    pushq %rbx
    pushq %rbp
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    movq %rdi, %r15  //save struct thread_ctx_regs *regs

    movq %rsp, %rdi

    call thread_set_tmp_sp

    movq 8(%r15), %rsp  //switch to thread stack

    pushq (%r15)         //set rip
    
    movq 24(%r15), %rdi  //pass parameters for next function call
    movq 32(%r15), %rsi
    movq 40(%r15), %rdx
    movq 48(%r15), %rcx

    retq
END_FUNC thread_resume

/* void thread_smc_args_retrieve(struct thread_smc_args *args) */
FUNC thread_smc_args_retrieve , :
    movq %rsi, (%rdi)
    movq %rdx, 8(%rdi)
    movq %rcx, 16(%rdi)
    movq %r8,  24(%rdi)

    retq
END_FUNC thread_smc_args_retrieve

FUNC thread_std_smc_entry , :
    call __thread_std_smc_entry
    pushq %rax //push return value

    cli
    call thread_state_free

    call thread_get_tmp_sp

    popq %r15 //pop return value

    movq %rax, %rsp

    movq %r15, %rsi   //prepare parameters for thread_smc_args_retrieve 
    xorq %rdx, %rdx
    xorq %rcx, %rcx
    xorq %r8,  %r8

    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %rbp
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
    movq %rax, %r12

    movl 4(%rdi), %eax
    movq %rax, %r13

    movl 8(%rdi), %eax
    movq %rax, %r14

    movq $THREAD_FLAGS_COPY_ARGS_ON_RETURN, %rdi
    movq %rsp, %rsi
    movq $.thread_rpc_return, %rdx

    cli
    call thread_state_suspend

    movq %rax, %r15

    call thread_get_tmp_sp

    movq %rax, %rsp

    movq %r12, %rsi   //prepare parameters for thread_smc_args_retrieve 
    movq %r13, %rdx
    movq %r14, %rcx
    movq %r15, %r8

    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %rbp
    popq %rbx
    popq %rax
    popfq

    retq
.thread_rpc_return:
    popq %r15  //get uint32_t rv[THREAD_RPC_NUM_ARGS]

    movl %edi, 4(%r15)
    movl %esi, 8(%r15)
    movl %edx, 16(%r15)
    movl %ecx, 20(%r15)

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

    movq $OPTEE_SMC_RETURN_RPC_FOREIGN_INTR, %r12

    movq %rdi, %r13

    movq $0x0, %r14

    movq $THREAD_FLAGS_EXIT_ON_FOREIGN_INTR, %rdi
    movq %rsp, %rsi
    movq $.foreign_intr_return, %rdx

    cli
    call thread_state_suspend

    movq %rax, %r15

    call thread_get_tmp_sp

    movq %rax, %rsp

    movq %r12, %rsi   //prepare parameters for thread_smc_args_retrieve 
    movq %r13, %rdx
    movq %r14, %rcx
    movq %r15, %r8

    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %rbp
    popq %rbx
    popq %rax
    popfq

    retq
.foreign_intr_return:
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

    movq  8(%rdi), %r15   //kern_sp
    pushq %r15

    pushq %rsi

    pushq %rdx

    movq %rdi, %r13

    movq %rsp, %rdi

    cli
    call thread_state_save

    pushq $0x5b           //USER_DATA_64_SELECTOR | USER_RPL
    pushq 16(%r13)        //user_sp
    pushq $0x3202         //IOPL_MASK | IF_MASK | EFLAGS_RESERVED
    pushq $0x53           //USER_CODE_64_SELECTOR | USER_RPL
    pushq (%r13)          //entry_func
    pushq $0x5b           //USER_DATA_64_SELECTOR | USER_RPL
    popq %rax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs

    movq 24(%r13), %rdi
    movq 32(%r13), %rsi
    movq 40(%r13), %rdx
    movq 48(%r13), %rcx

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
