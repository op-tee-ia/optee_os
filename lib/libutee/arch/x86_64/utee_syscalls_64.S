/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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

    /* Return Addr and stack*/
    leaq 1f(%rip), %rbx
    movq %rsp, %rbp
    /* save the 7th arg*/
    movq 56(%rsp), %r12
    /* save the 8th arg*/
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

