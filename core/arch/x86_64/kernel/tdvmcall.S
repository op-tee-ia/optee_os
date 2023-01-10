// SPDX-License-Identifier: BSD-2-Clause
/*
 *  Copyright (c) 2022 Intel Corporation
 */

 #include <asm.S>
 #include <kernel/tdx.h>

/* Set all GPR bits except rax/rcx/rsp */
#define TDVMCALL_GPR_BITMAP 0x000000000000ffec

.macro tdcall_op
.byte 0x66, 0x0f, 0x01, 0xcc
.endm

.macro tdvmcall_push_regs
    pushq %rbx
    pushq %rbp
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
.endm

.macro tdvmcall_pop_regs
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %rbp
    popq %rbx
.endm

/* uint64_t tdvmcall_io_read(uint64_t port, uint64_t size, uint64_t *val) */
FUNC tdvmcall_io_read , :
    tdvmcall_push_regs
    pushq %rdx

    movq $TDVMCALL, %rax
    movq $TDVMCALL_GPR_BITMAP, %rcx
    xorq %r10, %r10
    movq $REASON_30_IO_INSTR, %r11
    movq %rsi, %r12
    xorq %r13, %r13
    movq %rdi, %r14

    tdcall_op

    popq %rdx
    movq %r10, %rax
    movq %r11, (%rdx)

    tdvmcall_pop_regs
    retq
END_FUNC tdvmcall_io_read

/* uint64_t tdvmcall_io_write(uint64_t port, uint64_t size, uint64_t val) */
FUNC tdvmcall_io_write , :
    tdvmcall_push_regs

    movq $TDVMCALL, %rax
    movq $TDVMCALL_GPR_BITMAP, %rcx
    xorq %r10, %r10
    movq $REASON_30_IO_INSTR, %r11
    movq %rsi, %r12
    movq $1,   %r13
    movq %rdi, %r14
    movq %rdx, %r15

    tdcall_op

    movq %r10, %rax

    tdvmcall_pop_regs
    retq
END_FUNC tdvmcall_io_write

/* uint64_t tdvmcall_readmsr(uint64_t msr_id, uint64_t *val) */
FUNC tdvmcall_readmsr , :
    tdvmcall_push_regs
    pushq %rsi

    movq $TDVMCALL, %rax
    movq $TDVMCALL_GPR_BITMAP, %rcx
    xorq %r10, %r10
    movq $REASON_31_MSR_READ, %r11
    movq %rdi, %r12

    tdcall_op

    popq %rsi
    movq %r10, %rax
    movq %r11, (%rsi)

    tdvmcall_pop_regs
    retq
END_FUNC tdvmcall_readmsr

/* uint64_t tdvmcall_writemsr(uint64_t msr_id, uint64_t val) */
FUNC tdvmcall_writemsr , :
    tdvmcall_push_regs

    movq $TDVMCALL, %rax
    movq $TDVMCALL_GPR_BITMAP, %rcx
    xorq %r10, %r10
    movq $REASON_32_MSR_WRITE, %r11
    movq %rdi,   %r12
    movq %rsi,   %r13

    tdcall_op

    movq %r10, %rax

    tdvmcall_pop_regs
    retq
END_FUNC tdvmcall_writemsr

/* uint64_t tdvmcall_mapgpa(uint64_t paddr, uint64_t size) */
FUNC tdvmcall_mapgpa , :
    tdvmcall_push_regs

    movq $TDVMCALL, %rax
    movq $TDVMCALL_GPR_BITMAP, %rcx
    xorq %r10, %r10
    movq $TDVMCALL_MAPGPA, %r11
    movq %rdi,   %r12
    movq %rsi,   %r13

    tdcall_op

    movq %r10, %rax

    tdvmcall_pop_regs
    retq
END_FUNC tdvmcall_mapgpa

/* uint64_t tdvmcall_mmio_read(uint64_t paddr, uint64_t size, uint64_t *val) */
FUNC tdvmcall_mmio_read , :
    tdvmcall_push_regs
    pushq %rdx

    movq $TDVMCALL, %rax
    movq $TDVMCALL_GPR_BITMAP, %rcx
    xorq %r10, %r10
    movq $REASON_48_EPT_VIOLATION, %r11
    movq %rsi, %r12
    xorq %r13, %r13
    movq %rdi, %r14

    tdcall_op

    popq %rdx
    movq %r10, %rax
    movq %r11, (%rdx)

    tdvmcall_pop_regs
    retq
END_FUNC tdvmcall_mmio_read

/* uint64_t tdvmcall_mmio_write(uint64_t paddr, uint64_t size, uint64_t val) */
FUNC tdvmcall_mmio_write , :
    tdvmcall_push_regs
  
    movq $TDVMCALL, %rax
    movq $TDVMCALL_GPR_BITMAP, %rcx
    xorq %r10, %r10
    movq $REASON_48_EPT_VIOLATION, %r11
    movq %rsi,   %r12
    movq $1,     %r13
    movq %rdi,   %r14
    movq %rdx,   %r15

    tdcall_op

    movq %r10, %rax

    tdvmcall_pop_regs
    retq
END_FUNC tdvmcall_mmio_write

