/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2009 Corey Tabaka
 * Copyright (c) 2016 Travis Geiselbrecht
 * Copyright (c) 2018 Intel Corporation
 */

#include <asm.h>
#include <descriptor.h>

#define NUM_INT 0x100
#define NUM_EXC 0x14

.text

/* interrupt service routine stubs */
_isr:
.set i, 0
.rept NUM_INT

.align 16

.if i == 8 || (i >= 10 && i <= 14) || i == 17
    pushq $i    /* interrupt number */
    jmp interrupt_common
.else
    pushq $0    /* fill in error code in iframe */
    pushq $i    /* interrupt number */
    jmp interrupt_common
.endif

.set i, i + 1
.endr

/*  annoying, but force AS to use the same (longer)
 *  encoding of jmp for all of the stubs
 */
.fill 256

interrupt_common:
    /* Check if from user sapce */
    testb $3, 0x18(%rsp)
    jz 1f

    /* swap gs to kernel space */
    swapgs

1:
    /* save general purpose registers */
    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %r11
    pushq %r10
    pushq %r9
    pushq %r8
    pushq %rax
    pushq %rcx
    pushq %rdx
    pushq %rbx
    pushq %rbp
    pushq %rsi
    pushq %rdi

    movq %rsp, %rdi     /* pass the  iframe using rdi */

    call x86_exception_handler

    /* restore general purpose registers */
    popq %rdi
    popq %rsi
    popq %rbp
    popq %rbx
    popq %rdx
    popq %rcx
    popq %rax
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
    popq %r14
    popq %r15

    /* Check to if back to user space */
    testb $3, 0x18(%rsp)
    jz 1f

    /* swap gs to user space */
    swapgs

1:
    /* drop vector number and error code*/
    addq $16, %rsp
    iretq

FUNCTION(setup_idt)
    /* setup isr stub descriptors in the idt */
    mov  $_isr, %rsi
    mov  $_idt, %rdi
    movl $NUM_INT, %ecx

.Lloop:
    mov  %rsi, %rbx
    movw %bx, (%rdi)        /* offset [0:15] in IDT(n).low */
    shr  $16, %rbx
    movw %bx, 6(%rdi)       /* offset [16:31] in IDT(n).high */
    shr  $16, %rbx
    movl %ebx, 8(%rdi)      /* offset [32:63] */

    add  $16, %rsi          /* index the next ISR stub */
    add  $16, %rdi          /* index the next IDT entry */

    loop .Lloop

    lidt _idtr

    ret

.data

.align 8
DATA(_idtr)
    .short _idt_end - _idt - 1  /* IDT limit */
    .quad _idt
.fill 8

.align 8
/* interrupt descriptor table (IDT) */
DATA(_idt)

.set i, 0
.rept NUM_INT
    .short 0        /* low 16 bits of ISR offset (_isr#i & 0FFFFh) */
    .short CODE_64_SELECTOR   /* selector */
    .byte  0x1      /* use IST1 */
    .byte  0x8e     /* present, ring 0, 64-bit interrupt gate */
    .short  0       /* high 16 bits of ISR offset (_isr#i / 65536) */
    .short  0       /* ISR offset */
    .short  0       /* ISR offset */
    .short  0       /* 32bits Reserved */
    .short  0       /* 32bits Reserved */


.set i, i + 1
.endr

.global _idt_end
_idt_end:
