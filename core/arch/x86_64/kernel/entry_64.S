/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Intel Corporation
 */

#include <platform_config.h>
#include <descriptor.h>
#include <mm/core_mmu.h>

/* The magic number for the Multiboot header. */
#define MULTIBOOT_HEADER_MAGIC 0x1BADB002

/* The flags for the Multiboot header. */
#if defined(__ELF__) && 0
#define MULTIBOOT_HEADER_FLAGS 0x00000002
#else
#define MULTIBOOT_HEADER_FLAGS 0x00010002
#endif

/* The magic number passed by a Multiboot-compliant boot loader. */
#define MULTIBOOT_BOOTLOADER_MAGIC 0x2BADB002

#define MSR_EFER   0xc0000080
#define EFER_LME   0x00000100

.section .text.boot
.code32
.global _start
_start:
    jmp real_start

.align 8

.type multiboot_header,STT_OBJECT
multiboot_header:
    /* magic */
    .int MULTIBOOT_HEADER_MAGIC
    /* flags */
    .int MULTIBOOT_HEADER_FLAGS
    /* checksum */
    .int -(MULTIBOOT_HEADER_MAGIC + MULTIBOOT_HEADER_FLAGS)

#if !defined(__ELF__) || 1
    /* header_addr */
    .int multiboot_header
    /* load_addr */
    .int _start
    /* load_end_addr */
    .int __data_end
    /* bss_end_addr */
    .int __bss_end
    /* entry_addr */
    .int real_start
#endif

real_start:
    /* load our new gdt by physical pointer */
    lgdt _gdtr_phys
    /* load our data selectors */
    movw $DATA_SELECTOR, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %ss
    movw %ax, %gs
    movw %ax, %ss

    /* set the kernel stack */
    lea (_kstack + 4096), %esp

    /* We need to jump to our sane 32 bit CS */
    pushl $CODE_SELECTOR
    pushl $.Lfarjump
    retf

.Lfarjump:
    /* zero the bss section */
bss_setup:
    movl $__bss_start, %eax /* starting address of the bss */
    movl $__bss_end, %ecx   /* find the length of the bss in bytes */
    subl %eax, %ecx
    /* convert to 32 bit words, since the bss is aligned anyway */
    shrl $2, %ecx
.Lzero_bss_sec:
    movl $0, (%eax)
    addl $4, %eax
    loop .Lzero_bss_sec

#ifdef CFG_VIRTUALIZATION
clear_nex_bss:
    movl $__nex_bss_start, %eax
    movl $__nex_bss_end, %ecx
    subl %eax, %ecx
    /* convert to 32 bit words, since the nex_bss is aligned anyway */
    shrl $2, %ecx
.Lzero_nex_bss_sec:
    movl $0, (%eax)
    addl $4, %eax
    loop .Lzero_nex_bss_sec
#endif

paging_setup:
    /* Preparing 64 bit paging, we will use 2MB pages covering 4GB
    for initial bootstrap, this page table will be 1 to 1  */

    /* PAE bit must be enabled for 64 bit paging */
    mov  %cr4, %eax
    btsl $(5), %eax
    mov  %eax, %cr4

    /* load the physical pointer to the top level page table */
    lea  g_pml4_init, %eax
    mov  %eax, %cr3

    /* Long Mode Enabled at this point */
    movl $MSR_EFER ,%ecx
    rdmsr
    orl  $EFER_LME,%eax
    wrmsr

    /* Setting the First PML4E with a PDP table reference */
    movl $g_pdp_init, %eax
    orl  $X86_KERNEL_PD_FLAGS, %eax
    movl %eax, g_pml4_init

    /* map the first 4GB in this table */
    movl $g_pdp_init, %edi
    movl $g_pte_init, %esi
    orl  $X86_KERNEL_PD_FLAGS, %esi
    movl $4, %ecx
.Lfill_pdpte_entry:
    movl %esi, (%edi)
    add  $8, %edi
    addl $4096, %esi
    loop .Lfill_pdpte_entry

    /* loop across these page tables, incrementing the address by 2MB */
    movl $g_pte_init, %esi
    movl $2048, %ecx
    xor  %eax, %eax

.Lfill_pte_entry:
    mov  %eax, %ebx
    shll $21, %ebx
    orl  $X86_KERNEL_PD_LP_FLAGS, %ebx
    movl %ebx, (%esi)
    mov  %eax, %ebx
    shrl $11, %ebx
    movl %ebx, 4(%esi)
    addl $8, %esi
    inc  %eax
    loop .Lfill_pte_entry

    /* Enabling Paging and from this point we are in
    32 bit compatibility mode */
    mov  %cr0,  %eax
    btsl $(31), %eax
    mov  %eax,  %cr0

    /* Using another long jump to be on 64 bit mode
    after this we will be on real 64 bit mode */
    pushl $CODE_64_SELECTOR  /* Need to put it in the right CS */
    pushl $farjump64
    retf

.align 8
.code64

farjump64:
    /* set up the idt */
    call setup_idt

    /* Enable Console */
    call console_init

    /* Create MMU tables from OP-TEE memory structures */
    call core_mmu_init

    /* Init memory map structures related to OP-TEE operations */
    call core_init_mmu_map

    /* call the init module */
    call boot_init_primary

    /*
    * Clear current thread id now to allow the thread to be reused on
    * next entry. Matches the thread_init_boot_thread() in boot.c.
    */
    call thread_clr_boot_thread

    call sm_sched_nonsecure

.Lhalt:               /* just sit around waiting for interrupts */
    hlt               /* interrupts will unhalt the processor */
    pause
    jmp .Lhalt        /* so jump back to halt to conserve power */
