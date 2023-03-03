/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Intel Corporation
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

#define KERNEL_BASE 0x12f52000
#define MSR_EFER    0xc0000080
#define EFER_LME    0x00000100
#define EFER_NXE    0x00000800
#define MSR_GS_BASE 0xc0000101

/* Manually change the number to align with file size */
#ifdef CFG_TEE_CORE_DEBUG
#define ELF_FILE_SIZE 663576
#else
#define ELF_FILE_SIZE 335896
#endif

.section ".text.header"
/*
 * EFI header is used to launch OP-TEE binary by TDVF, for most fields
 * of this header are set as zero since either they are useless or will
 * not be checked by TDVF.
 * This is a just POC work, some fileds are filled mananually, if you
 * want to fill these fields automatically, please write an application
 * to parse OP-TEE image and then fill in these fields.
 */
efi_header:
    .ascii "MZ"    // Magic number
    .word 0x0      // Bytes on last page of file
    .word 0x0      // Pages in file
    .word 0x0      // Relocations
    .word 0x0      // Size of header in paragraphs
    .word 0x0      // Minimum extra paragraphs needed
    .word 0x0      // Maximum extra paragraphs needed
    .word 0x0      // Initial (relative) SS value
    .word 0x0      // Initial SP value
    .word 0x0      // Checksum
    .word 0x0      // Initial IP value
    .word 0x0      // Initial (relative) CS value
    .word 0x0      // File address of relocation table
    .word 0x0      // Overlay number
    .word 0x0      // Reserved word 0
    .word 0x0      // Reserved word 1
    .word 0x0      // Reserved word 2
    .word 0x0      // Reserved word 3
    .word 0x0      // OEM identifier (for e_oeminfo)
    .word 0x0      // OEM information; e_oemid specific
    .word 0x0      // Reserved word 0
    .word 0x0      // Reserved word 1
    .word 0x0      // Reserved word 2
    .word 0x0      // Reserved word 3
    .word 0x0      // Reserved word 4
    .word 0x0      // Reserved word 5
    .word 0x0      // Reserved word 6
    .word 0x0      // Reserved word 7
    .word 0x0      // Reserved word 8
    .word 0x0      // Reserved word 9
    .long 0x100    // File address of new exe header

.org efi_header + 0x100
pe_header:
    .long 0x00004550    // PE_MAGIC
    .word 0x8664        // IMAGE_FILE_MACHINE_AMD64
    .word 0x1           // number of sections, we just have "text" section
    .long 0             // TimeDataStmap
    .long 0             // PointerToSymbolTable
    .long 0             // NumberOfSymbols
    .word section_table - optional_header // SizeOfOptionalHeader
    .word 0x0206        // Flags

optional_header:
    .word 0x020b        // PeOptMagic: PE_OPT_MAGIC_PE32PLUS
    .byte 0x02          // MajorLinkerVersion
    .byte 0x14          // MinorLinkerVersion
    .long 0             // SizeOfCode
    .long 0             // SizeOfInitializedData
    .long 0             // SizeOfUninitializedData
    .long 0x2000        // AddressOfEntryPoint :TODO: this is filled manaually.
    .long real_start-efi_header // BaseOfCode :TODO: seems useless

extra_header_fields:
    .quad 0x1000000     // ImageBase :TODO: this is filled manaually.
    .long 0x20          // SectionAlingment
    .long 0x20          // FileAlignment
    .word 0             // MajorOperatingSystemVersion
    .word 0             // MinorOperatingSystemVersion
    .word 0x1           // MajorImageVersion
    .word 0             // MinorImageVersion
    .word 0             // MajorSubsystemVersion
    .word 0             // MinorSubsystemVersion
    .long 0             // Win32VersionValue
    .long ELF_FILE_SIZE // SizeOfImage :TODO: this is filled manaually.
    .long 0x200         // SizeofHeader
    .long 0             // Cheksum
    .word 0x0a          // Subsystem (EFI application)
    .word 0             // DllCharacteristics
    .quad 0             // SizeOfStackReserve
    .quad 0             // SizeOfStackCommit
    .quad 0             // SiZeofHeapReserve
    .quad 0             // SizeofHeapCommit
    .long 0             // LoaderFlags
    .long (section_table - .)/8 // NumbefOfRvaAndSizes
    .quad 0             // ExportTable
    .quad 0             // ImportTable
    .quad 0             // ResourceTable
    .quad 0             // ExceptionTable
    .quad 0             // CertificationTable
    .quad 0             // BaseRelocationTable

section_table:
    .ascii  ".text"
    .byte 0
    .byte 0
    .byte 0
    .long ELF_FILE_SIZE - 0x2000
		                // size to be copied
                        // :TODO: formula(size = filesize - efi_header_sie)
    .long 0x2000        // startup_{32,64}   :TODO: this is filled manaually.
    .long ELF_FILE_SIZE - 0x2000 
			            // Size of initialized data # on disk
                        //:TODO: formula(size = filesize - efi_header_sie)
    .long 0x2000        // startup_{32,64}   :TODO: this is filled manaually.
    .long 0             // PointerToRelocations
    .long 0             // PointerToLineNumbers
    .word 0             // NumberOfRelocations
    .word 0             // NumberOfLineNumbers
    .long 0x60500020    // IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ |
                        //IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_ALIGN_16BYTES

.org efi_header + 0x200
linux_format_header:
    jmp .               // deadloop here for easy debugging
    .word 0
    .long 0
    .quad 0
    .fill 0x1D0, 1, 0
    .quad 0
    .long 0
    .long 0xFF000000    // 0x1de-0x1f1:0xFF used to detect broken loaders
    .byte 0xFF

header_start:
setup_secs:     .byte 7         //UINT8 parsed by QEMU x86_load_linux
root_flags:     .word 1         //UINT16
sys_size:       .long 0         //UINT32
ram_size:       .word 0         //UINT16
video_mode:     .word 0xffff    //UINT16
root_dev:       .word 0         //UINT16
signature:      .word 0xAA55    //UINT16
jump:           .byte 0xEB      //UINT16
                .byte 0xFE      //0xeb 0xfe: "jmp .", for debug usage
header:         .ascii "HdrS"   //UINT32
version:        .word 0x020d    //UINT16
su_switch:      .word 0         //UINT16
setup_seg:      .word 0         //UINT16
start_sys:      .word 0         //UINT16
kernel_ver:     .word 0         //UINT16
loader_id:      .byte 0         //UINT8
load_flags:     .byte 1         //UINT8
movesize:       .word 0x8000    //UINT16
code32_start:   .long 0x100000  //UINT32 default start address of QEMU
ramdisk_start:  .long 0         //UINT32
ramdisk_len:    .long 0         //UINT32
bootsec_kludge: .long 0         //UINT32
heap_end:       .word 0         //UINT16
ext_ldr_ver:    .byte 0         //UINT8
ext_ldr_type:   .byte 0         //UINT8
cmd_line_ptr:   .long 0         //UINT32
ramdisk_max:    .long 0x7FFFFFFF	//UINT32
krnl_align:     .long 0x200000  //UINT32
relo_krnl:      .byte 1         //UINT8
min_alignment:  .byte 0x15      //UINT8
xloadflags:     .word 0x1D      //UINT16 EFI load type
                                //bit(0):64bit,bit(2):HANDOVER32
                                //bit(3):HANDOVER64, bit(4):EFI_KEXEC
cmdline_size:   .long 0         //UINT32
hw_subarch:     .long 0         //UINT32
hw_subarch_d:   .quad 0         //UINT64
payload_off:    .long 0         //UINT32
payload_len:    .long 0         //UINT32
setup_data:     .quad 0         //UINT64
pref_addr:      .quad 0x200000  //UINT64
init_size:      .long 0x1E0000  //UINT32
handover_size:  .long 0x200     //UINT32


/*
 * This is the start of kernel data, QEMU copies kernel data from
 * here to QEMU fw_cfg. Formula of start address of kernel data in
 * QEMU: linux_format_header + (setup_secs + 1) * 512
 */
.org linux_format_header + 0x1000

.org 0x2000
.section .text.boot
.code64
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
    jmp bss_setup

bss_setup:
    movq $__bss_start, %rax /* starting address of the bss */
    movq $__bss_end, %rcx   /* find the length of the bss in bytes */
    subq %rax, %rcx
    /* convert to 32 bit words, since the bss is aligned anyway */
    shrq $2, %rcx
.Lzero_bss_sec:
    movq $0, (%rax)
    addq $4, %rax
    loop .Lzero_bss_sec

#ifdef CFG_VIRTUALIZATION
clear_nex_bss:
    movq $__nex_bss_start, %rax
    movq $__nex_bss_end, %rcx
    subq %rax, %rcx
    /* convert to 32 bit words, since the nex_bss is aligned anyway */
    shrq $2, %rcx
.Lzero_nex_bss_sec:
    movq $0, (%rax)
    addq $4, %rax
    loop .Lzero_nex_bss_sec
#endif

paging_setup:
    /* Preparing 64 bit paging, we will use 2MB pages covering 4GB */
    /*for initial bootstrap, this page table will be 1 to 1  */

    /* Setting the First PML4E with a PDP table reference */
    movq $g_pdpt_init, %rax
    orq  $X86_KERNEL_PD_FLAGS, %rax
    movq %rax, g_pml4_init

    /* map the first 4GB in this table */
    movq $g_pdpt_init, %rdi
    movq $g_pd_init, %rsi
    movq $4, %rcx
.Lfill_pdpt_entry:
    orq  $X86_KERNEL_PD_FLAGS, %rsi
    movq %rsi, (%rdi)
    addq $8, %rdi
    addq $4096, %rsi
    loop .Lfill_pdpt_entry
   
    /* rdx is every physical page size 2^21 = 2M */
    movq $1, %rdx
    shlq $21, %rdx
    movq $g_pd_init, %rdi
    movq $X86_KERNEL_PD_LP_FLAGS, %rsi
    movq $2048, %rcx
.Lfill_pd_entry:
    movq %rsi, (%rdi)
    addq $8, %rdi
    addq %rdx, %rsi
    loop .Lfill_pd_entry

    lgdt _gdtr_phys
    pushq $CODE_SELECTOR
    pushq $.Lfarjump
    lretq

.Lfarjump:
    /* Disabling Paging */
    mov  %cr0,  %eax
    btrl $(31), %eax
    mov  %eax,  %cr0

    /* load our data selectors */
    movw $DATA_SELECTOR, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %ss
    movw %ax, %gs
    movw %ax, %ss

    /* Make sure four level paging will be used */
    mov %cr4,  %eax
    btrl $(12), %eax
    mov %eax,  %cr4
    
    leaq  g_pml4_init, %rax
    movq %rax, %cr3

    /* Enabling Paging and from this point we are in
    32 bit compatibility mode */
    mov  %cr0,  %eax
    btsl $(31), %eax
    mov  %eax,  %cr0

    push $CODE_64_SELECTOR
    push $.Lfarjump64
    retf

.align 8
.code64

.Lfarjump64:
    leaq (_kstack + 4096), %rsp

    /* set up the idt */
    call setup_idt
    cli

    /* Enable Console */
    call console_init

    /* Init thread_core_local */
    call thread_init_thread_core_local

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

