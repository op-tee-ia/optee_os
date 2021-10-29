/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 * Copyright (c) 2020, Arm Limited
 * Copyright (c) 2021 Intel Corporation
 */

#include <asm.S>
#include <elf_common.h>

/*
 * _start() - Entry of ldelf
 *
 * See include/ldelf.h for details on TEE Core interaction.
 *
 * void start(struct ldelf_arg *arg);
 */
FUNC _ldelf_start , :
	/*
	 * First ldelf needs to be relocated. The binary is compiled to
	 * contain only a minimal number of R_X86_64_RELATIVE relocations
	 * in read/write memory, leaving read-only and executeble memory
	 * untouched.
	 */
	leaq	reloc_begin_rel(%rip), %r14
	movl	(%r14), %eax
	leaq	reloc_end_rel(%rip), %r15
	movl	(%r15), %ecx
	addq	%r14, %rax
	addq	%r14, %rcx
	cmp	%rax, %rcx
	je	2f

	leaq	_ldelf_start(%rip), %r14
	/* Loop over the relocations (Elf64_Rela) and process all entries */
1:	movq	(%rax), %r11
	movq	8(%rax), %rdx
	movq	16(%rax), %r13
	addq	$24, %rax
	andl	$0xffffffff, %edx
	cmpl	$R_X86_64_RELATIVE, %edx
	jne	3f

	/*
	 * Update the pointer at r_offset + load_offset with r_addend +
	 * load_offset.
	 */
	addq	%r14, %r11
	addq	%r14, %r13
	movq	%r13, (%r11)

	cmp	%rax, %rcx
	jg	1b

2:	call	ldelf
	xorq	%rdi, %rdi
	call	_ldelf_return
3:	xorq	%rdi, %rdi
	call	_ldelf_panic

reloc_begin_rel:
    .long __reloc_begin - reloc_begin_rel
reloc_end_rel:
    .long __reloc_end - reloc_end_rel
END_FUNC _ldelf_start
