/*
   Copyright (c) 2019 Intel Corporation
 */

#
# The jmp_buf is assumed to contain the following, in order:
#	%rbx
#	%rsp (post-return)
#	%rbp
#	%r12
#	%r13
#	%r14
#	%r15
#	<return address>
#

	.text
	.align 4
	.globl setjmp
	.type  setjmp, @function
setjmp:
	popq %rsi			# Return address, and adjust the stack
	xorq %rax, %rax			# Return value
	movq %rbx, (%rdi)
	movq %rsp, 8(%rdi)		# Post-return %rsp!
	pushq %rsi			# Make the call/return stack happy
	movq %rbp, 16(%rdi)
	movq %r12, 24(%rdi)
	movq %r13, 32(%rdi)
	movq %r14, 40(%rdi)
	movq %r15, 48(%rdi)
	movq %rsi, 56(%rdi)		# Return address
	retq

	.size setjmp, .-setjmp

	.text
	.align 4
	.globl longjmp
	.type  longjmp, @function
longjmp:
	movq %rsi, %rax			# Return value (int)
	movq (%rdi), %rbx
	movq 8(%rdi), %rsp
	movq 16(%rdi), %rbp
	movq 24(%rdi), %r12
	movq 32(%rdi), %r13
	movq 40(%rdi), %r14
	movq 48(%rdi), %r15
	jmp *56(%rdi)

	.size longjmp, .-longjmp
