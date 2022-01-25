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
	.globl longjmp
	.type  longjmp, @function
longjmp:
	movq %rdi, %rax
	movq (%rax), %rbx
	movq 8(%rax), %rsp
	movq 16(%rax), %rbp
	movq 24(%rax), %r12
	movq 32(%rax), %r13
	movq 40(%rax), %r14
	movq 48(%rax), %r15
	movq %rsi, %rax
	jmp *56(%rdi)

	.size longjmp, .-longjmp

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
