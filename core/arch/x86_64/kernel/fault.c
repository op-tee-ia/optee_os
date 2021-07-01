// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2009 Corey Tabaka
 * Copyright (c) 2018 Intel Corporation
 */
#include <stdio.h>
#include <trace.h>
#include <kernel/trace_ext.h>
#include <descriptor.h>
#include <drivers/apic.h>
#include <kernel/fault.h>
#include <tee/tee_svc.h>

/* exceptions */
#define INT_DIVIDE_0        0x00
#define INT_DEBUG_EX        0x01
#define INT_INVALID_OP      0x06
#define INT_DEV_NA_EX       0x07
#define INT_STACK_FAULT     0x0c
#define INT_GP_FAULT        0x0d
#define INT_PAGE_FAULT      0x0e
#define INT_MF              0x10
#define INT_XM              0x13

static void dump_fault_frame(x86_iframe_t *frame)
{
	EMSG(" CS:              %4lx RIP: %16lx EFL: %16lx CR3: %16lx\n",
			frame->cs, frame->ip, frame->flags, x86_get_cr3());
	EMSG(" RAX: %16lx RBX: %16lx RCX: %16lx RDX: %16lx\n",
			frame->ax, frame->bx, frame->cx, frame->dx);
	EMSG(" RSI: %16lx RDI: %16lx RBP: %16lx RSP: %16lx\n",
			frame->si, frame->di, frame->bp, frame->user_sp);
	EMSG("  R8: %16lx  R9: %16lx R10: %16lx R11: %16lx\n",
			frame->r8, frame->r9, frame->r10, frame->r11);
	EMSG(" R12: %16lx R13: %16lx R14: %16lx R15: %16lx\n",
			frame->r12, frame->r13, frame->r14, frame->r15);
	EMSG("errc: %16lx CR2: %16lx\n", frame->err_code, x86_get_cr2());
}

static void exception_die(x86_iframe_t *frame, const char *msg)
{
	trace_ext_puts(msg);
	dump_fault_frame(frame);

	for (;;) {
		x86_cli();
		x86_hlt();
	}
}

static void x86_gpf_handler(x86_iframe_t *frame)
{
	exception_die(frame, "unhandled gpf, halting\n");
}

static void x86_invop_handler(x86_iframe_t *frame)
{
	uint8_t rpl = frame->cs & USER_RPL;

	if (rpl == USER_RPL) {
		/* User mode invalid op */
		syscall_panic(0xdeadbeef);
	} else {
		/* Supervisor mode invalid op */
		exception_die(frame, "Invalid op exception, halting\n");
	}
}

static void x86_unhandled_exception(x86_iframe_t *frame)
{
	EMSG("vector %u\n", (unsigned int)frame->vector);
	exception_die(frame, "unhandled exception, halting\n");
}

static void x86_pfe_handler(x86_iframe_t *frame)
{
	uint32_t error_code = frame->err_code;

	if (error_code & PFEX_U) {
		/* User mode page fault */
		syscall_panic(0xdeadbeef);
	} else {
		/* Supervisor mode page fault */
		exception_die(frame, "Page Fault exception, halting\n");
	}
}

void x86_exception_handler(x86_iframe_t *frame)
{
	unsigned int vector = frame->vector;

	if (vector >= 0x20 && vector <= 255) {
		trace_disable();
		apic_it_handle(frame);
		trace_enable();
		return;
	}

	switch (vector) {
	case INT_GP_FAULT:
		x86_gpf_handler(frame);
		break;

	case INT_INVALID_OP:
		x86_invop_handler(frame);
		break;

	case INT_PAGE_FAULT:
		x86_pfe_handler(frame);
		break;

	case INT_DIVIDE_0:
	case INT_DEBUG_EX:
	case INT_STACK_FAULT:
	case 3:
	default:
		x86_unhandled_exception(frame);
		break;
	}
}
