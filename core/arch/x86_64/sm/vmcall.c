// SPDX-License-Identifier: BSD-2-Clause
/*
 *  Copyright (c) 2018 Intel Corporation
 */

#include <sm/vmcall.h>

#define OPTEE_VMCALL_SMC               0x6F707400 /* "opt" is 0x6F7074 */

void make_smc_vmcall(struct thread_smc_args *args)
{
	__asm__ __volatile__(
		"vmcall;"
		: "=D"(args->a0), "=S"(args->a1),
		"=d"(args->a2), "=b"(args->a3), "=c"(args->a6)
		: "a"(OPTEE_VMCALL_SMC), "D"(args->a0), "S"(args->a1),
		"d"(args->a2), "b"(args->a3)
	);

	args->a4 = args->a6 & 0xffffffff;
	args->a5 = (args->a6 & 0xffffffff00000000) >> 32;
}

