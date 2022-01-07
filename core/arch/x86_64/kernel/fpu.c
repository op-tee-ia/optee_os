// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019 Intel Corporation
 */

#include <x86.h>
#include <kernel/fpu.h>

#define FPU_MASK_ALL_EXCEPTIONS 1

/* CPUID EAX = 1 return values */

#define ECX_SSE3    (0x00000001 << 0)
#define ECX_SSSE3   (0x00000001 << 9)
#define ECX_SSE4_1  (0x00000001 << 19)
#define ECX_SSE4_2  (0x00000001 << 20)
#define ECX_OSXSAVE (0x00000001 << 27)
#define EDX_FXSR    (0x00000001 << 24)
#define EDX_SSE     (0x00000001 << 25)
#define EDX_SSE2    (0x00000001 << 26)
#define EDX_FPU     (0x00000001 << 0)

#define FPU_CAP(ecx, edx) ((edx & EDX_FPU) != 0)

#define SSE_CAP(ecx, edx) ( \
    ((ecx & (ECX_SSE3 | ECX_SSSE3 | ECX_SSE4_1 | ECX_SSE4_2)) != 0) || \
    ((edx & (EDX_SSE | EDX_SSE2)) != 0) \
    )

#define FXSAVE_CAP(ecx, edx) ((edx & EDX_FXSR) != 0)

#define OSXSAVE_CAP(ecx, edx) ((ecx & ECX_OSXSAVE) !=0 )

static void get_cpu_cap(uint32_t *ecx, uint32_t *edx)
{
	uint32_t eax = 1;

	__asm__ __volatile__
	("cpuid" : "=c" (*ecx), "=d" (*edx) : "a" (eax));
}

void fpu_init(void)
{
	uint32_t ecx = 0, edx = 0;
	uint16_t fcw;
	uint32_t mxcsr;
	uint64_t x;

	get_cpu_cap(&ecx, &edx);

	if (!FPU_CAP(ecx, edx) || !SSE_CAP(ecx, edx) || !FXSAVE_CAP(ecx, edx))
		return;

	/* No x87 emul, monitor co-processor */

	x = x86_get_cr0();
	x &= (uint64_t)(~X86_CR0_EM);
	x |= X86_CR0_NE;
	x |= X86_CR0_MP;
	x86_set_cr0(x);

	/* Init x87 */
	__asm__ __volatile__ ("finit");
	__asm__ __volatile__("fstcw %0" : "=m" (fcw));
#if FPU_MASK_ALL_EXCEPTIONS
	/* mask all exceptions */
	fcw |= 0x3f;
#else
	/* unmask all exceptions */
	fcw &= 0xffc0;
#endif
	__asm__ __volatile__("fldcw %0" : : "m" (fcw));

	/* Init SSE */
	x = x86_get_cr4();
	x |= X86_CR4_OSXMMEXPT;
	x |= X86_CR4_OSFXSR;
	if(OSXSAVE_CAP(ecx, edx)) {
		x |= X86_CR4_OSXSAVE;
	}
	x86_set_cr4(x);

	__asm__ __volatile__("stmxcsr %0" : "=m" (mxcsr));
#if FPU_MASK_ALL_EXCEPTIONS
	/* mask all exceptions */
	mxcsr = (0x3f << 7);
#else
	/* unmask all exceptions */
	mxcsr &= 0x0000003f;
#endif
	__asm__ __volatile__("ldmxcsr %0" : : "m" (mxcsr));

	return;
}
