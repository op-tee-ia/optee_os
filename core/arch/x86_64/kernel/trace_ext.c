// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Intel Corporation
 * Copyright (c) 2014, Linaro Limited
 */
#include <stdbool.h>
#include <trace.h>
#include <kernel/trace_ext.h>
#include <console.h>
#include <kernel/spinlock.h>
#include <kernel/thread.h>
#include <mm/core_mmu.h>

#define TRACE_DISABLE -1

const char trace_ext_prefix[] = "TC";
int trace_level __nex_data = TRACE_LEVEL;
int org_trace_level;
static unsigned int puts_lock __nex_bss = SPINLOCK_UNLOCK;

void trace_ext_puts(const char *str)
{
	uint32_t itr_status = thread_mask_exceptions(THREAD_EXCP_ALL);
	bool mmu_enabled = cpu_mmu_enabled();
	bool was_contended = false;
	const char *p;

	if (mmu_enabled && !cpu_spin_trylock(&puts_lock)) {
		was_contended = true;
		cpu_spin_lock_no_dldetect(&puts_lock);
	}

	console_flush();

	if (was_contended)
		console_putc('*');

	for (p = str; *p; p++)
		console_putc(*p);

	console_flush();

	if (mmu_enabled)
		cpu_spin_unlock(&puts_lock);

	thread_unmask_exceptions(itr_status);
}

int trace_ext_get_thread_id(void)
{
    return thread_get_id_may_fail();
}

void trace_disable(void)
{
	if (trace_level != TRACE_DISABLE) {
		org_trace_level = trace_level;
		trace_level = TRACE_DISABLE;
	}
}

void trace_enable(void)
{
	if (trace_level == TRACE_DISABLE)
		trace_level = org_trace_level;
}
