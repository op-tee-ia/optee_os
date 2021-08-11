// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Linaro Limited
 */
#include <compiler.h>
#include <initcall.h>
#include <kernel/boot.h>
#include <kernel/thread.h>
#include <kernel/wait_queue.h>
#include <tee_api_types.h>
#include <tee/entry_std.h>

#include "thread_private.h"

void __section(".text.dummy.call_initcalls") call_initcalls(void)
{
}

void __section(".text.dummy.call_finalcalls") call_finalcalls(void)
{
}

void __section(".text.dummy.boot_init_primary_late")
boot_init_primary_late(unsigned long fdt __unused)
{
}

void __section(".text.dummy.__thread_std_smc_entry")
__thread_std_smc_entry(struct thread_smc_args *args __unused)
{
}
void __section(".text.dummy.__wq_rpc")
__wq_rpc(uint32_t func __unused, int id __unused,
	 const void *sync_obj __unused, const char *fname __unused,
	 int lineno  __unused)
{
}
