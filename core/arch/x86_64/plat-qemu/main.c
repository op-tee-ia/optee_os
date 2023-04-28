// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Intel Corporation
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <console.h>
#include <drivers/uart.h>
#include <initcall.h>
#include <keep.h>
#include <kernel/boot.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/tee_time.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <string.h>
#include <tee/entry_fast.h>
#include <tee/entry_std.h>
#include <trace.h>

static struct uart_data console_data __nex_bss;

register_phys_mem(MEM_AREA_IO_SEC, APIC_BASE, APIC_REG_SIZE);
#ifdef CFG_VIRTIO_TEE
register_phys_mem(MEM_AREA_RAM_NSEC, VIRTIO_BASE, VIRTIO_SIZE);
#endif


void console_init(void)
{
	uart_init(&console_data, CONSOLE_UART_BASE);
	register_serial_console(&console_data.chip);
	IMSG("TRACE INITIALIZED\n");
}

#ifdef IT_CONSOLE_UART
static enum itr_return console_itr_cb(struct itr_handler *h __unused)
{
	struct serial_chip *cons = &console_data.chip;

	while (cons->ops->have_rx_data(cons)) {
		int ch __maybe_unused = cons->ops->getchar(cons);

		DMSG("cpu %zu: got 0x%x", get_core_pos(), ch);
	}
	return ITRR_HANDLED;
}

static struct itr_handler console_itr = {
	.it = IT_CONSOLE_UART,
	.flags = ITRF_TRIGGER_LEVEL,
	.handler = console_itr_cb,
};
KEEP_PAGER(console_itr);

static TEE_Result init_console_itr(void)
{
	itr_add(&console_itr);
	itr_enable(IT_CONSOLE_UART);
	return TEE_SUCCESS;
}
driver_init(init_console_itr);
#endif
