// SPDX-License-Identifier: BSD-2-Clause
/*
 *  Copyright (c) 2018 Intel Corporation
 */

#include <drivers/uart.h>
#include <util.h>
#include <platform_config.h>

uint8_t (*io_get_reg)(uint64_t base_addr, uint32_t reg_id);
void (*io_set_reg)(uint64_t base_addr, uint32_t reg_id, uint8_t val);

#if PRINT_USE_MMIO
static uint8_t uart_mmio_get_reg(uint64_t base_addr, uint32_t reg_id)
{
	return *(volatile uint8_t *)(base_addr + (uint64_t)reg_id * 4);
}

static void uart_mmio_set_reg(uint64_t base_addr, uint32_t reg_id, uint8_t val)
{
	*(volatile uint8_t *)(base_addr + (uint64_t)reg_id * 4) = val;
}
#elif PRINT_USE_IO_PORT
static inline uint8_t asm_in8(uint16_t port)
{
	uint8_t val8;

	__asm__ __volatile__ (
	"inb %1, %0"
	: "=a" (val8)
	: "d" (port));
	return val8;
}

static inline void asm_out8(uint16_t port, uint8_t val8)
{
	__asm__ __volatile__ (
	"outb %1, %0"
	:
	: "d" (port), "a" (val8));

}

static uint8_t serial_io_get_reg(uint64_t base_addr, uint32_t reg_id)
{
	return asm_in8((uint16_t)base_addr + (uint16_t)reg_id);
}

static void serial_io_set_reg(uint64_t base_addr, uint32_t reg_id, uint8_t val)
{
	asm_out8((uint16_t)base_addr + (uint16_t)reg_id, val);
}
#endif

static vaddr_t chip_to_base(struct serial_chip *chip)
{
	struct uart_data *pd =
		container_of(chip, struct uart_data, chip);

	return pd->base.va;
}

static void uart_putc(struct serial_chip *chip, int c)
{
	uart_lsr_t lsr;
	vaddr_t io_base = chip_to_base(chip);

#if PRINT_USE_MMIO
	io_get_reg = uart_mmio_get_reg;
	io_set_reg = uart_mmio_set_reg;
#elif PRINT_USE_IO_PORT
	io_get_reg = serial_io_get_reg;
	io_set_reg = serial_io_set_reg;
#else
	return;
#endif

	while (1) {
		lsr.data = io_get_reg(io_base, UART_REGISTER_LSR);
		if (lsr.bits.thre == 1)
			break;
	}

	io_set_reg(io_base, UART_REGISTER_THR, c);
}

static void uart_flush(struct serial_chip *chip)
{
	uart_lsr_t lsr;
	vaddr_t io_base = chip_to_base(chip);

#if PRINT_USE_MMIO
	io_get_reg = uart_mmio_get_reg;
	io_set_reg = uart_mmio_set_reg;
#elif PRINT_USE_IO_PORT
	io_get_reg = serial_io_get_reg;
	io_set_reg = serial_io_set_reg;
#else
	return;
#endif

	while (1) {
		lsr.data = io_get_reg(io_base, UART_REGISTER_LSR);
		if (lsr.bits.temt == 1 && lsr.bits.thre == 1)
			break;
	}
}

static const struct serial_ops uart_ops = {
	.flush = uart_flush,
	.getchar = NULL,
	.have_rx_data = NULL,
	.putc = uart_putc,
};

void uart_init(struct uart_data *pd, uint64_t serial_base)
{
	pd->base.pa = serial_base;
	pd->base.va = 0;
	pd->base.va = io_pa_or_va(&pd->base);
	pd->chip.ops = &uart_ops;
}
