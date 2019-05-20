/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Intel Corporation
 */

#ifndef __DRIVER_UART_H
#define __DRIVER_UART_H

#include <types_ext.h>
#include <drivers/serial.h>

#define UART_REGISTER_THR 0     /* WO Transmit Holding Register */
#define UART_REGISTER_RBR 0     /* RO Receive Buffer Register */
#define UART_REGISTER_DLL 0     /* R/W Divisor Latch LSB */
#define UART_REGISTER_DLM 1     /* R/W Divisor Latch MSB */
#define UART_REGISTER_IER 1     /* R/W Interrupt Enable Register */
#define UART_REGISTER_IIR 2     /* RO Interrupt Identification Register */
#define UART_REGISTER_FCR 2     /* WO FIFO Cotrol Register */
#define UART_REGISTER_LCR 3     /* R/W Line Control Register */
#define UART_REGISTER_MCR 4     /* R/W Modem Control Register */
#define UART_REGISTER_LSR 5     /* R/W Line Status Register */
#define UART_REGISTER_MSR 6     /* R/W Modem Status Register */
#define UART_REGISTER_SCR 7     /* R/W Scratch Pad Register */

typedef union {
	struct {
		uint8_t dr:1;
		uint8_t oe:1;
		uint8_t pe:1;
		uint8_t fe:1;
		uint8_t bi:1;
		uint8_t thre:1;
		uint8_t temt:1;
		uint8_t fifoe:1;
	} bits;
	uint8_t data;
} uart_lsr_t;

struct uart_data {
	struct io_pa_va base;
	struct serial_chip chip;
};

void uart_init(struct uart_data *pd, uint64_t serial_base);

#endif /* __DRIVER_UART_H */

