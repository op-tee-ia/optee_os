/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Intel Corporation
 */

#ifndef DRIVER_IOAPIC_H
#define DRIVER_IOAPIC_H

#include <types_ext.h>

#define IOAPIC_PHYS_ADDR	0xF8000000
#define IRQ_BASE		0x20
#define REG_ID			0x00			// Register index: ID
#define REG_VER			0x01		// Register index: version
#define REG_TABLE		0x10		// Redirection table base
#define INT_MASK		0x00010000 // Interrupt disabled

union ioapic_reg_01
{
	uint32_t raw;
	struct
	{
		uint32_t version	: 8,
			 __reserved_2	: 8,
			 entries	: 8,
			 __reserved_1	: 8;
	} __attribute__((packed)) bits;
};

union ioapic_route_entry
{
	uint64_t raw;
	struct
	{
		uint64_t vector			: 8,
			 delivery_mode		: 3,
			 dest_mode_logical	: 1,
			 delivery_status	: 1,
			 active_low		: 1,
			 irr			: 1,
			 is_level		: 1,
			 masked			: 1,
			 reserved_0		: 39,
			 destid			: 8;
	} __attribute__((packed)) bits;
	struct
	{
		uint64_t w1 : 32,
			 w2 : 32;
	} val;
};

struct ioapic
{
	uint32_t reg;
	uint32_t pad[3];
	uint32_t data;
};

uint32_t ioapic_read(int reg);
void ioapic_write(int reg, uint32_t data);
void ioapic_set_route_entry(int pin, union ioapic_route_entry entry);
union ioapic_route_entry ioapic_get_route_entry(int pin);
void ioapic_disable_interrupt(int pin);
void ioapic_enable_interrupt(int pin);
uint32_t ioapic_get_it_num(int pin);
void ioapic_init(void);

#endif
