/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Intel Corporation
 */

#ifndef DRIVER_APIC_H
#define DRIVER_APIC_H

#include <types_ext.h>
#include <kernel/interrupt.h>
#include <x86.h>

typedef enum {
	LAPIC_ID_REG            = 0x2,
	LAPIC_EOI               = 0xB,
	LAPIC_SIVR              = 0xF,
	LAPIC_INTR_CMD_REG      = 0x30, /* 64-bits in x2APIC */
	LAPIC_INTR_CMD_HI_REG   = 0x31, /* not available in x2APIC */
	LAPIC_LVT_TIMER_REG     = 0x32,
	LAPIC_SELF_IPI_REG      = 0x3F  /* not available in xAPIC */
} lapic_reg_id_t;

struct apic_data {
    struct itr_chip chip;
};

uint64_t lapic_read_reg(lapic_reg_id_t reg_id);
void lapic_write_reg(lapic_reg_id_t reg_id, uint64_t data);
void apic_init(void);
void restore_pic(void);
void lapic_software_disable(void);
void apic_it_handle(uint32_t id);
uint8_t lapic_get_id(void);
bool send_self_ipi(uint32_t vector);

#endif
