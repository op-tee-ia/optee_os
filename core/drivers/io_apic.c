// SPDX-License-Identifier: BSD-2-Clause
/*
 *  Copyright (c) 2023 Intel Corporation
 */
#include <drivers/io_apic.h>
#include <drivers/apic.h>
#include <kernel/panic.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <string_ext.h>
#include <trace.h>

volatile struct ioapic *ioapic;

uint32_t ioapic_read(int reg)
{
	ioapic->reg = reg;
	return ioapic->data;
}

void ioapic_write(int reg, uint32_t data)
{
	ioapic->reg = reg;
	ioapic->data = data;
}

void ioapic_set_route_entry(int pin, union ioapic_route_entry entry)
{
	ioapic_write(REG_TABLE + 2 * pin, entry.val.w1);
	ioapic_write(REG_TABLE + 2 * pin + 1, entry.val.w2);
}

union ioapic_route_entry ioapic_get_route_entry(int pin)
{
	union ioapic_route_entry entry;

	entry.val.w1 = ioapic_read(REG_TABLE + 2 * pin);
	entry.val.w2 = ioapic_read(REG_TABLE + 2 * pin + 1);

	return entry;
}

void ioapic_disable_interrupt(int pin)
{
	union ioapic_route_entry entry;

	entry.val.w1 = ioapic_read(REG_TABLE + 2 * pin);
	entry.bits.masked = 1;
	ioapic_write(REG_TABLE + 2 * pin, entry.val.w1);
}

void ioapic_enable_interrupt(int pin)
{
	union ioapic_route_entry entry;

	entry.val.w1 = ioapic_read(REG_TABLE + 2 * pin);
	entry.bits.masked = 0;
	ioapic_write(REG_TABLE + 2 * pin, entry.val.w1);
}

uint32_t ioapic_get_it_num(int pin)
{
	return IRQ_BASE + pin;
}

void ioapic_init(void)
{
	if (!core_mmu_add_mapping(MEM_AREA_IO_SEC, IOAPIC_PHYS_ADDR, 0x1000)) {
		EMSG("ioapic page map failed\n");
		panic();
	}

	ioapic = (volatile struct ioapic *)phys_to_virt(IOAPIC_PHYS_ADDR, MEM_AREA_IO_SEC);

	union ioapic_route_entry entry;
	union ioapic_reg_01 reg_01;
	reg_01.raw = ioapic_read(REG_VER);

	//Delivery Mode: Fixed, Destination Mode: Physical, Interrupt Pin Polarity: Low active
	//Trigger Mode: Level sensitive, Interrupt Mask: Masked, Destination Field: apic id
	entry.raw = 0;
	entry.bits.active_low = 1;
	entry.bits.is_level = 1;
	entry.bits.masked = 1;
	entry.bits.destid = lapic_get_id();
	IMSG("lapic id: %d\n", entry.bits.destid);

	for(int pin = 0; pin <= reg_01.bits.entries; pin++) {
		entry.bits.vector = IRQ_BASE + pin;
		ioapic_set_route_entry(pin, entry);
	}
	IMSG("ioapic init succussfully");
}
