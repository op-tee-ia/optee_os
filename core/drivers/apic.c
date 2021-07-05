// SPDX-License-Identifier: BSD-2-Clause
/*
 *  Copyright (c) 2018 Intel Corporation
 */

#include <drivers/apic.h>
#include <kernel/interrupt.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <trace.h>
#include <assert.h>

typedef enum {
	LAPIC_ID_REG            = 0x2,
	LAPIC_EOI               = 0xB,
	LAPIC_SIVR              = 0xF,
	LAPIC_INTR_CMD_REG      = 0x30, /* 64-bits in x2APIC */
	LAPIC_INTR_CMD_HI_REG   = 0x31, /* not available in x2APIC */
	LAPIC_SELF_IPI_REG      = 0x3F  /* not available in xAPIC */
} lapic_reg_id_t;

#define PIC1_DATA 0x21
#define PIC2_DATA 0xA1

#define MSR_APIC_BASE    0x1B
#define PAGE_4K_MASK     0xfffULL
#define LAPIC_BASE_ADDR(base_msr) ((base_msr) & (~PAGE_4K_MASK))
#define LAPIC_ENABLED    (1ULL << 11)
#define LAPIC_X2_ENABLED (1ULL << 10)

#define APIC_DS_BIT (1<<12)
#define MSR_X2APIC_BASE 0x800

#define APIC_DM_FIXED     0x000
#define APIC_DM_NMI       0x400
#define APIC_DM_INIT      0X500
#define APIC_DM_STARTUP   0x600
#define APIC_LEVEL_ASSERT 0x4000
#define APIC_DEST_NOSHORT 0x00000
#define APIC_DEST_SELF    0x40000
#define APIC_DEST_EXCLUDE 0xC0000

static volatile vaddr_t lapic_base_virtual_addr = 0;

static char master_pic, slave_pic;

static void disable_pic(void) {
	/* save PIC value */
	master_pic = inp(PIC1_DATA);
	slave_pic = inp(PIC2_DATA);

	/* disable all IRQs */
	outp(PIC1_DATA, 0xff);
	outp(PIC2_DATA, 0xff);
}

void restore_pic(void)
{
	outp(PIC1_DATA, master_pic);
	outp(PIC2_DATA, slave_pic);
}

static uint32_t lapic_x1_read_reg(lapic_reg_id_t reg_id)
{
	uint64_t addr;

	assert(lapic_base_virtual_addr);
	addr = lapic_base_virtual_addr + (uint64_t)(reg_id << 4);

	return *(volatile uint32_t*)(addr);
}

static void lapic_x1_write_reg(lapic_reg_id_t reg_id, uint32_t data)
{
	uint64_t addr;

	assert(lapic_base_virtual_addr);
	addr = lapic_base_virtual_addr + (uint64_t)(reg_id << 4);

	*(volatile uint32_t*)addr = data;
}

static void lapic_x1_wait_for_ipi(void)
{
	uint32_t icr_low;

	while (1) {
		icr_low = lapic_x1_read_reg(LAPIC_INTR_CMD_REG);
		if ((icr_low & APIC_DS_BIT) == 0)
			return;
	}
}

static uint64_t __unused lapic_x2_read_reg(lapic_reg_id_t reg_id)
{
	return read_msr(MSR_X2APIC_BASE + reg_id);
}

static void lapic_x2_write_reg(lapic_reg_id_t reg_id, uint64_t data)
{
	write_msr(MSR_X2APIC_BASE + reg_id, data);
}

static void local_apic_init(void)
{
	uint64_t lapic_base_phy_addr = read_msr(MSR_APIC_BASE);

	lapic_base_phy_addr = LAPIC_BASE_ADDR(lapic_base_phy_addr);

	lapic_base_virtual_addr = (vaddr_t)phys_to_virt_io(lapic_base_phy_addr);
}

static bool send_self_ipi(uint32_t vector)
{
	uint32_t icr_low = APIC_DEST_SELF|APIC_LEVEL_ASSERT|APIC_DM_FIXED|vector;
	uint64_t apic_base_msr = read_msr(MSR_APIC_BASE);

	if (!(apic_base_msr & LAPIC_ENABLED)) {
		return false;
	}

	if (apic_base_msr & LAPIC_X2_ENABLED) {
		lapic_x2_write_reg(LAPIC_SELF_IPI_REG, (uint64_t)vector);
	} else {
		lapic_x1_wait_for_ipi();
		lapic_x1_write_reg(LAPIC_INTR_CMD_REG, icr_low);
	}

	return true;
}

static void lapic_eoi(void)
{
	uint64_t apic_base_msr = read_msr(MSR_APIC_BASE);

	if (!(apic_base_msr & LAPIC_ENABLED))
		return;

	if (apic_base_msr & LAPIC_X2_ENABLED)
		lapic_x2_write_reg(LAPIC_EOI, 0);
	else
		lapic_x1_write_reg(LAPIC_EOI, 0);
}

void lapic_software_disable(void)
{
	uint64_t apic_base_msr = read_msr(MSR_APIC_BASE);

	if (!(apic_base_msr & LAPIC_ENABLED))
		return;

	if (apic_base_msr & LAPIC_X2_ENABLED)
		lapic_x2_write_reg(LAPIC_SIVR, 0xFF);
	else
		lapic_x1_write_reg(LAPIC_SIVR, 0xFF);
}

void apic_init(void)
{
	disable_pic();

	x86_set_cr8(0xF);

	local_apic_init();
}

void apic_it_handle(x86_iframe_t *frame)
{
	uint32_t id = frame->vector;

	//TODO: will add native interrupt handling
	send_self_ipi(id);

	lapic_eoi();

	foreign_intr_handle(id);
}
