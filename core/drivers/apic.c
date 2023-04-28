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

#define PIC1_DATA 0x21
#define PIC2_DATA 0xA1

#define MSR_APIC_BASE               0x1B
#define PAGE_4K_MASK                0xfffULL
#define LAPIC_BASE_ADDR(base_msr)   ((base_msr) & (~PAGE_4K_MASK))
#define LAPIC_ENABLED               (1ULL << 11)
#define LAPIC_X2_ENABLED            (1ULL << 10)
#define LAPIC_SOFTWARE_ENABLED      (1ULL << 8)
#define LAPIC_TIMER_MASK_BIT        (1ULL << 16)
#define LAPIC_TIMER_VEC_MASK        0xFF
#define MSR_x2APIC_ID               0x802

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

static struct apic_data lapic_data;

static uint8_t lvt_timer_vec;

//dummy functions on x86
static void apic_op_add(struct itr_chip *chip __unused, size_t it __unused,
	uint32_t flags __unused)
{
	return;
}

static void apic_op_enable(struct itr_chip *chip __unused, size_t it __unused)
{
	return;
}

static void apic_op_disable(struct itr_chip *chip __unused, size_t it __unused)
{
#ifdef CFG_VIRTIO_TEE
	if (it == lvt_timer_vec) {
		lapic_write_reg(LAPIC_LVT_TIMER_REG,
			lapic_read_reg(LAPIC_LVT_TIMER_REG) | LAPIC_TIMER_MASK_BIT);
	}
#endif

	return;
}

static void apic_op_raise_pi(struct itr_chip *chip __unused, size_t it __unused)
{
	return;
}

static void apic_op_raise_sgi(struct itr_chip *chip __unused, size_t it __unused,
	uint8_t cpu_mask __unused)
{
	return;
}

static void apic_op_set_affinity(struct itr_chip *chip __unused, size_t it __unused,
	uint8_t cpu_mask __unused)
{
	return;
}

static const struct itr_ops apic_ops = {
	.add = apic_op_add,
	.enable = apic_op_enable,
	.disable = apic_op_disable,
	.raise_pi = apic_op_raise_pi,
	.raise_sgi = apic_op_raise_sgi,
	.set_affinity = apic_op_set_affinity,
};

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
	uint64_t addr = lapic_base_virtual_addr + (uint64_t)(reg_id << 4);

	return *(volatile uint32_t*)(addr);
}

static void lapic_x1_write_reg(lapic_reg_id_t reg_id, uint32_t data)
{
	uint64_t addr = lapic_base_virtual_addr + (uint64_t)(reg_id << 4);

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

static uint64_t lapic_x2_read_reg(lapic_reg_id_t reg_id)
{
	return read_msr(MSR_X2APIC_BASE + reg_id);
}

static void lapic_x2_write_reg(lapic_reg_id_t reg_id, uint64_t data)
{
	write_msr(MSR_X2APIC_BASE + reg_id, data);
}

static void local_apic_init(void)
{
	uint64_t lapic_base_phy_addr = LAPIC_BASE_ADDR(read_msr(MSR_APIC_BASE));

	lapic_base_virtual_addr = (vaddr_t)phys_to_virt_io(lapic_base_phy_addr);

	lvt_timer_vec = lapic_read_reg(LAPIC_LVT_TIMER_REG) & LAPIC_TIMER_VEC_MASK;
	IMSG("lvt_timer_vec=%d\n", lvt_timer_vec);

	lapic_data.chip.ops = &apic_ops;
}

bool send_self_ipi(uint32_t vector)
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

static void lapic_software_enable(void)
{
	uint64_t value = 0;
	uint64_t apic_base_msr = read_msr(MSR_APIC_BASE);

	if (!(apic_base_msr & LAPIC_ENABLED))
		return;

	if (apic_base_msr & LAPIC_X2_ENABLED) {
		IMSG("x2 lapic id=0x%lx\n", read_msr(MSR_x2APIC_ID));
		value = lapic_x2_read_reg(LAPIC_SIVR);
		value = value | LAPIC_SOFTWARE_ENABLED;
		lapic_x2_write_reg(LAPIC_SIVR, value);
	} else {
		IMSG("x1 lapic id=0x%lx\n", get_lapicx1_id());
		value = lapic_x1_read_reg(LAPIC_SIVR);
		value = value | LAPIC_SOFTWARE_ENABLED;
		lapic_x1_write_reg(LAPIC_SIVR, value);
	}
}

uint64_t lapic_read_reg(lapic_reg_id_t reg_id)
{
	uint64_t apic_base_msr = read_msr(MSR_APIC_BASE);
	uint64_t value = 0;

	if (apic_base_msr & LAPIC_X2_ENABLED)
		value = lapic_x2_read_reg(reg_id);
	else
		value = lapic_x1_read_reg(reg_id);

	return value;
}

void lapic_write_reg(lapic_reg_id_t reg_id, uint64_t data)
{
	uint64_t apic_base_msr = read_msr(MSR_APIC_BASE);

	if (apic_base_msr & LAPIC_X2_ENABLED)
		lapic_x2_write_reg(reg_id, data);
	else
		lapic_x1_write_reg(reg_id, data);
}

void apic_init(void)
{
	disable_pic();

	x86_set_cr8(0xF);

	if (check_x2apic_support())
		IMSG("support x2 apic\n");
	else
		IMSG("not support x2 apic\n");

	local_apic_init();

	lapic_software_enable();

	itr_init(&lapic_data.chip);
}

void apic_it_handle(uint32_t id)
{
//TODO: will merge these tow cases for interrupt handling
#ifdef CFG_FOREIGN_INTR
	send_self_ipi(id);

	lapic_eoi();

	foreign_intr_handle(id);
#else
	itr_handle(id);

	lapic_eoi();
#endif
}
