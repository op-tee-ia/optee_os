// SPDX-License-Identifier: BSD-2-Clause
/*
 *  Copyright (c) 2023 Intel Corporation
 */
#include <drivers/io_mem.h>
#include <drivers/ivshmem.h>
#include <drivers/pci.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <sm/optee_smc.h>
#include <assert.h>
#include <optee_msg.h>
#include <platform_config.h>
#include <string.h>
#include <string_ext.h>
#include <trace.h>

#define IVSHMEM_VENDOR_ID	0x1AF4
#define IVSHMEM_DEVICE_ID	0x1110

#define TEE_MAX_IVSHMEM_DEVICE	2
#define IVSHMEM_DOORBELL_VECTOR	0xF0

#define IVPOSITION_OFF 0x08
#define DOORBELL_OFF   0x0C

#define ROT_INTERRUPT_OFF		1
#define ROLLBACK_INDEX_INTERRUPT_OFF	2

#define MSIX_ADDR_LOW_FIXED		0xFEE00000
#define MSIX_ADDR_LOW_RH		0x8

#define MSIX_DM_FIXED			0x000
#define MSIX_DM_LOWEST_PRIO		0x100

#define IVSHMEM_SMC_SIZE		0x200000
#define IVSHMEM_ROT_MAX_SIZE		0x100000

#define IVSHMEM_MSIX_ENTRY_NUM		3

struct ivshmem_device {
	uint8_t dev;
	uint8_t func;
	uint8_t revision;

	vaddr_t regs_addr;
	vaddr_t msix_addr;
	vaddr_t smc_addr;
	vaddr_t rot_addr;

	uint32_t bar0_addr;
	uint32_t bar0_len;
	uint32_t bar1_addr;
	uint32_t bar1_len;
	uint32_t bar2_addr;
	uint32_t bar2_len;
};

static struct ivshmem_device g_ivshmem_devs[TEE_MAX_IVSHMEM_DEVICE];

extern paddr_t tee_shmem_start;

struct thread_smc_args *g_smc_args = NULL;
struct optee_smc_ring *smc_avail_ring = NULL;
struct optee_smc_ring *smc_used_ring = NULL;
struct optee_vm_ids *smc_vm_ids = NULL;

static enum itr_return ivshmem_doorbell_itr_cb(struct itr_handler *h __unused)
{
	return ITRR_HANDLED;
}

static enum itr_return ivshmem_rot_itr_cb(struct itr_handler *h __unused)
{
	return ITRR_HANDLED;
}

static enum itr_return ivshmem_rollback_index_itr_cb(struct itr_handler *h __unused)
{
	return ITRR_HANDLED;
}

static struct itr_handler ivshmem_doorbell_itr = {
	.it = IVSHMEM_DOORBELL_VECTOR,
	.flags = ITRF_TRIGGER_LEVEL,
	.handler = ivshmem_doorbell_itr_cb,
};

static struct itr_handler ivshmem_rot_itr = {
	.it = IVSHMEM_DOORBELL_VECTOR + ROT_INTERRUPT_OFF,
	.flags = ITRF_TRIGGER_LEVEL,
	.handler = ivshmem_rot_itr_cb,
};

static struct itr_handler ivshmem_rollback_index_itr = {
	.it = IVSHMEM_DOORBELL_VECTOR + ROLLBACK_INDEX_INTERRUPT_OFF,
	.flags = ITRF_TRIGGER_LEVEL,
	.handler = ivshmem_rollback_index_itr_cb,
};

static uint8_t ivshmem_get_dev_func(void)
{
	uint8_t device;
	uint8_t function;
	uint32_t expect;
	uint32_t dev_vndr;
	uint8_t num = 0;

	expect = IVSHMEM_VENDOR_ID | (IVSHMEM_DEVICE_ID << 16);

	for (device = 0; device < PCI_MAX_DEV_NUM; device++) {
		for (function = 0; function < PCI_MAX_FUNC_NUM; function++) {
			dev_vndr = pci_read32(0, device, function, PCI_CONFIG_VENDOR_ID_OFFSET);

			if (dev_vndr == expect) {
				g_ivshmem_devs[num].dev = device;
				g_ivshmem_devs[num].func = function;
				if (++num >= TEE_MAX_IVSHMEM_DEVICE)
					break;
			}
		}
	}

	return num;
}

void ivshmem_init(void)
{
	uint8_t dev_num = 0;
	uint8_t i = 0, j = 0;
	uint8_t dev, func;
	uint8_t cap_offset = 0;
	uint16_t val16 = 0;
	uint32_t *vector_ctrl;
	uint32_t *msg_data;
	uint32_t *msg_lower_addr;
	uint32_t *msg_upper_addr;

	/*
	 * PCI devices reside in bus zero for QEMU by default.
	 *
	 * Traverse all devices and functions of bus zero to find virtio console
	 * device. To speed up probe, read 32 bits combination of vendor ID and
	 * device ID directly insteading of read 16 bits twice.
	 */
	dev_num = ivshmem_get_dev_func();
	if (dev_num == 0) {
		panic("Error: IVSHMEM PCI device not found!\n");
	} else {
		IMSG("Found %d IVSHMEM device\n", dev_num);
	}

	for (i = 0; i < dev_num; i++) {
		dev = g_ivshmem_devs[i].dev;
		func = g_ivshmem_devs[i].func;
		g_ivshmem_devs[i].revision = pci_read8(0, dev, func, PCI_CONFIG_REVISION_OFFSET);
		IMSG("IVSHMEM device %d: revision=%d\n", i, g_ivshmem_devs[i].revision);

		/* Enable BAR address MMIO support. */
		val16 = pci_read16(0, dev, func, PCI_CONFIG_COMMAND_OFFSET);
		val16 |= 1 << CMD_MEM_SPACE_BIT_POSITION;
		pci_write16(0, dev, func, PCI_CONFIG_COMMAND_OFFSET, val16);

		g_ivshmem_devs[i].bar0_addr = pci_resource_start(0, dev, func, PCI_CONFIG_BAR0_OFFSET);
		g_ivshmem_devs[i].bar0_len = pci_resource_len(0, dev, func, PCI_CONFIG_BAR0_OFFSET);
		IMSG("IVSHMEM device %d: bar0 addr=0x%x, len=0x%x\n", i,
			g_ivshmem_devs[i].bar0_addr, g_ivshmem_devs[i].bar0_len);
		if (!core_mmu_add_mapping(MEM_AREA_IO_SEC, g_ivshmem_devs[i].bar0_addr, PAGE_SIZE)) {
			EMSG("IVSHMEM device %d: regs map failed\n", i);
			panic();
		}
		g_ivshmem_devs[i].regs_addr = (vaddr_t)phys_to_virt(g_ivshmem_devs[i].bar0_addr,
			MEM_AREA_IO_SEC);
		IMSG("IVSHMEM device %d: regs_addr=0x%lx\n", i, g_ivshmem_devs[i].regs_addr);

		g_ivshmem_devs[i].bar1_addr = pci_resource_start(0, dev, func, PCI_CONFIG_BAR1_OFFSET);
		g_ivshmem_devs[i].bar1_len = pci_resource_len(0, dev, func, PCI_CONFIG_BAR1_OFFSET);
		IMSG("IVSHMEM device %d: bar1 addr=0x%x, len=0x%x\n", i,
			g_ivshmem_devs[i].bar1_addr, g_ivshmem_devs[i].bar1_len);

		g_ivshmem_devs[i].bar2_addr = pci_resource_start(0, dev, func, PCI_CONFIG_BAR2_OFFSET);
		g_ivshmem_devs[i].bar2_len = pci_resource_len(0, dev, func, PCI_CONFIG_BAR2_OFFSET);
		IMSG("IVSHMEM device %d: bar2 addr=0x%x, len=0x%x\n", i,
			g_ivshmem_devs[i].bar2_addr, g_ivshmem_devs[i].bar2_len);
		if (g_ivshmem_devs[i].bar2_len < 0x400000) {
			EMSG("IVSHMEM device %d: bar2 size too small\n", i);
			panic();
		}
		if (!core_mmu_add_mapping(MEM_AREA_RAM_NSEC, g_ivshmem_devs[i].bar2_addr,
				IVSHMEM_SMC_SIZE)) {
			EMSG("IVSHMEM device %d: smc map failed\n", i);
			panic();
		}
		g_ivshmem_devs[i].smc_addr = (vaddr_t)phys_to_virt(g_ivshmem_devs[i].bar2_addr,
			MEM_AREA_RAM_NSEC);
		IMSG("IVSHMEM device %d: smc_addr=0x%lx\n", i, g_ivshmem_devs[i].smc_addr);

		smc_vm_ids = (struct optee_vm_ids *)g_ivshmem_devs[i].smc_addr;
		smc_avail_ring = (struct optee_smc_ring *)(g_ivshmem_devs[i].smc_addr +
			sizeof(struct optee_vm_ids));
		smc_used_ring = (struct optee_smc_ring *)(g_ivshmem_devs[i].smc_addr +
			sizeof(struct optee_vm_ids) + sizeof(struct optee_smc_ring));
		g_smc_args = (struct thread_smc_args *)(g_ivshmem_devs[i].smc_addr +
			sizeof(struct optee_vm_ids) + sizeof(struct optee_smc_ring) +
			sizeof(struct optee_smc_ring));
		smc_avail_ring->head = 0;
		smc_avail_ring->tail = 0;
		for (j = 0; j < OPTEE_SHM_QUEUE_SIZE; j++) {
			smc_avail_ring->ring[j] = j;
		}
		smc_used_ring->head = 0;
		smc_used_ring->tail = 0;
		for (j = 0; j < OPTEE_SHM_QUEUE_SIZE; j++) {
			smc_used_ring->ring[j] = OPTEE_SHM_QUEUE_SIZE;
		}

		g_ivshmem_devs[i].rot_addr = g_ivshmem_devs[i].smc_addr + 0x100000;
		IMSG("IVSHMEM device %d: rot_addr=0x%lx\n", i, g_ivshmem_devs[i].rot_addr);

		tee_shmem_start = ROUNDUP(g_ivshmem_devs[i].bar2_addr + 0x200000, 0x100000);
		IMSG("IVSHMEM device %d: tee_shmem_start=0x%lx\n", i, tee_shmem_start);
		if ((tee_shmem_start + TEE_SHMEM_SIZE) >
			(g_ivshmem_devs[i].bar2_addr + g_ivshmem_devs[i].bar2_len))
			panic("nsec shm is out of bar2");
		if (!core_mmu_add_mapping(MEM_AREA_NSEC_SHM, tee_shmem_start, TEE_SHMEM_SIZE)) {
			EMSG("IVSHMEM device %d: nsec shm map failed\n", i);
			panic();
		}
		IMSG("IVSHMEM device %d: tee_shmem_start vaddr=0x%lx\n", i,
			(vaddr_t)phys_to_virt(tee_shmem_start, MEM_AREA_NSEC_SHM));

		if (g_ivshmem_devs[i].revision == 1) {
			smc_vm_ids->tee_id = 
				io_read_32((void *)(g_ivshmem_devs[i].regs_addr + IVPOSITION_OFF));
			IMSG("IVSHMEM device %d: ivposition=%d\n", i, smc_vm_ids->tee_id);

			if (g_ivshmem_devs[i].bar1_addr != 0 && g_ivshmem_devs[i].bar1_len != 0) {
				if (!core_mmu_add_mapping(MEM_AREA_RAM_SEC, g_ivshmem_devs[i].bar1_addr,
						g_ivshmem_devs[i].bar1_len)) {
					EMSG("IVSHMEM device %d: msix map failed\n", i);
					panic();
				}
				g_ivshmem_devs[i].msix_addr = (vaddr_t)phys_to_virt(
					g_ivshmem_devs[i].bar1_addr, MEM_AREA_RAM_SEC);
				IMSG("IVSHMEM device %d: msix_addr=0x%lx\n",
					i, g_ivshmem_devs[i].msix_addr);
			}

			/* Check capabilities list support. */
			val16 = pci_read16(0, dev, func, PCI_CONFIG_STATUS_OFFSET);
			if (!(val16 & (1 << STATUS_CAP_LIST_BIT_POSITION))) {
				panic("Error: IVSHMEM capabilities list unsupport!\n");
			}

			/* Get capabilities start offset */
			cap_offset = pci_read8(0, dev, func, PCI_CONFIG_CAP_PTR_OFFSET);
			IMSG("IVSHMEM device %d: cap_offset=0x%x\n", i, cap_offset);

			val16 = pci_read16(0, dev, func, cap_offset + PCI_MSIX_FLAGS);
			IMSG("IVSHMEM device %d: capability message control=0x%x\n", i, val16);
			pci_write16(0, dev, func, cap_offset + PCI_MSIX_FLAGS,
				val16 | PCI_MSIX_FLAGS_ENABLE);

			/* Traverse capabilities linked list to find MSI-X capabilities */
			for (j = 0; j < 3; j++) {
				IMSG("IVSHMEM device %d: cap_offset%d=0x%x\n", i, j,
					pci_read32(0, dev, func, cap_offset));
				cap_offset += 0x4; 
			}

			for (j = 0; j < IVSHMEM_MSIX_ENTRY_NUM; j++) {
				msg_lower_addr = (uint32_t *)(g_ivshmem_devs[i].msix_addr +
					PCI_MSIX_ENTRY_SIZE * j + PCI_MSIX_ENTRY_LOWER_ADDR);
				msg_upper_addr = (uint32_t *)(g_ivshmem_devs[i].msix_addr +
					PCI_MSIX_ENTRY_SIZE * j + PCI_MSIX_ENTRY_UPPER_ADDR);
				msg_data = (uint32_t *)(g_ivshmem_devs[i].msix_addr +
					PCI_MSIX_ENTRY_SIZE * j + PCI_MSIX_ENTRY_DATA);
				vector_ctrl = (uint32_t *)(g_ivshmem_devs[i].msix_addr +
					PCI_MSIX_ENTRY_SIZE * j + PCI_MSIX_ENTRY_VECTOR_CTRL);
			
				*msg_lower_addr = MSIX_ADDR_LOW_FIXED | MSIX_ADDR_LOW_RH;
				*msg_upper_addr = 0x0;
				*msg_data = (IVSHMEM_DOORBELL_VECTOR + i * IVSHMEM_MSIX_ENTRY_NUM + j) |
					MSIX_DM_LOWEST_PRIO;
				*vector_ctrl = 0x0;
				IMSG("IVSHMEM device %d: msi-x table entry %d 0x%x/0x%x/0x%x/0x%x\n", i, j,
					*msg_lower_addr, *msg_upper_addr, *msg_data, *vector_ctrl);
			}
		}
	}

	itr_add(&ivshmem_doorbell_itr);
	itr_add(&ivshmem_rot_itr);
	itr_add(&ivshmem_rollback_index_itr);

	return;
}

void ivshmem_doorbell_ring(uint8_t dev, uint32_t peer)
{
	assert(peer != 0);

	io_write_32((void *)(g_ivshmem_devs[dev].regs_addr + DOORBELL_OFF), peer<<16);
}

TEE_Result ivshmem_rot_copy(uint8_t dev, void *dest, size_t size)
{
	if (g_ivshmem_devs[dev].rot_addr != 0 && size <= IVSHMEM_ROT_MAX_SIZE) {
		memcpy(dest, (void *)g_ivshmem_devs[dev].rot_addr, size);
		return TEE_SUCCESS;
	} else {
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

TEE_Result ivshmem_rot_clean(uint8_t dev, size_t size)
{
	if (g_ivshmem_devs[dev].rot_addr != 0 && size <= IVSHMEM_ROT_MAX_SIZE) {
		memzero_explicit((void *)g_ivshmem_devs[dev].rot_addr, size);
		return TEE_SUCCESS;
	} else {
		return TEE_ERROR_NOT_SUPPORTED;
	}
}


