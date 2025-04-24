// SPDX-License-Identifier: BSD-2-Clause
/*
 *  Copyright (c) 2023 Intel Corporation
 */
#include <drivers/guest_shm.h>
#include <drivers/io_apic.h>
#include <drivers/io_mem.h>
#include <drivers/ivshmem.h>
#include <drivers/pci.h>
#ifdef CFG_EDK2_TPM
#include <drivers/tpm2_seed.h>
#endif
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

/* QNX tee shm size in pages*/
#define QNX_TEE_SHM_SIZE		0x500

#ifdef CFG_EDK2_TPM
#define TEE_TPM2_INIT                   0x00000001
#define TEE_TPM2_END                    0x00000002
#define TEE_TPM2_READ_DEVICE_STATE      0x00000003
#define TEE_TPM2_WRITE_DEVICE_STATE     0x00000004
#define TEE_TPM2_READ_ROLLBACK_INDEX    0x00000005
#define TEE_TPM2_WRITE_ROLLBACK_INDEX   0x00000006
#define TEE_TPM2_BOOTLOADER_NEED_INIT   0x00000007
#define TEE_TPM2_FUSE_LOCK_OWNER        0x00000008
#define TEE_TPM2_FUSE_PROVISION_SEED    0x00000009
#define TEE_TPM2_SHOW_INDEX             0x0000000A
#define TEE_TPM2_DELETE_INDEX           0x0000000B
#endif

extern bool is_qnx;

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

	volatile struct guest_shm_factory *fact;
	volatile struct guest_shm_control *ctrl;
};

static struct ivshmem_device g_ivshmem_devs[TEE_MAX_IVSHMEM_DEVICE] __nex_bss;

static struct ex_rot_data_t g_rot_data __nex_bss;

static bool g_rot_already_set __nex_data = false;

extern paddr_t tee_shmem_start[TEE_MAX_IVSHMEM_DEVICE];
extern bool g_tpm_nv_bootloader_lock;

struct thread_smc_args *g_smc_args[TEE_MAX_IVSHMEM_DEVICE] __nex_data = {NULL};
struct optee_smc_ring *smc_avail_ring[TEE_MAX_IVSHMEM_DEVICE] __nex_data = {NULL};
struct optee_smc_ring *smc_used_ring[TEE_MAX_IVSHMEM_DEVICE] __nex_data = {NULL};
struct optee_vm_ids *smc_vm_ids[TEE_MAX_IVSHMEM_DEVICE] __nex_data = {NULL};
uint32_t *smc_evt_src __nex_data = NULL;
uint8_t g_ivshmem_dev_num __nex_data = 0;

#ifdef CFG_EDK2_TPM
struct tpm2_int_req {
        uint32_t cmd;
        volatile int32_t ret;
        uint32_t size;
        uint8_t  payload[0];
};
#endif

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

static bool check_if_vm_reset(uint8_t vmid)
{
	IMSG("Checking if there is a reset for VM %d", vmid);

	assert(vmid <= TEE_MAX_IVSHMEM_DEVICE);
	assert(vmid >= 1);

	if (!g_tpm_nv_bootloader_lock)
		return true;

	asm_out8(0x600U, vmid);
	uint8_t val = asm_in8(0x600U);
	if (val == 1) {
		g_tpm_nv_bootloader_lock = false;
		g_rot_already_set = false;
		IMSG("g_tpm_nv_bootloader_lock is changed to UNLOCKED due to Android reset.");
	} else
		EMSG("g_tpm_nv_bootloader_lock(id:%d, val:%d) is still LOCKED! BLOCK TPM access!!!", vmid, val);

	return !g_tpm_nv_bootloader_lock;
}

static enum itr_return ivshmem_rot_itr_cb_0(struct itr_handler *h __unused)
{
	/* TODO: currently only have one ivsh device */

	if (!g_rot_already_set) {
		assert(g_ivshmem_devs[0].rot_addr != 0);

		memset(&g_rot_data, 0, sizeof(g_rot_data));

		memcpy(&g_rot_data.rot_data, (void *)g_ivshmem_devs[0].rot_addr,
						sizeof(struct rot_data_t));

		memzero_explicit((void *)g_ivshmem_devs[0].rot_addr, sizeof(struct rot_data_t));

		g_rot_already_set = true;
	}

	return ITRR_HANDLED;
}

static enum itr_return ivshmem_rollback_index_itr_cb_0(struct itr_handler *h __unused)
{
#ifdef CFG_EDK2_TPM
	EFI_STATUS ret = EFI_DEVICE_ERROR;
	// offset 0x1000 is reserved for seed rot to use.
	volatile struct tpm2_int_req *req =
		(struct tpm2_int_req *)(g_ivshmem_devs[0].rot_addr + 0x1000);

	//TEE_TPM2_READ_DEVICE_STATE
	UINT8 *rd_state = req->payload;

	//TEE_TPM2_WRITE_DEVICE_STATE:
	UINT8 wr_state = *(UINT8*)(req->payload);

	//TEE_TPM2_READ_ROLLBACK_INDEX
	size_t rd_rollback_index_slot = *(size_t*)(req->payload);
	uint64_t *rd_out_rollback_index = req->payload + sizeof(rd_rollback_index_slot);

	//TEE_TPM2_WRITE_ROLLBACK_INDEX:
	size_t wr_rollback_index_slot = *(size_t*)(req->payload);
	uint64_t wr_rollback_index = *(uint64_t*)(req->payload + sizeof(wr_rollback_index_slot));

	uint8_t vmid = smc_vm_ids[0]->ree_id;
	if (!check_if_vm_reset(vmid)) {
		EMSG("Failure: VM(%d) TPM locked by TEE, refuse...", vmid);
		req->ret = EFI_DEVICE_ERROR;
		return ITRR_HANDLED;
	}

	switch(req->cmd)
	{
	case TEE_TPM2_INIT:
		ret = tee_tpm2_init();
		break;
	case TEE_TPM2_END:
		ret = tee_tpm2_end();
		break;
	case TEE_TPM2_READ_DEVICE_STATE:
		ret = tee_tpm2_read_device_state(rd_state);
		break;
	case TEE_TPM2_WRITE_DEVICE_STATE:
		ret = tee_tpm2_write_device_state(wr_state);
		break;
	case TEE_TPM2_READ_ROLLBACK_INDEX:
		ret = tee_tpm2_read_rollback_index(rd_rollback_index_slot, rd_out_rollback_index);
		break;
	case TEE_TPM2_WRITE_ROLLBACK_INDEX:
		ret = tee_tpm2_write_rollback_index(wr_rollback_index_slot, wr_rollback_index);
		break;
	case TEE_TPM2_BOOTLOADER_NEED_INIT:
		ret = tee_tpm2_bootloader_need_init();
		break;
	case TEE_TPM2_FUSE_LOCK_OWNER:
		ret = tee_tpm2_fuse_lock_owner();
		break;
	case TEE_TPM2_FUSE_PROVISION_SEED:
		ret = EFI_NOT_READY;
		break;
	case TEE_TPM2_SHOW_INDEX:
		ret = EFI_NOT_READY;
		break;
	case TEE_TPM2_DELETE_INDEX:
		ret = EFI_NOT_READY;
		break;
	default:
		ret = EFI_UNSUPPORTED;
		break;
	}

	req->ret = ret;
#endif

	return ITRR_HANDLED;
}

static enum itr_return ivshmem_doorbell_itr_cb(struct itr_handler *h __unused)
{
	enum itr_return ret = ITRR_HANDLED;

	if (!is_qnx)
		return ret;

	if (g_ivshmem_devs[0].ctrl->status & (1 << smc_vm_ids[0]->ree_id)) {
		if (*smc_evt_src == EVENT_ROT)
			ret = ivshmem_rot_itr_cb_0(NULL);
		else if (*smc_evt_src == EVENT_ROLLBACK)
			ret = ivshmem_rollback_index_itr_cb_0(NULL);
	}

	return ret;
}

static struct itr_handler ivshmem_doorbell_itr_0 __nex_data = {
	.it = IVSHMEM_DOORBELL_VECTOR,
	.flags = ITRF_TRIGGER_LEVEL,
	.handler = ivshmem_doorbell_itr_cb,
};

static struct itr_handler ivshmem_doorbell_itr_1 __nex_data = {
	.it = IVSHMEM_DOORBELL_VECTOR + IVSHMEM_MSIX_ENTRY_NUM,
	.flags = ITRF_TRIGGER_LEVEL,
	.handler = ivshmem_doorbell_itr_cb,
};

static struct itr_handler ivshmem_doorbell_itr_2 __nex_data = {
	.it = IVSHMEM_DOORBELL_VECTOR + 2 * IVSHMEM_MSIX_ENTRY_NUM,
	.flags = ITRF_TRIGGER_LEVEL,
	.handler = ivshmem_doorbell_itr_cb,
};

static struct itr_handler ivshmem_doorbell_itr_3 __nex_data = {
	.it = IVSHMEM_DOORBELL_VECTOR + 3 * IVSHMEM_MSIX_ENTRY_NUM,
	.flags = ITRF_TRIGGER_LEVEL,
	.handler = ivshmem_doorbell_itr_cb,
};

static struct itr_handler ivshmem_rot_itr_0 __nex_data = {
	.it = IVSHMEM_DOORBELL_VECTOR + ROT_INTERRUPT_OFF,
	.flags = ITRF_TRIGGER_LEVEL,
	.handler = ivshmem_rot_itr_cb_0,
};

static struct itr_handler ivshmem_rot_itr_1 __nex_data = {
	.it = IVSHMEM_DOORBELL_VECTOR + IVSHMEM_MSIX_ENTRY_NUM + ROT_INTERRUPT_OFF,
	.flags = ITRF_TRIGGER_LEVEL,
	.handler = ivshmem_rot_itr_cb_0,
};

static struct itr_handler ivshmem_rot_itr_2 __nex_data = {
	.it = IVSHMEM_DOORBELL_VECTOR + 2 * IVSHMEM_MSIX_ENTRY_NUM + ROT_INTERRUPT_OFF,
	.flags = ITRF_TRIGGER_LEVEL,
	.handler = ivshmem_rot_itr_cb_0,
};

static struct itr_handler ivshmem_rot_itr_3 __nex_data = {
	.it = IVSHMEM_DOORBELL_VECTOR + 3 * IVSHMEM_MSIX_ENTRY_NUM + ROT_INTERRUPT_OFF,
	.flags = ITRF_TRIGGER_LEVEL,
	.handler = ivshmem_rot_itr_cb_0,
};

static struct itr_handler ivshmem_rollback_index_itr_0 __nex_data = {
	.it = IVSHMEM_DOORBELL_VECTOR + ROLLBACK_INDEX_INTERRUPT_OFF,
	.flags = ITRF_TRIGGER_LEVEL,
	.handler = ivshmem_rollback_index_itr_cb_0,
};

static struct itr_handler ivshmem_rollback_index_itr_1 __nex_data = {
	.it = IVSHMEM_DOORBELL_VECTOR + IVSHMEM_MSIX_ENTRY_NUM + ROLLBACK_INDEX_INTERRUPT_OFF,
	.flags = ITRF_TRIGGER_LEVEL,
	.handler = ivshmem_rollback_index_itr_cb_0,
};

static struct itr_handler ivshmem_rollback_index_itr_2 __nex_data = {
	.it = IVSHMEM_DOORBELL_VECTOR + 2 * IVSHMEM_MSIX_ENTRY_NUM + ROLLBACK_INDEX_INTERRUPT_OFF,
	.flags = ITRF_TRIGGER_LEVEL,
	.handler = ivshmem_rollback_index_itr_cb_0,
};

static struct itr_handler ivshmem_rollback_index_itr_3 __nex_data = {
	.it = IVSHMEM_DOORBELL_VECTOR + 3 * IVSHMEM_MSIX_ENTRY_NUM + ROLLBACK_INDEX_INTERRUPT_OFF,
	.flags = ITRF_TRIGGER_LEVEL,
	.handler = ivshmem_rollback_index_itr_cb_0,
};

static uint8_t ivshmem_get_dev_func(void)
{
	uint8_t device;
	uint8_t function;
	uint32_t expect;
	uint32_t dev_vndr;
	uint8_t num = 0;

	if (is_qnx)
		expect = PCI_VID_BlackBerry_QNX | (PCI_DID_QNX_GUEST_SHM << 16);
	else
		expect = IVSHMEM_VENDOR_ID | (IVSHMEM_DEVICE_ID << 16);

	for (device = 0; device < PCI_MAX_DEV_NUM; device++) {
		for (function = 0; function < PCI_MAX_FUNC_NUM; function++) {
			dev_vndr = pci_read32(0, device, function, PCI_CONFIG_VENDOR_ID_OFFSET);

			if (dev_vndr == expect) {
				g_ivshmem_devs[num].dev = device;
				g_ivshmem_devs[num].func = function;
				if (++num >= TEE_MAX_IVSHMEM_DEVICE)
					return num;
			}
		}
	}

	return num;
}

static void generic_ivshmem_init(void)
{
	uint8_t i = 0, j = 0;
	uint8_t dev, func;
	uint8_t cap_offset = 0;
	uint16_t val16 = 0;
	volatile uint32_t *vector_ctrl;
	volatile uint32_t *msg_data;
	volatile uint32_t *msg_lower_addr;
	volatile uint32_t *msg_upper_addr;

	/*
	 * PCI devices reside in bus zero for QEMU by default.
	 *
	 * Traverse all devices and functions of bus zero to find virtio console
	 * device. To speed up probe, read 32 bits combination of vendor ID and
	 * device ID directly insteading of read 16 bits twice.
	 */
	g_ivshmem_dev_num = ivshmem_get_dev_func();
	if (g_ivshmem_dev_num == 0) {
		panic("Error: IVSHMEM PCI device not found!\n");
	} else if (g_ivshmem_dev_num > TEE_MAX_IVSHMEM_DEVICE) {
		EMSG("Found too many ivshmem devices %d", g_ivshmem_dev_num);
		panic("Error: IVSHMEM PCI devices found too many!\n");
	} else {
		IMSG("Found %d IVSHMEM device\n", g_ivshmem_dev_num);
	}

	for (i = 0; i < g_ivshmem_dev_num; i++) {
		dev = g_ivshmem_devs[i].dev;
		func = g_ivshmem_devs[i].func;
		g_ivshmem_devs[i].revision = pci_read8(0, dev, func, PCI_CONFIG_REVISION_OFFSET);
		IMSG("IVSHMEM device %d/%d/%d: revision=%d\n", i, dev, func, g_ivshmem_devs[i].revision);

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

		smc_vm_ids[i] = (struct optee_vm_ids *)g_ivshmem_devs[i].smc_addr;
		smc_avail_ring[i] = (struct optee_smc_ring *)(g_ivshmem_devs[i].smc_addr +
			sizeof(struct optee_vm_ids));
		smc_used_ring[i] = (struct optee_smc_ring *)(g_ivshmem_devs[i].smc_addr +
			sizeof(struct optee_vm_ids) + sizeof(struct optee_smc_ring));
		g_smc_args[i] = (struct thread_smc_args *)(g_ivshmem_devs[i].smc_addr +
			sizeof(struct optee_vm_ids) + sizeof(struct optee_smc_ring) +
			sizeof(struct optee_smc_ring));
		smc_avail_ring[i]->head = 0;
		smc_avail_ring[i]->tail = 0;
		for (j = 0; j < OPTEE_SHM_QUEUE_SIZE; j++) {
			smc_avail_ring[i]->ring[j] = j;
		}
		smc_used_ring[i]->head = 0;
		smc_used_ring[i]->tail = 0;
		for (j = 0; j < OPTEE_SHM_QUEUE_SIZE; j++) {
			smc_used_ring[i]->ring[j] = OPTEE_SHM_QUEUE_SIZE;
		}

		g_ivshmem_devs[i].rot_addr = g_ivshmem_devs[i].smc_addr + 0x100000;
		IMSG("IVSHMEM device %d: rot_addr=0x%lx\n", i, g_ivshmem_devs[i].rot_addr);

		tee_shmem_start[i] = ROUNDUP(g_ivshmem_devs[i].bar2_addr + 0x200000, 0x100000);
		IMSG("IVSHMEM device %d: tee_shmem_start=0x%lx\n", i, tee_shmem_start[i]);
		if ((tee_shmem_start[i] + TEE_SHMEM_SIZE) >
			(g_ivshmem_devs[i].bar2_addr + g_ivshmem_devs[i].bar2_len))
			panic("nsec shm is out of bar2");
		if (!core_mmu_add_mapping(MEM_AREA_NSEC_SHM, tee_shmem_start[i], TEE_SHMEM_SIZE)) {
			EMSG("IVSHMEM device %d: nsec shm map failed\n", i);
			panic();
		}
		IMSG("IVSHMEM device %d: tee_shmem_start vaddr=0x%lx\n", i,
			(vaddr_t)phys_to_virt(tee_shmem_start[i], MEM_AREA_NSEC_SHM));

		if (g_ivshmem_devs[i].revision == 1) {
			smc_vm_ids[i]->tee_id = 
				io_read_32((void *)(g_ivshmem_devs[i].regs_addr + IVPOSITION_OFF));
			IMSG("IVSHMEM device %d: ivposition=%d\n", i, smc_vm_ids[i]->tee_id);

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

	itr_add(&ivshmem_doorbell_itr_0);
	itr_add(&ivshmem_doorbell_itr_1);
	itr_add(&ivshmem_doorbell_itr_2);
	itr_add(&ivshmem_doorbell_itr_3);
	itr_add(&ivshmem_rot_itr_0);
	itr_add(&ivshmem_rot_itr_1);
	itr_add(&ivshmem_rot_itr_2);
	itr_add(&ivshmem_rot_itr_3);
	itr_add(&ivshmem_rollback_index_itr_0);
	itr_add(&ivshmem_rollback_index_itr_1);
	itr_add(&ivshmem_rollback_index_itr_2);
	itr_add(&ivshmem_rollback_index_itr_3);

	return;
}

static void qnx_ivshmem_init(void)
{
	uint8_t j = 0;
	uint8_t dev, func;
	uint32_t shmem_addr;
	uint32_t shmem_len;


	/*
	 * PCI devices reside in bus zero for QEMU by default.
	 *
	 * Traverse all devices and functions of bus zero to find virtio console
	 * device. To speed up probe, read 32 bits combination of vendor ID and
	 * device ID directly insteading of read 16 bits twice.
	 */
	g_ivshmem_dev_num = ivshmem_get_dev_func();
	if (g_ivshmem_dev_num == 0) {
		panic("Error: IVSHMEM PCI device not found!!\n");
	} else if (g_ivshmem_dev_num > TEE_MAX_IVSHMEM_DEVICE) {
		EMSG("Found too many ivshmem devices %d", g_ivshmem_dev_num);
		panic("Error: IVSHMEM PCI devices found too many!\n");
	} else {
		IMSG("Found %d IVSHMEM device\n", g_ivshmem_dev_num);
	}

	// Support only 1 ivshmem device on QNX currently
	dev = g_ivshmem_devs[0].dev;
	func = g_ivshmem_devs[0].func;

	g_ivshmem_devs[0].bar0_addr = pci_resource_start(0, dev, func, PCI_CONFIG_BAR0_OFFSET);
	g_ivshmem_devs[0].bar0_len = pci_resource_len(0, dev, func, PCI_CONFIG_BAR0_OFFSET);
	IMSG("IVSHMEM device: bar0 addr=0x%x, len=0x%x\n",
	  g_ivshmem_devs[0].bar0_addr, g_ivshmem_devs[0].bar0_len);

	if (!core_mmu_add_mapping(MEM_AREA_RAM_SEC, g_ivshmem_devs[0].bar0_addr, PAGE_SIZE)) {
		EMSG("IVSHMEM device: factory page map failed\n");
		panic();
	}

	g_ivshmem_devs[0].fact = phys_to_virt(g_ivshmem_devs[0].bar0_addr, MEM_AREA_RAM_SEC);

	if ((g_ivshmem_devs[0].fact->signature & 0xFFFFFFFF) != GUEST_SHM_SIGNATURE_L
	  || (g_ivshmem_devs[0].fact->signature >> 32) != GUEST_SHM_SIGNATURE_H) {
		EMSG("factory signature doesn't match 0x%lx\n", g_ivshmem_devs[0].fact->signature);
		panic();
	}

	strcpy(g_ivshmem_devs[0].fact->name, "tee_shmem");
	//Allocate 5M memory
	guest_shm_create(g_ivshmem_devs[0].fact, QNX_TEE_SHM_SIZE);

	if (g_ivshmem_devs[0].fact->status != GSS_OK) {
		EMSG("factory status is not GSS_OK: %d name: %s!\n",
		  g_ivshmem_devs[0].fact->status, g_ivshmem_devs[0].fact->name);
		panic();
	}

	IMSG("factory status is GSS_OK shmem name is %s size 0x%x\n",
	  g_ivshmem_devs[0].fact->name, g_ivshmem_devs[0].fact->size);

	if (!core_mmu_add_mapping(MEM_AREA_RAM_SEC, g_ivshmem_devs[0].fact->shmem, PAGE_SIZE)) {
		EMSG("IVSHMEM device: shm ctrl page map failed\n");
		panic();
	}

	g_ivshmem_devs[0].ctrl = phys_to_virt(g_ivshmem_devs[0].fact->shmem, MEM_AREA_RAM_SEC);
	IMSG("ctrl status is 0x%x\n", g_ivshmem_devs[0].ctrl->status);

	shmem_addr = g_ivshmem_devs[0].fact->shmem + PAGE_SIZE;
	shmem_len = g_ivshmem_devs[0].fact->size * PAGE_SIZE;

	if (shmem_len < 0x400000) {
		EMSG("IVSHMEM device: bar2 size too small\n");
		panic();
	}

	if (!core_mmu_add_mapping(MEM_AREA_RAM_NSEC, shmem_addr, IVSHMEM_SMC_SIZE)) {
		EMSG("IVSHMEM device: smc map failed\n");
		panic();
	}

	g_ivshmem_devs[0].smc_addr = (vaddr_t)phys_to_virt(shmem_addr, MEM_AREA_RAM_NSEC);

	smc_evt_src = (uint32_t *)g_ivshmem_devs[0].smc_addr;
	smc_vm_ids[0] = (struct optee_vm_ids *)(g_ivshmem_devs[0].smc_addr +
	  sizeof(uint32_t));
	smc_avail_ring[0] = (struct optee_smc_ring *)(g_ivshmem_devs[0].smc_addr +
	  sizeof(uint32_t) + sizeof(struct optee_vm_ids));
	smc_used_ring[0] = (struct optee_smc_ring *)(g_ivshmem_devs[0].smc_addr +
	  sizeof(uint32_t) + sizeof(struct optee_vm_ids) +
	  sizeof(struct optee_smc_ring));
	g_smc_args[0] = (struct thread_smc_args *)(g_ivshmem_devs[0].smc_addr +
	  sizeof(uint32_t) + sizeof(struct optee_vm_ids) +
	  sizeof(struct optee_smc_ring) + sizeof(struct optee_smc_ring));

	smc_avail_ring[0]->head = 0;
	smc_avail_ring[0]->tail = 0;
	for (j = 0; j < OPTEE_SHM_QUEUE_SIZE; j++) {
		smc_avail_ring[0]->ring[j] = j;
	}

	smc_used_ring[0]->head = 0;
	smc_used_ring[0]->tail = 0;
	for (j = 0; j < OPTEE_SHM_QUEUE_SIZE; j++) {
		smc_used_ring[0]->ring[j] = OPTEE_SHM_QUEUE_SIZE;
	}

	g_ivshmem_devs[0].rot_addr = g_ivshmem_devs[0].smc_addr + 0x100000;

	tee_shmem_start[0] = ROUNDUP(shmem_addr + 0x200000, PAGE_SIZE);

	if ((tee_shmem_start[0] + TEE_SHMEM_SIZE) > (shmem_addr + shmem_len))
		panic("nsec shm is out of bar2");

	if (!core_mmu_add_mapping(MEM_AREA_NSEC_SHM, tee_shmem_start[0], TEE_SHMEM_SIZE)) {
		EMSG("IVSHMEM device: nsec shm map failed\n");
		panic();
	}

	smc_vm_ids[0]->tee_id = g_ivshmem_devs[0].ctrl->idx;
	IMSG("IVSHMEM device: tee_id:%d ree_id:%d", smc_vm_ids[0]->tee_id, smc_vm_ids[0]->ree_id);

#ifdef CFG_IO_APIC
	ivshmem_doorbell_itr_0.it = ioapic_get_it_num(g_ivshmem_devs[0].fact->vector);
	itr_add(&ivshmem_doorbell_itr_0);

	ioapic_enable_interrupt(g_ivshmem_devs[0].fact->vector);
#endif

	return;
}

void ivshmem_init(void)
{
	if(is_qnx)
		qnx_ivshmem_init();
	else
		generic_ivshmem_init();

}

void ivshmem_doorbell_ring(uint8_t dev, uint32_t peer)
{
	assert(peer != 0);

	if(is_qnx)
		g_ivshmem_devs[dev].ctrl->notify = 1 << peer;
	else
		io_write_32((void *)(g_ivshmem_devs[dev].regs_addr + DOORBELL_OFF), peer<<16);
}

TEE_Result ivshmem_rot_copy(uint8_t dev __unused, void *dest, size_t size)
{
	if (!dest)
		return TEE_ERROR_BAD_PARAMETERS;

	if (size != sizeof(g_rot_data))
		return TEE_ERROR_BAD_PARAMETERS;

	memcpy(dest, (void *)&g_rot_data, size);
	return TEE_SUCCESS;
}

TEE_Result ivshmem_rot_set(uint8_t dev __unused, uint32_t a, uint32_t b)
{
	if (a >= KM_INFO_SLOT_NUM)
		return TEE_ERROR_BAD_PARAMETERS;

	g_rot_data.km_info[a] = b;

	return TEE_SUCCESS;
}
