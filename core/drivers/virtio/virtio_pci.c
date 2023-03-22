// SPDX-License-Identifier: BSD-2-Clause
/*
 *  Copyright (c) 2022 Intel Corporation
 */

#include <drivers/pci.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <trace.h>
#include <assert.h>

#include "virtio_device.h"
#include "virtio_pci.h"

/* Queue notification base address */
static uint64_t notify_base;

/* Device configuration base address */
static uint64_t device_base;


/*
 * Queue notification multiplier, notify_multiplier is combined with the
 * queue notify offset to derive the Queue Notify address within a BAR for
 * a virtqueue.
 */
static uint32_t notify_multiplier;

void virtio_set_features(struct virtio_config* vio, uint64_t features)
{
    struct virtio_pci_common_cfg* vio_pci = (struct virtio_pci_common_cfg*)vio;

    io_write_32(&vio_pci->guest_features_sel, 0);
    io_write_32(&vio_pci->guest_features, features & 0xFFFF);
    io_write_32(&vio_pci->guest_features_sel, 1);
    io_write_32(&vio_pci->guest_features, features >> 32);
}

uint64_t virtio_get_features(struct virtio_config* vio) 
{
    struct virtio_pci_common_cfg* vio_pci = (struct virtio_pci_common_cfg*)vio;
    uint64_t features;

    io_write_32(&vio_pci->host_features_sel, 1);
    features = io_read_32(&vio_pci->host_features);
    features <<= 32;
    io_write_32(&vio_pci->host_features_sel, 0);
    features |= io_read_32(&vio_pci->host_features);

    return features;
}

void vq_attach(struct virtq* vq, uint16_t idx)
{
    struct virtio_pci_common_cfg* vio_pci =
            (struct virtio_pci_common_cfg*)vq->vio;

    vq->queue_id = idx;
    io_write_16(&vio_pci->queue_sel, idx);
    io_write_16(&vio_pci->queue_size, vq->num_bufs);

    io_write_64(&vio_pci->queue_desc, (uint64_t)virt_to_phys(&vq->raw->desc));
    io_write_64(&vio_pci->queue_avail, (uint64_t)virt_to_phys(&vq->raw->avail));
    io_write_64(&vio_pci->queue_used, (uint64_t)virt_to_phys(&vq->raw->used));

    io_write_16(&vio_pci->queue_enable, 1);
}

void vq_kick(struct virtq* vq)
{
    struct virtio_pci_common_cfg* vio_pci =
            (struct virtio_pci_common_cfg*)vq->vio;
    uint16_t notify_off;
    uint64_t notify_addr;

    io_write_16(&vio_pci->queue_sel, vq->queue_id);

    notify_off = io_read_16(&vio_pci->queue_notify_off);

    notify_addr = notify_base + notify_off * notify_multiplier;
    io_write_32((void*)notify_addr, vq->queue_id);
}

void virtio_or_status(struct virtio_config* vio, uint32_t flags)
{
    struct virtio_pci_common_cfg* vio_pci = (struct virtio_pci_common_cfg*)vio;
    uint8_t old_status = io_read_8(&vio_pci->device_status);

    io_write_8(&vio_pci->device_status, old_status | flags);
}

uint32_t virtio_get_status(struct virtio_config* vio)
{
    struct virtio_pci_common_cfg* vio_pci = (struct virtio_pci_common_cfg*)vio;

    return io_read_8(&vio_pci->device_status);
}

void virtio_pci_common_cfg_print(struct virtio_config* vio)
{
    struct virtio_pci_common_cfg* vio_pci = (struct virtio_pci_common_cfg*)vio;

    DMSG("msix_config=0x%x\n", io_read_16(&vio_pci->msix_config));

    io_write_16(&vio_pci->queue_sel, 0);
    DMSG("queue0 msix_vector=0x%x\n", io_read_16(&vio_pci->queue_msix_vector));

    io_write_16(&vio_pci->queue_sel, 1);
    DMSG("queue1 msix_vector=0x%x\n", io_read_16(&vio_pci->queue_msix_vector));
}

void virtio_reset_device(struct virtio_config* vio)
{
    struct virtio_pci_common_cfg* vio_pci = (struct virtio_pci_common_cfg*)vio;

    io_write_8(&vio_pci->device_status, 0);
}

void virtio_set_guest_page_size(struct virtio_config* vio, uint32_t size)
{
    (void) vio;
    (void) size;
}

uint64_t virtio_get_device_config(void)
{
    struct virtio_device_config* dev_config = (struct virtio_device_config*)device_base;

    return io_read_64(&dev_config->guest_cid);
}


static void virtio_pci_get_dev_func(uint8_t* dev, uint8_t* func)
{
    uint8_t device;
    uint8_t function;
    uint32_t expect1, expect2;
    uint32_t dev_vndr;

    expect1 = VIRTIO_DEVICE_VENDOR_ID | (VIRTIO_PCI_DEVICE_SOCKET_ID << 16);
    expect2 = VIRTIO_DEVICE_VENDOR_ID | (VIRTIO_PCI_DEVICE_LEGACY_SOCKET_ID << 16);

    for (device = 0; device < PCI_MAX_DEV_NUM; device++) {
        for (function = 0; function < PCI_MAX_FUNC_NUM; function++) {
            dev_vndr = pci_read32(0, device, function, PCI_CONFIG_VENDOR_ID_OFFSET);

            DMSG("%d/%d/0x%x\n",device, function, dev_vndr);
            if (dev_vndr == expect1 || dev_vndr == expect2) {
                *dev = device;
                *func = function;
                return;
            }
        }
    }
}

static void* virtio_tee_probe_pci_io(void)
{
    uint8_t dev = 0xFF;
    uint8_t func = 0xFF;
    uint8_t cap_offset = 0;
    uint8_t common_bar = 0;
    uint16_t val16 = 0;
    uint32_t val = 0;
    uint64_t virtio_cfg = 0;
    uint64_t paddr = 0;
    vaddr_t vaddr = 0;

    /*
     * PCI devices reside in bus zero for QEMU by default.
     *
     * Traverse all devices and functions of bus zero to find virtio console
     * device. To speed up probe, read 32 bits combination of vendor ID and
     * device ID directly insteading of read 16 bits twice.
     */
    virtio_pci_get_dev_func(&dev, &func);

    if ((0xFF == dev) || (0xFF == func)) {
        EMSG("Error: Virtio tee PCI device not found!\n");
        return NULL;
    }

    /* Check capabilities list support. */
    val16 = pci_read16(0, dev, func, PCI_CONFIG_STATUS_OFFSET);
    if (!(val16 & (1 << STATUS_CAP_LIST_BIT_POSITION))) {
        EMSG("Error: Virtio tee capabilities list unsupport!\n");
        return NULL;
    }

    /* Enable BAR address MMIO support. */
    val16 = pci_read16(0, dev, func, PCI_CONFIG_COMMAND_OFFSET);
    val16 |= 1 << CMD_MEM_SPACE_BIT_POSITION;
    pci_write16(0, dev, func, PCI_CONFIG_COMMAND_OFFSET, val16);

    /* Get capabilities start offset */
    cap_offset = pci_read8(0, dev, func, PCI_CONFIG_CAP_PTR_OFFSET);

    /*
     * Traverse capabilites linked list to find common configuration
     * and notification settings. Common configuration and notification
     * should share same BAR with different offset.
     */
    do {
        val = pci_read32(0, dev, func, cap_offset);

        if (VIRTIO_PCI_CAP_COMMON_CFG == VIRTIO_CAP_TYPE(val)) {
            common_bar = pci_read8(0, dev, func,
                                   cap_offset + VIRTIO_PCI_CAP_BAR_OFFSET);

            virtio_cfg = pci_read32(0, dev, func,
                                    cap_offset + VIRTIO_PCI_CAP_OFF_OFFSET);
        }

        if (VIRTIO_PCI_CAP_NOTIFY_CFG == VIRTIO_CAP_TYPE(val)) {
            notify_multiplier = pci_read32(
                    0, dev, func, cap_offset + VIRTIO_NOTIFY_CAP_MLTP_OFFSET);

            notify_base = pci_read32(0, dev, func,
                                     cap_offset + VIRTIO_PCI_CAP_OFF_OFFSET);
        }

        if (VIRTIO_PCI_CAP_DEVICE_CFG == VIRTIO_CAP_TYPE(val)) {
            device_base = pci_read32(0, dev, func,
                                    cap_offset + VIRTIO_PCI_CAP_OFF_OFFSET);
        }

        cap_offset = VIRTIO_CAP_NEXT(val);
    } while (0 != cap_offset);

    paddr = pci_read32(0, dev, func, PCI_CONFIG_BAR0_OFFSET + (common_bar + 1) * 4);
    paddr <<= 32;
    paddr |= pci_read32(0, dev, func, PCI_CONFIG_BAR0_OFFSET + common_bar * 4);
    paddr = ROUNDDOWN(paddr, PAGE_SIZE);

    DMSG("0x%lx/0x%lx/0x%lx/0x%x/0x%lx/%d\n", paddr, virtio_cfg, notify_base,
        notify_multiplier, device_base, common_bar);

    if (!core_mmu_add_mapping(MEM_AREA_IO_NSEC, paddr, 4 * PAGE_SIZE)) {
        EMSG("virtio config map failed\n");
        return NULL;
    }
    vaddr = (vaddr_t)phys_to_virt(paddr, MEM_AREA_IO_NSEC);
    DMSG("vaddr=0x%lx\n", vaddr);

    virtio_cfg += vaddr;
    notify_base += vaddr;
    device_base += vaddr;
    
    return (void*)virtio_cfg;
}

struct virtio_config* virtio_tee_probe(void) {
    /* X86 utilizes PCI solution */
    return virtio_tee_probe_pci_io();
}

