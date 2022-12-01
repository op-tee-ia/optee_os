/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Intel Corporation
 */

#ifndef DRIVER_VIRTIO_DEVICE_H
#define DRIVER_VIRTIO_DEVICE_H

#include "virtio.h"

/**
 * virtio_tee_probe() - Probe Virtio console device
 *
 * Return: Base address of the Virtio device specific configuration structure
 */
struct virtio_config* virtio_tee_probe(void);

/**
 * virtio_or_status() - Set status bit of Virtio device
 * @vio:    The Virtio device to set feature bit on
 * @flags:  The feature bit to be set
 */
void virtio_or_status(struct virtio_config* vio, uint32_t flags);

/**
 * virtio_get_status() - Get status of Virtio device
 * @vio:    The Virtio device to get status from
 *
 * Return: Status of the Virtio device
 */
uint32_t virtio_get_status(struct virtio_config* vio);

/**
 * virtio_reset_device() - Reset Virtio device
 * @vio:    The Virtio device to be reset
 */
void virtio_reset_device(struct virtio_config* vio);

/**
 * virtio_set_guest_page_size() - Set guest page size of Virtio device
 * @vio:    The Virtio device to set guest page size on
 * @size:   Size of guest page
 */
void virtio_set_guest_page_size(struct virtio_config* vio, uint32_t size);

uint64_t virtio_get_device_config(void);

void virtio_pci_common_cfg_print(struct virtio_config* vio);

#endif
