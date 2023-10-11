/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023, Intel Corporation
 */

#ifndef DRIVER_IVSHMEM_H
#define DRIVER_IVSHMEM_H

#include <compiler.h>
#include <tee_api_types.h>

#define OPTEE_SHM_QUEUE_SIZE 64

struct optee_smc_ring {
	uint16_t head;
	uint16_t tail;
	uint16_t ring[OPTEE_SHM_QUEUE_SIZE];
} __packed;

struct optee_vm_ids {
	uint32_t ree_id;
	uint32_t tee_id;
} __packed;

/* Initialize ivshmem device */
void ivshmem_init(void);

/* Ivshmem device doorbell ring operation */
void ivshmem_doorbell_ring(uint8_t dev, uint32_t peer);

/* ROT infomation copy basedon ivshmem */
TEE_Result ivshmem_rot_copy(uint8_t dev, void *dest, size_t size);

/* ROT infomation clean basedon ivshmem */
TEE_Result ivshmem_rot_clean(uint8_t dev, size_t size);

#endif
