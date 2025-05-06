/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023, Intel Corporation
 */

#ifndef DRIVER_IVSHMEM_H
#define DRIVER_IVSHMEM_H

#include <compiler.h>
#include <tee_api_types.h>

#define TEE_MAX_IVSHMEM_DEVICE	4

#define OPTEE_SHM_QUEUE_SIZE 64
#define SHA256_DIGEST_LENGTH    32
#define AVB_SHA512_DIGEST_SIZE  64
#define KM_INFO_SLOT_NUM 4

extern uint8_t g_ivshmem_dev_num;

/* Structure for RoT info (fields defined by Google Keymaster2)
*/
struct rot_data_t {
	/* version 2 for current TEE keymaster2 */
	uint32_t version;
	/* 0:unlocked, 1:locked, others not used */
	uint32_t deviceLocked;
	/* GREEN:0, YELLOW:1, ORANGE:2, others not used(no RED for TEE) */
	uint32_t verifiedBootState;
	/* The current version of the OS as an integer in the format MMmmss,
		* where MM is a two-digit major version number, mm is a two-digit,
		* minor version number, and ss is a two-digit sub-minor version number.
		* For example, version 6.0.1 would be represented as 060001;
	*/
	uint32_t osVersion;
	/* The day, month and year of the last patch as an integer in the format,
		* YYYYMMDD, where YYYY is a four-digit year and MM is a two-digit month,
		* DD is a two-digit day. For example, April 1, 2016 would be represented
		* 20160401.
	*/
	uint32_t patchMonthYearDay;
	/* A secure hash (SHA-256 recommended by Google) of the key used to verify the system image
		* key_size (in bytes) is zero: denotes no key provided by Bootloader. When key_size is
		* 32, it denotes,key_hash256 is available. Other values not defined now.
	*/
	uint32_t keySize;
	uint8_t  keyHash256[SHA256_DIGEST_LENGTH];

	uint32_t digestSize;
	uint8_t  vbmetaDigest[AVB_SHA512_DIGEST_SIZE];

};

struct ex_rot_data_t {
	struct rot_data_t rot_data;
	/* ROT info specific for keymaster */
	uint32_t km_info[KM_INFO_SLOT_NUM];
};

struct optee_smc_ring {
	uint16_t head;
	uint16_t tail;
	uint16_t ring[OPTEE_SHM_QUEUE_SIZE];
} __packed;

struct optee_vm_ids {
	uint32_t ree_id;
	uint32_t tee_id;
} __packed;

typedef enum {
	EVENT_KERNEL = 1,
	EVENT_ROT,
	EVENT_ROLLBACK,
} shm_event_src_t;

/* Initialize ivshmem device */
void ivshmem_init(void);

/* Ivshmem device doorbell ring operation */
void ivshmem_doorbell_ring(uint8_t dev, uint32_t peer);

/* ROT infomation copy basedon ivshmem */
TEE_Result ivshmem_rot_copy(uint8_t dev, void *dest, size_t size);

/* OsPatchLevel, VendorPatchLevel and EarlyBootSet info will be set
 * by keymaster ta */
TEE_Result ivshmem_rot_set(uint8_t dev __unused, uint32_t a, uint32_t b);

/* Get current using ivshmem device index */
uint8_t get_cur_smc_idx(void);

#endif
