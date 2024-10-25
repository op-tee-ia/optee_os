/*
 * INTEL CONFIDENTIAL
 * Copyright (C) 2024 Intel Corporation
 *
 * This software and the related documents are Intel copyrighted materials,
 * and your use of them is governed by the express license under which
 * they were provided to you ("License"). Unless the License provides otherwise,
 * you may not use, modify, copy, publish, distribute, disclose or transmit
 * this software or the related documents without Intel's prior written permission.
 * This software and the related documents are provided as is,
 * with no express or implied warranties,
 * other than those that are expressly stated in the License.
 */


#ifndef ANDROID_OPTEE_ROT_H
#define ANDROID_OPTEE_ROT_H

#include "ta_ca_defs.h"

#define SHA256_DIGEST_LENGTH    32
#define AVB_SHA512_DIGEST_SIZE  64
#define KM_INFO_SLOT_NUM	4

enum KM_SLOT_INDEX {
	KM_OS_VERSION,
	KM_OS_PATCH_LEVEL,
	KM_VENDOR_PATCH_LEVEL,
	KM_EARLY_BOOT_SET
};

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
	uint32_t km_info[KM_INFO_SLOT_NUM];
};

typedef struct tee_km_context {
	bool version_info_set;
	bool vendor_patchlevel_set;
	uint32_t os_version;
	uint32_t os_patchlevel;
	uint32_t vendor_patchlevel;
	uint32_t boot_patchlevel;
	struct ex_rot_data_t rot;
} tee_km_context_t;

#define DICE_CDI_SIZE 32
#define DICE_PRIVATE_KEY_SEED_SIZE 32
typedef struct tee_dice_context {
	bool cdi_set;
	uint8_t attest_cdi[DICE_CDI_SIZE];
	uint8_t seal_cdi[DICE_CDI_SIZE];
	uint8_t cdi_certificate[2048];
	size_t cdi_certificate_actual_size;
} tee_dice_context_t;

keymaster_error_t TA_restore_km_info(void);
void TA_init_km_context(void);
keymaster_error_t TA_configure_rot_info(enum KM_SLOT_INDEX index, uint32_t value);

#endif/* ANDROID_OPTEE_ROT_H */
