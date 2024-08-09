/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANDROID_OPTEE_ROT_H
#define ANDROID_OPTEE_ROT_H

#include "ta_ca_defs.h"

#define SHA256_DIGEST_LENGTH    32
#define AVB_SHA512_DIGEST_SIZE  64

/* Structure for RoT info (fields defined by Google Keymaster2)
*/
struct rot_data_t{
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

typedef struct tee_km_context {
	bool version_info_set;
	bool rot_info_set;
	bool vendor_patchlevel_set;
	bool boot_patchlevel_set;
	uint32_t os_version;
	uint32_t os_patchlevel;
	uint32_t vendor_patchlevel;
	uint32_t boot_patchlevel;
	struct rot_data_t rot;
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

void TA_init_km_context(void);
keymaster_error_t TA_set_rot_data(void);

#endif/* ANDROID_OPTEE_ROT_H */
