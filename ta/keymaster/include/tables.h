/*
 * Copyright (C) 2017 GlobalLogic
 *
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


#ifndef ANDROID_OPTEE_TABLES_H
#define ANDROID_OPTEE_TABLES_H

#define KM_MAX_USE_COUNTERS 20U
#define KM_MAX_USE_TIMERS 32U
#define UNDEFINED UINT32_MAX

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "ta_ca_defs.h"
#include "master_crypto.h"

typedef struct {
	uint8_t key_id[TAG_LENGTH];
	uint32_t count;
} keymaster_use_counter_t;

typedef struct {
	uint8_t key_id[TAG_LENGTH];
	TEE_Time last_access;
	uint32_t min_sec;
} keymaster_use_timer_t;

keymaster_error_t TA_count_key_uses(uint8_t *key_id,
				const uint32_t max_uses);

keymaster_error_t TA_trigger_timer(uint8_t *key_id);

keymaster_error_t TA_check_key_use_timer(uint8_t *key_id,
				const uint32_t min_sec);

#endif/* ANDROID_OPTEE_TABLES_H */
