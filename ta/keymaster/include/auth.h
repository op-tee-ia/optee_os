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


#ifndef ANDROID_OPTEE_AUTH_H
#define ANDROID_OPTEE_AUTH_H

#define MAX_SUID 10

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "ta_ca_defs.h"
#include "tables.h"

TEE_Result TA_InitializeAuthTokenKey(void);

keymaster_error_t TA_GetAuthTokenKey(TEE_Param params[TEE_NUM_PARAMS]);

TEE_Result TA_computeTokenHmac(const hw_auth_token_t *auth_token, uint8_t *hmac,
					uint32_t hmac_length);

keymaster_error_t TA_check_auth_token(const uint64_t *suid,
					const uint32_t suid_count,
					const hw_authenticator_type_t auth_type,
					const hw_auth_token_t *auth_token,
					uint32_t timeout);

keymaster_error_t TA_do_auth(const keymaster_key_param_set_t in_params,
				const keymaster_key_param_set_t key_params,
				const keymaster_operation_handle_t operation_handle);

keymaster_error_t TA_do_confirm(const keymaster_key_param_set_t in_params,
				const keymaster_key_param_set_t key_params);

#define HMAC_SHA256_KEY_SIZE_BYTE 32
#define HMAC_SHA256_KEY_SIZE_BIT (8*HMAC_SHA256_KEY_SIZE_BYTE)
#define HW_AUTH_TOKEN_VERSION 0

#endif/*ANDROID_OPTEE_AUTH_H*/
