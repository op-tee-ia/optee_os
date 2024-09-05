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


#ifndef ANDROID_OPTEE_CRYPTO_AES_H
#define ANDROID_OPTEE_CRYPTO_AES_H

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "ta_ca_defs.h"
#include "operations.h"
#include "paddings.h"

keymaster_error_t TA_aes_finish(keymaster_operation_t *operation,
				keymaster_blob_t *input,
				keymaster_blob_t *output, uint32_t *out_size,
				uint32_t tag_len, bool *is_input_ext,
				const keymaster_key_param_set_t *in_params);

keymaster_error_t TA_aes_update(keymaster_operation_t *operation,
				keymaster_blob_t *input,
				keymaster_blob_t *output,
				uint32_t *out_size,
				const uint32_t input_provided,
				size_t *input_consumed,
				const keymaster_key_param_set_t *in_params,
				bool *is_input_ext);

keymaster_error_t TA_aes_init_operation(uint32_t algorithm, uint32_t mode,
				uint32_t objecttype, uint32_t objectusage,
				uint32_t attributeid,
				void *keybuffer, uint32_t maxkeylen,
				void *iv, size_t ivlen,
				TEE_OperationHandle *op);

#endif/*ANDROID_OPTEE_CRYPTO_AES_H*/
