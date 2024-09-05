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


#ifndef ANDROID_OPTEE_CRYPTO_RSA_H
#define ANDROID_OPTEE_CRYPTO_RSA_H

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "ta_ca_defs.h"
#include "operations.h"
#include "generator.h"

#define KM_MAX_DIGEST_SIZE 64

keymaster_error_t TA_rsa_finish(keymaster_operation_t *operation,
				keymaster_blob_t *input,
				keymaster_blob_t *output, uint32_t *out_size,
				const uint32_t key_size,
				const keymaster_blob_t signature,
				const TEE_ObjectHandle obj_h,
				bool *is_input_ext);

keymaster_error_t TA_rsa_update(keymaster_operation_t *operation,
				const keymaster_blob_t *input,
				keymaster_blob_t *output,
				uint32_t *out_size,
				const uint32_t key_size,
				size_t *input_consumed,
				const uint32_t input_provided,
				const TEE_ObjectHandle obj_h);

#endif/*ANDROID_OPTEE_CRYPTO_RSA_H*/
