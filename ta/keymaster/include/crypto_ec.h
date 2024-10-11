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


#ifndef ANDROID_OPTEE_CRYPTO_EC_H
#define ANDROID_OPTEE_CRYPTO_EC_H

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "shift.h"
#include "ta_ca_defs.h"
#include "operations.h"
#include "crypto_rsa.h"
#include "mbedtls_proxy.h"

#define TA_SHARED_SECRET_MAX_SIZE  128

keymaster_error_t TA_ec_update(keymaster_operation_t *operation,
				const uint32_t type,
				const keymaster_blob_t *input,
				keymaster_blob_t *output,
				size_t *input_consumed,
				const uint32_t input_provided);

keymaster_error_t TA_ec_finish(const keymaster_operation_t *operation,
				const uint32_t type,
				keymaster_blob_t *input,
				keymaster_blob_t *output,
				keymaster_blob_t *signature,
				uint32_t *out_size,
				const uint32_t key_size,
				bool *is_input_ext);

#endif/* ANDROID_OPTEE_CRYPTO_EC_H */
