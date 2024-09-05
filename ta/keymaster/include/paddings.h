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


#ifndef ANDROID_OPTEE_PADDINGS_H
#define ANDROID_OPTEE_PADDINGS_H

#define BLOCK_SIZE 16U
#define DES_BLOCK_SIZE 8U

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "ta_ca_defs.h"

keymaster_error_t TA_check_out_size(uint32_t block_size, const uint32_t input_l,
					keymaster_blob_t *output,
					uint32_t *out_size,
					uint32_t tag_len);

keymaster_error_t TA_add_pkcs7_pad(uint32_t block_size, keymaster_blob_t *input, uint32_t buffering_size,
				const bool force, keymaster_blob_t *output,
				uint32_t *out_size, bool *is_input_ext);

keymaster_error_t TA_remove_pkcs7_pad(uint32_t block_size, keymaster_blob_t *output,
					uint32_t *out_size);

bool TA_check_pkcs7_pad(uint32_t block_size, keymaster_blob_t *output);

keymaster_error_t TA_do_rsa_pad(uint8_t **input, uint32_t *input_l,
				const uint32_t key_size);

keymaster_error_t TA_do_rsa_pkcs_v1_5_rawpad(uint8_t **input, uint32_t *input_l,
					     const uint32_t key_size);

#endif/* ANDROID_OPTEE_PADDINGS_H */
