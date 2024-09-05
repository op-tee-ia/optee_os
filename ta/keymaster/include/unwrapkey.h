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


#ifndef UNWRAPKEY_H_
#define UNWRAPKEY_H_

#include "mbedtls_proxy.h"
#include "ta_ca_defs.h"

#define UNWRAPKEY_BUFFER_SIZE 8192U

keymaster_error_t TA_decode_wrapped_key_sequence(uint8_t *key_blob,
					 uint32_t key_size,
					 keymaster_key_param_set_t *auth_set,
					 keymaster_blob_t *iv,
					 keymaster_blob_t *tag,
					 keymaster_key_blob_t *transit_key,
					 keymaster_key_blob_t *secure_key,
					 keymaster_key_format_t *key_format,
					 keymaster_blob_t *wrapped_key_description);

keymaster_error_t TA_check_secure_id(keymaster_key_param_set_t *auth_set,
					int64_t password_sid,
					int64_t biometric_sid);

keymaster_error_t TA_construct_transport_key_params(
							keymaster_key_param_set_t *aes_params);
#endif /* UNWRAPKEY_H_ */
