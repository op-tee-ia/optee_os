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


#ifndef ANDROID_OPTEE_HMAC_H
#define ANDROID_OPTEE_HMAC_H

#define KEY_LENGTH 32
#define HMAC256_TAG_LENGTH 32
#define IV_LENGTH 12

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "ta_ca_defs.h"
#include "paddings.h"

TEE_Result TA_open_hmac_key(TEE_ObjectHandle *secretKey);

TEE_Result TA_create_hmac_key(void);

TEE_Result TA_hmac_execute(uint8_t *message, size_t message_len, uint8_t *tag, uint32_t tag_len);

void TA_free_hmac_key(void);

#endif/* ANDROID_OPTEE_HMAC_H */
