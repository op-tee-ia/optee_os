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


#ifndef ANDROID_OPTEE_MASTER_CRYPTO_H
#define ANDROID_OPTEE_MASTER_CRYPTO_H

#define KEY_LENGTH 32
#define TAG_LENGTH 16
#define IV_LENGTH 12

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "ta_ca_defs.h"
#include "paddings.h"

TEE_Result TA_open_secret_key(TEE_ObjectHandle *secretKey);

TEE_Result TA_create_secret_key(void);

TEE_Result TA_execute(uint8_t *data, const size_t size, const uint8_t *hidden, const size_t hidden_size, const uint32_t mode);
TEE_Result TA_encrypt(uint8_t *data, const size_t size, const uint8_t *hidden, const size_t hidden_size);
TEE_Result TA_decrypt(uint8_t *data, const size_t size, const uint8_t *hidden, const size_t hidden_size);

void TA_free_master_key(void);

#endif/* ANDROID_OPTEE_MASTER_CRYPTO_H */
