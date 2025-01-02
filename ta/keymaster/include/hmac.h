/*
 *
 * Copyright (C) 2017 GlobalLogic
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
