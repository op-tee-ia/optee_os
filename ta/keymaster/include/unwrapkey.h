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
