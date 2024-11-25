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

#ifndef ANDROID_OPTEE_COSE_H
#define ANDROID_OPTEE_COSE_H

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "ta_ca_defs.h"
#include "generator.h"
#include "keystore_ta.h"
#include "rot.h"
#include "attestation.h"
#include <cbor.h>

#define KCOSE_MAC0_PROTECTED_PARAMS 0
#define KCOSE_MAC0_UNPROTECTED_PARAMS 1
#define KCOSE_MAC0_PAYLOAD 2
#define KCOSE_MAC0_TAG 3

#define SHA256_DIGEST_LENGTH 32

// These are the negations of the actual error codes
#define K_STATUS_FAILED ((keymaster_error_t)(-1))
#define K_STATUS_INVALID_MAC ((keymaster_error_t)(-2))
#define K_STATUS_REMOVED ((keymaster_error_t)(-6))

typedef enum {
	LABEL_ALGORITHM = 1,
	LABEL_KEY_ID_ = 4,
	LABEL_IV = 5,
	LABEL_COSE_KEY = -1,
} label_t;

typedef enum {
	AES_GCM_256 = 3,
	HMAC_256 = 5,
	ES256 = -7,  // ECDSA with SHA-256
	EDDSA = -8,
	ECDH_ES_HKDF_256 = -25,
	ES384 = -35,  // ECDSA with SHA-384
} cosekey_algorithm_t;

typedef enum {
	P256 = 1,
	P384 = 2,
	X25519 = 4,
	ED25519 = 6,
} cosekey_curve_t;

typedef enum {
	OCTET_KEY_PAIR = 1,
	EC2 = 2,
	SYMMETRIC_KEY = 4,
} cosekey_type_t;

typedef enum {
	SIGN = 1,
	VERIFY = 2,
	ENCRYPT = 3,
	DECRYPT = 4,
} cosekey_ops_t;

typedef enum {
	KEY_TYPE = 1,
	KEY_ID = 2,
	ALGORITHM = 3,
	KEY_OPS = 4,
	CURVE = -1,
	PUBKEY_X = -2,
	PUBKEY_Y = -3,
	PRIVATE_KEY = -4,
	TEST_KEY = -70000  // Application-defined
} cosekey_label_t;

keymaster_error_t TA_construct_cose_mac0(uint8_t *external_aad,
					 size_t external_aad_size,
					 uint8_t *payload,
					 size_t payload_size,
					 uint8_t **maced_key,
					 size_t *maced_key_size);

keymaster_error_t TA_validate_and_extract_pubkeys(bool testMode,
						  uint32_t num_keys,
						  keymaster_blob_t *keys_to_sign,
						  cbor_item_t **pubkeys_array);

keymaster_error_t TA_build_csr(tee_km_context_t *optee_km_context,
			       tee_dice_context_t *optee_dice_context,
			       tee_att_ids_cxt_t *optee_att_ids,
			       keymaster_blob_t *challenge,
			       cbor_item_t *keys_to_sign,
			       uint8_t **csr_blob_data,
		  	       size_t *csr_blob_data_length);

#endif /*ANDROID_OPTEE_COSE_H*/

