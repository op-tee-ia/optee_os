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


#ifndef KEYMASTER_COMMON_H
#define KEYMASTER_COMMON_H

#define SIZE_LENGTH sizeof(size_t)
/* AKMS stands for android keymaster serailzing function */
#define SIZE_LENGTH_AKMS sizeof(uint32_t)

#define SIZE_OF_ITEM(item) (item ? sizeof(item[0]) : 0)
#define PARAM_SET_SIZE(parameters) \
	(SIZE_LENGTH + \
	parameters->length * SIZE_OF_ITEM(parameters->params) \
	+ get_blob_size_in_params(parameters))
#define BLOB_SIZE(blob) \
	(blob->data_length * SIZE_OF_ITEM(blob->data) + SIZE_LENGTH)
#define BLOB_SIZE_AKMS(blob) \
	(blob->data_length * SIZE_OF_ITEM(blob->data) + SIZE_LENGTH_AKMS)

#define KEY_BLOB_SIZE(key_blob) \
	(key_blob->key_material_size * \
	SIZE_OF_ITEM(key_blob->key_material) + SIZE_LENGTH)
#define KEY_BLOB_SIZE_AKMS(key_blob) \
	(key_blob->key_material_size * \
	SIZE_OF_ITEM(key_blob->key_material) + SIZE_LENGTH_AKMS)

#define TA_KEYMASTER_UUID { 0xdba51a17, 0x0563, 0x11e7, \
	{ 0x93, 0xb1, 0x6f, 0xa7, 0xb0, 0x07, 0x1a, 0x51} }

enum keystore_command {
	KEYMASTER_RESP_BIT = 1,
	KEYMASTER_STOP_BIT = 2,
	KEYMASTER_REQ_SHIFT = 2,

	KM_GENERATE_KEY                 = (0 << KEYMASTER_REQ_SHIFT),
	KM_BEGIN_OPERATION              = (1 << KEYMASTER_REQ_SHIFT),
	KM_UPDATE_OPERATION             = (2 << KEYMASTER_REQ_SHIFT),
	KM_FINISH_OPERATION             = (3 << KEYMASTER_REQ_SHIFT),
	KM_ABORT_OPERATION              = (4 << KEYMASTER_REQ_SHIFT),
	KM_IMPORT_KEY                   = (5 << KEYMASTER_REQ_SHIFT),
	KM_EXPORT_KEY                   = (6 << KEYMASTER_REQ_SHIFT),
	KM_GET_VERSION                  = (7 << KEYMASTER_REQ_SHIFT),
	KM_ADD_RNG_ENTROPY              = (8 << KEYMASTER_REQ_SHIFT),
	KM_GET_SUPPORTED_ALGORITHMS     = (9 << KEYMASTER_REQ_SHIFT),
	KM_GET_SUPPORTED_BLOCK_MODES    = (10 << KEYMASTER_REQ_SHIFT),
	KM_GET_SUPPORTED_PADDING_MODES  = (11 << KEYMASTER_REQ_SHIFT),
	KM_GET_SUPPORTED_DIGESTS        = (12 << KEYMASTER_REQ_SHIFT),
	KM_GET_SUPPORTED_IMPORT_FORMATS = (13 << KEYMASTER_REQ_SHIFT),
	KM_GET_SUPPORTED_EXPORT_FORMATS = (14 << KEYMASTER_REQ_SHIFT),
	KM_GET_KEY_CHARACTERISTICS      = (15 << KEYMASTER_REQ_SHIFT),
	KM_ATTEST_KEY                   = (16 << KEYMASTER_REQ_SHIFT),
	KM_UPGRADE_KEY                  = (17 << KEYMASTER_REQ_SHIFT),
	KM_CONFIGURE                    = (18 << KEYMASTER_REQ_SHIFT),
	KM_GET_HMAC_SHARING_PARAMETERS  = (19 << KEYMASTER_REQ_SHIFT),
	KM_COMPUTE_SHARED_HMAC          = (20 << KEYMASTER_REQ_SHIFT),
	KM_VERIFY_AUTHORIZATION         = (21 << KEYMASTER_REQ_SHIFT),
	KM_DELETE_KEY                   = (22 << KEYMASTER_REQ_SHIFT),
	KM_DELETE_ALL_KEYS              = (23 << KEYMASTER_REQ_SHIFT),
	KM_DESTROY_ATTESTATION_IDS      = (24 << KEYMASTER_REQ_SHIFT),
	KM_IMPORT_WRAPPED_KEY           = (25 << KEYMASTER_REQ_SHIFT),
	KM_GET_VERSION_2                = (28 << KEYMASTER_REQ_SHIFT),
	KM_EARLY_BOOT_ENDED             = (29 << KEYMASTER_REQ_SHIFT),
	KM_DEVICE_LOCKED                = (30 << KEYMASTER_REQ_SHIFT),
	KM_GENERATE_RKP_KEY             = (31 << KEYMASTER_REQ_SHIFT),
	KM_GENERATE_CSR                 = (32 << KEYMASTER_REQ_SHIFT),
	KM_CONFIGURE_VENDOR_PATCHLEVEL  = (33 << KEYMASTER_REQ_SHIFT),
	KM_GET_ROOT_OF_TRUST            = (34 << KEYMASTER_REQ_SHIFT),
	KM_GET_HW_INFO                  = (35 << KEYMASTER_REQ_SHIFT),
	KM_GENERATE_CSR_V2              = (36 << KEYMASTER_REQ_SHIFT),

	// Bootloader/provisioning calls.
	KM_SET_BOOT_PARAMS = (0x1000 << KEYMASTER_REQ_SHIFT),
	KM_SET_ATTESTATION_KEY = (0x2000 << KEYMASTER_REQ_SHIFT),
	KM_APPEND_ATTESTATION_CERT_CHAIN = (0x3000 << KEYMASTER_REQ_SHIFT),
	KM_ATAP_GET_CA_REQUEST = (0x4000 << KEYMASTER_REQ_SHIFT),
	KM_ATAP_SET_CA_RESPONSE_BEGIN = (0x5000 << KEYMASTER_REQ_SHIFT),
	KM_ATAP_SET_CA_RESPONSE_UPDATE = (0x6000 << KEYMASTER_REQ_SHIFT),
	KM_ATAP_SET_CA_RESPONSE_FINISH = (0x7000 << KEYMASTER_REQ_SHIFT),
	KM_ATAP_READ_UUID = (0x8000 << KEYMASTER_REQ_SHIFT),
	KM_SET_PRODUCT_ID = (0x9000 << KEYMASTER_REQ_SHIFT),
	KM_CLEAR_ATTESTATION_CERT_CHAIN = (0xa000 << KEYMASTER_REQ_SHIFT),
	KM_SET_WRAPPED_ATTESTATION_KEY = (0xb000 << KEYMASTER_REQ_SHIFT),
	KM_SET_ATTESTATION_IDS = (0xc000 << KEYMASTER_REQ_SHIFT),
	KM_SET_ATTESTATION_IDS_KM3 = (0xc001 << KEYMASTER_REQ_SHIFT),
	KM_CONFIGURE_BOOT_PATCHLEVEL = (0xd000 << KEYMASTER_REQ_SHIFT),

/*
 * Please keep this constant consistent with KM_GET_AUTHTOKEN_KEY define that
 * is defined in Gatekeeper
 */
	KM_GET_AUTHTOKEN_KEY = 0x10000,

};

typedef enum{
	KM_NULL = 0,
	KM_POPULATED = 1,
} presence;

#endif /* KEYMASTER_COMMON_H */
