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


#ifndef ANDROID_OPTEE_KEYSTORE_TA_H
#define ANDROID_OPTEE_KEYSTORE_TA_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "operations.h"
#include "tables.h"
#include "parsel.h"
#include "master_crypto.h"
#include "paddings.h"
#include "parameters.h"
#include "generator.h"
#include "mbedtls_proxy.h"
#include "crypto_aes.h"
#include "crypto_des.h"
#include "crypto_rsa.h"
#include "crypto_ec.h"

/*
 * KeyMaster message size
 */
#define KM_RECV_BUF_SIZE 8192

/* Max size of attestation challenge */
#define MAX_ATTESTATION_CHALLENGE 128

/* Empty definitions */
#define EMPTY_CERT_CHAIN {.entries = NULL, .entry_count = 0}
#define EMPTY_BLOB {.data = NULL, .data_length = 0}
#define EMPTY_KEY_BLOB {.key_material = NULL, .key_material_size = 0}
#define EMPTY_PARAM_SET {.params = NULL, .length = 0}
#define EMPTY_CHARACTS {					\
			.hw_enforced = EMPTY_PARAM_SET,		\
			.sw_enforced = EMPTY_PARAM_SET}
#define EMPTY_ATTRS {					\
			.attrs = NULL,		\
			.attrs_count = 0,	\
			.size = 0,	\
			.type = 0, \
			.alg = 0}
#define EMPTY_OPERATION {					\
			.key = NULL,				\
			.nonce = EMPTY_BLOB,			\
			.op_handle = UNDEFINED,			\
			.purpose = UNDEFINED,			\
			.padding = UNDEFINED,			\
			.mode = UNDEFINED,			\
			.sf_item = NULL,			\
			.last_access = NULL,			\
			.operation = TEE_HANDLE_NULL,		\
			.digest_op = TEE_HANDLE_NULL,		\
			.prev_in_size = UNDEFINED,		\
			.min_sec = UNDEFINED,			\
			.mac_length = UNDEFINED,		\
			.a_data_length = 0,			\
			.a_data = NULL,				\
			.do_auth = false,			\
			.got_input = false,			\
			.buffering = false,			\
			.padded = false,			\
			.first = true,				\
			.last_block = EMPTY_BLOB}

typedef struct tee_km_rkp_hwinfo {
	uint32_t version;
	const char *rpc_author_name;
	uint32_t supported_eek_curve;
	const char *unique_id;
	uint32_t supported_num_keys_in_csr;
} tee_km_rkp_hwinfo_t;

#endif  /* ANDROID_OPTEE_KEYSTORE_TA_H */
