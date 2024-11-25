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


#ifndef ATTESTATION_H_
#define ATTESTATION_H_

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "mbedtls_proxy.h"
#include "ta_ca_defs.h"

#define EMPTY_BLOB {.data = NULL, .data_length = 0}

//#define ENUM_PERS_OBJS //only for testing
//#define WIPE_PERS_OBJS //only for testing

#define RSA_KEY_SIZE 1024U
#define EC_KEY_SIZE 256U

#define RSA_MAX_KEY_SIZE 4096U
#define EC_MAX_KEY_SIZE 521U

#define RSA_KEY_BUFFER_SIZE (RSA_KEY_SIZE / 8)
#define EC_KEY_BUFFER_SIZE (EC_KEY_SIZE / 8)

#define RSA_MAX_KEY_BUFFER_SIZE (RSA_MAX_KEY_SIZE / 8)
#define EC_MAX_KEY_BUFFER_SIZE (EC_MAX_KEY_SIZE / 8 + 1)

#define ROOT_CERT_BUFFER_SIZE 4096U
#define ATTEST_CERT_BUFFER_SIZE 4096U

#define UNIQUE_ID_BUFFER_SIZE 16U

#define ROOT_ATT_CERT_INDEX 1U
#define KEY_ATT_CERT_INDEX 0U
#define ATTESTATION_ID_LENGTH_MAX_SIZE 64

struct attestation_ids_state_t {
	bool att_prov;
	bool att_des;
};

struct attestation_ids_data_t {
	uint32_t brand_size;
	uint8_t brand[ATTESTATION_ID_LENGTH_MAX_SIZE];
	uint32_t device_size;
	uint8_t device[ATTESTATION_ID_LENGTH_MAX_SIZE];
	uint32_t product_size;
	uint8_t product[ATTESTATION_ID_LENGTH_MAX_SIZE];
	uint32_t serial_size;
	uint8_t serial[ATTESTATION_ID_LENGTH_MAX_SIZE];
	uint32_t imei_size;
	uint8_t imei[ATTESTATION_ID_LENGTH_MAX_SIZE];
	uint32_t meid_size;
	uint8_t meid[ATTESTATION_ID_LENGTH_MAX_SIZE];
	uint32_t manufacturer_size;
	uint8_t manufacturer[ATTESTATION_ID_LENGTH_MAX_SIZE];
	uint32_t model_size;
	uint8_t model[ATTESTATION_ID_LENGTH_MAX_SIZE];
	uint32_t second_imei_size;
	uint8_t second_imei[ATTESTATION_ID_LENGTH_MAX_SIZE];
};

typedef struct tee_attestation_ids_context {
	struct attestation_ids_state_t att_state;
	struct attestation_ids_data_t att_data;
}tee_att_ids_cxt_t;

#ifdef ENUM_PERS_OBJS
void TA_enum_attest_objs(void);
#endif

#ifdef WIPE_PERS_OBJS
void TA_wipe_attest_objs(void);
#endif

TEE_Result TA_init_attestation_ids_context(void);
TEE_Result TA_save_attestation_ids_info(void);
TEE_Result TA_destroy_attestation_ids_info(void);
TEE_Result TA_open_rsa_attest_key(TEE_ObjectHandle *rsaKey);
TEE_Result TA_open_ec_attest_key(TEE_ObjectHandle *ecKey);
TEE_Result TA_open_root_rsa_attest_cert(TEE_ObjectHandle *attCert);
TEE_Result TA_open_root_ec_attest_cert(TEE_ObjectHandle *attCert);

#ifdef CFG_ATTESTATION_PROVISIONING
TEE_Result TA_SetAttestationKey(TEE_Param params[TEE_NUM_PARAMS]);
TEE_Result TA_AppendAttestationCertKey(TEE_Param params[TEE_NUM_PARAMS]);
#endif

keymaster_error_t TA_read_root_attest_cert(uint32_t type,
		keymaster_cert_chain_t *cert_chain);
TEE_Result TA_gen_self_signed_cert(const keymaster_key_param_set_t *input_set,
				keymaster_algorithm_t alg,
				TEE_ObjectHandle root_key, keymaster_blob_t *root_cert,
				uint64_t not_before_val, uint64_t not_after_val);
TEE_Result TA_gen_fake_cert(const keymaster_key_param_set_t *input_set,
				keymaster_algorithm_t alg,
				TEE_ObjectHandle asymmetric_key, keymaster_blob_t *fake_cert,
				uint64_t not_before_val, uint64_t not_after_val);
TEE_Result TA_gen_key_attest_cert_with_rootkey(keymaster_algorithm_t root_alg,
				keymaster_algorithm_t alg,
				TEE_ObjectHandle root_key,
				const keymaster_key_param_set_t *root_params,
				TEE_ObjectHandle attested_key,
				keymaster_key_param_set_t *attest_params,
				keymaster_key_characteristics_t *key_chr,
				keymaster_cert_chain_t *cert_chain,
				bool includeUniqueID,
				keymaster_blob_t *cert_issuer,
				uint64_t not_before_val, uint64_t not_after_val);
TEE_Result TA_gen_key_attest_cert(uint32_t root_type, uint32_t type,
				TEE_ObjectHandle attestedKey,
				keymaster_key_param_set_t *attest_params,
				keymaster_key_characteristics_t *key_chr,
				keymaster_cert_chain_t *cert_chain,
				bool includeUniqueID);

TEE_Result TA_create_attest_objs(void);

void TA_close_attest_obj(TEE_ObjectHandle attObj);

TEE_Result TA_read_attest_cert(TEE_ObjectHandle attObj,
						keymaster_cert_chain_t *cert_chain);

TEE_Result TA_generate_UniqueID(uint64_t T, uint8_t *appID,uint32_t appIDlen,
		uint8_t R, uint8_t *uniqueID, uint32_t *uniqueIDlen);

#endif /* ATTESTATION_H_ */
