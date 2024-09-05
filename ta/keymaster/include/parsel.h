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


#ifndef ANDROID_OPTEE_PARSEL_H
#define ANDROID_OPTEE_PARSEL_H

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "common.h"
#include "ta_ca_defs.h"

#define MAX_OCTET_COUNT 10
#define ADDITIONAL_TAGS 8 /*
			   * Number of tags that can be added
			   * (KM_TAG_ORIGIN, KM_TAG_CREATION_DATETIME,
			   * KM_TAG_OS_VERSION, KM_TAG_OS_PATCHLEVEL,
			   * KM_TAG_KEY_SIZE, KM_TAG_RSA_PUBLIC_EXPONENT,
			   * KM_TAG_VENDOR_PATCHLEVEL, KM_TAG_BOOT_PATCHLEVEL)
			   */

bool TA_is_out_of_bounds(uint8_t *in, uint8_t *in_end, size_t size);

/* Serializers */
int TA_serialize_rsp_err(uint8_t *out, uint8_t *out_end,
			 const keymaster_error_t *error, bool *oob);

int TA_serialize_blob_akms(uint8_t *out, uint8_t *out_end,
			   const keymaster_blob_t *blob, bool *oob);

int TA_serialize_characteristics(uint8_t *out, uint8_t *out_end,
		const keymaster_key_characteristics_t *characteristics,
		bool *oob);

int TA_serialize_characteristics_akms(uint8_t *out, uint8_t *out_end,
		const keymaster_key_characteristics_t *characteristics,
		bool *oob);

int TA_serialize_key_blob_akms(uint8_t *out, uint8_t *out_end,
			       const keymaster_key_blob_t *key_blob,
			       bool *oob);

int TA_serialize_cert_chain_akms(uint8_t *out, uint8_t *out_end,
				 const keymaster_cert_chain_t *cert_chain,
				 keymaster_error_t *res, bool *oob);

int TA_serialize_auth_set(uint8_t *out, uint8_t *out_end,
			  const keymaster_key_param_set_t *param_set,
			  bool *oob);
int TA_serialize_param_set(uint8_t *out, uint8_t *out_end,
			   const keymaster_key_param_set_t *params, bool *oob);

TEE_Result TA_serialize_rsa_keypair(uint8_t *out, uint8_t *out_end,
				    uint32_t *out_size,
				    const TEE_ObjectHandle key_obj, bool *oob);

TEE_Result TA_serialize_ec_keypair(uint8_t *out, uint8_t *out_end,
				   uint32_t *out_size,
				   const TEE_ObjectHandle key_obj, bool *oob);

/* Deserializers */
int TA_deserialize_blob_akms(uint8_t *in, uint8_t *end, keymaster_blob_t *blob,
			     const bool check_presence, keymaster_error_t *res,
			     bool is_input);

int TA_deserialize_auth_set(uint8_t *in, uint8_t *end,
			    keymaster_key_param_set_t *param_set,
			    const bool check_presence, keymaster_error_t *res);

int TA_deserialize_param_set(uint8_t *in, uint8_t *end,
			     keymaster_key_param_set_t *params,
			     const bool check_presence,
			     keymaster_error_t *res);

int TA_deserialize_key_blob_akms(uint8_t *in, uint8_t *end,
				 keymaster_key_blob_t *key_blob,
				 keymaster_error_t *res);

int TA_deserialize_op_handle(uint8_t *in, uint8_t *in_end,
			     keymaster_operation_handle_t *op_handle,
			     keymaster_error_t *res);

int TA_deserialize_purpose(uint8_t *in, uint8_t *in_end,
			   keymaster_purpose_t *purpose,
			   keymaster_error_t *res);

int TA_deserialize_key_format(uint8_t *in, uint8_t *in_end,
			      keymaster_key_format_t *key_format,
			      keymaster_error_t *res);
#endif/* ANDROID_OPTEE_PARSEL_H */
