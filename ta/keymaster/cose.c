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

#include <cose.h>
#include "hmac.h"
#include <mbedtls/pk.h>
#include <mbedtls/ecdsa.h>

static keymaster_error_t TA_generate_cose_mac0mac(uint8_t *external_aad,
						  size_t external_aad_size,
						  uint8_t *payload,
						  size_t payload_size,
						  uint8_t *mac_tag,
						  size_t mac_tag_size)
{
	keymaster_error_t error = KM_ERROR_OK;
	cbor_item_t *mac_structure = NULL;
	uint8_t *data = NULL;
	size_t data_size = 0;
	cbor_item_t *cose_hmac_parameter_map = NULL;
	uint8_t *cose_hmac_parameter = NULL;
	size_t cose_hmac_parameter_size = 0;
	TEE_Result res = TEE_SUCCESS;
	bool result = false;

	DMSG("%s %d", __func__, __LINE__);

	mac_structure = cbor_new_definite_array(4);
	if (!mac_structure) {
		EMSG("Failed to allocate memory for mac_structure");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}
	result = cbor_array_push(mac_structure, cbor_move(cbor_build_string("MAC0")));
	if (!result) {
		EMSG("Add HMAC SHA2-256 parameters to mac structure failed, result=%x", result);
		error = KM_ERROR_UNKNOWN_ERROR;
		goto exit;
	}

	cose_hmac_parameter_map = cbor_new_definite_map(1);
	if (!cose_hmac_parameter_map) {
		MSG("Failed to allocate memory for cose_hmac_parameter_map");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}
	result = cbor_map_add(cose_hmac_parameter_map,
			      (struct cbor_pair) {.key = cbor_move(cbor_build_uint8(LABEL_ALGORITHM)),
						  .value = cbor_move(cbor_build_uint8(HMAC_256))});
	if (!result) {
		EMSG("Add HMAC SHA2-256 parameter to cbor hmac parameter map failed, result=%x", result);
		error = KM_ERROR_UNKNOWN_ERROR;
		goto exit;
	}
	cbor_serialize_alloc(cose_hmac_parameter_map, &cose_hmac_parameter, &cose_hmac_parameter_size);
	
	result = cbor_array_push(mac_structure,
				 cbor_move(cbor_build_bytestring(cose_hmac_parameter, cose_hmac_parameter_size)));
	if (external_aad) {
		result &= cbor_array_push(mac_structure,
					  cbor_move(cbor_build_bytestring(external_aad, external_aad_size)));

	} else {
		/*Load an empty byte string */
		result &= cbor_array_push(mac_structure,
					  cbor_move(cbor_new_definite_bytestring()));
	}

	if (payload) {
		result &= cbor_array_push(mac_structure,
					  cbor_move(cbor_build_bytestring(payload, payload_size)));
	}
	if (!result) {
		EMSG("Add HMAC SHA2-256 parameters to mac structure failed, result=%x", result);
		error = KM_ERROR_UNKNOWN_ERROR;
		goto exit;
	}

	cbor_serialize_alloc(mac_structure, &data, &data_size);
	if (mac_tag) {
		res = TA_hmac_execute(data, data_size, mac_tag, mac_tag_size);
		if (res != TEE_SUCCESS) {
			error = KM_ERROR_UNKNOWN_ERROR;
			goto exit;
		}
	}

exit:
	if (cose_hmac_parameter)
		free(cose_hmac_parameter);
	if (cose_hmac_parameter_map)
		cbor_decref(&cose_hmac_parameter_map);
	if (data)
		free(data);
	if (mac_structure)
		cbor_decref(&mac_structure);
	return error;
}

keymaster_error_t TA_construct_cose_mac0(uint8_t *external_aad,
	       				 size_t external_aad_size,
					 uint8_t *payload,
					 size_t payload_size,
					 uint8_t **maced_key,
					 size_t *maced_key_size)
{
	keymaster_error_t error = KM_ERROR_OK;
	uint8_t *tag = NULL;
	size_t tag_size = SHA256_DIGEST_LENGTH;
	cbor_item_t *maced_key_item = NULL;
	uint8_t *maced_key_data = NULL;
	size_t maced_key_data_size = 0;
	cbor_item_t *cose_hmac_parameter_map = NULL;
	uint8_t *cose_hmac_parameter = NULL;
	size_t cose_hmac_parameter_size = 0;
	bool result = false;
	size_t serialize_size = 0;

	DMSG("%s %d", __func__, __LINE__);


	tag = TEE_Malloc(SHA256_DIGEST_LENGTH, TEE_MALLOC_FILL_ZERO);
	if (!tag) {
		EMSG("Failed to allocate memory for tag");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}

	error = TA_generate_cose_mac0mac(external_aad,
					 external_aad_size,
				 	 payload,
					 payload_size,
					 tag,
					 tag_size);
	if (error != KM_ERROR_OK) {
		EMSG("Generate cose mac0mac failed");
		goto exit;
	}

	maced_key_item = cbor_new_definite_array(4);
	if (!maced_key_item) {
		EMSG("Failed to allocate memory for maced key");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}
	
	cose_hmac_parameter_map = cbor_new_definite_map(1);
	if (!cose_hmac_parameter_map) {
		EMSG("Failed to allocate memory for cose_hmac_parameter_map");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}
	result = cbor_map_add(cose_hmac_parameter_map,
			      (struct cbor_pair) {.key = cbor_move(cbor_build_uint8(LABEL_ALGORITHM)),
						  .value = cbor_move(cbor_build_uint8(HMAC_256))});
	if (!result) {
		EMSG("Add HMAC SHA2-256 parameter to cose hmac parameter map failed, result=%x", result);
		error = KM_ERROR_UNKNOWN_ERROR;
		goto exit;
	}
	cbor_serialize_alloc(cose_hmac_parameter_map, &cose_hmac_parameter, &cose_hmac_parameter_size);
	
	result = cbor_array_push(maced_key_item,
				 cbor_move(cbor_build_bytestring(cose_hmac_parameter, cose_hmac_parameter_size)));
	result &= cbor_array_push(maced_key_item, cbor_move(cbor_new_definite_map(0)));
	result &= cbor_array_push(maced_key_item,
				  cbor_move(cbor_build_bytestring(payload, payload_size)));
	result &= cbor_array_push(maced_key_item,
				  cbor_move(cbor_build_bytestring(tag, tag_size)));
	if (!result) {
		EMSG("Add HMAC SHA2-256 parameters to maced key array failed, result=%x", result);
		error = KM_ERROR_UNKNOWN_ERROR;
		goto exit;
	}
        serialize_size = cbor_serialize_alloc(maced_key_item, &maced_key_data, &maced_key_data_size);
	if (serialize_size > 0) {
		*maced_key = TEE_Malloc(maced_key_data_size, TEE_MALLOC_FILL_ZERO);
		if (!*maced_key) {
			EMSG("Failed to allocate memory for maced key");
			goto exit;
		}
		TEE_MemMove(*maced_key, maced_key_data, maced_key_data_size);
		*maced_key_size = maced_key_data_size;
	}

exit:
	if (tag)
		TEE_Free(tag);

	if (cose_hmac_parameter)
		free(cose_hmac_parameter);
	if (cose_hmac_parameter_map)
		cbor_decref(&cose_hmac_parameter_map);
	if (maced_key_data) 
		free(maced_key_data);
	if (maced_key_item)
		cbor_decref(&maced_key_item);

	return error;
}

keymaster_error_t TA_validate_and_extract_pubkeys(bool testMode,
						  uint32_t num_keys,
						  keymaster_blob_t *keys_to_sign,
						  cbor_item_t **pubkeys_array)
{
	keymaster_error_t error = KM_ERROR_OK;
	cbor_item_t *pubkeys_to_mac = NULL;
	cbor_item_t *maced_key_item = NULL;
	cbor_item_t *protected_parms = NULL;
	cbor_item_t *unprotected_parms = NULL;
	cbor_item_t *payload = NULL;
	cbor_item_t *tag = NULL;
	struct cbor_load_result maced_key_load_result = { 0 };
	cbor_item_t *cose_hmac_parameter_map = NULL;
	uint8_t *cose_hmac_parameter = NULL;
	size_t cose_hmac_parameter_size = 0;
	struct cbor_load_result cose_hmac_parameter_load_result = { 0 };
	struct cbor_pair *cose_hmac_parameter_pair = NULL;
	cosekey_algorithm_t algorithm;
	cbor_item_t *cose_public_key_map = NULL;
	struct cbor_load_result cose_public_key_load_result = { 0 };
	uint8_t digest[SHA256_DIGEST_LENGTH] = { 0 };
	size_t digest_size = SHA256_DIGEST_LENGTH;
	bool result = false;

	DMSG("%s %d", __func__, __LINE__);

	pubkeys_to_mac = cbor_new_definite_array(num_keys);
	if (!pubkeys_to_mac) {
		EMSG("Failed to allocate memory for pubkeys mac");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}
	for (size_t i = 0; i < num_keys; i++) {
		maced_key_item = cbor_load(keys_to_sign[i].data,
					   keys_to_sign[i].data_length,
					   &maced_key_load_result);
		if (!maced_key_item) {
			EMSG("Failed to parse maced key item");
			error = KM_ERROR_UNKNOWN_ERROR;
			goto exit;
		}

		protected_parms = cbor_array_get(maced_key_item, KCOSE_MAC0_PROTECTED_PARAMS);
		unprotected_parms = cbor_array_get(maced_key_item, KCOSE_MAC0_UNPROTECTED_PARAMS);
		payload = cbor_array_get(maced_key_item, KCOSE_MAC0_PAYLOAD);
		tag = cbor_array_get(maced_key_item, KCOSE_MAC0_TAG);
		if (!protected_parms || !unprotected_parms || !payload || !tag) {
			EMSG("Invalid COSE_Mac0 contents");
			error = KM_ERROR_UNKNOWN_ERROR;
			goto exit;
		}

		cose_hmac_parameter = cbor_bytestring_handle(protected_parms);
		cose_hmac_parameter_size = cbor_bytestring_length(protected_parms);
		if (!cose_hmac_parameter || cose_hmac_parameter_size == 0) {
			EMSG("Cose hmac parameter is null");
			error = KM_ERROR_UNKNOWN_ERROR;
			goto exit;
		}

		cose_hmac_parameter_map = cbor_load(cose_hmac_parameter,
						    cose_hmac_parameter_size,
						    &cose_hmac_parameter_load_result);
		if (!cose_hmac_parameter_map) {
			EMSG("Failed to parse cose hmac parameter map");
			error = KM_ERROR_UNKNOWN_ERROR;
			goto exit;
		}

		cose_hmac_parameter_pair = cbor_map_handle(cose_hmac_parameter_map);
		if (cose_hmac_parameter_pair->key == NULL || cose_hmac_parameter_pair->value == NULL) {
			EMSG("Cose hmac parameter pair is null");
			error = KM_ERROR_UNKNOWN_ERROR;
			goto exit;
		}

		algorithm = cbor_get_uint8((cbor_item_t *)cose_hmac_parameter_pair->value);
		if (algorithm != HMAC_256) {
			EMSG("Unsupported Mac0 algorithm");
			error = KM_ERROR_UNKNOWN_ERROR;
			goto exit;
		}

		cose_public_key_map = cbor_load(cbor_bytestring_handle(payload),
						cbor_bytestring_length(payload),
						&cose_public_key_load_result);
		if (!cose_public_key_map) {
			EMSG("Failed to parse cose public key map");
			error = KM_ERROR_UNKNOWN_ERROR;
			goto exit;
		}

		(void)testMode;

		error = TA_generate_cose_mac0mac(NULL,
						 0,
						 cbor_bytestring_handle(payload),
						 cbor_bytestring_length(payload),
						 digest,
						 digest_size);
		if (error != KM_ERROR_OK) {
			EMSG("Generate cose mac0mac failed");
			goto exit;
		}
		if (TEE_MemCompare(cbor_bytestring_handle(tag), digest, digest_size) != 0) {
			EMSG("MAC tag mismatch");
			error = K_STATUS_INVALID_MAC;
			goto exit;
		}

		result = cbor_array_push(pubkeys_to_mac, cbor_move(cose_public_key_map));
		if (!result) {
			EMSG("Add pubilic_key_map to pubkeys_to_mac array failed, result=%x", result);
			error = KM_ERROR_UNKNOWN_ERROR;
			goto exit;
		}
	}

	*pubkeys_array = pubkeys_to_mac;
exit:
	if (cose_hmac_parameter_map)
		cbor_decref(&cose_hmac_parameter_map);
	if (maced_key_item)
		cbor_decref(&maced_key_item);

	return error;
}

static keymaster_error_t TA_create_device_info(tee_km_context_t *optee_km_context,
					       uint32_t csr_version,
					       cbor_item_t **device_info_map)
{
	keymaster_error_t error = KM_ERROR_OK;
	const char *vb_state_str = NULL;
	char os_version_str[6] = { 0 };
	cbor_item_t *device_info = NULL;
	bool result = true;

	DMSG("%s %d", __func__, __LINE__);

	device_info = cbor_new_definite_map(14);
	if (!device_info) {
		EMSG("Failed to allocate memory for result map");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		*device_info_map = NULL;
	return error;
	}

	result = cbor_map_add(device_info,
			      (struct cbor_pair) {.key = cbor_move(cbor_build_string("brand")),
						  .value = cbor_move(cbor_build_string("Intel"))});
	result &= cbor_map_add(device_info,
			       (struct cbor_pair) {.key = cbor_move(cbor_build_string("fused")),
						   .value = cbor_move(cbor_build_uint8(0))});
	result &= cbor_map_add(device_info,
			       (struct cbor_pair) {.key = cbor_move(cbor_build_string("model")),
						   .value = cbor_move(cbor_build_string("Fake Model"))});
	result &= cbor_map_add(device_info,
			       (struct cbor_pair) {.key = cbor_move(cbor_build_string("device")),
						   .value = cbor_move(cbor_build_string("Fake Device"))});
	result &= cbor_map_add(device_info,
			       (struct cbor_pair) {.key = cbor_move(cbor_build_string("product")),
						   .value = cbor_move(cbor_build_string("Fake Product"))});

	switch(optee_km_context->rot.rot_data.verifiedBootState) {
	case KM_VERIFIED_BOOT_VERIFIED:
		vb_state_str = "green";
		break;
		case KM_VERIFIED_BOOT_SELF_SIGNED:
		vb_state_str = "yellow";
		break;
	case KM_VERIFIED_BOOT_UNVERIFIED:
		vb_state_str = "orange";
		break;
	default:
		break;
	}

	result &= cbor_map_add(device_info,
			       (struct cbor_pair) {.key = cbor_move(cbor_build_string("vb_state")),
						   .value = cbor_move(cbor_build_string(vb_state_str))});
	memset(os_version_str, 0, 6);
	snprintf((char *)os_version_str, 6, "%06u", optee_km_context->rot.rot_data.osVersion);

	result &= cbor_map_add(device_info,
			       (struct cbor_pair) {.key = cbor_move(cbor_build_string("os_version")),
						   .value = cbor_move(cbor_build_string(os_version_str))});
	result &= cbor_map_add(device_info,
			       (struct cbor_pair) {.key = cbor_move(cbor_build_string("manufacturer")),
						   .value = cbor_move(cbor_build_string("Intel"))});
	result &= cbor_map_add(device_info,
			       (struct cbor_pair) {.key = cbor_move(cbor_build_string("vbmeta_digest")),
						   .value = cbor_move(cbor_build_bytestring(optee_km_context->rot.rot_data.vbmetaDigest, optee_km_context->rot.rot_data.digestSize))});
	result &= cbor_map_add(device_info,
			       (struct cbor_pair) {.key = cbor_move(cbor_build_string("security_level")),
						   .value = cbor_move(cbor_build_string("tee"))});
	result &= cbor_map_add(device_info,
			       (struct cbor_pair) {.key = cbor_move(cbor_build_string("boot_patch_level")),
						   .value = cbor_move(cbor_build_uint32(optee_km_context->boot_patchlevel))});
	result &= cbor_map_add(device_info,
			       (struct cbor_pair) {.key = cbor_move(cbor_build_string("bootloader_state")),
						   .value = cbor_move(cbor_build_string(optee_km_context->rot.rot_data.deviceLocked ? "locked" : "unlocked"))});
	result &= cbor_map_add(device_info,
			       (struct cbor_pair) {.key = cbor_move(cbor_build_string("system_patch_level")),
						   .value = cbor_move(cbor_build_uint32(optee_km_context->os_patchlevel))});
	result &= cbor_map_add(device_info,
			       (struct cbor_pair) {.key = cbor_move(cbor_build_string("vendor_patch_level")),
						   .value = cbor_move(cbor_build_uint32(optee_km_context->vendor_patchlevel))});
	if (csr_version < 3) {
		result &= cbor_map_add(device_info,
				       (struct cbor_pair) {.key = cbor_move(cbor_build_string("version")),
							   .value = cbor_move(cbor_build_uint8(csr_version))});
	}

	if (!result) {
		EMSG("Failed to push items to device info map");
		error = KM_ERROR_UNKNOWN_ERROR;
		cbor_decref(&device_info);
		*device_info_map = NULL;
		return error;
	}

	*device_info_map = device_info;
	return error;
}

static keymaster_error_t TA_sign_data(tee_dice_context_t *optee_dice_context,
				      mbedtls_pk_context *context,
				      uint8_t *data,
			              size_t data_size,
				      cbor_item_t **cose_sign1)
{
	keymaster_error_t error = KM_ERROR_OK;
	cbor_item_t *signed_data_sig_struct = NULL;
	uint8_t *signed_data_sig_struct_data = NULL;
	size_t signed_data_sig_struct_size = 0;
	size_t serialize_size = 0;
	bool result = false;
	cbor_item_t *cose_algorithm_parameter = NULL;
	uint8_t *cose_algorithm_parameter_data = NULL;
	size_t cose_algorithm_parameter_size = 0;
	cbor_item_t *cose_signed_data = NULL;
	uint8_t *signature = NULL;
	size_t signature_buffer_length = 0;
	size_t actual_signature_length = 0;

	DMSG("%s %d", __func__, __LINE__);

	if (context == NULL || data == NULL) {
		return KM_ERROR_UNEXPECTED_NULL_POINTER;
	}

	error = mbedTLS_gen_ecdsa_p256_key_pair(context,
						optee_dice_context->attest_cdi,
						DICE_CDI_SIZE);
	if (error != KM_ERROR_OK) {
		EMSG("Generate ECDSA P256 keypair failed");
		goto exit;
	}

	signed_data_sig_struct = cbor_new_definite_array(4);
	if (!signed_data_sig_struct) {
		EMSG("Failed to allocate memory for signed_data_sig_struct");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}
	result = cbor_array_push(signed_data_sig_struct, cbor_move(cbor_build_string("Signature1")));

	cose_algorithm_parameter = cbor_new_definite_map(1);
	if (!cose_algorithm_parameter) {
		MSG("Failed to allocate memory for cose_algorithm_parameter");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}
	cbor_map_add(cose_algorithm_parameter,
		     (struct cbor_pair) {.key = cbor_move(cbor_build_uint8(LABEL_ALGORITHM)),
					 .value = cbor_move(cbor_build_negint8(abs(ES256) - 1))});
	serialize_size = cbor_serialize_alloc(cose_algorithm_parameter, &cose_algorithm_parameter_data, &cose_algorithm_parameter_size);
	result &= cbor_array_push(signed_data_sig_struct, 
				  cbor_move(cbor_build_bytestring(cose_algorithm_parameter_data, cose_algorithm_parameter_size)));
	result &= cbor_array_push(signed_data_sig_struct, cbor_move(cbor_new_definite_bytestring()));
	result &= cbor_array_push(signed_data_sig_struct,
				  cbor_move(cbor_build_bytestring(data, data_size)));

	if (!result) {
		EMSG("Add signed data parameters to cbor array failed, result=%x", result);
		error = KM_ERROR_UNKNOWN_ERROR;
		goto exit;
	}
	serialize_size = cbor_serialize_alloc(signed_data_sig_struct, &signed_data_sig_struct_data, &signed_data_sig_struct_size);

	cose_signed_data = cbor_new_definite_array(4);
	if (!cose_signed_data) {
		EMSG("Failed to allocate memory for cose_signed_data");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}
	result = cbor_array_push(cose_signed_data,
				 cbor_move(cbor_build_bytestring(cose_algorithm_parameter_data, cose_algorithm_parameter_size)));
	result &= cbor_array_push(cose_signed_data,
				  cbor_move(cbor_new_definite_map(0)));
	result &= cbor_array_push(cose_signed_data, cbor_move(cbor_build_bytestring(data, data_size)));

	signature_buffer_length = MBEDTLS_ECDSA_MAX_LEN;
	signature = TEE_Malloc(signature_buffer_length, TEE_MALLOC_FILL_ZERO);
	if (!signature) {
		EMSG("Failed to allocate memory for signature");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}

	error = mbedTLS_sign_data_with_ecdsa_p256(context,
						  signed_data_sig_struct_data,
						  signed_data_sig_struct_size,
						  signature,
						  signature_buffer_length,
						  &actual_signature_length);
	if (error != KM_ERROR_OK) {
		EMSG("Sign data with ECDSA P256 keypair failed");
		goto exit;
	}

	DMSG("actual_signature_length %ld", actual_signature_length);
	result &= cbor_array_push(cose_signed_data,
				  cbor_move(cbor_build_bytestring(signature, actual_signature_length)));

	if (!result) {
		EMSG("Add signed data parameters to cose_sign1 array failed, result=%x", result);
		error = KM_ERROR_UNKNOWN_ERROR;
		goto exit;
	}

	*cose_sign1 = cose_signed_data;
exit:
	if (cose_algorithm_parameter_data)
		free(cose_algorithm_parameter_data);
	if (cose_algorithm_parameter)
		 cbor_decref(&cose_algorithm_parameter);

	if (signed_data_sig_struct_data)
		free(signed_data_sig_struct_data);
	if (signed_data_sig_struct)
		cbor_decref(&signed_data_sig_struct);

	if (signature)
		TEE_Free(signature);

	return error;
}

static keymaster_error_t TA_generate_certificate(tee_dice_context_t *optee_dice_context,
						 mbedtls_pk_context *subject_key_context,
						 mbedtls_pk_context *authority_key_context,
						 cbor_item_t **bcc)
{
	keymaster_error_t error = KM_ERROR_OK;
	uint8_t *x_coordinate = NULL;
	uint8_t *y_coordinate = NULL;
	cbor_item_t *cose_public_key_map = NULL;
	uint8_t *cose_public_key = NULL;
	size_t cose_public_key_size = 0;
	uint8_t *signature = NULL;
	size_t signature_buffer_length = 0;
	size_t actual_signature_length = 0;
	size_t serialize_size = 0;
	bool result = false;
	cbor_item_t *dice_chain_entry_payload = NULL;
	uint8_t *dice_chain_entry_payload_data = NULL;
	size_t dice_chain_entry_payload_size = 0;
	uint8_t key_usage[1] = { 0x20 };
	cbor_item_t *cose_algorithm_parameter = NULL;
	uint8_t *cose_algorithm_parameter_data = NULL;
	size_t cose_algorithm_parameter_size = 0;
	cbor_item_t *dice_chain_entry_input = NULL;
	uint8_t *dice_chain_entry_input_data = NULL;
	size_t dice_chain_entry_input_size = 0;
	cbor_item_t *dice_chain_entry = NULL;
	uint8_t *signed_data = NULL;
	size_t signed_data_length = 0;
	cbor_item_t *dice_cert_chain = NULL;

	DMSG("%s %d", __func__, __LINE__);

	if (optee_dice_context == NULL || subject_key_context == NULL || authority_key_context == NULL) {
		return KM_ERROR_UNEXPECTED_NULL_POINTER;
	}

	x_coordinate = TEE_Malloc(K_P256_AFFINE_POINT_SIZE, TEE_MALLOC_FILL_ZERO);
	y_coordinate = TEE_Malloc(K_P256_AFFINE_POINT_SIZE, TEE_MALLOC_FILL_ZERO);
	signature_buffer_length = MBEDTLS_ECDSA_MAX_LEN;
	signature = TEE_Malloc(signature_buffer_length, TEE_MALLOC_FILL_ZERO);
	if (!x_coordinate || !y_coordinate || !signature) {
		EMSG("Failed to allocate memory for x_coordinate, y_coordinate or signature");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		return error;
	}

	error = mbedTLS_gen_ecdsa_p256_key_pair(subject_key_context,
						optee_dice_context->attest_cdi,
						DICE_CDI_SIZE);
	if (error != KM_ERROR_OK) {
		EMSG("Generate ECDSA P256 keypair failed");
		goto exit;
	}

	error = mbedTLS_export_ecdsa_p256_public_key(subject_key_context,
						     x_coordinate,
						     K_P256_AFFINE_POINT_SIZE,
						     y_coordinate,
						     K_P256_AFFINE_POINT_SIZE);
	if (error != KM_ERROR_OK) {
		EMSG("Export ECDSA P256 public key failed");
		goto exit;
	}

	cose_public_key_map = cbor_new_definite_map(5);
	if (!cose_public_key_map) {
		EMSG("Failed to allocate memory for cose_public_key_map");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}
	result = cbor_map_add(cose_public_key_map,
			      (struct cbor_pair) {.key = cbor_move(cbor_build_uint8(KEY_TYPE)),
						  .value = cbor_move(cbor_build_uint8(EC2))});
	result &= cbor_map_add(cose_public_key_map,
			       (struct cbor_pair) {.key = cbor_move(cbor_build_uint8(ALGORITHM)),
						   .value = cbor_move(cbor_build_negint8(abs(ES256) - 1))});
	result &= cbor_map_add(cose_public_key_map,
			       (struct cbor_pair) {.key = cbor_move(cbor_build_negint8(abs(CURVE) - 1)),
						   .value = cbor_move(cbor_build_uint8(P256))});
	result &= cbor_map_add(cose_public_key_map,
			       (struct cbor_pair) {.key = cbor_move(cbor_build_negint8(abs(PUBKEY_X) - 1)),
						   .value = cbor_move(cbor_build_bytestring(x_coordinate, K_P256_AFFINE_POINT_SIZE))});
	result &= cbor_map_add(cose_public_key_map,
			       (struct cbor_pair) {.key = cbor_move(cbor_build_negint8(abs(PUBKEY_Y) - 1)),
						   .value = cbor_move(cbor_build_bytestring(y_coordinate, K_P256_AFFINE_POINT_SIZE))});
	if (!result) {
		EMSG("Add ECDSA P256 parameters to cbor map failed, result=%x", result);
		error = KM_ERROR_UNKNOWN_ERROR;
	goto exit;
	}

	serialize_size = cbor_serialize_alloc(cose_public_key_map, &cose_public_key, &cose_public_key_size);

	dice_chain_entry_payload = cbor_new_definite_map(4);
	if (!dice_chain_entry_payload) {
		EMSG("Failed to allocate memory for dice_chain_entry_payload");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}
	result = cbor_map_add(dice_chain_entry_payload,
			      (struct cbor_pair) {.key = cbor_move(cbor_build_uint8(1)),
						  .value = cbor_move(cbor_build_string("Issue"))});
	result &= cbor_map_add(dice_chain_entry_payload,
			      (struct cbor_pair) {.key = cbor_move(cbor_build_uint8(2)),
			      			  .value = cbor_move(cbor_build_string("Subject"))});
	result &= cbor_map_add(dice_chain_entry_payload,
			      (struct cbor_pair) {.key = cbor_move(cbor_build_negint32(abs(-4670552) - 1)),
			      			  .value = cbor_move(cbor_build_bytestring(cose_public_key, cose_public_key_size))});
	result &= cbor_map_add(dice_chain_entry_payload,
			      (struct cbor_pair) {.key = cbor_move(cbor_build_negint32(abs(-4670553) - 1)),
			      			  .value = cbor_move(cbor_build_bytestring(key_usage, 1))});

	if (!result) {
		EMSG("Build dice chain entry payload cbor map failed, result=%x", result);
		error = KM_ERROR_UNKNOWN_ERROR;
		goto exit;
	}

	serialize_size = cbor_serialize_alloc(dice_chain_entry_payload,
					      &dice_chain_entry_payload_data,
					      &dice_chain_entry_payload_size);

	dice_chain_entry_input = cbor_new_definite_array(4);
	if (!dice_chain_entry_input) {
		EMSG("Failed to allocate memory for dice_chain_entry_input");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}
	result = cbor_array_push(dice_chain_entry_input, cbor_move(cbor_build_string("Signature1")));

	cose_algorithm_parameter = cbor_new_definite_map(1);
	if (!cose_algorithm_parameter) {
		MSG("Failed to allocate memory for cose_algorithm_parameter");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}
	cbor_map_add(cose_algorithm_parameter,
		     (struct cbor_pair) {.key = cbor_move(cbor_build_uint8(LABEL_ALGORITHM)),
					 .value = cbor_move(cbor_build_negint8(abs(ES256) - 1))});
	serialize_size = cbor_serialize_alloc(cose_algorithm_parameter, &cose_algorithm_parameter_data, &cose_algorithm_parameter_size);
	
	result &= cbor_array_push(dice_chain_entry_input,
				  cbor_move(cbor_build_bytestring(cose_algorithm_parameter_data, cose_algorithm_parameter_size)));
	/*Load an empty byte string */
	result &= cbor_array_push(dice_chain_entry_input,
				  cbor_move(cbor_new_definite_bytestring()));
	result &= cbor_array_push(dice_chain_entry_input,
				  cbor_move(cbor_build_bytestring(dice_chain_entry_payload_data, dice_chain_entry_payload_size)));

	if (!result) {
		EMSG("Build dice chain entry input cbor array failed, result=%x", result);
		error = KM_ERROR_UNKNOWN_ERROR;
		goto exit;
	}
	serialize_size = cbor_serialize_alloc(dice_chain_entry_input,
					      &dice_chain_entry_input_data,
					      &dice_chain_entry_input_size);

	dice_chain_entry = cbor_new_definite_array(4);
	if (!dice_chain_entry) {
		EMSG("Failed to allocate memory for dice_chain_entry");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}
	result = cbor_array_push(dice_chain_entry,
				 cbor_move(cbor_build_bytestring(cose_algorithm_parameter_data, cose_algorithm_parameter_size)));
	result &= cbor_array_push(dice_chain_entry, cbor_move(cbor_new_definite_map(0)));
	result &= cbor_array_push(dice_chain_entry,
				  cbor_move(cbor_build_bytestring(dice_chain_entry_payload_data, dice_chain_entry_payload_size)));


	signed_data = TEE_Malloc(dice_chain_entry_input_size, TEE_MALLOC_FILL_ZERO);
	if (!signed_data) {
		EMSG("Failed to allocate memory for signed_data");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}
	signed_data_length = dice_chain_entry_input_size;
	TEE_MemMove(signed_data, dice_chain_entry_input_data, signed_data_length);

	error = mbedTLS_sign_data_with_ecdsa_p256(authority_key_context,
						  signed_data,
						  signed_data_length,
						  signature,
						  signature_buffer_length,
						  &actual_signature_length);
	if (error != KM_ERROR_OK) {
		EMSG("Sign data with ECDSA P256 keypair failed");
		goto exit;
	}

	DMSG("actual_signature_length %ld", actual_signature_length);
	result &= cbor_array_push(dice_chain_entry,
				  cbor_move(cbor_build_bytestring(signature, actual_signature_length)));
	if (!result) {
		EMSG("Build dice chain entry cbor array failed, result=%x", result);
		error = KM_ERROR_UNKNOWN_ERROR;
		goto exit;
	}

	dice_cert_chain = cbor_new_definite_array(2);	
	if (!dice_cert_chain) {
		EMSG("Failed to allocate memory for dice_cert_chain");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}
	result = cbor_array_push(dice_cert_chain, cbor_move(cose_public_key_map));
	result &= cbor_array_push(dice_cert_chain, cbor_move(dice_chain_entry));
	if (!result) {
		EMSG("Build dice cert chain cbor array failed, result=%x", result);
		error = KM_ERROR_UNKNOWN_ERROR;
		goto exit;
	}
	*bcc = dice_cert_chain;
exit:
	if (x_coordinate)
		TEE_Free(x_coordinate);
	if (y_coordinate)
		TEE_Free(y_coordinate);

	if (signature)
		TEE_Free(signature);

	if (cose_public_key)
		free(cose_public_key);

	if (dice_chain_entry_payload_data)
		free(dice_chain_entry_payload_data);
	if (dice_chain_entry_payload)
		cbor_decref(&dice_chain_entry_payload);

	if (cose_algorithm_parameter_data)
		free(cose_algorithm_parameter_data);
	if (cose_algorithm_parameter)
		 cbor_decref(&cose_algorithm_parameter);

	if (dice_chain_entry_input_data)
		free(dice_chain_entry_input_data);
	if (dice_chain_entry_input)
		cbor_decref(&dice_chain_entry_input);

	if (signed_data)
		TEE_Free(signed_data);

	return error;
}

static keymaster_error_t TA_get_protected_data(tee_dice_context_t *optee_dice_context,
					       uint8_t *data,
					       size_t data_size,
					       cbor_item_t **cose_sign1,
					       cbor_item_t **bcc)
{
	keymaster_error_t error = KM_ERROR_OK;
	mbedtls_pk_context key_context;
	cbor_item_t *dice_cert_chain = NULL;
	struct cbor_load_result load_result = { 0 };

	DMSG("%s %d", __func__, __LINE__);

	DMSG("cdi_certificate_actual_size %ld", optee_dice_context->cdi_certificate_actual_size);

	dice_cert_chain = cbor_load(optee_dice_context->cdi_certificate,
				    optee_dice_context->cdi_certificate_actual_size,
				    &load_result);
        if (!dice_cert_chain) {
		EMSG("Failed to parse DICE certificate chain");
		error = KM_ERROR_UNKNOWN_ERROR;
		return error;
	}
	*bcc = dice_cert_chain;

	mbedtls_pk_init(&key_context);
	error = TA_sign_data(optee_dice_context, &key_context, data, data_size, cose_sign1);
	if (error != KM_ERROR_OK) {
		EMSG("Failed to sign data");
		goto exit;
	}

exit:
	mbedtls_pk_free(&key_context);
	return error;
}

keymaster_error_t TA_build_csr(tee_km_context_t *optee_km_context,
			       tee_dice_context_t *optee_dice_context,
			       keymaster_blob_t *challenge,
			       cbor_item_t *keys_to_sign,
			       uint8_t **csr_blob_data,
			       size_t *csr_blob_data_length)
{
	keymaster_error_t error = KM_ERROR_OK;
	uint32_t csr_version = 3;
	cbor_item_t *device_info = NULL;
	cbor_item_t *csr_payload = NULL;
	uint8_t *csr_payload_data = NULL;
	size_t csr_payload_data_size = 0;
	cbor_item_t *signed_data_payload = NULL;
	uint8_t *signed_data_payload_serialize = NULL;
	size_t signed_data_payload_serialize_size = 0;
	cbor_item_t *signed_data = NULL;
	cbor_item_t *dice_cert_chain = NULL;
	cbor_item_t *csr = NULL;
	uint8_t *csr_serialize = NULL;
	size_t csr_serialize_size = 0;
	bool result = false;

	DMSG("%s %d", __func__, __LINE__);

	error = TA_create_device_info(optee_km_context, csr_version, &device_info);
	if (error != KM_ERROR_OK) {
		EMSG("Failed to create device info map");
		goto exit;
	}

	csr_payload = cbor_new_definite_array(4);
	if (!csr_payload) {
		EMSG("Failed to allocate memory for csr payload array");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}

	result = cbor_array_push(csr_payload, cbor_move(cbor_build_uint8(csr_version)));
	result &= cbor_array_push(csr_payload, cbor_move(cbor_build_string("keymint")));
	result &= cbor_array_push(csr_payload, cbor_move(device_info));
	result &= cbor_array_push(csr_payload, cbor_move(keys_to_sign));
	if (!result) {
		EMSG("Failed to push items to csr payload array");
		error = KM_ERROR_UNKNOWN_ERROR;
		goto exit;
	}
	cbor_serialize_alloc(csr_payload, &csr_payload_data, &csr_payload_data_size);
	signed_data_payload = cbor_new_definite_array(2);
	if (!signed_data_payload) {
		EMSG("Failed to allocate memory for signed data payload array");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}

	result = cbor_array_push(signed_data_payload,
				 cbor_move(cbor_build_bytestring(challenge->data, challenge->data_length)));	
	result &= cbor_array_push(signed_data_payload,
				  cbor_move(cbor_build_bytestring(csr_payload_data, csr_payload_data_size)));
	if (!result) {
		EMSG("Failed to push items to signed data payload array");
		error = KM_ERROR_UNKNOWN_ERROR;
		goto exit;
	}

	cbor_serialize_alloc(signed_data_payload, &signed_data_payload_serialize, &signed_data_payload_serialize_size);
	error = TA_get_protected_data(optee_dice_context,
				      signed_data_payload_serialize,
				      signed_data_payload_serialize_size,
				      &signed_data,
				      &dice_cert_chain);
	if (error != KM_ERROR_OK) {
		EMSG("Failed to get protected data");
		goto exit;
	}

	csr = cbor_new_definite_array(4);
	if (!csr) {
		 EMSG("Failed to allocate memory for csr array");
		 error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		 goto exit;
	}
	result = cbor_array_push(csr, cbor_move(cbor_build_uint8(1)));
	/* uds_certs_data */
	result &= cbor_array_push(csr, cbor_move(cbor_new_definite_map(0)));
	result &= cbor_array_push(csr, cbor_move(dice_cert_chain));
	result &= cbor_array_push(csr, cbor_move(signed_data));
	if (!result) {
		EMSG("Failed to push items to csr array");
		error = KM_ERROR_UNKNOWN_ERROR;
		goto exit;
	}
	cbor_serialize_alloc(csr, &csr_serialize, &csr_serialize_size);
	if (csr_serialize_size > 0) {
		*csr_blob_data = TEE_Malloc(csr_serialize_size, TEE_MALLOC_FILL_ZERO);
		if (!*csr_blob_data) {
			EMSG("Failed to allocate memory for csr blob");
			error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
			goto exit;
		}
		TEE_MemMove(*csr_blob_data, csr_serialize, csr_serialize_size);
		*csr_blob_data_length = csr_serialize_size;
	}

exit:
	if (device_info)
		cbor_decref(&device_info);

	if (csr_payload_data)
		free(csr_payload_data);
	if (csr_payload)
		cbor_decref(&csr_payload);

	if (signed_data_payload_serialize)
		free(signed_data_payload_serialize);
	if (signed_data_payload)
		cbor_decref(&signed_data_payload);

	if (signed_data)
		cbor_decref(&signed_data);
	if (dice_cert_chain)
		cbor_decref(&dice_cert_chain);

	if (csr_serialize)
		free(csr_serialize);
	if (csr)
		cbor_decref(&csr);
	return error;
}
