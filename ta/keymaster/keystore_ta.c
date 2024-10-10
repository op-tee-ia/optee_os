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


#include <stdio.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "common.h"
#include "ta_ca_defs.h"
#include "keystore_ta.h"
#include "attestation.h"
#include "rot.h"
#include "unwrapkey.h"
#include <pta_system.h>
#include <mbedtls/platform_util.h>
#include <hmac.h>
#include <cbor.h>
#include <cose.h>

// todo: 1. multiple-Android support
//       2. Android resets but tee does not
bool g_isEarlyBootEnded = false;

uint64_t identifier_rsa[] = {1, 2, 840, 113549, 1, 1, 1};
/* RSAPrivateKey ::= SEQUENCE {
 *    version Version,
 *    modulus INTEGER, -- n
 *    publicExponent INTEGER, -- e
 *    privateExponent INTEGER, -- d
 *    prime1 INTEGER, -- p
 *    prime2 INTEGER, -- q
 *    exponent1 INTEGER, -- d mod (p-1)
 *    exponent2 INTEGER, -- d mod (q-1)
 *    coefficient INTEGER -- (inverse of q) mod p }
 */

uint64_t identifier_ec[] = {1, 2, 840, 10045, 2, 1};
/* ECPrivateKey ::= SEQUNCE {
 *    version Version,
 *    secretValue OCTET_STRING,
 *    publicValue CONSTRUCTED {
 *        XYValue BIT_STRING } }
 */

static TEE_TASessionHandle session_rngSTA = TEE_HANDLE_NULL;
static TEE_TASessionHandle session_diceSTA = TEE_HANDLE_NULL;
const int k_rot_version1 = 40001;
const int k_cose_mac0_semantic_tag = 17;

extern tee_km_context_t optee_km_context;
extern tee_dice_context_t optee_dice_context;

static const uint32_t k_rkp_version = 3;
static const tee_km_rkp_hwinfo_t optee_km_rpk_hwinfo = {
	.version = k_rkp_version,
	.rpc_author_name = "Intel",
	.supported_eek_curve = k_rkp_version >= 3 ? 0 : 2,
	.unique_id = "Intel Optee Implementation",
	.supported_num_keys_in_csr = 20,
};

static const keymaster_key_param_t ecdsap256_params[8] = {
	{.tag = KM_TAG_PURPOSE, .key_param.enumerated = KM_PURPOSE_ATTEST_KEY},
	{.tag = KM_TAG_ALGORITHM, .key_param.enumerated = KM_ALGORITHM_EC},
	{.tag = KM_TAG_KEY_SIZE, .key_param.integer = 256},
	{.tag = KM_TAG_DIGEST, .key_param.enumerated = KM_DIGEST_SHA_2_256},
	{.tag = KM_TAG_EC_CURVE, .key_param.enumerated = KM_EC_CURVE_P_256},
	{.tag = KM_TAG_NO_AUTH_REQUIRED, .key_param.boolean = false},
	{.tag = KM_TAG_CERTIFICATE_NOT_BEFORE, .key_param.date_time = 0},
	{.tag = KM_TAG_CERTIFICATE_NOT_AFTER, .key_param.date_time = 0},
};

static const keymaster_key_param_set_t ecdsap256_key_param_set = {
	.params = (keymaster_key_param_t *)ecdsap256_params,
	.length = 8
};

static const size_t k_rkp_version_without_super_encryption = 3;

static keymaster_error_t TA_checkParams(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in;
	uint8_t *out;
	size_t out_size;

	in = (uint8_t *)params[0].memref.buffer;
	out = (uint8_t *)params[1].memref.buffer;
	out_size = params[1].memref.size;

	if (!in || !out) {
		EMSG("Unexpected null pointer");
		return KM_ERROR_UNEXPECTED_NULL_POINTER;
	}

	if (out_size != KM_RECV_BUF_SIZE) {
		EMSG("Output buffer size incorrect: %ld != %d", out_size, KM_RECV_BUF_SIZE);
		return KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
	}

	return KM_ERROR_OK;
}

static TEE_Result TA_errorRsp(TEE_Param params[TEE_NUM_PARAMS], keymaster_error_t error)
{
	uint8_t *out = NULL;
	uint8_t *out_end = NULL;
	size_t out_size = 0;
	keymaster_error_t km_error = error;
	bool oob = false;

	out = (uint8_t *)params[1].memref.buffer;
	out_size = params[1].memref.size;
	out_end = out + out_size;

	if (!out) {
		EMSG("Cannot add error response, out null pointer");
		return TEE_ERROR_GENERIC;
	}

	TA_serialize_rsp_err(out, out_end, &km_error, &oob);
	if (oob) {
		EMSG("Out of output buffer space");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	return TEE_SUCCESS;
}

static keymaster_error_t TA_stubOperation(TEE_Param params[TEE_NUM_PARAMS])
{
	DMSG("Stub operation");

	params[1].memref.size = sizeof(keymaster_error_t);

	return KM_ERROR_OK;
}

static keymaster_error_t TA_unimplementedOperation(TEE_Param params[TEE_NUM_PARAMS])
{
	DMSG("Unimplemented operation");

	params[1].memref.size = sizeof(keymaster_error_t);

	return KM_ERROR_UNIMPLEMENTED;
}

TEE_Result TA_CreateEntryPoint(void)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_Param params[TEE_NUM_PARAMS];
	uint32_t ret_orig = 0;

	const TEE_UUID rng_entropy_uuid = PTA_SYSTEM_UUID /*RNG_ENTROPY_UUID*/;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("%s %d", __func__, __LINE__);

	res = TA_init_km_context();
	if (res != TEE_SUCCESS) {
		EMSG("TA_init_km_context failed(%x)", res);
		goto exit;
	}

	TA_reset_operations_table();

	res = TA_create_secret_key();
	if (res != TEE_SUCCESS) {
		EMSG("Something wrong with secret key (%x)", res);
		goto exit;
	}

	res = TA_create_hmac_key();
	if (res != TEE_SUCCESS) {
		EMSG("Something wrong with HMAC key create (%x)", res);
		goto exit;
	}

	res = TA_InitializeAuthTokenKey();
	if (res != TEE_SUCCESS) {
		EMSG("Something wrong with authorization token (%x)", res);
		goto exit;
	}

	res = TEE_OpenTASession(&rng_entropy_uuid, TEE_TIMEOUT_INFINITE,
				exp_param_types, params, &session_rngSTA,
				NULL);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to create session with RNG static TA (%x)", res);
		goto exit;
	}

        res = TEE_OpenTASession(&(const TEE_UUID)PTA_SYSTEM_UUID,
                                TEE_TIMEOUT_INFINITE, 0, NULL, &session_diceSTA,
                                &ret_orig);
        if (res != TEE_SUCCESS) {
                EMSG("Failed to creat session with DICE static TA (%x)", res);
                goto exit;
        }

exit:
	return res;
}

void TA_DestroyEntryPoint(void)
{
	DMSG("%s %d", __func__, __LINE__);
	TA_free_master_key();
	TA_free_hmac_key();
	TEE_CloseTASession(session_rngSTA);
	session_rngSTA = TEE_HANDLE_NULL;
	TEE_CloseTASession(session_diceSTA);
	session_diceSTA = TEE_HANDLE_NULL;
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param params[TEE_NUM_PARAMS] __unused,
				    void **sess_ctx __unused)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	DMSG("%s %d", __func__, __LINE__);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	return KM_ERROR_OK;
}

void TA_CloseSessionEntryPoint(void *sess_ctx __unused)
{
	DMSG("%s %d", __func__, __LINE__);
}

static uint32_t TA_possibe_size(const uint32_t type, const uint32_t key_size,
				const keymaster_blob_t input,
				const uint32_t tag_len)
{
	DMSG("%s %d", __func__, __LINE__);
	switch (type) {
	case TEE_TYPE_AES:
		/*
		 * Input can be extended to block size and one block
		 * can be added as a padding.
		 * Additionaly GCM tag can be added
		 */
		return ((input.data_length + BLOCK_SIZE - 1)
				/ BLOCK_SIZE + 1) * BLOCK_SIZE + tag_len;
	case TEE_TYPE_DES3:
		return ((input.data_length + DES_BLOCK_SIZE - 1)
				/ DES_BLOCK_SIZE + 1) * DES_BLOCK_SIZE + tag_len;
	case TEE_TYPE_RSA_KEYPAIR:
		return (key_size + 7) / 8;
	case TEE_TYPE_ECDSA_KEYPAIR:
	case TEE_TYPE_ED25519_KEYPAIR:
	case TEE_TYPE_X25519_KEYPAIR:
		/*
		 * Output is a sign with r and s parameters each sized as
		 * a key in ASN.1 format
		 */
		return 3 * key_size;
	case TEE_TYPE_ECDH_KEYPAIR:
		return TA_SHARED_SECRET_MAX_SIZE;
	default:/* HMAC */
		return KM_MAX_DIGEST_SIZE;
	}
}

static uint32_t tee_get_os_version(void)
{
	return optee_km_context.os_version;
}

static uint32_t tee_get_os_patchlevel(void)
{
	return optee_km_context.os_patchlevel;
}

static uint32_t tee_get_vendor_patchlevel(void)
{
	return optee_km_context.vendor_patchlevel;
}

static uint32_t tee_get_boot_patchlevel(void)
{
	optee_km_context.boot_patchlevel = optee_km_context.rot.rot_data.patchMonthYearDay;
	return optee_km_context.boot_patchlevel;
}

static keymaster_error_t TA_getHmacSharingParameters(TEE_Param params[TEE_NUM_PARAMS])
{
	static hmac_sharing_parameters_t *hmac_saved_parameters = NULL;
	uint8_t *out = NULL;
	uint8_t *out_end = NULL;
	size_t out_size = 0;
	bool oob = false; /* out of bounds flag */

	DMSG("%s %d", __func__, __LINE__);

	out = (uint8_t *)params[1].memref.buffer;
	out_size = (size_t)params[1].memref.size;
	out_end = out + out_size;

	out += sizeof(keymaster_error_t);

	if (hmac_saved_parameters == NULL) {
		hmac_saved_parameters = TEE_Malloc(sizeof(hmac_sharing_parameters_t),
						   TEE_MALLOC_FILL_ZERO);
		if (!hmac_saved_parameters) {
			EMSG("%s: failed to allocate memory", __func__);
			return KM_ERROR_MEMORY_ALLOCATION_FAILED;
		}

		TEE_GenerateRandom(hmac_saved_parameters->nonce, 32);
	}

	out += TA_serialize_blob_akms(out, out_end, &hmac_saved_parameters->seed, &oob);
	if (oob) {
		EMSG("Out of output buffer space");
		return KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
	}

	TEE_MemMove(out, hmac_saved_parameters->nonce, sizeof(hmac_saved_parameters->nonce));
	out += sizeof(hmac_saved_parameters->nonce);

	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	return KM_ERROR_OK;
}

static keymaster_error_t TA_verifyAuthorization(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	size_t in_size = 0;
	uint8_t *out = NULL;
	uint8_t *out_end = NULL;
	size_t out_size = 0;
	uint64_t challenge = UNDEFINED;
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET;
	keymaster_error_t error = KM_ERROR_OK;
	keymaster_blob_t hmac = EMPTY_BLOB;
	hw_auth_token_t auth_token;
	keymaster_security_level_t security_level;
	uint64_t millis;
	bool oob = false; /* out of bounds flag */
	TEE_Time time;
	TEE_Result res;

	DMSG("%s %d", __func__, __LINE__);

	in = (uint8_t *)params[0].memref.buffer;
	in_size = (size_t)params[0].memref.size;
	in_end = in + in_size;

	out = (uint8_t *)params[1].memref.buffer;
	out_size = (size_t)params[1].memref.size; /* limited to 8192 */
	out_end = out + out_size;

	out += sizeof(keymaster_error_t);

	TEE_MemMove(&challenge, in, sizeof(uint64_t));
	in += sizeof(uint64_t);

	in += TA_deserialize_auth_set(in, in_end, &params_t, false, &error);
	if (error != KM_ERROR_OK)
		goto exit;

	TEE_MemMove(&auth_token.challenge, in, sizeof(hw_auth_token_t));
	in += sizeof(hw_auth_token_t);

	auth_token.challenge = challenge;

	/*
	 * WORKAROUND: add error code to data buffer
	 * VerifyAuthorizationResponse() expects the data buffer to also contain the error response
	 * See: https://android.googlesource.com/platform/system/keymaster/+/refs/tags/android-14.0.0_r1/include/keymaster/android_keymaster_messages.h#1010
	 */
	keymaster_error_t error_tmp = KM_ERROR_OK;
	TEE_MemMove(out, &error_tmp, sizeof(uint32_t));
	out += sizeof(uint32_t);

	TEE_MemMove(out, &challenge, sizeof(uint64_t));
	out += sizeof(uint64_t);

	TEE_GetSystemTime(&time);
	millis = ((uint64_t)time.seconds * 1000) + time.millis;
	TEE_MemMove(out, &millis, sizeof(uint64_t));
	out += sizeof(uint64_t);

	out += TA_serialize_auth_set(out, out_end, &params_t, &oob);
	if (oob) {
		EMSG("Out of output buffer space");
		error = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto exit;
	}

	security_level = KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT;
	TEE_MemMove(out, &security_level, sizeof(uint32_t));
	out += sizeof(uint32_t);

	/* Token HMAC */
	hmac.data_length = 32;
	hmac.data = TEE_Malloc(hmac.data_length, TEE_MALLOC_FILL_ZERO);
	if (!hmac.data) {
		EMSG("Failed to allocate memory for hmac");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}

	res = TA_computeTokenHmac(&auth_token, hmac.data, 32);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to compute HMAC of token");
		error = KM_ERROR_OPERATION_CANCELLED;
		goto free_hmac_data;
	}

	out += TA_serialize_blob_akms(out, out_end, &hmac, &oob);
	if (oob) {
		EMSG("Out of output buffer space");
		error = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto free_hmac_data;
	}

free_hmac_data:
	free(hmac.data);
exit:
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	return error;
}

static keymaster_error_t TA_get_dice_data(void)
{
	TEE_Param params[TEE_NUM_PARAMS] = { };
	TEE_Result res = TEE_ERROR_GENERIC;

	uint32_t ret_orig = 0;
	uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
					       TEE_PARAM_TYPE_VALUE_OUTPUT,
					       TEE_PARAM_TYPE_MEMREF_OUTPUT,
					       TEE_PARAM_TYPE_NONE);

	if (session_diceSTA == TEE_HANDLE_NULL) {
		EMSG("Session with DICE static TA is not opened");
		res = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
		goto out;
	}

	params[0].memref.buffer = optee_dice_context.attest_cdi;
	params[0].memref.size = sizeof(optee_dice_context.attest_cdi);
	params[1].value.a = 0;
	params[1].value.b = 0;
	params[2].memref.buffer = optee_dice_context.cdi_certificate;
	params[2].memref.size = sizeof(optee_dice_context.cdi_certificate);

	res = TEE_InvokeTACommand(session_diceSTA, TEE_TIMEOUT_INFINITE,
				  PTA_SYSTEM_GET_DICE,
				  param_types, params, &ret_orig);
	if (res) {
		EMSG("Failed(%d) to invoke PTA command", res);
		res = KM_ERROR_UNKNOWN_ERROR;
		goto out;
	}

	DMSG("TA next_cdi_certificate_actual_size is %d", params[1].value.a);
	optee_dice_context.cdi_certificate_actual_size = params[1].value.a;

out:
	return res;
}

static keymaster_error_t TA_get_client_info(
				const keymaster_key_param_set_t *input_set,
				keymaster_blob_t *client_id,
				keymaster_blob_t *app_data)
{
	keymaster_error_t res = KM_ERROR_OK;

	DMSG("%s %d", __func__, __LINE__);
	TEE_MemFill(client_id, 0, sizeof(keymaster_blob_t));
	TEE_MemFill(app_data, 0, sizeof(keymaster_blob_t));

	for (size_t i = 0; i < input_set->length; i++) {
		if (input_set->params[i].tag == KM_TAG_APPLICATION_ID) {
			client_id->data_length = input_set->params[i].key_param.blob.data_length;
			/* Freed when deserialized blob is destroyed by caller */
			client_id->data = TEE_Malloc(client_id->data_length, TEE_MALLOC_FILL_ZERO);
			if (!client_id->data) {
				EMSG("Failed to allocate memory for client id");
				res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
				goto err;
			}
			TEE_MemMove(client_id->data, input_set->params[i].key_param.blob.data, client_id->data_length);
		}
		if (input_set->params[i].tag == KM_TAG_APPLICATION_DATA) {
			app_data->data_length = input_set->params[i].key_param.blob.data_length;
			/* Freed when deserialized blob is destroyed by caller */
			app_data->data = TEE_Malloc(app_data->data_length, TEE_MALLOC_FILL_ZERO);
			if (!app_data->data) {
				EMSG("Failed to allocate memory for app_data");
				res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
				goto err;
			}
			TEE_MemMove(app_data->data, input_set->params[i].key_param.blob.data, app_data->data_length);
		}
	}

	return KM_ERROR_OK;

err:
	if (client_id->data)
		TEE_Free(client_id->data);
	if (app_data->data)
		TEE_Free(app_data->data);
	return res;
}

static keymaster_error_t TA_build_hidden_info(uint8_t **hidden, size_t* hidden_size,
			keymaster_blob_t* client_id, keymaster_blob_t* app_data)
{
	keymaster_blob_t rot = EMPTY_BLOB;
	keymaster_error_t res = KM_ERROR_OK;
	size_t buf_size = 0;
	bool oob = false; /* out of bounds flag */

	buf_size = client_id->data_length + SIZE_LENGTH_AKMS
				+ app_data->data_length + SIZE_LENGTH_AKMS
				+ sizeof(struct rot_data_t);

	uint8_t* tmp = TEE_Malloc(buf_size, TEE_MALLOC_FILL_ZERO);
	if (!tmp) {
		EMSG("Failed to allocate memory for hidden");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto err;
	}

	uint8_t* out = tmp;
	uint8_t* out_end = tmp + buf_size;

	/* copy client_id to hidden */
	out += TA_serialize_blob_akms(out, out_end, client_id, &oob);
	if (oob) {
		EMSG("Out of output buffer space");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto err;
	}

	/* copy app_data to hidden */
	out += TA_serialize_blob_akms(out, out_end, app_data, &oob);
	if (oob) {
		EMSG("Out of output buffer space");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto err;
	}

	/* set rot data if not */
	if (!optee_km_context.rot_info_set) {
		res = TA_get_rot_data();
		if (res != KM_ERROR_OK && res != KM_ERROR_ROOT_OF_TRUST_ALREADY_SET) {
			EMSG("Failed(%d) to get root of trust data", res);
			goto err;
		}
		optee_km_context.rot_info_set = true;
	}

	/* copy rot.deviceLocked to hidden */
	rot.data = (uint8_t*)&optee_km_context.rot.rot_data.deviceLocked;
	rot.data_length = sizeof(optee_km_context.rot.rot_data.deviceLocked);
	out += TA_serialize_blob_akms(out, out_end, &rot, &oob);
	if (oob) {
		EMSG("Out of output buffer space");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto err;
	}

	/* copy rot.verifiedBootState to hidden */
	rot.data = (uint8_t*)&optee_km_context.rot.rot_data.verifiedBootState;
	rot.data_length = sizeof(optee_km_context.rot.rot_data.verifiedBootState);
	out += TA_serialize_blob_akms(out, out_end, &rot, &oob);
	if (oob) {
		EMSG("Out of output buffer space");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto err;
	}

	/* copy rot.keyHash256 to hidden */
	rot.data = (uint8_t*)optee_km_context.rot.rot_data.keyHash256;
	rot.data_length = optee_km_context.rot.rot_data.keySize;
	out += TA_serialize_blob_akms(out, out_end, &rot, &oob);
	if (oob) {
		EMSG("Out of output buffer space");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto err;
	}

	*hidden_size = buf_size;
	*hidden = tmp;
	return KM_ERROR_OK;

err:
	if (tmp)
		TEE_Free(tmp);
	return res;
}

static keymaster_error_t TA_get_validity_info(
				const keymaster_key_param_set_t *input_set,
				uint64_t *not_before_val, uint64_t *not_after_val)
{
	bool not_before = false;
	bool not_after = false;
	size_t i = 0;

	DMSG("%s %d", __func__, __LINE__);

	for (i = 0; i < input_set->length; i++) {
		if (input_set->params[i].tag == KM_TAG_CERTIFICATE_NOT_BEFORE) {
			not_before = true;
			*not_before_val = input_set->params[i].key_param.date_time / 1000;
			DMSG("not_before %ld", *not_before_val);
			break;
		}
	}

	for (i = 0; i < input_set->length; i++) {
		if (input_set->params[i].tag == KM_TAG_CERTIFICATE_NOT_AFTER) {
			not_after = true;
			*not_after_val = input_set->params[i].key_param.date_time / 1000;
			DMSG("not_after %ld", *not_after_val);
			break;
		}
	}

	if (not_before == false)
		return KM_ERROR_MISSING_NOT_BEFORE;

	if (not_after == false)
		return KM_ERROR_MISSING_NOT_AFTER;

	return KM_ERROR_OK;
}

static keymaster_error_t TA_configure(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	size_t  in_size = 0;
	uint8_t *out = NULL;
	keymaster_error_t res = KM_ERROR_OK;

	in = (uint8_t *)params[0].memref.buffer;
	in_size = (size_t)params[0].memref.size;
	in_end = in + in_size;
	out = (uint8_t *)params[1].memref.buffer;
	out += sizeof(keymaster_error_t);

	DMSG("%s %d", __func__, __LINE__);

	if (TA_is_out_of_bounds(in, in_end,
				sizeof(optee_km_context.os_version) +
				sizeof(optee_km_context.os_patchlevel))) {
		EMSG("Out of input array bounds on deserialization");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto out;
	}

	/* parse parameters */
	if (!optee_km_context.version_info_set) {
		/*
		 * Note that version info is now set by Configure, rather than
		 * by the bootloader.  This is to ensure that system-only
		 * updates can be done, to avoid breaking Project Treble.
		 */
		TEE_MemMove(&optee_km_context.os_version, in,
		       sizeof(optee_km_context.os_version));
		in += 4;
		TEE_MemMove(&optee_km_context.os_patchlevel, in,
		       sizeof(optee_km_context.os_patchlevel));
		in += 4;
		optee_km_context.version_info_set = true;

		if ((res = TA_configure_rot_info(KM_OS_VERSION,
							optee_km_context.os_version))) {
			DMSG("Configure KM_OS_VERSION to rot failed");
			goto out;
		}
		if ((res = TA_configure_rot_info(KM_OS_PATCH_LEVEL,
							optee_km_context.os_patchlevel))) {
			DMSG("Configure KM_OS_PATCH_LEVEL to rot failed");
			goto out;
		}
	}

out:
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	return res;
}

static keymaster_error_t TA_configure_vendor_patchlevel(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	size_t  in_size = 0;
	uint8_t *out = NULL;
	keymaster_error_t res = KM_ERROR_OK;

	in = (uint8_t *)params[0].memref.buffer;
	in_size = (size_t)params[0].memref.size;
	in_end = in + in_size;
	out = (uint8_t *)params[1].memref.buffer;
	out += sizeof(keymaster_error_t);

	DMSG("%s %d", __func__, __LINE__);

	if (TA_is_out_of_bounds(in, in_end,
				sizeof(optee_km_context.vendor_patchlevel))) {
		EMSG("Out of input array bounds on deserialization");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto out;
	}

	/* parse parameters */
	if (!optee_km_context.vendor_patchlevel_set) {
		/*
		 * Note that version info is now set by Configure, rather than
		 * by the bootloader.  This is to ensure that system-only
		 * updates can be done, to avoid breaking Project Treble.
		 */
		TEE_MemMove(&optee_km_context.vendor_patchlevel, in,
		       sizeof(optee_km_context.vendor_patchlevel));
		optee_km_context.vendor_patchlevel_set = true;

		if ((res = TA_configure_rot_info(KM_VENDOR_PATCH_LEVEL,
						optee_km_context.vendor_patchlevel))) {
			DMSG("Configure KM_VENDOR_PATCH_LEVEL to rot failed");
			goto out;
		}
	}

out:
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	return res;
}

static keymaster_error_t TA_getVersion(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *out = NULL;

	DMSG("%s %d", __func__, __LINE__);

	out = (uint8_t *)params[1].memref.buffer;
	out += sizeof(keymaster_error_t);

	/* current version 4.1 */
	keymaster_version_t version = { 4, 1, 0 };
	TEE_MemMove(out, &version, sizeof(keymaster_version_t));
	out += sizeof(keymaster_version_t);

	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	return KM_ERROR_OK;
}

static keymaster_error_t TA_getVersion2(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *out;

	DMSG("%s %d", __func__, __LINE__);

	out = (uint8_t *)params[1].memref.buffer;
	out += sizeof(keymaster_error_t);

	/* current version Keymint 3 */
	keymaster_version2_t version2 = { 4, KEYMINT_3, 0 };
	TEE_MemMove(out, &version2, sizeof(keymaster_version2_t));
	out += sizeof(keymaster_version2_t);

	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	return KM_ERROR_OK;
}

/* Adds caller-provided entropy to the pool */
static keymaster_error_t TA_addRngEntropy(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	size_t  in_size = 0;
	uint8_t *out = NULL;
	uint8_t *data = NULL; /* IN */
	uint32_t data_length = 0; /* IN */
	uint32_t sta_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	TEE_Param params_tee[TEE_NUM_PARAMS];
	keymaster_error_t res = KM_ERROR_OK;

	in = (uint8_t *)params[0].memref.buffer;
	in_size = (size_t)params[0].memref.size;
	in_end = in + in_size;
	out = (uint8_t *)params[1].memref.buffer;
	out += sizeof(keymaster_error_t);

	DMSG("%s %d", __func__, __LINE__);

	if (in_size == 0)
		goto out;
	if (TA_is_out_of_bounds(in, in_end, sizeof(data_length))) {
		EMSG("Out of input array bounds on deserialization");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto out;
	}
	TEE_MemMove(&data_length, in, sizeof(data_length));
	in += sizeof(data_length);
	if (TA_is_out_of_bounds(in, in_end, data_length)) {
		EMSG("Out of input array bounds on deserialization");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto out;
	}
	data = TEE_Malloc(data_length, TEE_MALLOC_FILL_ZERO);
	if (!data) {
		EMSG("Failed to allocate memory for data");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	/* oob check done before TEE_Malloc above */
	TEE_MemMove(data, in, data_length);
	if (session_rngSTA == TEE_HANDLE_NULL) {
		EMSG("Session with RNG static TA is not opened");
		res = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
		goto out;
	}
	params_tee[0].memref.buffer = data;
	params_tee[0].memref.size = data_length;
	res = TEE_InvokeTACommand(session_rngSTA, TEE_TIMEOUT_INFINITE,
				  PTA_SYSTEM_ADD_RNG_ENTROPY, sta_param_types,
				  params_tee, NULL);
	if (res != TEE_SUCCESS) {
		EMSG("Invoke command for RNG static TA failed, res=%x", res);
		goto out;
	}

out:
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;
	if (data) {
		mbedtls_platform_zeroize(data, data_length);
		TEE_Free(data);
	}

	DMSG("rsp out buf:");
	DHEXDUMP(params[1].memref.buffer, params[1].memref.size);
	return res;
}

static bool attestation_key_blob_not_null(uint8_t *start, uint8_t *end)
{
	size_t key_material_size = 0;

	DMSG("%s %d", __func__, __LINE__);

	if (TA_is_out_of_bounds(start, end, SIZE_LENGTH_AKMS)) {
		DMSG("Out of input array bounds");
		return false;
	}

	TEE_MemMove(&key_material_size, start, SIZE_LENGTH_AKMS);
	DMSG("key_material_size = %zu sizeof(key_material_size) = %zu",
	     key_material_size, SIZE_LENGTH_AKMS);

	if (key_material_size == 0)
		return false;

	return true;
}

static bool attestation_key_purpose_check(const keymaster_key_param_set_t *input_set)
{
	keymaster_purpose_t key_purpose = UNDEFINED;

	DMSG("%s %d", __func__, __LINE__);

	for (size_t i = 0; i < input_set->length; i++) {
		if (input_set->params[i].tag == KM_TAG_PURPOSE) {
			key_purpose = (keymaster_purpose_t)(input_set->params[i].key_param.enumerated);
			DMSG("key purpose is %d", key_purpose);
			if (key_purpose == KM_PURPOSE_ATTEST_KEY) {
				return true;
			}
		}
	}

	return false;
}

static keymaster_error_t TA_attestKey(uint8_t *start, uint8_t *end,
				keymaster_algorithm_t alg,
				TEE_ObjectHandle attested_key,
				keymaster_key_param_set_t *attest_params,
				keymaster_key_characteristics_t *attest_key_chr,
				keymaster_cert_chain_t *cert_chain,
				uint64_t not_before_val, uint64_t not_after_val)
{
	keymaster_key_blob_t root_key_blob = EMPTY_KEY_BLOB; /* IN */
	keymaster_key_param_set_t root_params = EMPTY_PARAM_SET; /* IN */
	keymaster_blob_t issuer_subject = EMPTY_BLOB; /* IN */
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET;
	keymaster_algorithm_t root_algorithm = KM_ALGORITHM_RSA;
	TEE_ObjectHandle root_key = TEE_HANDLE_NULL;
	uint8_t *key_material = NULL;
	uint32_t key_size = 0;
	uint32_t key_type = 0;
	uint8_t* hidden = NULL;
	size_t hidden_size = 0;
	bool includeUniqueID = false;
	keymaster_blob_t root_app_id = EMPTY_BLOB;
	keymaster_blob_t root_app_data = EMPTY_BLOB;
	bool resetSinceIDRotation = false;
	keymaster_blob_t *app_id = NULL;
	keymaster_blob_t *app_data = NULL;
	keymaster_blob_t *attest_app_id = NULL;
	keymaster_error_t res = KM_ERROR_OK;
	TEE_Result result = TEE_SUCCESS;
	uint8_t R = 0;
	uint64_t creation_datetime = 0;
	uint64_t tem_counter_value = 0;
	TEE_Time time;

	/* Key blob for root key */
	start += TA_deserialize_key_blob_akms(start, end, &root_key_blob, &res);
	if (res != KM_ERROR_OK) {
		if (res == KM_ERROR_INSUFFICIENT_BUFFER_SPACE)
			res = KM_ERROR_ATTESTATION_KEYS_NOT_PROVISIONED;
		goto exit;
	}

	if (root_key_blob.key_material_size == 0) {
		EMSG("Bad attestation key blob: size is 0");
		res = KM_ERROR_ATTESTATION_KEYS_NOT_PROVISIONED;
		goto exit;
	}

	key_material = TEE_Malloc(root_key_blob.key_material_size,
				  TEE_MALLOC_FILL_ZERO);
	if (!key_material) {
		EMSG("Failed to allocate memory for key material");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}

	/* Key params for root key */
	start += TA_deserialize_auth_set(start, end, &root_params, false, &res);
	if (res != KM_ERROR_OK)
		goto exit;

	res = TA_get_client_info(&root_params, &root_app_id, &root_app_data);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to get client info, res=%x", res);
		goto exit;
	}

	res = TA_build_hidden_info(&hidden, &hidden_size, &root_app_id, &root_app_data);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to serialize hidden info, res=%x", res);
		goto exit;
	}

	/* Restore root key */
	res = TA_restore_key(key_material, &root_key_blob, &key_size,
			     hidden, hidden_size, &key_type, false,
			     &root_key, &params_t);
	if (res != KM_ERROR_OK)
		goto exit;

	if (attestation_key_purpose_check(&params_t) == false) {
		EMSG("Key purpose is not attest");
		res = KM_ERROR_INCOMPATIBLE_PURPOSE;
		goto exit;
	}

	/* Check root key type */
	if (key_type == TEE_TYPE_RSA_KEYPAIR) {
		root_algorithm = KM_ALGORITHM_RSA;
	} else if (key_type == TEE_TYPE_ECDSA_KEYPAIR ||
		   key_type == TEE_TYPE_ED25519_KEYPAIR) {
		root_algorithm = KM_ALGORITHM_EC;
	} else {
		EMSG("Key attestation supports only asymmetric key pairs, "
		     "root key type=%x", key_type);
		res = KM_ERROR_INCOMPATIBLE_ALGORITHM;
		goto exit;
	}

	/* Analyze atttest parameters necessary for attestation */
	for (size_t i = 0; i < attest_params->length; i++) {
		switch (attest_params->params[i].tag) {
		case KM_TAG_APPLICATION_ID:
			app_id = &attest_params->params[i].key_param.blob;
			break;
		case KM_TAG_APPLICATION_DATA:
			app_data = &attest_params->params[i].key_param.blob;
			break;
		case KM_TAG_INCLUDE_UNIQUE_ID:
			includeUniqueID =
				attest_params->params[i].key_param.boolean;
			break;
		case KM_TAG_RESET_SINCE_ID_ROTATION:
			resetSinceIDRotation =
				attest_params->params[i].key_param.boolean;
			R = 1;
			break;
		case KM_TAG_ATTESTATION_APPLICATION_ID:
			attest_app_id =
				&attest_params->params[i].key_param.blob;
			break;
		case KM_TAG_ATTESTATION_ID_BRAND:
		case KM_TAG_ATTESTATION_ID_DEVICE:
		case KM_TAG_ATTESTATION_ID_PRODUCT:
		case KM_TAG_ATTESTATION_ID_SERIAL:
		case KM_TAG_ATTESTATION_ID_IMEI:
		case KM_TAG_ATTESTATION_ID_MEID:
		case KM_TAG_ATTESTATION_ID_MANUFACTURER:
		case KM_TAG_ATTESTATION_ID_MODEL:
		case KM_TAG_ATTESTATION_ID_SECOND_IMEI:
			DMSG("Cannot attest ids tag %x",
			    attest_params->params[i].tag);
			res = KM_ERROR_CANNOT_ATTEST_IDS;
			goto exit;
		case KM_TAG_CREATION_DATETIME:
			creation_datetime =
				attest_params->params[i].key_param.date_time;
			break;
		default:
			DMSG("Unused attestation parameter tag %x",
			     attest_params->params[i].tag);
			break;
		}
	}

	(void)resetSinceIDRotation;
	(void)app_id;
	(void)app_data;

	if (attest_app_id == NULL) {
		EMSG("Attestation application ID is missing");
		res = KM_ERROR_ATTESTATION_APPLICATION_ID_MISSING;
		goto exit;
	}

	if (includeUniqueID == true) {
		uint32_t uniqueIDlen = UNIQUE_ID_BUFFER_SIZE;
		extern uint8_t unique_id[UNIQUE_ID_BUFFER_SIZE];
		if (creation_datetime == 0)
		{
			TEE_GetSystemTime(&time);
			creation_datetime = (time.seconds * 1000) + time.millis;
		}
		// T changes every 30 days (2592000000 = 30 * 24 * 60 * 60 * 1000).
		tem_counter_value = creation_datetime / 2592000000;

		res = TA_generate_UniqueID(tem_counter_value, attest_app_id->data, attest_app_id->data_length, R, unique_id, &uniqueIDlen);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to generate Unique ID, res=%x", res);
			goto exit;
		}
		DMSG("Unique ID generated successfully");
	}

	/* Allocate memory for chain of certificates */
	cert_chain->entry_count = 2;
	cert_chain->entries =
		TEE_Malloc(sizeof(keymaster_blob_t)*cert_chain->entry_count,
			   TEE_MALLOC_FILL_ZERO);
	if (!cert_chain->entries) {
		EMSG("Failed to allocate memory for chain of certificates");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}

	/* Issue subject for attestation */
	start += TA_deserialize_blob_akms(start, end, &issuer_subject, false, &res, false);
	if (res != KM_ERROR_OK) {
		if (res == KM_ERROR_INSUFFICIENT_BUFFER_SPACE)
			res = KM_ERROR_INVALID_ARGUMENT;
		goto exit;
	}

	if (issuer_subject.data_length == 0) {
		EMSG("Bad issuer subject blob: size is 0");
		res = KM_ERROR_INVALID_ARGUMENT;
		goto exit;
	}

	/* Generate key attestation certificate (using STA ASN.1) */
	result = TA_gen_key_attest_cert_with_rootkey(root_algorithm, alg, root_key,
					&params_t,
					attested_key, attest_params, attest_key_chr, cert_chain,
					includeUniqueID, &issuer_subject, not_before_val, not_after_val);
	if (result != TEE_SUCCESS) {
		EMSG("Failed to gen key att cert, res=%x", result);
		res = KM_ERROR_UNKNOWN_ERROR;
		goto exit;
	}

	cert_chain->entry_count = 1;
	if (cert_chain->entries[1].data)
		TEE_Free(cert_chain->entries[1].data);

exit:
	if (root_key_blob.key_material)
		TEE_Free(root_key_blob.key_material);

	if (root_key != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(root_key);

	if (key_material)
		TEE_Free(key_material);

	if (issuer_subject.data)
		TEE_Free(issuer_subject.data);

	TA_free_params(&root_params);
	TA_free_params(&params_t);
	if (hidden)
		TEE_Free(hidden);

	return res;
}

/* Generate new key and specify associated authorizations (key params) */
static keymaster_error_t TA_generateKey(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	uint8_t *out_end = NULL;
	size_t out_size = 0;
	uint8_t *key_material = NULL;
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET; /* IN */
	keymaster_key_blob_t key_blob = EMPTY_KEY_BLOB; /* OUT */
	keymaster_key_characteristics_t characts = EMPTY_CHARACTS; /* OUT */
	keymaster_cert_chain_t cert_chain = EMPTY_CERT_CHAIN; /* OUT */
	keymaster_algorithm_t key_algorithm = UNDEFINED;
	keymaster_error_t res = KM_ERROR_OK;
	TEE_Result result = TEE_SUCCESS;
	keymaster_digest_t key_digest = UNDEFINED;
	uint32_t key_buffer_size = 0; /* For serialization of generated key */
	uint32_t characts_size = 0;
	uint32_t key_size = UNDEFINED;
	uint64_t key_rsa_public_exponent = UNDEFINED;
	uint64_t not_before_val = UNDEFINED;
	uint64_t not_after_val = UNDEFINED;
	uint32_t os_version = 0xFFFFFFFF;
	uint32_t os_patchlevel = 0xFFFFFFFF;
	uint32_t vendor_patchlevel = 0xFFFFFFFF;
	uint32_t boot_patchlevel = 0xFFFFFFFF;
	bool oob = false; /* out of bounds flag */
	bool attest_purpose = false;
	bool key_agree_purpose = false;
	bool asymmetric_alg = false;
	uint8_t* hidden = NULL;
	size_t hidden_size = 0;
	TEE_ObjectHandle key_obj_h = TEE_HANDLE_NULL;
	TEE_Attribute *attrs_in = NULL;
	uint32_t attrs_in_count = 1;
	keymaster_blob_t client_id = EMPTY_BLOB;
	keymaster_blob_t app_data = EMPTY_BLOB;
	keymaster_blob_t *challenge = NULL;
	keymaster_blob_t *root_cert = NULL;
	bool early_boot_only = false;
	keymaster_ec_curve_t ec_curve = KM_EC_CURVE_UNKNOWN;
	bool is_ed25519 = false;

	in = (uint8_t *)params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *)params[1].memref.buffer;
	out_size = (size_t)params[1].memref.size; /* limited to 8192 */
	out_end = out + out_size;
	out += sizeof(keymaster_error_t);

	DMSG("%s %d", __func__, __LINE__);

	in += TA_deserialize_auth_set(in, in_end, &params_t, false, &res);
	if (res != KM_ERROR_OK)
		goto exit;

	/*
	 * Need add os version and patchlevel to key_description,
	 * attest_key will check thess sections.
	 * optee add these values in hal and pass to ta.
	 */
	os_version = tee_get_os_version();
	os_patchlevel = tee_get_os_patchlevel();
	vendor_patchlevel = tee_get_vendor_patchlevel();
	boot_patchlevel = tee_get_boot_patchlevel();

	/* Add additional parameters */
	TA_add_origin(&params_t, KM_ORIGIN_GENERATED, true);
	TA_add_version_patchlevel(&params_t, os_version, os_patchlevel,
				vendor_patchlevel, boot_patchlevel);

	/* Parse mandatory and optional parameters */
	res = TA_parse_params(params_t, &key_algorithm, &key_size,
			      &key_rsa_public_exponent, &ec_curve, &is_ed25519, &key_digest,
				  &attest_purpose, &key_agree_purpose, &challenge, false,
				  &early_boot_only);
	if (res != KM_ERROR_OK)
		goto exit;

	if (key_size == UNDEFINED) {
		EMSG("Key size must be specified");
		res = KM_ERROR_UNSUPPORTED_KEY_SIZE;
		goto exit;
	}

	if (key_algorithm == KM_ALGORITHM_RSA || key_algorithm == KM_ALGORITHM_EC) {
		asymmetric_alg = true;
	}

	if (key_algorithm == KM_ALGORITHM_RSA &&
			key_rsa_public_exponent == UNDEFINED) {
		EMSG("RSA public exponent is missed");
		res = KM_ERROR_INVALID_ARGUMENT;
		goto exit;
	}

	if (key_algorithm == KM_ALGORITHM_EC) {
		DMSG("key_algorithm == KM_ALGORITHM_EC");
		TA_add_ec_curve(&params_t, key_size, is_ed25519);
	}
	
	DMSG("key_algorithm=%d key_rsa_public_exponent=%lu",
			key_algorithm, key_rsa_public_exponent);

	/*
	 * Newly-generated key's characteristics divided appropriately
	 * into hardware-enforced and software-enforced lists
	 * (except APPLICATION_ID and APPLICATION_DATA)
	 */
	res = TA_fill_characteristics(&characts, &params_t, &characts_size);
	if (res != KM_ERROR_OK)
		goto exit;

	key_buffer_size = TA_get_key_size(key_algorithm);

	key_blob.key_material_size = characts_size + key_buffer_size +
				     TAG_LENGTH;

	key_material = TEE_Malloc(key_blob.key_material_size,
				  TEE_MALLOC_FILL_ZERO);
	if (!key_material) {
		EMSG("Failed to allocate memory for key_material");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}
	res = TA_generate_key(key_algorithm, key_size, key_material,
			      key_digest, key_rsa_public_exponent, ec_curve, is_ed25519,
			      false, key_agree_purpose, &key_obj_h, &attrs_in);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to generate key, res=%x", res);
		goto exit;
	}

	TA_serialize_param_set(key_material + key_buffer_size,
			       key_material + key_blob.key_material_size,
			       &params_t, &oob);
	if (oob) {
		EMSG("Out of output buffer space");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto exit;
	}

	res = TA_get_client_info(&params_t, &client_id, &app_data);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to get client info, res=%x", res);
		goto exit;
	}

	res = TA_build_hidden_info(&hidden, &hidden_size, &client_id, &app_data);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to serialize hidden info, res=%x", res);
		goto exit;
	}
	
	res = TA_encrypt(key_material, key_blob.key_material_size,
					hidden, hidden_size);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to encrypt key blob, res=%x", res);
		goto exit;
	}
	key_blob.key_material = key_material;
	
	if (!asymmetric_alg)
		goto exit;

	if (challenge != NULL) {
		if (challenge->data_length > MAX_ATTESTATION_CHALLENGE) {
			EMSG("Attestation challenge is too big");
			res = KM_ERROR_INVALID_INPUT_LENGTH;
			goto exit;
		}

		res = TA_get_validity_info(&params_t, &not_before_val, &not_after_val);
		if (res != KM_ERROR_OK) {
			EMSG("Failed to get validity info, res=%x", res);
			goto exit;
		}

		DMSG("Generate Key to be Attested");
		res = TA_attestKey(in, in_end, key_algorithm, key_obj_h,
				&params_t, &characts, &cert_chain, not_before_val, not_after_val);
	} else if (attestation_key_blob_not_null(in, in_end)) {
		EMSG("Attestation challenge missing!");
		res = KM_ERROR_ATTESTATION_CHALLENGE_MISSING;
	} else {
		/* Allocate memory for chain of certificates */
		cert_chain.entry_count = 1;
		cert_chain.entries =
		TEE_Malloc(sizeof(keymaster_blob_t)*cert_chain.entry_count,
			TEE_MALLOC_FILL_ZERO);
		if (!cert_chain.entries) {
			EMSG("Failed to allocate memory for chain of certificates");
			res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
			goto exit;
		}

		root_cert = &cert_chain.entries[0];

		if (attest_purpose == true) {
			DMSG("Generate self-signed cert for signing key");

			res = TA_get_validity_info(&params_t, &not_before_val, &not_after_val);
			if (res != KM_ERROR_OK) {
				EMSG("Failed to get validity info, res=%x", res);
				goto exit;
			}

			result = TA_gen_self_signed_cert(&params_t, key_algorithm, key_obj_h,
						root_cert, not_before_val, not_after_val);
			if (result != TEE_SUCCESS) {
				EMSG("Failed to generated root certificate, res=%x", res);
				res = KM_ERROR_UNKNOWN_ERROR;
			}
		} else {
			DMSG("Generate fake cert for non-signing asymmetric key");
			
			res = TA_get_validity_info(&params_t, &not_before_val, &not_after_val);
			if (res != KM_ERROR_OK) {
				EMSG("Failed to get validity info, res=%x", res);
			}

			result = TA_gen_fake_cert(&params_t, key_algorithm, key_obj_h, root_cert,
						not_before_val, not_after_val);
			if (result != TEE_SUCCESS) {
				EMSG("Failed to generated fake certificate, res=%x", res);
				res = KM_ERROR_UNKNOWN_ERROR;
			}
		}
	}
	
exit:
	if (res == KM_ERROR_OK) {
		out += TA_serialize_key_blob_akms(out, out_end, &key_blob,
						  &oob);
		if (oob) {
			EMSG("Out of output buffer space");
			res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
			goto out;
		}
		out += TA_serialize_characteristics_akms(out, out_end,
							 &characts, &oob);
		if (oob) {
			EMSG("Out of output buffer space");
			res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
			goto out;
		}

		if (asymmetric_alg == true || challenge != NULL) {
			out += TA_serialize_cert_chain_akms(out, out_end, &cert_chain,
						    &res, &oob);
			if (oob) {
				EMSG("Out of output buffer space");
				res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
				goto out;
			}
		}
	}

out:
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;
	if (key_material)
		TEE_Free(key_material);
	TA_free_params(&characts.sw_enforced);
	TA_free_params(&characts.hw_enforced);
	TA_free_params(&params_t);
	TA_free_cert_chain(&cert_chain);

	if (client_id.data)
		TEE_Free(client_id.data);
	if (app_data.data)
		TEE_Free(app_data.data);
	if (hidden)
		TEE_Free(hidden);
	if (key_obj_h != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(key_obj_h);
	free_attrs(attrs_in, attrs_in_count);
	return res;
}

/* Return key parameters and characteristics associated during generation */
static keymaster_error_t TA_getKeyCharacteristics(
					TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	uint8_t *out_end = NULL;
	size_t out_size = 0;
	uint8_t *key_material = NULL;
	keymaster_key_blob_t key_blob = EMPTY_KEY_BLOB; /* IN */
	keymaster_key_param_set_t additional_params_t = EMPTY_PARAM_SET; /* IN */
	keymaster_blob_t client_id = EMPTY_BLOB;
	keymaster_blob_t app_data = EMPTY_BLOB;
	keymaster_key_characteristics_t chr = EMPTY_CHARACTS; /* OUT */
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET;
	keymaster_error_t res = KM_ERROR_OK;
	TEE_ObjectHandle obj_h = TEE_HANDLE_NULL;
	uint32_t characts_size = 0;
	uint32_t key_size = 0;
	uint32_t type = 0;
	uint32_t os_version = 0xFFFFFFFF;
	uint32_t os_patchlevel = 0xFFFFFFFF;
	uint32_t vendor_patchlevel = 0xFFFFFFFF;
	uint32_t boot_patchlevel = 0xFFFFFFFF;
	bool exportable = false;
	bool oob = false; /* out of bounds flag */
	uint8_t* hidden = NULL;
	size_t hidden_size = 0;
	bool is_modified = false;

	DMSG("%s %d", __func__, __LINE__);

	in = (uint8_t *)params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *)params[1].memref.buffer;
	out_size = (size_t)params[1].memref.size; /* limited to 8192 */
	out_end = out + out_size;
	out += sizeof(keymaster_error_t);

	os_version = tee_get_os_version();
	os_patchlevel = tee_get_os_patchlevel();
	vendor_patchlevel = tee_get_vendor_patchlevel();
	boot_patchlevel = tee_get_boot_patchlevel();

	in += TA_deserialize_key_blob_akms(in, in_end, &key_blob, &res);
	if (res != KM_ERROR_OK)
		goto exit;
	in += TA_deserialize_auth_set(in, in_end, &additional_params_t, false, &res);
	if (res != KM_ERROR_OK)
		goto exit;
	if (key_blob.key_material_size == 0) {
		EMSG("Bad key blob");
		res = KM_ERROR_UNSUPPORTED_KEY_FORMAT;
		goto exit;
	}
	key_material = TEE_Malloc(key_blob.key_material_size,
				  TEE_MALLOC_FILL_ZERO);
	if (!key_material) {
		EMSG("Failed to allocate memory for key material");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}

	res = TA_get_client_info(&additional_params_t, &client_id, &app_data);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to get client info, res=%x", res);
		goto exit;
	}

	res = TA_build_hidden_info(&hidden, &hidden_size, &client_id, &app_data);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to serialize hidden info, res=%x", res);
		goto exit;
	}

	res = TA_restore_key(key_material, &key_blob, &key_size,
				hidden, hidden_size, &type, false,
				&obj_h, &params_t);
	if (res != KM_ERROR_OK)
		goto exit;

	if (!TA_upgrade_version_patchlevel(&params_t, os_version, os_patchlevel,
		  vendor_patchlevel, boot_patchlevel, &is_modified, true)) {
		res = KM_ERROR_INVALID_ARGUMENT;
		goto out;
	}

	if (is_modified) {
		EMSG("need to upgrade the key");
		res = KM_ERROR_KEY_REQUIRES_UPGRADE;
		goto out;
	}

	res = TA_check_permission(&params_t, client_id, app_data, &exportable);
	if (res != KM_ERROR_OK)
		goto exit;

	res = TA_fill_characteristics(&chr, &params_t, &characts_size);
	if (res != KM_ERROR_OK)
		goto exit;

exit:
	if (res == KM_ERROR_OK) {
		out += TA_serialize_characteristics_akms(out, out_end, &chr,
							 &oob);
		if (oob) {
			EMSG("Out of output buffer space");
			res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
			goto out;
		}
	}

out:
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	if (obj_h != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(obj_h);
	if (key_blob.key_material)
		TEE_Free(key_blob.key_material);
	TA_free_params(&additional_params_t);
	if (client_id.data)
		TEE_Free(client_id.data);
	if (app_data.data)
		TEE_Free(app_data.data);
	if (key_material)
		TEE_Free(key_material);
	TA_free_params(&chr.sw_enforced);
	TA_free_params(&chr.hw_enforced);
	TA_free_params(&params_t);
	if (hidden)
		TEE_Free(hidden);

	return res;
}

/* Imports key material into Keymaster hardware */
static keymaster_error_t TA_importKey(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	uint8_t *out_end = NULL;
	size_t out_size = 0;
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET; /* IN */
	keymaster_key_format_t key_format = UNDEFINED; /* IN */
	keymaster_blob_t key_data = EMPTY_BLOB; /* IN */
	keymaster_key_blob_t key_blob = EMPTY_KEY_BLOB; /* OUT */
	keymaster_key_characteristics_t characts = EMPTY_CHARACTS; /* OUT */
	keymaster_cert_chain_t cert_chain = EMPTY_CERT_CHAIN; /* OUT */
	keymaster_error_t res = KM_ERROR_OK;
	TEE_Result result = TEE_SUCCESS;
	keymaster_algorithm_t key_algorithm = UNDEFINED;
	keymaster_digest_t key_digest = UNDEFINED;
	TEE_Attribute *attrs_in = NULL;
	uint8_t *key_material = NULL;
	uint32_t key_buffer_size = 0;
	uint32_t characts_size = 0;
	uint32_t key_size = UNDEFINED;
	uint32_t attrs_in_count = 0;
	uint64_t key_rsa_public_exponent = UNDEFINED;
	uint64_t not_before_val = 0xFFFFFFFF;
	uint64_t not_after_val = 0xFFFFFFFF;
	uint32_t os_version = 0xFFFFFFFF;
	uint32_t os_patchlevel = 0xFFFFFFFF;
	uint32_t vendor_patchlevel = 0xFFFFFFFF;
	uint32_t boot_patchlevel = 0xFFFFFFFF;
	bool oob = false; /* out of bounds flag */
	bool attest_purpose = false;
	bool key_agree_purpose = false;
	uint8_t* hidden = NULL;
	size_t hidden_size = 0;
	keymaster_blob_t client_id = EMPTY_BLOB;
	keymaster_blob_t app_data = EMPTY_BLOB;
	keymaster_blob_t *challenge = NULL;
	bool asymmetric_alg = false;
	uint8_t *key_material_restore = NULL;
	TEE_ObjectHandle key_obj_h = TEE_HANDLE_NULL;
	keymaster_key_param_set_t params_restore = EMPTY_PARAM_SET;
	uint32_t type = 0;
	keymaster_blob_t *root_cert = NULL;
	bool early_boot_only = false;
	keymaster_ec_curve_t ec_curve = KM_EC_CURVE_UNKNOWN;
	bool is_ed25519 = false;
	bool is_ed25519_oid = false;
	bool is_curve25519 = false;

	DMSG("%s %d", __func__, __LINE__);

	in = (uint8_t *)params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *)params[1].memref.buffer;
	out_size = (size_t)params[1].memref.size; /* limited to 8192 */
	out_end = out + out_size;
	out += sizeof(keymaster_error_t);

	in += TA_deserialize_auth_set(in, in_end, &params_t, false, &res);
	if (res != KM_ERROR_OK)
		goto out;
	TA_add_origin(&params_t, KM_ORIGIN_IMPORTED, true);

	if (TA_is_out_of_bounds(in, in_end, sizeof(key_format))) {
		EMSG("Out of input array bounds on deserialization");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto out;
	}
	TEE_MemMove(&key_format, in, sizeof(key_format));
	in += TA_deserialize_key_format(in, in_end, &key_format, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_blob_akms(in, in_end, &key_data, false, &res,
				       false);
	if (res != KM_ERROR_OK)
		goto out;

	/*
	 * Need add os version and patchlevel to key_description,
	 * attest_key will check thess sections.
	 * optee add these values in hal and pass to ta.
	 */
	os_version = tee_get_os_version();
	os_patchlevel = tee_get_os_patchlevel();
	vendor_patchlevel = tee_get_vendor_patchlevel();
	boot_patchlevel = tee_get_boot_patchlevel();
	TA_add_version_patchlevel(&params_t, os_version, os_patchlevel,
				vendor_patchlevel, boot_patchlevel);

	/* Parse mandatory and optional parameters */
	res = TA_parse_params(params_t, &key_algorithm, &key_size,
			      &key_rsa_public_exponent, &ec_curve, &is_ed25519, &key_digest,
				  &attest_purpose, &key_agree_purpose, &challenge, true,
				  &early_boot_only);
	if (res != KM_ERROR_OK)
		goto out;
	if (early_boot_only && g_isEarlyBootEnded) {
		res = KM_ERROR_EARLY_BOOT_ENDED;
		goto out;
	}
	if (key_format == KM_KEY_FORMAT_RAW) {
		if (key_algorithm != KM_ALGORITHM_AES &&
		    key_algorithm != KM_ALGORITHM_HMAC &&
		    key_algorithm != KM_ALGORITHM_TRIPLE_DES &&
		    (key_algorithm == KM_ALGORITHM_EC && ec_curve != KM_EC_CURVE_CURVE_25519)) {
			EMSG("Only DES3, HMAC and AES keys can imported in raw "
			     "format");
			res = KM_ERROR_UNSUPPORTED_KEY_FORMAT;
			goto out;
		}
		if (key_size == UNDEFINED)
			key_size = key_data.data_length * 8;
		if (key_algorithm == KM_ALGORITHM_HMAC) {
			res = TA_check_hmac_key_size(&key_data, &key_size,
						     key_digest);
			if (res != KM_ERROR_OK) {
				EMSG("HMAC key check failed");
				goto out;
			}
		}
		if (key_algorithm == KM_ALGORITHM_HMAC &&
					(key_size % 8 != 0 ||
					key_size > MAX_KEY_HMAC ||
					key_size < MIN_KEY_HMAC)) {
			EMSG("HMAC key size must be multiple of 8 in range "
			     "from %d to %d", MIN_KEY_HMAC, MAX_KEY_HMAC);
			res = KM_ERROR_UNSUPPORTED_KEY_SIZE;
			goto out;
		} else if (key_algorithm == KM_ALGORITHM_AES &&
						key_size != 128 &&
						key_size != 192 &&
						key_size != 256) {
			EMSG("Unsupported key size %d ! Supported only 128, "
			     "192 and 256", key_size);
			res = KM_ERROR_UNSUPPORTED_KEY_SIZE;
			goto out;
		} else if (key_algorithm == KM_ALGORITHM_TRIPLE_DES &&
						key_size != 112 &&
						key_size != 168 &&
						key_size != 192) {
			 EMSG("Unsupported key size %d ! Supported only 112, "
			      "168 and 192", key_size);
			 res = KM_ERROR_UNSUPPORTED_KEY_SIZE;
			 goto out;
		}
		if (key_algorithm == KM_ALGORITHM_EC && ec_curve == KM_EC_CURVE_CURVE_25519) {
			asymmetric_alg = true;
			is_curve25519 = true;

			if (key_data.data_length > 32) {
				uint32_t temp_key_size = key_size;
				uint64_t temp_key_rsa_public_exponent = key_rsa_public_exponent;

				res = mbedTLS_decode_pkcs8(key_data, &attrs_in,
							   &attrs_in_count, key_algorithm,
							   &temp_key_size,
							   &temp_key_rsa_public_exponent,
							   &is_ed25519_oid);

				if (res == KM_ERROR_OK) {
					EMSG("Input raw key is pkcs#8 format");
				}
				res = KM_ERROR_UNSUPPORTED_KEY_SIZE;
				goto out;
			}
			res = mbedTLS_decode_raw(key_data, &attrs_in,
						 &attrs_in_count, key_algorithm,
						 &key_size,
						 &key_rsa_public_exponent,
						 is_ed25519);
			if (res != KM_ERROR_OK)
				goto out;
		} else {
			attrs_in = TEE_Malloc(sizeof(TEE_Attribute),
								TEE_MALLOC_FILL_ZERO);
			if (!attrs_in) {
				EMSG("Failed to allocate memory for attributes");
				res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
				goto out;
			}
			attrs_in_count = 1;

			TEE_InitRefAttribute(attrs_in, TEE_ATTR_SECRET_VALUE,
					(void *) key_data.data, key_data.data_length);
		}
	} else { /* KM_KEY_FORMAT_PKCS8 */
		if (key_algorithm != KM_ALGORITHM_RSA &&
		    key_algorithm != KM_ALGORITHM_EC) {
			EMSG("Only RSA and EC keys can be imported in PKCS8 "
			     "format");
			res = KM_ERROR_UNSUPPORTED_KEY_FORMAT;
			goto out;
		}

		if (key_algorithm == KM_ALGORITHM_RSA ||
		    key_algorithm == KM_ALGORITHM_EC) {
			asymmetric_alg = true;
		}

		uint32_t key_size_set_in_tag = key_size;
		res = mbedTLS_decode_pkcs8(key_data, &attrs_in,
					   &attrs_in_count, key_algorithm,
					   &key_size,
					   &key_rsa_public_exponent,
					   &is_ed25519_oid);

		if (res != KM_ERROR_OK)
			goto out;
		if (key_algorithm == KM_ALGORITHM_RSA && (key_size % 8 != 0 ||
		    key_size > MAX_KEY_RSA)) {
			EMSG("RSA key size must be multiple of 8 and less than"
			     " %u", MAX_KEY_RSA);
			res = KM_ERROR_UNSUPPORTED_KEY_SIZE;
			goto out;
		}
		if (key_algorithm == KM_ALGORITHM_RSA) {
			if (key_size > MAX_KEY_RSA) {
				EMSG("RSA key size must be multiple of 8 and "
				     "less than %u", MAX_KEY_RSA);
				res = KM_ERROR_UNSUPPORTED_KEY_SIZE;
				goto out;
			}
		}
		if (key_algorithm == KM_ALGORITHM_RSA ||
		    key_algorithm == KM_ALGORITHM_EC) {
			if ((key_size_set_in_tag != UNDEFINED) && (key_size_set_in_tag != key_size)) {
				EMSG("Key size: %u setting in TAG::KEY_SIZE is mismatch "
				     "with key material: %u", key_size_set_in_tag, key_size);
				res = KM_ERROR_IMPORT_PARAMETER_MISMATCH;
				goto out;
			}
		}
		if (key_algorithm == KM_ALGORITHM_EC && ec_curve == KM_EC_CURVE_CURVE_25519) {
			is_curve25519 = true;
			if (is_ed25519 == false && is_ed25519_oid == true) {
				EMSG("Key purpose: %s setting in TAG::KM_TAG_PURPOSE is mismatch "
				     "with key material: %s", (is_ed25519 == true ? ("SIGN") : ("AGREE_KEY")),
				     (is_ed25519_oid == true ? ("SIGN") : ("AGREE_KEY")));
				res = KM_ERROR_INCOMPATIBLE_PURPOSE;
				goto out;
			}
		}
	}
	TA_add_to_params(&params_t, key_size, key_rsa_public_exponent, is_curve25519);
	res = TA_fill_characteristics(&characts, &params_t, &characts_size);
	if (res != KM_ERROR_OK)
		goto out;
	key_buffer_size = TA_get_key_size(key_algorithm);
	key_blob.key_material_size = characts_size + key_buffer_size +
				     TAG_LENGTH;
	key_material = TEE_Malloc(key_blob.key_material_size,
				  TEE_MALLOC_FILL_ZERO);
	if (!key_material) {
		EMSG("Failed to allocate memory for key_material");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}

	res = TA_import_key(key_algorithm, key_size, ec_curve, is_ed25519, key_material, key_digest,
			    attrs_in, attrs_in_count, key_agree_purpose);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to import key");
		goto out;
	}
	TA_serialize_param_set(key_material + key_buffer_size,
			       key_material + key_blob.key_material_size,
			       &params_t, &oob);
	if (oob) {
		EMSG("Out of output buffer space");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto out;
	}

	res = TA_get_client_info(&params_t, &client_id, &app_data);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to get client info, res=%x", res);
		goto exit;
	}

	res = TA_build_hidden_info(&hidden, &hidden_size, &client_id, &app_data);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to serialize hidden info, res=%x", res);
		goto exit;
	}

	res = TA_encrypt(key_material, key_blob.key_material_size,
				hidden, hidden_size);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to encrypt blob");
		goto out;
	}
	key_blob.key_material = key_material;

	if (!asymmetric_alg)
		goto out;

	key_material_restore = TEE_Malloc(key_blob.key_material_size,
					  TEE_MALLOC_FILL_ZERO);
	if (!key_material_restore) {
		EMSG("Failed to allocate memory for key_material_restore");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}

	res = TA_restore_key(key_material_restore, &key_blob, &key_size,
			     hidden, hidden_size, &type, false,
			     &key_obj_h, &params_restore);
	if (res != KM_ERROR_OK)
		goto out;

	if (challenge != NULL) {
		if (challenge->data_length > MAX_ATTESTATION_CHALLENGE) {
			EMSG("Attestation challenge is too big");
			res = KM_ERROR_INVALID_INPUT_LENGTH;
			goto out;
		}

		res = TA_get_validity_info(&params_t, &not_before_val, &not_after_val);
		if (res != KM_ERROR_OK) {
			EMSG("Failed to get validity info, res=%x", res);
			goto out;
		}

		DMSG("Generate Key to be attested");
		res = TA_attestKey(in, in_end, key_algorithm, key_obj_h,
				   &params_t, &characts, &cert_chain, not_before_val, not_after_val);
	} else if (attestation_key_blob_not_null(in, in_end)) {
		EMSG("Attestation challenge missing!");
		res = KM_ERROR_ATTESTATION_CHALLENGE_MISSING;
	} else {
		/* Allocate memory for chain of certificates */
		cert_chain.entry_count = 1;
		cert_chain.entries = TEE_Malloc(sizeof(keymaster_blob_t) * cert_chain.entry_count,
						TEE_MALLOC_FILL_ZERO);
		if (!cert_chain.entries) {
			EMSG("Failed to allocate memory for chain of certificates");
			res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
			goto out;
		}

		root_cert = &cert_chain.entries[0];

		if (attest_purpose == true) {
			DMSG("Generate self-signed cert for signing key");
			res = TA_get_validity_info(&params_t, &not_before_val, &not_after_val);
			if (res != KM_ERROR_OK) {
				EMSG("Failed to get validity info, res=%x", res);
				goto out;
			}

			result = TA_gen_self_signed_cert(&params_t, key_algorithm, key_obj_h,
							root_cert, not_before_val, not_after_val);
			if (result != TEE_SUCCESS) {
				EMSG("Failed to generated root certificate, res=%x", res);
				res = KM_ERROR_UNKNOWN_ERROR;
			}
		} else {
			DMSG("Generate fake cert for non-signing asymmetric key");
			result = TA_gen_fake_cert(&params_t, key_algorithm, key_obj_h, root_cert,
						  not_before_val, not_after_val);
			if (result != TEE_SUCCESS) {
				EMSG("Failed to generated fake certificate, res=%x", res);
				res = KM_ERROR_UNKNOWN_ERROR;
			}
		}
	}

out:
	if (res == KM_ERROR_OK) {
		out += TA_serialize_key_blob_akms(out, out_end, &key_blob,
						  &oob);
		if (oob) {
			EMSG("Out of output buffer space");
			res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
			goto exit;
		}
		out += TA_serialize_characteristics_akms(out, out_end,
							 &characts, &oob);
		if (oob) {
			EMSG("Out of output buffer space");
			res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
			goto exit;
		}

		if (asymmetric_alg == true || challenge != NULL) {
			out += TA_serialize_cert_chain_akms(out, out_end, &cert_chain,
							    &res, &oob);
			if (oob) {
				EMSG("Out of output buffer space");
				res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
				goto exit;
			}
		}
	}

exit:
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	if ((key_data.data && key_format != KM_KEY_FORMAT_RAW) ||
	    (key_data.data && key_format == KM_KEY_FORMAT_RAW &&
	     res != KM_ERROR_OK)) {
		TEE_Free(key_data.data);
	}

	free_attrs(attrs_in, attrs_in_count);
	TA_free_params(&params_t);
	TA_free_params(&characts.sw_enforced);
	TA_free_params(&characts.hw_enforced);
	TA_free_cert_chain(&cert_chain);
	if (key_material)
		TEE_Free(key_material);
	if (client_id.data)
		TEE_Free(client_id.data);
	if (app_data.data)
		TEE_Free(app_data.data);
	if (hidden)
		TEE_Free(hidden);

	if (key_obj_h != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(key_obj_h);
	if (key_material_restore)
		TEE_Free(key_material_restore);
	TA_free_params(&params_restore);

	return res;
}

/* Exports a public key from a Keymaster RSA or EC key pair */
static keymaster_error_t TA_exportKey(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	uint8_t *out_end = NULL;
	size_t out_size = 0;
	keymaster_key_format_t export_format = UNDEFINED; /* IN */
	keymaster_key_blob_t key_to_export = EMPTY_KEY_BLOB; /* IN */
	keymaster_key_param_set_t in_params = EMPTY_PARAM_SET; /* IN */
	keymaster_blob_t export_data = EMPTY_BLOB; /* OUT */
	keymaster_error_t res = KM_ERROR_OK;
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET;
	TEE_ObjectHandle obj_h = TEE_HANDLE_NULL;
	bool exportable = false;
	uint8_t *key_material = NULL;
	uint32_t key_size = UNDEFINED;
	uint32_t type = 0;
	bool oob = false; /* out of bounds flag */
	uint8_t* hidden = NULL;
	size_t hidden_size = 0;
	uint32_t os_version = 0xFFFFFFFF;
	uint32_t os_patchlevel = 0xFFFFFFFF;
	uint32_t vendor_patchlevel = 0xFFFFFFFF;
	uint32_t boot_patchlevel = 0xFFFFFFFF;
	bool is_modified = false;
	keymaster_blob_t client_id = EMPTY_BLOB;
	keymaster_blob_t app_data = EMPTY_BLOB;

	DMSG("%s %d", __func__, __LINE__);

	in = (uint8_t *)params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *)params[1].memref.buffer;
	out_size = (size_t)params[1].memref.size; /* limited to 8192 */
	out_end = out + out_size;
	out += sizeof(keymaster_error_t);

	os_version = tee_get_os_version();
	os_patchlevel = tee_get_os_patchlevel();
	vendor_patchlevel = tee_get_vendor_patchlevel();
	boot_patchlevel = tee_get_boot_patchlevel();

	/* additional param */
	in += TA_deserialize_auth_set(in, in_end, &in_params, false, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_key_format(in, in_end, &export_format, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_key_blob_akms(in, in_end, &key_to_export, &res);
	if (res != KM_ERROR_OK)
		goto out;

	/* Keymaster supports export of public keys only in X.509 format */
	if (export_format != KM_KEY_FORMAT_X509) {
		EMSG("Unsupported key export format");
		res = KM_ERROR_UNSUPPORTED_KEY_FORMAT;
		goto out;
	}
	key_material = TEE_Malloc(key_to_export.key_material_size,
				  TEE_MALLOC_FILL_ZERO);
	if (!key_material) {
		EMSG("Failed to allocate memory for key material");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}

	res = TA_get_client_info(&in_params, &client_id, &app_data);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to get client info, res=%x", res);
		goto exit;
	}

	res = TA_build_hidden_info(&hidden, &hidden_size, &client_id, &app_data);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to serialize hidden info, res=%x", res);
		goto exit;
	}

	res = TA_restore_key(key_material, &key_to_export, &key_size,
				hidden, hidden_size, &type, false,
				&obj_h, &params_t);
	if (res != KM_ERROR_OK)
		goto out;

	if (!TA_upgrade_version_patchlevel(&params_t, os_version, os_patchlevel,
		  vendor_patchlevel, boot_patchlevel, &is_modified, true)) {
		res = KM_ERROR_INVALID_ARGUMENT;
		goto exit;
	}

	if (is_modified) {
		EMSG("need to upgrade the key");
		res = KM_ERROR_KEY_REQUIRES_UPGRADE;
		goto exit;
	}

	res = TA_check_permission(&params_t,
				  /* client id */
				  in_params.params[0].key_param.blob,
				  /* app_data */
				  in_params.params[1].key_param.blob,
				  &exportable);
	if (res != KM_ERROR_OK)
		goto out;
	if (!exportable && type != TEE_TYPE_RSA_KEYPAIR
	    && type != TEE_TYPE_ECDSA_KEYPAIR) {
		res = KM_ERROR_UNSUPPORTED_KEY_FORMAT;
		EMSG("This key type is not exportable");
		goto out;
	}
	res = mbedTLS_encode_key(&export_data, type, &obj_h);
	if (res != KM_ERROR_OK)
		goto out;

out:
	if (res == KM_ERROR_OK) {
		out += TA_serialize_blob_akms(out, out_end, &export_data,
					      &oob);
		if (oob) {
			EMSG("Out of output buffer space");
			res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
			goto exit;
		}
	}

exit:
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	if (obj_h != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(obj_h);
	if (key_to_export.key_material)
		TEE_Free(key_to_export.key_material);
	if (key_material)
		TEE_Free(key_material);
	if (export_data.data)
		TEE_Free(export_data.data);
	TA_free_params(&params_t);
	TA_free_params(&in_params);

	if (client_id.data)
		TEE_Free(client_id.data);
	if (app_data.data)
		TEE_Free(app_data.data);
	if (hidden)
		TEE_Free(hidden);

	return res;
}

static keymaster_error_t TA_upgradeKey(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	uint8_t *out_end = NULL;
	uint8_t *key_material = NULL;
	size_t out_size = 0;
	uint32_t key_size = 0;
	uint32_t type = 0;
	bool oob = false; /* out of bounds flag */
	bool is_modified = false;
	uint8_t* hidden = NULL;
	size_t hidden_size = 0;
	uint32_t key_buffer_size = 0; /* For serialization of generated key */
	uint32_t os_version = 0xFFFFFFFF;
	uint32_t os_patchlevel = 0xFFFFFFFF;
	uint32_t vendor_patchlevel = 0xFFFFFFFF;
	uint32_t boot_patchlevel = 0xFFFFFFFF;
	keymaster_key_blob_t key_to_upgrade = EMPTY_KEY_BLOB; /* IN */
	keymaster_key_param_set_t upgr_params = EMPTY_PARAM_SET; /* IN */
	keymaster_key_blob_t upgraded_key = EMPTY_KEY_BLOB; /* OUT */
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET;
	keymaster_error_t res = KM_ERROR_OK;
	TEE_ObjectHandle obj_h = TEE_HANDLE_NULL;
	keymaster_blob_t client_id = EMPTY_BLOB;
	keymaster_blob_t app_data = EMPTY_BLOB;
	tee_key_attributes attrs;

	DMSG("%s %d", __func__, __LINE__);

	os_version = tee_get_os_version();
	os_patchlevel = tee_get_os_patchlevel();
	vendor_patchlevel = tee_get_vendor_patchlevel();
	boot_patchlevel = tee_get_boot_patchlevel();

	in = (uint8_t *)params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *)params[1].memref.buffer;
	out_size = (size_t)params[1].memref.size; /* limited to 8192 */
	out_end = out + out_size;
	out += sizeof(keymaster_error_t);

	in += TA_deserialize_key_blob_akms(in, in_end, &key_to_upgrade, &res);
	if (res != KM_ERROR_OK)
		goto exit;
	in += TA_deserialize_auth_set(in, in_end, &upgr_params, false, &res);
	if (res != KM_ERROR_OK)
		goto exit;

	key_material = TEE_Malloc(key_to_upgrade.key_material_size, TEE_MALLOC_FILL_ZERO);
	if (!key_material) {
		EMSG("Failed to allocate memory for key material");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}

	res = TA_get_client_info(&upgr_params, &client_id, &app_data);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to get client info, res=%x", res);
		goto exit;
	}

	res = TA_build_hidden_info(&hidden, &hidden_size, &client_id, &app_data);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to serialize hidden info, res=%x", res);
		goto exit;
	}

	res = TA_restore_key(key_material, &key_to_upgrade, &key_size,
				hidden, hidden_size, &type, false,
				&obj_h, &params_t);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to restore the upgraded key, res=%x", res);
		goto exit;
	}

	if (!TA_upgrade_version_patchlevel(&params_t, os_version, os_patchlevel,
		  vendor_patchlevel, boot_patchlevel, &is_modified, false)) {
		EMSG("Failed to upgrade the os version and patchlevel");
		res = KM_ERROR_INVALID_ARGUMENT;
		goto exit;
	}

	if (!is_modified) {
		EMSG("Dont need to upgrade");
		goto out;
	}

	res = TA_populate_key_attrs(key_material, &attrs);
	if (res != KM_ERROR_OK)	{
		EMSG("Failed to get key attributes from rey data");
		return KM_ERROR_INVALID_KEY_BLOB;
	}

	key_buffer_size = TA_get_key_size(attrs.alg);
	upgraded_key.key_material = TEE_Malloc(key_to_upgrade.key_material_size, TEE_MALLOC_FILL_ZERO);
	if (!upgraded_key.key_material) {
		EMSG("Failed to allocate memory for upgraded key material");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}
	upgraded_key.key_material_size = key_to_upgrade.key_material_size;
	TEE_MemMove(upgraded_key.key_material, key_material, key_buffer_size);
	TA_serialize_param_set(upgraded_key.key_material + key_buffer_size,
			       upgraded_key.key_material + upgraded_key.key_material_size,
			       &params_t, &oob);
	if (oob) {
		EMSG("Out of output buffer space");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto exit;
	}

	res = TA_encrypt(upgraded_key.key_material, upgraded_key.key_material_size,
					hidden, hidden_size);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to encrypt key blob, res=%x", res);
		goto exit;
	}

out:
	if (res == KM_ERROR_OK) {
		out += TA_serialize_key_blob_akms(out, out_end, &upgraded_key,
						  &oob);
		if (oob) {
			EMSG("Out of output buffer space");
			res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
			goto exit;
		}
	}

exit:
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	TA_free_params(&upgr_params);
	if (key_to_upgrade.key_material)
		TEE_Free(key_to_upgrade.key_material);
	if (upgraded_key.key_material)
		TEE_Free(upgraded_key.key_material);
	if (key_material)
		TEE_Free(key_material);
	return res;
}

/*
 * Begins a cryptographic operation, using the specified key, for the specified
 * purpose, with the specified parameters (as appropriate), and returns an
 * operation handle that is used with update and finish to complete the
 * operation
 */
static keymaster_error_t TA_begin(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	uint8_t *out_end = NULL;
	size_t out_size = 0;
	uint8_t *key_material = NULL;
	uint8_t *secretIV = NULL;
	uint32_t mac_length = UNDEFINED;
	uint32_t key_size = 0;
	uint32_t IVsize = UNDEFINED;
	uint32_t min_sec = UNDEFINED;
	uint32_t type = 0;
	bool do_auth = false;
	keymaster_purpose_t purpose = UNDEFINED; /* IN */
	keymaster_key_blob_t key = EMPTY_KEY_BLOB; /* IN */
	keymaster_key_param_set_t in_params = EMPTY_PARAM_SET; /* IN */
	keymaster_key_param_set_t out_params = EMPTY_PARAM_SET; /* OUT */
	keymaster_operation_handle_t operation_handle = 0; /* OUT */
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET;
	keymaster_key_param_t *nonce_param = NULL;
	keymaster_error_t res = KM_ERROR_OK;
	keymaster_algorithm_t algorithm = UNDEFINED;
	keymaster_blob_t nonce = EMPTY_BLOB;
	keymaster_digest_t digest = UNDEFINED;
	keymaster_digest_t mgf_digest = UNDEFINED;
	keymaster_block_mode_t mode = UNDEFINED;
	keymaster_padding_t padding = UNDEFINED;
	TEE_ObjectHandle obj_h = TEE_HANDLE_NULL;
	TEE_OperationHandle *operation = TEE_HANDLE_NULL;
	TEE_OperationHandle *digest_op = TEE_HANDLE_NULL;
	uint8_t key_id[TAG_LENGTH];
	bool oob = false; /* out of bounds flag */
	uint8_t* hidden = NULL;
	size_t hidden_size = 0;
	keymaster_blob_t client_id = EMPTY_BLOB;
	keymaster_blob_t app_data = EMPTY_BLOB;

	DMSG("%s %d", __func__, __LINE__);

	in = (uint8_t *)params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *)params[1].memref.buffer;
	out_size = (size_t)params[1].memref.size; /* limited to 8192 */
	out_end = out + out_size;
	out += sizeof(keymaster_error_t);

	/* Freed when operation is aborted (TA_abort_operation) */
	operation = TEE_Malloc(sizeof(TEE_OperationHandle),
			       TEE_MALLOC_FILL_ZERO);
	if (!operation) {
		EMSG("Failed to allocate memory for operation");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	/* Freed when operation is aborted (TA_abort_operation) */
	digest_op = TEE_Malloc(sizeof(TEE_OperationHandle),
			       TEE_MALLOC_FILL_ZERO);
	if (!digest_op) {
		EMSG("Failed to allocate memory for digest operation");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	*operation = TEE_HANDLE_NULL;
	*digest_op = TEE_HANDLE_NULL;

	in += TA_deserialize_purpose(in, in_end, &purpose, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_key_blob_akms(in, in_end, &key, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_auth_set(in, in_end, &in_params, false, &res);
	if (res != KM_ERROR_OK)
		goto out;
	key_material = TEE_Malloc(key.key_material_size, TEE_MALLOC_FILL_ZERO);

	memcpy(key_id, key.key_material + key.key_material_size - TAG_LENGTH,
	       TAG_LENGTH);

	res = TA_get_client_info(&in_params, &client_id, &app_data);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to get client info, res=%x", res);
		goto exit;
	}

	res = TA_build_hidden_info(&hidden, &hidden_size, &client_id, &app_data);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to serialize hidden info, res=%x", res);
		goto exit;
	}

	res = TA_restore_key(key_material, &key, &key_size,
				hidden, hidden_size, &type, purpose == KM_PURPOSE_AGREE_KEY,
				&obj_h, &params_t);
	if (res != KM_ERROR_OK)
		goto out;
	switch (type) {
	case TEE_TYPE_AES:
		algorithm = KM_ALGORITHM_AES;
		break;
	case TEE_TYPE_DES3:
		algorithm = KM_ALGORITHM_TRIPLE_DES;
		break;
	case TEE_TYPE_RSA_KEYPAIR:
		algorithm = KM_ALGORITHM_RSA;
		break;
	case TEE_TYPE_ECDSA_KEYPAIR:
	case TEE_TYPE_ECDH_KEYPAIR:
	case TEE_TYPE_ED25519_KEYPAIR:
	case TEE_TYPE_X25519_KEYPAIR:
		algorithm = KM_ALGORITHM_EC;
		break;
	default:/* HMAC */
		algorithm = KM_ALGORITHM_HMAC;
	}
	res = TA_check_params(&params_t, &in_params, &algorithm, purpose,
			      &digest, &mgf_digest, &mode, &padding, &mac_length, &nonce,
			      &min_sec, &do_auth, key_id);
	if (res != KM_ERROR_OK)
		goto out;

	if (purpose == KM_PURPOSE_WRAP_KEY)
		purpose = KM_PURPOSE_DECRYPT;

	if ((algorithm == KM_ALGORITHM_AES && mode != KM_MODE_ECB &&
	    nonce.data_length == 0) || (algorithm == KM_ALGORITHM_TRIPLE_DES &&
	    mode != KM_MODE_ECB && nonce.data_length == 0)) {
		if (mode == KM_MODE_CBC || mode == KM_MODE_CTR) {
			IVsize = 16;
		} else { /* GCM mode */
			IVsize = 12;
		}
		if (algorithm == KM_ALGORITHM_TRIPLE_DES) {
			IVsize = 8;
		}
		out_params.length = 1;
		secretIV = TEE_Malloc(IVsize, TEE_MALLOC_FILL_ZERO);
		if (!secretIV) {
			EMSG("Failed to allocate memory for secretIV");
			res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
			goto out;
		}
		nonce_param = TEE_Malloc(sizeof(keymaster_key_param_t),
					 TEE_MALLOC_FILL_ZERO);
		if (!nonce_param) {
			TEE_Free(secretIV);
			EMSG("Failed to allocate memory for parameters");
			res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
			goto out;
		}
		TEE_GenerateRandom(secretIV, IVsize);
		nonce_param->tag = KM_TAG_NONCE;
		nonce_param->key_param.blob.data = secretIV;
		nonce_param->key_param.blob.data_length = IVsize;
		out_params.params = nonce_param;
		nonce.data_length = IVsize;
		nonce.data = secretIV;
	}

	res = TA_create_operation(operation, obj_h, purpose, algorithm, type,
				  key_size, nonce, digest, mode, padding,
				  mac_length);
	if (res != KM_ERROR_OK)
		goto out;

	TEE_GenerateRandom(&operation_handle, sizeof(operation_handle));
	if (purpose == KM_PURPOSE_SIGN || purpose == KM_PURPOSE_VERIFY ||
	    (algorithm == KM_ALGORITHM_RSA && padding == KM_PAD_RSA_PSS)) {
		res = TA_create_digest_op(digest_op, digest);
		if (res != KM_ERROR_OK)
			goto out;
	}
	res = TA_start_operation(operation_handle, key, min_sec, operation,
				 purpose, digest_op, do_auth, padding, mode,
				 mac_length, digest, mgf_digest, nonce, client_id, app_data, key_id);
	if (res != KM_ERROR_OK)
		goto out;

out:
	if (res == KM_ERROR_OK) {
		if (TA_is_out_of_bounds(out, out_end,
					sizeof(operation_handle))) {
			EMSG("Out of output buffer space");
			res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
			goto exit;
		}
		TEE_MemMove(out, &operation_handle, sizeof(operation_handle));
		out += sizeof(operation_handle);
		out += TA_serialize_auth_set(out, out_end, &out_params, &oob);
		if (oob) {
			EMSG("Out of output buffer space");
			res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
			goto exit;
		}
	}

exit:
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	if (obj_h != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(obj_h);
	if (key.key_material)
		TEE_Free(key.key_material);
	if (res != KM_ERROR_OK) {
		if (*digest_op != TEE_HANDLE_NULL)
			TEE_FreeOperation(*digest_op);
		if (*operation != TEE_HANDLE_NULL)
			TEE_FreeOperation(*operation);
		TEE_Free(operation);
		TEE_Free(digest_op);
	}
	if (key_material)
		TEE_Free(key_material);
	TA_free_params(&in_params);
	TA_free_params(&params_t);
	TA_free_params(&out_params);

	if (client_id.data)
		TEE_Free(client_id.data);
	if (app_data.data)
		TEE_Free(app_data.data);
	if (hidden)
		TEE_Free(hidden);

	return res;
}

/* Provides data to process in an ongoing operation started with begin */
static keymaster_error_t TA_update(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	uint8_t *out_end = NULL;
	size_t out_size = 0;
	keymaster_operation_handle_t operation_handle = 0; /* IN */
	keymaster_key_param_set_t in_params = EMPTY_PARAM_SET; /* IN */
	keymaster_blob_t input = EMPTY_BLOB; /* IN */
	size_t input_consumed = 0; /* OUT */
	keymaster_key_param_set_t out_params = EMPTY_PARAM_SET; /* OUT */
	keymaster_blob_t output = EMPTY_BLOB; /* OUT */
	uint8_t *key_material = NULL;
	uint32_t key_size = 0;
	uint32_t type = 0;
	uint32_t keyblob_out_size = 0;
	uint32_t input_provided = 0;
	keymaster_error_t res = KM_ERROR_OK;
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET;
	keymaster_operation_t operation = EMPTY_OPERATION;
	TEE_ObjectHandle obj_h = TEE_HANDLE_NULL;
	bool is_input_ext = false;
	bool oob = false; /* out of bounds flag */
	uint8_t* hidden = NULL;
	size_t hidden_size = 0;
	keymaster_blob_t client_id = EMPTY_BLOB;
	keymaster_blob_t app_data = EMPTY_BLOB;

	DMSG("%s %d", __func__, __LINE__);

	in = (uint8_t *)params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *)params[1].memref.buffer;
	out_size = (size_t)params[1].memref.size; /* limited to 8192 */
	out_end = out + out_size;
	out += sizeof(keymaster_error_t);

	in += TA_deserialize_op_handle(in, in_end, &operation_handle, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_blob_akms(in, in_end, &input, false, &res, true);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_auth_set(in, in_end, &in_params, false, &res);
	if (res != KM_ERROR_OK)
		goto out;

	input_provided = input.data_length;
	res = TA_get_operation(operation_handle, &operation);
	if (res != KM_ERROR_OK)
		goto out;
	key_material = TEE_Malloc(operation.key->key_material_size,
				  TEE_MALLOC_FILL_ZERO);

	res = TA_build_hidden_info(&hidden, &hidden_size, &operation.client_id, &operation.app_data);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to serialize hidden info, res=%x", res);
		goto exit;
	}

	res = TA_restore_key(key_material, operation.key, &key_size,
				hidden, hidden_size, &type, false,
				&obj_h, &params_t);
	if (res != KM_ERROR_OK)
		goto out;
	if (operation.do_auth) {
		res = TA_do_auth(in_params, params_t, operation_handle);
		if (res != KM_ERROR_OK) {
			EMSG("Authentication failed");
			goto out;
		}
	}

	if (input.data_length != 0 && type == TEE_TYPE_RSA_KEYPAIR)
		operation.got_input = true;
	keyblob_out_size = TA_possibe_size(type, key_size, input, 0);
	output.data = TEE_Malloc(keyblob_out_size, TEE_MALLOC_FILL_ZERO);
	if (!output.data) {
		EMSG("Failed to allocate memory for output");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	switch (type) {
	case TEE_TYPE_AES:
		res = TA_aes_update(&operation, &input, &output, &keyblob_out_size,
				    input_provided, &input_consumed,
				    &in_params, &is_input_ext);
		break;
	case TEE_TYPE_DES3:
		res = TA_des_update(&operation, &input, &output, &keyblob_out_size,
				    input_provided, &input_consumed, &is_input_ext);
		break;
	case TEE_TYPE_RSA_KEYPAIR:
		res = TA_rsa_update(&operation, &input, &output,
				    &keyblob_out_size, key_size,
				    &input_consumed, input_provided, obj_h);
		break;
	case TEE_TYPE_ECDSA_KEYPAIR:
	case TEE_TYPE_ECDH_KEYPAIR:
	case TEE_TYPE_ED25519_KEYPAIR:
	case TEE_TYPE_X25519_KEYPAIR:
		res = TA_ec_update(&operation, type, &input, &output,
				   &input_consumed, input_provided);
		break;
	default:/* HMAC */
		TEE_MACUpdate(*operation.operation, input.data,
			      input.data_length);
		input_consumed = input_provided;
	}
	if (res != KM_ERROR_OK) {
		EMSG("Update operation failed with error code %x", res);
		goto out;
	}

out:
	if (res == KM_ERROR_OK) {
		out += TA_serialize_blob_akms(out, out_end, &output, &oob);
		if (oob) {
			EMSG("Out of output buffer space");
			res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
			goto exit;
		}
		if (TA_is_out_of_bounds(out, out_end, SIZE_LENGTH_AKMS)) {
			EMSG("Out of output buffer space");
			res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
			goto exit;
		}
		TEE_MemMove(out, &input_consumed, SIZE_LENGTH_AKMS);
		out += SIZE_LENGTH_AKMS;
		out += TA_serialize_auth_set(out, out_end, &out_params, &oob);
		if (oob) {
			EMSG("Out of output buffer space");
			res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
			goto exit;
		}
		TA_update_operation(operation_handle, &operation);
	}

exit:
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	if (input.data && is_input_ext)
		TEE_Free(input.data);
	if (output.data)
		TEE_Free(output.data);
	if (obj_h != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(obj_h);
	if (key_material)
		TEE_Free(key_material);
	if (res != KM_ERROR_OK)
		TA_abort_operation(operation_handle);
	TA_free_params(&params_t);
	TA_free_params(&in_params);
	TA_free_params(&out_params);

	if (client_id.data)
		TEE_Free(client_id.data);
	if (app_data.data)
		TEE_Free(app_data.data);
	if (hidden)
		TEE_Free(hidden);

	return res;
}

/*
 * Finishes an ongoing operation started with begin, processing all of the
 * as-yet-unprocessed data provided by update(s)
 */
static keymaster_error_t TA_finish(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	uint8_t *out_end = NULL;
	size_t out_size = 0;
	keymaster_operation_handle_t operation_handle = 0; /* IN */
	keymaster_key_param_set_t in_params = EMPTY_PARAM_SET; /* IN */
	keymaster_blob_t input = EMPTY_BLOB; /* IN */
	keymaster_blob_t signature = EMPTY_BLOB; /* IN */
	keymaster_key_param_set_t out_params = EMPTY_PARAM_SET; /* OUT */
	keymaster_blob_t output = EMPTY_BLOB; /* OUT */
	uint8_t *key_material = NULL;
	uint32_t key_size = 0;
	uint32_t type = 0;
	uint32_t keyblob_out_size = 0;
	uint32_t tag_len = 0;
	keymaster_error_t res = KM_ERROR_OK;
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET;
	keymaster_operation_t operation = EMPTY_OPERATION;
	TEE_ObjectHandle obj_h = TEE_HANDLE_NULL;
	bool is_input_ext = false;
	bool oob = false; /* out of bounds flag */
	uint8_t* hidden = NULL;
	size_t hidden_size = 0;
	keymaster_blob_t client_id = EMPTY_BLOB;
	keymaster_blob_t app_data = EMPTY_BLOB;

	DMSG("%s %d", __func__, __LINE__);

	in = (uint8_t *)params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *)params[1].memref.buffer;
	out_size = (size_t)params[1].memref.size; /* limited to 8192 */
	out_end = out + out_size;
	out += sizeof(keymaster_error_t);

	in += TA_deserialize_op_handle(in, in_end, &operation_handle, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_blob_akms(in, in_end, &signature, false, &res,
				       false);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_auth_set(in, in_end, &in_params, false, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_blob_akms(in, in_end, &input, false, &res, true);
	if (res != KM_ERROR_OK)
		goto out;

	res = TA_get_operation(operation_handle, &operation);
	if (res != KM_ERROR_OK)
		goto out;
	key_material = TEE_Malloc(operation.key->key_material_size,
				  TEE_MALLOC_FILL_ZERO);
	if (!key_material) {
		EMSG("Failed to allocate memory for key_material");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}

	res = TA_build_hidden_info(&hidden, &hidden_size, &operation.client_id, &operation.app_data);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to serialize hidden info, res=%x", res);
		goto exit;
	}

	res = TA_restore_key(key_material, operation.key, &key_size,
				hidden, hidden_size, &type, false,
				&obj_h, &params_t);
	if (res != KM_ERROR_OK)
		goto out;
	if (operation.do_auth) {
		res = TA_do_auth(in_params, params_t, operation_handle);
		if (res != KM_ERROR_OK) {
			EMSG("Authentication failed");
			goto out;
		}
	}
	if (operation.purpose == KM_PURPOSE_SIGN) {
		res = TA_do_confirm(in_params, params_t);
		if (res != KM_ERROR_OK) {
			EMSG("Confirmation failed");
			goto out;
		}
	}
	if (type == TEE_TYPE_AES && operation.mode == KM_MODE_GCM)
		tag_len = operation.mac_length / 8; /* from bits to bytes */

	keyblob_out_size = TA_possibe_size(type, key_size, input, tag_len);
	output.data = TEE_Malloc(keyblob_out_size, TEE_MALLOC_FILL_ZERO);
	if (!output.data) {
		EMSG("Failed to allocate memory for output");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	switch (type) {
	case TEE_TYPE_AES:
		res = TA_aes_finish(&operation, &input, &output,
				    &keyblob_out_size, tag_len, &is_input_ext,
				    &in_params);
		break;
	case TEE_TYPE_DES3:
		res = TA_des_finish(&operation, &input, &output,
				    &keyblob_out_size, &is_input_ext);
		break;
	case TEE_TYPE_RSA_KEYPAIR:
		res = TA_rsa_finish(&operation, &input, &output,
				    &keyblob_out_size, key_size,
				    signature, obj_h, &is_input_ext);
		break;
	case TEE_TYPE_ECDSA_KEYPAIR:
	case TEE_TYPE_ECDH_KEYPAIR:
	case TEE_TYPE_ED25519_KEYPAIR:
	case TEE_TYPE_X25519_KEYPAIR:
		res = TA_ec_finish(&operation, type, &input, &output, &signature,
				   &keyblob_out_size, key_size, &is_input_ext);
		break;
	default: /* HMAC */
		if (operation.purpose == KM_PURPOSE_SIGN) {
			TEE_MACComputeFinal(*operation.operation, input.data,
					    input.data_length, output.data,
					    &keyblob_out_size);
			/* Trim out size to KM_TAG_MAC_LENGTH */
			if (operation.mac_length != UNDEFINED) {
				if (keyblob_out_size >
				    operation.mac_length / 8) {
					DMSG("Trim HMAC out size to %d",
					     operation.mac_length);
					keyblob_out_size =
						operation.mac_length / 8;
				}
			}
		} else { /* KM_PURPOSE_VERIFY */
			uint8_t computed_mac[TEE_MAX_HASH_SIZE];
			uint32_t computed_mac_size = TEE_MAX_HASH_SIZE;
			res = TEE_MACComputeFinal(*operation.operation,
						  input.data,
						  input.data_length,
						  computed_mac,
						  &computed_mac_size);
			if (res == TEE_SUCCESS) {
				if (computed_mac_size >= signature.data_length) {
					if (TEE_MemCompare(signature.data, computed_mac, signature.data_length) != 0) {
						res = TEE_ERROR_MAC_INVALID;
					}
				}
			}
			keyblob_out_size = 0;
			/* Convert error code to Android style */
			if (res == (int) TEE_ERROR_MAC_INVALID)
				res = KM_ERROR_VERIFICATION_FAILED;
		}
	}
	if (res != TEE_SUCCESS) {
		EMSG("Finish operation failed with error code %x", res);
		goto out;
	}
	output.data_length = keyblob_out_size;

out:
	if (res == KM_ERROR_OK) {
		out += TA_serialize_blob_akms(out, out_end, &output, &oob);
		if (oob) {
			EMSG("Out of output buffer space");
			res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
			goto exit;
		}
		out += TA_serialize_auth_set(out, out_end, &out_params, &oob);
		if (oob) {
			EMSG("Out of output buffer space");
			res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
			goto exit;
		}
	}

exit:
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	TA_abort_operation(operation_handle);
	if (input.data && is_input_ext)
		TEE_Free(input.data);
	if (output.data)
		TEE_Free(output.data);
	if (signature.data)
		TEE_Free(signature.data);
	if (obj_h != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(obj_h);
	if (key_material)
		TEE_Free(key_material);
	TA_free_params(&params_t);
	TA_free_params(&in_params);
	TA_free_params(&out_params);

	if (client_id.data)
		TEE_Free(client_id.data);
	if (app_data.data)
		TEE_Free(app_data.data);
	if (hidden)
		TEE_Free(hidden);

	return res;
}

/* Aborts the in-progress operation */
static keymaster_error_t TA_abort(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	keymaster_error_t res = KM_ERROR_OK;
	keymaster_operation_handle_t operation_handle = 0; /* IN */

	DMSG("%s %d", __func__, __LINE__);

	in = (uint8_t *)params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *)params[1].memref.buffer;
	out += sizeof(keymaster_error_t);

	in += TA_deserialize_op_handle(in, in_end, &operation_handle, &res);
	if (res != KM_ERROR_OK)
		goto out;
	res = TA_abort_operation(operation_handle);

out:
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;
	return res;
}

/* Imports wrapped key material into Keymaster hardware */
static keymaster_error_t TA_importWrappedKey(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *arg_in = NULL;
	uint8_t *arg_in_end = NULL;
	uint8_t *arg_out = NULL;
	uint8_t *arg_out_end = NULL;
	int64_t password_sid = 0;
	int64_t biometric_sid = 0;
	size_t auth_set_size = 0;
	bool oob = false;
	keymaster_operation_handle_t operation_handle = 0;
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET;
	keymaster_key_param_set_t wrapping_des_t = EMPTY_PARAM_SET;
	keymaster_key_param_set_t aes_params = EMPTY_PARAM_SET;
	keymaster_key_param_set_t finish_params_t = EMPTY_PARAM_SET;
	keymaster_key_format_t key_format = UNDEFINED;
	keymaster_key_format_t wrapped_key_fmt = UNDEFINED;
	keymaster_blob_t iv = EMPTY_BLOB;
	keymaster_blob_t tag = EMPTY_BLOB;
	keymaster_blob_t wrapped_key_description = EMPTY_BLOB;
	keymaster_key_blob_t transport_key = EMPTY_KEY_BLOB;
	keymaster_key_blob_t secure_key = EMPTY_KEY_BLOB;
	keymaster_key_blob_t transit_key = EMPTY_KEY_BLOB;
	keymaster_key_blob_t imported_aes_key = EMPTY_KEY_BLOB;
	keymaster_key_blob_t wrapped_key = EMPTY_KEY_BLOB;
	keymaster_key_blob_t wrapping_key = EMPTY_KEY_BLOB;
	keymaster_key_blob_t masking_key = EMPTY_KEY_BLOB;
	keymaster_key_param_set_t wrapping_params = EMPTY_PARAM_SET;
	keymaster_blob_t signature = EMPTY_BLOB;
	keymaster_error_t res = KM_ERROR_OK;
	keymaster_purpose_t op_purpose = KM_PURPOSE_WRAP_KEY;
	keymaster_blob_t secure_key_blob = EMPTY_BLOB;
	keymaster_blob_t secure_key_dec = EMPTY_BLOB;
	TEE_Param param_res[2] = { 0 };

	DMSG("%s %d", __func__, __LINE__);

	in = (uint8_t *)params[0].memref.buffer;
	in_end = in + params[0].memref.size;

	in += TA_deserialize_key_blob_akms(in, in_end, &wrapped_key, &res);
	if (res != KM_ERROR_OK) {
		DMSG("deserialize wrapped key blob failed");
		goto exit;
	}

	in += TA_deserialize_key_blob_akms(in, in_end, &wrapping_key, &res);
	if (res != KM_ERROR_OK) {
		DMSG("deserialize wrapping key blob failed");
		goto exit;
	}

	in += TA_deserialize_key_blob_akms(in, in_end, &masking_key, &res);
	if (res != KM_ERROR_OK) {
		DMSG("deserialize masking key blob failed");
		goto exit;
	}

	in += TA_deserialize_auth_set(in, in_end, &wrapping_params, false, &res);
	if (res != KM_ERROR_OK) {
		EMSG("deserialize wrapping_params failed");
		goto exit;
	}

	TEE_MemMove(&password_sid, in, sizeof(int64_t));
	in += sizeof(int64_t);
	TEE_MemMove(&biometric_sid, in, sizeof(int64_t));

	res = TA_decode_wrapped_key_sequence(wrapped_key.key_material,
			wrapped_key.key_material_size,
			&params_t,
			&iv,
			&tag,
			&transit_key,
			&secure_key,
			&wrapped_key_fmt,
			&wrapped_key_description);
	if (res != KM_ERROR_OK) {
		EMSG("TA_decode_wrapped_key_sequence failed, res=%x", res);
		goto exit;
	}

	res = TA_check_secure_id(&params_t, password_sid, biometric_sid);
	if (res != KM_ERROR_OK) {
		EMSG("TA_check_secure_id failed, res=%x", res);
		goto exit;
	}

	/*Decryt transport key by using the begin & finish process*/
	param_res[0].memref.buffer = TEE_Malloc(UNWRAPKEY_BUFFER_SIZE,
										TEE_MALLOC_FILL_ZERO);
	param_res[0].memref.size = UNWRAPKEY_BUFFER_SIZE;
	if (!param_res[0].memref.buffer) {
		EMSG("Failed to allocate memory for param_res in buffer");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}

	param_res[1].memref.buffer = TEE_Malloc(UNWRAPKEY_BUFFER_SIZE,
										TEE_MALLOC_FILL_ZERO);
	param_res[1].memref.size = UNWRAPKEY_BUFFER_SIZE;
	if (!param_res[1].memref.buffer) {
		EMSG("Failed to allocate memory for param_res out buffer");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}

	arg_in = (uint8_t *) param_res[0].memref.buffer;
	arg_in_end = arg_in + param_res[0].memref.size;

	TEE_MemMove(arg_in, &op_purpose, sizeof(keymaster_purpose_t));
	arg_in += sizeof(keymaster_purpose_t);
	arg_in += TA_serialize_key_blob_akms(arg_in, arg_in_end, &wrapping_key, &oob);
	if (oob) {
		EMSG("Out of input buffer space");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto exit;
	}
	arg_in += TA_serialize_auth_set(arg_in, arg_in_end, &wrapping_params, &oob);
	if (oob) {
		EMSG("Out of input buffer space");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto exit;
	}

	DMSG("begin decrypt the transport key");
	res = TA_begin(param_res);
	if (res != KM_ERROR_OK) {
		EMSG("TA_begin failed, res=%x", res);
		goto exit;
	}

	TEE_MemMove(&operation_handle,
				(uint8_t *)param_res[1].memref.buffer + sizeof(keymaster_error_t),
				sizeof(keymaster_operation_handle_t));

	TEE_MemFill(param_res[0].memref.buffer, 0, UNWRAPKEY_BUFFER_SIZE);
	TEE_MemFill(param_res[1].memref.buffer, 0, UNWRAPKEY_BUFFER_SIZE);
	param_res[0].memref.size = UNWRAPKEY_BUFFER_SIZE;
	param_res[1].memref.size = UNWRAPKEY_BUFFER_SIZE;
	arg_in = (uint8_t *) param_res[0].memref.buffer;
	arg_in_end = (uint8_t *) (arg_in + param_res[0].memref.size);

	TEE_MemMove(arg_in, &operation_handle, sizeof(keymaster_operation_handle_t));
	arg_in += sizeof(keymaster_operation_handle_t);

	arg_in += TA_serialize_blob_akms(arg_in, arg_in_end, &signature, &oob);
	if (oob) {
		EMSG("Out of input buffer space");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto exit;
	}

	arg_in += TA_serialize_auth_set(arg_in, arg_in_end, &finish_params_t, &oob);
	if (oob) {
		EMSG("Out of input buffer space");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto exit;
	}

	arg_in += TA_serialize_key_blob_akms(arg_in, arg_in_end, &transit_key, &oob);
	if (oob) {
		EMSG("Out of input buffer space");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto exit;
	}

	res = TA_finish(param_res);
	if (res != KM_ERROR_OK) {
		EMSG("TA_finish failed, res=%x", res);
		goto exit;
	}
	DMSG("TA_finish decrypt transport key successfully");

	/* Decryt transport key finished, import it now, so we can use it to decrypt
	 * wrapped key*/
	arg_out = (uint8_t *)param_res[1].memref.buffer;
	arg_out_end = (uint8_t *)param_res[1].memref.buffer + param_res[1].memref.size;
	arg_out += sizeof(keymaster_error_t);

	TA_deserialize_key_blob_akms(arg_out, arg_out_end, &transport_key, &res);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to deserialize transport_key, res=%x", res);
		goto exit;
	}

	if (masking_key.key_material_size != transport_key.key_material_size) {
		EMSG("masking_key.key_material_size != transport_key.key_material_size");
		res = KM_ERROR_INVALID_INPUT_LENGTH;
		goto exit;
	}

	for (size_t k = 0; k < transport_key.key_material_size; k++)
		transport_key.key_material[k] ^= masking_key.key_material[k];

	if ((res = TA_construct_transport_key_params(&aes_params)) != KM_ERROR_OK)
	{
		EMSG("TA_construct_transport_key_params failed(%d)", res);
		goto exit;
	}

	TEE_MemFill(param_res[0].memref.buffer, 0, UNWRAPKEY_BUFFER_SIZE);
	TEE_MemFill(param_res[1].memref.buffer, 0, UNWRAPKEY_BUFFER_SIZE);
	param_res[0].memref.size = UNWRAPKEY_BUFFER_SIZE;
	param_res[1].memref.size = UNWRAPKEY_BUFFER_SIZE;
	arg_in = (uint8_t *) param_res[0].memref.buffer;
	arg_in_end = (uint8_t *) (arg_in + param_res[0].memref.size);

	arg_in += TA_serialize_auth_set(arg_in, arg_in_end, &aes_params, &oob);
	if (oob) {
		DMSG("TA_serialize_auth_set failed");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto exit;
	}

	key_format = KM_KEY_FORMAT_RAW;
	TEE_MemMove(arg_in, &key_format, sizeof(keymaster_key_format_t));
	arg_in += sizeof(keymaster_key_format_t);

	arg_in += TA_serialize_key_blob_akms(arg_in, arg_in_end, &transport_key, &oob);
	if (oob) {
		EMSG("Out of input buffer space");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto exit;
	}

	res = TA_importKey(param_res);
	if (res != KM_ERROR_OK) {
		EMSG("import the transport key failed(ret=%d)", res);
		goto exit;
	}

	/*Import the transport key finished, now use it to decrypt the wrapped key*/
	arg_out = (uint8_t *)param_res[1].memref.buffer;
	arg_out_end = (uint8_t *)param_res[1].memref.buffer + param_res[1].memref.size;
	arg_out += sizeof(keymaster_error_t);
	TA_deserialize_key_blob_akms(arg_out, arg_out_end, &imported_aes_key, &res);
	if (res != KM_ERROR_OK) {
		DMSG("deserialize the imported transport key blob failed");
		goto exit;
	}

	TEE_MemFill(param_res[0].memref.buffer, 0, UNWRAPKEY_BUFFER_SIZE);
	TEE_MemFill(param_res[1].memref.buffer, 0, UNWRAPKEY_BUFFER_SIZE);
	param_res[0].memref.size = UNWRAPKEY_BUFFER_SIZE;
	param_res[1].memref.size = UNWRAPKEY_BUFFER_SIZE;
	arg_in = (uint8_t *) param_res[0].memref.buffer;
	arg_in_end = (uint8_t *) (arg_in + param_res[0].memref.size);

	op_purpose = KM_PURPOSE_DECRYPT;
	TEE_MemMove(arg_in, &op_purpose, sizeof(keymaster_purpose_t));
	arg_in += sizeof(keymaster_purpose_t);
	arg_in += TA_serialize_key_blob_akms(arg_in, arg_in_end, &imported_aes_key, &oob);
	if (oob) {
		EMSG("Out of input buffer space");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto exit;
	}

	aes_params.params[4].tag = KM_TAG_NONCE;
	aes_params.params[4].key_param.blob = iv;
	iv.data = NULL;
	arg_in += TA_serialize_auth_set(arg_in, arg_in_end, &aes_params, &oob);
	if (oob) {
		EMSG("Out of input buffer space");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto exit;
	}

	DMSG("begin decrypt the encrypted secure key");
	res = TA_begin(param_res);
	if (res != KM_ERROR_OK) {
		EMSG("TA_begin failed, res=%x", res);
		goto exit;
	}

	TEE_MemMove(&operation_handle,
			(uint8_t *)param_res[1].memref.buffer + sizeof(keymaster_error_t),
			sizeof(keymaster_operation_handle_t));

	TEE_MemFill(param_res[0].memref.buffer, 0, UNWRAPKEY_BUFFER_SIZE);
	TEE_MemFill(param_res[1].memref.buffer, 0, UNWRAPKEY_BUFFER_SIZE);
	param_res[0].memref.size = UNWRAPKEY_BUFFER_SIZE;
	param_res[1].memref.size = UNWRAPKEY_BUFFER_SIZE;
	arg_in = (uint8_t *) param_res[0].memref.buffer;
	arg_in_end = arg_in + param_res[0].memref.size;

	TEE_MemMove(arg_in, &operation_handle, sizeof(keymaster_operation_handle_t));
	arg_in += sizeof(keymaster_operation_handle_t);

	arg_in += TA_serialize_blob_akms(arg_in, arg_in_end, &signature, &oob);
	if (oob) {
		EMSG("Out of input buffer space");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto exit;
	}

	finish_params_t.length = 1;
	auth_set_size = 0;
	if (MUL_OVERFLOW(sizeof(keymaster_key_param_t), finish_params_t.length, &auth_set_size)) {
		EMSG("Overflow: too many key params! Abort!");
		res = KM_ERROR_INVALID_INPUT_LENGTH;
		goto exit;
	}

	finish_params_t.params = TEE_Malloc(auth_set_size, TEE_MALLOC_FILL_ZERO);
	if (!finish_params_t.params) {
		EMSG("Failed to allocate memory for params");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}

	finish_params_t.params[0].tag = KM_TAG_ASSOCIATED_DATA;
	finish_params_t.params[0].key_param.blob = wrapped_key_description;
	wrapped_key_description.data = NULL;
	arg_in += TA_serialize_auth_set(arg_in, arg_in_end, &finish_params_t, &oob);
	if (oob) {
		EMSG("Out of input buffer space");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto exit;
	}

	secure_key_blob.data_length = secure_key.key_material_size + tag.data_length;
	secure_key_blob.data = TEE_Malloc(secure_key_blob.data_length, TEE_MALLOC_FILL_ZERO);
	if (!secure_key_blob.data) {
		EMSG("Failed to allocate memory for secure_key_blob");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}
	TEE_MemMove(secure_key_blob.data, secure_key.key_material, secure_key.key_material_size);
	TEE_MemMove(secure_key_blob.data + secure_key.key_material_size,
					tag.data, tag.data_length);

	arg_in += TA_serialize_blob_akms(arg_in, arg_in_end, &secure_key_blob, &oob);
	if (oob) {
		EMSG("Out of input buffer space");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto exit;
	}

	res = TA_finish(param_res);
	if (res != KM_ERROR_OK) {
		EMSG("TA_finish failed, res=%x", res);
		goto exit;
	}

	DMSG("TA_finish decrypt secure key successfully");

	/*The wrapped key is decrypted successfuly, now import this key*/
	arg_out = (uint8_t *)param_res[1].memref.buffer;
	arg_out_end = (uint8_t *)param_res[1].memref.buffer + param_res[1].memref.size;
	arg_out += sizeof(keymaster_error_t);
	TA_deserialize_blob_akms(arg_out, arg_out_end, &secure_key_dec, false, &res, false);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to deserialize secure_key_dec, res=%x", res);
		goto exit;
	}

	TEE_MemFill(param_res[0].memref.buffer, 0, UNWRAPKEY_BUFFER_SIZE);
	TEE_MemFill(param_res[1].memref.buffer, 0, UNWRAPKEY_BUFFER_SIZE);
	param_res[0].memref.size = UNWRAPKEY_BUFFER_SIZE;
	param_res[1].memref.size = UNWRAPKEY_BUFFER_SIZE;
	arg_in = (uint8_t *) param_res[0].memref.buffer;
	arg_in_end = arg_in + param_res[0].memref.size;
	arg_in += TA_serialize_auth_set(arg_in, arg_in_end, &params_t, &oob);
	if (oob) {
		EMSG("TA_serialize_auth_set failed");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto exit;
	}

	TEE_MemMove(arg_in, &wrapped_key_fmt, sizeof(keymaster_key_format_t));
	arg_in += sizeof(keymaster_key_format_t);

	arg_in += TA_serialize_blob_akms(arg_in, arg_in_end, &secure_key_dec, &oob);
	if (oob) {
		EMSG("Out of input buffer space");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto exit;
	}

	res = TA_importKey(param_res);
	if (res != KM_ERROR_OK) {
		EMSG("TA_importkey in importwrapedkey failed(ret=%d)", res);
		goto exit;
	}

	if (param_res[1].memref.size > params[1].memref.size)
	{
		EMSG("The importwrappedkey params out size is too small");
		goto exit;
	}

	/*wrapped key is decrypted successfuly, now import this key*/
	TEE_MemMove(params[1].memref.buffer,
				param_res[1].memref.buffer, param_res[1].memref.size);

	DMSG("Import the wrapped key successfully");

exit:
	TA_free_params(&params_t);
	TA_free_params(&wrapping_des_t);
	TA_free_params(&aes_params);
	TA_free_params(&finish_params_t);
	TA_free_params(&wrapping_params);
	if (iv.data)
		TEE_Free(iv.data);
	if (tag.data)
		TEE_Free(tag.data);
	if (signature.data)
		TEE_Free(signature.data);
	if (secure_key_blob.data)
		TEE_Free(secure_key_blob.data);
	if (secure_key_dec.data)
		TEE_Free(secure_key_dec.data);
	if (wrapped_key_description.data)
		TEE_Free(wrapped_key_description.data);
	if (secure_key.key_material)
		TEE_Free(secure_key.key_material);
	if (transport_key.key_material)
		TEE_Free(transport_key.key_material);
	if (transit_key.key_material)
		TEE_Free(transit_key.key_material);
	if (imported_aes_key.key_material)
		TEE_Free(imported_aes_key.key_material);
	if (wrapped_key.key_material)
		TEE_Free(wrapped_key.key_material);
	if (wrapping_key.key_material)
		TEE_Free(wrapping_key.key_material);
	if (masking_key.key_material)
		TEE_Free(masking_key.key_material);
	if (param_res[0].memref.buffer)
		TEE_Free(param_res[0].memref.buffer);
	if (param_res[1].memref.buffer)
		TEE_Free(param_res[1].memref.buffer);

	return res;
}

static keymaster_error_t TA_earlyBootEnded()
{
	keymaster_error_t res = KM_ERROR_OK;
	g_isEarlyBootEnded = true;

	if ((res = TA_configure_rot_info(KM_EARLY_BOOT_SET, 1)))
		DMSG("Configure KM_EARLY_BOOT_SET to rot failed");

	return res;
}

static keymaster_error_t TA_getRootOfTrust(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	uint8_t *out_end = NULL;
	size_t out_size = 0;
	keymaster_blob_t challenge = EMPTY_BLOB; /* IN */
	keymaster_blob_t maced_root_of_trust = EMPTY_BLOB;
	keymaster_blob_t root_of_trust = EMPTY_BLOB; /* OUT */
	keymaster_error_t error = KM_ERROR_OK;
	cbor_item_t *root_of_trust_tag = NULL;
	cbor_item_t *root_of_trust_array = NULL;
	uint8_t *root_of_trust_data = NULL;
	size_t root_of_trust_size = 0;
	bool result = false;
	bool device_locked = false;
	cbor_item_t *maced_root_of_trust_deserialize = NULL;
	struct cbor_load_result load_result = { 0 };
	cbor_item_t *cose_mac0_semantic_tag = NULL;
	uint8_t *root_of_trust_data_serialize = NULL;
	size_t root_of_trust_size_serialize = 0;
	bool oob = false; /* out of bounds flag */

	DMSG("%s %d", __func__, __LINE__);

	in = (uint8_t *)params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *)params[1].memref.buffer;
	out_size = (size_t)params[1].memref.size; /* limited to 8192 */
	out_end = out + out_size;
	out += sizeof(keymaster_error_t);

	in += TA_deserialize_blob_akms(in, in_end, &challenge, false, &error,
			false);
	if (error != KM_ERROR_OK)
		goto exit;

	/* set rot data if not */
	if (!optee_km_context.rot_info_set) {
		error = TA_get_rot_data();
		if (error != KM_ERROR_OK && error != KM_ERROR_ROOT_OF_TRUST_ALREADY_SET) {
			EMSG("Failed(%d) to get root of trust data", error);
			goto exit;
		}
		optee_km_context.rot_info_set = true;
	}

	root_of_trust_array = cbor_new_definite_array(5);
	if (!root_of_trust_array) {
		EMSG("Failed to allocate memory for root_of_trust_array");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}
	result = cbor_array_push(root_of_trust_array,
			cbor_move(cbor_build_bytestring(optee_km_context.rot.rot_data.keyHash256, optee_km_context.rot.rot_data.keySize)));
	if (!optee_km_context.rot.rot_data.deviceLocked) {
		device_locked = false;
	} else {
		device_locked = true;
	}
	result &= cbor_array_push(root_of_trust_array,
			cbor_move(cbor_build_bool(device_locked)));
	result &= cbor_array_push(root_of_trust_array,
			cbor_move(cbor_build_uint8(optee_km_context.rot.rot_data.verifiedBootState)));
	result &= cbor_array_push(root_of_trust_array,
			cbor_move(cbor_build_bytestring(optee_km_context.rot.rot_data.vbmetaDigest, optee_km_context.rot.rot_data.digestSize)));
	result &= cbor_array_push(root_of_trust_array,
			cbor_move(cbor_build_uint8(optee_km_context.boot_patchlevel)));
	if (!result) {
		EMSG("Failed to push items to root_of_trust_array");
		error = KM_ERROR_UNKNOWN_ERROR;
		goto exit;
	}

	root_of_trust_tag = cbor_build_tag(k_rot_version1, cbor_move(root_of_trust_array));
	if (!root_of_trust_tag) {
		EMSG("Failed to build tag for root_of_trust_tag");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}
	cbor_serialize_alloc(root_of_trust_tag, &root_of_trust_data, &root_of_trust_size);
	error = TA_construct_cose_mac0(challenge.data,
				       challenge.data_length,
				       root_of_trust_data,
				       root_of_trust_size,
				       &maced_root_of_trust.data,
				       &maced_root_of_trust.data_length);
	if (error != KM_ERROR_OK) {
		EMSG("maced challenge and root of trust data failed, error=%x", error);
		goto exit;
	}
	maced_root_of_trust_deserialize = cbor_load(maced_root_of_trust.data,
						    maced_root_of_trust.data_length,
						    &load_result);
	if (!maced_root_of_trust_deserialize) {
		EMSG("Failed to deserialize maced_root_of_trust.data");
		error = KM_ERROR_UNKNOWN_ERROR;
		goto exit;
	}

	cose_mac0_semantic_tag = cbor_build_tag(k_cose_mac0_semantic_tag, cbor_move(maced_root_of_trust_deserialize));
	if (!cose_mac0_semantic_tag) {
		EMSG("Failed to build tag for cose_mac0_semantic_tag");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}
	cbor_serialize_alloc(cose_mac0_semantic_tag, &root_of_trust_data_serialize, &root_of_trust_size_serialize);
	if (root_of_trust_data_serialize) {
		root_of_trust.data = root_of_trust_data_serialize;
		root_of_trust.data_length = root_of_trust_size_serialize;
		if (error == KM_ERROR_OK) {
			out += TA_serialize_blob_akms(out, out_end, &root_of_trust,
					&oob);
			if (oob) {
				EMSG("Out of output buffer space");
				error = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
				goto exit;
			}
		}
	}
exit:
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	if (challenge.data)
		TEE_Free(challenge.data);
	if (maced_root_of_trust.data)
		TEE_Free(maced_root_of_trust.data);
	if (root_of_trust_array)
		cbor_decref(&root_of_trust_array);
	if (root_of_trust_tag)
		cbor_decref(&root_of_trust_tag);
	if (root_of_trust_data)
		free(root_of_trust_data);
	if (maced_root_of_trust_deserialize)
		cbor_decref(&maced_root_of_trust_deserialize);
	if (cose_mac0_semantic_tag)
		cbor_decref(&cose_mac0_semantic_tag);
	if (root_of_trust_data_serialize)
		free(root_of_trust_data_serialize);

	return error;
}

static keymaster_error_t TA_generateRkpKey(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	uint8_t *out_end = NULL;
	size_t out_size = 0;
	uint8_t *key_material = NULL;
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET; /* IN */
	keymaster_key_blob_t key_blob = EMPTY_KEY_BLOB; /* OUT */
	keymaster_key_characteristics_t characts = EMPTY_CHARACTS; /* OUT */
	keymaster_algorithm_t key_algorithm = UNDEFINED;
	keymaster_error_t error = KM_ERROR_OK;
	keymaster_digest_t key_digest = UNDEFINED;
	uint32_t key_buffer_size = 0; /* For serialization of generated key */
	uint32_t characts_size = 0;
	uint32_t key_size = UNDEFINED;
	uint64_t key_rsa_public_exponent = UNDEFINED;
	uint32_t os_version = 0xFFFFFFFF;
	uint32_t os_patchlevel = 0xFFFFFFFF;
	uint32_t vendor_patchlevel = 0xFFFFFFFF;
	uint32_t boot_patchlevel = 0xFFFFFFFF;
	bool test_mode = false;
	bool oob = false; /* out of bounds flag */
	bool attest_purpose = false;
	bool key_agree_purpose = false;
	size_t num_params = 0;
	uint8_t* hidden = NULL;
	size_t hidden_size = 0;
	keymaster_blob_t client_id = EMPTY_BLOB;
	keymaster_blob_t app_data = EMPTY_BLOB;
	TEE_ObjectHandle obj_h = TEE_HANDLE_NULL;
	TEE_Attribute *attrs_in = NULL;
	uint32_t attrs_in_count = 1;
	keymaster_blob_t ec_cert = EMPTY_BLOB; //EC certificate
	uint8_t *x_coordinate = NULL;
	uint8_t *y_coordinate = NULL;
	cbor_item_t *cose_public_key_map = NULL;
	uint8_t *cose_public_key = NULL;
	size_t cose_public_key_size = 0;
	keymaster_blob_t maced_public_key = EMPTY_BLOB;
	size_t serialize_size = 0;
	bool result = false;
	keymaster_blob_t *challenge = NULL;
	bool early_boot_only = false;
	keymaster_ec_curve_t ec_curve = KM_EC_CURVE_UNKNOWN;
	bool is_ed25519 = false;

	DMSG("%s %d", __func__, __LINE__);

	in = (uint8_t *)params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *)params[1].memref.buffer;
	out_size = (size_t)params[1].memref.size; /* limited to 8192 */
	out_end = out + out_size;
	out += sizeof(keymaster_error_t);

	if (TA_is_out_of_bounds(in, in_end, sizeof(test_mode))) {
		EMSG("Out of input array bounds on deserialization");
		error = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto out;
	}
	TEE_MemMove(&test_mode, in, sizeof(test_mode));
	in += sizeof(test_mode);
	if (optee_km_rpk_hwinfo.version >= k_rkp_version_without_super_encryption && test_mode) {
		EMSG("Key generation for test mode on version 3 is not supported");
		error = KM_ERROR_UNSUPPORTED_KEY_SIZE;
		goto out;
	}

	/* Do +6 to params count to have memory for
	 * adding KM_TAG_ORIGIN params and key size with RSA
	 * public exponent on import
	 */
	if (MUL_OVERFLOW(sizeof(keymaster_key_param_t),
		ecdsap256_key_param_set.length + ADDITIONAL_TAGS, &num_params)) {
		EMSG("Overflow: too many key params! Abort!");
		error = KM_ERROR_INVALID_INPUT_LENGTH;
		goto out;
	}
	params_t.params = TEE_Malloc(num_params, TEE_MALLOC_FILL_ZERO);
	/* Freed when deserialized params set is destroyed by caller */
	if (!params_t.params) {
		EMSG("Failed to allocate memory for params");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	for (size_t i = 0; i < ecdsap256_key_param_set.length; i++) {
		TA_push_param(&params_t, &ecdsap256_key_param_set.params[i]);
	}

	/*
	 * Need add os version and patchlevel to key_description,
	 * attest_key will check thess sections.
	 * optee add these values in hal and pass to ta.
	 */
	os_version = tee_get_os_version();
	os_patchlevel = tee_get_os_patchlevel();
	vendor_patchlevel = tee_get_vendor_patchlevel();
	boot_patchlevel = tee_get_boot_patchlevel();

	/* Add additional parameters */
	TA_add_origin(&params_t, KM_ORIGIN_GENERATED, true);
	TA_add_creation_datetime(&params_t, true);
	TA_add_version_patchlevel(&params_t, os_version, os_patchlevel,
				vendor_patchlevel, boot_patchlevel);

	/* Parse mandatory and optional parameters */
	error = TA_parse_params(params_t, &key_algorithm, &key_size,
			    &key_rsa_public_exponent, &ec_curve, &is_ed25519, &key_digest,
				&attest_purpose, &key_agree_purpose, &challenge, false,
				&early_boot_only);
	if (error != KM_ERROR_OK)
		goto exit;

	if (key_size == UNDEFINED) {
		EMSG("Key size must be specified");
		error = KM_ERROR_UNSUPPORTED_KEY_SIZE;
		goto exit;
	}

	if (key_algorithm == KM_ALGORITHM_RSA && key_rsa_public_exponent == UNDEFINED) {
		EMSG("RSA public exponent is missed");
		error = KM_ERROR_INVALID_ARGUMENT;
		goto exit;
	}

	if (key_algorithm == KM_ALGORITHM_EC) {
		DMSG("key_algorithm == KM_ALGORITHM_EC");
		TA_add_ec_curve(&params_t, key_size, is_ed25519);
	}

	DMSG("key_algorithm=%d key_rsa_public_exponent=%lu", key_algorithm,
	     key_rsa_public_exponent);

	/*
	 * Newly-generated key's characteristics divided appropriately
	 * into hardware-enforced and software-enforced lists
	 * (except APPLICATION_ID and APPLICATION_DATA)
	 */
	error = TA_fill_characteristics(&characts, &params_t, &characts_size);
	if (error != KM_ERROR_OK)
		goto exit;

	key_buffer_size = TA_get_key_size(key_algorithm);

	key_blob.key_material_size = characts_size + key_buffer_size + TAG_LENGTH;

	key_material = TEE_Malloc(key_blob.key_material_size, TEE_MALLOC_FILL_ZERO);
	if (!key_material) {
		EMSG("Failed to allocate memory for key_material");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}
	error = TA_generate_key(key_algorithm, key_size, key_material, key_digest,
				key_rsa_public_exponent, ec_curve, is_ed25519, false,
				key_agree_purpose, &obj_h, &attrs_in);
	if (error != KM_ERROR_OK) {
		EMSG("Failed to generate key, error=%x", error);
		goto exit;
	}

	error = mbedTLS_gen_root_cert_ecc(obj_h, &ec_cert);
	if (error != TEE_SUCCESS) {
		EMSG("Failed to generate EC certificate, error=%x", error);
		goto exit;
	}

	TA_serialize_param_set(key_material + key_buffer_size,
			       key_material + key_blob.key_material_size, &params_t, &oob);
	if (oob) {
		EMSG("Out of output buffer space");
		error = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto exit;
	}

	error = TA_get_client_info(&params_t, &client_id, &app_data);
	if (error != KM_ERROR_OK) {
		EMSG("Failed to get client info, res=%x", error);
		goto exit;
	}

	error = TA_build_hidden_info(&hidden, &hidden_size, &client_id, &app_data);
	if (error != KM_ERROR_OK) {
		EMSG("Failed to serialize hidden info, res=%x", error);
		goto exit;
	}

	error = TA_encrypt(key_material, key_blob.key_material_size,
			   hidden, hidden_size);
	if (error != KM_ERROR_OK) {
		EMSG("Failed to encrypt key blob, error=%x", error);
		goto exit;
	}
	key_blob.key_material = key_material;

	x_coordinate = TEE_Malloc(K_P256_AFFINE_POINT_SIZE, TEE_MALLOC_FILL_ZERO);
	y_coordinate = TEE_Malloc(K_P256_AFFINE_POINT_SIZE, TEE_MALLOC_FILL_ZERO);
	if (!x_coordinate || !y_coordinate) {
		EMSG("Failed to allocate memory for x_coordinate and y_coordinate");
		error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}

        error = mbedTLS_get_ecdsa256_key_from_cert(&ec_cert,
						   x_coordinate,
						   K_P256_AFFINE_POINT_SIZE,
						   y_coordinate,
						   K_P256_AFFINE_POINT_SIZE);
	if (error != KM_ERROR_OK) {
		EMSG("Failed to get ecdsa256 key from certificate, error=%x", error);
		goto exit;
	}

	cose_public_key_map = cbor_new_definite_map(5);
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
	if (serialize_size > 0) {
		error = TA_construct_cose_mac0(NULL,
					       0,
					       cose_public_key,
					       cose_public_key_size,
					       &maced_public_key.data,
					       &maced_public_key.data_length);
		if (error != KM_ERROR_OK) {
			EMSG("maced ECDSA P256 public key failed, error=%x", error);
			goto out;
		}
	}

exit:
	if (error == KM_ERROR_OK) {
		out += TA_serialize_key_blob_akms(out, out_end, &key_blob, &oob);
		if (oob) {
			EMSG("Out of output buffer space");
			error = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
			goto out;
		}
		out += TA_serialize_blob_akms(out, out_end, &maced_public_key, &oob);
		if (oob) {
			EMSG("Out of output buffer space");
			error = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
			goto out;
		}
	}
out:
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	if (ec_cert.data)
		TEE_Free(ec_cert.data);
	if (obj_h != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(obj_h);
	free_attrs(attrs_in, attrs_in_count);

	if (x_coordinate)
		TEE_Free(x_coordinate);
	if (y_coordinate)
		TEE_Free(y_coordinate);

	if (maced_public_key.data)
		TEE_Free(maced_public_key.data);
	if (cose_public_key)
		free(cose_public_key);
	if (cose_public_key_map)
		cbor_decref(&cose_public_key_map);

	if (key_material)
		TEE_Free(key_material);
	TA_free_params(&characts.sw_enforced);
	TA_free_params(&characts.hw_enforced);
	TA_free_params(&params_t);

	if (client_id.data)
		TEE_Free(client_id.data);
	if (app_data.data)
		TEE_Free(app_data.data);
	if (hidden)
		TEE_Free(hidden);
	return error;
}

static keymaster_error_t TA_generateCsr(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *out = NULL;
	keymaster_error_t res = K_STATUS_REMOVED;

	out = (uint8_t *)params[1].memref.buffer;
	out += sizeof(keymaster_error_t);

	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	return res;
}

static keymaster_error_t TA_getHwInfo(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *out = NULL;
	uint8_t *out_end = NULL;
	size_t out_size = 0;
	keymaster_error_t res = KM_ERROR_OK;
	uint32_t data_length = 0;

	DMSG("%s %d", __func__, __LINE__);

	out = (uint8_t *)params[1].memref.buffer;
	out_size = (size_t)params[1].memref.size; /* limited to 8192 */
	out_end = out + out_size;
	out += sizeof(keymaster_error_t);

	data_length = sizeof(optee_km_rpk_hwinfo.version) +
		      sizeof(data_length) +
		      strlen(optee_km_rpk_hwinfo.rpc_author_name) +
		      sizeof(optee_km_rpk_hwinfo.supported_eek_curve) +
		      sizeof(data_length) +
		      strlen(optee_km_rpk_hwinfo.unique_id) +
		      sizeof(optee_km_rpk_hwinfo.supported_num_keys_in_csr);
	if (TA_is_out_of_bounds(out, out_end, data_length)) {
		EMSG("Out of output array bounds on serialization");
		return KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
	}

	TEE_MemMove(out, &optee_km_rpk_hwinfo.version, sizeof(optee_km_rpk_hwinfo.version));
	out += sizeof(optee_km_rpk_hwinfo.version);

	data_length = strlen(optee_km_rpk_hwinfo.rpc_author_name);
	TEE_MemMove(out, &data_length, sizeof(data_length));
	out += sizeof(data_length);
	TEE_MemMove(out, optee_km_rpk_hwinfo.rpc_author_name, data_length);
	out += data_length;

	TEE_MemMove(out, &optee_km_rpk_hwinfo.supported_eek_curve,
		    sizeof(optee_km_rpk_hwinfo.supported_eek_curve));
	out += sizeof(optee_km_rpk_hwinfo.supported_eek_curve);

	data_length = strlen(optee_km_rpk_hwinfo.unique_id);
	TEE_MemMove(out, &data_length, sizeof(data_length));
	out += sizeof(data_length);
	TEE_MemMove(out, optee_km_rpk_hwinfo.unique_id, data_length);
	out += data_length;

	TEE_MemMove(out, &optee_km_rpk_hwinfo.supported_num_keys_in_csr,
		    sizeof(optee_km_rpk_hwinfo.supported_num_keys_in_csr));
	out += sizeof(optee_km_rpk_hwinfo.supported_num_keys_in_csr);

	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;
	DMSG("HW info: \n");
	DHEXDUMP(params[1].memref.buffer, params[1].memref.size);\

	return res;
}

static keymaster_error_t TA_generateCsrV2(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	uint8_t *out_end = NULL;
	size_t out_size = 0;
	uint32_t num_keys = 0;
	keymaster_blob_t *keys_to_sign_array = NULL;
	keymaster_blob_t challenge = EMPTY_BLOB;
	cbor_item_t *pubkeys = NULL;
	keymaster_blob_t csr = EMPTY_BLOB;
	keymaster_error_t res = KM_ERROR_OK;
	bool oob = false; /* out of bounds flag */

	DMSG("%s %d", __func__, __LINE__);

	in = (uint8_t *)params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *)params[1].memref.buffer;
	out_size = (size_t)params[1].memref.size; /* limited to 8192 */
	out_end = out + out_size;
	out += sizeof(keymaster_error_t);

	/* Size of num_keys (uint32_t) */
	if (TA_is_out_of_bounds(in, in_end, sizeof(num_keys))) {
		EMSG("Out of input array bounds on deserialization");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto out;
	}
	TEE_MemMove(&num_keys, in, sizeof(num_keys));
	in += SIZE_LENGTH_AKMS;

	DMSG("num_keys: %d", num_keys);
	if (num_keys > 0) {
		keys_to_sign_array = TEE_Malloc(sizeof(keymaster_blob_t) * num_keys, TEE_MALLOC_FILL_ZERO);
		if (!keys_to_sign_array) {
			EMSG("Failed to allocate memory for keys_to_sign_array");
			res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
			goto out;
		}

		for (size_t i = 0; i < num_keys; i++) {
			in += TA_deserialize_blob_akms(in, in_end, &keys_to_sign_array[i], false, &res, false);
			if (res != KM_ERROR_OK)
				goto out;
		}
	}
	in += TA_deserialize_blob_akms(in, in_end, &challenge, false, &res, false);
	if (res != KM_ERROR_OK)
		goto out;

	if (challenge.data_length > K_MAX_CHALLENGE_SIZE_V2) {
		EMSG("Challenge is too large. %d expected. %zu actual.", K_MAX_CHALLENGE_SIZE_V2, challenge.data_length);
		res = K_STATUS_FAILED;
		goto out;
	}

	res = TA_validate_and_extract_pubkeys(false, num_keys, keys_to_sign_array, &pubkeys);
	if (res != KM_ERROR_OK || !pubkeys) {
		EMSG("Failed to validate and extract the public keys for the CSR");
		goto out;
	}

	/* set rot data if not */
	if (!optee_km_context.rot_info_set) {
		res = TA_get_rot_data();
		if (res != KM_ERROR_OK && res != KM_ERROR_ROOT_OF_TRUST_ALREADY_SET) {
			EMSG("Failed(%d) to get root of trust data", res);
			goto out;
		}
		optee_km_context.rot_info_set = true;
	}

	/* set DICE CDI data if not */
	res = TA_get_dice_data();
	if (res != KM_ERROR_OK) {
		EMSG("Failed(%d) to get DICE certificate and CDI attestation data", res);
		goto out;
	}

	res = TA_build_csr(&optee_km_context, &optee_dice_context, &challenge, pubkeys, &csr.data, &csr.data_length);
	if (res != KM_ERROR_OK)
		goto out;

	if (res == KM_ERROR_OK) {
		out += TA_serialize_blob_akms(out, out_end, &csr, &oob);
		if (oob) {
			EMSG("Out of output buffer space");
			res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
			goto out;
		}
	}

out:
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	if (keys_to_sign_array)
		TEE_Free(keys_to_sign_array);
	if (pubkeys)
		cbor_decref(&pubkeys);
	if (csr.data)
		TEE_Free(csr.data);

	return res;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx __unused,
				      uint32_t cmd_id, uint32_t param_types,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	keymaster_error_t error;

	if (param_types != exp_param_types) {
		EMSG("Keystore TA wrong parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (cmd_id == KM_GET_AUTHTOKEN_KEY) {
		DMSG("KM_GET_AUTHTOKEN_KEY");
		return TA_GetAuthTokenKey(params);
	}

	error = TA_checkParams(params);
	if (error != KM_ERROR_OK)
		return TA_errorRsp(params, error);

	switch(cmd_id) {
	/* Keymaster commands */
	case KM_GENERATE_KEY:
		DMSG("KM_GENERATE_KEY");
		error = TA_generateKey(params);
		break;
	case KM_BEGIN_OPERATION:
		DMSG("KM_BEGIN_OPERATION");
		error = TA_begin(params);
		break;
	case KM_UPDATE_OPERATION:
		DMSG("KM_UPDATE_OPERATION");
		error = TA_update(params);
		break;
	case KM_FINISH_OPERATION:
		DMSG("KM_FINISH_OPERATION");
		error = TA_finish(params);
		break;
	case KM_ABORT_OPERATION:
		DMSG("KM_ABORT_OPERATION");
		error = TA_abort(params);
		break;
	case KM_IMPORT_KEY:
		DMSG("KM_IMPORT_KEY");
		error = TA_importKey(params);
		break;
	case KM_IMPORT_WRAPPED_KEY:
		DMSG("KM_IMPORT_WRAPPED_KEY");
		error = TA_importWrappedKey(params);
		break;
	case KM_EXPORT_KEY:
		DMSG("KM_EXPORT_KEY");
		error = TA_exportKey(params);
		break;
	case KM_GET_VERSION:
		DMSG("KM_GET_VERSION");
		error = TA_getVersion(params);
		break;
	case KM_ADD_RNG_ENTROPY:
		DMSG("KM_ADD_RNG_ENTROPY");
		error = TA_addRngEntropy(params);
		break;
	case KM_GET_KEY_CHARACTERISTICS:
		DMSG("KM_GET_KEY_CHARACTERISTICS");
		error = TA_getKeyCharacteristics(params);
		break;
	case KM_UPGRADE_KEY:
		DMSG("KM_UPGRADE_KEY");
		error = TA_upgradeKey(params);
		break;
	case KM_CONFIGURE:
		DMSG("KM_CONFIGURE");
		error = TA_configure(params);
		break;
	case KM_GET_HMAC_SHARING_PARAMETERS:
		DMSG("KM_GET_HMAC_SHARING_PARAMETERS");
		error = TA_getHmacSharingParameters(params);
		break;
	case KM_VERIFY_AUTHORIZATION:
		DMSG("KM_VERIFY_AUTHORIZATION");
		error = TA_verifyAuthorization(params);
		break;
	case KM_DELETE_KEY:
		DMSG("KM_DELETE_KEY");
		error = TA_stubOperation(params);
		break;
	case KM_DELETE_ALL_KEYS:
		DMSG("KM_DELETE_ALL_KEYS");
		error = TA_stubOperation(params);
		break;
	case KM_DESTROY_ATTESTATION_IDS:
		DMSG("KM_DESTROY_ATTESTATION_IDS");
		error = TA_stubOperation(params);
		break;
	case KM_GET_VERSION_2:
		DMSG("KM_GET_VERSION_2");
		error = TA_getVersion2(params);
		break;
	case KM_CONFIGURE_VENDOR_PATCHLEVEL:
		DMSG("KM_CONFIGURE_VENDOR_PATCHLEVEL");
		error = TA_configure_vendor_patchlevel(params);
		break;
	case KM_GET_SUPPORTED_ALGORITHMS:
	case KM_GET_SUPPORTED_BLOCK_MODES:
	case KM_GET_SUPPORTED_PADDING_MODES:
	case KM_GET_SUPPORTED_DIGESTS:
	case KM_GET_SUPPORTED_IMPORT_FORMATS:
	case KM_GET_SUPPORTED_EXPORT_FORMATS:
	case KM_COMPUTE_SHARED_HMAC:
	case KM_DEVICE_LOCKED:
		error = TA_unimplementedOperation(params);
		break;
	case KM_EARLY_BOOT_ENDED:
		error = TA_earlyBootEnded();
		break;
	case KM_GET_ROOT_OF_TRUST:
		DMSG("KM_GET_ROOT_OF_TRUST");
		error = TA_getRootOfTrust(params);
		break;
	case KM_GENERATE_RKP_KEY:
		DMSG("KM_GENERATE_RKP_KEY");
		error = TA_generateRkpKey(params);
		break;
	case KM_GENERATE_CSR:
		DMSG("KM_GENERATE_CSR");
		error = TA_generateCsr(params);
		break;
	case KM_GET_HW_INFO:
		DMSG("KM_GET_HW_INFO");
		error = TA_getHwInfo(params);
		break;
	case KM_GENERATE_CSR_V2:
		DMSG("KM_GENERATE_CSR_V2");
		error = TA_generateCsrV2(params);
		break;

#ifdef CFG_ATTESTATION_PROVISIONING
	/* Provisioning commands */
	case KM_SET_ATTESTATION_KEY:
		DMSG("KM_SET_ATTESTATION_KEY");
		error = TA_SetAttestationKey(params);
		break;
	case KM_APPEND_ATTESTATION_CERT_CHAIN:
		DMSG("KM_APPEND_ATTESTATION_CERT_CHAIN");
		error = TA_AppendAttestationCertKey(params);
		break;
	case KM_SET_BOOT_PARAMS:
	case KM_ATAP_GET_CA_REQUEST:
	case KM_ATAP_SET_CA_RESPONSE_BEGIN:
	case KM_ATAP_SET_CA_RESPONSE_UPDATE:
	case KM_ATAP_SET_CA_RESPONSE_FINISH:
	case KM_ATAP_READ_UUID:
	case KM_SET_PRODUCT_ID:
	case KM_CLEAR_ATTESTATION_CERT_CHAIN:
	case KM_SET_WRAPPED_ATTESTATION_KEY:
	case KM_SET_ATTESTATION_IDS:
	case KM_SET_ATTESTATION_IDS_KM3:
	case KM_CONFIGURE_BOOT_PATCHLEVEL:
		error = TA_unimplementedOperation(params);
		break;
#endif
	default:
		EMSG("Unknown command %d", cmd_id);
		error = KM_ERROR_INVALID_ARGUMENT;
		break;
	}

	return TA_errorRsp(params, error);
}
