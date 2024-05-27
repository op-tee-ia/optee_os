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

#include <stdio.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "common.h"
#include "ta_ca_defs.h"
#include "keystore_ta.h"
#include "attestation.h"
#include <pta_system.h>
#include <mbedtls/platform_util.h>

static TEE_TASessionHandle session_rngSTA = TEE_HANDLE_NULL;

static tee_km_context_t optee_km_context;

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

static void TA_init_km_context(void)
{
	memset(&optee_km_context, 0, sizeof(tee_km_context_t));
	optee_km_context.version_info_set = false;
	optee_km_context.rot_info_set = false;
}

TEE_Result TA_CreateEntryPoint(void)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_Param params[TEE_NUM_PARAMS];

	const TEE_UUID rng_entropy_uuid = PTA_SYSTEM_UUID /*RNG_ENTROPY_UUID*/;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("%s %d", __func__, __LINE__);

	TA_init_km_context();
	TA_reset_operations_table();

	res = TA_create_secret_key();
	if (res != TEE_SUCCESS) {
		EMSG("Something wrong with secret key (%x)", res);
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

exit:
	return res;
}

void TA_DestroyEntryPoint(void)
{
	DMSG("%s %d", __func__, __LINE__);
	TA_free_master_key();
	TEE_CloseTASession(session_rngSTA);
	session_rngSTA = TEE_HANDLE_NULL;
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

	return TEE_SUCCESS;
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
	case TEE_TYPE_RSA_KEYPAIR:
		return (key_size + 7) / 8;
	case TEE_TYPE_ECDSA_KEYPAIR:
		/*
		 * Output is a sign with r and s parameters each sized as
		 * a key in ASN.1 format
		 */
		return 3 * key_size;
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
	millis = (time.seconds * 1000) + time.millis;
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

static keymaster_error_t TA_set_rot_data(void)
{
	TEE_TASessionHandle sess = TEE_HANDLE_NULL;
	TEE_Param params[TEE_NUM_PARAMS] = { };
	TEE_Result res = TEE_ERROR_GENERIC;

	if (optee_km_context.rot_info_set)
		return KM_ERROR_ROOT_OF_TRUST_ALREADY_SET;

	uint32_t ret_orig = 0;
	uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);

	res = TEE_OpenTASession(&(const TEE_UUID)PTA_SYSTEM_UUID,
				TEE_TIMEOUT_INFINITE, 0, NULL, &sess,
				&ret_orig);
	if (res) {
		EMSG("Failed(%d) to open PTA session", res);
		res = KM_ERROR_UNKNOWN_ERROR;
		goto out;
	}


	params[0].memref.buffer = &optee_km_context.rot;
	params[0].memref.size = sizeof(struct rot_data_t);

	res = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE,
				  PTA_SYSTEM_GET_ROT,
				  param_types, params, &ret_orig);
	if (res) {
		EMSG("Failed(%d) to open PTA session", res);
		res = KM_ERROR_UNKNOWN_ERROR;
		goto out;
	}

out:
	TEE_CloseTASession(sess);

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
		res = TA_set_rot_data();
		if (res != KM_ERROR_OK && res != KM_ERROR_ROOT_OF_TRUST_ALREADY_SET) {
			EMSG("Failed(%d) to get root of trust data", res);
			goto err;
		}
		optee_km_context.rot_info_set = true;
	}

	/* copy rot.deviceLocked to hidden */
	rot.data = (uint8_t*)&optee_km_context.rot.deviceLocked;
	rot.data_length = sizeof(optee_km_context.rot.deviceLocked);
	out += TA_serialize_blob_akms(out, out_end, &rot, &oob);
	if (oob) {
		EMSG("Out of output buffer space");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto err;
	}

	/* copy rot.verifiedBootState to hidden */
	rot.data = (uint8_t*)&optee_km_context.rot.verifiedBootState;
	rot.data_length = sizeof(optee_km_context.rot.verifiedBootState);
	out += TA_serialize_blob_akms(out, out_end, &rot, &oob);
	if (oob) {
		EMSG("Out of output buffer space");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto err;
	}

	/* copy rot.keyHash256 to hidden */
	rot.data = (uint8_t*)optee_km_context.rot.keyHash256;
	rot.data_length = optee_km_context.rot.keySize;
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
		memcpy(&optee_km_context.os_version, in,
		       sizeof(optee_km_context.os_version));
		in += 4;
		memcpy(&optee_km_context.os_patchlevel, in,
		       sizeof(optee_km_context.os_patchlevel));
		in += 4;
		optee_km_context.version_info_set = true;
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
	keymaster_version2_t version2 = { 3, KEYMINT_3, 0 };
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
	keymaster_algorithm_t key_algorithm = UNDEFINED;
	keymaster_error_t res = KM_ERROR_OK;
	keymaster_digest_t key_digest = UNDEFINED;
	uint32_t key_buffer_size = 0; /* For serialization of generated key */
	uint32_t characts_size = 0;
	uint32_t key_size = UNDEFINED;
	uint64_t key_rsa_public_exponent = UNDEFINED;
	uint32_t os_version = 0xFFFFFFFF;
	uint32_t os_patchlevel = 0xFFFFFFFF;
	bool oob = false; /* out of bounds flag */
	uint8_t* hidden = NULL;
	size_t hidden_size = 0;
	keymaster_blob_t client_id = EMPTY_BLOB;
	keymaster_blob_t app_data = EMPTY_BLOB;

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

	/* Add additional parameters */
	TA_add_origin(&params_t, KM_ORIGIN_GENERATED, true);
	TA_add_creation_datetime(&params_t, true);
	TA_add_os_version_patchlevel(&params_t, os_version, os_patchlevel);

	/* Parse mandatory and optional parameters */
	res = TA_parse_params(params_t, &key_algorithm, &key_size,
			      &key_rsa_public_exponent, &key_digest, false);
	if (res != KM_ERROR_OK)
		goto exit;

	if (key_size == UNDEFINED) {
		EMSG("Key size must be specified");
		res = KM_ERROR_UNSUPPORTED_KEY_SIZE;
		goto exit;
	}
	if (key_algorithm == KM_ALGORITHM_RSA &&
			key_rsa_public_exponent == UNDEFINED) {
		EMSG("RSA public exponent is missed");
		res = KM_ERROR_INVALID_ARGUMENT;
		goto exit;
	}
	if (key_algorithm == KM_ALGORITHM_EC) {
		DMSG("key_algorithm == KM_ALGORITHM_EC");
		TA_add_ec_curve(&params_t, key_size);
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
			      key_digest, key_rsa_public_exponent);
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
	}

out:
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;
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
	keymaster_blob_t client_id = EMPTY_BLOB; /* IN */
	keymaster_blob_t app_data = EMPTY_BLOB; /* IN */
	keymaster_key_characteristics_t chr = EMPTY_CHARACTS; /* OUT */
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET;
	keymaster_error_t res = KM_ERROR_OK;
	TEE_ObjectHandle obj_h = TEE_HANDLE_NULL;
	uint32_t characts_size = 0;
	uint32_t key_size = 0;
	uint32_t type = 0;
	bool exportable = false;
	bool oob = false; /* out of bounds flag */
	uint8_t* hidden = NULL;
	size_t hidden_size = 0;

	DMSG("%s %d", __func__, __LINE__);

	in = (uint8_t *)params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *)params[1].memref.buffer;
	out_size = (size_t)params[1].memref.size; /* limited to 8192 */
	out_end = out + out_size;
	out += sizeof(keymaster_error_t);

	in += TA_deserialize_key_blob_akms(in, in_end, &key_blob, &res);
	if (res != KM_ERROR_OK)
		goto exit;
	in += TA_deserialize_blob_akms(in, in_end, &client_id, false, &res,
				       false);
	if (res != KM_ERROR_OK)
		goto exit;
	in += TA_deserialize_blob_akms(in, in_end, &app_data, false, &res,
				       false);
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

	res = TA_build_hidden_info(&hidden, &hidden_size, &client_id, &app_data);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to serialize hidden info, res=%x", res);
		goto exit;
	}

	res = TA_restore_key(key_material, &key_blob, &key_size,
				hidden, hidden_size, &type, &obj_h, &params_t);
	if (res != KM_ERROR_OK)
		goto exit;

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
	keymaster_error_t res = KM_ERROR_OK;
	keymaster_algorithm_t key_algorithm = UNDEFINED;
	keymaster_digest_t key_digest = UNDEFINED;
	TEE_Attribute *attrs_in = NULL;
	uint8_t *key_material = NULL;
	uint32_t key_buffer_size = 0;
	uint32_t characts_size = 0;
	uint32_t key_size = UNDEFINED;
	uint32_t attrs_in_count = 0;
	uint64_t key_rsa_public_exponent = UNDEFINED;
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

	/* Parse mandatory and optional parameters */
	res = TA_parse_params(params_t, &key_algorithm, &key_size,
			      &key_rsa_public_exponent, &key_digest, true);
	if (res != KM_ERROR_OK)
		goto out;
	if (key_format == KM_KEY_FORMAT_RAW) {
		if (key_algorithm != KM_ALGORITHM_AES &&
		    key_algorithm != KM_ALGORITHM_HMAC) {
			EMSG("Only HMAC and AES keys can imported in raw "
			     "format");
			res = KM_ERROR_UNSUPPORTED_KEY_FORMAT;
			/* goto out; */
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
		}

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
	} else { /* KM_KEY_FORMAT_PKCS8 */
		if (key_algorithm != KM_ALGORITHM_RSA &&
		    key_algorithm != KM_ALGORITHM_EC) {
			EMSG("Only RSA and EC keys can be imported in PKCS8 "
			     "format");
			res = KM_ERROR_UNSUPPORTED_KEY_FORMAT;
			/* goto out; */
		}

		res = mbedTLS_decode_pkcs8(key_data, &attrs_in,
					   &attrs_in_count, key_algorithm,
					   &key_size,
					   &key_rsa_public_exponent);

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
	}
	TA_add_to_params(&params_t, key_size, key_rsa_public_exponent);
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

	res = TA_import_key(key_algorithm, key_size, key_material, key_digest,
			    attrs_in, attrs_in_count);
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
	if (key_material)
		TEE_Free(key_material);
	if (client_id.data)
		TEE_Free(client_id.data);
	if (app_data.data)
		TEE_Free(app_data.data);
	if (hidden)
		TEE_Free(hidden);

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
	keymaster_blob_t client_id = EMPTY_BLOB;
	keymaster_blob_t app_data = EMPTY_BLOB;

	DMSG("%s %d", __func__, __LINE__);

	in = (uint8_t *)params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *)params[1].memref.buffer;
	out_size = (size_t)params[1].memref.size; /* limited to 8192 */
	out_end = out + out_size;
	out += sizeof(keymaster_error_t);

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
				hidden, hidden_size, &type, &obj_h, &params_t);
	if (res != KM_ERROR_OK)
		goto out;
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

static keymaster_error_t TA_attestKey(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	uint8_t *out_end = NULL;
	uint32_t out_size = 0;
	keymaster_key_blob_t key_to_attest = EMPTY_KEY_BLOB; /* IN */
	keymaster_key_param_set_t attest_params = EMPTY_PARAM_SET; /* IN */
	keymaster_cert_chain_t cert_chain = EMPTY_CERT_CHAIN; /* OUT */
	keymaster_error_t res = KM_ERROR_OK;
	TEE_Result result = TEE_SUCCESS;
	keymaster_blob_t *challenge = NULL;
	bool includeUniqueID = false;
	bool resetSinceIDRotation = false;
	keymaster_blob_t *app_id = NULL;
	keymaster_blob_t *app_data = NULL;
	keymaster_blob_t *attest_app_id = NULL;
	bool exportable = false;

	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET;
	TEE_ObjectHandle attestedKey = TEE_HANDLE_NULL;
	uint8_t *key_material = NULL;
	uint32_t key_size = 0;
	uint32_t key_type = 0;

	keymaster_key_characteristics_t key_chr = EMPTY_CHARACTS;
	uint32_t key_chr_size = 0;
	uint8_t verified_boot_state = 0xff;
	bool oob = false; /* out of bounds flag */
	uint8_t* hidden = NULL;
	size_t hidden_size = 0;

#ifdef ENUM_PERS_OBJS
	TA_enum_attest_objs();
#endif
#ifdef WIPE_PERS_OBJS
	TA_wipe_attest_objs();
#endif

	DMSG("%s %d", __func__, __LINE__);

	in = (uint8_t *)params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *)params[1].memref.buffer;
	out_size = params[1].memref.size; /* limited to 8192 */
	out_end = out + out_size;
	out += sizeof(keymaster_error_t);

#ifndef CFG_ATTESTATION_PROVISIONING
	/* This call creates keys/certs only once during first TA run */
	result = TA_create_attest_objs();
	if (result != TEE_SUCCESS) {
		EMSG("Failed to create attestation objects, res=%x", result);
		res = KM_ERROR_UNKNOWN_ERROR;
		goto exit;
	}
#endif

	/* Key blob for which the attestation will be created */
	in += TA_deserialize_key_blob_akms(in, in_end, &key_to_attest, &res);
	if (res != KM_ERROR_OK)
		goto exit;

	if (key_to_attest.key_material_size == 0) {
		EMSG("Bad attestation key blob");
		res = KM_ERROR_UNSUPPORTED_KEY_FORMAT;
		goto exit;
	}

	key_material = TEE_Malloc(key_to_attest.key_material_size,
				  TEE_MALLOC_FILL_ZERO);
	if (!key_material) {
		EMSG("Failed to allocate memory for key material");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}

	/* Deserialize parameters necessary for attestation */
	in += TA_deserialize_auth_set(in, in_end, &attest_params, false, &res);
	if (res != KM_ERROR_OK)
		goto exit;
	verified_boot_state = *in;

	for (size_t i = 0; i < attest_params.length; i++) {
		switch (attest_params.params[i].tag) {
		case KM_TAG_APPLICATION_ID:
			app_id = &attest_params.params[i].key_param.blob;
			break;
		case KM_TAG_APPLICATION_DATA:
			app_data = &attest_params.params[i].key_param.blob;
			break;
		case KM_TAG_ATTESTATION_CHALLENGE:
			challenge = &attest_params.params[i].key_param.blob;
			if (challenge->data_length >
			    MAX_ATTESTATION_CHALLENGE) {
				EMSG("Attestation challenge is too big");
				res = KM_ERROR_INVALID_INPUT_LENGTH;
				goto exit;
			}
			break;
		case KM_TAG_INCLUDE_UNIQUE_ID:
			includeUniqueID =
				attest_params.params[i].key_param.boolean;
			break;
		case KM_TAG_RESET_SINCE_ID_ROTATION:
			resetSinceIDRotation =
				attest_params.params[i].key_param.boolean;
			break;
		case KM_TAG_ATTESTATION_APPLICATION_ID:
			attest_app_id =
				&attest_params.params[i].key_param.blob;
			break;
		default:
			DMSG("Unused attestation parameter tag %x",
			     attest_params.params[i].tag);
			break;
		}
	}

	(void)resetSinceIDRotation;
	if (challenge == NULL) {
		EMSG("Attestation challenge is missing");
		res = KM_ERROR_ATTESTATION_CHALLENGE_MISSING;
		goto exit;
	}
	if (attest_app_id == NULL) {
		EMSG("Attestation application ID is missing");
		res = KM_ERROR_ATTESTATION_APPLICATION_ID_MISSING;
		goto exit;
	}

	res = TA_build_hidden_info(&hidden, &hidden_size, app_id, app_data);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to serialize hidden info, res=%x", res);
		goto exit;
	}

	/* Restore key */
	res = TA_restore_key(key_material, &key_to_attest, &key_size,
			     hidden, hidden_size, &key_type, &attestedKey, &params_t);
	if (res != KM_ERROR_OK)
		goto exit;

	if (app_id != NULL && app_data != NULL) {
		res = TA_check_permission(&params_t, *app_id, *app_data,
					  &exportable);
		if (res != KM_ERROR_OK)
			goto exit;
	}

	/* Check attested key type */
	if (key_type != TEE_TYPE_RSA_KEYPAIR &&
	    key_type != TEE_TYPE_ECDSA_KEYPAIR) {
		EMSG("Key attestation supports only asymmetric key pairs, "
		     "type=%x", key_type);
		res = KM_ERROR_INCOMPATIBLE_ALGORITHM;
		goto exit;
	}

	res = TA_fill_characteristics(&key_chr, &params_t, &key_chr_size);
	if (res != KM_ERROR_OK)
		goto exit;

	if (includeUniqueID == true) {
		/* TODO TA_generate_UniqueID(...); */
		IMSG("Unique id is missing");
	}

	/*
	 * Read Root attestation certificate (must be generated and stored
	 * before)
	 */
	res = TA_read_root_attest_cert(key_type, &cert_chain);
	if (res != KM_ERROR_INSUFFICIENT_BUFFER_SPACE) {
		EMSG("Failed to get att cert chain len, res=%x", res);
		goto exit;
	}

	/* Allocate memory for chain of certificates */
	cert_chain.entries =
		TEE_Malloc(sizeof(keymaster_blob_t)*cert_chain.entry_count,
			   TEE_MALLOC_FILL_ZERO);
	if (!cert_chain.entries) {
		EMSG("Failed to allocate memory for chain of certificates");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}

	/*
	 * Read Root attestation certificate (must be generated and stored
	 * before)
	 */
	res = TA_read_root_attest_cert(key_type, &cert_chain);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to read root att cert, res=%x", res);
		goto exit;
	}
	/* Generate key attestation certificate (using STA ASN.1) */
	result = TA_gen_key_attest_cert(key_type, attestedKey, &attest_params,
					&key_chr, &cert_chain,
					verified_boot_state, includeUniqueID);
	if (result != TEE_SUCCESS) {
		EMSG("Failed to gen key att cert, res=%x", result);
		res = KM_ERROR_UNKNOWN_ERROR;
		goto exit;
	}

	/* Check output buffer length */
	if (TA_cert_chain_size(&cert_chain) > out_size) {
		EMSG("Short output buffer for chain of certificates");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto exit;
	}

exit:
	/* Serialize output chain of certificates */
	if (res == KM_ERROR_OK) {
		out += TA_serialize_cert_chain_akms(out, out_end, &cert_chain,
						    &res, &oob);
		if (oob) {
			EMSG("Out of output buffer space");
			res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
			goto out;
		}
	}

out:
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	if (key_to_attest.key_material)
		TEE_Free(key_to_attest.key_material);

	if (attestedKey != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(attestedKey);

	if (key_material)
		TEE_Free(key_material);

	TA_free_params(&attest_params);
	TA_free_params(&key_chr.sw_enforced);
	TA_free_params(&key_chr.hw_enforced);
	TA_free_params(&params_t);
	TA_free_cert_chain(&cert_chain);
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
	size_t out_size = 0;
	keymaster_key_blob_t key_to_upgrade = EMPTY_KEY_BLOB; /* IN */
	keymaster_key_param_set_t upgr_params = EMPTY_PARAM_SET; /* IN */
	keymaster_key_blob_t upgraded_key = EMPTY_KEY_BLOB; /* OUT */
	keymaster_error_t res = KM_ERROR_OK;
	bool oob = false; /* out of bounds flag */

	DMSG("%s %d", __func__, __LINE__);

	in = (uint8_t *)params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *)params[1].memref.buffer;
	out_size = (size_t)params[1].memref.size; /* limited to 8192 */
	out_end = out + out_size;
	out += sizeof(keymaster_error_t);

	in += TA_deserialize_key_blob_akms(in, in_end, &key_to_upgrade, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_auth_set(in, in_end, &upgr_params, false, &res);
	if (res != KM_ERROR_OK)
		goto out;
	TA_add_origin(&upgr_params, KM_ORIGIN_UNKNOWN, false);

out:
	/* TODO Upgrade Key */
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
				hidden, hidden_size, &type, &obj_h, &params_t);
	if (res != KM_ERROR_OK)
		goto out;
	switch (type) {
	case TEE_TYPE_AES:
		algorithm = KM_ALGORITHM_AES;
		break;
	case TEE_TYPE_RSA_KEYPAIR:
		algorithm = KM_ALGORITHM_RSA;
		break;
	case TEE_TYPE_ECDSA_KEYPAIR:
		algorithm = KM_ALGORITHM_EC;
		break;
	default:/* HMAC */
		algorithm = KM_ALGORITHM_HMAC;
	}
	res = TA_check_params(&params_t, &in_params, &algorithm, purpose,
			      &digest, &mode, &padding, &mac_length, &nonce,
			      &min_sec, &do_auth, key_id);
	if (res != KM_ERROR_OK)
		goto out;
	if (algorithm == KM_ALGORITHM_AES && mode != KM_MODE_ECB &&
	    nonce.data_length == 0) {
		if (mode == KM_MODE_CBC || mode == KM_MODE_CTR) {
			IVsize = 16;
		} else { /* GCM mode */
			IVsize = 12;
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

	res = TA_create_operation(operation, obj_h, purpose, algorithm,
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
				 mac_length, digest, nonce, client_id, app_data, key_id);
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
				hidden, hidden_size, &type, &obj_h, &params_t);
	if (res != KM_ERROR_OK)
		goto out;
	if (operation.do_auth) {
		res = TA_do_auth(in_params, params_t);
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
	case TEE_TYPE_RSA_KEYPAIR:
		res = TA_rsa_update(&operation, &input, &output,
				    &keyblob_out_size, key_size,
				    &input_consumed, input_provided, obj_h);
		break;
	case TEE_TYPE_ECDSA_KEYPAIR:
		res = TA_ec_update(&operation, &input, &output,
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
				hidden, hidden_size, &type, &obj_h, &params_t);
	if (res != KM_ERROR_OK)
		goto out;
	if (operation.do_auth) {
		res = TA_do_auth(in_params, params_t);
		if (res != KM_ERROR_OK) {
			EMSG("Authentication failed");
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
	case TEE_TYPE_RSA_KEYPAIR:
		res = TA_rsa_finish(&operation, &input, &output,
				    &keyblob_out_size, key_size,
				    signature, obj_h, &is_input_ext);
		break;
	case TEE_TYPE_ECDSA_KEYPAIR:
		res = TA_ec_finish(&operation, &input, &output, &signature,
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
			res = TEE_MACCompareFinal(*operation.operation,
						  input.data,
						  input.data_length,
						  signature.data,
						  signature.data_length);
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
	case KM_ATTEST_KEY:
		DMSG("KM_ATTEST_KEY");
		error = TA_attestKey(params);
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
		return TA_stubOperation(params);
	case KM_GET_SUPPORTED_ALGORITHMS:
	case KM_GET_SUPPORTED_BLOCK_MODES:
	case KM_GET_SUPPORTED_PADDING_MODES:
	case KM_GET_SUPPORTED_DIGESTS:
	case KM_GET_SUPPORTED_IMPORT_FORMATS:
	case KM_GET_SUPPORTED_EXPORT_FORMATS:
	case KM_COMPUTE_SHARED_HMAC:
	case KM_IMPORT_WRAPPED_KEY:
	case KM_EARLY_BOOT_ENDED:
	case KM_DEVICE_LOCKED:
	case KM_GENERATE_RKP_KEY:
	case KM_GENERATE_CSR:
	case KM_GET_ROOT_OF_TRUST:
	case KM_GET_HW_INFO:
	case KM_GENERATE_CSR_V2:
		error = TA_unimplementedOperation(params);
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
	/* Gatekeeper commands */
	case KM_GET_AUTHTOKEN_KEY:
		DMSG("KM_GET_AUTHTOKEN_KEY");
		error = TA_GetAuthTokenKey(params);
		break;

	default:
		EMSG("Unknown command %d", cmd_id);
		error = KM_ERROR_INVALID_ARGUMENT;
		break;
	}

	return TA_errorRsp(params, error);
}
