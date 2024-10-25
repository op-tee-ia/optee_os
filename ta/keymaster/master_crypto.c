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


#include "master_crypto.h"
#include "shift.h"

#include "mbedtls/md.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/platform.h"
//Master key for encryption/decryption of all CA's keys,
//and also used as HBK (hardware-bound private key) during attestation

static uint8_t objID[] = {0xa7U, 0x62U, 0xcfU, 0x11U};
static uint8_t iv[IV_LENGTH];

static TEE_Result TA_derive_kek(TEE_ObjectHandle ikm,
			uint8_t *kek, size_t kek_size,
			const uint8_t *hidden, const size_t hidden_size)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t kmkData[KEY_LENGTH];
	uint32_t kmk_size = KEY_LENGTH;
	const unsigned char salt[] = "OP-TEE Keymaster";
	const size_t salt_size = sizeof(salt);

	if (!ikm || !hidden)
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_GetObjectBufferAttribute(ikm,
				TEE_ATTR_SECRET_VALUE,
				kmkData,
				&kmk_size);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to read keymaster master key, res=%x", res);
		goto out;
	}

	res = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
				salt/*salt*/, salt_size,
				kmkData/*input key*/, sizeof(kmkData),
				hidden/*app specific info */, hidden_size,
				kek/*output key*/, kek_size);
	if (res != 0){
		EMSG("Failed to derive key encryption key, res=%x", res);
		res = TEE_ERROR_GENERIC;
		goto out;
	}

out:
	mbedtls_platform_zeroize(kmkData, sizeof(kmkData));

	return res;
}

TEE_Result TA_open_secret_key(TEE_ObjectHandle *secretKey)
{
	static TEE_ObjectHandle masterKey = TEE_HANDLE_NULL;
	TEE_Result res = TEE_SUCCESS;
	TEE_Attribute attrs[1];
	uint8_t keyData[KEY_LENGTH];
	uint32_t readSize = 0;
	TEE_ObjectHandle object = TEE_HANDLE_NULL;

	DMSG("%s %d", __func__, __LINE__);
	if (masterKey != TEE_HANDLE_NULL) {
		DMSG("Use existing masterKey");
		*secretKey = masterKey;
		return TEE_SUCCESS;
	}

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
			objID, sizeof(objID),
			TEE_DATA_FLAG_ACCESS_READ, &object);

	if (res == TEE_SUCCESS) {
		//Key size is fixed
		res = TEE_ReadObjectData(object, keyData, sizeof(keyData), &readSize);
		if (res != TEE_SUCCESS || readSize != KEY_LENGTH) {
			EMSG("Failed to read key, res = %x", res);
			goto close;
		}

		//IV size is fixed
		res = TEE_ReadObjectData(object, iv, sizeof(iv), &readSize);
		if (res != TEE_SUCCESS || readSize != IV_LENGTH) {
			EMSG("Failed to read IV, res = %x", res);
			goto close;
		}

		TEE_InitRefAttribute(&attrs[0], TEE_ATTR_SECRET_VALUE,
				keyData, sizeof(keyData));

		res = TEE_AllocateTransientObject(TEE_TYPE_AES,
				KEY_LENGTH * BITS_IN_BYTE, &masterKey);
		if (res == TEE_SUCCESS) {
			res = TEE_PopulateTransientObject(masterKey, attrs,
					sizeof(attrs)/sizeof(TEE_Attribute));
			if (res != TEE_SUCCESS) {
				EMSG("Failed to populate transient object, res = %x", res);
				TEE_FreeTransientObject(masterKey);
				masterKey = TEE_HANDLE_NULL;
			}
		} else {
			EMSG("Failed to allocate transient object, res = %x", res);
		}

close:
		TEE_CloseObject(object);

	} else {
		EMSG("Failed to open a secret persistent key, res = %x", res);
		masterKey = TEE_HANDLE_NULL;
	}

	if (res == TEE_SUCCESS) {
		*secretKey = masterKey;
	}

	return res;
}

TEE_Result TA_create_secret_key(void)
{
	TEE_Result res;
	TEE_ObjectHandle object = TEE_HANDLE_NULL;
	uint8_t keyData[KEY_LENGTH];

	DMSG("%s %d", __func__, __LINE__);
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				objID, sizeof(objID),
				TEE_DATA_FLAG_ACCESS_READ, &object);

	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		//No such key, create it
		TEE_GenerateRandom(keyData, sizeof(keyData));
		TEE_GenerateRandom((void *)iv, sizeof(iv));

		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
				objID, sizeof(objID),
				TEE_DATA_FLAG_ACCESS_WRITE,
				TEE_HANDLE_NULL, NULL, 0U, &object);

		if (res != TEE_SUCCESS) {
			EMSG("Failed to create a secret persistent key, res = %x", res);
			goto error;
		}

		res = TEE_WriteObjectData(object, (void *)keyData, sizeof(keyData));
		if (res != TEE_SUCCESS) {
			EMSG("Failed to write key data, res = %x", res);
			goto error;
		}
		mbedtls_platform_zeroize(keyData, sizeof(keyData));

		res = TEE_WriteObjectData(object, (void *)iv, sizeof(iv));
		if (res != TEE_SUCCESS) {
			EMSG("Failed to write IV, res = %x", res);
			goto error;
		}

error:
		(res == TEE_SUCCESS) ?
				TEE_CloseObject(object) :
				TEE_CloseAndDeletePersistentObject(object);

	} else if (res == TEE_SUCCESS) {
		//Key already exits
		TEE_CloseObject(object);
	} else {
		//Something wrong...
		EMSG("Failed to open secret key, res=%x", res);
	}

	return res;
}

TEE_Result TA_execute(uint8_t *data, const size_t size,
			const uint8_t* hidden, const size_t hidden_size,
			const uint32_t mode)
{
	uint8_t *outbuf = NULL;
	uint32_t outbuf_size = size;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectInfo info;
	TEE_Result res;
	TEE_ObjectHandle secretKey = TEE_HANDLE_NULL;
	uint8_t tag[TAG_LENGTH];
	uint32_t tagLen = TAG_LENGTH;
	uint8_t kekData[KEY_LENGTH];
	TEE_ObjectHandle kek = TEE_HANDLE_NULL;
	TEE_Attribute attr = { };
	uint32_t tmp_len = 0;

	DMSG("%s %d size = %zu", __func__, __LINE__, size);
	res = TA_open_secret_key(&secretKey);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to read secret key");
		goto exit;
	}

#if (TRACE_LEVEL >= TRACE_DEBUG)
	printf("hidden: ");
	tmp_len = hidden_size > 16 ? 16 : hidden_size;
	for (int i = 0; i < tmp_len; i++)
		printf("%02x", hidden[i]);
	printf("\n");
#endif


	outbuf = TEE_Malloc(size, TEE_MALLOC_FILL_ZERO);
	if (!outbuf) {
		EMSG("failed to allocate memory for out buffer");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}
	TEE_GetObjectInfo1(secretKey, &info);

	res = TEE_AllocateOperation(&op, TEE_ALG_AES_GCM, mode, info.maxKeySize);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate AES operation, res=%x", res);
		goto exit;
	}

	res = TEE_AllocateTransientObject(TEE_TYPE_AES,
				KEY_LENGTH * BITS_IN_BYTE, &kek);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate transient object, res = %x", res);
		res = TEE_ERROR_GENERIC;
		goto free_op;
	}

	TEE_MemFill(kekData, 0, KEY_LENGTH);
	res = TA_derive_kek(secretKey, kekData, sizeof(kekData), hidden, hidden_size);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to derive kek, res=%x", res);
		goto free_op;
	}

#if (TRACE_LEVEL >= TRACE_DEBUG)
	printf("kekData: ");
	tmp_len = KEY_LENGTH > 16 ? 16 : KEY_LENGTH;
	for (int i = 0; i < tmp_len; i++)
		printf("%02x", kekData[i]);
	printf("\n");
#endif

	attr.attributeID = TEE_ATTR_SECRET_VALUE;
	attr.content.ref.buffer = kekData;
	attr.content.ref.length = sizeof(kekData);
	res = TEE_PopulateTransientObject(kek, &attr, 1);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to populate transient object, res = %x", res);
		goto free_op;
	}

	//Use persistent key objects
	res = TEE_SetOperationKey(op, kek);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to set secret key, res=%x", res);
		goto free_op;
	}

	TEE_AEInit(op, iv, sizeof(iv), TAG_LENGTH * BITS_IN_BYTE, 0, 0);
	if (res == TEE_SUCCESS && size > 0) {
		if (mode == TEE_MODE_ENCRYPT) {
			DMSG("tagLen = %u", tagLen);
			res = TEE_AEEncryptFinal(op, data, size - TAG_LENGTH,
					outbuf, &outbuf_size,
					(void *)&tag, &tagLen);
			DMSG("tagLen = %u", tagLen);
		}
		else {
			res = TEE_AEDecryptFinal(op, data, size - TAG_LENGTH,
					outbuf, &outbuf_size,
					(void *)(data + size - TAG_LENGTH), TAG_LENGTH);
		}
	}
	if (res != TEE_SUCCESS)
		EMSG("Error TEE_AEFinal res=%x", res);
	else {
		TEE_MemMove(data, outbuf, size - TAG_LENGTH);
		if (mode == TEE_MODE_ENCRYPT)
			TEE_MemMove(data + size - TAG_LENGTH, tag, TAG_LENGTH);
	}
free_op:
	if (op != TEE_HANDLE_NULL)
		TEE_FreeOperation(op);
	if (kek != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(kek);
exit:
	if (outbuf != NULL)
		TEE_Free(outbuf);
	/* clean kekData before return */
	TEE_MemFill(kekData, 0, KEY_LENGTH);
	return res;
}

TEE_Result TA_encrypt(uint8_t *data, const size_t size,
			const uint8_t* hidden, const size_t hidden_size)
{
	DMSG("%s %d", __func__, __LINE__);
	return TA_execute(data, size, hidden, hidden_size, TEE_MODE_ENCRYPT);
}

TEE_Result TA_decrypt(uint8_t *data, const size_t size,
			const uint8_t* hidden, const size_t hidden_size)
{
	DMSG("%s %d", __func__, __LINE__);
	return TA_execute(data, size, hidden, hidden_size, TEE_MODE_DECRYPT);
}

void TA_free_master_key(void)
{
	TEE_ObjectHandle secretKey = TEE_HANDLE_NULL;

	DMSG("%s %d", __func__, __LINE__);
	if (TA_open_secret_key(&secretKey) == TEE_SUCCESS) {
		TEE_FreeTransientObject(secretKey);
	}
}
