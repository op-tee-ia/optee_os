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

#include "hmac.h"
#include "shift.h"

#include "mbedtls/md.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/platform.h"
//Hmac key for message authentication code

static uint8_t objID[] = {0xb7U, 0x72U, 0xdfU, 0x21U};
static uint8_t iv[IV_LENGTH];

TEE_Result TA_open_hmac_key(TEE_ObjectHandle *secretKey)
{
	static TEE_ObjectHandle hmacKey = TEE_HANDLE_NULL;
	TEE_Result res = TEE_SUCCESS;
	TEE_Attribute attrs[1];
	uint8_t keyData[KEY_LENGTH];
	uint32_t readSize = 0;
	TEE_ObjectHandle object = TEE_HANDLE_NULL;

	DMSG("%s %d", __func__, __LINE__);
	if (hmacKey != TEE_HANDLE_NULL) {
		DMSG("Use existing hmacKey");
		*secretKey = hmacKey;
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

		res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256,
				KEY_LENGTH * BITS_IN_BYTE, &hmacKey);
		if (res == TEE_SUCCESS) {
			res = TEE_PopulateTransientObject(hmacKey, attrs,
					sizeof(attrs)/sizeof(TEE_Attribute));
			if (res != TEE_SUCCESS) {
				EMSG("Failed to populate transient object, res = %x", res);
				TEE_FreeTransientObject(hmacKey);
				hmacKey = TEE_HANDLE_NULL;
			}
		} else {
			EMSG("Failed to allocate transient object, res = %x", res);
		}

close:
		TEE_CloseObject(object);

	} else {
		EMSG("Failed to open a secret persistent key, res = %x", res);
		hmacKey = TEE_HANDLE_NULL;
	}

	if (res == TEE_SUCCESS) {
		*secretKey = hmacKey;
	}

	return res;
}

TEE_Result TA_create_hmac_key(void)
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

TEE_Result TA_hmac_execute(uint8_t *message, size_t message_len,
			   uint8_t *tag, uint32_t tag_len)
{
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectInfo info;
	TEE_Result res;
	TEE_ObjectHandle secretKey = TEE_HANDLE_NULL;

	DMSG("%s %d message_len = %zu", __func__, __LINE__, message_len);
	res = TA_open_hmac_key(&secretKey);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to read secret key");
		goto exit;
	}	
	TEE_GetObjectInfo1(secretKey, &info);

	res = TEE_AllocateOperation(&op, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC, info.maxKeySize);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate HMAC operation, res=%x", res);
		goto exit;
	}

	//Use persistent key objects
	res = TEE_SetOperationKey(op, secretKey);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to set secret key, res=%x", res);
		goto free_op;
	}

	TEE_MACInit(op, iv, sizeof(iv));
	if (res == TEE_SUCCESS) {
		res = TEE_MACComputeFinal(op, (void *)message, message_len,
					  (void *)tag, &tag_len);
	}
	if (res != TEE_SUCCESS) {
		EMSG("Error TEE_MACComputeFinal res=%x", res);
	}
free_op:
	if (op != TEE_HANDLE_NULL)
		TEE_FreeOperation(op);
exit:
	return res;
}

void TA_free_hmac_key(void)
{
	TEE_ObjectHandle secretKey = TEE_HANDLE_NULL;

	DMSG("%s %d", __func__, __LINE__);
	if (TA_open_hmac_key(&secretKey) == TEE_SUCCESS) {
		TEE_FreeTransientObject(secretKey);
	}
}
