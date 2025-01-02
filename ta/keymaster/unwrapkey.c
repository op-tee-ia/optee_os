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

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <generator.h>

#include "common.h"
#include "ta_ca_defs.h"
#include "unwrapkey.h"
#include <pta_system.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/platform_util.h>

#include <printk.h>


typedef struct {
    int tag;
    mbedtls_asn1_sequence *cur;
} cb_ctx_t;

static int TA_get_asn1_sequence_of_cb(void *ctx,
                                   int tag,
                                   unsigned char *start,
                                   size_t len)
{
    cb_ctx_t *cb_ctx = (cb_ctx_t *) ctx;
    mbedtls_asn1_sequence *cur =
        cb_ctx->cur;

    if (cur->buf.p != NULL) {
        cur->next =
            TEE_Malloc(sizeof(mbedtls_asn1_sequence), TEE_MALLOC_FILL_ZERO);

        if (cur->next == NULL) {
            return MBEDTLS_ERR_ASN1_ALLOC_FAILED;
        }

        cur = cur->next;
    }

    cur->buf.p = start;
    cur->buf.len = len;
    cur->buf.tag = tag;

    cb_ctx->cur = cur;
    return 0;
}

static int TA_get_asn1_sequence_of(unsigned char **p,
                                 const unsigned char *end,
                                 mbedtls_asn1_sequence *cur,
                                 int tag)
{
    cb_ctx_t cb_ctx = { tag, cur };
    memset(cur, 0, sizeof(mbedtls_asn1_sequence));
    return mbedtls_asn1_traverse_sequence_of(
        p, end, 0, 0, 0xFF, tag,
        TA_get_asn1_sequence_of_cb, &cb_ctx);
}

static void TA_free_asn1_seq(mbedtls_asn1_sequence *cur) {
	if (cur == NULL)
		return;

	mbedtls_asn1_sequence * seq = cur->next;
	mbedtls_asn1_sequence * temp = NULL;
	while (seq) {
		temp = seq->next;
		TEE_Free(seq);
		seq = temp;
	}
}

#define TAG_VAL(km_tag)		(km_tag & 0x0FFFFFFF)

static keymaster_tag_type_t TA_get_km_tag_type(uint32_t km_tag) {
	switch(km_tag) {
		case TAG_VAL(KM_TAG_PURPOSE):
		case TAG_VAL(KM_TAG_BLOCK_MODE):
		case TAG_VAL(KM_TAG_DIGEST):
		case TAG_VAL(KM_TAG_PADDING):
		case TAG_VAL(KM_TAG_KDF):
		case TAG_VAL(KM_TAG_RSA_OAEP_MGF_DIGEST):
			return KM_ENUM_REP;
		case TAG_VAL(KM_TAG_ALGORITHM):
		case TAG_VAL(KM_TAG_EC_CURVE):
		case TAG_VAL(KM_TAG_BLOB_USAGE_REQUIREMENTS):
		case TAG_VAL(KM_TAG_USER_AUTH_TYPE):
		case TAG_VAL(KM_TAG_ORIGIN):
			return KM_ENUM;
		case TAG_VAL(KM_TAG_KEY_SIZE):
		case TAG_VAL(KM_TAG_MIN_MAC_LENGTH):
		case TAG_VAL(KM_TAG_MIN_SECONDS_BETWEEN_OPS):
		case TAG_VAL(KM_TAG_MAX_USES_PER_BOOT):
		case TAG_VAL(KM_TAG_USAGE_COUNT_LIMIT):
		case TAG_VAL(KM_TAG_USER_ID):
		case TAG_VAL(KM_TAG_AUTH_TIMEOUT):
		case TAG_VAL(KM_TAG_OS_VERSION):
		case TAG_VAL(KM_TAG_OS_PATCHLEVEL):
		case TAG_VAL(KM_TAG_VENDOR_PATCHLEVEL):
		case TAG_VAL(KM_TAG_BOOT_PATCHLEVEL):
		case TAG_VAL(KM_TAG_MAC_LENGTH):
		case TAG_VAL(KM_TAG_MAX_BOOT_LEVEL):
			return KM_UINT;
		case TAG_VAL(KM_TAG_USER_SECURE_ID):
		case TAG_VAL(KM_TAG_RSA_PUBLIC_EXPONENT):
			return KM_ULONG;
		case TAG_VAL(KM_TAG_ACTIVE_DATETIME):
		case TAG_VAL(KM_TAG_ORIGINATION_EXPIRE_DATETIME):
		case TAG_VAL(KM_TAG_USAGE_EXPIRE_DATETIME):
		case TAG_VAL(KM_TAG_CREATION_DATETIME):
		case TAG_VAL(KM_TAG_CERTIFICATE_NOT_BEFORE):
		case TAG_VAL(KM_TAG_CERTIFICATE_NOT_AFTER):
			return KM_DATE;
		case TAG_VAL(KM_TAG_CALLER_NONCE):
		case TAG_VAL(KM_TAG_ECIES_SINGLE_HASH_MODE):
		case TAG_VAL(KM_TAG_INCLUDE_UNIQUE_ID):
		case TAG_VAL(KM_TAG_BOOTLOADER_ONLY):
		case TAG_VAL(KM_TAG_ROLLBACK_RESISTANCE):
		case TAG_VAL(KM_TAG_EARLY_BOOT_ONLY):
		case TAG_VAL(KM_TAG_ALL_USERS):
		case TAG_VAL(KM_TAG_NO_AUTH_REQUIRED):
		case TAG_VAL(KM_TAG_ALLOW_WHILE_ON_BODY):
		case TAG_VAL(KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED):
		case TAG_VAL(KM_TAG_TRUSTED_CONFIRMATION_REQUIRED):
		case TAG_VAL(KM_TAG_UNLOCKED_DEVICE_REQUIRED):
		case TAG_VAL(KM_TAG_ALL_APPLICATIONS):
		case TAG_VAL(KM_TAG_EXPORTABLE):
		case TAG_VAL(KM_TAG_ROLLBACK_RESISTANT):
		case TAG_VAL(KM_TAG_DEVICE_UNIQUE_ATTESTATION):
		case TAG_VAL(KM_TAG_IDENTITY_CREDENTIAL_KEY):
		case TAG_VAL(KM_TAG_RESET_SINCE_ID_ROTATION):
			return KM_BOOL;
		case TAG_VAL(KM_TAG_APPLICATION_ID):
		case TAG_VAL(KM_TAG_APPLICATION_DATA):
		case TAG_VAL(KM_TAG_ROOT_OF_TRUST):
		case TAG_VAL(KM_TAG_UNIQUE_ID):
		case TAG_VAL(KM_TAG_ATTESTATION_CHALLENGE):
		case TAG_VAL(KM_TAG_ATTESTATION_APPLICATION_ID):
		case TAG_VAL(KM_TAG_ATTESTATION_ID_BRAND):
		case TAG_VAL(KM_TAG_ATTESTATION_ID_DEVICE):
		case TAG_VAL(KM_TAG_ATTESTATION_ID_PRODUCT):
		case TAG_VAL(KM_TAG_ATTESTATION_ID_SERIAL):
		case TAG_VAL(KM_TAG_ATTESTATION_ID_IMEI):
		case TAG_VAL(KM_TAG_ATTESTATION_ID_MEID):
		case TAG_VAL(KM_TAG_ATTESTATION_ID_MANUFACTURER):
		case TAG_VAL(KM_TAG_ATTESTATION_ID_MODEL):
		case TAG_VAL(KM_TAG_ATTESTATION_ID_SECOND_IMEI):
		case TAG_VAL(KM_TAG_ASSOCIATED_DATA):
		case TAG_VAL(KM_TAG_NONCE):
		case TAG_VAL(KM_TAG_AUTH_TOKEN):
			return KM_INVALID;
		default:
			return KM_INVALID;

	}
}

static keymaster_error_t TA_get_km_tag(uint8_t **p, uint32_t *km_tag) {
	uint32_t tag = 0;

	if (!p || !km_tag) {
		DMSG("Input arg pointer is NULL");
		return KM_ERROR_INVALID_ARGUMENT;
	}

	if ((**p & 0x1F) != 0x1F) {
		*km_tag = **p & 0x1F;
		goto exit;
	}

	(*p)++;
	while (**p & 0x80) {
		tag = (tag << 7) | (**p & 0x7F);
		(*p)++;
	}
	tag = (tag << 7) | **p;

	*km_tag = tag;

exit:
	(*p)++;

	return KM_ERROR_OK;
}

static keymaster_error_t TA_set_auth_item(uint8_t **p,
							uint32_t asn1_tag,
							uint32_t km_tag,
							size_t len,
						    keymaster_tag_type_t km_tag_type,
							keymaster_key_param_t *param) {
	if(param == NULL) {
		DMSG("param is null");
		return KM_ERROR_INVALID_ARGUMENT;
	}

	param->tag = km_tag;
	if (asn1_tag == MBEDTLS_ASN1_INTEGER) {
		if (len > sizeof(uint64_t)) {
			return KM_ERROR_INVALID_INPUT_LENGTH;
		}

		uint64_t val = 0;
		while (len-- > 0) {
			val = (val << 8) | **p;
			*p = *p + 1;
		}

		if (km_tag_type == KM_ENUM || km_tag_type == KM_ENUM_REP) {
			param->key_param.enumerated = (uint32_t)val;
		} else if (km_tag_type == KM_UINT || km_tag_type == KM_UINT_REP) {
			param->key_param.integer = (uint32_t)val;
		} else if (km_tag_type == KM_ULONG || km_tag_type == KM_ULONG_REP) {
			param->key_param.long_integer = val;
		} else if (km_tag_type == KM_DATE) {
			param->key_param.date_time = val;
		}
	} else if (asn1_tag == MBEDTLS_ASN1_NULL) {
		if (km_tag_type == KM_BOOL) {
			param->key_param.boolean = 1;
		}
	} else if (asn1_tag == MBEDTLS_ASN1_BOOLEAN) {
		param->key_param.boolean = **p;
	} else {
		DMSG("asn1 tag %x doesn't support currently", asn1_tag);
		return KM_ERROR_INVALID_ARGUMENT;
	}

	return 0;
}

static keymaster_error_t TA_get_auth_set(uint8_t **p, uint8_t *end,
										uint32_t *auth_count,
										keymaster_key_param_set_t *auth_set) {
	keymaster_tag_type_t km_tag_type = KM_INVALID;
	int ret = 0;
	size_t len = 0, sub_len = 0;
	uint32_t count = 0;
	uint32_t km_tag = 0;
	uint32_t tag = 0;
	bool is_asym = false;
	uint8_t *sub_end = NULL;

	if (!p || !*p || !end || !auth_count) {
		DMSG("Input arg pointer is NULL");
		return KM_ERROR_INVALID_ARGUMENT;
	}

	while (*p < end) {
		if (((**p & 0xE0) != (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED))) {
			DMSG("invalid authrization format %d", MBEDTLS_ERR_ASN1_UNEXPECTED_TAG);
			ret = KM_ERROR_INVALID_TAG;
			goto exit;
		}

		TA_get_km_tag(p, &km_tag);

		km_tag_type = TA_get_km_tag_type(km_tag);
		if(km_tag_type == KM_INVALID)
		{
			DMSG("Invalid km_tag_type");
			ret = KM_ERROR_INVALID_TAG;
			goto exit;
		}

		km_tag |= km_tag_type;
		DMSG("km_tag is %x %x", km_tag, **p);

		if ((ret = mbedtls_asn1_get_len(p, end, &len)) < 0) {
			DMSG("mbedtls_asn1_get_len failed %d(%d)", ret, __LINE__);
			ret = KM_ERROR_UNKNOWN_ERROR;
			goto exit;
		}

		if (**p != (MBEDTLS_ASN1_SET | MBEDTLS_ASN1_CONSTRUCTED)) {
			tag = **p;
			if ((ret = mbedtls_asn1_get_tag(p, end, &len, tag)) < 0) {
				DMSG("mbedtls_asn1_get_tag failed %d(%d)", ret, __LINE__);
				ret = KM_ERROR_INVALID_TAG;
				goto exit;
			}

			if (auth_set == NULL) {
				count++;
				*p = *p + len;
				continue;
			}

			ret = TA_set_auth_item(p, tag, km_tag, len,
						km_tag_type, auth_set->params + count);
			if (ret != KM_ERROR_OK) {
				DMSG("TA_set_auth_item failed %d", ret);
				goto exit;
			}
			count++;
		} else {
			tag = **p;
			if ((ret = mbedtls_asn1_get_tag(p, end, &len, tag)) < 0) {
				DMSG("mbedtls_asn1_get_tag failed %d(%d)", ret, __LINE__);
				ret = KM_ERROR_INVALID_TAG;
				goto exit;
			}

			sub_end = *p + len;
			while (*p < sub_end) {
				tag = **p;
				if ((ret = mbedtls_asn1_get_tag(p, end, &sub_len, **p)) < 0) {
					DMSG("mbedtls_asn1_get_tag failed %d(%d)", ret, __LINE__);
					ret = KM_ERROR_INVALID_TAG;
					goto exit;
				}

				if (auth_set == NULL) {
					*p += sub_len;
					count++;
					continue;
				}

				if ((ret = TA_set_auth_item(p, tag, km_tag, sub_len,
					  km_tag_type, auth_set->params + count)) != KM_ERROR_OK) {
					DMSG("TA_set_auth_item failed %d", ret);
					goto exit;
				}
				count++;
			}
		}
	}

	if (auth_set) {
		for (size_t i = 0; i < count; i++) {
			if (auth_set->params[i].tag == KM_TAG_ALGORITHM &&
				(auth_set->params[i].key_param.enumerated == KM_ALGORITHM_RSA ||
				 auth_set->params[i].key_param.enumerated == KM_ALGORITHM_EC))
				is_asym = true;
		}

		if (is_asym) {
			auth_set->params[count].tag = KM_TAG_CERTIFICATE_NOT_BEFORE;
			auth_set->params[count].key_param.date_time = 0;
			auth_set->params[count + 1].tag = KM_TAG_CERTIFICATE_NOT_AFTER;
			auth_set->params[count + 1].key_param.date_time = 253402300799000;
			auth_set->length = count + 2;
		} else
			auth_set->length = count;
	}

	*auth_count = count;

exit:
	return ret;
}

static keymaster_error_t TA_encode_asn1_sequence(uint8_t tag,
					mbedtls_asn1_sequence *seq,
					keymaster_blob_t *asn_seq) {
	size_t size = 1;
	size_t seq_len = 1;

	if(!asn_seq || !seq) {
		DMSG("asn_seq or seq is null");
		return KM_ERROR_INVALID_ARGUMENT;
	}

	TEE_MemFill(asn_seq, 0, sizeof(*asn_seq));

	if (seq->buf.len > 127) {
		int val = seq->buf.len;
		while ((val = val >> 8) != 0)
			size ++;
		seq_len = size + seq->buf.len + 2;
	} else
		seq_len = size + seq->buf.len + 1;


	asn_seq->data_length = seq_len;
	asn_seq->data = TEE_Malloc(seq_len, TEE_MALLOC_FILL_ZERO);
	if (!asn_seq->data) {
		EMSG("Failed to allocate memory for asn_seq(%d)", __LINE__);
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	int k = 2;
	asn_seq->data[0] = tag;
	if (seq->buf.len > 127) {
		asn_seq->data[1] = (size | 0x80);
		for (int i = (size - 1) * 8; i >= 0; i -= 8)
			asn_seq->data[k++] = (seq->buf.len >> i);
	} else
		asn_seq->data[1] = seq->buf.len;

	TEE_MemMove(asn_seq->data + k, seq->buf.p, seq->buf.len);

	return 0;
}

keymaster_error_t TA_decode_wrapped_key_sequence(uint8_t *key_blob,
					 uint32_t key_size,
					 keymaster_key_param_set_t *auth_set,
					 keymaster_blob_t *iv,
					 keymaster_blob_t *tag,
					 keymaster_key_blob_t *transit_key,
					 keymaster_key_blob_t *secure_key,
					 keymaster_key_format_t *key_format,
					 keymaster_blob_t *wrapped_key_description) {
	int ret = 0;

	struct mbedtls_asn1_sequence km_wrapped_key = { 0 };
	struct mbedtls_asn1_sequence km_wrapped_des = { 0 };
	struct mbedtls_asn1_sequence *seq = &km_wrapped_key;
	uint8_t *blob_start = key_blob;
	size_t auth_set_size = 0;
	size_t seq_index = 0;
	uint8_t *end = NULL;
	uint8_t *start = NULL;
	uint8_t *start2 = NULL;
	int key_fmt = 0;
	size_t len = 0;
	uint32_t auth_count = 0;

	if (!key_blob || !auth_set || !iv || !tag || !transit_key ||
		!key_format || !wrapped_key_description) {
		DMSG("Input arg pointer is NULL %d", __LINE__);
		return KM_ERROR_INVALID_ARGUMENT;
	}

	ret = TA_get_asn1_sequence_of(&key_blob,
			(key_blob + key_size),
			&km_wrapped_key,
			MBEDTLS_ASN1_OCTET_STRING);
	if (ret != 0) {
		DMSG("TA_get_asn1_sequence_of OCTET_STRING failed(%d)", ret);
		goto exit;
	}

	/* The seq order for transit_key, iv, wrapped_key and tag is pre-defined
	 * and the data format can be ensured by the package version which is not
	 * used here */
	while (seq) {
		if (seq_index == 0) {
			TEE_MemFill(transit_key, 0, sizeof(*transit_key));
			transit_key->key_material_size = seq->buf.len;
			transit_key->key_material = TEE_Malloc(seq->buf.len, TEE_MALLOC_FILL_ZERO);
			if (!transit_key->key_material) {
				EMSG("Failed to allocate memory for transit key(%d)", __LINE__);
				ret = KM_ERROR_MEMORY_ALLOCATION_FAILED;
				goto exit;
			}
			TEE_MemMove(transit_key->key_material, seq->buf.p, seq->buf.len);
		} else if (seq_index == 1) {
			TEE_MemFill(iv, 0, sizeof(*iv));
			iv->data_length = seq->buf.len;
			iv->data = TEE_Malloc(iv->data_length, TEE_MALLOC_FILL_ZERO);
			if (!iv->data) {
				EMSG("Failed to allocate memory for iv(%d)", __LINE__);
				ret = KM_ERROR_MEMORY_ALLOCATION_FAILED;
				goto exit;
			}
			TEE_MemMove(iv->data, seq->buf.p, seq->buf.len);
		} else if (seq_index == 2) {
			TEE_MemFill(secure_key, 0, sizeof(*secure_key));
			secure_key->key_material_size = seq->buf.len;
			secure_key->key_material = TEE_Malloc(seq->buf.len, TEE_MALLOC_FILL_ZERO);
			if (!secure_key->key_material) {
				EMSG("Failed to allocate memory for secure key(%d)", __LINE__);
				ret = KM_ERROR_MEMORY_ALLOCATION_FAILED;
				goto exit;
			}
			TEE_MemMove(secure_key->key_material, seq->buf.p, seq->buf.len);
		} else if (seq_index == 3) {
			TEE_MemFill(tag, 0, sizeof(*tag));
			tag->data_length = seq->buf.len;
			tag->data = TEE_Malloc(tag->data_length, TEE_MALLOC_FILL_ZERO);
			if (!tag->data) {
				EMSG("Failed to allocate memory for iv(%d)", __LINE__);
				ret = KM_ERROR_MEMORY_ALLOCATION_FAILED;
				goto exit;
			}
			TEE_MemMove(tag->data, seq->buf.p, seq->buf.len);
		}
		seq_index ++;
		seq = seq->next;
	}

	if (seq_index < 4) {
		DMSG("Wrapped keyblob miss key material, iv or tag, wrong format!");
		ret = KM_ERROR_INVALID_KEY_BLOB;
		goto exit;
	}

	seq = &km_wrapped_des;
	ret = TA_get_asn1_sequence_of(&blob_start,
			(blob_start+ key_size),
			&km_wrapped_des,
			MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
	if (ret != 0) {
		DMSG("mbedtls_asn1_get_sequence_of sequence failed(%d)", ret);
		goto exit;
	}

	if ((ret = TA_encode_asn1_sequence(seq->buf.tag, seq, wrapped_key_description))) {
		EMSG("TA_encode_asn1_sequence failed(%d)", ret);
		goto exit;
	}

	end = seq->buf.p + seq->buf.len;
	start = seq->buf.p;
	ret = mbedtls_asn1_get_int(&start, end, &key_fmt);
	*key_format = key_fmt;

	if ((ret = mbedtls_asn1_get_tag(&start, end, &len,
			  MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)) < 0) {
		DMSG("invalid authrization format %d", ret);
		goto exit;
	}

	start2 = start;
	if ((ret = TA_get_auth_set(&start, end, &auth_count, NULL)) < 0) {
		DMSG("Get auth count failed %d", ret);
		goto exit;
	}
	DMSG("auth count %d", auth_count);

	TEE_MemFill(auth_set, 0, sizeof(*auth_set));
	// Additional two items for certificate validity tags and one item for sid
	auth_set->length = auth_count + 2 + 1;
	if (MUL_OVERFLOW(sizeof(keymaster_key_param_t), auth_set->length, &auth_set_size)) {
		EMSG("Overflow: too many key params! Abort!");
		ret = KM_ERROR_INVALID_INPUT_LENGTH;
		goto exit;
	}

	auth_set->params = TEE_Malloc(auth_set_size, TEE_MALLOC_FILL_ZERO);
	if (!auth_set->params) {
		EMSG("Failed to allocate memory for params");
		ret = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}

	if ((ret = TA_get_auth_set(&start2, end, &auth_count, auth_set)) < 0) {
		DMSG("TA_get_auth_set failed %d", ret);
		goto exit;
	}

exit:
	if (ret != 0) {
		if (iv->data) {
			TEE_Free(iv->data);
			iv->data = NULL;
		}
		if (tag->data) {
			TEE_Free(tag->data);
			tag->data = NULL;
		}
		if (transit_key->key_material) {
			TEE_Free(transit_key->key_material);
			transit_key->key_material = NULL;
		}
		if (secure_key->key_material) {
			TEE_Free(secure_key->key_material);
			secure_key->key_material = NULL;
		}
		if (wrapped_key_description->data) {
			TEE_Free(wrapped_key_description->data);
			wrapped_key_description->data = NULL;
		}
		if (auth_set->params) {
			TA_free_params(auth_set);
			auth_set->params = NULL;
		}
		TA_free_asn1_seq(&km_wrapped_key);
		TA_free_asn1_seq(&km_wrapped_des);
	}

	return ret;
}

keymaster_error_t TA_check_secure_id(keymaster_key_param_set_t *auth_set,
					int64_t password_sid,
					int64_t biometric_sid) {
	size_t pos;
	uint8_t sids;

	if (!auth_set) {
		EMSG("auth_set is NULL");
		return KM_ERROR_INVALID_ARGUMENT;
	}

	for (pos = 0; pos < auth_set->length; pos++) {
		if (auth_set->params[pos].tag == KM_TAG_USER_SECURE_ID)
			break;
	}

	if (pos < auth_set->length) {
		sids = (uint8_t) auth_set->params[pos].key_param.long_integer;

		for (size_t i = pos; i < auth_set->length - 1; i++)
			TEE_MemMove(&auth_set->params[i],
			  &auth_set->params[i+1], sizeof(keymaster_key_param_t));
		auth_set->length--;

		if (sids & HW_AUTH_PASSWORD) {
			auth_set->params[auth_set->length].tag = KM_TAG_USER_SECURE_ID;
			auth_set->params[auth_set->length].key_param.long_integer = password_sid;
			auth_set->length++;
		}

		if (sids & HW_AUTH_FINGERPRINT) {
			auth_set->params[auth_set->length].tag = KM_TAG_USER_SECURE_ID;
			auth_set->params[auth_set->length].key_param.long_integer = biometric_sid;
			auth_set->length++;
		}
	}

	return KM_ERROR_OK;
}

keymaster_error_t TA_construct_transport_key_params(keymaster_key_param_set_t *aes_params)
{
	uint32_t aes_set_size = 0;

	if (!aes_params) {
		EMSG("aes_params is NULL");
		return KM_ERROR_INVALID_ARGUMENT;
	}

	aes_params->length = 8;
	if (MUL_OVERFLOW(sizeof(keymaster_key_param_t), aes_params->length, &aes_set_size)) {
		EMSG("Overflow: too many key params! Abort!");
		return KM_ERROR_INVALID_INPUT_LENGTH;
	}

	aes_params->params = TEE_Malloc(aes_set_size, TEE_MALLOC_FILL_ZERO);
	if (!aes_params->params) {
		EMSG("Failed to allocate memory for params");
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	aes_params->params[0].tag = KM_TAG_ALGORITHM;
	aes_params->params[0].key_param.enumerated = KM_ALGORITHM_AES;
	aes_params->params[1].tag = KM_TAG_KEY_SIZE;
	aes_params->params[1].key_param.integer = 256;
	aes_params->params[2].tag = KM_TAG_BLOCK_MODE;
	aes_params->params[2].key_param.enumerated = KM_MODE_GCM;
	aes_params->params[3].tag = KM_TAG_PURPOSE;
	aes_params->params[3].key_param.enumerated = KM_PURPOSE_ENCRYPT;
	aes_params->params[4].tag = KM_TAG_PURPOSE;
	aes_params->params[4].key_param.enumerated = KM_PURPOSE_DECRYPT;
	aes_params->params[5].tag = KM_TAG_PADDING;
	aes_params->params[5].key_param.enumerated = KM_PAD_NONE;
	aes_params->params[6].tag = KM_TAG_MIN_MAC_LENGTH;
	aes_params->params[6].key_param.integer = 128;
	aes_params->params[7].tag = KM_TAG_NO_AUTH_REQUIRED;
	aes_params->params[7].key_param.boolean = true;

	return 0;
}
