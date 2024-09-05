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


#include "crypto_ec.h"
#include "mbedtls_proxy.h"

static keymaster_error_t TA_check_ec_data_size(uint8_t **data, uint32_t *data_l,
				const uint32_t key_size)
{
	keymaster_error_t res = KM_ERROR_OK;
	uint32_t key_size_bytes = (key_size + 7) / 8;

	/*
	 * If the data provided for signing
	 * or verification is too long, truncate it
	 */
	if (*data_l >= key_size_bytes) {
		/* assemed that data represented as big endian,
		 * so first zero can be ignored
		 */
		while (*data_l > key_size_bytes && (*data)[0] == 0) {
			(*data_l)--;
			(*data)++;
		}
		*data_l = key_size_bytes;
		if (key_size < *data_l * 8) {
			TA_short_be_rshift(*data, *data_l,
				8 - (key_size & 0x7));
		}
	}

	return res;
}

keymaster_error_t TA_ec_update(keymaster_operation_t *operation,
				const keymaster_blob_t *input,
				keymaster_blob_t *output,
				size_t *input_consumed,
				const uint32_t input_provided)
{
	keymaster_error_t res = KM_ERROR_OK;

	switch (operation->purpose) {
	case KM_PURPOSE_VERIFY:
	case KM_PURPOSE_SIGN:
		if (*operation->digest_op != TEE_HANDLE_NULL) {
			TEE_DigestUpdate(*operation->digest_op, input->data,
							input->data_length);
		} else {
			/* if digest is not specified save all
			 * blocks to use it in finish
			 */
			res = TA_store_sf_data(input, operation);
		}
		*input_consumed = input_provided;
		output->data_length = 0;
		break;
	default:
		res = KM_ERROR_UNSUPPORTED_PURPOSE;
	}
	return res;
}

keymaster_error_t TA_ec_finish(const keymaster_operation_t *operation,
				keymaster_blob_t *input,
				keymaster_blob_t *output,
				keymaster_blob_t *signature,
				uint32_t *out_size,
				const uint32_t key_size,
				bool *is_input_ext)
{
	keymaster_error_t res = KM_ERROR_OK;
	uint32_t digest_out_size = KM_MAX_DIGEST_SIZE;
	uint8_t digest_out[KM_MAX_DIGEST_SIZE];
	uint8_t *in_buf = NULL;
	uint32_t in_buf_l = 0;

	switch (operation->purpose) {
	case KM_PURPOSE_VERIFY:
	case KM_PURPOSE_SIGN:
		if (*operation->digest_op != TEE_HANDLE_NULL) {
			res = TEE_DigestDoFinal(*operation->digest_op,
					input->data,
					input->data_length,
					digest_out,
					&digest_out_size);
			if (res != KM_ERROR_OK) {
				EMSG("Failed to obtain digest for EC, res=%x", res);
				break;
			}
			in_buf = digest_out;
			in_buf_l = digest_out_size;
		} else {
			res = TA_append_sf_data(input, operation, is_input_ext);
			if (res != KM_ERROR_OK)
				break;
			/* Output size wount change ahen
			 * stored data is appended
			 */
			in_buf = input->data;
			in_buf_l = input->data_length;
		}
		/* If the data provided for unpadded signing or
		 * verification is too long, truncate it.
		 */
		res = TA_check_ec_data_size(&in_buf, &in_buf_l, key_size);
		if (res != KM_ERROR_OK)
			break;

		if (operation->purpose == KM_PURPOSE_SIGN) {
			res = TEE_AsymmetricSignDigest(*operation->operation,
							NULL, 0, in_buf,
							in_buf_l, output->data,
							out_size);
			if (res == TEE_SUCCESS && *out_size > 0) {
				res = mbedTLS_encode_ec_sign(output->data,
							     out_size);
				if (res != KM_ERROR_OK) {
					EMSG("Failed to encode EC sign, res=%x",
					     res);
					break;
				}
			}
		} else {
			*out_size = 0;
			res = mbedTLS_decode_ec_sign(signature, key_size);
			if (res != KM_ERROR_OK) {
				EMSG("Failed to decode EC sign, res=%x", res);
				break;
			}
			res = TEE_AsymmetricVerifyDigest(*operation->operation,
							NULL, 0, in_buf,
							in_buf_l,
							signature->data,
							signature->data_length);
			/* Convert error code to Android style */
			if (res == (int) TEE_ERROR_SIGNATURE_INVALID)
				res = KM_ERROR_VERIFICATION_FAILED;
		}
		break;
	default:
		res = KM_ERROR_UNSUPPORTED_PURPOSE;
	}
	return res;
}
