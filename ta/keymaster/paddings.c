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


#include "paddings.h"

bool TA_check_pkcs7_pad(uint32_t block_size, keymaster_blob_t *output)
{
	uint32_t last_i;
	uint8_t pad;

	if (output->data == NULL || output->data_length == 0 ||
			output->data_length < block_size ||
			output->data_length % block_size != 0)
		return false;
	last_i = output->data_length - 1;
	pad = output->data[last_i];
	if (pad > block_size || pad > output->data_length)
		return false;
	for (uint32_t i = 0; i < pad; i++) {
		if (output->data[last_i - i] != pad)
			return false;
	}
	return true;
}

keymaster_error_t TA_check_out_size(uint32_t block_size, const uint32_t input_l,
					keymaster_blob_t *output,
					uint32_t *out_size,
					uint32_t tag_len)
{
	uint8_t *ptr = NULL;

	/* Recalculate output size */
	if (*out_size != (((input_l + block_size - 1) / block_size + 1)
						* block_size + tag_len)) {
		*out_size = ((input_l + block_size - 1) / block_size + 1)
							* block_size + tag_len;
		ptr = TEE_Realloc(output->data, *out_size);
		if (!ptr) {
			EMSG("Failed reallocate memory for output");
			return KM_ERROR_MEMORY_ALLOCATION_FAILED;
		}
		output->data = ptr;
	}
	return KM_ERROR_OK;
}

keymaster_error_t TA_add_pkcs7_pad(uint32_t block_size, keymaster_blob_t *input, uint32_t buffering_size,
				const bool force, keymaster_blob_t *output,
				uint32_t *out_size, bool *is_input_ext)
{
	uint32_t pad = 0;
	uint8_t *data = NULL;

	if (input == NULL) {
		EMSG("Input is NULL");
		return KM_ERROR_UNEXPECTED_NULL_POINTER;
	}
	if (input->data_length == 0 && buffering_size == 0 && !force)
		return KM_ERROR_OK;
	pad = block_size - ((input->data_length + buffering_size) % block_size);
	DMSG("PKCS7 ADD pad = 0x%x", pad);
	/* if input data size is a multiple of block size add
	 * one extra block as padding
	 */
	if (pad == 0)
		pad = block_size;
	/* Freed before input blob is destroyed by caller */
	data = TEE_Malloc(pad + input->data_length, TEE_MALLOC_FILL_ZERO);
	if (!data) {
		EMSG("Failed to allocate memory for buffer on padding adding");
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}
	if (input->data_length > 0)
		TEE_MemMove(data, input->data, input->data_length);
	TEE_MemFill(data + input->data_length, pad, pad);
	if (*is_input_ext)
		TEE_Free(input->data);
	input->data = data;
	input->data_length = input->data_length + pad;
	*is_input_ext = true;
	return TA_check_out_size(block_size, input->data_length, output, out_size, 0);
}

keymaster_error_t TA_remove_pkcs7_pad(uint32_t block_size, keymaster_blob_t *output,
					uint32_t *out_size)
{
	uint32_t pad = 0;
	uint8_t *data;

	if (output == NULL) {
		EMSG("Output is NULL");
		return KM_ERROR_UNEXPECTED_NULL_POINTER;
	}
	if (output->data_length == 0)
		return KM_ERROR_OK;
	pad = output->data[output->data_length - 1];
	DMSG("PKCS7 REMOVE pad = %x", pad);
	if (!TA_check_pkcs7_pad(block_size, output)) {
		EMSG("Failed to read PKCS7 padding");
		return KM_ERROR_INVALID_ARGUMENT;
	}
	/* Freed before output blob is destroyed by caller */
	data = TEE_Realloc(output->data, output->data_length - pad);
	if (!data) {
		EMSG("Failed to reallocate memory for unpudded out");
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}
	output->data = data;
	output->data_length = output->data_length - pad;
	*out_size = output->data_length;
	return KM_ERROR_OK;
}

keymaster_error_t TA_do_rsa_pad(uint8_t **input, uint32_t *input_l,
				const uint32_t key_size)
{
	uint8_t *buf;
	uint32_t key_size_bytes = key_size / 8;

	/* Freed before input blob is destroyed by caller */
	buf = TEE_Malloc(key_size_bytes, TEE_MALLOC_FILL_ZERO);
	if (!buf) {
		EMSG("Failed to allocate memory for padded RSA input");
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}
	TEE_MemMove(buf + key_size_bytes - *input_l, *input, *input_l);
	TEE_Free(*input);
	*input = buf;
	*input_l = key_size_bytes;
	return KM_ERROR_OK;
}

/* Padding according PKCS#1 v1_5 (https://tools.ietf.org/html/rfc2437#section-9.2.1),
 * with modification from https://source.android.com/security/keystore/implementer-ref#begin
 * (when Digest::NONE and PaddingMode::RSA_PKCS1_1_5_SIGN) */
keymaster_error_t TA_do_rsa_pkcs_v1_5_rawpad(uint8_t **input, uint32_t *input_l,
					     const uint32_t key_size)
{
	uint8_t *buf;
	uint32_t key_size_bytes = key_size / 8;

	/* Freed before input blob is destroyed by caller */
	buf = TEE_Malloc(key_size_bytes, TEE_MALLOC_FILL_ZERO);
	if (!buf) {
		EMSG("Failed to allocate memory for padded RSA input");
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	/* adding padding */
	buf[0] = 0;
	buf[1] = 1;
	TEE_MemFill(buf + 2, 0xFF, key_size_bytes - 3 - *input_l);
	buf[key_size_bytes - *input_l - 1] = 0;
	TEE_MemMove(buf + key_size_bytes - *input_l, *input, *input_l);
	TEE_Free(*input);
	*input = buf;
	*input_l = key_size_bytes;
	return KM_ERROR_OK;
}
