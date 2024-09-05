/*
 *
 * INTEL CONFIDENTIAL
 *
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

#include "crypto_des.h"

static bool TA_is_stream_cipher(const keymaster_block_mode_t mode)
{
	switch (mode) {
	case KM_MODE_CBC:
	case KM_MODE_ECB:
		return false;
	default:/*KM_MODE_GCM, KM_MODE_CTR*/
		return true;
	}
}

keymaster_error_t TA_des_finish(keymaster_operation_t *operation,
 				keymaster_blob_t *input,
 				keymaster_blob_t *output, uint32_t *out_size,
				bool *is_input_ext)
{
	keymaster_error_t res = KM_ERROR_OK;

	if (operation->padding == KM_PAD_PKCS7 &&
			operation->purpose == KM_PURPOSE_ENCRYPT) {
		if (operation->prev_in_size == UNDEFINED)
			operation->prev_in_size = 0;
		res = TA_add_pkcs7_pad(DES_BLOCK_SIZE, input, operation->prev_in_size, !operation->padded,
							output, out_size, is_input_ext);
		if (res != KM_ERROR_OK)
			goto out;
		operation->padded = true;
		operation->prev_in_size = 0;
	} else if (operation->padding == KM_PAD_NONE && (operation->mode ==
			KM_MODE_CBC || operation->mode == KM_MODE_ECB) &&
			input->data_length % DES_BLOCK_SIZE != 0) {
		EMSG("Input data size for DES CBC and ECB modes without padding must be a multiple of block size");
		res = KM_ERROR_INVALID_INPUT_LENGTH;
		goto out;
	} else if (operation->padding == KM_PAD_PKCS7 &&
			operation->purpose == KM_PURPOSE_DECRYPT &&
			input->data_length % DES_BLOCK_SIZE != 0) {
		EMSG("Input data size for DES PKCS7 must be a multiple of block size");
		res = KM_ERROR_INVALID_INPUT_LENGTH;
		goto out;
	}
	res = TEE_CipherDoFinal(*operation->operation, input->data,
				input->data_length, output->data,
				out_size);
	output->data_length = *out_size;
	if (res == KM_ERROR_OK && operation->padding == KM_PAD_PKCS7
			&& operation->purpose == KM_PURPOSE_DECRYPT) {
		if (output->data_length > 0) {
			res = TA_remove_pkcs7_pad(DES_BLOCK_SIZE, output, out_size);
			if (res == KM_ERROR_OK)
				operation->padded = true;
		}
		if (!operation->padded) {
			EMSG("Padding was not removed");
			res = KM_ERROR_INVALID_ARGUMENT;
		}
	}
out:
	return res;
}

static keymaster_error_t TA_store_last_block(keymaster_blob_t *output,
					size_t *input_consumed,
					keymaster_operation_t *op)
{
	if (output->data_length < DES_BLOCK_SIZE) {
		EMSG("Output is too smal to be stored");
		return KM_ERROR_UNKNOWN_ERROR;
	}
	op->last_block.data = TEE_Malloc(DES_BLOCK_SIZE, TEE_MALLOC_FILL_ZERO);
	if (!op->last_block.data) {
		EMSG("Failed to allocate memory for last block buffer");
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}
	TEE_MemMove(op->last_block.data, output->data +
		output->data_length - DES_BLOCK_SIZE, DES_BLOCK_SIZE);
	output->data_length -= DES_BLOCK_SIZE;
	*input_consumed -= DES_BLOCK_SIZE;
	op->prev_in_size += DES_BLOCK_SIZE;
	op->last_block.data_length = DES_BLOCK_SIZE;
	return KM_ERROR_OK;
}

static keymaster_error_t TA_restore_last_block(keymaster_blob_t *output,
					size_t *input_consumed,
					keymaster_operation_t *op,
					uint32_t *pos)
{
	if (op->last_block.data_length != DES_BLOCK_SIZE) {
		EMSG("Stored block has a bad size");
		return KM_ERROR_UNKNOWN_ERROR;
	}
	TEE_MemMove(output->data, op->last_block.data, DES_BLOCK_SIZE);
	*input_consumed += DES_BLOCK_SIZE;
	*pos += DES_BLOCK_SIZE;
	op->last_block.data_length = 0;
	TEE_Free(op->last_block.data);
	op->last_block.data = NULL;
	output->data_length += DES_BLOCK_SIZE;
	return KM_ERROR_OK;
}

keymaster_error_t TA_des_update(keymaster_operation_t *operation,
				keymaster_blob_t *input,
				keymaster_blob_t *output,
				uint32_t *out_size,
				const uint32_t input_provided,
				size_t *input_consumed,
				bool *is_input_ext)
{
	keymaster_error_t res = KM_ERROR_OK;
	uint32_t pos = 0U;
	uint32_t remainder = 0;
	uint32_t in_size = DES_BLOCK_SIZE;
	static bool remainder_from_last_update = false;

	/* KM_MODE_CBC, KM_MODE_ECB */
	if (!TA_is_stream_cipher(operation->mode)) {
		if (operation->last_block.data != NULL && operation->last_block.data_length != 0) {
			DMSG("Restore last block");
			res = TA_restore_last_block(output, input_consumed, operation, &pos);
			if (res != KM_ERROR_OK) {
				EMSG("Failed to restore last block");
				goto out;
			}
		}
		if (operation->padding == KM_PAD_PKCS7) {
			if (operation->prev_in_size == input->data_length) {
				DMSG("End of data reached");
				operation->buffering = false;
			} else {
				DMSG("Buffering ON");
				operation->buffering = true;
			}
			if (operation->prev_in_size == UNDEFINED
					&& input->data_length == DES_BLOCK_SIZE) {
				operation->prev_in_size = input->data_length;
				/* calculate memory left.
				 * Add DES_BLOCK_SIZE in case adding padding
				 */
				*out_size = DES_BLOCK_SIZE + input->data_length -
						output->data_length;
				res = TEE_CipherUpdate(*operation->operation,
					input->data, in_size,
					output->data, out_size);
				if (res != TEE_SUCCESS) {
					EMSG("Error TEE_CipherUpdate, res=%x", res);
					goto out;
				}
				output->data_length = *out_size;
				*input_consumed = in_size;
				if (*out_size == DES_BLOCK_SIZE)
					operation->prev_in_size -= *out_size;
				goto out;
			}
			if (operation->purpose == KM_PURPOSE_DECRYPT) {
				if (input->data_length > DES_BLOCK_SIZE) {
					operation->prev_in_size = input->data_length;
					operation->buffering = false;
				} else {
					operation->buffering = true;
					if (operation->prev_in_size == UNDEFINED)
						operation->prev_in_size = 0;
					if ((remainder_from_last_update == true) &&
					     operation->prev_in_size == input->data_length) {
						operation->prev_in_size = 0;
						remainder_from_last_update = false;
					}
					operation->prev_in_size += input->data_length;
				}
			} else {
				operation->buffering = true;
				if (operation->prev_in_size == UNDEFINED)
					operation->prev_in_size = 0;

				if ((remainder_from_last_update == true) &&
				     operation->prev_in_size == input->data_length) {
					operation->prev_in_size = 0;
					remainder_from_last_update = false;
				}
				operation->prev_in_size += input->data_length;
			}
			if (operation->buffering && ((input->data_length <=
					DES_BLOCK_SIZE && operation->purpose ==
					KM_PURPOSE_DECRYPT) ||
					(input->data_length < DES_BLOCK_SIZE &&
					operation->purpose ==
					KM_PURPOSE_ENCRYPT))) {
				DMSG("Input data is too small. Buffering");
				/* Buffering if data
				 * transferred by chunks
				 */
				in_size = input->data_length;
				/* calculate memory left.
				 * Add DES_BLOCK_SIZE in case adding padding
				 */
				*out_size = DES_BLOCK_SIZE + input->data_length -
						output->data_length;
				res = TEE_CipherUpdate(*operation->operation,
					input->data, in_size,
					output->data, out_size);
				if (res != TEE_SUCCESS) {
					EMSG("Error TEE_CipherUpdate, res=%x", res);
					goto out;
				}
				output->data_length = *out_size;
				*input_consumed = in_size;
				operation->prev_in_size -= *out_size;
				if ((operation->purpose == KM_PURPOSE_DECRYPT) &&
					(*out_size == DES_BLOCK_SIZE)) {
					goto out1;
				}
				goto out;
			}
			DMSG("Some blocks can be processed");
		} else {/* KM_PAD_NONE */
			operation->prev_in_size = input->data_length;
			if (input->data_length < DES_BLOCK_SIZE) {
				/* Buffering if data
				 * transferred by chunks
				 */
				in_size = input->data_length;
				/* calculate memory left.
				 * Add DES_BLOCK_SIZE in case adding padding
				 */
				*out_size = DES_BLOCK_SIZE + input->data_length -
						output->data_length;
				res = TEE_CipherUpdate(*operation->operation,
					input->data, in_size,
					output->data, out_size);
				if (res != TEE_SUCCESS) {
					EMSG("Error TEE_CipherUpdate, res=%x", res);
					goto out;
				}
				output->data_length = *out_size;
				*input_consumed = in_size;
				operation->prev_in_size -= in_size;
				goto out;
			}
		}
	}

	/* only KM_MODE_CBC and KM_MODE_ECB */
	if (operation->padding == KM_PAD_PKCS7 && !operation->buffering &&
			operation->purpose == KM_PURPOSE_ENCRYPT) {
		DMSG("Adding padding before encryption");
		res = TA_add_pkcs7_pad(DES_BLOCK_SIZE, input, operation->prev_in_size, !operation->padded,
					output, out_size, is_input_ext);
		if (res != KM_ERROR_OK)
			goto out;
		operation->padded = true;
	}
	remainder = input->data_length - pos;
	while (remainder / DES_BLOCK_SIZE != 0) {
		/* calculate memory left.
		 * Add DES_BLOCK_SIZE in case adding padding
		 */
		*out_size = DES_BLOCK_SIZE + input->data_length -
						output->data_length;
		res = TEE_CipherUpdate(*operation->operation,
				input->data + pos, in_size,
				output->data + pos, out_size);
		if (res != TEE_SUCCESS) {
			EMSG("Error TEE_CipherUpdate, res=%x", res);
			goto out;
		}
		output->data_length += *out_size;
		pos += in_size;
		*input_consumed += in_size;
		operation->prev_in_size -= in_size;
		remainder -= in_size;
		if (remainder < DES_BLOCK_SIZE) {
			if (!TA_is_stream_cipher(operation->mode) &&
			    operation->padding == KM_PAD_PKCS7 &&
			    (remainder > 0)) {
				remainder_from_last_update = true;
			}
			break;
		}
	}
out1:
	if (*input_consumed > input_provided)
		*input_consumed = input_provided;
	if (res == KM_ERROR_OK && operation->padding == KM_PAD_PKCS7 &&
			operation->purpose == KM_PURPOSE_DECRYPT
			&& *input_consumed == input_provided) {
		if (operation->buffering && TA_check_pkcs7_pad(DES_BLOCK_SIZE, output)
						&& operation->first) {
			DMSG("Store last block");
			res = TA_store_last_block(output, input_consumed,
								operation);
			if (res != KM_ERROR_OK) {
				EMSG("Failed to store last block");
				goto out;
			}
		}
		if (!operation->buffering || TA_check_pkcs7_pad(DES_BLOCK_SIZE, output)) {
			DMSG("Remove PKCS7 pad");
			res = TA_remove_pkcs7_pad(DES_BLOCK_SIZE, output, out_size);
			if (res == KM_ERROR_OK) {
				operation->padded = true;
			} else if (res == KM_ERROR_INVALID_ARGUMENT) {
				DMSG("No padding");
				res = KM_ERROR_OK;
			}
		}
	}
	operation->first = false;
out:
	return res;
}
