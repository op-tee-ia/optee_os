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


#include <pta_system.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "rot.h"

tee_km_context_t optee_km_context;
tee_dice_context_t optee_dice_context;

void TA_init_km_context(void)
{
	memset(&optee_km_context, 0, sizeof(tee_km_context_t));
	optee_km_context.version_info_set = false;
	optee_km_context.vendor_patchlevel_set = false;
	optee_km_context.boot_patchlevel_set = false;
	optee_km_context.rot_info_set = false;
	memset(&optee_dice_context, 0, sizeof(tee_dice_context_t));
	optee_dice_context.cdi_set = false;
}

keymaster_error_t TA_set_rot_data(void)
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
		EMSG("Failed(%d) to invoke PTA command", res);
		res = KM_ERROR_UNKNOWN_ERROR;
		goto out;
	}

out:
	TEE_CloseTASession(sess);

	return res;
}
