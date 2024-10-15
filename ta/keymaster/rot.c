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
extern bool g_isEarlyBootEnded;

static keymaster_error_t TA_restore_km_info()
{
	keymaster_error_t res = KM_ERROR_OK;

	res = TA_get_rot_data();
	if (res != KM_ERROR_OK && res != KM_ERROR_ROOT_OF_TRUST_ALREADY_SET) {
		EMSG("Failed(%d) to get root of trust data", res);
		goto out;
	}
	if (res == KM_ERROR_ROOT_OF_TRUST_ALREADY_SET)
		res = KM_ERROR_OK;
	optee_km_context.rot_info_set = true;

	optee_km_context.os_version =
				optee_km_context.rot.km_info[KM_OS_VERSION];
	optee_km_context.os_patchlevel =
				optee_km_context.rot.km_info[KM_OS_PATCH_LEVEL];
	optee_km_context.vendor_patchlevel =
				optee_km_context.rot.km_info[KM_VENDOR_PATCH_LEVEL];
	optee_km_context.boot_patchlevel =
				optee_km_context.rot.rot_data.patchMonthYearDay;
	if (optee_km_context.rot.km_info[KM_EARLY_BOOT_SET] != 0)
		g_isEarlyBootEnded = true;
	else
		g_isEarlyBootEnded = false;

out:
	return res;
}

keymaster_error_t TA_init_km_context(void)
{
	keymaster_error_t res = KM_ERROR_OK;

	memset(&optee_km_context, 0, sizeof(tee_km_context_t));
	optee_km_context.version_info_set = false;
	optee_km_context.vendor_patchlevel_set = false;
	optee_km_context.rot_info_set = false;
	memset(&optee_dice_context, 0, sizeof(tee_dice_context_t));
	optee_dice_context.cdi_set = false;

	res = TA_restore_km_info();
	if (res)
		DMSG("Restore the km info from kernel rot data failed");

	return res;
}

keymaster_error_t TA_get_rot_data(void)
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
	params[0].memref.size = sizeof(struct ex_rot_data_t);

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

keymaster_error_t TA_configure_rot_info(enum KM_SLOT_INDEX index, uint32_t value)
{
	TEE_TASessionHandle sess = TEE_HANDLE_NULL;
	TEE_Param params[TEE_NUM_PARAMS] = { };
	TEE_Result res = TEE_ERROR_GENERIC;

	uint32_t ret_orig = 0;
	uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
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


	params[0].value.a = index;
	params[0].value.b = value;

	DMSG("## PTA_SYSTEM_SET_ROT >");
	res = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE,
				  PTA_SYSTEM_SET_ROT,
				  param_types, params, &ret_orig);
	DMSG("## PTA_SYSTEM_SET_ROT <");
	if (res) {
		EMSG("Failed(%d) to invoke PTA command", res);
		res = KM_ERROR_UNKNOWN_ERROR;
		goto out;
	}

out:
	TEE_CloseTASession(sess);

	return res;
}
