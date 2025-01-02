// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2024, Intel Corporation */

#include <pta_system.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "rot.h"

tee_km_context_t optee_km_context;
tee_dice_context_t optee_dice_context;
extern bool g_isEarlyBootEnded;
extern TEE_TASessionHandle session_ptaSTA;

static keymaster_error_t TA_get_rot_data(void)
{
	TEE_Param params[TEE_NUM_PARAMS] = { };
	TEE_Result res = TEE_ERROR_GENERIC;

	uint32_t ret_orig = 0;
	uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);

	params[0].memref.buffer = &optee_km_context.rot;
	params[0].memref.size = sizeof(struct ex_rot_data_t);

	res = TEE_InvokeTACommand(session_ptaSTA, TEE_TIMEOUT_INFINITE,
				  PTA_SYSTEM_GET_ROT,
				  param_types, params, &ret_orig);
	if (res) {
		EMSG("Failed(%d) to invoke PTA command", res);
		res = KM_ERROR_UNKNOWN_ERROR;
		goto out;
	}

out:
	return res;
}

keymaster_error_t TA_restore_km_info(void)
{
	keymaster_error_t res = KM_ERROR_OK;

	res = TA_get_rot_data();
	if (res != KM_ERROR_OK) {
		EMSG("Failed(%d) to get root of trust data", res);
		goto out;
	}

	optee_km_context.os_version =
				optee_km_context.rot.km_info[KM_OS_VERSION];
	optee_km_context.os_patchlevel =
				optee_km_context.rot.km_info[KM_OS_PATCH_LEVEL];
	optee_km_context.vendor_patchlevel =
				optee_km_context.rot.km_info[KM_VENDOR_PATCH_LEVEL];
	optee_km_context.boot_patchlevel =
				optee_km_context.rot.rot_data.patchMonthYearDay;
	if (optee_km_context.rot.km_info[KM_EARLY_BOOT_SET] != 0) {
		g_isEarlyBootEnded = true;
		optee_km_context.version_info_set = true;
		optee_km_context.vendor_patchlevel_set = true;
	} else {
		g_isEarlyBootEnded = false;
		optee_km_context.version_info_set = false;
		optee_km_context.vendor_patchlevel_set = false;
	}

out:
	return res;
}

void TA_init_km_context(void)
{
	memset(&optee_km_context, 0, sizeof(tee_km_context_t));
	optee_km_context.version_info_set = false;
	optee_km_context.vendor_patchlevel_set = false;
	memset(&optee_dice_context, 0, sizeof(tee_dice_context_t));
	optee_dice_context.cdi_set = false;
}

keymaster_error_t TA_configure_rot_info(enum KM_SLOT_INDEX index, uint32_t value)
{
	TEE_Param params[TEE_NUM_PARAMS] = { };
	TEE_Result res = TEE_ERROR_GENERIC;

	uint32_t ret_orig = 0;
	uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);

	params[0].value.a = index;
	params[0].value.b = value;

	res = TEE_InvokeTACommand(session_ptaSTA, TEE_TIMEOUT_INFINITE,
				  PTA_SYSTEM_SET_ROT,
				  param_types, params, &ret_orig);
	if (res) {
		EMSG("Failed(%d) to invoke PTA command", res);
		res = KM_ERROR_UNKNOWN_ERROR;
		goto out;
	}

out:
	return res;
}
