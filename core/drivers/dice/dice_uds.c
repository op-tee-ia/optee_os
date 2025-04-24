// SPDX-License-Identifier: BSD-2-Clause
/*
 *  Copyright (c) 2023 Intel Corporation
 */

#include <crypto/crypto.h>
#include <initcall.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/panic.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdlib.h>
#include <string.h>
#include <tee/tee_cryp_utl.h>
#include <trace.h>
#include <util.h>
#include <dice/dice.h>
#include <dice/known_test_values.h>
#include <kernel/tee_common_otp.h>

uint8_t g_uds[UDS_LENGTH] __nex_data = { 0 };
static bool g_dice_initialized __nex_data = false;


static TEE_Result dice_init(void)
{
	TEE_Result ret = TEE_SUCCESS;

#ifdef CFG_EDK2_TPM
	if (!g_dice_initialized) {
		ret = tee_otp_get_hw_uds(g_uds, sizeof(g_uds));
		if (TEE_SUCCESS != ret) {
			panic("Failed to get UDS.");
		}

		g_dice_initialized = true;
		DMSG("Successfully init UDS from TPM.");
	} else {
		DMSG("DICE already initialized");
	}
#else
	DMSG("FAKE UDS is used!");
#endif

	return ret;
}

driver_init(dice_init);
