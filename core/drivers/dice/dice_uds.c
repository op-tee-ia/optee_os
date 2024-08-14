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

//TODO hard code UDS with all 0, will fix it by getting UDS from TPM device
uint8_t g_uds[32] = { 0 };

static TEE_Result dice_init(void)
{
    size_t next_cdi_certificate_buffer_size = 2048;
    uint8_t next_cdi_certificate[next_cdi_certificate_buffer_size];
    size_t next_cdi_certificate_actual_size = 0;
    uint8_t next_cdi_attest[DICE_CDI_SIZE] = { 0 };
    uint8_t next_cdi_seal[DICE_CDI_SIZE] = { 0 };
    DiceInputValues input_values = { 0 };

    DMSG("%s %d", __func__, __LINE__);

    DiceResult ret = DiceMainFlow(NULL,
                                  g_uds,
                                  g_uds,
                                  &input_values,
                                  next_cdi_certificate_buffer_size,
                                  next_cdi_certificate,
                                  &next_cdi_certificate_actual_size,
                                  next_cdi_attest,
                                  next_cdi_seal);

    if (ret != kDiceResultOk) {
        EMSG("Generate DICE certificate and CDI attestation failed");
	return TEE_ERROR_GENERIC;
    }

    DMSG("next_cdi_certificate_actual_size: %ld", next_cdi_certificate_actual_size);
    return TEE_SUCCESS;
}
driver_init(dice_init);
