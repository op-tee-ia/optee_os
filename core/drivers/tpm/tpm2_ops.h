// SPDX-License-Identifier: BSD-2-Clause
/*
 *  Copyright (c) 2023 Intel Corporation
*/

#ifndef _TPM2_OPS_H_
#define _TPM2_OPS_H_

#include <efi.h>
#include <lib.h>

EFI_STATUS tpm2_get_cap_permanent(TPMA_PERMANENT *per);

EFI_STATUS tpm2_create_nvindex(TPMI_RH_NV_INDEX nv_index,
                               TPMA_NV attributes,
                               UINT16 data_size);

EFI_STATUS tpm2_delete_index(IN UINT32 index);

EFI_STATUS tpm2_read_nvindex(TPMI_RH_NV_INDEX nv_index,
                            UINT16 data_size,
							BYTE *data,
							UINT16 offset);

EFI_STATUS tpm2_read_lock_nvindex(TPMI_RH_NV_INDEX nv_index);


EFI_STATUS tpm2_write_nvindex(TPMI_RH_NV_INDEX nv_index,
                              UINT16 data_size,
							  BYTE *data,
							  UINT16 offset);

EFI_STATUS tpm2_write_lock_nvindex(TPMI_RH_NV_INDEX nv_index);

EFI_STATUS create_index_and_write_lock(TPM_NV_INDEX nv_index, TPMA_NV attributes,
					      UINT16 data_size, BYTE *data);
#endif