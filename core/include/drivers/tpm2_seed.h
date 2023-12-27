/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023, Intel Corporation
 */

#ifndef DRIVER_TPM2_SEED_H
#define DRIVER_TPM2_SEED_H

#include <efi.h>
#include <lib.h>

EFI_STATUS tee_tpm2_init(void);
EFI_STATUS tee_tpm2_end(void);
EFI_STATUS tee_tpm2_read_device_state(UINT8 *state);
EFI_STATUS tee_tpm2_write_device_state(UINT8 state);
EFI_STATUS tee_tpm2_read_rollback_index(size_t rollback_index_slot, uint64_t *out_rollback_index);
EFI_STATUS tee_tpm2_write_rollback_index(size_t rollback_index_slot, uint64_t rollback_index);
BOOLEAN tee_tpm2_bootloader_need_init(void);
EFI_STATUS tee_tpm2_fuse_lock_owner(void);


#endif
