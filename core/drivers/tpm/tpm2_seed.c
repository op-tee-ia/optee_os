// SPDX-License-Identifier: BSD-2-Clause
/*
 *  Copyright (c) 2023 Intel Corporation
 */

#include <efi.h>
#include <lib.h>
#include <byteswap.h>
#include <Tcg2Protocol.h>
#include <Tpm2CommandLib.h>
#include <Tpm2Help.h>

#include <string.h>
#include <trace.h>
#include <Base.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <types_ext.h>
#include <kernel/tee_common_otp.h>

#include "tpm2_ops.h"

uint64_t g_tpm_base_vaddr = 0;

static bool g_huk_initialized = false;
static uint8_t g_huk[HW_UNIQUE_KEY_LENGTH] = {0};

#define NV_INDEX_OPTEEOS_SEED  0x01500050

typedef struct {
	TPMI_RH_NV_INDEX nv_index;
	TPMA_NV attribute;
} attribute_matrix_t;

static const attribute_matrix_t config_table =
{
	NV_INDEX_OPTEEOS_SEED,
	{
		/* The Index data can be written if Owner Authorization is provided. */
		.TPMA_NV_OWNERWRITE = 1,
		/* Authorizations to change the Index contents that require
			* USER role may be provided with an HMAC session or password.
		*/
		.TPMA_NV_AUTHWRITE = 1,
		/* The Index data may be read if the authValue is provided. */
		. TPMA_NV_AUTHREAD = 1,
		/* A partial write of the Index data is not allowed. The write size
			* shall match the defined space size.
			*/
		.TPMA_NV_WRITEALL = 1,
		/* TPM2_NV_WriteLock may be used to prevent further writes
			* to this location regardless of TPM reset/restart.
			*/
		.TPMA_NV_WRITEDEFINE = 1,
		/* TPM2_NV_ReadLock may be used to SET TPMA_NV_READLOCKED
			* for this Index. When TPMA_NV_READLOCKED is set after calling TPM2_NV_ReadLock,
			* Reads of this Index are blocked until the next TPM Reset or TPM Restart.
			*/
		.TPMA_NV_READ_STCLEAR = 1,
	}
};

register_phys_mem(MEM_AREA_IO_SEC, _PCD_VALUE_PcdTpmBaseAddress, 0x1000);


static EFI_STATUS tpm2_check_cap_permanent(void)
{
	EFI_STATUS ret;
	TPMA_PERMANENT per;

	ret = tpm2_get_cap_permanent(&per);
	if (EFI_ERROR(ret)) {
		EMSG("Check TPM cap permanent for lockoutAuthSet failed(%lx)", ret);
		return ret;
	}

	/* Verify the LOCKOUT_AUTH */
	if (!per.lockoutAuthSet)
		IMSG("TPM LOCKOUT_AUTH is not set, set it can get higher security");

	if (!per.ownerAuthSet)
		IMSG("TPM owner is not taken! Take it after verification to get higher security!");

	return ret;
}

static EFI_STATUS tpm2_fuse_optee_seed(void)
{
	EFI_STATUS ret;
	TPM2B_DIGEST optee_seed;
	UINT8 read_seed[HW_UNIQUE_KEY_LENGTH];

	ret = Tpm2GetRandom(HW_UNIQUE_KEY_LENGTH, &optee_seed);
	if (EFI_ERROR(ret)) {
		EMSG("Tpm2GetRandom failed");
		goto out;
	}

	ret = create_index_and_write_lock(config_table.nv_index, config_table.attribute,
					HW_UNIQUE_KEY_LENGTH, optee_seed.buffer);
	if (EFI_ERROR(ret)) {
		EMSG("Failed(%ld) to create and write optee seed", ret);
		goto out;
	}
	IMSG("Success create and write optee seed");

	// Read the data again to verify it
	ret = tpm2_read_nvindex(NV_INDEX_OPTEEOS_SEED, HW_UNIQUE_KEY_LENGTH, read_seed, 0);
	if (EFI_ERROR(ret)) {
		EMSG("Read optee seed back failed(%lx) just after write it", ret);
		goto out;
	}
	if (memcmp(optee_seed.buffer, read_seed, sizeof(read_seed))) {
		EMSG("Security error! Read optee seed back but verify failed!");
		ret = EFI_SECURITY_VIOLATION;
		goto out;
	}

out:
	// Always clear the memory
	// Maybe be optimized?
	memset(optee_seed.buffer, 0, HW_UNIQUE_KEY_LENGTH);
	memset(read_seed, 0, HW_UNIQUE_KEY_LENGTH);
	barrier();
	return ret;
}

static EFI_STATUS tpm2_check_optee_seed_index(void)
{
	EFI_STATUS ret;
	TPM2B_NV_PUBLIC NvPublic;
	TPM2B_NAME NvName;

	// tpm2_delete_index(NV_INDEX_OPTEEOS_SEED); //for debug only, delete the index and refuse again.

	ret = Tpm2NvReadPublic(NV_INDEX_OPTEEOS_SEED, &NvPublic, &NvName);
	if (EFI_ERROR(ret)) {
		if (ret != EFI_NOT_FOUND) {
			EMSG("Read optee seed NV index failed(%lx)", ret);
			return ret;
		}

		ret = tpm2_fuse_optee_seed();
		if (EFI_ERROR(ret))
			EMSG("Failed(%lx) to fuse optee seed", ret);

		return ret;
	}

	DMSG("optee seed already fused");

	return EFI_SUCCESS;
}

static EFI_STATUS tpm2_init_seed(void)
{
	EFI_STATUS ret = EFI_SUCCESS;

	g_tpm_base_vaddr = (uint64_t)phys_to_virt(_PCD_VALUE_PcdTpmBaseAddress, MEM_AREA_IO_SEC);

	ret = tpm2_check_cap_permanent();
	if (EFI_ERROR(ret)) {
		EMSG("Failed(%lx) to check tpm cap.", ret);
		return ret;
	}

	ret = tpm2_check_optee_seed_index();
	if (EFI_ERROR(ret)) {
		EMSG("Failed(%lx) to check optee seed status.", ret);
		return ret;
	}

	return ret;
}

static EFI_STATUS tpm2_read_lock_seed(OUT BYTE *Key, IN UINT16 KeySize)
{
	EFI_STATUS ret;
	UINT8 TempKey[HW_UNIQUE_KEY_LENGTH] = {0};

	if (KeySize < HW_UNIQUE_KEY_LENGTH || Key == NULL)
		return EFI_BUFFER_TOO_SMALL;

	ret = tpm2_read_nvindex(config_table.nv_index, HW_UNIQUE_KEY_LENGTH, TempKey, 0);
	if (EFI_ERROR(ret)) {
		EMSG("Failed to read nv index:%lx.\n", ret);
		goto out;
	}

	ret = tpm2_read_lock_nvindex(config_table.nv_index);
	if (EFI_ERROR(ret)) {
		EMSG("Failed to read lock nv index:%lx.\n", ret);
		goto out;
	}

	IMSG("Successfully to read and lock optee seed.\n");
out:
	if (ret == EFI_SUCCESS)
		memcpy(Key, TempKey, HW_UNIQUE_KEY_LENGTH);

	memset(TempKey, 0, sizeof(TempKey));

	return ret;
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	EFI_STATUS ret;

	if (!hwkey)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!g_huk_initialized)
	{
		ret = tpm2_init_seed();
		if (EFI_ERROR(ret)) {
			EMSG("Failed(%lx) to init optee seed.", ret);
			return TEE_ERROR_GENERIC;
		}

		ret = tpm2_read_lock_seed(g_huk, HW_UNIQUE_KEY_LENGTH);
		if (EFI_ERROR(ret)) {
			EMSG("Failed(%lx) to read and lock optee seed.", ret);
			return TEE_ERROR_GENERIC;
		}

		g_huk_initialized = true;
	}

	memcpy(&hwkey->data[0], g_huk, HW_UNIQUE_KEY_LENGTH);

	return TEE_SUCCESS;
}