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
#include <mbedtls/platform_util.h>
#include "tpm2_ops.h"
#include <drivers/tpm2_seed.h>

uint64_t g_tpm_base_vaddr = 0;

static bool g_huk_initialized = false;
static uint8_t g_huk[HW_UNIQUE_KEY_LENGTH] = {0};

#define DIGEST_SIZE 32

#define NV_INDEX_OPTEEOS_SEED  0x01500091
#define NV_INDEX_BOOTLOADER    0x01500092
typedef struct {
	TPMI_RH_NV_INDEX nv_index;
	TPMA_NV attribute;
} attribute_matrix_t;

static const attribute_matrix_t config_table[] =
{
	{NV_INDEX_OPTEEOS_SEED,
		{
		/* Authorization failures of the Index do not affect the DA logic
		* and authorization of the Index is not blocked when the TPM is in
		* Lockout mode.
		*/
		.TPMA_NV_NO_DA = 1,
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
		/* TPM2_NV_WriteLock may be used to prevent further writes
		* to this location regardless of TPM reset/restart.
		*/
		.TPMA_NV_WRITE_STCLEAR = 1,
		}
	},
	{NV_INDEX_BOOTLOADER,
		{
		.TPMA_NV_NO_DA = 1,
		.TPMA_NV_AUTHWRITE = 1,
		.TPMA_NV_AUTHREAD = 1,
		.TPMA_NV_WRITE_STCLEAR = 1,
		.TPMA_NV_READ_STCLEAR = 1,
		}
	}
};

#define NV_INDEX_BOOTLOADER_STRUCT_VER	1
/* Since can't create new NV index after lock owner, so alloc more space for future usage */
#define NV_INDEX_BOOTLOADER_SIZE	512

typedef struct {
	UINT8	struct_ver;  /* the version of this struct */
	UINT8	lock_state;
	UINT8	reserved[6];  /* keep 8 bytes align */
	uint64_t rollback_index[8];  /* AVB max rollback index slot is 32, now we support 8 for TPM */
} tpm2_bootloader_t;

enum device_state {
	UNKNOWN_STATE = -1,
	LOCKED = 0,
	UNLOCKED = 1
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

	ret = create_index_and_write_lock(config_table[0].nv_index, config_table[0].attribute,
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
	mbedtls_platform_zeroize(optee_seed.buffer, HW_UNIQUE_KEY_LENGTH);
	mbedtls_platform_zeroize(read_seed, HW_UNIQUE_KEY_LENGTH);
	return ret;
}

static EFI_STATUS tpm2_check_optee_seed_index(void)
{
	EFI_STATUS ret;
	TPM2B_NV_PUBLIC NvPublic;
	TPM2B_NAME NvName;

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

	ret = tpm2_read_nvindex(config_table[0].nv_index, HW_UNIQUE_KEY_LENGTH, TempKey, 0);
	if (EFI_ERROR(ret)) {
		EMSG("Failed to read nv index:%lx.\n", ret);
		goto out;
	}

	ret = tpm2_read_lock_nvindex(config_table[0].nv_index);
	if (EFI_ERROR(ret)) {
		EMSG("Failed to read lock nv index:%lx.\n", ret);
		goto out;
	}

	IMSG("Successfully to read and lock optee seed.\n");
out:
	if (ret == EFI_SUCCESS)
		memcpy(Key, TempKey, HW_UNIQUE_KEY_LENGTH);

	mbedtls_platform_zeroize(TempKey, sizeof(TempKey));

	return ret;
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	EFI_STATUS ret;

	g_tpm_base_vaddr = (uint64_t)phys_to_virt(_PCD_VALUE_PcdTpmBaseAddress, MEM_AREA_IO_SEC);

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
#ifdef CFG_TEE_CORE_DEBUG
	mbedtls_platform_zeroize(g_huk, HW_UNIQUE_KEY_LENGTH);
	DMSG("Warning: for debug build it will use a dummy key:");
	for (uint32_t i=0; i<HW_UNIQUE_KEY_LENGTH; i++)
		DMSG("huk[%d] = %x", i, g_huk[i]);
#endif
	memcpy(&hwkey->data[0], g_huk, HW_UNIQUE_KEY_LENGTH);

	return TEE_SUCCESS;
}

static EFI_STATUS tpm2_fuse_bootloader(void)
{
	EFI_STATUS ret;
	BYTE data[NV_INDEX_BOOTLOADER_SIZE] = {0};
	BYTE data_read[sizeof(data)];
	UINT16 data_read_size = sizeof(data);
	tpm2_bootloader_t *bootloader = (tpm2_bootloader_t *)data;

	ret = tpm2_create_nvindex(NV_INDEX_BOOTLOADER, config_table[1].attribute, sizeof(data));
	if (EFI_ERROR(ret)) {
		EMSG("Failed(%lx) to create bootloader NV index", ret);
		return ret;
	}

	bootloader->struct_ver = NV_INDEX_BOOTLOADER_STRUCT_VER;
	/* Set to unlock in a device just create the NV index. */
	bootloader->lock_state = UNLOCKED;

	ret = tpm2_write_nvindex(NV_INDEX_BOOTLOADER, sizeof(data), data, 0);
	if (EFI_ERROR(ret)) {
		EMSG("Write bootloader NV index failed(%lx)", ret);
		return ret;
	}

	/* Read the data again to verify it */
	ret = tpm2_read_nvindex(NV_INDEX_BOOTLOADER, data_read_size, data_read, 0);
	if (EFI_ERROR(ret)) {
		EMSG("Read bootloader NV index back failed(%lx) just after write it", ret);
		return ret;
	}

	if (memcmp(data, data_read, sizeof(data))) {
		EMSG("Security error! Read bootloader NV index back but verify failed!");
		return EFI_SECURITY_VIOLATION;
	}

	DMSG("Success create and write bootloader NV index");
	return EFI_SUCCESS;
}

static EFI_STATUS tpm2_check_bootloader_index(void)
{
	EFI_STATUS ret;
	TPM2B_NV_PUBLIC NvPublic;
	TPM2B_NAME NvName;
	UINT8 struct_ver;
	UINT16 data_size = sizeof(struct_ver);

	ret = Tpm2NvReadPublic(NV_INDEX_BOOTLOADER, &NvPublic, &NvName);
	if (EFI_ERROR(ret)) {
		if (ret != EFI_NOT_FOUND) {
			EMSG("Read bootloader NV index failed(%lx)", ret);
			return ret;
		}

		DMSG("tpm2_check_bootloader_index not found.");
		ret = tpm2_fuse_bootloader();
		if (EFI_ERROR(ret))
			EMSG("Failed(%lx) to fuse bootloader NV index", ret);

		return ret;
	}

	ret = tpm2_read_nvindex(NV_INDEX_BOOTLOADER, data_size,
			(BYTE *)&struct_ver,
			offsetof(tpm2_bootloader_t, struct_ver));
	if (EFI_ERROR(ret) || data_size != sizeof(struct_ver)) {
		EMSG("Read bootloader NV index for struct version failed(%lx), read size: %d", ret, data_size);
		return ret;
	}

	if (struct_ver > NV_INDEX_BOOTLOADER_STRUCT_VER)
		DMSG("Bootloader NV index is fused with new struct version %d, are you running old software?", struct_ver);
	else if (struct_ver < NV_INDEX_BOOTLOADER_STRUCT_VER)
		DMSG("Bootloader NV index is fused with old struct version %d, are you running in old device?", struct_ver);
	else {
		if (NvPublic.nvPublic.dataSize != NV_INDEX_BOOTLOADER_SIZE) {
			DMSG("Find bootloader NV index, but the NV index size is %d", NvPublic.nvPublic.dataSize);
			return EFI_COMPROMISED_DATA;
		}
		DMSG("Bootloader NV index already fused");
	}
	return EFI_SUCCESS;
}

EFI_STATUS tee_tpm2_init(void)
{
	EFI_STATUS ret;

	g_tpm_base_vaddr = (uint64_t)phys_to_virt(_PCD_VALUE_PcdTpmBaseAddress, MEM_AREA_IO_SEC);

	ret = tpm2_check_cap_permanent();
	if (EFI_ERROR(ret))
		return ret;

	ret = tpm2_check_bootloader_index();
	if (EFI_ERROR(ret))
		return ret;

	ret = tpm2_check_optee_seed_index();
	if (EFI_ERROR(ret)) {
		EMSG("Failed(%lx) to init optee seed.", ret);
		return TEE_ERROR_GENERIC;
	}

	return ret;
}

EFI_STATUS tee_tpm2_end(void)
{
	EFI_STATUS ret1 = tpm2_read_lock_nvindex(NV_INDEX_BOOTLOADER);
	EFI_STATUS ret2 = tpm2_write_lock_nvindex(NV_INDEX_BOOTLOADER);
	EFI_STATUS ret3 = Tpm2Shutdown(TPM_SU_CLEAR);

	if (EFI_ERROR(ret3))
		EMSG("Failed(%lx) to shutdown TPM.", ret3);

	if (ret1 == EFI_SUCCESS && ret2 == EFI_SUCCESS)
		return EFI_SUCCESS;

	EMSG("Read lock TPM result:(%lx).", ret1);
	EMSG("Write lock TPM result: (%lx).", ret2);

	return EFI_LOAD_ERROR;
}

EFI_STATUS tee_tpm2_read_device_state(UINT8 *state)
{
	EFI_STATUS ret;
	UINT16 data_size = sizeof(UINT8);

	ret = tpm2_read_nvindex(NV_INDEX_BOOTLOADER, data_size, (BYTE *)state,
			offsetof(tpm2_bootloader_t, lock_state));
	if (EFI_ERROR(ret)) {
		EMSG("Read device state from TPM failed(%lx)", ret);
		return ret;
	}

	if (data_size != sizeof(UINT8)) {
		EMSG("Read device state from TPM, but data size is wrong: %d", data_size);
		return EFI_COMPROMISED_DATA;
	}

	DMSG("Read device state from TPM success, state: %d", *state);
	return ret;
}

EFI_STATUS tee_tpm2_write_device_state(UINT8 state)
{
	EFI_STATUS ret;

	ret = tpm2_write_nvindex(NV_INDEX_BOOTLOADER, sizeof(UINT8), (BYTE *)&state,
			offsetof(tpm2_bootloader_t, lock_state));
	if (EFI_ERROR(ret)) {
		EMSG("Write device state %d to TPM failed(%lx)", state, ret);
		return ret;
	}

	DMSG("Write device state %d to TPM success", state);
	return ret;
}

EFI_STATUS tee_tpm2_read_rollback_index(size_t rollback_index_slot, uint64_t *out_rollback_index)
{
	EFI_STATUS ret;
	UINT16 data_size = sizeof(uint64_t);

	if (rollback_index_slot >= ARRAY_SIZE(((tpm2_bootloader_t *)0)->rollback_index)) {
		EMSG("The rollback index slot is too large to write into TPM: %ld", rollback_index_slot);
		return EFI_INVALID_PARAMETER;
	}

	ret = tpm2_read_nvindex(NV_INDEX_BOOTLOADER, data_size, (BYTE *)out_rollback_index,
			rollback_index_slot * sizeof(uint64_t) + offsetof(tpm2_bootloader_t, rollback_index));
	if (EFI_ERROR(ret)) {
		EMSG("Read rollback index from TPM failed(%lx), slot: %ld", ret, rollback_index_slot);
		return ret;
	}

	if (data_size != sizeof(uint64_t)) {
		EMSG("Read rollback index from TPM, but data size is wrong: %d", data_size);
		return EFI_COMPROMISED_DATA;
	}

	DMSG("Read rollback index from TPM success, slot: %ld, index: 0x%lx", rollback_index_slot, *out_rollback_index);
	return ret;

}

EFI_STATUS tee_tpm2_write_rollback_index(size_t rollback_index_slot, uint64_t rollback_index)
{
	EFI_STATUS ret;

	if (rollback_index_slot >= ARRAY_SIZE(((tpm2_bootloader_t *)0)->rollback_index)) {
		EMSG("The rollback index slot is too large to write into TPM: %ld", rollback_index_slot);
		return EFI_INVALID_PARAMETER;
	}

	ret = tpm2_write_nvindex(NV_INDEX_BOOTLOADER, sizeof(uint64_t), (BYTE *)&rollback_index,
			rollback_index_slot * sizeof(uint64_t) + offsetof(tpm2_bootloader_t, rollback_index));
	if (EFI_ERROR(ret)) {
		EMSG("Write rollback index to TPM failed(%lx), slot: %ld, index: 0x%lx",
				ret, rollback_index_slot, rollback_index);
		return ret;
	}

	DMSG("Write rollback index to TPM success, slot: %ld, index: 0x%lx", rollback_index_slot, rollback_index);
	return ret;
}

BOOLEAN tee_tpm2_bootloader_need_init(void)
{
	EFI_STATUS ret;
	TPM2B_NV_PUBLIC NvPublic;
	TPM2B_NAME NvName;

	ret = Tpm2NvReadPublic(NV_INDEX_BOOTLOADER, &NvPublic, &NvName);
	if (EFI_ERROR(ret)) {
		if (ret == EFI_NOT_FOUND) {
			return TRUE;
		}
		EMSG("Failed(%lx) to read NV_INDEX_BOOTLOADER", ret);
	}

	return FALSE;
}

// Triggered by: fastboot oem fuse lock-tpm2-owner
EFI_STATUS tee_tpm2_fuse_lock_owner(void)
{
	TPMS_AUTH_COMMAND session_data = {0};
	TPM2B_AUTH owner_auth;
	EFI_STATUS ret;
	TPMA_PERMANENT per;
	UINT8 state;

	ret = tpm2_get_cap_permanent(&per);
	if (EFI_ERROR(ret)) {
		EMSG("Check TPM cap permanent for lock owner failed(%lx).", ret);
		return ret;
	}

	if (per.ownerAuthSet) {
		EMSG("TPM owner is already locked");
		return EFI_SUCCESS;
	}

	/* Check can read the bootloader NV index */
	ret = tee_tpm2_read_device_state(&state);
	if (EFI_ERROR(ret)) {
		EMSG("Read device state failed, should not lock the owner!");
		return ret;
	}

	session_data.sessionHandle = TPM_RS_PW;
	session_data.nonce.size = 0;
	session_data.hmac.size = 0;
	*((UINT8 *)((void *)&session_data.sessionAttributes)) = 0;

	ret = Tpm2GetRandom(DIGEST_SIZE, &owner_auth);
	if (EFI_ERROR(ret)) {
		EMSG("failed(%lx) to get random", ret);
		goto out;
	}

	ret = Tpm2HierarchyChangeAuth(TPM_RH_OWNER, &session_data, &owner_auth);
	if (EFI_ERROR(ret)) {
		EMSG("failed(%lx) to Tpm2HierarchyChangeAuth", ret);
		goto out;
	}

	ret = tpm2_get_cap_permanent(&per);
	if (EFI_ERROR(ret)) {
		EMSG("Check TPM cap permanent after take owner failed(%lx)", ret);
		goto out;
	}

	if (!per.ownerAuthSet) {
		EMSG("Try to lock TPM owner, success call Tpm2HierarchyChangeAuth, but ownerAuthSet is not set!");
		ret = EFI_SECURITY_VIOLATION;
		goto out;
	}

	IMSG("Success lock TPM owner");

out:
	mbedtls_platform_zeroize(owner_auth.buffer, DIGEST_SIZE);

	return ret;
}
