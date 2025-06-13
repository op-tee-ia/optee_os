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
#include <kernel/virtualization.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/constant_time.h>
#include <mbedtls/sha256.h>
#include "tpm2_ops.h"
#include <drivers/tpm2_seed.h>

uint64_t g_tpm_base_vaddr __nex_bss;

static bool g_huk_initialized = false;
bool g_tpm_nv_bootloader_lock = false;
static uint8_t g_huk[HW_UNIQUE_KEY_LENGTH] = {0};

#define DIGEST_SIZE 32

#define NV_ID_OPTEEOS_SEED  0x0U
#define NV_ID_BOOTLOADER    0x1U
#define NV_ID_UDS           0x2U

#define NV_INDEX_BASE          0x01500091
#define NV_INDEX_OPTEEOS_SEED  (NV_INDEX_BASE + NV_ID_OPTEEOS_SEED)
#define NV_INDEX_BOOTLOADER    (NV_INDEX_BASE + NV_ID_BOOTLOADER)
#define NV_INDEX_UDS           (NV_INDEX_BASE + NV_ID_UDS)

#define NV_INDEX_TYPE_NUM        3

#define CALCULATE_NV_INDEX(dev, type)	(NV_INDEX_BASE + (dev) * NV_INDEX_TYPE_NUM + (type))

#define NV_INDEX_BOOTLOADER_STRUCT_VER  1
/* Since can't create new NV index after lock owner, so allocate more space for future usage */
#define NV_INDEX_BOOTLOADER_SIZE        512

typedef struct {
	TPMI_RH_NV_INDEX nv_index;
	UINT16 nv_size;
	TPMA_NV attribute;
} attribute_matrix_t;

static const attribute_matrix_t config_table[TEE_MAX_IVSHMEM_DEVICE][NV_INDEX_TYPE_NUM] __nex_data =
{
	{{CALCULATE_NV_INDEX(0, NV_ID_OPTEEOS_SEED),
	 HW_UNIQUE_KEY_LENGTH,
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
		.TPMA_NV_AUTHREAD = 1,
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
	{CALCULATE_NV_INDEX(0, NV_ID_BOOTLOADER),
	 NV_INDEX_BOOTLOADER_SIZE,
		{
		.TPMA_NV_NO_DA = 1,
		.TPMA_NV_AUTHWRITE = 1,
		.TPMA_NV_AUTHREAD = 1,
		.TPMA_NV_WRITE_STCLEAR = 1,
		.TPMA_NV_READ_STCLEAR = 1,
		}
	},
	{CALCULATE_NV_INDEX(0, NV_ID_UDS),
	 UDS_LENGTH,
		{
		.TPMA_NV_NO_DA = 1,
		.TPMA_NV_AUTHWRITE = 1,
		.TPMA_NV_AUTHREAD = 1,
		.TPMA_NV_WRITEALL = 1,
		.TPMA_NV_WRITEDEFINE = 1,
		.TPMA_NV_WRITE_STCLEAR = 1,
		.TPMA_NV_READ_STCLEAR = 1,
		}
	}},

	{{CALCULATE_NV_INDEX(1, NV_ID_OPTEEOS_SEED),
	 HW_UNIQUE_KEY_LENGTH,
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
		.TPMA_NV_AUTHREAD = 1,
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
	{CALCULATE_NV_INDEX(1, NV_ID_BOOTLOADER),
	 NV_INDEX_BOOTLOADER_SIZE,
		{
		.TPMA_NV_NO_DA = 1,
		.TPMA_NV_AUTHWRITE = 1,
		.TPMA_NV_AUTHREAD = 1,
		.TPMA_NV_WRITE_STCLEAR = 1,
		.TPMA_NV_READ_STCLEAR = 1,
		}
	},
	{CALCULATE_NV_INDEX(1, NV_ID_UDS),
	 UDS_LENGTH,
		{
		.TPMA_NV_NO_DA = 1,
		.TPMA_NV_AUTHWRITE = 1,
		.TPMA_NV_AUTHREAD = 1,
		.TPMA_NV_WRITEALL = 1,
		.TPMA_NV_WRITEDEFINE = 1,
		.TPMA_NV_WRITE_STCLEAR = 1,
		.TPMA_NV_READ_STCLEAR = 1,
		}
	}},

	{{CALCULATE_NV_INDEX(2, NV_ID_OPTEEOS_SEED),
	 HW_UNIQUE_KEY_LENGTH,
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
		.TPMA_NV_AUTHREAD = 1,
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
	{CALCULATE_NV_INDEX(2, NV_ID_BOOTLOADER),
	 NV_INDEX_BOOTLOADER_SIZE,
		{
		.TPMA_NV_NO_DA = 1,
		.TPMA_NV_AUTHWRITE = 1,
		.TPMA_NV_AUTHREAD = 1,
		.TPMA_NV_WRITE_STCLEAR = 1,
		.TPMA_NV_READ_STCLEAR = 1,
		}
	},
	{CALCULATE_NV_INDEX(2, NV_ID_UDS),
	 UDS_LENGTH,
		{
		.TPMA_NV_NO_DA = 1,
		.TPMA_NV_AUTHWRITE = 1,
		.TPMA_NV_AUTHREAD = 1,
		.TPMA_NV_WRITEALL = 1,
		.TPMA_NV_WRITEDEFINE = 1,
		.TPMA_NV_WRITE_STCLEAR = 1,
		.TPMA_NV_READ_STCLEAR = 1,
		}
	}},

	{{CALCULATE_NV_INDEX(3, NV_ID_OPTEEOS_SEED),
	 HW_UNIQUE_KEY_LENGTH,
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
		.TPMA_NV_AUTHREAD = 1,
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
	{CALCULATE_NV_INDEX(3, NV_ID_BOOTLOADER),
	 NV_INDEX_BOOTLOADER_SIZE,
		{
		.TPMA_NV_NO_DA = 1,
		.TPMA_NV_AUTHWRITE = 1,
		.TPMA_NV_AUTHREAD = 1,
		.TPMA_NV_WRITE_STCLEAR = 1,
		.TPMA_NV_READ_STCLEAR = 1,
		}
	},
	{CALCULATE_NV_INDEX(3, NV_ID_UDS),
	 UDS_LENGTH,
		{
		.TPMA_NV_NO_DA = 1,
		.TPMA_NV_AUTHWRITE = 1,
		.TPMA_NV_AUTHREAD = 1,
		.TPMA_NV_WRITEALL = 1,
		.TPMA_NV_WRITEDEFINE = 1,
		.TPMA_NV_WRITE_STCLEAR = 1,
		.TPMA_NV_READ_STCLEAR = 1,
		}
	}}
};


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

static EFI_STATUS tpm2_fuse_optee_secret(UINT16 id, UINT16 type)
{
	EFI_STATUS ret;
	TPM2B_DIGEST optee_secret;

	if (type != NV_ID_OPTEEOS_SEED && type != NV_ID_UDS) {
		EMSG("Unexpected secret type: %d/%d.", id, type);
		return EFI_INVALID_PARAMETER;
	}

	ret = Tpm2GetRandom(config_table[id][type].nv_size, &optee_secret);
	if (EFI_ERROR(ret)) {
		EMSG("Tpm2GetRandom %d/%d failed(%ld).", id, type, ret);
		goto out;
	}

	ret = create_index_and_write_lock(config_table[id][type].nv_index,
					config_table[id][type].attribute,
					config_table[id][type].nv_size, optee_secret.buffer);
	if (EFI_ERROR(ret)) {
		EMSG("Failed(%ld) to create and write optee secret(%d/%d)", ret, id, type);
		goto out;
	}
	IMSG("Success create and write optee secret %d/%d", id, type);

out:
	mbedtls_platform_zeroize(optee_secret.buffer, config_table[id][type].nv_size);
	return ret;
}

static EFI_STATUS tpm2_check_optee_secret_index(UINT16 id, UINT16 type)
{
	EFI_STATUS ret;
	TPM2B_NV_PUBLIC NvPublic;
	TPM2B_NAME NvName;

	if (type != NV_ID_OPTEEOS_SEED && type != NV_ID_UDS) {
		EMSG("Unexpected secret type: 0x%X.", type);
		return EFI_INVALID_PARAMETER;
	}

	ret = Tpm2NvReadPublic(config_table[id][type].nv_index, &NvPublic, &NvName);
	if (EFI_ERROR(ret)) {
		if (ret != EFI_NOT_FOUND) {
			EMSG("Read optee secret NV index %d/%d failed(%lx)", id, type, ret);
			return ret;
		}

		ret = tpm2_fuse_optee_secret(id, type);
		if (EFI_ERROR(ret))
			EMSG("Failed(%lx) to fuse optee secret(%d/%d)", ret, id, type);

		return ret;
	}

	DMSG("optee secret(%d/%d) already fused", id, type);

	return EFI_SUCCESS;
}

static EFI_STATUS tpm2_init_secret(UINT16 id, UINT16 type)
{
	if (type != NV_ID_OPTEEOS_SEED && type != NV_ID_UDS) {
		EMSG("Unexpected secret type: 0x%X.", type);
		return EFI_INVALID_PARAMETER;
	}

	g_tpm_base_vaddr = (uint64_t)phys_to_virt(_PCD_VALUE_PcdTpmBaseAddress, MEM_AREA_IO_SEC);

	EFI_STATUS ret = tpm2_check_cap_permanent();
	if (EFI_ERROR(ret)) {
		EMSG("Failed(%lx) to check tpm cap.", ret);
		return ret;
	}

	ret = tpm2_check_optee_secret_index(id, type);
	if (EFI_ERROR(ret)) {
		EMSG("Failed(%lx) to check optee %d/%d status.", ret, id, type);
		return ret;
	}

	return ret;
}

static EFI_STATUS tpm2_read_lock_secret(IN UINT16 id, IN UINT16 type,
	OUT BYTE *Key, IN UINT16 KeySize)
{
	if (type != NV_ID_OPTEEOS_SEED && type != NV_ID_UDS) {
		EMSG("Unexpected secret type: 0x%X.", type);
		return EFI_INVALID_PARAMETER;
	}

	EFI_STATUS ret;
	const UINT16 secret_size = config_table[id][type].nv_size;
	UINT8* TempKey = NULL;

	if (KeySize < secret_size || Key == NULL)
		return EFI_BUFFER_TOO_SMALL;

	TempKey = malloc(secret_size);
	if (!TempKey)
		return EFI_OUT_OF_RESOURCES;

	ret = tpm2_read_nvindex(config_table[id][type].nv_index, secret_size, TempKey, 0);
	if (EFI_ERROR(ret)) {
		EMSG("Failed to read nv index %d/%d:%lx.\n", id, type, ret);
		goto out;
	}

	ret = tpm2_read_lock_nvindex(config_table[id][type].nv_index);
	if (EFI_ERROR(ret)) {
		EMSG("Failed to read lock nv index %d/%d:%lx.\n", id, type, ret);
		goto out;
	}

	IMSG("Successfully to read and lock optee secret %d/%d.\n", id, type);
out:
	if (ret == EFI_SUCCESS)
		memcpy(Key, TempKey, secret_size);

	mbedtls_platform_zeroize(TempKey, secret_size);
	free(TempKey);

	return ret;
}

TEE_Result tee_sha256_pcrs(uint8_t *digest, size_t len)
{
	EFI_STATUS          Status;
	TPML_PCR_SELECTION  PcrSelectionIn;
	UINT32              PcrUpdateCounter;
	TPML_PCR_SELECTION  PcrSelectionOut;
	TPML_DIGEST         PcrValues;

	if (!digest || len < TEE_SHA256_HASH_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	ZeroMem(&PcrSelectionIn, sizeof(PcrSelectionIn));
	PcrSelectionIn.count = 1;

	PcrSelectionIn.pcrSelections[0].hash = TPM_ALG_SHA256;
	PcrSelectionIn.pcrSelections[0].sizeofSelect = 3;

	PcrSelectionIn.pcrSelections[0].pcrSelect[0] = 0xFF; //PCR 0-7 selected
	PcrSelectionIn.pcrSelections[0].pcrSelect[1] = 0x00; //PCR 8-15 not selected
	PcrSelectionIn.pcrSelections[0].pcrSelect[2] = 0x00; //PCR 16-23 not selected

	Status = Tpm2PcrRead(&PcrSelectionIn, &PcrUpdateCounter, &PcrSelectionOut, &PcrValues);
	if (EFI_ERROR(Status)) {
		EMSG("Tpm2PcrRead failed: %d\n", Status);
		return TEE_ERROR_GENERIC;
	}

	UINT8 PCRs[8*32]; // PCR 0~7 * 32B SHA256
	for (UINT32 i = 0; i < PcrValues.count; i++) {
		memcpy(PCRs + i * PcrValues.digests[i].size,
			PcrValues.digests[i].buffer,
			PcrValues.digests[i].size);
	}

	mbedtls_sha256_context ctx;
	int mbedtls_ret = 1;

	mbedtls_sha256_init(&ctx);
	if (0 != mbedtls_sha256_starts(&ctx, 0))
		goto err;
	if (0 != mbedtls_sha256_update(&ctx, PCRs, sizeof(PCRs)))
		goto err;
	if (0 != mbedtls_sha256_finish(&ctx, digest))
		goto err;
	mbedtls_ret = 0;

err:
	mbedtls_sha256_free(&ctx);
	if (mbedtls_ret) {
		EMSG("PCRs mbedtls_sha256 failed.");
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	EFI_STATUS ret;
#ifdef CFG_VIRTUALIZATION
	UINT16 id = get_partition_guest_id() - 1;
#else
	UINT16 id = 0;
#endif

	assert(id < TEE_MAX_IVSHMEM_DEVICE);

	g_tpm_base_vaddr = (uint64_t)phys_to_virt(_PCD_VALUE_PcdTpmBaseAddress, MEM_AREA_IO_SEC);

	if (!hwkey)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!g_huk_initialized)
	{
		ret = tpm2_init_secret(id, NV_ID_OPTEEOS_SEED);
		if (EFI_ERROR(ret)) {
			EMSG("Failed(%lx) to init optee seed %d.", ret, id);
			return TEE_ERROR_GENERIC;
		}

		ret = tpm2_read_lock_secret(id, NV_ID_OPTEEOS_SEED, g_huk, HW_UNIQUE_KEY_LENGTH);
		if (EFI_ERROR(ret)) {
			EMSG("Failed(%lx) to read and lock optee seed %d.", ret, id);
			return TEE_ERROR_GENERIC;
		}

		g_huk_initialized = true;
	}
#ifdef CFG_TEE_CORE_DEBUG
	uint8_t digest[32] = {0};
	mbedtls_sha256_context ctx;

	mbedtls_sha256_init(&ctx);
	mbedtls_sha256_starts(&ctx, 0);
	mbedtls_sha256_update(&ctx, g_huk, sizeof(g_huk));
	mbedtls_sha256_finish(&ctx, digest);
	mbedtls_sha256_free(&ctx);

	for (uint32_t i = 0; i < sizeof(digest); i++)
		DMSG("huk digest[%d] = %x", i, digest[i]);

	DMSG("Warning: for debug build it will use a all-zero dummy key.");
	mbedtls_platform_zeroize(g_huk, HW_UNIQUE_KEY_LENGTH);
#endif
	memcpy(&hwkey->data[0], g_huk, HW_UNIQUE_KEY_LENGTH);

	return TEE_SUCCESS;
}

TEE_Result tee_otp_get_hw_uds(uint8_t *hwuds, size_t len)
{
	EFI_STATUS ret;
#ifdef CFG_VIRTUALIZATION
	UINT16 id = get_partition_guest_id() - 1;
#else
	UINT16 id = 0;
#endif

	assert(id < TEE_MAX_IVSHMEM_DEVICE);

	if (!hwuds || len < UDS_LENGTH)
		return TEE_ERROR_BAD_PARAMETERS;

	g_tpm_base_vaddr = (uint64_t)phys_to_virt(_PCD_VALUE_PcdTpmBaseAddress, MEM_AREA_IO_SEC);

	ret = tpm2_init_secret(id, NV_ID_UDS);
	if (EFI_ERROR(ret)) {
		EMSG("Failed(%lx) to init optee uds %d.", ret, id);
		return TEE_ERROR_GENERIC;
	}

	ret = tpm2_read_lock_secret(id, NV_ID_UDS, hwuds, UDS_LENGTH);
	if (EFI_ERROR(ret)) {
		EMSG("Failed(%lx) to read and lock optee uds %d.", ret, id);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

static EFI_STATUS tpm2_fuse_bootloader(UINT16 id)
{
	EFI_STATUS ret;
	BYTE data[NV_INDEX_BOOTLOADER_SIZE] = {0};
	BYTE data_read[sizeof(data)];
	UINT16 data_read_size = sizeof(data);
	tpm2_bootloader_t *bootloader = (tpm2_bootloader_t *)data;

	ret = tpm2_create_nvindex(config_table[id][NV_ID_BOOTLOADER].nv_index,
		config_table[id][NV_ID_BOOTLOADER].attribute, sizeof(data));
	if (EFI_ERROR(ret)) {
		EMSG("Failed(%lx) to create bootloader NV index %d", ret, id);
		return ret;
	}

	bootloader->struct_ver = NV_INDEX_BOOTLOADER_STRUCT_VER;
	/* Set to unlock in a device just create the NV index. */
	bootloader->lock_state = UNLOCKED;

	ret = tpm2_write_nvindex(config_table[id][NV_ID_BOOTLOADER].nv_index,
		sizeof(data), data, 0);
	if (EFI_ERROR(ret)) {
		EMSG("Write bootloader NV index %d failed(%lx)", id, ret);
		return ret;
	}

	/* Read the data again to verify it */
	ret = tpm2_read_nvindex(config_table[id][NV_ID_BOOTLOADER].nv_index,
		data_read_size, data_read, 0);
	if (EFI_ERROR(ret)) {
		EMSG("Read bootloader NV index %d back failed(%lx) just after write it", id, ret);
		return ret;
	}

	if (mbedtls_ct_memcmp(data, data_read, sizeof(data))) {
		EMSG("Security error! Read bootloader NV index %d back but verify failed!", id);
		return EFI_SECURITY_VIOLATION;
	}

	DMSG("Success create and write bootloader NV index %d", id);
	return EFI_SUCCESS;
}

static EFI_STATUS tpm2_check_bootloader_index(UINT16 id)
{
	EFI_STATUS ret;
	TPM2B_NV_PUBLIC NvPublic;
	TPM2B_NAME NvName;
	UINT8 struct_ver;
	UINT16 data_size = sizeof(struct_ver);

	ret = Tpm2NvReadPublic(config_table[id][NV_ID_BOOTLOADER].nv_index,
		&NvPublic, &NvName);
	if (EFI_ERROR(ret)) {
		if (ret != EFI_NOT_FOUND) {
			EMSG("Read bootloader NV index %d failed(%lx)", id, ret);
			return ret;
		}

		DMSG("tpm2_check_bootloader_index %d not found.", id);
		ret = tpm2_fuse_bootloader(id);
		if (EFI_ERROR(ret))
			EMSG("Failed(%lx) to fuse bootloader NV index %d", ret, id);

		return ret;
	}

	ret = tpm2_read_nvindex(config_table[id][NV_ID_BOOTLOADER].nv_index, data_size,
			(BYTE *)&struct_ver,
			offsetof(tpm2_bootloader_t, struct_ver));
	if (EFI_ERROR(ret) || data_size != sizeof(struct_ver)) {
		EMSG("Read bootloader NV index %d for struct version failed(%lx), read size: %d",
			id, ret, data_size);
		return ret;
	}

	if (struct_ver > NV_INDEX_BOOTLOADER_STRUCT_VER)
		DMSG("Bootloader NV index %d is fused with new struct version %d, are you running old software?", id, struct_ver);
	else if (struct_ver < NV_INDEX_BOOTLOADER_STRUCT_VER)
		DMSG("Bootloader NV index %d is fused with old struct version %d, are you running in old device?", id, struct_ver);
	else {
		if (NvPublic.nvPublic.dataSize != NV_INDEX_BOOTLOADER_SIZE) {
			DMSG("Find bootloader NV index %d, but the NV index size is %d",
				id, NvPublic.nvPublic.dataSize);
			return EFI_COMPROMISED_DATA;
		}
		DMSG("Bootloader NV index %d already fused", id);
	}
	return EFI_SUCCESS;
}

EFI_STATUS tee_tpm2_init(void)
{
	EFI_STATUS ret;
#ifdef CFG_VIRTUALIZATION
	UINT16 id = get_partition_guest_id() - 1;
#else
	UINT16 id = 0;
#endif

	assert(id < TEE_MAX_IVSHMEM_DEVICE);

	g_tpm_base_vaddr = (uint64_t)phys_to_virt(_PCD_VALUE_PcdTpmBaseAddress, MEM_AREA_IO_SEC);

	ret = tpm2_check_cap_permanent();
	if (EFI_ERROR(ret))
		return ret;

	ret = tpm2_check_bootloader_index(id);
	if (EFI_ERROR(ret))
		return ret;

	ret = tpm2_check_optee_secret_index(id, NV_ID_OPTEEOS_SEED);
	if (EFI_ERROR(ret)) {
		EMSG("Failed(%lx) to init optee seed.", ret);
		return TEE_ERROR_GENERIC;
	}

	return ret;
}

EFI_STATUS tee_tpm2_end(void)
{
	/* NV_INDEX_BOOTLOADER is not rd/wr locked upon TPM
	 * due to TPM access failure after Android VM reboots.
	 * Tha cause is TPM is not in a new power cycle.
	 * Current solution is:
	 * TEE stop serving any TPM requests from Android after
	 * this tee_tpm2_end(). If Android gets rebooting,
	 * TEE requests a trusted source to notify the event
	 * and then enable TPM serving.
	 */
	g_tpm_nv_bootloader_lock = true;
	IMSG("g_tpm_nv_bootloader_lock is changed to LOCKED...");

	/* Since TPM is passthroughed to TEE, SOS and Android
	 * cannot send TPM2Shutdown(STATE) when S3. It causes
	 * to an SBL failure when resume back:
	 *     -- Attempting TPM_Startup with TPM_SU_STATE.
	 *     -- Tpm2Startup: Response Code error! 0x000001C4
	 * If SBL does not provide a workaround, TEE makes such
	 * workaround by sending Tpm2Shutdown(TPM_SU_STATE).
	 * For most cases, TPM only covers two states:
	 * TPM_Restart and TPM_Resume.
	 */
	EFI_STATUS ret = Tpm2Shutdown(TPM_SU_STATE);
	if (EFI_ERROR(ret))
		EMSG("Failed(%lx) to shutdown TPM STATE.", ret);

	return ret;
}

EFI_STATUS tee_tpm2_read_device_state(UINT8 *state)
{
	EFI_STATUS ret;
	UINT16 data_size = sizeof(UINT8);
#ifdef CFG_VIRTUALIZATION
	UINT16 id = get_partition_guest_id() - 1;
#else
	UINT16 id = 0;
#endif

	assert(id < TEE_MAX_IVSHMEM_DEVICE);

	ret = tpm2_read_nvindex(config_table[id][NV_ID_BOOTLOADER].nv_index,
			data_size, (BYTE *)state,
			offsetof(tpm2_bootloader_t, lock_state));
	if (EFI_ERROR(ret)) {
		EMSG("Read device state %d from TPM failed(%lx)", id, ret);
		return ret;
	}

	if (data_size != sizeof(UINT8)) {
		EMSG("Read device state %d from TPM, but data size is wrong: %d", id, data_size);
		return EFI_COMPROMISED_DATA;
	}

	DMSG("Read device state %d from TPM success, state: %d", id, *state);
	return ret;
}

EFI_STATUS tee_tpm2_write_device_state(UINT8 state)
{
	EFI_STATUS ret;
#ifdef CFG_VIRTUALIZATION
	UINT16 id = get_partition_guest_id() - 1;
#else
	UINT16 id = 0;
#endif

	assert(id < TEE_MAX_IVSHMEM_DEVICE);

	ret = tpm2_write_nvindex(config_table[id][NV_ID_BOOTLOADER].nv_index,
			sizeof(UINT8), (BYTE *)&state,
			offsetof(tpm2_bootloader_t, lock_state));
	if (EFI_ERROR(ret)) {
		EMSG("Write device state %d to TPM %d failed(%lx)", state, id, ret);
		return ret;
	}

	DMSG("Write device state %d to TPM %d success", state, id);
	return ret;
}

EFI_STATUS tee_tpm2_read_rollback_index(size_t rollback_index_slot, uint64_t *out_rollback_index)
{
	EFI_STATUS ret;
	UINT16 data_size = sizeof(uint64_t);
#ifdef CFG_VIRTUALIZATION
	UINT16 id = get_partition_guest_id() - 1;
#else
	UINT16 id = 0;
#endif

	assert(id < TEE_MAX_IVSHMEM_DEVICE);

	if (rollback_index_slot >= ARRAY_SIZE(((tpm2_bootloader_t *)0)->rollback_index)) {
		EMSG("The rollback index slot is too large to write into TPM: %ld", rollback_index_slot);
		return EFI_INVALID_PARAMETER;
	}

	ret = tpm2_read_nvindex(config_table[id][NV_ID_BOOTLOADER].nv_index,
			data_size, (BYTE *)out_rollback_index,
			rollback_index_slot * sizeof(uint64_t) + offsetof(tpm2_bootloader_t, rollback_index));
	if (EFI_ERROR(ret)) {
		EMSG("Read rollback index %d from TPM failed(%lx), slot: %ld",
			id, ret, rollback_index_slot);
		return ret;
	}

	if (data_size != sizeof(uint64_t)) {
		EMSG("Read rollback index %d from TPM, but data size is wrong: %d",
			id, data_size);
		return EFI_COMPROMISED_DATA;
	}

	DMSG("Read rollback index %d from TPM success, slot: %ld, index: 0x%lx",
		id, rollback_index_slot, *out_rollback_index);
	return ret;

}

EFI_STATUS tee_tpm2_write_rollback_index(size_t rollback_index_slot, uint64_t rollback_index)
{
	EFI_STATUS ret;
#ifdef CFG_VIRTUALIZATION
	UINT16 id = get_partition_guest_id() - 1;
#else
	UINT16 id = 0;
#endif

	assert(id < TEE_MAX_IVSHMEM_DEVICE);

	if (rollback_index_slot >= ARRAY_SIZE(((tpm2_bootloader_t *)0)->rollback_index)) {
		EMSG("The rollback index slot is too large to write into TPM: %ld", rollback_index_slot);
		return EFI_INVALID_PARAMETER;
	}

	ret = tpm2_write_nvindex(config_table[id][NV_ID_BOOTLOADER].nv_index,
			sizeof(uint64_t), (BYTE *)&rollback_index,
			rollback_index_slot * sizeof(uint64_t) + offsetof(tpm2_bootloader_t, rollback_index));
	if (EFI_ERROR(ret)) {
		EMSG("Write rollback index %d to TPM failed(%lx), slot: %ld, index: 0x%lx",
				id, ret, rollback_index_slot, rollback_index);
		return ret;
	}

	DMSG("Write rollback index %d to TPM success, slot: %ld, index: 0x%lx",
		id, rollback_index_slot, rollback_index);
	return ret;
}

BOOLEAN tee_tpm2_bootloader_need_init(void)
{
	EFI_STATUS ret;
	TPM2B_NV_PUBLIC NvPublic;
	TPM2B_NAME NvName;
#ifdef CFG_VIRTUALIZATION
	UINT16 id = get_partition_guest_id() - 1;
#else
	UINT16 id = 0;
#endif

	assert(id < TEE_MAX_IVSHMEM_DEVICE);

	ret = Tpm2NvReadPublic(config_table[id][NV_ID_BOOTLOADER].nv_index, &NvPublic, &NvName);
	if (EFI_ERROR(ret)) {
		if (ret == EFI_NOT_FOUND) {
			return TRUE;
		}
		EMSG("Failed(%lx) to read NV_INDEX_BOOTLOADER %d", ret, id);
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
