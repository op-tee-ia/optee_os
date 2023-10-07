#include <efi.h>
#include <lib.h>
#include <byteswap.h>
#include "Tcg2Protocol.h"
#include "Tpm2CommandLib.h"
#include "Tpm2Help.h"

#include <string.h>
#include <trace.h>

#include "Base.h"
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <types_ext.h>

uint64_t g_tpm_base_vaddr = 0;

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

static EFI_STATUS tpm2_get_capability(
		IN      TPM_CAP                   Capability,
		IN      UINT32                    Property,
		IN      UINT32                    PropertyCount,
		OUT     TPMI_YES_NO               * MoreData,
		OUT     TPMS_CAPABILITY_DATA      * CapabilityData
		)
{
	EFI_STATUS ret;
	UINT32 i;
	TPML_TAGGED_TPM_PROPERTY *prop;

	ret = Tpm2GetCapability(Capability, Property, PropertyCount, MoreData, CapabilityData);
	if (EFI_ERROR(ret)) {
		EMSG("Call Tpm2GetCapability failed(%ld)", ret);
		return ret;
	}

	// // Process the handles (CapabilityData.data.handles)
    // EMSG("TPM handles:\n");
    // for (UINT32 i = 0; i < CapabilityData->data.handles.count; i++) {
    //     EMSG("Handle: 0x%08X\n", CapabilityData->data.handles.handle[i]);
    // }

	prop = &CapabilityData->data.tpmProperties;
	DMSG("TPM2 capability: 0x%08x, data.tpmProperties.count: %d, more data: %d",
			bswap_32(CapabilityData->capability), bswap_32(prop->count), *MoreData);
	for (i = 0; i < bswap_32(prop->count); i++)
		DMSG("prop %d: property: 0x%08x, value: 0x%08x", i,
				bswap_32(prop->tpmProperty[i].property),
				bswap_32(prop->tpmProperty[i].value));

	return ret;
}

static EFI_STATUS tpm2_get_cap_permanent(TPMA_PERMANENT *per)
{
	EFI_STATUS ret;
	TPMI_YES_NO more_data;
	TPMS_CAPABILITY_DATA cap_data;
	UINT32 value;
	TPML_TAGGED_TPM_PROPERTY *prop;

	ret = tpm2_get_capability(TPM_CAP_TPM_PROPERTIES, TPM_PT_PERMANENT, 1, &more_data, &cap_data);
	if (EFI_ERROR(ret)) {
		EMSG("Get TPM cap permanent failed(%ld)", ret);
		return ret;
	}
	prop = &cap_data.data.tpmProperties;
	if (bswap_32(prop->count) <= 0) {
		EMSG("Get empty TPM capability data of TPM_PT_PERMANENT");
		ret = EFI_NOT_FOUND;
		return ret;
	}

	value = bswap_32(prop->tpmProperty[0].value);
	*per = *(TPMA_PERMANENT *)&value;

	return ret;
}

static EFI_STATUS tpm2_check_cap_permanent(void)
{
	EFI_STATUS ret;
	TPMA_PERMANENT per;

	ret = tpm2_get_cap_permanent(&per);
	if (EFI_ERROR(ret)) {
		EMSG("Check TPM cap permanent for lockoutAuthSet failed(%ld)", ret);
		return ret;
	}

	/* Verify the LOCKOUT_AUTH */
	if (!per.lockoutAuthSet)
		EMSG(L"TPM LOCKOUT_AUTH is not set, set it can get higher security");

	if (!per.ownerAuthSet)
		IMSG("TPM owner is not taken! Take it after verification to get higher security!");

	return ret;
}

EFI_STATUS tpm2_create_nvindex(TPMI_RH_NV_INDEX nv_index,
                               TPMA_NV attributes,
                               UINT16 data_size)
{
	TPMI_RH_PROVISION auth_handle = TPM_RH_OWNER;
	TPM2B_NV_PUBLIC public_info = {0};
	TPM2B_AUTH nv_auth = {0};

	nv_auth.size = 0;
	public_info.size = sizeof(TPMI_RH_NV_INDEX)
					+ sizeof(TPMI_ALG_HASH) + sizeof(TPMA_NV)
					+ sizeof(UINT16) + sizeof(UINT16);

	public_info.nvPublic.nvIndex = nv_index;
	public_info.nvPublic.nameAlg = TPM_ALG_SHA256;
	public_info.nvPublic.attributes = attributes;
	public_info.nvPublic.authPolicy.size = (UINT16)0;
	public_info.nvPublic.dataSize = data_size;

	return Tpm2NvDefineSpace(auth_handle, NULL,
							&nv_auth, &public_info);
}

EFI_STATUS tpm2_delete_index(IN UINT32 index)
{
	EFI_STATUS ret = Tpm2NvUndefineSpace(TPM_RH_OWNER, index, NULL);

	if (EFI_ERROR(ret))
		EMSG("Delete TPM NV index failed %ld, index: 0x%x.\n", ret, index);

	return ret;
}

EFI_STATUS tpm2_read_nvindex(TPMI_RH_NV_INDEX nv_index,
                            UINT16 data_size,
							BYTE *data,
							UINT16 offset)
{
	EFI_STATUS ret;
	TPMS_AUTH_COMMAND session_data = {0};
	TPM2B_MAX_BUFFER nv_read_data = {0};
	INT8 retry_times = 5;

	session_data.sessionHandle  = TPM_RS_PW;
	session_data.nonce.size     = 0;
	*((UINT8 *) &(session_data.sessionAttributes)) = 0;
	session_data.hmac.size      = 0;

	nv_read_data.size = data_size;

	do {
		ret = Tpm2NvRead(nv_index, nv_index, &session_data, nv_read_data.size, offset, &nv_read_data);
		retry_times --;
	} while (ret == EFI_DEVICE_ERROR && retry_times > 0);

	if (EFI_ERROR(ret)) {
		EMSG("Read NVIndex failed: %ld.\n", ret);
		return ret;
	}
	memcpy(data, nv_read_data.buffer, nv_read_data.size);

	return EFI_SUCCESS;
}

EFI_STATUS tpm2_read_lock_nvindex(TPMI_RH_NV_INDEX nv_index)
{
	TPMS_AUTH_COMMAND session_data = {0};

	session_data.sessionHandle  = TPM_RS_PW;
	session_data.nonce.size     = 0;
	*((UINT8 *)&(session_data.sessionAttributes)) = 0;
	session_data.hmac.size      = 0;

	return Tpm2NvReadLock(nv_index, nv_index, &session_data);
}

EFI_STATUS tpm2_write_nvindex(TPMI_RH_NV_INDEX nv_index,
                              UINT16 data_size,
							  BYTE *data,
							  UINT16 offset)
{
	EFI_STATUS ret = EFI_SUCCESS;
	TPMS_AUTH_COMMAND session_data = {0};
	TPM2B_MAX_BUFFER nv_write_data = {0};
	INT8 retry_times = 5;

	session_data.sessionHandle = TPM_RS_PW;

	nv_write_data.size = data_size;
	memcpy(nv_write_data.buffer, data, nv_write_data.size);

	do {
		ret = Tpm2NvWrite(nv_index, nv_index,
				&session_data, &nv_write_data, offset);
	    retry_times --;
	} while (ret == EFI_DEVICE_ERROR && retry_times > 0);

	if (EFI_ERROR(ret)) {
		EMSG("Write TPM NV index failed, index: 0x%x, size: %d, ret: %ld.\n",
						nv_index, nv_write_data.size, ret);
	}

	return ret;
}

EFI_STATUS tpm2_write_lock_nvindex(TPMI_RH_NV_INDEX nv_index)
{
	TPMS_AUTH_COMMAND session_data = {0};

	session_data.sessionHandle = TPM_RS_PW;

	return Tpm2NvWriteLock(nv_index, nv_index, &session_data);
}

static EFI_STATUS create_index_and_write_lock(TPM_NV_INDEX nv_index, TPMA_NV attributes,
					      UINT16 data_size, BYTE *data)
{
	EFI_STATUS ret;

	ret = tpm2_create_nvindex(nv_index, attributes, data_size);
	if (EFI_ERROR(ret)) {
		EMSG("NV Index failed(%ld) to create, index: 0x%x, size: %d", ret, nv_index, data_size);
		goto out;
	}

	ret = tpm2_write_nvindex(nv_index, data_size, data, 0);
	if (EFI_ERROR(ret)) {
		EMSG("Write to NV Index failed(%ld), index: 0x%x, size: %d", ret, nv_index, data_size);
		goto out;
	}

	ret = tpm2_write_lock_nvindex(nv_index);
	if (EFI_ERROR(ret)) {
		EMSG("Write lock to NV Index failed(%ld), index: 0x%x", ret, nv_index);
		goto out;
	}

out:
	if (EFI_ERROR(ret)){
		if (EFI_SUCCESS != tpm2_delete_index(config_table.nv_index))
            EMSG("Failed to delete nv index.\n");
	}

	return ret;
}

EFI_STATUS tpm2_fuse_optee_seed(void)
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
		EMSG("Read optee seed back failed(%ld) just after write it", ret);
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
	UINT32 *attr;
	UINT32 *config_attr;

	// tpm2_delete_index(NV_INDEX_OPTEEOS_SEED);

	ret = Tpm2NvReadPublic(NV_INDEX_OPTEEOS_SEED, &NvPublic, &NvName);
	if (EFI_ERROR(ret)) {
		if (ret != EFI_NOT_FOUND) {
			EMSG("Read optee seed NV index failed(%ld)", ret);
			return ret;
		}

		ret = tpm2_fuse_optee_seed();
		if (EFI_ERROR(ret))
			EMSG("Failed(%ld) to fuse optee seed", ret);

		return ret;
	}

	DMSG("optee seed already fused");

	return EFI_SUCCESS;
}

EFI_STATUS tpm2_init_seed(void)
{
	EFI_STATUS ret;

	g_tpm_base_vaddr = (uint64_t)phys_to_virt(_PCD_VALUE_PcdTpmBaseAddress, MEM_AREA_IO_SEC);

	ret = tpm2_check_cap_permanent();
	if (EFI_ERROR(ret)) {
		EMSG("Failed(%ld) to check tpm cap.", ret);
		return ret;
	}

	ret = tpm2_check_optee_seed_index();
	if (EFI_ERROR(ret)) {
		EMSG("Failed(%ld) to check optee seed status.", ret);
		return ret;
	}

	return ret;
}

EFI_STATUS tpm2_read_lock_seed(OUT BYTE *Key, IN UINT16 KeySize)
{
    EFI_STATUS ret;
	UINT8 TempKey[HW_UNIQUE_KEY_LENGTH] = {0};

    if (KeySize < HW_UNIQUE_KEY_LENGTH || Key == NULL)
        return EFI_BUFFER_TOO_SMALL;

    ret = tpm2_read_nvindex(config_table.nv_index, HW_UNIQUE_KEY_LENGTH, TempKey, 0);
	if (EFI_ERROR(ret)) {
		EMSG("Failed to read nv index:%ld.\n", ret);
		goto out;
	}

    ret = tpm2_read_lock_nvindex(config_table.nv_index);
	if (EFI_ERROR(ret)) {
		EMSG("Failed to read lock nv index:%ld.\n", ret);
		goto out;
	}

	IMSG("Successfully to read and lock optee seed.\n");
out:
    if (ret == EFI_SUCCESS)
        memcpy(Key, TempKey, HW_UNIQUE_KEY_LENGTH);

    memset(TempKey, 0, sizeof(TempKey));

    return ret;
}
