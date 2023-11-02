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

#include "tpm2_ops.h"

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
		EMSG("Call Tpm2GetCapability failed(%lx)", ret);
		return ret;
	}

	prop = &CapabilityData->data.tpmProperties;
	DMSG("TPM2 capability: 0x%08x, data.tpmProperties.count: %d, more data: %d",
			bswap_32(CapabilityData->capability), bswap_32(prop->count), *MoreData);
	for (i = 0; i < bswap_32(prop->count); i++)
		DMSG("prop %d: property: 0x%08x, value: 0x%08x", i,
				bswap_32(prop->tpmProperty[i].property),
				bswap_32(prop->tpmProperty[i].value));

	return ret;
}

EFI_STATUS tpm2_get_cap_permanent(TPMA_PERMANENT *per)
{
	EFI_STATUS ret;
	TPMI_YES_NO more_data;
	TPMS_CAPABILITY_DATA cap_data;
	UINT32 value;
	TPML_TAGGED_TPM_PROPERTY *prop;

	ret = tpm2_get_capability(TPM_CAP_TPM_PROPERTIES, TPM_PT_PERMANENT, 1, &more_data, &cap_data);
	if (EFI_ERROR(ret)) {
		EMSG("Get TPM cap permanent failed(%lx)", ret);
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
		EMSG("Read NVIndex failed: %lx.\n", ret);
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
		ret = Tpm2NvWrite(nv_index, nv_index, &session_data, &nv_write_data, offset);
		retry_times --;
	} while (ret == EFI_DEVICE_ERROR && retry_times > 0);

	if (EFI_ERROR(ret)) {
		EMSG("Write TPM NV index failed, index: 0x%x, size: %d, ret: %lx.\n",
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

EFI_STATUS create_index_and_write_lock(TPM_NV_INDEX nv_index, TPMA_NV attributes,
							UINT16 data_size, BYTE *data)
{
	EFI_STATUS ret;

	ret = tpm2_create_nvindex(nv_index, attributes, data_size);
	if (EFI_ERROR(ret)) {
		EMSG("NV Index failed(%lx) to create, index: 0x%x, size: %d", ret, nv_index, data_size);
		goto out;
	}

	ret = tpm2_write_nvindex(nv_index, data_size, data, 0);
	if (EFI_ERROR(ret)) {
		EMSG("Write to NV Index failed(%lx), index: 0x%x, size: %d", ret, nv_index, data_size);
		goto out;
	}

	ret = tpm2_write_lock_nvindex(nv_index);
	if (EFI_ERROR(ret)) {
		EMSG("Write lock to NV Index failed(%lx), index: 0x%x", ret, nv_index);
		goto out;
	}

out:
	if (EFI_ERROR(ret)){
		if (EFI_SUCCESS != tpm2_delete_index(nv_index))
			EMSG("Failed to delete nv index.\n");
	}

	return ret;
}