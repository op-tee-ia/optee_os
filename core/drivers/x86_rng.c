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
#include <rng_support.h>
#include <stdlib.h>
#include <string.h>
#include <tee/tee_cryp_utl.h>
#include <trace.h>
#include <util.h>

#define DRNG_MAX_TRIES 10
#define DRNG_HAS_RDRAND 0X1
#define DRNG_HAS_RDSEED  0X2

static uint32_t g_drng_feature = 0;

static void __cpuid(uint32_t info[4], uint32_t leaf, uint32_t subleaf) {
    __asm__ __volatile__ (
        "cpuid"
        : "=a" (info[0]), "=b" (info[1]), "=c" (info[2]), "=d" (info[3])
        : "a" (leaf), "c" (subleaf)
        : "cc"
    );
}

static TEE_Result rdseed32(uint32_t *out)
{
	uint8_t ret;
	int i;

	for (i=0; i<DRNG_MAX_TRIES; i++) {
		__asm__ __volatile__ (
				"RDSEED %0;"
				"setc %1;"
				: "=r"(*out), "=qm"(ret)
				);
		if(ret)
			return TEE_SUCCESS;
	}
	return TEE_ERROR_GENERIC;
}

static TEE_Result rdrand32(uint32_t *out)
{
	uint8_t ret;
	int i;

	for (i=0; i<DRNG_MAX_TRIES; i++) {
		__asm__ __volatile__ (
				"RDRAND %0;"
				"setc %1;"
				: "=r"(*out), "=qm"(ret)
				);
		if(ret)
			return TEE_SUCCESS;
	}
	return TEE_ERROR_GENERIC;
}

static TEE_Result drng_rand32(uint32_t *out)
{
	int rc = TEE_ERROR_GENERIC;

	if (g_drng_feature & DRNG_HAS_RDSEED) {
		rc = rdseed32(out);
		if (TEE_SUCCESS == rc)
			return rc;
	}

	if (g_drng_feature & DRNG_HAS_RDRAND) {
		rc = rdrand32(out);
		if (TEE_SUCCESS != rc)
			EMSG("failed with rdrand32\n");
	}

	return rc;
}

static TEE_Result drng_rand_multiple4_buf(uint8_t *buf, size_t len)
{
	uint32_t i;

	if (len%4) {
		EMSG("the len isn't multiple of 4bytes\n");
		return TEE_ERROR_GENERIC;
	}

	for (i=0; i<len; i+=4) {
		uint32_t tmp_buf=0;
		if (TEE_SUCCESS != drng_rand32(&tmp_buf)) {
			EMSG("failed with rdseed32\n");
			return TEE_ERROR_GENERIC;
		}
		memcpy(buf+i, &tmp_buf, sizeof(tmp_buf));
	}

	return TEE_SUCCESS;
}

TEE_Result crypto_rng_read(void *buf, size_t len)
{
	uint32_t tmp_buf = 0;
	assert(buf);

	if (len <= 4) {
		if (TEE_SUCCESS != drng_rand32(&tmp_buf)) {
			EMSG("failed with drng_rand32\n");
			return TEE_ERROR_GENERIC;
		}
		memcpy(buf, &tmp_buf, len);
		tmp_buf = 0;
		return TEE_SUCCESS;
	}

	const size_t len_multiple4 = len & ~3;
	if (TEE_SUCCESS != drng_rand_multiple4_buf(buf, len_multiple4)) {
		/* If failed to get random data, clear filled data */
		EMSG("failed with drng_rand_multiple4_buf\n");
		memset(buf, 0, len_multiple4);
		return TEE_ERROR_GENERIC;
	}
	len -= len_multiple4;
	if (len != 0) {
		assert(len <  4);

		if (TEE_SUCCESS != drng_rand32(&tmp_buf)) {
			EMSG("failed with drng_rand32\n");
			return TEE_ERROR_GENERIC;
		}
		memcpy(buf + len_multiple4, &tmp_buf, len);
		tmp_buf = 0;
	}
	return TEE_SUCCESS;
}

void plat_rng_init(void)
{
}

void x86_drng_init(void)
{
	uint32_t info[4] = {0};

	__cpuid(info, 1, 0);
	/* CPUID: ECX.RDRAND[bit30] = 1? */
	if (info[2] & (1 << 30)) {
		IMSG("This platform support RDRAND.\n");
		g_drng_feature |= DRNG_HAS_RDRAND;
	}

	__cpuid(info, 7, 0);
	/* CPUID: EBX.RDREED[bit18] = 1? */
	if (info[1] & (1 << 18)) {
		IMSG("This platform support RDSEED.");
		g_drng_feature |= DRNG_HAS_RDSEED;
	}
		
}

driver_init(x86_drng_init);