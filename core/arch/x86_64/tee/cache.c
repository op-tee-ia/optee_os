// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2018, intel Corporation
 */

#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <tee/cache.h>
/*
 * tee_uta_cache_operation - dynamic cache clean/inval request from a TA.
 */
TEE_Result cache_operation(enum utee_cache_operation op, void *va, size_t len)
{
	paddr_t pa;

	pa = virt_to_phys(va);
	if (!pa)
		return TEE_ERROR_ACCESS_DENIED;

	switch (op) {
	case TEE_CACHEFLUSH:
		return cache_op_inner(DCACHE_AREA_CLEAN_INV, va, len);

	case TEE_CACHECLEAN:
		return cache_op_inner(DCACHE_AREA_CLEAN, va, len);

	case TEE_CACHEINVALIDATE:
		return cache_op_inner(DCACHE_AREA_INVALIDATE, va, len);

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
