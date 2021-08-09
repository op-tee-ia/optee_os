/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2017, Linaro Limited
 */

#ifndef TLB_HELPERS_H
#define TLB_HELPERS_H

#ifndef __ASSEMBLER__
#include <types_ext.h>
#include <x86.h>

static inline void tlbi_all(void)
{
	x86_set_cr3(x86_get_cr3());
}

static inline void tlbi_mva_allasid(unsigned long addr __unused)
{
	tlbi_all();
}

static inline void tlbi_mva_allasid_nosync(vaddr_t va __unused)
{
	tlbi_all();
}

static inline void tlbi_mva_asid_nosync(vaddr_t va __unused, uint32_t asid __unused)
{
	tlbi_all();
}

#endif /*!__ASSEMBLER__*/

#endif /* TLB_HELPERS_H */
