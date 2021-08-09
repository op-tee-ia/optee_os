/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2016, Linaro Limited
 */
#ifndef CORE_MMU_PRIVATE_H
#define CORE_MMU_PRIVATE_H

#include <mm/core_mmu.h>
#include <mm/tee_mmu_types.h>


void core_init_mmu(struct tee_mmap_region *mm);

static inline bool core_mmap_is_end_of_table(const struct tee_mmap_region *mm)
{
	return mm->type == MEM_AREA_END;
}

#endif /*CORE_MMU_PRIVATE_H*/

