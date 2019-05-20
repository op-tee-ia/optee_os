// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2009 Corey Tabaka
 * Copyright (c) 2018 Intel Corporation
 */

#include <compiler.h>
#include <util.h>
#include <types_ext.h>
#include <descriptor.h>


void set_global_desc(seg_sel_t sel, void *base, uint32_t limit,
					uint8_t present, uint8_t ring,
					uint8_t sys, uint8_t type,
					uint8_t gran, uint8_t bits)
{
	/* convert selector into index */
	uint16_t index = sel >> 3;

	_gdt[index].seg_desc_legacy.limit_15_0 = limit & GENMASK_32(15, 0);
	_gdt[index].seg_desc_legacy.limit_19_16 =
		(limit & GENMASK_32(19, 16)) >> 16;

	_gdt[index].seg_desc_legacy.base_15_0 =
		((uint64_t) base) & GENMASK_32(15, 0);
	_gdt[index].seg_desc_legacy.base_23_16 =
		(((uint64_t) base) & GENMASK_32(23, 16)) >> 16;
	_gdt[index].seg_desc_legacy.base_31_24 = ((uint64_t) base) >> 24;

	_gdt[index].seg_desc_legacy.type = type & 0x0f; /* segment type */
	_gdt[index].seg_desc_legacy.p = present != 0;   /* present */
	/* descriptor privilege level */
	_gdt[index].seg_desc_legacy.dpl = ring & 0x03;
	_gdt[index].seg_desc_legacy.g = gran != 0;      /* granularity */
	_gdt[index].seg_desc_legacy.s = sys != 0;       // system / non-system
	_gdt[index].seg_desc_legacy.d_b = bits != 0;    /* 16 / 32 bit */

	if (sel == TSS_SELECTOR) {
		index = (sel+8) >> 3;
		_gdt[index].seg_desc_64_t.base_32_63 =
			((uint64_t)base >> 32)	& 0xffffffff;
	}
}

