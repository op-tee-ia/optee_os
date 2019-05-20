/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2009 Corey Tabaka
 * Copyright (c) 2018 Intel Corporation
 */
#ifndef __DESCRIPTOR_H
#define __DESCRIPTOR_H

/*
 * System Selectors
 */
#define NULL_SELECTOR                   0x00

/********* x86 selectors *********/
#define CODE_SELECTOR                   0x08
#define DATA_SELECTOR                   0x10
#define USER_CODE_32_SELECTOR           0x18
#define USER_DATA_32_SELECTOR           0x20
#define NULL_2_SELECTOR                 0x28

/******* x86-64 selectors ********/
#define CODE_64_SELECTOR                0x30
#define STACK_64_SELECTOR               0x38
#define USER_CODE_COMPAT_SELECTOR       0x40
#define USER_DATA_COMPAT_SELECTOR       0x48
#define USER_CODE_64_SELECTOR           0x50
#define USER_DATA_64_SELECTOR           0x58

#define TSS_SELECTOR                    0x60

/*
 * Descriptor Types
 */
#define SEG_TYPE_TSS        0x9
#define SEG_TYPE_TSS_BUSY   0xb
#define SEG_TYPE_TASK_GATE  0x5
#define SEG_TYPE_INT_GATE   0xe     // 32 bit
#define SEG_TYPE_DATA_RW    0x2
#define SEG_TYPE_CODE_RW    0xa

#define USER_DPL	        0x03
#define USER_RPL	        0x03

#ifndef __ASSEMBLY__
typedef uint16_t seg_sel_t;

typedef union{
	struct {
		uint16_t limit_15_0;
		uint16_t base_15_0;
		uint8_t base_23_16;

		uint8_t type : 4;
		uint8_t s : 1;
		uint8_t dpl : 2;
		uint8_t p : 1;

		uint8_t limit_19_16 : 4;
		uint8_t avl : 1;
		uint8_t reserved_0 : 1;
		uint8_t d_b : 1;
		uint8_t g : 1;

		uint8_t base_31_24;
	} __packed seg_desc_legacy;
	struct {
		uint32_t base_32_63;
		uint16_t rsvd_1;
		uint16_t rsvd_2;
		/*TSS: Higher order 8 bytes.Intel Man Fig 7.4*/
	} __packed seg_desc_64_t;
} __packed seg_desc_t;

extern seg_desc_t _gdt[];

void set_global_desc(seg_sel_t sel, void *base, uint32_t limit,
					uint8_t present, uint8_t ring,
					uint8_t sys, uint8_t type,
					uint8_t gran, uint8_t bits);
#endif

#endif
