/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Intel Corporation
 * Copyright (c) 2014, Linaro Limited
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <stdint.h>
#include <mm/generic_ram_layout.h>

#define PLATFORM_QEMU 1
#define PRINT_USE_MMIO 0
#define PRINT_USE_IO_PORT 1
#define return_flags

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

/* SDP enable but no pool defined: reserve 4MB for SDP tests */
#if defined(CFG_SECURE_DATA_PATH) && !defined(CFG_TEE_SDP_MEM_BASE)
#define CFG_TEE_SDP_MEM_TEST_SIZE	0x00400000
#else
#define CFG_TEE_SDP_MEM_TEST_SIZE	0
#endif

#define CONSOLE_UART_BASE1	0x3f8
#define CONSOLE_UART_BASE2	0x3f8

/* PIC remap bases */
#define PIC1_BASE 0x20
#define PIC2_BASE 0x28

#define APIC_BASE       0xfee00000
#define APIC_REG_SIZE   0x1000

/* TA user mode virtual address */
// ToDo: How to prevent overlapping to other virtual addresses (self check)
#define TA_USER_BASE_VA 0xF0000000

/* Secure data path test memory pool: located at end of TA RAM */
#if CFG_TEE_SDP_MEM_TEST_SIZE
#define CFG_TEE_SDP_MEM_SIZE		CFG_TEE_SDP_MEM_TEST_SIZE
#define CFG_TEE_SDP_MEM_BASE		(TZDRAM_BASE + TZDRAM_SIZE - \
						CFG_TEE_SDP_MEM_SIZE)
#endif

#endif /*PLATFORM_CONFIG_H*/
