/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Intel Corporation
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2000, 2001 Ben Harris
 * Copyright (c) 1996 Scott K. Stevens
 */

#ifndef KERNEL_UNWIND
#define KERNEL_UNWIND

#ifndef ASM
#include <compiler.h>
#include <types_ext.h>

static inline void print_kernel_stack(int level __unused)
{
}
#endif /*ASM*/

#endif /*KERNEL_UNWIND*/
