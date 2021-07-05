/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef KERNEL_MISC_H
#define KERNEL_MISC_H

#include <kernel/thread.h>
#include <types_ext.h>

size_t get_core_pos(void);
size_t get_core_pos_mpidr(uint32_t mpidr);

#endif /*KERNEL_MISC_H*/

