/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Intel Corporation
 * Copyright (c) 2015, Linaro Limited
 */
#ifndef KERNEL_GENERIC_BOOT_H
#define KERNEL_GENERIC_BOOT_H

#include <initcall.h>
#include <types_ext.h>

void generic_boot_init_primary(void);

const struct thread_handlers *generic_boot_get_handlers(void);

#endif /* KERNEL_GENERIC_BOOT_H */
