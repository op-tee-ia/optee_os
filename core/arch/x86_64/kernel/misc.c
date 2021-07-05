// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018 Intel Corporation
 */

#include <x86.h>
#include <kernel/misc.h>

size_t get_core_pos(void)
{
	return 0;
}

size_t get_core_pos_mpidr(uint32_t mpidr __unused)
{
	return 0;
}
