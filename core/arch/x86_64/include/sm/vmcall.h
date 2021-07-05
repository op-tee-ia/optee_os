/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017 Intel Corporation
 */
#ifndef VMCALL_H
#define VMCALL_H

#include <kernel/thread.h>

void make_smc_vmcall(struct thread_smc_args *args);

#endif
