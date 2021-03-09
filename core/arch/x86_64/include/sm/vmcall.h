/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017 Intel Corporation
 */
#ifndef __VMCALL_H
#define __VMCALL_H

#include <kernel/thread.h>

//hypercall id for ACRN
#define _HC_ID(x,y)     (((x)<<24)|(y))
#define HC_ID_TEE_BASE  0x90UL
#define HC_ID           0x80UL

#define HC_TEE_BOOT_DONE    _HC_ID(HC_ID,HC_ID_TEE_BASE+0x00)
#define HC_TEE_SERVICE_DONE _HC_ID(HC_ID,HC_ID_TEE_BASE+0x02)

void make_smc_hypercall(unsigned long hcall_id);
void make_smc_vmcall(struct thread_smc_args *args);

#endif
