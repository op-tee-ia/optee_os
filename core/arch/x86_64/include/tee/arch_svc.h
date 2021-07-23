/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2020, Arm Limited
 * Copyright (c) 2021, Intel Corporation
 */
#ifndef TEE_ARCH_SVC_H
#define TEE_ARCH_SVC_H

extern unsigned long syscall_table;
extern const unsigned long tee_syscall_table[];
extern const unsigned long ldelf_syscall_table[];

void x86_syscall(void);
void __syscall_sys_return(unsigned long ret, unsigned long sp);
void __syscall_panic(unsigned long code, unsigned long sp);

#endif /*TEE_ARCH_SVC_H*/
