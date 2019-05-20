/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */
#ifndef TEE_ARCH_SVC_H
#define TEE_ARCH_SVC_H

void x86_syscall(void);
void __syscall_sys_return(unsigned long ret, unsigned long sp);
void __syscall_panic(unsigned long code, unsigned long sp);

#endif /*TEE_ARCH_SVC_H*/
