/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */
#ifndef ARCH_SVC_PRIVATE_H
#define ARCH_SVC_PRIVATE_H

#include <tee_api_types.h>

/*
 * Generic "pointer to function" type. Actual syscalls take zero or more
 * arguments and return TEE_Result.
 */
typedef void (*syscall_t)(void);

#endif /*ARCH_SVC_PRIVATE_H*/
