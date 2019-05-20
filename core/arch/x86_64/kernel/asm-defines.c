// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2018, Intel Corporation
 */

#include <gen-asm-defines.h>
#include <kernel/thread.h>
#include <types_ext.h>
#include "thread_private.h"

DEFINES
{
	DEFINE(THREAD_SMC_ARGS_X0, offsetof(struct thread_smc_args, a0));
	DEFINE(THREAD_SMC_ARGS_SIZE, sizeof(struct thread_smc_args));

	/* struct thread_ctx */
	DEFINE(THREAD_CTX_KERN_SP, offsetof(struct thread_ctx, kern_sp));
	DEFINE(THREAD_CTX_SIZE, sizeof(struct thread_ctx));

	/* struct thread_user_mode_rec */
	DEFINE(THREAD_USER_MODE_REC_EXIT_STATUS0_PTR,
		offsetof(struct thread_user_mode_rec, exit_status0_ptr));
	DEFINE(THREAD_USER_MODE_REC_X19,
		offsetof(struct thread_user_mode_rec, x[0]));
	DEFINE(THREAD_USER_MODE_REC_SIZE, sizeof(struct thread_user_mode_rec));

	/* struct thread_core_local */
	DEFINE(THREAD_CORE_LOCAL_X0, offsetof(struct thread_core_local, x[0]));
	DEFINE(THREAD_CORE_LOCAL_X2, offsetof(struct thread_core_local, x[2]));

	/* struct thread_core_local */
	DEFINE(THREAD_CORE_LOCAL_TMP_STACK_VA_END,
		offsetof(struct thread_core_local, tmp_stack_va_end));
	DEFINE(THREAD_CORE_LOCAL_CURR_THREAD,
		offsetof(struct thread_core_local, curr_thread));
	DEFINE(THREAD_CORE_LOCAL_FLAGS,
		offsetof(struct thread_core_local, flags));
	DEFINE(THREAD_CORE_LOCAL_ABT_STACK_VA_END,
		offsetof(struct thread_core_local, abt_stack_va_end));

}
