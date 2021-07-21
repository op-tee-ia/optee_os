/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef THREAD_PRIVATE_H
#define THREAD_PRIVATE_H

#ifndef __ASSEMBLER__

#include <mm/core_mmu.h>
#include <mm/pgt_cache.h>
#include <kernel/mutex.h>
#include <kernel/thread.h>

enum thread_state {
	THREAD_STATE_FREE,
	THREAD_STATE_SUSPENDED,
	THREAD_STATE_ACTIVE,
};

#define MAX_TA_IDX		4

struct thread_user_mode_rec {
	uint64_t exit_status0_ptr;
	uint64_t exit_status1_ptr;
	uint64_t x[31 - 19]; /* x19..x30 */
};

struct thread_shm_cache_entry {
	struct mobj *mobj;
	size_t size;
	enum thread_shm_type type;
	enum thread_shm_cache_user user;
	SLIST_ENTRY(thread_shm_cache_entry) link;
};

SLIST_HEAD(thread_shm_cache, thread_shm_cache_entry);

struct thread_ctx {
	struct thread_ctx_regs regs;
	enum thread_state state;
	vaddr_t stack_va_end;
	vaddr_t stack_va_curr[MAX_TA_IDX];
	uint32_t ta_idx;
	uint32_t hyp_clnt_id;
	uint32_t flags;
	struct core_mmu_user_map user_map;
	bool have_user_map;
	vaddr_t kern_sp;	/* Saved kernel SP during user TA execution */
	void *rpc_arg;
	struct mobj *rpc_mobj;
	struct thread_shm_cache shm_cache;
	struct thread_specific_data tsd;
};
#endif /*__ASSEMBLER__*/

/* Describes the flags field of struct thread_core_local */
#define THREAD_CLF_SAVED_SHIFT			4
#define THREAD_CLF_CURR_SHIFT			0
#define THREAD_CLF_MASK				0xf
#define THREAD_CLF_TMP_SHIFT			0
#define THREAD_CLF_ABORT_SHIFT			1
#define THREAD_CLF_IRQ_SHIFT			2
#define THREAD_CLF_FIQ_SHIFT			3

#define THREAD_CLF_TMP				(1 << THREAD_CLF_TMP_SHIFT)
#define THREAD_CLF_ABORT			(1 << THREAD_CLF_ABORT_SHIFT)
#define THREAD_CLF_IRQ				(1 << THREAD_CLF_IRQ_SHIFT)
#define THREAD_CLF_FIQ				(1 << THREAD_CLF_FIQ_SHIFT)

#ifndef __ASSEMBLER__
extern const void *stack_tmp_export;
extern const uint32_t stack_tmp_stride;
extern struct thread_ctx threads[];

/*
 * During boot note the part of code and data that needs to be mapped while
 * in user mode. The provided address and size have to be page aligned.
 * Note that the code and data will be mapped at the lowest possible
 * addresses available for user space (see core_mmu_get_user_va_range()).
 */
extern long thread_user_kcode_offset;

/*
 * Initializes VBAR for current CPU (called by thread_init_per_cpu()
 */
void thread_init_vbar(vaddr_t addr);

/*
 * Handles a stdcall, r10-r15 holds the parameters
 */
void thread_std_smc_entry(void);
void __thread_std_smc_entry(struct thread_smc_args *args);

void thread_sp_alloc_and_run(struct thread_smc_args *args);

/*
 * Resumes execution of currently active thread by restoring context and
 * jumping to the instruction where to continue execution.
 *
 * Arguments supplied by non-secure world will be copied into the saved
 * context of the current thread if THREAD_FLAGS_COPY_ARGS_ON_RETURN is set
 * in the flags field in the thread context.
 */
void thread_resume(struct thread_ctx_regs *regs, vaddr_t tmp_stack);

void thread_rpc_resume(vaddr_t sp, struct thread_smc_args *args,
						vaddr_t tmp_stack);
/*
 * Resume thread status from a foreign interrupt
 */
void foreign_intr_resume(vaddr_t sp, vaddr_t abt_stack);

/*
 * Get the return value from a standard secure monitor call
 */
void thread_get_stdcall_ret(struct thread_smc_args *args);

/*
 * Main loop between secure world and non-secure world
 */
void sm_sched_nonsecure(void);

uint32_t __thread_enter_user_mode(struct thread_ctx_regs *regs,
				  uint32_t *exit_status0,
				  uint32_t *exit_status1);

/*
 * Private functions made available for thread_asm.S
 */

/* Returns the temp stack for current CPU */
void *thread_get_tmp_sp(void);

/*
 * Marks the current thread as suspended. And updated the flags
 * for the thread context (see thread resume for use of flags).
 * Returns thread index of the thread that was suspended.
 */
int thread_state_suspend(uint32_t flags, vaddr_t sp);

/*
 * Save the state of current thread
 */
void thread_state_save(vaddr_t sp, uint32_t client);

/*
 * Marks the current thread as free.
 */
void thread_state_free(void);

/* Returns a pointer to the saved registers in current thread context. */
struct thread_ctx_regs *thread_get_ctx_regs(void);

/* Checks stack canaries */
void thread_check_canaries(void);

void thread_alloc_and_run(struct thread_smc_args *args);
void thread_resume_from_rpc(struct thread_smc_args *args);
void thread_lock_global(void);
void thread_unlock_global(void);

/*
 * Suspends current thread and temorarily exits to non-secure world.
 * This function returns later when non-secure world returns.
 *
 * The purpose of this function is to request services from non-secure
 * world.
 */
#define THREAD_RPC_NUM_ARGS     4
void thread_rpc(uint32_t rv[THREAD_RPC_NUM_ARGS]);

/*
 * Handles a fast SMC by dispatching it to the registered fast SMC handler
 */
void thread_handle_fast_smc(struct thread_smc_args *args);

/*
 * Handles a std SMC by dispatching it to the registered std SMC handler
 */
void thread_handle_std_smc(struct thread_smc_args *args);

/* Frees the cache of allocated FS RPC memory */
void thread_rpc_shm_cache_clear(struct thread_shm_cache *cache);
#endif /*__ASSEMBLER__*/
#endif /*THREAD_PRIVATE_H*/
