// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2021, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2020-2021, Arm Limited
 * Copyright (c) 2021, Intel Corporation
 */

#include <platform_config.h>
#include <x86.h>
#include <descriptor.h>
#include <assert.h>
#include <config.h>
#include <io.h>
#include <keep.h>
#include <kernel/asan.h>
#include <kernel/boot.h>
#include <kernel/linker.h>
#include <kernel/lockdep.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread_defs.h>
#include <kernel/thread.h>
#include <tee/arch_svc.h>
#include <sm/optee_smc.h>
#include <kernel/user_mode_ctx_struct.h>
#include <kernel/virtualization.h>
#include <mm/core_memprot.h>
#include <mm/mobj.h>
#include <mm/tee_mm.h>
#include <mm/tee_pager.h>
#include <mm/vm.h>
#include <trace.h>
#include <util.h>
#include <console.h>

#include "thread_private.h"

struct thread_ctx threads[CFG_NUM_THREADS];

struct thread_core_local thread_core_local[CFG_TEE_CORE_NB_CORE] __nex_bss;

/*
 * Stacks
 *
 * [Lower addresses on the left]
 *
 * [ STACK_CANARY_SIZE/2 | STACK_CHECK_EXTRA | STACK_XXX_SIZE | STACK_CANARY_SIZE/2 ]
 * ^                     ^                   ^                ^
 * stack_xxx[n]          "hard" top          "soft" top       bottom
 */

#define STACK_TMP_OFFS		64
#define STACK_TMP_SIZE		(2048 + STACK_TMP_OFFS)
#define STACK_THREAD_SIZE	8192

#if TRACE_LEVEL > 0
#define STACK_ABT_SIZE		3072
#else
#define STACK_ABT_SIZE		1024
#endif

#ifdef CFG_WITH_STACK_CANARIES
#define STACK_CANARY_SIZE	(8 * sizeof(uint32_t))
#define START_CANARY_VALUE	0xdededede
#define END_CANARY_VALUE	0xabababab
#define GET_START_CANARY(name, stack_num) name[stack_num][0]
#define GET_END_CANARY(name, stack_num) \
	name[stack_num][sizeof(name[stack_num]) / sizeof(uint32_t) - 1]
#else
#define STACK_CANARY_SIZE	0
#endif

#ifdef CFG_CORE_DEBUG_CHECK_STACKS
/*
 * Extra space added to each stack in order to reliably detect and dump stack
 * overflows. Should cover the maximum expected overflow size caused by any C
 * function (say, 512 bytes; no function should have that much local variables),
 * plus the maximum stack space needed by __cyg_profile_func_exit(): about 1 KB,
 * a large part of which is used to print the call stack. Total: 1.5 KB.
 */
#define STACK_CHECK_EXTRA	1536
#else
#define STACK_CHECK_EXTRA	0
#endif

#define DECLARE_STACK(name, num_stacks, stack_size, linkage) \
linkage uint32_t name[num_stacks] \
		[ROUNDUP(stack_size + STACK_CANARY_SIZE + STACK_CHECK_EXTRA, \
			 STACK_ALIGNMENT) / sizeof(uint32_t)] \
		__attribute__((section(".nozi_stack." # name), \
			       aligned(STACK_ALIGNMENT)))

#define STACK_SIZE(stack) (sizeof(stack) - STACK_CANARY_SIZE / 2)
#define GET_STACK(stack) ((vaddr_t)(stack) + STACK_SIZE(stack))

DECLARE_STACK(stack_tmp, CFG_TEE_CORE_NB_CORE,
	      STACK_TMP_SIZE + CFG_STACK_TMP_EXTRA, static);
/* Change from per core to per thread on x86. */
DECLARE_STACK(stack_abt, CFG_NUM_THREADS, STACK_ABT_SIZE, static);
#ifndef CFG_WITH_PAGER
DECLARE_STACK(stack_thread, CFG_NUM_THREADS,
	      STACK_THREAD_SIZE + CFG_STACK_THREAD_EXTRA, static);
#endif

#define GET_STACK_TOP_HARD(stack, n) \
	((vaddr_t)&(stack)[n] + STACK_CANARY_SIZE / 2)
#define GET_STACK_TOP_SOFT(stack, n) \
	(GET_STACK_TOP_HARD(stack, n) + STACK_CHECK_EXTRA)
#define GET_STACK_BOTTOM(stack, n) ((vaddr_t)&(stack)[n] + sizeof(stack[n]) - \
				    STACK_CANARY_SIZE / 2)

const void *stack_tmp_export __section(".identity_map.stack_tmp_export") =
	(void *)(GET_STACK_BOTTOM(stack_tmp, 0) - STACK_TMP_OFFS);
const uint32_t stack_tmp_stride __section(".identity_map.stack_tmp_stride") =
	sizeof(stack_tmp[0]);

/*
 * These stack setup info are required by secondary boot cores before they
 * each locally enable the pager (the mmu). Hence kept in pager sections.
 */
DECLARE_KEEP_PAGER(stack_tmp_export);
DECLARE_KEEP_PAGER(stack_tmp_stride);

static unsigned int thread_global_lock __nex_bss = SPINLOCK_UNLOCK;

static void syscall_init(vaddr_t sp)
{
	write_msr(SYSENTER_CS_MSR, CODE_64_SELECTOR); /* cs_addr  */
	write_msr(SYSENTER_ESP_MSR, sp); 	      /* esp_addr */
}

static void init_canaries(void)
{
#ifdef CFG_WITH_STACK_CANARIES
	size_t n;
#define INIT_CANARY(name)						\
	for (n = 0; n < ARRAY_SIZE(name); n++) {			\
		uint32_t *start_canary = &GET_START_CANARY(name, n);	\
		uint32_t *end_canary = &GET_END_CANARY(name, n);	\
									\
		*start_canary = START_CANARY_VALUE;			\
		*end_canary = END_CANARY_VALUE;				\
	}

	INIT_CANARY(stack_tmp);
	INIT_CANARY(stack_abt);
#if !defined(CFG_WITH_PAGER) && !defined(CFG_VIRTUALIZATION)
	INIT_CANARY(stack_thread);
#endif
#endif/*CFG_WITH_STACK_CANARIES*/
}

#define CANARY_DIED(stack, loc, n, addr) \
	do { \
		EMSG_RAW("Dead canary at %s of '%s[%zu]' (%p)", #loc, #stack, \
			 n, (void *)addr); \
		panic(); \
	} while (0)

void thread_check_canaries(void)
{
#ifdef CFG_WITH_STACK_CANARIES
	uint32_t *canary = NULL;
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(stack_tmp); n++) {
		canary = &GET_START_CANARY(stack_tmp, n);
		if (*canary != START_CANARY_VALUE)
			CANARY_DIED(stack_tmp, start, n, canary);
		canary = &GET_END_CANARY(stack_tmp, n);
		if (*canary != END_CANARY_VALUE)
			CANARY_DIED(stack_tmp, end, n, canary);
	}

	for (n = 0; n < ARRAY_SIZE(stack_abt); n++) {
		canary = &GET_START_CANARY(stack_abt, n);
		if (*canary != START_CANARY_VALUE)
			CANARY_DIED(stack_abt, start, n, canary);
		canary = &GET_END_CANARY(stack_abt, n);
		if (*canary != END_CANARY_VALUE)
			CANARY_DIED(stack_abt, end, n, canary);

	}
#if !defined(CFG_WITH_PAGER) && !defined(CFG_VIRTUALIZATION)
	for (n = 0; n < ARRAY_SIZE(stack_thread); n++) {
		canary = &GET_START_CANARY(stack_thread, n);
		if (*canary != START_CANARY_VALUE)
			CANARY_DIED(stack_thread, start, n, canary);
		canary = &GET_END_CANARY(stack_thread, n);
		if (*canary != END_CANARY_VALUE)
			CANARY_DIED(stack_thread, end, n, canary);
	}
#endif
#endif/*CFG_WITH_STACK_CANARIES*/
}

void thread_lock_global(void)
{
	cpu_spin_lock(&thread_global_lock);
}

void thread_unlock_global(void)
{
	cpu_spin_unlock(&thread_global_lock);
}

uint32_t thread_get_exceptions(void)
{
	uint64_t rflags = x86_save_flags();

	if (rflags & THREAD_EXCP_ALL) {
		return 0;
	} else {
		return THREAD_EXCP_ALL;
	}
}

void __nostackcheck thread_set_exceptions(uint32_t exceptions)
{
	uint64_t rflags = x86_save_flags();

	/* Foreign interrupts must not be unmasked while holding a spinlock */
	if (!(exceptions & THREAD_EXCP_FOREIGN_INTR))
		assert_have_no_spinlock();

	rflags &= ~THREAD_EXCP_ALL;
	rflags |= (~exceptions & THREAD_EXCP_ALL);

	x86_restore_flags(rflags);
}

uint32_t __nostackcheck thread_mask_exceptions(uint32_t exceptions)
{
	uint32_t state = thread_get_exceptions();

	thread_set_exceptions(state | (exceptions & THREAD_EXCP_ALL));
	return state;
}

void __nostackcheck thread_unmask_exceptions(uint32_t state)
{
	thread_set_exceptions(state & THREAD_EXCP_ALL);
}


static struct thread_core_local * __nostackcheck
get_core_local(unsigned int pos)
{
	/*
	 * Foreign interrupts must be disabled before playing with core_local
	 * since we otherwise may be rescheduled to a different core in the
	 * middle of this function.
	 */
	assert(thread_get_exceptions() & THREAD_EXCP_FOREIGN_INTR);

	assert(pos < CFG_TEE_CORE_NB_CORE);
	return &thread_core_local[pos];
}

struct thread_core_local * __nostackcheck thread_get_core_local(void)
{
	unsigned int pos = get_core_pos();

	return get_core_local(pos);
}

#ifdef CFG_CORE_DEBUG_CHECK_STACKS
static void print_stack_limits(void)
{
	size_t n = 0;
	vaddr_t __maybe_unused start = 0;
	vaddr_t __maybe_unused end = 0;

	for (n = 0; n < CFG_TEE_CORE_NB_CORE; n++) {
		start = GET_STACK_TOP_SOFT(stack_tmp, n);
		end = GET_STACK_BOTTOM(stack_tmp, n);
		DMSG("tmp [%zu] 0x%" PRIxVA "..0x%" PRIxVA, n, start, end);
	}
	for (n = 0; n < CFG_TEE_CORE_NB_CORE; n++) {
		start = GET_STACK_TOP_SOFT(stack_abt, n);
		end = GET_STACK_BOTTOM(stack_abt, n);
		DMSG("abt [%zu] 0x%" PRIxVA "..0x%" PRIxVA, n, start, end);
	}
	for (n = 0; n < CFG_NUM_THREADS; n++) {
		end = threads[n].stack_va_end;
		start = end - STACK_THREAD_SIZE;
		DMSG("thr [%zu] 0x%" PRIxVA "..0x%" PRIxVA, n, start, end);
	}
}

static void check_stack_limits(void)
{
	vaddr_t stack_start = 0;
	vaddr_t stack_end = 0;
	/* Any value in the current stack frame will do */
	vaddr_t current_sp = (vaddr_t)&stack_start;

	if (!get_stack_soft_limits(&stack_start, &stack_end))
		panic("Unknown stack limits");
	if (current_sp < stack_start || current_sp > stack_end) {
		DMSG("Stack pointer out of range (0x%" PRIxVA ")", current_sp);
		print_stack_limits();
		panic();
	}
}

static bool * __nostackcheck get_stackcheck_recursion_flag(void)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	unsigned int pos = get_core_pos();
	struct thread_core_local *l = get_core_local(pos);
	int ct = l->curr_thread;
	bool *p = NULL;

	if (l->flags & (THREAD_CLF_ABORT | THREAD_CLF_TMP))
		p = &l->stackcheck_recursion;
	else if (!l->flags)
		p = &threads[ct].tsd.stackcheck_recursion;

	thread_unmask_exceptions(exceptions);
	return p;
}

void __cyg_profile_func_enter(void *this_fn, void *call_site);
void __nostackcheck __cyg_profile_func_enter(void *this_fn __unused,
					     void *call_site __unused)
{
	bool *p = get_stackcheck_recursion_flag();

	assert(p);
	if (*p)
		return;
	*p = true;
	check_stack_limits();
	*p = false;
}

void __cyg_profile_func_exit(void *this_fn, void *call_site);
void __nostackcheck __cyg_profile_func_exit(void *this_fn __unused,
					    void *call_site __unused)
{
}
#else
static void print_stack_limits(void)
{
}
#endif

static void init_regs(struct thread_ctx *thread, struct thread_smc_args *args)
{
	struct thread_ctx_regs *regs;

	thread->stack_va_curr[0] = thread->stack_va_end -
		sizeof(struct thread_ctx_regs);
	thread->stack_va_curr[0] = ROUNDDOWN(thread->stack_va_curr[0], 64);
	regs = (struct thread_ctx_regs *)(thread->stack_va_curr[0]);

	memset(regs, 0, sizeof(*regs));

	regs->rip = (uint64_t)thread_std_smc_entry;
	regs->rflags = 0x3002;

	regs->r10 = args->a0;
	regs->r11 = args->a1;
	regs->r12 = args->a2;
	regs->r13 = args->a3;
	regs->r14 = args->a4;
	regs->r15 = args->a5;
}

void thread_init_boot_thread(void)
{
	struct thread_core_local *l = thread_get_core_local();

	thread_init_threads();

	l->curr_thread = 0;
	threads[0].state = THREAD_STATE_ACTIVE;
}

void __nostackcheck thread_clr_boot_thread(void)
{
	struct thread_core_local *l = thread_get_core_local();

	assert(l->curr_thread >= 0 && l->curr_thread < CFG_NUM_THREADS);
	assert(threads[l->curr_thread].state == THREAD_STATE_ACTIVE);
	threads[l->curr_thread].state = THREAD_STATE_FREE;
	l->curr_thread = THREAD_ID_INVALID;
}

/* main tss */
static tss_t system_tss;

static void switch_interrupt_stack(short int thread_id)
{
	system_tss.rsp0 = GET_STACK(stack_abt[thread_id]);
	system_tss.ist1 = GET_STACK(stack_abt[thread_id]);
}

static void init_tss(void)
{
	memset(&system_tss, 0, sizeof(system_tss));
	set_global_desc(TSS_SELECTOR, &system_tss, sizeof(system_tss),
		1, 0, 0, SEG_TYPE_TSS, 0, 0);

	x86_ltr(TSS_SELECTOR);
}

void thread_alloc_and_run(struct thread_smc_args *args)
{
	size_t n;
	struct thread_core_local *l = thread_get_core_local();
	bool found_thread = false;

	assert(l->curr_thread == THREAD_ID_INVALID);

	thread_lock_global();

	for (n = 0; n < CFG_NUM_THREADS; n++) {
		if (threads[n].state == THREAD_STATE_FREE) {
			threads[n].state = THREAD_STATE_ACTIVE;
			found_thread = true;
			break;
		}
	}

	thread_unlock_global();

	if (!found_thread) {
		args->a0 = OPTEE_SMC_RETURN_ETHREAD_LIMIT;
		return;
	}

	l->curr_thread = n;

	threads[n].flags = 0;
	threads[n].ta_idx = 0;
	init_regs(threads + n, args);

	switch_interrupt_stack(n);

	l->flags &= ~THREAD_CLF_TMP;

	thread_resume((struct thread_ctx_regs *)(threads[n].stack_va_curr[0]), args,
			l->tmp_stack_va_end);
}

#ifdef CFG_SECURE_PARTITION
void thread_sp_alloc_and_run(struct thread_smc_args *args __maybe_unused)
{
	__thread_alloc_and_run(args->a0, args->a1, args->a2, args->a3, args->a4,
			       args->a5, args->a6, args->a7,
			       spmc_sp_thread_entry);
}
#endif

#ifdef CFG_SYSCALL_FTRACE
static void __noprof ftrace_suspend(void)
{
	struct ts_session *s = TAILQ_FIRST(&thread_get_tsd()->sess_stack);

	if (s && s->fbuf)
		s->fbuf->syscall_trace_suspended = true;
}

static void __noprof ftrace_resume(void)
{
	struct ts_session *s = TAILQ_FIRST(&thread_get_tsd()->sess_stack);

	if (s && s->fbuf)
		s->fbuf->syscall_trace_suspended = false;
}
#else
static void __noprof ftrace_suspend(void)
{
}

static void __noprof ftrace_resume(void)
{
}
#endif

void thread_resume_from_rpc(struct thread_smc_args *args)
{
	size_t n = args->a3; /* thread id */
	struct thread_core_local *l = thread_get_core_local();
	bool found_thread = false;

	assert(l->curr_thread == THREAD_ID_INVALID);

	thread_lock_global();

	if (n < CFG_NUM_THREADS && threads[n].state == THREAD_STATE_SUSPENDED) {
		threads[n].state = THREAD_STATE_ACTIVE;
		found_thread = true;
	}

	thread_unlock_global();

	if (!found_thread) {
		args->a0 = OPTEE_SMC_RETURN_ERESUME;
		return;
	}

	l->curr_thread = n;
	switch_interrupt_stack(n);

	if (threads[n].have_user_map)
		ftrace_resume();

	l->flags &= ~THREAD_CLF_TMP;

	if (threads[n].flags & THREAD_FLAGS_COPY_ARGS_ON_RETURN) {
		if (threads[n].have_user_map) {
			struct thread_specific_data *tsd = thread_get_tsd();

			tee_ta_update_session_utime_resume();
			core_mmu_set_user_map(&threads[n].user_map);
		}

		threads[n].flags &= ~THREAD_FLAGS_COPY_ARGS_ON_RETURN;
		assert(threads[n].ta_idx < MAX_TA_IDX);

		thread_rpc_resume(threads[n].stack_va_curr[threads[n].ta_idx],
				args, l->tmp_stack_va_end);
	} else if (threads[n].flags & THREAD_FLAGS_EXIT_ON_FOREIGN_INTR) {
		threads[n].flags &= ~THREAD_FLAGS_EXIT_ON_FOREIGN_INTR;
		foreign_intr_resume(threads[n].abt_stack_va_end, args, l->tmp_stack_va_end);
	} else {
		args->a0 = OPTEE_SMC_RETURN_ERESUME;
		return;
	}
}

void __nostackcheck *thread_get_tmp_sp(void)
{
	struct thread_core_local *l = thread_get_core_local();

	/*
	 * Called from assembly when switching to the temporary stack, so flags
	 * need updating
	 */
	l->flags |= THREAD_CLF_TMP;

	return (void *)l->tmp_stack_va_end;
}

vaddr_t thread_stack_start(void)
{
	struct thread_ctx *thr;
	int ct = thread_get_id_may_fail();

	if (ct == THREAD_ID_INVALID)
		return 0;

	thr = threads + ct;
	return thr->stack_va_end - STACK_THREAD_SIZE;
}

size_t thread_stack_size(void)
{
	return STACK_THREAD_SIZE;
}

bool get_stack_limits(vaddr_t *start, vaddr_t *end, bool hard)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	unsigned int pos = get_core_pos();
	struct thread_core_local *l = get_core_local(pos);
	int ct = l->curr_thread;
	bool ret = false;

	if (l->flags & THREAD_CLF_TMP) {
		if (hard)
			*start = GET_STACK_TOP_HARD(stack_tmp, pos);
		else
			*start = GET_STACK_TOP_SOFT(stack_tmp, pos);
		*end = GET_STACK_BOTTOM(stack_tmp, pos);
		ret = true;
	} else if (l->flags & THREAD_CLF_ABORT) {
		if (hard)
			*start = GET_STACK_TOP_HARD(stack_abt, pos);
		else
			*start = GET_STACK_TOP_SOFT(stack_abt, pos);
		*end = GET_STACK_BOTTOM(stack_abt, pos);
		ret = true;
	} else if (!l->flags) {
		if (ct < 0 || ct >= CFG_NUM_THREADS)
			goto out;

		*end = threads[ct].stack_va_end;
		*start = *end - STACK_THREAD_SIZE;
		if (!hard)
			*start += STACK_CHECK_EXTRA;
		ret = true;
	}
out:
	thread_unmask_exceptions(exceptions);
	return ret;
}

bool thread_is_from_abort_mode(void)
{
	struct thread_core_local *l = thread_get_core_local();

	return (l->flags >> THREAD_CLF_SAVED_SHIFT) & THREAD_CLF_ABORT;
}

bool thread_is_in_normal_mode(void)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	struct thread_core_local *l = thread_get_core_local();
	bool ret;

	/* If any bit in l->flags is set we're handling some exception. */
	ret = !l->flags;
	thread_unmask_exceptions(exceptions);

	return ret;
}

void thread_state_free(void)
{
	struct thread_core_local *l = thread_get_core_local();
	int ct = l->curr_thread;

	assert(ct != THREAD_ID_INVALID);

	tee_pager_release_phys(
		(void *)(threads[ct].stack_va_end - STACK_THREAD_SIZE),
		STACK_THREAD_SIZE);

	thread_lock_global();

	assert(threads[ct].state == THREAD_STATE_ACTIVE);
	threads[ct].state = THREAD_STATE_FREE;
	threads[ct].flags = 0;
	l->curr_thread = THREAD_ID_INVALID;

#ifdef CFG_VIRTUALIZATION
	virt_unset_guest();
#endif
	thread_unlock_global();
}

#ifdef CFG_WITH_PAGER
static void release_unused_kernel_stack(struct thread_ctx *thr,
					uint32_t cpsr __maybe_unused)
{
#ifdef ARM64
	/*
	 * If we're from user mode then thr->regs.sp is the saved user
	 * stack pointer and thr->kern_sp holds the last kernel stack
	 * pointer. But if we're from kernel mode then thr->kern_sp isn't
	 * up to date so we need to read from thr->regs.sp instead.
	 */
	vaddr_t sp = is_from_user(cpsr) ?  thr->kern_sp : thr->regs.sp;
#else
	vaddr_t sp = thr->regs.svc_sp;
#endif
	vaddr_t base = thr->stack_va_end - STACK_THREAD_SIZE;
	size_t len = sp - base;

	tee_pager_release_phys((void *)base, len);
}
#else
static void release_unused_kernel_stack(struct thread_ctx *thr __unused,
					uint32_t cpsr __unused)
{
}
#endif

int thread_state_suspend(uint32_t flags, vaddr_t sp)
{
	struct thread_core_local *l = thread_get_core_local();
	int ct = l->curr_thread;

	assert(ct != THREAD_ID_INVALID);

	if (core_mmu_user_mapping_is_active())
		ftrace_suspend();

	thread_check_canaries();

	release_unused_kernel_stack(threads + ct, 0);

	thread_lock_global();

	assert(threads[ct].state == THREAD_STATE_ACTIVE);
	threads[ct].flags |= flags;

	if (flags & THREAD_FLAGS_EXIT_ON_FOREIGN_INTR) {
		threads[ct].abt_stack_va_end = sp;
	} else {
		assert(threads[ct].ta_idx < MAX_TA_IDX);
		threads[ct].stack_va_curr[threads[ct].ta_idx] = sp;

		threads[ct].have_user_map = core_mmu_user_mapping_is_active();
		if (threads[ct].have_user_map) {
			core_mmu_get_user_map(&threads[ct].user_map);
			core_mmu_set_user_map(NULL);
		}
	}

	threads[ct].state = THREAD_STATE_SUSPENDED;
	l->curr_thread = THREAD_ID_INVALID;

#ifdef CFG_VIRTUALIZATION
	virt_unset_guest();
#endif

	thread_unlock_global();

	return ct;
}

void thread_state_save(vaddr_t sp)
{
	struct thread_core_local *l = thread_get_core_local();
	int ct = l->curr_thread;

	assert(ct != THREAD_ID_INVALID);

	thread_lock_global();

	assert(threads[ct].state == THREAD_STATE_ACTIVE);

	threads[ct].ta_idx++;
	assert(threads[ct].ta_idx < MAX_TA_IDX+1);
	threads[ct].stack_va_curr[threads[ct].ta_idx-1] = sp;

	syscall_init(sp - 64);

	thread_unlock_global();
}

vaddr_t thread_state_restore(void)
{
	struct thread_core_local *l = thread_get_core_local();
	int ct = l->curr_thread;

	assert(ct != THREAD_ID_INVALID);

	assert(threads[ct].state == THREAD_STATE_ACTIVE);

	assert(threads[ct].ta_idx < MAX_TA_IDX+1);

	if (threads[ct].ta_idx > 1) {
		threads[ct].ta_idx--;
		syscall_init(threads[ct].stack_va_curr[threads[ct].ta_idx]
				- 64);
		return threads[ct].stack_va_curr[threads[ct].ta_idx];
	}

	threads[ct].ta_idx = 0;
	return threads[ct].stack_va_curr[0];
}

static void set_tmp_stack(struct thread_core_local *l, vaddr_t sp)
{
	/*
	 * We're already using the tmp stack when this function is called
	 * so there's no need to assign it to any stack pointer. However,
	 * we'll need to restore it at different times so store it here.
	 */
	l->tmp_stack_va_end = sp;
}

static void set_abt_stack(struct thread_ctx *thread, vaddr_t sp)
{
	thread->abt_stack_va_end = sp;
}

bool thread_init_stack(uint32_t thread_id, vaddr_t sp, vaddr_t abt_sp)
{
	if (thread_id >= CFG_NUM_THREADS)
		return false;
	threads[thread_id].stack_va_end = sp;
	threads[thread_id].abt_stack_va_end = abt_sp;
	return true;
}

short int thread_get_id_may_fail(void)
{
	/*
	 * thread_get_core_local() requires foreign interrupts to be disabled
	 */
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	struct thread_core_local *l = thread_get_core_local();

	short int ct = l->curr_thread;

	thread_unmask_exceptions(exceptions);
	return ct;
}

short int thread_get_id(void)
{
	short int ct = thread_get_id_may_fail();

	/* Thread ID has to fit in a short int */
	COMPILE_TIME_ASSERT(CFG_NUM_THREADS <= SHRT_MAX);
	assert(ct >= 0 && ct < CFG_NUM_THREADS);
	return ct;
}

#ifdef CFG_WITH_PAGER
static void init_thread_stacks(void)
{
	size_t n = 0;

	/*
	 * Allocate virtual memory for thread stacks.
	 */
	for (n = 0; n < CFG_NUM_THREADS; n++) {
		tee_mm_entry_t *mm = NULL;
		vaddr_t sp = 0;
		size_t num_pages = 0;
		struct fobj *fobj = NULL;

		/* Find vmem for thread stack and its protection gap */
		mm = tee_mm_alloc(&tee_mm_vcore,
				  SMALL_PAGE_SIZE + STACK_THREAD_SIZE);
		assert(mm);

		/* Claim eventual physical page */
		tee_pager_add_pages(tee_mm_get_smem(mm), tee_mm_get_size(mm),
				    true);

		num_pages = tee_mm_get_bytes(mm) / SMALL_PAGE_SIZE - 1;
		fobj = fobj_locked_paged_alloc(num_pages);

		/* Add the area to the pager */
		tee_pager_add_core_area(tee_mm_get_smem(mm) + SMALL_PAGE_SIZE,
					PAGER_AREA_TYPE_LOCK, fobj);
		fobj_put(fobj);

		/* init effective stack */
		sp = tee_mm_get_smem(mm) + tee_mm_get_bytes(mm);
		asan_tag_access((void *)tee_mm_get_smem(mm), (void *)sp);
		if (!thread_init_stack(n, sp))
			panic("init stack failed");
	}
}
#else
static void init_thread_stacks(void)
{
	size_t n;

	/* Assign the thread stacks */
	for (n = 0; n < CFG_NUM_THREADS; n++) {
		if (!thread_init_stack(n, GET_STACK_BOTTOM(stack_thread, n), GET_STACK(stack_abt[n])))
			panic("thread_init_stack failed");
	}
}
#endif /*CFG_WITH_PAGER*/

void thread_init_threads(void)
{
	size_t n = 0;

	init_thread_stacks();
	print_stack_limits();
	pgt_init();

	mutex_lockdep_init();

	for (n = 0; n < CFG_NUM_THREADS; n++) {
		TAILQ_INIT(&threads[n].tsd.sess_stack);
		SLIST_INIT(&threads[n].tsd.pgt_cache);
	}
}

void __nostackcheck thread_init_thread_core_local(void)
{
	size_t n = 0;
	struct thread_core_local *tcl = thread_core_local;

	for (n = 0; n < CFG_TEE_CORE_NB_CORE; n++) {
		tcl[n].curr_thread = THREAD_ID_INVALID;
		tcl[n].flags = THREAD_CLF_TMP;
	}

	tcl[0].tmp_stack_va_end = GET_STACK_BOTTOM(stack_tmp, 0);
}

void thread_init_primary(void)
{
	/* Initialize canaries around the stacks */
	init_canaries();
}

void thread_init_per_cpu(void)
{
	size_t pos = get_core_pos();
	struct thread_core_local *l = thread_get_core_local();

	set_tmp_stack(l, GET_STACK(stack_tmp[pos]) - STACK_TMP_OFFS);

	init_tss();
}

struct thread_specific_data *thread_get_tsd(void)
{
	return &threads[thread_get_id()].tsd;
}

struct thread_ctx_regs * __nostackcheck thread_get_ctx_regs(void)
{
	struct thread_core_local *l = thread_get_core_local();

	assert(l->curr_thread != THREAD_ID_INVALID);
	return &threads[l->curr_thread].regs;
}

void thread_set_foreign_intr(bool enable)
{
	/* thread_get_core_local() requires foreign interrupts to be disabled */
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	struct thread_core_local *l;

	l = thread_get_core_local();

	assert(l->curr_thread != THREAD_ID_INVALID);

	if (enable) {
		threads[l->curr_thread].flags |=
					THREAD_FLAGS_FOREIGN_INTR_ENABLE;
		thread_set_exceptions(exceptions & ~THREAD_EXCP_FOREIGN_INTR);
	} else {
		/*
		 * No need to disable foreign interrupts here since they're
		 * already disabled above.
		 */
		threads[l->curr_thread].flags &=
					~THREAD_FLAGS_FOREIGN_INTR_ENABLE;
	}
}

void thread_restore_foreign_intr(void)
{
	/* thread_get_core_local() requires foreign interrupts to be disabled */
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	struct thread_core_local *l;

	l = thread_get_core_local();

	assert(l->curr_thread != THREAD_ID_INVALID);

	if (threads[l->curr_thread].flags & THREAD_FLAGS_FOREIGN_INTR_ENABLE)
		thread_set_exceptions(exceptions & ~THREAD_EXCP_FOREIGN_INTR);
}

static void set_ctx_regs(struct thread_ctx_regs *regs, unsigned long a0,
			 unsigned long a1, unsigned long a2, unsigned long a3,
			 unsigned long user_sp, unsigned long entry_func,
			 uint32_t client)
{
	/*
	 * First clear all registers to avoid leaking information from
	 * other TAs or even the Core itself.
	 */
	*regs = (struct thread_ctx_regs){ };
	regs->r10 = a0;
	regs->r11 = a1;
	regs->r12 = a2;
	regs->r13 = a3;
	regs->r14 = user_sp;
	regs->r15 = client;
	regs->rip = entry_func;
}

uint32_t thread_enter_user_mode(unsigned long a0, unsigned long a1,
		unsigned long a2, unsigned long a3, unsigned long user_sp,
		unsigned long entry_func, uint32_t client,
		uint32_t *exit_status0, uint32_t *exit_status1)
{
	uint32_t exceptions = 0;
	uint32_t rc = 0;
	struct thread_ctx_regs *regs = NULL;

	tee_ta_update_session_utime_resume();

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	/*
	 * We're using the per thread location of saved context registers
	 * for temporary storage. Now that exceptions are masked they will
	 * not be used for any thing else until they are eventually
	 * unmasked when user mode has been entered.
	 */
	regs = thread_get_ctx_regs();
	set_ctx_regs(regs, a0, a1, a2, a3, user_sp, entry_func, client);

	rc = __thread_enter_user_mode(regs, exit_status0, exit_status1);
	thread_unmask_exceptions(exceptions);
	return rc;
}


/*
 * Provides addresses and size of kernel code that must be mapped while in
 * user mode.
 */
void thread_get_user_kcode(struct mobj **mobj, size_t *offset,
					 vaddr_t *va, size_t *sz)
{
	*mobj = mobj_tee_ram;
	*offset = 0;
	core_mmu_get_user_va_range(va, NULL);
	// TODO: hard code size temporarily to align with ARM.
	*sz = 0x8000;
}

/*
 * Provides addresses and size of kernel (rw) data that must be mapped
 * while in user mode.
 */
void thread_get_user_kdata(struct mobj **mobj, size_t *offset,
					 vaddr_t *va, size_t *sz)
{
	*mobj = mobj_tee_ram;
	*offset = 0;
	core_mmu_get_user_va_range(va, NULL);
	 // TODO: hard code size temporarily to align with ARM.
	*sz = 0x8000;
	*va = *va + *sz;
}

static void gprof_set_status(struct ts_session *s __maybe_unused,
			     enum ts_gprof_status status __maybe_unused)
{
#ifdef CFG_TA_GPROF_SUPPORT
	if (s->ctx->ops->gprof_set_status)
		s->ctx->ops->gprof_set_status(status);
#endif
}

static struct mobj *alloc_shm(enum thread_shm_type shm_type, size_t size)
{
	switch (shm_type) {
	case THREAD_SHM_TYPE_APPLICATION:
		return thread_rpc_alloc_payload(size);
	case THREAD_SHM_TYPE_KERNEL_PRIVATE:
		return thread_rpc_alloc_kernel_payload(size);
	case THREAD_SHM_TYPE_GLOBAL:
		return thread_rpc_alloc_global_payload(size);
	default:
		return NULL;
	}
}

static void clear_shm_cache_entry(struct thread_shm_cache_entry *ce)
{
	if (ce->mobj) {
		switch (ce->type) {
		case THREAD_SHM_TYPE_APPLICATION:
			thread_rpc_free_payload(ce->mobj);
			break;
		case THREAD_SHM_TYPE_KERNEL_PRIVATE:
			thread_rpc_free_kernel_payload(ce->mobj);
			break;
		case THREAD_SHM_TYPE_GLOBAL:
			thread_rpc_free_global_payload(ce->mobj);
			break;
		default:
			assert(0); /* "can't happen" */
			break;
		}
	}
	ce->mobj = NULL;
	ce->size = 0;
}

static struct thread_shm_cache_entry *
get_shm_cache_entry(enum thread_shm_cache_user user)
{
	struct thread_shm_cache *cache = &threads[thread_get_id()].shm_cache;
	struct thread_shm_cache_entry *ce = NULL;

	SLIST_FOREACH(ce, cache, link)
		if (ce->user == user)
			return ce;

	ce = calloc(1, sizeof(*ce));
	if (ce) {
		ce->user = user;
		SLIST_INSERT_HEAD(cache, ce, link);
	}

	return ce;
}

void *thread_rpc_shm_cache_alloc(enum thread_shm_cache_user user,
				 enum thread_shm_type shm_type,
				 size_t size, struct mobj **mobj)
{
	struct thread_shm_cache_entry *ce = NULL;
	size_t sz = size;
	paddr_t p = 0;
	void *va = NULL;

	if (!size)
		return NULL;

	ce = get_shm_cache_entry(user);
	if (!ce)
		return NULL;

	/*
	 * Always allocate in page chunks as normal world allocates payload
	 * memory as complete pages.
	 */
	sz = ROUNDUP(size, SMALL_PAGE_SIZE);

	if (ce->type != shm_type || sz > ce->size) {
		clear_shm_cache_entry(ce);

		ce->mobj = alloc_shm(shm_type, sz);
		if (!ce->mobj)
			return NULL;

		if (mobj_get_pa(ce->mobj, 0, 0, &p))
			goto err;

		if (!ALIGNMENT_IS_OK(p, uint64_t))
			goto err;

		va = mobj_get_va(ce->mobj, 0);
		if (!va)
			goto err;

		ce->size = sz;
		ce->type = shm_type;
	} else {
		va = mobj_get_va(ce->mobj, 0);
		if (!va)
			goto err;
	}
	*mobj = ce->mobj;

	return va;
err:
	clear_shm_cache_entry(ce);
	return NULL;
}

void thread_rpc_shm_cache_clear(struct thread_shm_cache *cache)
{
	while (true) {
		struct thread_shm_cache_entry *ce = SLIST_FIRST(cache);

		if (!ce)
			break;
		SLIST_REMOVE_HEAD(cache, link);
		clear_shm_cache_entry(ce);
		free(ce);
	}
}
