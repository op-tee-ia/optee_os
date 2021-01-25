// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Intel Corporation
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <kernel/trace_control_by_service.h>
#ifndef TRACE_SERV_THREAD
#undef TRACE_LEVEL
#define TRACE_LEVEL 0
#endif

#include <platform_config.h>
#include <x86.h>
#include <descriptor.h>
#include <assert.h>
#include <keep.h>
#include <kernel/asan.h>
#include <kernel/lockdep.h>
#include <kernel/misc.h>
#include <kernel/msg_param.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread_defs.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <mm/mobj.h>
#include <mm/tee_mm.h>
#include <mm/tee_mmu.h>
#include <mm/tee_pager.h>
#include <optee_msg.h>
#include <optee_rpc_cmd.h>
#include <sm/optee_smc.h>
#include <sm/vmcall.h>
#include <tee/tee_fs_rpc.h>
#include <tee/tee_cryp_utl.h>
#include <tee/arch_svc.h>
#include <drivers/apic.h>
#include <trace.h>
#include <util.h>
#include <console.h>

#include "thread_private.h"

#define STACK_TMP_OFFS		64

#define STACK_TMP_SIZE		(2048 + STACK_TMP_OFFS)
#define STACK_THREAD_SIZE	8192

#if TRACE_LEVEL > 0
#define STACK_ABT_SIZE		3072
#else
#define STACK_ABT_SIZE		1024
#endif

struct thread_ctx threads[CFG_NUM_THREADS];

struct thread_core_local thread_core_local[CFG_TEE_CORE_NB_CORE] __nex_bss;

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

#define DECLARE_STACK(name, num_stacks, stack_size, linkage) \
linkage uint32_t name[num_stacks] \
		[ROUNDUP(stack_size + STACK_CANARY_SIZE, STACK_ALIGNMENT) / \
		sizeof(uint32_t)] \
		__attribute__((section(".nozi_stack." # name), \
			       aligned(STACK_ALIGNMENT)))

#define STACK_SIZE(stack) (sizeof(stack) - STACK_CANARY_SIZE / 2)

#define GET_STACK(stack) \
	((vaddr_t)(stack) + STACK_SIZE(stack))

DECLARE_STACK(stack_tmp, CFG_TEE_CORE_NB_CORE, STACK_TMP_SIZE, static);
DECLARE_STACK(stack_abt, CFG_TEE_CORE_NB_CORE, STACK_ABT_SIZE, static);
#ifndef CFG_WITH_PAGER
DECLARE_STACK(stack_thread, CFG_NUM_THREADS, STACK_THREAD_SIZE, static);
#endif

const void *stack_tmp_export = (uint8_t *)stack_tmp + sizeof(stack_tmp[0]) -
			       (STACK_TMP_OFFS + STACK_CANARY_SIZE / 2);
const uint32_t stack_tmp_stride = sizeof(stack_tmp[0]);

/*
 * These stack setup info are required by secondary boot cores before they
 * each locally enable the pager (the mmu). Hence kept in pager sections.
 */
KEEP_PAGER(stack_tmp_export);
KEEP_PAGER(stack_tmp_stride);

thread_smc_handler_t thread_std_smc_handler_ptr __nex_bss;
static thread_smc_handler_t thread_fast_smc_handler_ptr __nex_bss;
thread_nintr_handler_t thread_nintr_handler_ptr __nex_bss;
thread_pm_handler_t thread_cpu_on_handler_ptr __nex_bss;
thread_pm_handler_t thread_cpu_off_handler_ptr __nex_bss;
thread_pm_handler_t thread_cpu_suspend_handler_ptr __nex_bss;
thread_pm_handler_t thread_cpu_resume_handler_ptr __nex_bss;
thread_pm_handler_t thread_system_off_handler_ptr __nex_bss;
thread_pm_handler_t thread_system_reset_handler_ptr __nex_bss;


static unsigned int thread_global_lock __nex_bss = SPINLOCK_UNLOCK;
static bool thread_prealloc_rpc_cache;

static unsigned int thread_rpc_pnum;

uint32_t is_optee_boot_complete = 0;

static void syscall_init(vaddr_t sp)
{
	write_msr(SYSENTER_CS_MSR, CODE_64_SELECTOR); /* cs_addr */
	write_msr(SYSENTER_ESP_MSR, sp); /* esp_addr */
	write_msr(SYSENTER_EIP_MSR, (uint64_t)(x86_syscall)); /* eip_addr */
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
		DMSG("#Stack canaries for %s[%zu] with top at %p\n",	\
			#name, n, (void *)(end_canary - 1));		\
		DMSG("watch *%p\n", (void *)end_canary);		\
	}

	INIT_CANARY(stack_tmp);
	INIT_CANARY(stack_abt);
#ifndef CFG_WITH_PAGER
	INIT_CANARY(stack_thread);
#endif
#endif/*CFG_WITH_STACK_CANARIES*/
}

#define CANARY_DIED(stack, loc, n) \
	do { \
		EMSG_RAW("Dead canary at %s of '%s[%zu]'", #loc, #stack, n); \
		panic(); \
	} while (0)

void thread_check_canaries(void)
{
#ifdef CFG_WITH_STACK_CANARIES
	size_t n;

	for (n = 0; n < ARRAY_SIZE(stack_tmp); n++) {
		if (GET_START_CANARY(stack_tmp, n) != START_CANARY_VALUE)
			CANARY_DIED(stack_tmp, start, n);
		if (GET_END_CANARY(stack_tmp, n) != END_CANARY_VALUE)
			CANARY_DIED(stack_tmp, end, n);
	}

	for (n = 0; n < ARRAY_SIZE(stack_abt); n++) {
		if (GET_START_CANARY(stack_abt, n) != START_CANARY_VALUE)
			CANARY_DIED(stack_abt, start, n);
		if (GET_END_CANARY(stack_abt, n) != END_CANARY_VALUE)
			CANARY_DIED(stack_abt, end, n);

	}
#ifndef CFG_WITH_PAGER
	for (n = 0; n < ARRAY_SIZE(stack_thread); n++) {
		if (GET_START_CANARY(stack_thread, n) != START_CANARY_VALUE)
			CANARY_DIED(stack_thread, start, n);
		if (GET_END_CANARY(stack_thread, n) != END_CANARY_VALUE)
			CANARY_DIED(stack_thread, end, n);
	}
#endif
#endif/*CFG_WITH_STACK_CANARIES*/
}

static void lock_global(void)
{
	cpu_spin_lock(&thread_global_lock);
}

static void unlock_global(void)
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

void thread_set_exceptions(uint32_t exceptions)
{
	uint64_t rflags = x86_save_flags();

	/* Foreign interrupts must not be unmasked while holding a spinlock */
	if (!(exceptions & THREAD_EXCP_FOREIGN_INTR))
		assert_have_no_spinlock();

	rflags &= ~THREAD_EXCP_ALL;
	rflags |= (~exceptions & THREAD_EXCP_ALL);

	x86_restore_flags(rflags);
}

uint32_t thread_mask_exceptions(uint32_t exceptions)
{
	uint32_t state = thread_get_exceptions();

	thread_set_exceptions(state | (exceptions & THREAD_EXCP_ALL));
	return state;
}

void thread_unmask_exceptions(uint32_t state)
{
	thread_set_exceptions(state & THREAD_EXCP_ALL);
}


struct thread_core_local *thread_get_core_local(void)
{
	uint32_t cpu_id = get_core_pos();

	/*
	 * Foreign interrupts must be disabled before playing with core_local
	 * since we otherwise may be rescheduled to a different core in the
	 * middle of this function.
	 */
	assert(thread_get_exceptions() & THREAD_EXCP_FOREIGN_INTR);

	assert(cpu_id < CFG_TEE_CORE_NB_CORE);
	return &thread_core_local[cpu_id];
}

static void init_regs(struct thread_ctx *thread,
		struct thread_smc_args *args)
{
	struct thread_ctx86_regs *regs;

	thread->stack_va_curr[0] = thread->stack_va_start -
		sizeof(struct thread_ctx86_regs);
	thread->stack_va_curr[0] = ROUNDDOWN(thread->stack_va_curr[0], 64);
	regs = (struct thread_ctx86_regs *)(thread->stack_va_curr[0]);

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
	size_t n;

	mutex_lockdep_init();

	for (n = 0; n < CFG_NUM_THREADS; n++) {
		TAILQ_INIT(&threads[n].tsd.sess_stack);
		SLIST_INIT(&threads[n].tsd.pgt_cache);
	}

	for (n = 0; n < CFG_TEE_CORE_NB_CORE; n++)
		thread_core_local[n].curr_thread = -1;

	l->curr_thread = 0;
	threads[0].state = THREAD_STATE_ACTIVE;
}

void thread_clr_boot_thread(void)
{
	struct thread_core_local *l = thread_get_core_local();

	assert(l->curr_thread >= 0 && l->curr_thread < CFG_NUM_THREADS);
	assert(threads[l->curr_thread].state == THREAD_STATE_ACTIVE);
	threads[l->curr_thread].state = THREAD_STATE_FREE;
	l->curr_thread = -1;
}

static void thread_alloc_and_run(struct thread_smc_args *args)
{
	size_t n;
	struct thread_core_local *l = thread_get_core_local();
	bool found_thread = false;

	assert(l->curr_thread == -1);

	lock_global();

	for (n = 0; n < CFG_NUM_THREADS; n++) {
		if (threads[n].state == THREAD_STATE_FREE) {
			threads[n].state = THREAD_STATE_ACTIVE;
			found_thread = true;
			break;
		}
	}

	unlock_global();

	if (!found_thread) {
		args->a0 = OPTEE_SMC_RETURN_ETHREAD_LIMIT;
		return;
	}

	l->curr_thread = n;

	threads[n].flags = 0;
	threads[n].ta_idx = 0;
	init_regs(threads + n, args);

	thread_resume((struct thread_ctx86_regs *)(threads[n].stack_va_curr[0]),
			l->tmp_stack_va_end);
}

static void thread_resume_from_rpc(struct thread_smc_args *args)
{
	size_t n = args->a3; /* thread id */
	struct thread_core_local *l = thread_get_core_local();
	uint32_t rv = 0;

	assert(l->curr_thread == -1);

	lock_global();

	if (n < CFG_NUM_THREADS &&
	    threads[n].state == THREAD_STATE_SUSPENDED) {
		threads[n].state = THREAD_STATE_ACTIVE;
	} else {
		rv = OPTEE_SMC_RETURN_ERESUME;
	}

	unlock_global();

	if (rv) {
		args->a0 = rv;
		return;
	}

	l->curr_thread = n;

	if (threads[n].flags & THREAD_FLAGS_COPY_ARGS_ON_RETURN) {
		if (threads[n].have_user_map) {
			struct thread_specific_data *tsd = thread_get_tsd();
			struct user_ta_ctx *utc = to_user_ta_ctx(tsd->ctx);

			tee_ta_update_session_utime_resume();
			core_mmu_create_user_map(utc, &threads[n].user_map);
			core_mmu_set_user_map(&threads[n].user_map);
		}

		threads[n].flags &= ~THREAD_FLAGS_COPY_ARGS_ON_RETURN;
		assert(threads[n].ta_idx < MAX_TA_IDX);
		thread_rpc_resume(threads[n].stack_va_curr[threads[n].ta_idx],
				args, l->tmp_stack_va_end);
	} else if (threads[n].flags & THREAD_FLAGS_EXIT_ON_FOREIGN_INTR) {
		threads[n].flags &= ~THREAD_FLAGS_EXIT_ON_FOREIGN_INTR;
		foreign_intr_resume(l->abt_stack_va_end, l->tmp_stack_va_end);
	} else {
		args->a0 = OPTEE_SMC_RETURN_ERESUME;
		return;
	}
}

void thread_handle_fast_smc(struct thread_smc_args *args)
{
	thread_check_canaries();
	thread_fast_smc_handler_ptr(args);
	/* Fast handlers must not unmask any exceptions */
	assert(thread_get_exceptions() == THREAD_EXCP_ALL);
}

void thread_handle_std_smc(struct thread_smc_args *args)
{
	thread_check_canaries();

	if (args->a0 == OPTEE_SMC_CALL_RETURN_FROM_RPC)
		thread_resume_from_rpc(args);
	else
		thread_alloc_and_run(args);

	if (args->a0 == OPTEE_SMC_RETURN_ETHREAD_LIMIT) {
		IMSG("return due to thread limit\n");
		return;
	}

	if (args->a0 == OPTEE_SMC_RETURN_ERESUME) {
		IMSG("return due to resume error\n");
		return;
	}

	thread_get_stdcall_ret(args);
}

/**
 * Free physical memory previously allocated with thread_rpc_alloc_arg()
 *
 * @cookie:	cookie received when allocating the buffer
 */
static void thread_rpc_free_arg(uint64_t cookie)
{
	if (cookie) {
		uint32_t rpc_args[THREAD_RPC_NUM_ARGS] = {
			OPTEE_SMC_RETURN_RPC_FREE
		};

		reg_pair_from_64(cookie, rpc_args + 1, rpc_args + 2);
		thread_rpc(rpc_args);
	}
}

/*
 * Helper routine for the assembly function thread_std_smc_entry()
 *
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
void __weak __thread_std_smc_entry(struct thread_smc_args *args)
{
	thread_std_smc_handler_ptr(args);

	if (args->a0 == OPTEE_SMC_RETURN_OK) {
		struct thread_ctx *thr = threads + thread_get_id();

		tee_fs_rpc_cache_clear(&thr->tsd);
		if (!thread_prealloc_rpc_cache) {
			thread_rpc_free_arg(mobj_get_cookie(thr->rpc_mobj));
			mobj_free(thr->rpc_mobj);
			thr->rpc_arg = 0;
			thr->rpc_mobj = NULL;
		}
	}
}

void *thread_get_tmp_sp(void)
{
	struct thread_core_local *l = thread_get_core_local();

	return (void *)l->tmp_stack_va_end;
}

vaddr_t thread_get_saved_thread_sp(void)
{
	struct thread_core_local *l = thread_get_core_local();
	int ct = l->curr_thread;

	assert(ct != -1);
	return threads[ct].kern_sp;
}

vaddr_t thread_stack_start(void)
{
	struct thread_ctx *thr;
	int ct = thread_get_id_may_fail();

	if (ct == -1)
		return 0;

	thr = threads + ct;
	return thr->stack_va_start;
}

size_t thread_stack_size(void)
{
	return STACK_THREAD_SIZE;
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

	assert(ct != -1);

	lock_global();

	assert(threads[ct].state == THREAD_STATE_ACTIVE);
	threads[ct].state = THREAD_STATE_FREE;
	threads[ct].flags = 0;
	l->curr_thread = -1;

	unlock_global();
}

#ifdef CFG_WITH_PAGER
static void release_unused_kernel_stack(struct thread_ctx *thr,
					uint32_t cpsr __maybe_unused)
{
	/*
	 * If we're from user mode then thr->regs.sp is the saved user
	 * stack pointer and thr->kern_sp holds the last kernel stack
	 * pointer. But if we're from kernel mode then thr->kern_sp isn't
	 * up to date so we need to read from thr->regs.sp instead.
	 */
	vaddr_t sp = is_from_user(cpsr) ?  thr->kern_sp : thr->regs.sp;
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

	assert(ct != -1);

	thread_check_canaries();

	release_unused_kernel_stack(threads + ct, 0);

	lock_global();

	assert(threads[ct].state == THREAD_STATE_ACTIVE);
	threads[ct].flags |= flags;

	if (flags & THREAD_FLAGS_EXIT_ON_FOREIGN_INTR) {
		l->abt_stack_va_end = sp;
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

	l->curr_thread = -1;

	unlock_global();

	return ct;
}

void thread_state_save(vaddr_t sp, uint32_t client)
{
	struct thread_core_local *l = thread_get_core_local();
	int ct = l->curr_thread;

	assert(ct != -1);

	lock_global();

	assert(threads[ct].state == THREAD_STATE_ACTIVE);

	if (client == TEE_LOGIN_TRUSTED_APP) {
		threads[ct].ta_idx++;
		assert(threads[ct].ta_idx < MAX_TA_IDX+1);
		threads[ct].stack_va_curr[threads[ct].ta_idx-1] = sp;
	} else {
		threads[ct].ta_idx = 1;
		threads[ct].stack_va_curr[0] = sp;
	}

	syscall_init(sp - 64);

	unlock_global();
}

vaddr_t thread_state_restore(void)
{
	struct thread_core_local *l = thread_get_core_local();
	int ct = l->curr_thread;

	assert(ct != -1);

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

static void set_abt_stack(struct thread_core_local *l, vaddr_t sp)
{
	l->abt_stack_va_end = sp;
}

bool thread_init_stack(uint32_t thread_id, vaddr_t sp)
{
	if (thread_id >= CFG_NUM_THREADS)
		return false;
	threads[thread_id].stack_va_start = sp;
	return true;
}

int thread_get_id_may_fail(void)
{
	/*
	 * thread_get_core_local() requires foreign interrupts to be disabled
	 */
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	struct thread_core_local *l = thread_get_core_local();
	int ct = l->curr_thread;

	thread_unmask_exceptions(exceptions);
	return ct;
}

int thread_get_id(void)
{
	int ct = thread_get_id_may_fail();

	assert(ct >= 0 && ct < CFG_NUM_THREADS);
	return ct;
}

static void init_handlers(const struct thread_handlers *handlers)
{
	thread_std_smc_handler_ptr = handlers->std_smc;
	thread_fast_smc_handler_ptr = handlers->fast_smc;
	thread_nintr_handler_ptr = handlers->nintr;
	thread_cpu_on_handler_ptr = handlers->cpu_on;
	thread_cpu_off_handler_ptr = handlers->cpu_off;
	thread_cpu_suspend_handler_ptr = handlers->cpu_suspend;
	thread_cpu_resume_handler_ptr = handlers->cpu_resume;
	thread_system_off_handler_ptr = handlers->system_off;
	thread_system_reset_handler_ptr = handlers->system_reset;
}

#ifdef CFG_WITH_PAGER
static void init_thread_stacks(void)
{
	size_t n;

	/*
	 * Allocate virtual memory for thread stacks.
	 */
	for (n = 0; n < CFG_NUM_THREADS; n++) {
		tee_mm_entry_t *mm;
		vaddr_t sp;

		/* Find vmem for thread stack and its protection gap */
		mm = tee_mm_alloc(&tee_mm_vcore,
				  SMALL_PAGE_SIZE + STACK_THREAD_SIZE);
		assert(mm);

		/* Claim eventual physical page */
		tee_pager_add_pages(tee_mm_get_smem(mm), tee_mm_get_size(mm),
				    true);

		/* Add the area to the pager */
		tee_pager_add_core_area(tee_mm_get_smem(mm) + SMALL_PAGE_SIZE,
					tee_mm_get_bytes(mm) - SMALL_PAGE_SIZE,
					TEE_MATTR_PRW | TEE_MATTR_LOCKED,
					NULL, NULL);

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
		if (!thread_init_stack(n, GET_STACK(stack_thread[n])))
			panic("thread_init_stack failed");
	}
}
#endif /*CFG_WITH_PAGER*/

#ifdef HV_ACRN
void return_flags sm_sched_nonsecure(void)
{
	uint32_t smc_nr;
	struct thread_smc_args *args = (struct thread_smc_args *)parameters_nsec_shm_vaddr;

    memset(args, 0, sizeof(struct thread_smc_args));

return_sm_err:
    if (is_optee_boot_complete == 0) {
        restore_pic();
        x86_set_cr8(0);
        IMSG("return to nonsecure firstly, boot=%d, args=0x%lx, a0=0x%lx\n",
				is_optee_boot_complete, (vaddr_t)args, args->a0);
        make_smc_hypercall(HC_TEE_BOOT_DONE);
        is_optee_boot_complete = 1;
    } else {
        //args->a6 = 0xa5a5a5a5;
        make_smc_hypercall(HC_TEE_SERVICE_DONE);
    }

	smc_nr = args->a0;
	if (OPTEE_SMC_IS_64(smc_nr)) {/* 64bits */
		args->a0 = OPTEE_SMC_RETURN_ENOTAVAIL;
		goto return_sm_err;
	}

	if (OPTEE_SMC_IS_FAST_CALL(smc_nr))
		thread_handle_fast_smc(args);
	else
		thread_handle_std_smc(args);


	goto return_sm_err;
}
#else
void return_flags sm_sched_nonsecure(void)
{
	uint32_t smc_nr;
	struct thread_smc_args args = {0};

return_sm_err:
	if (is_optee_boot_complete == 0) {
		restore_pic();
		x86_set_cr8(0);
		is_optee_boot_complete = 1;
/*
 * Because current x86 QEMU environment doesn't support hypervisor yet,
 * here just return to halt instead of issue vmcall to boot up REE OS
 */
#ifdef PLATFORM_QEMU
		IMSG("Boot complete in QEMU.Execution halted\n");
		return;
#endif
		IMSG("return to nonsecure firstly, boot=%d, a0=0x%lx\n",
				is_optee_boot_complete, args.a0);
		console_init();
	}

	make_smc_vmcall(&args);
	is_optee_boot_complete = 1;

	smc_nr = args.a0;
	if (OPTEE_SMC_IS_64(smc_nr)) {/* 64bits */
		args.a0 = OPTEE_SMC_RETURN_ENOTAVAIL;
		goto return_sm_err;
	}

	if (OPTEE_SMC_IS_FAST_CALL(smc_nr))
		thread_handle_fast_smc(&args);
	else
		thread_handle_std_smc(&args);


	goto return_sm_err;
}
#endif

void thread_init_primary(const struct thread_handlers *handlers)
{
	init_handlers(handlers);

	/* Initialize canaries around the stacks */
	init_canaries();

	init_thread_stacks();
	pgt_init();

	//init_user_kcode();
}

/* main tss */
static tss_t system_tss;

static void init_tss(struct thread_core_local *l)
{
	memset(&system_tss, 0, sizeof(system_tss));

	system_tss.rsp0 = l->abt_stack_va_end;

	system_tss.ist1 = l->abt_stack_va_end;

	set_global_desc(TSS_SELECTOR, &system_tss, sizeof(system_tss),
			1, 0, 0, SEG_TYPE_TSS, 0, 0);

	x86_ltr(TSS_SELECTOR);
}

void thread_init_per_cpu(void)
{
	size_t pos = get_core_pos();
	struct thread_core_local *l = thread_get_core_local();

	set_tmp_stack(l, GET_STACK(stack_tmp[pos]) - STACK_TMP_OFFS);
	set_abt_stack(l, GET_STACK(stack_abt[pos]));

	init_tss(l);
}

struct thread_specific_data *thread_get_tsd(void)
{
	return &threads[thread_get_id()].tsd;
}

void thread_set_foreign_intr(bool enable)
{
	/* thread_get_core_local() requires foreign interrupts to be disabled */
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	struct thread_core_local *l;

	l = thread_get_core_local();

	assert(l->curr_thread != -1);

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

	assert(l->curr_thread != -1);

	if (threads[l->curr_thread].flags & THREAD_FLAGS_FOREIGN_INTR_ENABLE)
		thread_set_exceptions(exceptions & ~THREAD_EXCP_FOREIGN_INTR);
}

uint32_t thread_enter_user_mode(unsigned long a0, unsigned long a1,
		unsigned long a2, unsigned long a3, unsigned long user_sp,
		unsigned long entry_func, uint32_t client,
		uint32_t *exit_status0, uint32_t *exit_status1)
{
	struct tee_usr_args usr_args;

	usr_args.func = a0;
	usr_args.session_id = a1;
	usr_args.utee_params = a2;
	usr_args.cmd_id = a3;

	tee_ta_update_session_utime_resume();

#if 0
	if (!get_spsr(is_32bit, entry_func, &spsr)) {
		*exit_status0 = 1; /* panic */
		*exit_status1 = 0xbadbadba;
		return 0;
	}
#endif

	DMSG("usr_args.func 0x%lx\n", usr_args.func);
	DMSG("usr_args.session_id 0x%lx\n", usr_args.session_id);
	DMSG("usr_args.utee_params 0x%lx\n", usr_args.utee_params);
	DMSG("usr_args.cmd_id 0x%lx\n", usr_args.cmd_id);
	DMSG("user_sp 0x%lx\n", user_sp);
	DMSG("entry_func 0x%lx\n", entry_func);

	return __thread_enter_user_mode(&usr_args, user_sp, entry_func,
			exit_status0, exit_status1, client);
}


bool thread_disable_prealloc_rpc_cache(uint64_t *cookie)
{
	bool rv;
	size_t n;
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);

	lock_global();

	for (n = 0; n < CFG_NUM_THREADS; n++) {
		if (threads[n].state != THREAD_STATE_FREE) {
			rv = false;
			goto out;
		}
	}

	rv = true;
	for (n = 0; n < CFG_NUM_THREADS; n++) {
		if (threads[n].rpc_arg) {
			*cookie = mobj_get_cookie(threads[n].rpc_mobj);
			mobj_free(threads[n].rpc_mobj);
			threads[n].rpc_arg = NULL;
			goto out;
		}
	}

	*cookie = 0;
	thread_prealloc_rpc_cache = false;
out:
	unlock_global();
	thread_unmask_exceptions(exceptions);
	return rv;
}

bool thread_enable_prealloc_rpc_cache(void)
{
	bool rv;
	size_t n;
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);

	lock_global();

	for (n = 0; n < CFG_NUM_THREADS; n++) {
		if (threads[n].state != THREAD_STATE_FREE) {
			rv = false;
			goto out;
		}
	}

	rv = true;
	thread_prealloc_rpc_cache = true;
out:
	unlock_global();
	thread_unmask_exceptions(exceptions);
	return rv;
}

/**
 * Allocates data for struct optee_msg_arg.
 *
 * @size:	size in bytes of struct optee_msg_arg
 *
 * @returns	mobj that describes allocated buffer or NULL on error
 */
static struct mobj *thread_rpc_alloc_arg(size_t size)
{
	paddr_t pa;
	uint64_t co;
	uint32_t rpc_args[THREAD_RPC_NUM_ARGS] = {
		OPTEE_SMC_RETURN_RPC_ALLOC, size
	};
	struct mobj *mobj = NULL;

	thread_rpc(rpc_args);

	pa = reg_pair_to_64(rpc_args[1], rpc_args[2]);
	co = reg_pair_to_64(rpc_args[4], rpc_args[5]);

	if (!ALIGNMENT_IS_OK(pa, struct optee_msg_arg))
		goto err;

	/* Check if this region is in static shared space */
	if (core_pbuf_is(CORE_MEM_NSEC_SHM, pa, size))
		mobj = mobj_shm_alloc(pa, size, co);
	else if ((!(pa & SMALL_PAGE_MASK)) && size <= SMALL_PAGE_SIZE)
		mobj = mobj_mapped_shm_alloc(&pa, 1, 0, co);

	if (!mobj)
		goto err;

	return mobj;
err:
	thread_rpc_free_arg(co);
	mobj_free(mobj);
	return NULL;
}

static bool set_rmem(struct optee_msg_param *param,
				struct thread_param *tpm)
{
	param->attr = tpm->attr - THREAD_PARAM_ATTR_MEMREF_IN +
				OPTEE_MSG_ATTR_TYPE_RMEM_INPUT;
	param->u.rmem.offs = tpm->u.memref.offs;
	param->u.rmem.size = tpm->u.memref.size;
	if (tpm->u.memref.mobj) {
		param->u.rmem.shm_ref = mobj_get_cookie(tpm->u.memref.mobj);
		if (!param->u.rmem.shm_ref)
			return false;
	} else {
		param->u.rmem.shm_ref = 0;
	}

	return true;
}

static bool set_tmem(struct optee_msg_param *param,
				struct thread_param *tpm)
{
	paddr_t pa = 0;
	uint64_t shm_ref = 0;
	struct mobj *mobj = tpm->u.memref.mobj;

	param->attr = tpm->attr - THREAD_PARAM_ATTR_MEMREF_IN +
				OPTEE_MSG_ATTR_TYPE_TMEM_INPUT;
	if (mobj) {
		shm_ref = mobj_get_cookie(mobj);
		if (!shm_ref)
			return false;
		if (mobj_get_pa(mobj, tpm->u.memref.offs, 0, &pa))
			return false;
	}

	param->u.tmem.size = tpm->u.memref.size;
	param->u.tmem.buf_ptr = pa;
	param->u.tmem.shm_ref = shm_ref;

	return true;
}

static bool get_rpc_arg(uint32_t cmd, size_t num_params,
			struct thread_param *params, void **arg_ret,
			uint64_t *carg_ret)
{
	struct thread_ctx *thr = threads + thread_get_id();
	struct optee_msg_arg *arg = thr->rpc_arg;
	size_t sz = OPTEE_MSG_GET_ARG_SIZE(THREAD_RPC_MAX_NUM_PARAMS);

	if (num_params > THREAD_RPC_MAX_NUM_PARAMS)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!arg) {
		struct mobj *mobj = thread_rpc_alloc_arg(sz);

		if (!mobj)
			return TEE_ERROR_OUT_OF_MEMORY;

		arg = mobj_get_va(mobj, 0);
		if (!arg) {
			thread_rpc_free_arg(mobj_get_cookie(mobj));
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		thr->rpc_arg = arg;
		thr->rpc_mobj = mobj;
	}

	memset(arg, 0, OPTEE_MSG_GET_ARG_SIZE(num_params));
	arg->cmd = cmd;
	arg->num_params = num_params;
	arg->ret = TEE_ERROR_GENERIC; /* in case value isn't updated */

	for (size_t n = 0; n < num_params; n++) {
		switch (params[n].attr) {
		case THREAD_PARAM_ATTR_NONE:
			arg->params[n].attr = OPTEE_MSG_ATTR_TYPE_NONE;
			break;
		case THREAD_PARAM_ATTR_VALUE_IN:
		case THREAD_PARAM_ATTR_VALUE_OUT:
		case THREAD_PARAM_ATTR_VALUE_INOUT:
			arg->params[n].attr = params[n].attr -
						THREAD_PARAM_ATTR_VALUE_IN +
						OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
			arg->params[n].u.value.a = params[n].u.value.a;
			arg->params[n].u.value.b = params[n].u.value.b;
			arg->params[n].u.value.c = params[n].u.value.c;
			break;
		case THREAD_PARAM_ATTR_MEMREF_IN:
		case THREAD_PARAM_ATTR_MEMREF_OUT:
		case THREAD_PARAM_ATTR_MEMREF_INOUT:
			if (!params[n].u.memref.mobj ||
				mobj_matches(params[n].u.memref.mobj,
					CORE_MEM_NSEC_SHM)) {
				if (!set_tmem(arg->params + n, params + n))
					return TEE_ERROR_BAD_PARAMETERS;
			} else  if (mobj_matches(params[n].u.memref.mobj,
						CORE_MEM_REG_SHM)) {
				if (!set_rmem(arg->params + n, params + n))
					return TEE_ERROR_BAD_PARAMETERS;
			} else {
				return TEE_ERROR_BAD_PARAMETERS;
			}
			break;
		default:
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	*arg_ret = arg;
	*carg_ret = mobj_get_cookie(thr->rpc_mobj);

	return TEE_SUCCESS;
}

static uint32_t get_rpc_arg_res(struct optee_msg_arg *arg, size_t num_params,
				struct thread_param *params)
{
	for (size_t n = 0; n < num_params; n++) {
		switch (params[n].attr) {
		case THREAD_PARAM_ATTR_VALUE_OUT:
		case THREAD_PARAM_ATTR_VALUE_INOUT:
			params[n].u.value.a = arg->params[n].u.value.a;
			params[n].u.value.b = arg->params[n].u.value.b;
			params[n].u.value.c = arg->params[n].u.value.c;
			break;
		case THREAD_PARAM_ATTR_MEMREF_OUT:
		case THREAD_PARAM_ATTR_MEMREF_INOUT:
		   /*
			* rmem.size and tmem.size is the same type and
			* location.
			*/
			params[n].u.memref.size = arg->params[n].u.rmem.size;
			break;
		default:
			break;
		}
	}

	return arg->ret;
}

uint32_t thread_rpc_cmd(uint32_t cmd, size_t num_params,
			struct thread_param *params)
{
	uint32_t rpc_args[THREAD_RPC_NUM_ARGS] = { OPTEE_SMC_RETURN_RPC_CMD };
	void *arg = NULL;
	uint64_t carg = 0;
	uint32_t ret = 0;

	/* The source CRYPTO_RNG_SRC_JITTER_RPC is safe to use here */
	plat_prng_add_jitter_entropy(CRYPTO_RNG_SRC_JITTER_RPC,
				     &thread_rpc_pnum);

	ret = get_rpc_arg(cmd, num_params, params, &arg, &carg);
	if (ret)
		return ret;

	reg_pair_from_64(carg, rpc_args + 1, rpc_args + 2);
	thread_rpc(rpc_args);

	return get_rpc_arg_res(arg, num_params, params);
}

/**
 * Free physical memory previously allocated with thread_rpc_alloc()
 *
 * @cookie:	cookie received when allocating the buffer
 * @bt:		must be the same as supplied when allocating
 * @mobj:	mobj that describes allocated buffer
 *
 * This function also frees corresponding mobj.
 */
static void thread_rpc_free(unsigned int bt, uint64_t cookie, struct mobj *mobj)
{
	uint32_t rpc_args[THREAD_RPC_NUM_ARGS] = { OPTEE_SMC_RETURN_RPC_CMD };
	void *arg = NULL;
	uint64_t carg = 0;
	struct thread_param param = THREAD_PARAM_VALUE(IN, bt, cookie, 0);
	uint32_t ret = get_rpc_arg(OPTEE_RPC_CMD_SHM_FREE, 1, &param,
					&arg, &carg);

	mobj_free(mobj);

	if (!ret) {
		reg_pair_from_64(carg, rpc_args + 1, rpc_args + 2);
		thread_rpc(rpc_args);
	}
}

static struct mobj *get_rpc_alloc_res(struct optee_msg_arg *arg,
						unsigned int bt)
{
	struct mobj *mobj = NULL;
	uint64_t cookie = 0;

	if (arg->ret || arg->num_params != 1)
		return NULL;

	if (arg->params[0].attr == OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT) {
		cookie = arg->params[0].u.tmem.shm_ref;
		mobj = mobj_shm_alloc(arg->params[0].u.tmem.buf_ptr,
				      arg->params[0].u.tmem.size,
				      cookie);
	} else if (arg->params[0].attr == (OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT |
					   OPTEE_MSG_ATTR_NONCONTIG)) {
		cookie = arg->params[0].u.tmem.shm_ref;
		mobj = msg_param_mobj_from_noncontig(
			arg->params[0].u.tmem.buf_ptr,
			arg->params[0].u.tmem.size,
			cookie,
			true);
	} else {
		return NULL;
	}

	if (!mobj) {
		thread_rpc_free(bt, cookie, mobj);
		return NULL;
	}

	assert(mobj_is_nonsec(mobj));

	return mobj;
}

/**
 * Allocates shared memory buffer via RPC
 *
 * @size:   size in bytes of shared memory buffer
 * @align:  required alignment of buffer
 * @bt:     buffer type OPTEE_RPC_SHM_TYPE_*
 *
 * Returns a pointer to MOBJ for the memory on success, or NULL on failure.
 */
static struct mobj *thread_rpc_alloc(size_t size, size_t align, unsigned int bt)
{
	uint32_t rpc_args[THREAD_RPC_NUM_ARGS] = { OPTEE_SMC_RETURN_RPC_CMD };
	void *arg = NULL;
	uint64_t carg = 0;
	struct thread_param param = THREAD_PARAM_VALUE(IN, bt, size, align);
	uint32_t ret = get_rpc_arg(OPTEE_RPC_CMD_SHM_ALLOC, 1, &param,
					&arg, &carg);

	if (ret)
		return NULL;

	reg_pair_from_64(carg, rpc_args + 1, rpc_args + 2);
	thread_rpc(rpc_args);

	return get_rpc_alloc_res(arg, bt);
}

struct mobj *thread_rpc_alloc_payload(size_t size)
{
	return thread_rpc_alloc(size, 8, OPTEE_RPC_SHM_TYPE_APPL);
}

void thread_rpc_free_payload(struct mobj *mobj)
{
	thread_rpc_free(OPTEE_RPC_SHM_TYPE_APPL, mobj_get_cookie(mobj),
			mobj);
}

struct mobj *thread_rpc_alloc_global_payload(size_t size)
{
	return thread_rpc_alloc(size, 8, OPTEE_RPC_SHM_TYPE_GLOBAL);
}

void thread_rpc_free_global_payload(struct mobj *mobj)
{
	thread_rpc_free(OPTEE_RPC_SHM_TYPE_GLOBAL, mobj_get_cookie(mobj),
			mobj);
}
