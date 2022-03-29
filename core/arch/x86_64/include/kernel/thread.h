/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2016-2017, Linaro Limited
 * Copyright (c) 2020-2021, Arm Limited
 * Copyright (c) 2018-2021, Intel Corporation
 */

#ifndef KERNEL_THREAD_H
#define KERNEL_THREAD_H

#ifndef __ASSEMBLER__
#include <types_ext.h>
#include <compiler.h>
#include <kernel/mutex.h>
#include <mm/pgt_cache.h>
#endif

#define THREAD_ID_0		0
#define THREAD_ID_INVALID	-1

#define THREAD_RPC_MAX_NUM_PARAMS	4

#ifndef __ASSEMBLER__

/*
 * struct thread_core_local needs to have alignment suitable for a stack
 * pointer since SP_EL1 points to this
 */
#define THREAD_CORE_LOCAL_ALIGNED __aligned(16)

struct thread_core_local {
	uint64_t x[4];
	vaddr_t tmp_stack_va_end;
	short int curr_thread;
	uint32_t flags;
#ifdef CFG_TEE_CORE_DEBUG
	unsigned int locked_count; /* Number of spinlocks held */
#endif
#ifdef CFG_CORE_DEBUG_CHECK_STACKS
	bool stackcheck_recursion;
#endif
} THREAD_CORE_LOCAL_ALIGNED;

struct thread_smc_args {
	uint64_t a0;	/* SMC function ID */
	uint64_t a1;	/* Parameter */
	uint64_t a2;	/* Parameter */
	uint64_t a3;	/* Thread ID when returning from RPC */
	uint64_t a4;	/* Not used */
	uint64_t a5;	/* Not used */
	uint64_t a6;	/* Not used */
	uint64_t a7;	/* Hypervisor Client ID */
};

struct thread_ctx_regs {
	uint64_t rip;
	uint64_t rsp_kern;
	uint64_t rsp_usr;
	uint64_t rdi;
	uint64_t rsi;
	uint64_t rdx;
	uint64_t rcx;
};

struct thread_specific_data {
	TAILQ_HEAD(, ts_session) sess_stack;
	struct ts_ctx *ctx;
	struct pgt_cache pgt_cache;
#ifdef CFG_CORE_DEBUG_CHECK_STACKS
	bool stackcheck_recursion;
#endif
	unsigned int syscall_recursion;
};

struct user_mode_ctx;

void thread_init_primary(void);
void thread_init_per_cpu(void);

struct thread_core_local *thread_get_core_local(void);

/*
 * Sets the stacks to be used by the different threads. Use THREAD_ID_0 for
 * first stack, THREAD_ID_0 + 1 for the next and so on.
 *
 * Returns true on success and false on errors.
 */
bool thread_init_stack(uint32_t stack_id, vaddr_t sp);

/*
 * Initializes thread contexts. Called in thread_init_boot_thread() if
 * virtualization is disabled. Virtualization subsystem calls it for
 * every new guest otherwise.
 */
void thread_init_threads(void);

/*
 * Called by the init CPU. Sets temporary stack mode for all CPUs
 * (curr_thread = -1 and THREAD_CLF_TMP) and sets the temporary stack limit for
 * the init CPU.
 */
void thread_init_thread_core_local(void);

/*
 * Initializes a thread to be used during boot
 */
void thread_init_boot_thread(void);

/*
 * Clears the current thread id
 * Only supposed to be used during initialization.
 */
void thread_clr_boot_thread(void);

/*
 * Returns current thread id.
 */
short int thread_get_id(void);

/*
 * Returns current thread id, return -1 on failure.
 */
short int thread_get_id_may_fail(void);

/* Returns Thread Specific Data (TSD) pointer. */
struct thread_specific_data *thread_get_tsd(void);

/*
 * Sets foreign interrupts status for current thread, must only be called
 * from an active thread context.
 *
 * enable == true  -> enable foreign interrupts
 * enable == false -> disable foreign interrupts
 */
void thread_set_foreign_intr(bool enable);

/*
 * Restores the foreign interrupts status (in CPSR) for current thread, must
 * only be called from an active thread context.
 */
void thread_restore_foreign_intr(void);

/*
 * Defines the bits for the exception mask used by the
 * thread_*_exceptions() functions below.
 */
#define THREAD_EXCP_FOREIGN_INTR       (1 << 9)
#define THREAD_EXCP_ALL                THREAD_EXCP_FOREIGN_INTR

/*
 * thread_get_exceptions() - return current exception mask
 */
uint32_t thread_get_exceptions(void);

/*
 * thread_set_exceptions() - set exception mask
 * @exceptions: exception mask to set
 *
 * Any previous exception mask is replaced by this exception mask, that is,
 * old bits are cleared and replaced by these.
 */
void thread_set_exceptions(uint32_t exceptions);

/*
 * thread_mask_exceptions() - Masks (disables) specified asynchronous exceptions
 * @exceptions	exceptions to mask
 * @returns old exception state
 */
uint32_t thread_mask_exceptions(uint32_t exceptions);

/*
 * thread_unmask_exceptions() - Unmasks asynchronous exceptions
 * @state	Old asynchronous exception state to restore (returned by
 *		thread_mask_exceptions())
 */
void thread_unmask_exceptions(uint32_t state);


static inline bool __nostackcheck thread_foreign_intr_disabled(void)
{
	return !!(thread_get_exceptions() & THREAD_EXCP_FOREIGN_INTR);
}

/*
 * thread_user_clear_vfp() - Clears the vfp state
 * @uctx:	pointer to user mode context containing the saved state to clear
 */
#ifdef CFG_WITH_VFP
void thread_user_clear_vfp(struct user_mode_ctx *uctx);
#else
static inline void thread_user_clear_vfp(struct user_mode_ctx *uctx __unused)
{
}
#endif

/*
 * thread_enter_user_mode() - Enters user mode
 * @a0:		Passed in r/x0 for user_func
 * @a1:		Passed in r/x1 for user_func
 * @a2:		Passed in r/x2 for user_func
 * @a3:		Passed in r/x3 for user_func
 * @user_sp:	Assigned sp value in user mode
 * @user_func:	Function to execute in user mode
 * @is_32bit:   True if TA should execute in Aarch32, false if Aarch64
 * @exit_status0: Pointer to opaque exit staus 0
 * @exit_status1: Pointer to opaque exit staus 1
 *
 * This functions enters user mode with the argument described above,
 * @exit_status0 and @exit_status1 are filled in by thread_unwind_user_mode()
 * when returning back to the caller of this function through an exception
 * handler.
 *
 * @Returns what's passed in "ret" to thread_unwind_user_mode()
 */
uint32_t thread_enter_user_mode(unsigned long a0, unsigned long a1,
		unsigned long a2, unsigned long a3, unsigned long user_sp,
		unsigned long entry_func, bool is_32bit,
		uint32_t *exit_status0, uint32_t *exit_status1);

/*
 * thread_get_saved_thread_sp() - Returns the saved sp of current thread
 *
 * When switching from the thread stack pointer the value is stored
 * separately in the current thread context. This function returns this
 * saved value.
 *
 * @returns stack pointer
 */
vaddr_t thread_get_saved_thread_sp(void);

/*
 * Provides addresses and size of kernel code that must be mapped while in
 * user mode.
 */
#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
void thread_get_user_kcode(struct mobj **mobj, size_t *offset,
			  vaddr_t *va, size_t *sz);
#else
static inline void thread_get_user_kcode(struct mobj **mobj, size_t *offset,
					 vaddr_t *va, size_t *sz)
{
	*mobj = NULL;
	*offset = 0;
	*va = 0;
	*sz = 0;
}
#endif

/*
 * Provides addresses and size of kernel (rw) data that must be mapped
 * while in user mode.
 */
#if defined(CFG_CORE_UNMAP_CORE_AT_EL0) && \
		defined(CFG_CORE_WORKAROUND_SPECTRE_BP_SEC) && defined(ARM64)
void thread_get_user_kdata(struct mobj **mobj, size_t *offset,
				  vaddr_t *va, size_t *sz);
#else
static inline void thread_get_user_kdata(struct mobj **mobj, size_t *offset,
					 vaddr_t *va, size_t *sz)
{
	*mobj = NULL;
	*offset = 0;
	*va = 0;
	*sz = 0;
}
#endif

/*
 * Returns the start address (bottom) of the stack for the current thread,
 * zero if there is no current thread.
 */
vaddr_t thread_stack_start(void);


/* Returns the stack size for the current thread */
size_t thread_stack_size(void);

/*
 * Returns the start (top, lowest address) and end (bottom, highest address) of
 * the current stack (thread, temporary or abort stack).
 * When CFG_CORE_DEBUG_CHECK_STACKS=y, the @hard parameter tells if the hard or
 * soft limits are queried. The difference between soft and hard is that for the
 * latter, the stack start includes some additional space to let any function
 * overflow the soft limit and still be able to print a stack dump in this case.
 */
bool get_stack_limits(vaddr_t *start, vaddr_t *end, bool hard);

static inline bool __nostackcheck get_stack_soft_limits(vaddr_t *start,
							vaddr_t *end)
{
	return get_stack_limits(start, end, false);
}

static inline bool __nostackcheck get_stack_hard_limits(vaddr_t *start,
							vaddr_t *end)
{
	return get_stack_limits(start, end, true);
}

vaddr_t __nostackcheck thread_get_kern_sp(void);

void __nostackcheck thread_set_kern_sp(vaddr_t sp);

bool thread_is_in_normal_mode(void);

/*
 * Disables and empties the prealloc RPC cache one reference at a time. If
 * all threads are idle this function returns true and a cookie of one shm
 * object which was removed from the cache. When the cache is empty *cookie
 * is set to 0 and the cache is disabled else a valid cookie value. If one
 * thread isn't idle this function returns false.
 */
bool thread_disable_prealloc_rpc_cache(uint64_t *cookie);

/*
 * Enabled the prealloc RPC cache. If all threads are idle the cache is
 * enabled and this function returns true. If one thread isn't idle this
 * function return false.
 */
bool thread_enable_prealloc_rpc_cache(void);

/**
 * Allocates data for payload buffers.
 *
 * @size:	size in bytes of payload buffer
 *
 * @returns	mobj that describes allocated buffer or NULL on error
 */
struct mobj *thread_rpc_alloc_payload(size_t size);

/**
 * Free physical memory previously allocated with thread_rpc_alloc_payload()
 *
 * @mobj:	mobj that describes the buffer
 */
void thread_rpc_free_payload(struct mobj *mobj);

/**
 * Allocate data for payload buffers only shared with the non-secure kernel
 *
 * @size:	size in bytes of payload buffer
 *
 * @returns	mobj that describes allocated buffer or NULL on error
 */
struct mobj *thread_rpc_alloc_kernel_payload(size_t size);

/**
 * Free physical memory previously allocated with
 * thread_rpc_alloc_kernel_payload()
 *
 * @mobj:	mobj that describes the buffer
 */
void thread_rpc_free_kernel_payload(struct mobj *mobj);

struct thread_param_memref {
	size_t offs;
	size_t size;
	struct mobj *mobj;
};

struct thread_param_value {
	uint64_t a;
	uint64_t b;
	uint64_t c;
};

/*
 * Note that there's some arithmetics done on the value so it's important
 * to keep in IN, OUT, INOUT order.
 */
enum thread_param_attr {
	THREAD_PARAM_ATTR_NONE = 0,
	THREAD_PARAM_ATTR_VALUE_IN,
	THREAD_PARAM_ATTR_VALUE_OUT,
	THREAD_PARAM_ATTR_VALUE_INOUT,
	THREAD_PARAM_ATTR_MEMREF_IN,
	THREAD_PARAM_ATTR_MEMREF_OUT,
	THREAD_PARAM_ATTR_MEMREF_INOUT,
};

struct thread_param {
	enum thread_param_attr attr;
	union {
		struct thread_param_memref memref;
		struct thread_param_value value;
	} u;
};

#define THREAD_PARAM_MEMREF(_direction, _mobj, _offs, _size) \
	(struct thread_param){ \
		.attr = THREAD_PARAM_ATTR_MEMREF_ ## _direction, .u.memref = { \
		.mobj = (_mobj), .offs = (_offs), .size = (_size) } \
	}

#define THREAD_PARAM_VALUE(_direction, _a, _b, _c) \
	(struct thread_param){ \
		.attr = THREAD_PARAM_ATTR_VALUE_ ## _direction, .u.value = { \
		.a = (_a), .b = (_b), .c = (_c) } \
	}

/**
 * Does an RPC using a preallocated argument buffer
 * @cmd: RPC cmd
 * @num_params: number of parameters
 * @params: RPC parameters
 * @returns RPC return value
 */
uint32_t thread_rpc_cmd(uint32_t cmd, size_t num_params,
		struct thread_param *params);

void foreign_intr_handle(uint32_t id);

unsigned long thread_smc(unsigned long func_id, unsigned long a1,
			 unsigned long a2, unsigned long a3);

/**
 * Allocate data for payload buffers.
 * Buffer is exported to user mode applications.
 *
 * @size:	size in bytes of payload buffer
 *
 * @returns	mobj that describes allocated buffer or NULL on error
 */
struct mobj *thread_rpc_alloc_global_payload(size_t size);

/**
 * Free physical memory previously allocated with
 * thread_rpc_alloc_global_payload()
 *
 * @mobj:	mobj that describes the buffer
 */
void thread_rpc_free_global_payload(struct mobj *mobj);

/*
 * enum thread_shm_type - type of non-secure shared memory
 * @THREAD_SHM_TYPE_APPLICATION - user space application shared memory
 * @THREAD_SHM_TYPE_KERNEL_PRIVATE - kernel private shared memory
 * @THREAD_SHM_TYPE_GLOBAL - user space and kernel shared memory
 */
enum thread_shm_type {
	THREAD_SHM_TYPE_APPLICATION,
	THREAD_SHM_TYPE_KERNEL_PRIVATE,
	THREAD_SHM_TYPE_GLOBAL,
};

/*
 * enum thread_shm_cache_user - user of a cache allocation
 * @THREAD_SHM_CACHE_USER_SOCKET - socket communication
 * @THREAD_SHM_CACHE_USER_FS - filesystem access
 * @THREAD_SHM_CACHE_USER_I2C - I2C communication
 *
 * To ensure that each user of the shared memory cache doesn't interfere
 * with each other a unique ID per user is used.
 */
enum thread_shm_cache_user {
	THREAD_SHM_CACHE_USER_SOCKET,
	THREAD_SHM_CACHE_USER_FS,
	THREAD_SHM_CACHE_USER_I2C,
};

/*
 * Returns a pointer to the cached RPC memory. Each thread and @user tuple
 * has a unique cache. The pointer is guaranteed to point to a large enough
 * area or to be NULL.
 */
void *thread_rpc_shm_cache_alloc(enum thread_shm_cache_user user,
				 enum thread_shm_type shm_type,
				 size_t size, struct mobj **mobj);
#endif /*__ASSEMBLER__*/

#endif /*KERNEL_THREAD_H*/
