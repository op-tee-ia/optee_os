// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2020, Linaro Limited
 * Copyright (c) 2021, Intel Corporation
 */

#include <assert.h>
#include <compiler.h>
#include <config.h>
#include <console.h>
#include <crypto/crypto.h>
#include <initcall.h>
#include <inttypes.h>
#include <keep.h>
#include <kernel/asan.h>
#include <kernel/boot.h>
#include <kernel/linker.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/tee_misc.h>
#include <kernel/thread.h>
#include <kernel/tpm.h>
#include <libfdt.h>
#include <malloc.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/fobj.h>
#include <mm/tee_mm.h>
#include <mm/tee_pager.h>
#include <stdio.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>
#include <kernel/fpu.h>
#include <drivers/apic.h>
#include <platform_config.h>
#include <sm/vmcall.h>

/*
 * In this file we're using unsigned long to represent physical pointers as
 * they are received in a single register when OP-TEE is initially entered.
 * This limits 32-bit systems to only use make use of the lower 32 bits
 * of a physical address for initial parameters.
 *
 * 64-bit systems on the other hand can use full 64-bit physical pointers.
 */
#define PADDR_INVALID		ULONG_MAX

#if defined(CFG_BOOT_SECONDARY_REQUEST)
struct ns_entry_context {
	uintptr_t entry_point;
	uintptr_t context_id;
};
struct ns_entry_context ns_entry_contexts[CFG_TEE_CORE_NB_CORE];
static uint32_t spin_table[CFG_TEE_CORE_NB_CORE];
#endif

#ifdef CFG_BOOT_SYNC_CPU
/*
 * Array used when booting, to synchronize cpu.
 * When 0, the cpu has not started.
 * When 1, it has started
 */
uint32_t sem_cpu_sync[CFG_TEE_CORE_NB_CORE];
DECLARE_KEEP_PAGER(sem_cpu_sync);
#endif

#ifdef CFG_SECONDARY_INIT_CNTFRQ
static uint32_t cntfrq;
#endif

/* May be overridden in plat-$(PLATFORM)/main.c */
__weak void plat_primary_init_early(void)
{
}
DECLARE_KEEP_PAGER(plat_primary_init_early);

/* May be overridden in plat-$(PLATFORM)/main.c */
__weak void main_init_gic(void)
{
}

/* May be overridden in plat-$(PLATFORM)/main.c */
__weak void main_secondary_init_gic(void)
{
}

void init_sec_mon(unsigned long nsec_entry __maybe_unused)
{
	assert(nsec_entry == PADDR_INVALID);
	/* Do nothing as we don't have a secure monitor */
}

#ifdef CFG_SECONDARY_INIT_CNTFRQ
static void primary_save_cntfrq(void)
{
	assert(cntfrq == 0);

	/*
	 * CNTFRQ should be initialized on the primary CPU by a
	 * previous boot stage
	 */
	cntfrq = read_cntfrq();
}

static void secondary_init_cntfrq(void)
{
	assert(cntfrq != 0);
	write_cntfrq(cntfrq);
}
#else /* CFG_SECONDARY_INIT_CNTFRQ */
static void primary_save_cntfrq(void)
{
}

static void secondary_init_cntfrq(void)
{
}
#endif

#ifdef CFG_CORE_SANITIZE_KADDRESS
static void init_run_constructors(void)
{
	const vaddr_t *ctor;

	for (ctor = &__ctor_list; ctor < &__ctor_end; ctor++)
		((void (*)(void))(*ctor))();
}

static void init_asan(void)
{

	/*
	 * CFG_ASAN_SHADOW_OFFSET is also supplied as
	 * -fasan-shadow-offset=$(CFG_ASAN_SHADOW_OFFSET) to the compiler.
	 * Since all the needed values to calculate the value of
	 * CFG_ASAN_SHADOW_OFFSET isn't available in to make we need to
	 * calculate it in advance and hard code it into the platform
	 * conf.mk. Here where we have all the needed values we double
	 * check that the compiler is supplied the correct value.
	 */

#define __ASAN_SHADOW_START \
	ROUNDUP(TEE_RAM_VA_START + (TEE_RAM_VA_SIZE * 8) / 9 - 8, 8)
	assert(__ASAN_SHADOW_START == (vaddr_t)&__asan_shadow_start);
#define __CFG_ASAN_SHADOW_OFFSET \
	(__ASAN_SHADOW_START - (TEE_RAM_VA_START / 8))
	COMPILE_TIME_ASSERT(CFG_ASAN_SHADOW_OFFSET == __CFG_ASAN_SHADOW_OFFSET);
#undef __ASAN_SHADOW_START
#undef __CFG_ASAN_SHADOW_OFFSET

	/*
	 * Assign area covered by the shadow area, everything from start up
	 * to the beginning of the shadow area.
	 */
	asan_set_shadowed((void *)TEE_TEXT_VA_START, &__asan_shadow_start);

	/*
	 * Add access to areas that aren't opened automatically by a
	 * constructor.
	 */
	asan_tag_access(&__ctor_list, &__ctor_end);
	asan_tag_access(__rodata_start, __rodata_end);
#ifdef CFG_WITH_PAGER
	asan_tag_access(__pageable_start, __pageable_end);
#endif /*CFG_WITH_PAGER*/
	asan_tag_access(__nozi_start, __nozi_end);
	asan_tag_access(__exidx_start, __exidx_end);
	asan_tag_access(__extab_start, __extab_end);

	init_run_constructors();

	/* Everything is tagged correctly, let's start address sanitizing. */
	asan_start();
}
#else /*CFG_CORE_SANITIZE_KADDRESS*/
static void init_asan(void)
{
}
#endif /*CFG_CORE_SANITIZE_KADDRESS*/

#ifdef CFG_WITH_PAGER

#ifdef CFG_CORE_SANITIZE_KADDRESS
static void carve_out_asan_mem(tee_mm_pool_t *pool)
{
	const size_t s = pool->hi - pool->lo;
	tee_mm_entry_t *mm;
	paddr_t apa = ASAN_MAP_PA;
	size_t asz = ASAN_MAP_SZ;

	if (core_is_buffer_outside(apa, asz, pool->lo, s))
		return;

	/* Reserve the shadow area */
	if (!core_is_buffer_inside(apa, asz, pool->lo, s)) {
		if (apa < pool->lo) {
			/*
			 * ASAN buffer is overlapping with the beginning of
			 * the pool.
			 */
			asz -= pool->lo - apa;
			apa = pool->lo;
		} else {
			/*
			 * ASAN buffer is overlapping with the end of the
			 * pool.
			 */
			asz = pool->hi - apa;
		}
	}
	mm = tee_mm_alloc2(pool, apa, asz);
	assert(mm);
}
#else
static void carve_out_asan_mem(tee_mm_pool_t *pool __unused)
{
}
#endif

static void print_pager_pool_size(void)
{
	struct tee_pager_stats __maybe_unused stats;

	tee_pager_get_stats(&stats);
	IMSG("Pager pool size: %zukB",
		stats.npages_all * SMALL_PAGE_SIZE / 1024);
}

static void init_vcore(tee_mm_pool_t *mm_vcore)
{
	const vaddr_t begin = VCORE_START_VA;
	vaddr_t end = begin + TEE_RAM_VA_SIZE;

#ifdef CFG_CORE_SANITIZE_KADDRESS
	/* Carve out asan memory, flat maped after core memory */
	if (end > ASAN_SHADOW_PA)
		end = ASAN_MAP_PA;
#endif

	if (!tee_mm_init(mm_vcore, begin, end, SMALL_PAGE_SHIFT,
			 TEE_MM_POOL_NO_FLAGS))
		panic("tee_mm_vcore init failed");
}

/*
 * With CFG_CORE_ASLR=y the init part is relocated very early during boot.
 * The init part is also paged just as the rest of the normal paged code, with
 * the difference that it's preloaded during boot. When the backing store
 * is configured the entire paged binary is copied in place and then also
 * the init part. Since the init part has been relocated (references to
 * addresses updated to compensate for the new load address) this has to be
 * undone for the hashes of those pages to match with the original binary.
 *
 * If CFG_CORE_ASLR=n, nothing needs to be done as the code/ro pages are
 * unchanged.
 */
static void undo_init_relocation(uint8_t *paged_store __maybe_unused)
{
#ifdef CFG_CORE_ASLR
	unsigned long *ptr = NULL;
	const uint32_t *reloc = NULL;
	const uint32_t *reloc_end = NULL;
	unsigned long offs = boot_mmu_config.load_offset;
	const struct boot_embdata *embdata = (const void *)__init_end;
	vaddr_t addr_end = (vaddr_t)__init_end - offs - TEE_RAM_START;
	vaddr_t addr_start = (vaddr_t)__init_start - offs - TEE_RAM_START;

	reloc = (const void *)((vaddr_t)embdata + embdata->reloc_offset);
	reloc_end = reloc + embdata->reloc_len / sizeof(*reloc);

	for (; reloc < reloc_end; reloc++) {
		if (*reloc < addr_start)
			continue;
		if (*reloc >= addr_end)
			break;
		ptr = (void *)(paged_store + *reloc - addr_start);
		*ptr -= offs;
	}
#endif
}

static struct fobj *ro_paged_alloc(tee_mm_entry_t *mm, void *hashes,
				   void *store)
{
	const unsigned int num_pages = tee_mm_get_bytes(mm) / SMALL_PAGE_SIZE;
#ifdef CFG_CORE_ASLR
	unsigned int reloc_offs = (vaddr_t)__pageable_start - VCORE_START_VA;
	const struct boot_embdata *embdata = (const void *)__init_end;
	const void *reloc = __init_end + embdata->reloc_offset;

	return fobj_ro_reloc_paged_alloc(num_pages, hashes, reloc_offs,
					 reloc, embdata->reloc_len, store);
#else
	return fobj_ro_paged_alloc(num_pages, hashes, store);
#endif
}

static void init_runtime(unsigned long pageable_part)
{
	size_t n;
	size_t init_size = (size_t)(__init_end - __init_start);
	size_t pageable_start = (size_t)__pageable_start;
	size_t pageable_end = (size_t)__pageable_end;
	size_t pageable_size = pageable_end - pageable_start;
	size_t tzsram_end = TZSRAM_BASE + TZSRAM_SIZE;
	size_t hash_size = (pageable_size / SMALL_PAGE_SIZE) *
			   TEE_SHA256_HASH_SIZE;
	const struct boot_embdata *embdata = (const void *)__init_end;
	const void *tmp_hashes = NULL;
	tee_mm_entry_t *mm = NULL;
	struct fobj *fobj = NULL;
	uint8_t *paged_store = NULL;
	uint8_t *hashes = NULL;

	assert(pageable_size % SMALL_PAGE_SIZE == 0);
	assert(embdata->total_len >= embdata->hashes_offset +
				     embdata->hashes_len);
	assert(hash_size == embdata->hashes_len);

	tmp_hashes = __init_end + embdata->hashes_offset;

	init_asan();

	malloc_add_pool(__heap1_start, __heap1_end - __heap1_start);
	malloc_add_pool(__heap2_start, __heap2_end - __heap2_start);

	/*
	 * This needs to be initialized early to support address lookup
	 * in MEM_AREA_TEE_RAM
	 */
	tee_pager_early_init();

	hashes = malloc(hash_size);
	IMSG_RAW("\n");
	IMSG("Pager is enabled. Hashes: %zu bytes", hash_size);
	assert(hashes);
	asan_memcpy_unchecked(hashes, tmp_hashes, hash_size);

	/*
	 * Need tee_mm_sec_ddr initialized to be able to allocate secure
	 * DDR below.
	 */
	core_mmu_init_ta_ram();

	carve_out_asan_mem(&tee_mm_sec_ddr);

	mm = tee_mm_alloc(&tee_mm_sec_ddr, pageable_size);
	assert(mm);
	paged_store = phys_to_virt(tee_mm_get_smem(mm), MEM_AREA_TA_RAM);
	/*
	 * Load pageable part in the dedicated allocated area:
	 * - Move pageable non-init part into pageable area. Note bootloader
	 *   may have loaded it anywhere in TA RAM hence use memmove().
	 * - Copy pageable init part from current location into pageable area.
	 */
	memmove(paged_store + init_size,
		phys_to_virt(pageable_part,
			     core_mmu_get_type_by_pa(pageable_part)),
		__pageable_part_end - __pageable_part_start);
	asan_memcpy_unchecked(paged_store, __init_start, init_size);
	/*
	 * Undo eventual relocation for the init part so the hash checks
	 * can pass.
	 */
	undo_init_relocation(paged_store);

	/* Check that hashes of what's in pageable area is OK */
	DMSG("Checking hashes of pageable area");
	for (n = 0; (n * SMALL_PAGE_SIZE) < pageable_size; n++) {
		const uint8_t *hash = hashes + n * TEE_SHA256_HASH_SIZE;
		const uint8_t *page = paged_store + n * SMALL_PAGE_SIZE;
		TEE_Result res;

		DMSG("hash pg_idx %zu hash %p page %p", n, hash, page);
		res = hash_sha256_check(hash, page, SMALL_PAGE_SIZE);
		if (res != TEE_SUCCESS) {
			EMSG("Hash failed for page %zu at %p: res 0x%x",
			     n, (void *)page, res);
			panic();
		}
	}

	/*
	 * Assert prepaged init sections are page aligned so that nothing
	 * trails uninited at the end of the premapped init area.
	 */
	assert(!(init_size & SMALL_PAGE_MASK));

	/*
	 * Initialize the virtual memory pool used for main_mmu_l2_ttb which
	 * is supplied to tee_pager_init() below.
	 */
	init_vcore(&tee_mm_vcore);

	/*
	 * Assign alias area for pager end of the small page block the rest
	 * of the binary is loaded into. We're taking more than needed, but
	 * we're guaranteed to not need more than the physical amount of
	 * TZSRAM.
	 */
	mm = tee_mm_alloc2(&tee_mm_vcore,
		(vaddr_t)tee_mm_vcore.hi - TZSRAM_SIZE, TZSRAM_SIZE);
	assert(mm);
	tee_pager_set_alias_area(mm);

	/*
	 * Claim virtual memory which isn't paged.
	 * Linear memory (flat map core memory) ends there.
	 */
	mm = tee_mm_alloc2(&tee_mm_vcore, VCORE_UNPG_RX_PA,
			   (vaddr_t)(__pageable_start - VCORE_UNPG_RX_PA));
	assert(mm);

	/*
	 * Allocate virtual memory for the pageable area and let the pager
	 * take charge of all the pages already assigned to that memory.
	 */
	mm = tee_mm_alloc2(&tee_mm_vcore, (vaddr_t)__pageable_start,
			   pageable_size);
	assert(mm);
	fobj = ro_paged_alloc(mm, hashes, paged_store);
	assert(fobj);
	tee_pager_add_core_area(tee_mm_get_smem(mm), PAGER_AREA_TYPE_RO, fobj);
	fobj_put(fobj);

	tee_pager_add_pages(pageable_start, init_size / SMALL_PAGE_SIZE, false);
	tee_pager_add_pages(pageable_start + init_size,
			    (pageable_size - init_size) / SMALL_PAGE_SIZE,
			    true);
	if (pageable_end < tzsram_end)
		tee_pager_add_pages(pageable_end, (tzsram_end - pageable_end) /
						   SMALL_PAGE_SIZE, true);

	/*
	 * There may be physical pages in TZSRAM before the core load address.
	 * These pages can be added to the physical pages pool of the pager.
	 * This setup may happen when a the secure bootloader runs in TZRAM
	 * and its memory can be reused by OP-TEE once boot stages complete.
	 */
	tee_pager_add_pages(tee_mm_vcore.lo,
			(VCORE_UNPG_RX_PA - tee_mm_vcore.lo) / SMALL_PAGE_SIZE,
			true);

	print_pager_pool_size();
}
#else

static void init_runtime(unsigned long pageable_part __unused)
{
	init_asan();

	/*
	 * By default whole OP-TEE uses malloc, so we need to initialize
	 * it early. But, when virtualization is enabled, malloc is used
	 * only by TEE runtime, so malloc should be initialized later, for
	 * every virtual partition separately. Core code uses nex_malloc
	 * instead.
	 */
#ifdef CFG_VIRTUALIZATION
	nex_malloc_add_pool(__nex_heap_start, __nex_heap_end -
					      __nex_heap_start);
#else
	malloc_add_pool(__heap1_start, __heap1_end - __heap1_start);
#endif

	IMSG_RAW("\n");
}
#endif

void *get_dt(void)
{
	void *fdt = get_embedded_dt();

	if (!fdt)
		fdt = get_external_dt();

	return fdt;
}

void *get_embedded_dt(void)
{
	return NULL;
}

void *get_external_dt(void)
{
	return NULL;
}

#ifdef CFG_CORE_DYN_SHM
static struct core_mmu_phys_mem *get_nsec_memory(void *fdt __unused,
						 size_t *nelems __unused)
{
	return NULL;
}
#endif /*CFG_CORE_DYN_SHM*/

#ifdef CFG_CORE_DYN_SHM
static void discover_nsec_memory(void)
{
	struct core_mmu_phys_mem *mem;
	const struct core_mmu_phys_mem *mem_begin = NULL;
	const struct core_mmu_phys_mem *mem_end = NULL;
	size_t nelems;
	void *fdt = get_external_dt();

	if (fdt) {
		mem = get_nsec_memory(fdt, &nelems);
		if (mem) {
			core_mmu_set_discovered_nsec_ddr(mem, nelems);
			return;
		}

		DMSG("No non-secure memory found in FDT");
	}

	mem_begin = phys_ddr_overall_begin;
	mem_end = phys_ddr_overall_end;
	nelems = mem_end - mem_begin;
	if (nelems) {
		/*
		 * Platform cannot use both register_ddr() and the now
		 * deprecated register_dynamic_shm().
		 */
		assert(phys_ddr_overall_compat_begin ==
		       phys_ddr_overall_compat_end);
	} else {
		mem_begin = phys_ddr_overall_compat_begin;
		mem_end = phys_ddr_overall_compat_end;
		nelems = mem_end - mem_begin;
		if (!nelems)
			return;
		DMSG("Warning register_dynamic_shm() is deprecated, please use register_ddr() instead");
	}

	mem = nex_calloc(nelems, sizeof(*mem));
	if (!mem)
		panic();

	memcpy(mem, phys_ddr_overall_begin, sizeof(*mem) * nelems);
	core_mmu_set_discovered_nsec_ddr(mem, nelems);
}
#else /*CFG_CORE_DYN_SHM*/
static void discover_nsec_memory(void)
{
}
#endif /*!CFG_CORE_DYN_SHM*/

void init_tee_runtime(void)
{
#ifdef CFG_VIRTUALIZATION
	/* We need to initialize pool for every virtual guest partition */
	malloc_add_pool(__heap1_start, __heap1_end - __heap1_start);
#endif

#ifndef CFG_WITH_PAGER
	/* Pager initializes TA RAM early */
	core_mmu_init_ta_ram();
#endif
	call_initcalls();
}

static void init_primary(unsigned long pageable_part, unsigned long nsec_entry)
{
	/*
	 * Mask asynchronous exceptions before switch to the thread vector
	 * as the thread handler requires those to be masked while
	 * executing with the temporary stack. The thread subsystem also
	 * asserts that the foreign interrupts are blocked when using most of
	 * its functions.
	 */
	thread_set_exceptions(THREAD_EXCP_ALL);
	primary_save_cntfrq();
	fpu_init();

	/*
	 * Pager: init_runtime() calls thread_kernel_enable_vfp() so we must
	 * set a current thread right now to avoid a chicken-and-egg problem
	 * (thread_init_boot_thread() sets the current thread but needs
	 * things set by init_runtime()).
	 */
	thread_get_core_local()->curr_thread = 0;
	init_runtime(pageable_part);

	if (IS_ENABLED(CFG_VIRTUALIZATION)) {
		/*
		 * Virtualization: We can't initialize threads right now because
		 * threads belong to "tee" part and will be initialized
		 * separately per each new virtual guest. So, we'll clear
		 * "curr_thread" and call it done.
		 */
		thread_get_core_local()->curr_thread = -1;
	} else {
		thread_init_boot_thread();
	}
	thread_init_primary();
	thread_init_per_cpu();
	init_sec_mon(nsec_entry);
#ifdef CFG_APIC
	apic_init();
#endif
}

/*
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
void __weak boot_init_primary_late(unsigned long fdt __unused)
{
	discover_nsec_memory();

	IMSG("OP-TEE version: %s", core_v_str);
	IMSG("Primary CPU initializing");
#ifdef CFG_CORE_ASLR
	DMSG("Executing at offset %#lx with virtual load address %#"PRIxVA,
	     (unsigned long)boot_mmu_config.load_offset, VCORE_START_VA);
#endif

	main_init_gic();
#ifndef CFG_VIRTUALIZATION
	init_tee_runtime();
#endif
#ifdef CFG_VIRTUALIZATION
	IMSG("Initializing virtualization support");
	core_mmu_init_virtualization();
#endif
	call_finalcalls();
	IMSG("Primary CPU switching to normal world boot");
}

static void init_secondary_helper(unsigned long nsec_entry)
{
	IMSG("Secondary CPU %zu initializing", get_core_pos());

	/*
	 * Mask asynchronous exceptions before switch to the thread vector
	 * as the thread handler requires those to be masked while
	 * executing with the temporary stack. The thread subsystem also
	 * asserts that the foreign interrupts are blocked when using most of
	 * its functions.
	 */
	thread_set_exceptions(THREAD_EXCP_ALL);

	secondary_init_cntfrq();
	thread_init_per_cpu();
	init_sec_mon(nsec_entry);
	main_secondary_init_gic();

	IMSG("Secondary CPU %zu switching to normal world boot", get_core_pos());
}

/*
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area so that it lies in the init area.
 */
void __weak boot_init_primary_early(unsigned long pageable_part,
				    unsigned long nsec_entry __maybe_unused)
{
	unsigned long e = PADDR_INVALID;

	e = nsec_entry;

	init_primary(pageable_part, e);
}

void boot_init_primary(void)
{
	IMSG("Welcome to OP-TEE\n");

	boot_init_primary_early(0, 0);

	boot_init_primary_late(0);

	DMSG("Primary CPU switching to normal world boot\n");
}

void boot_init_secondary(unsigned long nsec_entry)
{
	init_secondary_helper(nsec_entry);
}

#if defined(CFG_BOOT_SECONDARY_REQUEST)
void boot_set_core_ns_entry(size_t core_idx, uintptr_t entry,
			    uintptr_t context_id)
{
	ns_entry_contexts[core_idx].entry_point = entry;
	ns_entry_contexts[core_idx].context_id = context_id;
	dsb_ishst();
}

int boot_core_release(size_t core_idx, paddr_t entry)
{
	if (!core_idx || core_idx >= CFG_TEE_CORE_NB_CORE)
		return -1;

	ns_entry_contexts[core_idx].entry_point = entry;
	dmb();
	spin_table[core_idx] = 1;
	dsb();
	sev();

	return 0;
}

/*
 * spin until secondary boot request, then returns with
 * the secondary core entry address.
 */
struct ns_entry_context *boot_core_hpen(void)
{
	do {
		wfe();
	} while (!spin_table[get_core_pos()]);
	dmb();
	return &ns_entry_contexts[get_core_pos()];
}
#endif

#if defined(CFG_CORE_ASLR)
unsigned long __weak get_aslr_seed(void *fdt __unused)
{
	DMSG("Warning: no ASLR seed");
	return 0;
}
#endif /*CFG_CORE_ASLR*/
