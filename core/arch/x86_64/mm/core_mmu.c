// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <kernel/trace_control_by_service.h>
#ifndef TRACE_SERV_MMU
#undef TRACE_LEVEL
#define TRACE_LEVEL 0
#endif
#include <kernel/boot.h>

#include <assert.h>
#include <bitstring.h>
#include <config.h>
#include <kernel/boot.h>
#include <kernel/linker.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <kernel/tee_l2cc_mutex.h>
#include <kernel/tee_misc.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <kernel/tlb_helpers.h>
#include <kernel/user_mode_ctx.h>
#include <kernel/virtualization.h>

#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/mobj.h>
#include <mm/pgt_cache.h>
#include <mm/tee_pager.h>
#include <mm/vm.h>

#include <platform_config.h>
#include <stdlib.h>
#include <trace.h>
#include <util.h>
#include <x86.h>
#include <console.h>
#include <kernel/user_ta.h>

#include "core_mmu_private.h"

#ifndef DEBUG_XLAT_TABLE
#define DEBUG_XLAT_TABLE 0
#endif

#define SHM_VASPACE_SIZE	(1024 * 1024 * 32)

#define	TEE_MATTR_CACHE		BIT(12)

#define IS_ALIGNED(p, align_to) (!(((uintptr_t)(p)) & (((uintptr_t)(align_to))-1)))

/* Indicates kernel runtime MMU map status */
int optee_mem_structs_ready;

/*
 * These variables are initialized before .bss is cleared. To avoid
 * resetting them when .bss is cleared we're storing them in .data instead,
 * even if they initially are zero.
 */

/* Address width including virtual/physical address*/
uint8_t g_vaddr_width;
uint8_t g_paddr_width;

/* Initial memory mappings */
struct mmu_initial_mapping mmu_initial_mappings[] = {
	/* 4GB */
	{	.phys = 0x0,
		.virt = 0x0,
		.size = 4 * GB,
		.flags = 0
	},
	{ 0 }
};

/* 2MB MMU tables for initial usage */
uint64_t g_pml4_init[1] __aligned(PAGE_SIZE);
uint64_t g_pdp_init[32] __aligned(PAGE_SIZE);
uint64_t g_pte_init[2048] __aligned(PAGE_SIZE);

/* PML4 PDP table for each thread */
uint64_t g_thread_pml4[CFG_NUM_THREADS][NO_OF_PML4_ENTRIES] __aligned(PAGE_SIZE);
uint64_t g_thread_pdp[CFG_NUM_THREADS][NO_OF_PDP_ENTRIES] __aligned(PAGE_SIZE);

/* MMU tables for runtime usage for kernel */
/* The kernel space of each thread shares the same pd and pte*/
uint64_t g_pml4[NO_OF_PML4_ENTRIES] __aligned(PAGE_SIZE);
uint64_t g_pdp[NO_OF_PDP_ENTRIES] __aligned(PAGE_SIZE);
uint64_t g_pd[NO_OF_PD_ENTRIES] __aligned(PAGE_SIZE);
uint64_t g_pte[NO_OF_PT_TABLES][NO_OF_PT_ENTRIES] __aligned(PAGE_SIZE);

/* MMU tables for runtime usage for user mode of each thread*/
uint64_t g_thread_user_ta_pd[CFG_NUM_THREADS][NO_OF_USER_PD_ENTRIES] __aligned(PAGE_SIZE);
uint64_t g_thread_user_ta_pte[CFG_NUM_THREADS][NO_OF_USER_PT_TABLES][NO_OF_PT_ENTRIES]
			__aligned(PAGE_SIZE);
uint32_t pt_user_index[CFG_NUM_THREADS];

#ifdef CFG_CORE_RESERVED_SHM
/* Default NSec shared memory allocated from NSec world */
unsigned long default_nsec_shm_size __nex_bss;
unsigned long default_nsec_shm_paddr __nex_bss;
#endif

static struct tee_mmap_region static_memory_map[CFG_MMAP_REGIONS
#ifdef CFG_CORE_ASLR
						+ 1
#endif
						+ 1] __nex_bss;

#define PRINT_MATTR_BIT(value, bit) \
	{FMSG(#bit " %s\n", ((value & bit) ? "SET" : "CLEAR")); }

/* Define the platform's memory layout. */
struct memaccess_area {
	paddr_t paddr;
	size_t size;
};
#define MEMACCESS_AREA(a, s) { .paddr = a, .size = s }

static struct memaccess_area secure_only[] __nex_data = {
#ifdef TZSRAM_BASE
	MEMACCESS_AREA(TZSRAM_BASE, TZSRAM_SIZE),
#endif
	MEMACCESS_AREA(TZDRAM_BASE, TZDRAM_SIZE),
};

static struct memaccess_area nsec_shared[] __nex_data = {
#ifdef CFG_CORE_RESERVED_SHM
	MEMACCESS_AREA(TEE_SHMEM_START, TEE_SHMEM_SIZE),
#endif
};

#if defined(CFG_SECURE_DATA_PATH)
#ifdef CFG_TEE_SDP_MEM_BASE
register_sdp_mem(CFG_TEE_SDP_MEM_BASE, CFG_TEE_SDP_MEM_SIZE);
#endif
#ifdef TEE_SDP_TEST_MEM_BASE
register_sdp_mem(TEE_SDP_TEST_MEM_BASE, TEE_SDP_TEST_MEM_SIZE);
#endif
#endif

#ifdef CFG_CORE_RWDATA_NOEXEC
register_phys_mem_ul(MEM_AREA_TEE_RAM_RO, TEE_RAM_START,
		     VCORE_UNPG_RX_PA - TEE_RAM_START);
register_phys_mem_ul(MEM_AREA_TEE_RAM_RX, VCORE_UNPG_RX_PA,
		     VCORE_UNPG_RX_SZ_UNSAFE);
register_phys_mem_ul(MEM_AREA_TEE_RAM_RO, VCORE_UNPG_RO_PA,
		     VCORE_UNPG_RO_SZ_UNSAFE);

#ifdef CFG_VIRTUALIZATION
register_phys_mem_ul(MEM_AREA_TEE_RAM_RO, VCORE_UNPG_RW_PA,
		     VCORE_UNPG_RW_SZ_UNSAFE);
register_phys_mem_ul(MEM_AREA_NEX_RAM_RW, VCORE_NEX_RW_PA,
		     VCORE_NEX_RW_SZ_UNSAFE);
#else
register_phys_mem_ul(MEM_AREA_TEE_RAM_RW, VCORE_UNPG_RW_PA,
		     VCORE_UNPG_RW_SZ_UNSAFE);
#endif

#ifdef CFG_WITH_PAGER
register_phys_mem_ul(MEM_AREA_TEE_RAM_RX, VCORE_INIT_RX_PA,
		     VCORE_INIT_RX_SZ_UNSAFE);
register_phys_mem_ul(MEM_AREA_TEE_RAM_RO, VCORE_INIT_RO_PA,
		     VCORE_INIT_RO_SZ_UNSAFE);
#endif /*CFG_WITH_PAGER*/
#else /*!CFG_CORE_RWDATA_NOEXEC*/
register_phys_mem(MEM_AREA_TEE_RAM, TEE_RAM_START, TEE_RAM_PH_SIZE);
#endif /*!CFG_CORE_RWDATA_NOEXEC*/

#ifdef CFG_VIRTUALIZATION
register_phys_mem(MEM_AREA_SEC_RAM_OVERALL, TZDRAM_BASE, TZDRAM_SIZE);
#endif

#if defined(CFG_CORE_SANITIZE_KADDRESS) && defined(CFG_WITH_PAGER)
/* Asan ram is part of MEM_AREA_TEE_RAM_RW when pager is disabled */
register_phys_mem_ul(MEM_AREA_TEE_ASAN, ASAN_MAP_PA, ASAN_MAP_SZ);
#endif

#ifndef CFG_VIRTUALIZATION
/* Every guest will have own TA RAM if virtualization support is enabled */
register_phys_mem(MEM_AREA_TA_RAM, TA_RAM_START, TA_RAM_SIZE);
#endif
#ifdef CFG_CORE_RESERVED_SHM
register_phys_mem(MEM_AREA_NSEC_SHM, TEE_SHMEM_START, TEE_SHMEM_SIZE);
#endif

static struct tee_mmap_region *init_xlation_table(struct tee_mmap_region *mm,
				uint64_t base_va __unused, unsigned int level);

/*
 * Two ASIDs per context, one for kernel mode and one for user mode. ASID 0
 * and 1 are reserved and not used. This means a maximum of 126 loaded user
 * mode contexts. This value can be increased but not beyond the maximum
 * ASID, which is architecture dependent (max 255 for ARMv7-A and ARMv8-A
 * Aarch32). This constant defines number of ASID pairs.
 */
#define MMU_NUM_ASID_PAIRS		64

static bitstr_t bit_decl(g_asid, MMU_NUM_ASID_PAIRS) __nex_bss;
static unsigned int g_asid_spinlock __nex_bss = SPINLOCK_UNLOCK;

static unsigned int mmu_spinlock;

static uint32_t mmu_lock(void)
{
	return cpu_spin_lock_xsave(&mmu_spinlock);
}

static void mmu_unlock(uint32_t exceptions)
{
	cpu_spin_unlock_xrestore(&mmu_spinlock, exceptions);
}

static struct tee_mmap_region *get_memory_map(void)
{
#ifdef CFG_VIRTUALIZATION
	struct tee_mmap_region *map = virt_get_memory_map();

	if (map)
		return map;
#endif
	return static_memory_map;

}

static bool _pbuf_intersects(struct memaccess_area *a, size_t alen,
			     paddr_t pa, size_t size)
{
	size_t n;

	for (n = 0; n < alen; n++)
		if (core_is_buffer_intersect(pa, size, a[n].paddr, a[n].size))
			return true;
	return false;
}
#define pbuf_intersects(a, pa, size) \
	_pbuf_intersects((a), ARRAY_SIZE(a), (pa), (size))

static bool _pbuf_is_inside(struct memaccess_area *a, size_t alen,
			    paddr_t pa, size_t size)
{
	size_t n;

	for (n = 0; n < alen; n++)
		if (core_is_buffer_inside(pa, size, a[n].paddr, a[n].size))
			return true;
	return false;
}
#define pbuf_is_inside(a, pa, size) \
	_pbuf_is_inside((a), ARRAY_SIZE(a), (pa), (size))

static bool pa_is_in_map(struct tee_mmap_region *map, paddr_t pa)
{
	if (!map)
		return false;
	return (pa >= map->pa && pa <= (map->pa + map->size - 1));
}

static bool va_is_in_map(struct tee_mmap_region *map, vaddr_t va)
{
	if (!map)
		return false;
	return (va >= map->va && va <= (map->va + map->size - 1));
}

/* check if target buffer fits in a core default map area */
static bool pbuf_inside_map_area(unsigned long p, size_t l,
				 struct tee_mmap_region *map)
{
	return core_is_buffer_inside(p, l, map->pa, map->size);
}

static struct tee_mmap_region *find_map_by_type(enum teecore_memtypes type)
{
	struct tee_mmap_region *map;

	for (map = get_memory_map(); !core_mmap_is_end_of_table(map); map++)
		if (map->type == type)
			return map;
	return NULL;
}

static struct tee_mmap_region *find_map_by_type_and_pa(
			enum teecore_memtypes type, paddr_t pa)
{
	struct tee_mmap_region *map;

	for (map = get_memory_map(); !core_mmap_is_end_of_table(map); map++) {
		if (map->type != type)
			continue;
		if (pa_is_in_map(map, pa))
			return map;
	}
	return NULL;
}

static struct tee_mmap_region *find_map_by_va(void *va)
{
	struct tee_mmap_region *map = get_memory_map();
	unsigned long a = (unsigned long)va;

	while (!core_mmap_is_end_of_table(map)) {
		if ((a >= map->va) && (a <= (map->va - 1 + map->size)))
			return map;
		map++;
	}
	return NULL;
}

static struct tee_mmap_region *find_map_by_pa(unsigned long pa)
{
	struct tee_mmap_region *map = get_memory_map();

	while (!core_mmap_is_end_of_table(map)) {
		if ((pa >= map->pa) && (pa < (map->pa + map->size)))
			return map;
		map++;
	}
	return NULL;
}

#if defined(CFG_CORE_DYN_SHM) || defined(CFG_SECURE_DATA_PATH)
static bool pbuf_is_special_mem(paddr_t pbuf, size_t len,
				const struct core_mmu_phys_mem *start,
				const struct core_mmu_phys_mem *end)
{
	const struct core_mmu_phys_mem *mem;

	for (mem = start; mem < end; mem++) {
		if (core_is_buffer_inside(pbuf, len, mem->addr, mem->size))
			return true;
	}

	return false;
}
#endif

#ifdef CFG_CORE_DYN_SHM
static void carve_out_phys_mem(struct core_mmu_phys_mem **mem, size_t *nelems,
			       paddr_t pa, size_t size)
{
	struct core_mmu_phys_mem *m = *mem;
	size_t n = 0;

	while (true) {
		if (n >= *nelems) {
			DMSG("No need to carve out %#" PRIxPA " size %#zx",
			     pa, size);
			return;
		}
		if (core_is_buffer_inside(pa, size, m[n].addr, m[n].size))
			break;
		if (!core_is_buffer_outside(pa, size, m[n].addr, m[n].size))
			panic();
		n++;
	}

	if (pa == m[n].addr && size == m[n].size) {
		/* Remove this entry */
		(*nelems)--;
		memmove(m + n, m + n + 1, sizeof(*m) * (*nelems - n));
		m = nex_realloc(m, sizeof(*m) * *nelems);
		if (!m)
			panic();
		*mem = m;
	} else if (pa == m[n].addr) {
		m[n].addr += size;
		m[n].size -= size;
	} else if ((pa + size) == (m[n].addr + m[n].size)) {
		m[n].size -= size;
	} else {
		/* Need to split the memory entry */
		m = nex_realloc(m, sizeof(*m) * (*nelems + 1));
		if (!m)
			panic();
		*mem = m;
		memmove(m + n + 1, m + n, sizeof(*m) * (*nelems - n));
		(*nelems)++;
		m[n].size = pa - m[n].addr;
		m[n + 1].size -= size + m[n].size;
		m[n + 1].addr = pa + size;
	}
}

static void check_phys_mem_is_outside(struct core_mmu_phys_mem *start,
				      size_t nelems,
				      struct tee_mmap_region *map)
{
	size_t n;

	for (n = 0; n < nelems; n++) {
		if (!core_is_buffer_outside(start[n].addr, start[n].size,
					    map->pa, map->size)) {
			EMSG("Non-sec mem (%#" PRIxPA ":%#" PRIxPASZ
			     ") overlaps map (type %d %#" PRIxPA ":%#zx)",
			     start[n].addr, start[n].size,
			     map->type, map->pa, map->size);
			panic();
		}
	}
}

static const struct core_mmu_phys_mem *discovered_nsec_ddr_start __nex_bss;
static size_t discovered_nsec_ddr_nelems __nex_bss;

static int cmp_pmem_by_addr(const void *a, const void *b)
{
	const struct core_mmu_phys_mem *pmem_a = a;
	const struct core_mmu_phys_mem *pmem_b = b;

	return CMP_TRILEAN(pmem_a->addr, pmem_b->addr);
}

static bool get_discovered_nsec_ddr(const struct core_mmu_phys_mem **start,
				    const struct core_mmu_phys_mem **end)
{
	(void)start;
	(void)end;

	return false;
}

static bool pbuf_is_nsec_ddr(paddr_t pbuf, size_t len)
{
	const struct core_mmu_phys_mem *start;
	const struct core_mmu_phys_mem *end;

	if (!get_discovered_nsec_ddr(&start, &end))
		return false;

	return pbuf_is_special_mem(pbuf, len, start, end);
}

bool core_mmu_nsec_ddr_is_defined(void)
{
	const struct core_mmu_phys_mem *start;
	const struct core_mmu_phys_mem *end;

	if (!get_discovered_nsec_ddr(&start, &end))
		return false;

	return start != end;
}
#else
static bool pbuf_is_nsec_ddr(paddr_t pbuf __unused, size_t len __unused)
{
	return false;
}
#endif /*CFG_CORE_DYN_SHM*/

#define MSG_MEM_INSTERSECT(pa1, sz1, pa2, sz2) \
	EMSG("[%" PRIxPA " %" PRIx64 "] intersects [%" PRIxPA " %" PRIx64 "]", \
			pa1, (uint64_t)pa1 + sz1, pa2, (uint64_t)pa2 + sz2)

#ifdef CFG_SECURE_DATA_PATH
static bool pbuf_is_sdp_mem(paddr_t pbuf, size_t len)
{
	return pbuf_is_special_mem(pbuf, len, phys_sdp_mem_begin,
				   phys_sdp_mem_end);
}

struct mobj **core_sdp_mem_create_mobjs(void)
{
	const struct core_mmu_phys_mem *mem;
	struct mobj **mobj_base;
	struct mobj **mobj;
	int cnt = phys_sdp_mem_end - phys_sdp_mem_begin;

	/* SDP mobjs table must end with a NULL entry */
	mobj_base = calloc(cnt + 1, sizeof(struct mobj *));
	if (!mobj_base)
		panic("Out of memory");

	for (mem = phys_sdp_mem_begin, mobj = mobj_base;
	     mem < phys_sdp_mem_end; mem++, mobj++) {
		*mobj = mobj_phys_alloc(mem->addr, mem->size,
					TEE_MATTR_CACHE_CACHED,
					CORE_MEM_SDP_MEM);
		if (!*mobj)
			panic("can't create SDP physical memory object");
	}
	return mobj_base;
}

#else /* CFG_SECURE_DATA_PATH */
static bool pbuf_is_sdp_mem(paddr_t pbuf __unused, size_t len __unused)
{
	return false;
}

#endif /* CFG_SECURE_DATA_PATH */

/* Check special memories comply with registered memories */
static void verify_special_mem_areas(struct tee_mmap_region *mem_map,
				     size_t len,
				     const struct core_mmu_phys_mem *start,
				     const struct core_mmu_phys_mem *end,
				     const char *area_name __maybe_unused)
{
	const struct core_mmu_phys_mem *mem;
	const struct core_mmu_phys_mem *mem2;
	struct tee_mmap_region *mmap;
	size_t n;

	if (start == end) {
		DMSG("No %s memory area defined", area_name);
		return;
	}

	for (mem = start; mem < end; mem++)
		DMSG("%s memory [%" PRIxPA " %" PRIx64 "]",
		     area_name, mem->addr, (uint64_t)mem->addr + mem->size);

	/* Check memories do not intersect each other */
	for (mem = start; mem + 1 < end; mem++) {
		for (mem2 = mem + 1; mem2 < end; mem2++) {
			if (core_is_buffer_intersect(mem2->addr, mem2->size,
						     mem->addr, mem->size)) {
				MSG_MEM_INSTERSECT(mem2->addr, mem2->size,
						   mem->addr, mem->size);
				panic("Special memory intersection");
			}
		}
	}

	/*
	 * Check memories do not intersect any mapped memory.
	 * This is called before reserved VA space is loaded in mem_map.
	 */
	for (mem = start; mem < end; mem++) {
		for (mmap = mem_map, n = 0; n < len; mmap++, n++) {
			if (core_is_buffer_intersect(mem->addr, mem->size,
						     mmap->pa, mmap->size)) {
				MSG_MEM_INSTERSECT(mem->addr, mem->size,
						   mmap->pa, mmap->size);
				panic("Special memory intersection");
			}
		}
	}
}

static void add_phys_mem(struct tee_mmap_region *memory_map, size_t num_elems,
			 const struct core_mmu_phys_mem *mem, size_t *last)
{
	size_t n = 0;
	paddr_t pa;
	paddr_size_t size;

	/*
	 * If some ranges of memory of the same type do overlap
	 * each others they are coalesced into one entry. To help this
	 * added entries are sorted by increasing physical.
	 *
	 * Note that it's valid to have the same physical memory as several
	 * different memory types, for instance the same device memory
	 * mapped as both secure and non-secure. This will probably not
	 * happen often in practice.
	 */
	DMSG("%s type %s 0x%08" PRIxPA " size 0x%08" PRIxPASZ,
	     mem->name, teecore_memtype_name(mem->type), mem->addr, mem->size);
	while (true) {
		if (n >= (num_elems - 1)) {
			EMSG("Out of entries (%zu) in memory_map", num_elems);
			panic();
		}
		if (n == *last)
			break;
		pa = memory_map[n].pa;
		size = memory_map[n].size;
		if (mem->type == memory_map[n].type &&
		    ((pa <= (mem->addr + (mem->size - 1))) &&
		    (mem->addr <= (pa + (size - 1))))) {
			DMSG("Physical mem map overlaps 0x%" PRIxPA, mem->addr);
			memory_map[n].pa = MIN(pa, mem->addr);
			memory_map[n].size = MAX(size, mem->size) +
					     (pa - memory_map[n].pa);
			return;
		}
		if (mem->type < memory_map[n].type ||
		    (mem->type == memory_map[n].type && mem->addr < pa))
			break; /* found the spot where to insert this memory */
		n++;
	}

	memmove(memory_map + n + 1, memory_map + n,
		sizeof(struct tee_mmap_region) * (*last - n));
	(*last)++;
	memset(memory_map + n, 0, sizeof(memory_map[0]));
	memory_map[n].type = mem->type;
	memory_map[n].pa = mem->addr;
	memory_map[n].size = mem->size;
}

static void add_va_space(struct tee_mmap_region *memory_map, size_t num_elems,
			 enum teecore_memtypes type, size_t size, size_t *last)
{
	size_t n = 0;

	DMSG("type %s size 0x%08zx", teecore_memtype_name(type), size);
	while (true) {
		if (n >= (num_elems - 1)) {
			EMSG("Out of entries (%zu) in memory_map", num_elems);
			panic();
		}
		if (n == *last)
			break;
		if (type < memory_map[n].type)
			break;
		n++;
	}

	memmove(memory_map + n + 1, memory_map + n,
		sizeof(struct tee_mmap_region) * (*last - n));
	(*last)++;
	memset(memory_map + n, 0, sizeof(memory_map[0]));
	memory_map[n].type = type;
	memory_map[n].size = size;
}

static bool core_mmu_place_tee_ram_at_top(paddr_t paddr)
{
	size_t l1size = 1ul << PML4_SHIFT;
	paddr_t l1mask = l1size - 1;

	return (paddr & l1mask) > (l1size / 2);
}

uint32_t core_mmu_type_to_attr(enum teecore_memtypes t)
{
	const uint32_t attr = TEE_MATTR_VALID_BLOCK;
	const uint32_t cached = TEE_MATTR_CACHE_CACHED << TEE_MATTR_CACHE_SHIFT;
	const uint32_t noncache = TEE_MATTR_CACHE_NONCACHE <<
				  TEE_MATTR_CACHE_SHIFT;

	switch (t) {
	case MEM_AREA_TEE_RAM:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PRWX | cached;
	case MEM_AREA_TEE_RAM_RX:
	case MEM_AREA_IDENTITY_MAP_RX:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PRX | cached;
	case MEM_AREA_TEE_RAM_RO:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PR | cached;
	case MEM_AREA_TEE_RAM_RW:
	case MEM_AREA_NEX_RAM_RW:
	case MEM_AREA_TEE_ASAN:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PRW | cached;
	case MEM_AREA_TEE_COHERENT:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PRWX | noncache;
	case MEM_AREA_TA_RAM:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PRW | cached;
	case MEM_AREA_NSEC_SHM:
		return attr | TEE_MATTR_PRW | cached;
	case MEM_AREA_EXT_DT:
	case MEM_AREA_IO_NSEC:
		return attr | TEE_MATTR_PRW | noncache;
	case MEM_AREA_IO_SEC:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PRW | noncache;
	case MEM_AREA_RAM_NSEC:
		return attr | TEE_MATTR_PRW | cached;
	case MEM_AREA_RAM_SEC:
	case MEM_AREA_SEC_RAM_OVERALL:
		return attr | TEE_MATTR_SECURE | TEE_MATTR_PRW | cached;
	case MEM_AREA_RES_VASPACE:
	case MEM_AREA_SHM_VASPACE:
		return 0;
	case MEM_AREA_PAGER_VASPACE:
		return TEE_MATTR_SECURE;
	default:
		panic("invalid type");
	}
}

static bool __maybe_unused map_is_tee_ram(const struct tee_mmap_region *mm)
{
	switch (mm->type) {
	case MEM_AREA_TEE_RAM:
	case MEM_AREA_TEE_RAM_RX:
	case MEM_AREA_TEE_RAM_RO:
	case MEM_AREA_TEE_RAM_RW:
	case MEM_AREA_NEX_RAM_RW:
	case MEM_AREA_TEE_ASAN:
		return true;
	default:
		return false;
	}
}

static bool __maybe_unused map_is_secure(const struct tee_mmap_region *mm)
{
	return !!(core_mmu_type_to_attr(mm->type) & TEE_MATTR_SECURE);
}

static bool __maybe_unused map_is_pgdir(const struct tee_mmap_region *mm)
{
	return mm->region_size == CORE_MMU_PGDIR_SIZE;
}

static int cmp_mmap_by_lower_va(const void *a, const void *b)
{
	const struct tee_mmap_region *mm_a = a;
	const struct tee_mmap_region *mm_b = b;

	return CMP_TRILEAN(mm_a->va, mm_b->va);
}

static void dump_mmap_table(struct tee_mmap_region *memory_map)
{
	struct tee_mmap_region *map;

	for (map = memory_map; !core_mmap_is_end_of_table(map); map++) {
		vaddr_t __maybe_unused vstart;

		vstart = map->va + ((vaddr_t)map->pa & (map->region_size - 1));
		DMSG("type %-12s va 0x%08" PRIxVA "..0x%08" PRIxVA
		     " pa 0x%08" PRIxPA "..0x%08" PRIxPA " size 0x%08zx (%s)",
		     teecore_memtype_name(map->type), vstart,
		     vstart + map->size - 1, map->pa,
		     (paddr_t)(map->pa + map->size - 1), map->size,
		     map->region_size == SMALL_PAGE_SIZE ? "smallpg" : "pgdir");
	}
}

/*
 * Reserves virtual memory space for pager usage.
 *
 * From the start of the first memory used by the link script +
 * TEE_RAM_VA_SIZE should be covered, either with a direct mapping or empty
 * mapping for pager usage. This adds translation tables as needed for the
 * pager to operate.
 */
static void add_pager_vaspace(struct tee_mmap_region *mmap, size_t num_elems,
			      size_t *last)
{
	paddr_t begin = 0;
	paddr_t end = 0;
	size_t size = 0;
	size_t pos = 0;
	size_t n = 0;

	if (*last >= (num_elems - 1)) {
		EMSG("Out of entries (%zu) in memory map", num_elems);
		panic();
	}

	for (n = 0; !core_mmap_is_end_of_table(mmap + n); n++) {
		if (map_is_tee_ram(mmap + n)) {
			if (!begin)
				begin = mmap[n].pa;
			pos = n + 1;
		}
	}

	end = mmap[pos - 1].pa + mmap[pos - 1].size;
	size = TEE_RAM_VA_SIZE - (end - begin);
	if (!size)
		return;

	assert(pos <= *last);
	memmove(mmap + pos + 1, mmap + pos,
		sizeof(struct tee_mmap_region) * (*last - pos));
	(*last)++;
	memset(mmap + pos, 0, sizeof(mmap[0]));
	mmap[pos].type = MEM_AREA_PAGER_VASPACE;
	mmap[pos].va = 0;
	mmap[pos].size = size;
	mmap[pos].region_size = SMALL_PAGE_SIZE;
	mmap[pos].attr = core_mmu_type_to_attr(MEM_AREA_PAGER_VASPACE);
}

static void check_sec_nsec_mem_config(void)
{
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(secure_only); n++) {
		if (pbuf_intersects(nsec_shared, secure_only[n].paddr,
				    secure_only[n].size))
			panic("Invalid memory access config: sec/nsec");
	}
}

static size_t collect_mem_ranges(struct tee_mmap_region *memory_map,
				 size_t num_elems)
{
	const struct core_mmu_phys_mem *mem = NULL;
	size_t last = 0;

	for (mem = phys_mem_map_begin; mem < phys_mem_map_end; mem++) {
		struct core_mmu_phys_mem m = *mem;

		/* Discard null size entries */
		if (!m.size)
			continue;

		/* Only unmapped virtual range may have a null phys addr */
		assert(m.addr || !core_mmu_type_to_attr(m.type));

		if (m.type == MEM_AREA_IO_SEC) {
			m.addr = ROUNDDOWN(m.addr, CORE_MMU_PGDIR_SIZE);
			m.size = ROUNDUP(m.size + (mem->addr - m.addr),
				CORE_MMU_PGDIR_SIZE);
		}

		add_phys_mem(memory_map, num_elems, &m, &last);
	}

	if (IS_ENABLED(CFG_SECURE_DATA_PATH))
		verify_special_mem_areas(memory_map, num_elems,
					 phys_sdp_mem_begin,
					 phys_sdp_mem_end, "SDP");

	add_va_space(memory_map, num_elems, MEM_AREA_RES_VASPACE,
		     CFG_RESERVED_VASPACE_SIZE, &last);

	add_va_space(memory_map, num_elems, MEM_AREA_SHM_VASPACE,
		     SHM_VASPACE_SIZE, &last);

	memory_map[last].type = MEM_AREA_END;

	return last;
}

static void assign_mem_granularity(struct tee_mmap_region *memory_map)
{
	struct tee_mmap_region *map = NULL;

	/*
	 * Assign region sizes, note that MEM_AREA_TEE_RAM always uses
	 * SMALL_PAGE_SIZE.
	 */
	for (map = memory_map; !core_mmap_is_end_of_table(map); map++) {
		paddr_t mask = map->pa | map->size;

		if (!(mask & CORE_MMU_PGDIR_MASK))
			map->region_size = CORE_MMU_PGDIR_SIZE;
		else if (!(mask & SMALL_PAGE_MASK))
			map->region_size = SMALL_PAGE_SIZE;
		else
			panic("Impossible memory alignment");

		if (map_is_tee_ram(map))
			map->region_size = SMALL_PAGE_SIZE;
	}
}

static unsigned int get_va_width(void)
{
	return g_vaddr_width;
}

static bool assign_mem_va(vaddr_t tee_ram_va,
			  struct tee_mmap_region *memory_map)
{
	struct tee_mmap_region *map = NULL;
	vaddr_t va = tee_ram_va;
	bool va_is_secure = true;

	/* Clear eventual previous assignments */
	for (map = memory_map; !core_mmap_is_end_of_table(map); map++)
		map->va = 0;

	/*
	 * TEE RAM regions are always aligned with region_size.
	 *
	 * Note that MEM_AREA_PAGER_VASPACE also counts as TEE RAM here
	 * since it handles virtual memory which covers the part of the ELF
	 * that cannot fit directly into memory.
	 */
	for (map = memory_map; !core_mmap_is_end_of_table(map); map++) {
		if (map_is_tee_ram(map) ||
		    map->type == MEM_AREA_PAGER_VASPACE) {
			assert(!(va & (map->region_size - 1)));
			assert(!(map->size & (map->region_size - 1)));
			map->va = va;
			if (ADD_OVERFLOW(va, map->size, &va))
				return false;
			if (va >= BIT64(get_va_width()))
				return false;
		}
	}

	if (core_mmu_place_tee_ram_at_top(tee_ram_va)) {
		/*
		 * Map non-tee ram regions at addresses lower than the tee
		 * ram region.
		 */
		va = tee_ram_va;
		for (map = memory_map; !core_mmap_is_end_of_table(map); map++) {
			map->attr = core_mmu_type_to_attr(map->type);
			if (map->va)
				continue;

			if (!IS_ENABLED(CFG_WITH_LPAE) &&
			    va_is_secure != map_is_secure(map)) {
				va_is_secure = !va_is_secure;
				va = ROUNDDOWN(va, CORE_MMU_PGDIR_SIZE);
			}

			if (SUB_OVERFLOW(va, map->size, &va))
				return false;
			va = ROUNDDOWN(va, map->region_size);
			/*
			 * Make sure that va is aligned with pa for
			 * efficient pgdir mapping. Basically pa &
			 * pgdir_mask should be == va & pgdir_mask
			 */
			if (map->size > 2 * CORE_MMU_PGDIR_SIZE) {
				if (SUB_OVERFLOW(va, CORE_MMU_PGDIR_SIZE, &va))
					return false;
				va += (map->pa - va) & CORE_MMU_PGDIR_MASK;
			}
			map->va = va;
		}
	} else {
		/*
		 * Map non-tee ram regions at addresses higher than the tee
		 * ram region.
		 */
		for (map = memory_map; !core_mmap_is_end_of_table(map); map++) {
			map->attr = core_mmu_type_to_attr(map->type);
			if (map->va)
				continue;

			if (!IS_ENABLED(CFG_WITH_LPAE) &&
			    va_is_secure != map_is_secure(map)) {
				va_is_secure = !va_is_secure;
				if (ROUNDUP_OVERFLOW(va, CORE_MMU_PGDIR_SIZE,
						     &va))
					return false;
			}

			if (ROUNDUP_OVERFLOW(va, map->region_size, &va))
				return false;
			/*
			 * Make sure that va is aligned with pa for
			 * efficient pgdir mapping. Basically pa &
			 * pgdir_mask should be == va & pgdir_mask
			 */
			if (map->size > 2 * CORE_MMU_PGDIR_SIZE) {
				vaddr_t offs = (map->pa - va) &
					       CORE_MMU_PGDIR_MASK;

				if (ADD_OVERFLOW(va, offs, &va))
					return false;
			}

			map->va = va;
			if (ADD_OVERFLOW(va, map->size, &va))
				return false;
			if (va >= BIT64(get_va_width()))
				return false;
		}
	}

	return true;
}

static int cmp_init_mem_map(const void *a, const void *b)
{
	const struct tee_mmap_region *mm_a = a;
	const struct tee_mmap_region *mm_b = b;
	int rc = 0;

	rc = CMP_TRILEAN(mm_a->region_size, mm_b->region_size);
	if (!rc)
		rc = CMP_TRILEAN(mm_a->pa, mm_b->pa);
	/*
	 * 32bit MMU descriptors cannot mix secure and non-secure mapping in
	 * the same level2 table. Hence sort secure mapping from non-secure
	 * mapping.
	 */
	if (!rc && !IS_ENABLED(CFG_WITH_LPAE))
		rc = CMP_TRILEAN(map_is_secure(mm_a), map_is_secure(mm_b));

	return rc;
}

static bool mem_map_add_id_map(struct tee_mmap_region *memory_map,
			       size_t num_elems, size_t *last,
			       vaddr_t id_map_start, vaddr_t id_map_end)
{
	struct tee_mmap_region *map = NULL;
	vaddr_t start = ROUNDDOWN(id_map_start, SMALL_PAGE_SIZE);
	vaddr_t end = ROUNDUP(id_map_end, SMALL_PAGE_SIZE);
	size_t len = end - start;

	if (*last >= num_elems - 1) {
		EMSG("Out of entries (%zu) in memory map", num_elems);
		panic();
	}

	for (map = memory_map; !core_mmap_is_end_of_table(map); map++)
		if (core_is_buffer_intersect(map->va, map->size, start, len))
			return false;

	*map = (struct tee_mmap_region){
		.type = MEM_AREA_IDENTITY_MAP_RX,
		/*
		 * Could use CORE_MMU_PGDIR_SIZE to potentially save a
		 * translation table, at the increased risk of clashes with
		 * the rest of the memory map.
		 */
		.region_size = SMALL_PAGE_SIZE,
		.pa = start,
		.va = start,
		.size = len,
		.attr = core_mmu_type_to_attr(MEM_AREA_IDENTITY_MAP_RX),
	};

	(*last)++;

	return true;
}

static unsigned long init_mem_map(struct tee_mmap_region *memory_map,
				  size_t num_elems, unsigned long seed)
{
	/*
	 * @id_map_start and @id_map_end describes a physical memory range
	 * that must be mapped Read-Only eXecutable at identical virtual
	 * addresses.
	 */
	vaddr_t id_map_start = (vaddr_t)__identity_map_init_start;
	vaddr_t id_map_end = (vaddr_t)__identity_map_init_end;
	unsigned long offs = 0;
	size_t last = 0;

	last = collect_mem_ranges(memory_map, num_elems);
	assign_mem_granularity(memory_map);

	/*
	 * To ease mapping and lower use of xlat tables, sort mapping
	 * description moving small-page regions after the pgdir regions.
	 */
	qsort(memory_map, last, sizeof(struct tee_mmap_region),
	      cmp_init_mem_map);

	add_pager_vaspace(memory_map, num_elems, &last);
	if (IS_ENABLED(CFG_CORE_ASLR) && seed) {
		vaddr_t base_addr = TEE_RAM_START + seed;
		const unsigned int va_width = get_va_width();
		const vaddr_t va_mask = GENMASK_64(va_width - 1,
						   SMALL_PAGE_SHIFT);
		vaddr_t ba = base_addr;
		size_t n = 0;

		for (n = 0; n < 3; n++) {
			if (n)
				ba = base_addr ^ BIT64(va_width - n);
			ba &= va_mask;
			if (assign_mem_va(ba, memory_map) &&
			    mem_map_add_id_map(memory_map, num_elems, &last,
					       id_map_start, id_map_end)) {
				offs = ba - TEE_RAM_START;
				DMSG("Mapping core at %#"PRIxVA" offs %#lx",
				     ba, offs);
				goto out;
			} else {
				DMSG("Failed to map core at %#"PRIxVA, ba);
			}
		}
		EMSG("Failed to map core with seed %#lx", seed);
	}

	if (!assign_mem_va(TEE_RAM_START, memory_map))
		panic();

out:
	qsort(memory_map, last, sizeof(struct tee_mmap_region),
	      cmp_mmap_by_lower_va);

	dump_mmap_table(memory_map);

	return offs;
}

static void check_mem_map(struct tee_mmap_region *map)
{
	struct tee_mmap_region *m = NULL;

	for (m = map; !core_mmap_is_end_of_table(m); m++) {
		switch (m->type) {
		case MEM_AREA_TEE_RAM:
		case MEM_AREA_TEE_RAM_RX:
		case MEM_AREA_TEE_RAM_RO:
		case MEM_AREA_TEE_RAM_RW:
		case MEM_AREA_NEX_RAM_RW:
		case MEM_AREA_IDENTITY_MAP_RX:
			if (!pbuf_is_inside(secure_only, m->pa, m->size))
				panic("TEE_RAM can't fit in secure_only");
			break;
		case MEM_AREA_TA_RAM:
			if (!pbuf_is_inside(secure_only, m->pa, m->size))
				panic("TA_RAM can't fit in secure_only");
			break;
		case MEM_AREA_NSEC_SHM:
			if (!pbuf_is_inside(nsec_shared, m->pa, m->size))
				panic("NS_SHM can't fit in nsec_shared");
			break;
		case MEM_AREA_SEC_RAM_OVERALL:
		case MEM_AREA_TEE_COHERENT:
		case MEM_AREA_TEE_ASAN:
		case MEM_AREA_IO_SEC:
		case MEM_AREA_IO_NSEC:
		case MEM_AREA_EXT_DT:
		case MEM_AREA_RAM_SEC:
		case MEM_AREA_RAM_NSEC:
		case MEM_AREA_RES_VASPACE:
		case MEM_AREA_SHM_VASPACE:
		case MEM_AREA_PAGER_VASPACE:
			break;
		default:
			EMSG("Uhandled memtype %d", m->type);
			panic();
		}
	}
}

static struct tee_mmap_region *get_tmp_mmap(void)
{
	struct tee_mmap_region *tmp_mmap = (void *)__heap1_start;

#ifdef CFG_WITH_PAGER
	if (__heap1_end - __heap1_start < (ptrdiff_t)sizeof(static_memory_map))
		tmp_mmap = (void *)__heap2_start;
#endif

	memset(tmp_mmap, 0, sizeof(static_memory_map));

	return tmp_mmap;
}

/*
 * core_init_mmu_map() - init tee core default memory mapping
 *
 * This routine sets the static default TEE core mapping. If @seed is > 0
 * and configured with CFG_CORE_ASLR it will map tee core at a location
 * based on the seed and return the offset from the link address.
 *
 * If an error happened: core_init_mmu_map is expected to panic.
 *
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
void __weak core_init_mmu_map(unsigned long seed, struct core_mmu_config *cfg)
{
#ifndef CFG_VIRTUALIZATION
	vaddr_t start = ROUNDDOWN((vaddr_t)__nozi_start, SMALL_PAGE_SIZE);
#else
	vaddr_t start = ROUNDDOWN((vaddr_t)__vcore_nex_rw_start,
				  SMALL_PAGE_SIZE);
#endif
	vaddr_t len = ROUNDUP((vaddr_t)__nozi_end, SMALL_PAGE_SIZE) - start;
	struct tee_mmap_region *tmp_mmap = get_tmp_mmap();

	(void)cfg;
	(void)seed;

	check_sec_nsec_mem_config();

	/*
	 * Add a entry covering the translation tables which will be
	 * involved in some virt_to_phys() and phys_to_virt() conversions.
	 */
	static_memory_map[0] = (struct tee_mmap_region){
		.type = MEM_AREA_TEE_RAM,
		.region_size = SMALL_PAGE_SIZE,
		.pa = start,
		.va = start,
		.size = len,
		.attr = core_mmu_type_to_attr(MEM_AREA_IDENTITY_MAP_RX),
	};

	COMPILE_TIME_ASSERT(CFG_MMAP_REGIONS >= 13);
	init_mem_map(tmp_mmap, ARRAY_SIZE(static_memory_map), seed);

	check_mem_map(tmp_mmap);
	core_init_mmu(tmp_mmap);
	memcpy(static_memory_map, tmp_mmap, sizeof(static_memory_map));

	DMSG("Enable runtime MMU\n");

	x86_set_cr3((uint64_t)&g_pml4[0]);
	optee_mem_structs_ready = 1;
	console_init();
}

void core_init_mmu(struct tee_mmap_region *mm)
{
	paddr_t max_pa = 0;
	uint64_t max_va = 0;
	size_t n;

	for (n = 0; !core_mmap_is_end_of_table(mm + n); n++) {
		paddr_t pa_end;
		vaddr_t va_end;

		DMSG_RAW(" %010" PRIxVA " %010" PRIxPA " %10zx %x",
				mm[n].va, mm[n].pa, mm[n].size, mm[n].attr);

		if (!IS_PAGE_ALIGNED(mm[n].pa) || !IS_PAGE_ALIGNED(mm[n].size))
			panic("unaligned region");

		pa_end = mm[n].pa + mm[n].size - 1;
		va_end = mm[n].va + mm[n].size - 1;

		if (pa_end > max_pa)
			max_pa = pa_end;
		if (va_end > max_va)
			max_va = va_end;
	}

	/* Clear table before use */
	init_xlation_table(mm, 0, 1);

	COMPILE_TIME_ASSERT(CFG_LPAE_ADDR_SPACE_SIZE > 0);
	assert(max_va < CFG_LPAE_ADDR_SPACE_SIZE);
}

static arch_flags_t get_x86_arch_flags(arch_flags_t flags);
static void print_memory_attr(uint32_t optee_mmu_flags __unused)
{
#if (TRACE_LEVEL == TRACE_FLOW)
	arch_flags_t x86_mmu_flags __unused =
		get_x86_arch_flags((arch_flags_t)optee_mmu_flags);
#endif

	FMSG("OP-TEE MMU flags: 0x%x\n", optee_mmu_flags);
	PRINT_MATTR_BIT(optee_mmu_flags, TEE_MATTR_VALID_BLOCK);
	PRINT_MATTR_BIT(optee_mmu_flags, TEE_MATTR_TABLE);
	PRINT_MATTR_BIT(optee_mmu_flags, TEE_MATTR_PR);
	PRINT_MATTR_BIT(optee_mmu_flags, TEE_MATTR_PW);
	PRINT_MATTR_BIT(optee_mmu_flags, TEE_MATTR_PX);
	PRINT_MATTR_BIT(optee_mmu_flags, TEE_MATTR_UR);
	PRINT_MATTR_BIT(optee_mmu_flags, TEE_MATTR_UW);
	PRINT_MATTR_BIT(optee_mmu_flags, TEE_MATTR_UX);
	PRINT_MATTR_BIT(optee_mmu_flags, TEE_MATTR_GLOBAL);
	PRINT_MATTR_BIT(optee_mmu_flags, TEE_MATTR_SECURE);
	PRINT_MATTR_BIT(optee_mmu_flags, TEE_MATTR_CACHE);

	FMSG("x86 MMU flags: 0x%lx\n", x86_mmu_flags);
	PRINT_MATTR_BIT(x86_mmu_flags, X86_MMU_PG_P);
	PRINT_MATTR_BIT(x86_mmu_flags, X86_MMU_PG_RW);
	PRINT_MATTR_BIT(x86_mmu_flags, X86_MMU_PG_U);
	PRINT_MATTR_BIT(x86_mmu_flags, X86_MMU_PG_PWT);
	PRINT_MATTR_BIT(x86_mmu_flags, X86_MMU_PG_PCD);
	PRINT_MATTR_BIT(x86_mmu_flags, X86_MMU_PG_PS);
	PRINT_MATTR_BIT(x86_mmu_flags, X86_MMU_PG_PTE_PAT);
	PRINT_MATTR_BIT(x86_mmu_flags, X86_MMU_PG_G);
	PRINT_MATTR_BIT(x86_mmu_flags, X86_MMU_PG_NX);
}

static void *paddr_to_kvaddr(paddr_t pa)
{
	/* slow path to do reverse lookup */
	struct mmu_initial_mapping *map = mmu_initial_mappings;

	while (map->size > 0) {
		if (!(map->flags & MMU_INITIAL_MAPPING_TEMPORARY) &&
				pa >= map->phys &&
				pa <= map->phys + map->size - 1) {
			return (void *)(map->virt + (pa - map->phys));
		}
		map++;
	}
	return NULL;
}

/**
 * @brief Returning the x86 arch flags from OP-TEE MMU flags
 */
static arch_flags_t get_x86_arch_flags(arch_flags_t flags)
{
	arch_flags_t arch_flags = 0;

	if (flags & TEE_MATTR_VALID_BLOCK)
		arch_flags |= X86_MMU_PG_P;

	if (flags & TEE_MATTR_GLOBAL)
		arch_flags |= X86_MMU_PG_G;

	if ((flags & TEE_MATTR_PW) || (flags & TEE_MATTR_UW))
		arch_flags |= X86_MMU_PG_RW; // Enable write access.

	if (flags & TEE_MATTR_URWX)
		arch_flags |= X86_MMU_PG_U; // Enable user-mode access

	if (!(flags & TEE_MATTR_CACHE))
		// Disable cache
		arch_flags |= (uint64_t)(X86_MMU_PG_PCD | X86_MMU_PG_PWT);

	if (!((flags & TEE_MATTR_PX) || (flags & TEE_MATTR_UX)))
		arch_flags |= X86_MMU_PG_NX; // Disable execution

	return arch_flags;
}

/**
 * @brief Returning the generic mmu flags from x86 arch flags
 */
static unsigned int get_arch_mmu_flags(arch_flags_t flags)
{
	uint32_t mmu_flags = 0;

	if (!(flags & X86_MMU_PG_RW))
		mmu_flags |= ARCH_MMU_FLAG_PERM_RO;

	if (flags & X86_MMU_PG_U)
		mmu_flags |= ARCH_MMU_FLAG_PERM_USER;

	/* Default memory type is CASHED/WB */
	if ((flags & X86_MMU_PG_PCD) && (flags & X86_MMU_PG_PWT)
		&& !(flags & X86_MMU_PG_PTE_PAT))
		mmu_flags |= ARCH_MMU_FLAG_UNCACHED;
	else
		mmu_flags |= ARCH_MMU_FLAG_CACHED;

	if (flags & X86_MMU_PG_NX)
		mmu_flags |= ARCH_MMU_FLAG_PERM_NO_EXECUTE;

	return (unsigned int) mmu_flags;
}

static uint64_t get_pml4_entry_from_pml4_table(vaddr_t vaddr,
					uintptr_t pml4_addr)
{
	uint32_t pml4_index;
	uint64_t *pml4_table = (uint64_t *) (pml4_addr & X86_PG_VA_FRAME);

	pml4_index = (((uint64_t)vaddr >> PML4_SHIFT)
					& ((1ul << ADDR_OFFSET) - 1));

	return pml4_table[pml4_index];
}

static inline uint64_t get_pdp_entry_from_pdp_table(vaddr_t vaddr,
						uint64_t pml4e)
{
	uint32_t pdp_index;
	uint64_t *pdpe;

	pdp_index = (((uint64_t)vaddr >> PDP_SHIFT)
					& ((1ul << ADDR_OFFSET) - 1));

	pdpe = (uint64_t *) (pml4e & X86_PG_VA_FRAME);

	/*
	 *	FMSG("Page-Directory-Pointer table @ 0x%lx =
	 *	pdpe value 0x%lx\n",
	 *	(uint64_t)&pdpe[pdp_index], pdpe[pdp_index]);
	 */

	return pdpe[pdp_index];
}

static inline uint64_t get_pd_entry_from_pd_table(vaddr_t vaddr, uint64_t pdpe)
{
	uint32_t pd_index;
	uint64_t *pde;

	pd_index = (((uint64_t) vaddr >> PD_SHIFT)
					& ((1ul << ADDR_OFFSET) - 1));

	pde = (uint64_t *) (pdpe & X86_PG_VA_FRAME);

	/*
	 * FMSG("Page-Directory entry @ 0x%lx (pd_index %d) = pde 0x%lx\n",
	 * (uint64_t)&pde[pd_index], pd_index, pde[pd_index]);
	 */
	return pde[pd_index];
}

static inline uint64_t get_pt_entry_from_pt_table(vaddr_t vaddr, uint64_t pde)
{
	uint32_t pt_index;
	uint64_t *pte;

	pt_index = (((uint64_t) vaddr >> PT_SHIFT)
					& ((1ul << ADDR_OFFSET) - 1));

	pte = (uint64_t *) (pde & X86_PG_VA_FRAME);

	return pte[pt_index];
}

static inline uint64_t get_pfn_from_pde(uint64_t pde)
{
	uint64_t pfn;

	pfn = (pde & X86_2MB_PAGE_FRAME);

	return pfn;
}

static void update_pt_entry(vaddr_t vaddr, paddr_t paddr, uint64_t pde,
							arch_flags_t flags)
{
	uint32_t pt_index;

	uint64_t *pt_table = (uint64_t *)(pde & X86_PG_PA_FRAME);

	pt_index = ((uint64_t)vaddr >> PT_SHIFT) & ADDR_MASK;

	pt_table[pt_index] = (uint64_t)paddr | flags;
}

static void update_pd_entry(vaddr_t vaddr, uint64_t pdpe, map_addr_t m,
							arch_flags_t flags)
{
	uint32_t pd_index;
	uint64_t *pd_table = (uint64_t *)(pdpe & X86_PG_PA_FRAME);

	pd_index = (((uint64_t)vaddr >> PD_SHIFT) & ((1ul << ADDR_OFFSET) - 1));
	pd_table[pd_index] = m | flags;
}

static void update_pdp_entry(vaddr_t vaddr, uint64_t pml4e, map_addr_t m,
							arch_flags_t flags)
{
	uint32_t pdp_index;
	uint64_t *pdp_table = (uint64_t *)(pml4e & X86_PG_PA_FRAME);

	pdp_index = (((uint64_t)vaddr >> PDP_SHIFT)
					& ((1ul << ADDR_OFFSET) - 1));
	pdp_table[pdp_index] = m | flags;
}

static void update_pml4_entry(vaddr_t vaddr, uintptr_t pml4_addr, map_addr_t m,
							arch_flags_t flags)
{
	uint32_t pml4_index;
	uint64_t *pml4_table = (uint64_t *)(pml4_addr);

	pml4_index = (((uint64_t)vaddr >> PML4_SHIFT)
					& ((1ul << ADDR_OFFSET) - 1));

	pml4_table[pml4_index] = m | flags;

	DMSG("pml4_table %p pml4_index 0x%x m 0x%lx flags 0x%lx\n",
			(void *)pml4_table, pml4_index, m, flags);

	DMSG("m | flags 0x%lx\n", (m | flags));
}

static bool check_directory_update_need(arch_flags_t current_entry,
					arch_flags_t new_entry,
					arch_flags_t *updated_mmu_flags)
{
	bool ret = false;

	*updated_mmu_flags = current_entry;

	if (!(current_entry & X86_MMU_PG_RW) && (new_entry & X86_MMU_PG_RW)) {
		*updated_mmu_flags |= X86_MMU_PG_RW;
		ret = true;
	}

	if (!(current_entry & X86_MMU_PG_U) && (new_entry & X86_MMU_PG_U)) {
		*updated_mmu_flags |= X86_MMU_PG_U;
		ret = true;
	}

	if ((current_entry & X86_MMU_PG_NX) && !(new_entry & X86_MMU_PG_NX)) {
		*updated_mmu_flags &= ~(uint64_t)X86_MMU_PG_NX;
		ret = true;
	}

	/* If current entry has cached disabled and
	 * new entry wants enable caches
	 * let's enable them for page directory entries
	 */
	if ((current_entry & (X86_MMU_PG_PCD | X86_MMU_PG_PWT)) &&
		!(new_entry & (X86_MMU_PG_PCD | X86_MMU_PG_PWT))) {
		*updated_mmu_flags &= ~((uint64_t)(X86_MMU_PG_PCD | X86_MMU_PG_PWT));
		ret = true;
	}

	return ret;
}

/**
 * @brief  check if the physical address is valid and aligned
 *
 */
static bool x86_mmu_check_paddr(paddr_t paddr)
{
	uint64_t addr = (uint64_t)paddr;
	uint64_t max_paddr;

	/* Check to see if the address is PAGE aligned */
	if (!IS_ALIGNED(addr, PAGE_SIZE))
		return false;

	max_paddr = ((uint64_t)1ull << g_paddr_width) - 1;

	return addr <= max_paddr;
}

/**
 * @brief  check if the virtual address is aligned and canonical
 *
 */
static bool x86_mmu_check_vaddr(vaddr_t vaddr)
{
	uint64_t addr = (uint64_t)vaddr;
	uint64_t max_vaddr_lohalf, min_vaddr_hihalf;

	/* Check to see if the address is PAGE aligned */
	if (!IS_ALIGNED(addr, PAGE_SIZE))
		return false;

	/* get max address in lower-half canonical addr space */
	/* e.g. if width is 48, then 0x00007FFF_FFFFFFFF */
	max_vaddr_lohalf = ((uint64_t)1ull << (g_vaddr_width - 1)) - 1;

	/* get min address in higher-half canonical addr space */
	/* e.g. if width is 48, then 0xFFFF8000_00000000*/
	min_vaddr_hihalf = ~max_vaddr_lohalf;

	/* Check to see if the address in a canonical address */
	if ((addr > max_vaddr_lohalf) && (addr < min_vaddr_hihalf))
		return false;

	return true;
}

/**
 * @brief  Walk the page table structures
 *
 * In this scenario,
 * we are considering the paging scheme to be a PAE mode with
 * 4KB pages.
 */
static int x86_mmu_get_mapping(map_addr_t pml4, vaddr_t vaddr, uint32_t *ret_level,
		arch_flags_t *mmu_flags, map_addr_t *last_valid_entry)
{
	uint64_t pml4e, pdpe, pde, pte;

	assert(pml4);
	if ((!ret_level) || (!last_valid_entry) || (!mmu_flags))
		return TEE_ERROR_BAD_PARAMETERS;

	*ret_level = PML4_L;
	*last_valid_entry = pml4;
	*mmu_flags = 0;

	pml4e = get_pml4_entry_from_pml4_table(vaddr, pml4);
	if ((pml4e & X86_MMU_PG_P) == 0)
		return TEE_ERROR_ITEM_NOT_FOUND;
	//  FMSG("pml4 @ 0x%lx = pml4e value 0x%lx\n", pml4, pml4e);

	pdpe = get_pdp_entry_from_pdp_table(vaddr, (uint64_t)paddr_to_kvaddr(
						pml4e & X86_PG_PA_FRAME));
	if ((pdpe & X86_MMU_PG_P) == 0) {
		*ret_level = PDP_L;
		*last_valid_entry = pml4e;
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	pde = get_pd_entry_from_pd_table(vaddr, (uint64_t)paddr_to_kvaddr(pdpe &
	X86_PG_PA_FRAME));
	if ((pde & X86_MMU_PG_P) == 0) {
		*ret_level = PD_L;
		*last_valid_entry = pdpe;
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	/* 2 MB pages */
	if (pde & X86_MMU_PG_PS) {
		/* Getting the Page frame & adding the 4KB page offset from the
		 * vaddr
		 */
		*last_valid_entry = get_pfn_from_pde(pde)
			+ ((uint64_t)vaddr & PAGE_OFFSET_MASK_2MB);

		*mmu_flags = get_arch_mmu_flags(pde & X86_FLAGS_MASK);

		goto last;
	}

	/* 4 KB pages */
	pte = get_pt_entry_from_pt_table(vaddr, (uint64_t)paddr_to_kvaddr(pde &
						X86_PG_PA_FRAME));

	if ((pte & X86_MMU_PG_P) == 0) {
		*ret_level = PT_L;
		*last_valid_entry = pde;

		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	/* Getting the Page frame & adding the 4KB page offset from the vaddr */
	*last_valid_entry = (pte & X86_PG_PA_FRAME)
		+ ((uint64_t)vaddr & PAGE_OFFSET_MASK_4KB);

	*mmu_flags = get_arch_mmu_flags(pte & X86_FLAGS_MASK);

last:
	*ret_level = PF_L;
	return TEE_SUCCESS;
}

/**
 * @brief  Add a new mapping for the given virtual address & physical address
 *
 * This is a API which handles the mapping b/w a virtual address
 * & physical address
 *
 * either by checking if the mapping already exists and is valid
 * OR by adding a new mapping with the required flags
 *
 * In this scenario, we are considering the paging scheme to be
 * a PAE mode with 4KB pages.
 *
 */
static int x86_mmu_add_mapping(map_addr_t pml4, map_addr_t paddr,
				vaddr_t vaddr, arch_flags_t mmu_flags, uint8_t id)
{
	uint32_t pd_new = 0, pdp_new = 0;
	uint64_t pml4e, pdpe, pde;
	arch_flags_t updated_mmu_flags;
	map_addr_t *m = NULL;
	static uint32_t pdp_counter, pd_counter;
	static uint32_t pt_index;

	assert(pml4);

	if ((!x86_mmu_check_vaddr(vaddr)) || (!x86_mmu_check_paddr(paddr)))
		return TEE_ERROR_BAD_PARAMETERS;

	pml4e = get_pml4_entry_from_pml4_table(vaddr, pml4);

	if ((pml4e & X86_MMU_PG_P) == 0) {
		if ((pdp_counter + 1) > NO_OF_PDP_ENTRIES) {
			EMSG("pdp_counter %d\n", pdp_counter);
			panic("TEE_ERROR_OUT_OF_MEMORY");
		}

		/* Creating a new pdp table */
		m = &g_thread_pdp[id][pdp_counter];
		pdp_counter++;

		FMSG("pdp_counter %d\n", pdp_counter);
		update_pml4_entry(vaddr, pml4, virt_to_phys(m), mmu_flags);
		pml4e = (uint64_t)m;
		pdp_new = 1;
	} else if (check_directory_update_need(pml4e, mmu_flags,
							&updated_mmu_flags)) {
		update_pml4_entry(vaddr, pml4,
				virt_to_phys((void *)(pml4e & X86_PG_PA_FRAME)),
				updated_mmu_flags);

		FMSG("Just update PML4 entry %d\n", pdp_counter);
	}

	if (!pdp_new)
		pdpe = get_pdp_entry_from_pdp_table(vaddr, pml4e);

	if (pdp_new || (pdpe & X86_MMU_PG_P) == 0) {
		if ((vaddr & 0xFF000000) == (vaddr_t)TA_USER_BASE_VA) {
			m = &g_thread_user_ta_pd[id][0];
		} else {
			if ((pd_counter + 1) > NO_OF_PD_ENTRIES) {
				EMSG("pd_counter %d\n", pd_counter);
				panic("TEE_ERROR_OUT_OF_MEMORY");
			}

			/* Creating a new pd table  */
			m = &g_pd[pd_counter];
			pd_counter++;
		}
		update_pdp_entry(vaddr, pml4e, virt_to_phys(m), mmu_flags);
		pdpe = (uint64_t)m;
		pd_new = 1;
	} else if (check_directory_update_need(pdpe, mmu_flags,
				&updated_mmu_flags)) {
		update_pdp_entry(vaddr, pml4e,
				virt_to_phys((void *)(pdpe & X86_PG_PA_FRAME)),
				updated_mmu_flags);
	}


	if (!pd_new)
		pde = get_pd_entry_from_pd_table(vaddr, pdpe);

	if (pd_new || ((pde & X86_MMU_PG_P) == 0)) {
		if ((vaddr & 0xFF000000) == (vaddr_t)TA_USER_BASE_VA) {
			if ((pt_user_index[id] + 1) > NO_OF_USER_PT_TABLES) {
				EMSG("gt_user_index %d\n", pt_user_index[id]);
				panic("TEE_ERROR_OUT_OF_MEMORY");
			}
			m = &g_thread_user_ta_pte[id][pt_user_index[id]][0];
			pt_user_index[id]++;
		} else {
			if ((pt_index + 1) > NO_OF_PT_TABLES) {
				EMSG("pt_index %d\n", pt_index);
				panic("TEE_ERROR_OUT_OF_MEMORY");
			}
			/* Creating a new pt */
			m = &g_pte[pt_index][0];
			pt_index++;
		}
		update_pd_entry(vaddr, pdpe, virt_to_phys(m), mmu_flags);
		pde = (uint64_t)m;
	} else if (check_directory_update_need(pde, mmu_flags,
				&updated_mmu_flags)) {
		update_pd_entry(vaddr, pdpe,
				virt_to_phys((void *)(pde & X86_PG_PA_FRAME)),
				updated_mmu_flags);
	}

	/* Updating the page table entry with the paddr
	 * and access flags required for the Mapping
	 */
	update_pt_entry(vaddr, paddr, pde, mmu_flags);
	return TEE_SUCCESS;
}

/**
 * @brief	x86-64 MMU unmap an entry in the page tables
 *			recursively and clear out tables
 *
 */
static void x86_mmu_unmap_entry(vaddr_t vaddr, int level, vaddr_t table_entry)
{
	uint32_t offset = 0, next_level_offset = 0;
	vaddr_t *table, *next_table_addr;

	FMSG("vaddr 0x%lx level %d table_entry 0x%lx\n",
			vaddr, level, table_entry);

	next_table_addr = NULL;
	table = (vaddr_t *)(table_entry & X86_PG_PA_FRAME);
	FMSG("table %p\n", (void *)table);

	switch (level) {
	case PML4_L:
		offset = (((uint64_t)vaddr >> PML4_SHIFT)
				& ((1ul << ADDR_OFFSET) - 1));
		FMSG("offset %u\n", offset);
		next_table_addr =
			(vaddr_t *)virt_to_phys((void *)table[offset]);
		FMSG("next_table_addr %p\n", (void *)next_table_addr);

		if ((virt_to_phys((void *)table[offset])
					& X86_MMU_PG_P) == 0)
			return;
		break;
	case PDP_L:
		offset = (((uint64_t)vaddr >> PDP_SHIFT)
						& ((1ul << ADDR_OFFSET) - 1));

		FMSG("offset %u\n", offset);

		next_table_addr =
				(vaddr_t *)virt_to_phys((void *)table[offset]);

		FMSG("next_table_addr %p\n", (void *)next_table_addr);

		if ((virt_to_phys((void *)table[offset])
					& X86_MMU_PG_P) == 0)
			return;

		break;
	case PD_L:
		offset = (((uint64_t)vaddr >> PD_SHIFT)
				& ((1ul << ADDR_OFFSET) - 1));

		FMSG("offset %u\n", offset);

		next_table_addr =
			(vaddr_t *)virt_to_phys((void *)table[offset]);

		FMSG("next_table_addr %p\n", (void *)next_table_addr);

		if ((virt_to_phys((void *)table[offset])
					& X86_MMU_PG_P) == 0)
			return;

		break;
	case PT_L:
		offset = (((uint64_t)vaddr >> PT_SHIFT)
					& ((1ul << ADDR_OFFSET) - 1));
		FMSG("offset %u\n", offset);
		next_table_addr =
				(vaddr_t *)virt_to_phys((void *)table[offset]);
		FMSG("next_table_addr %p\n", (void *)next_table_addr);
		if ((virt_to_phys((void *)table[offset])
					& X86_MMU_PG_P) == 0)
			return;
		break;
	case PF_L:
				/* Reached page frame, Let's go back */
	default:
			return;
	}

	FMSG("recursing\n");

	level -= 1;
	x86_mmu_unmap_entry(vaddr, level, (vaddr_t)next_table_addr);
	level += 1;

	FMSG("next_table_addr %p\n", (void *)next_table_addr);

	next_table_addr = (vaddr_t *)((vaddr_t)(next_table_addr) &
						X86_PG_PA_FRAME);

	if (level > PT_L) {
		/* Check all entries of next level table for present bit */
		for (next_level_offset = 0; next_level_offset < (PAGE_SIZE/8);
				next_level_offset++) {
			if ((next_table_addr[next_level_offset] &
						X86_MMU_PG_P) != 0)
				return;
		}
	}
	/* All present bits for all entries in next level table
	 * for this address are 0
	 */
	if ((virt_to_phys((void *)table[offset]) & X86_MMU_PG_P) != 0) {
		x86_cli();
		table[offset] = 0;
		x86_sti();
	}
}

static int x86_mmu_unmap(map_addr_t pml4, vaddr_t vaddr, unsigned int count)
{
	vaddr_t next_aligned_v_addr;

	assert(pml4);

	if (!(x86_mmu_check_vaddr(vaddr)))
		return TEE_ERROR_BAD_PARAMETERS;

	if (count == 0)
		return TEE_SUCCESS;

	next_aligned_v_addr = vaddr;

	while (count > 0) {
		x86_mmu_unmap_entry(next_aligned_v_addr, X86_PAGING_LEVELS,
							pml4);
		next_aligned_v_addr += PAGE_SIZE;
		count--;
	}
	return TEE_SUCCESS;
}

/**
 * @brief  Mapping a section/range with specific permissions
 *
 */
static int x86_mmu_map_range(map_addr_t pml4, struct map_range *range,
						arch_flags_t flags, uint8_t id)
{
	vaddr_t next_aligned_v_addr;
	paddr_t next_aligned_p_addr;
	int map_status;
	uint32_t no_of_pages, index;

	assert(pml4);
	if (!range)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Calculating the number of 4k pages */
	if (IS_ALIGNED(range->size, PAGE_SIZE))
		no_of_pages = (range->size) >> PAGE_DIV_SHIFT;
	else
		no_of_pages = ((range->size) >> PAGE_DIV_SHIFT) + 1;

	next_aligned_v_addr = range->start_vaddr;
	next_aligned_p_addr = range->start_paddr;

	FMSG("no_of_pages %d pml4=0x%llx, start_vaddr=0x%llx paddr=0x%llx flags=0x%llx\n",
		no_of_pages, pml4, next_aligned_v_addr, next_aligned_p_addr, flags);

	for (index = 0; index < no_of_pages; index++) {
		map_status = x86_mmu_add_mapping(pml4, next_aligned_p_addr,
						next_aligned_v_addr, flags, id);
		if (map_status) {
			EMSG("Add mapping failed with err=%d\n", map_status);
			/* Unmap the partial mapping - if any */
			x86_mmu_unmap(pml4, range->start_vaddr, index);
			return map_status;
		}
		next_aligned_v_addr += PAGE_SIZE;
		next_aligned_p_addr += PAGE_SIZE;
	}

	mfence();
	return TEE_SUCCESS;
}

static int arch_mmu_query(vaddr_t vaddr, paddr_t *paddr, unsigned int *flags)
{
	uintptr_t current_cr3_val;
	uint32_t ret_level;
	map_addr_t last_valid_entry;
	arch_flags_t ret_flags;
	int stat;

	if (!paddr)
		return TEE_ERROR_BAD_PARAMETERS;

	assert(x86_get_cr3());
	current_cr3_val = (uintptr_t) x86_get_cr3();

	stat = x86_mmu_get_mapping((map_addr_t)paddr_to_kvaddr(current_cr3_val &
	X86_PG_PA_FRAME), vaddr, &ret_level, &ret_flags, &last_valid_entry);
	if (stat)
		return stat;

	*paddr = (paddr_t) (last_valid_entry);

	/* converting x86 arch specific flags to arch mmu flags */
	if (flags)
		*flags = ret_flags;

	return TEE_SUCCESS;
}

static int arch_mmu_map(vaddr_t vaddr, paddr_t paddr,
				unsigned int count, arch_flags_t flags, uint8_t id)
{
	struct map_range range;

	FMSG(">vaddr 0x%lx paddr 0x%lx count 0x%x flags 0x%lx\n",
			vaddr, paddr, count, flags);

	if ((!x86_mmu_check_paddr(paddr)))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!x86_mmu_check_vaddr(vaddr))
		return TEE_ERROR_BAD_PARAMETERS;

	if (count == 0)
		return TEE_SUCCESS;

	range.start_vaddr = vaddr;
	range.start_paddr = paddr;
	range.size = count;

	return x86_mmu_map_range(virt_to_phys((void *)&g_thread_pml4[id][0]),
								&range, flags, id);
}

static void init_kernel_mmu_table(void)
{
    uint8_t thread_id;

	// set up page table for kernel space
	memcpy(g_pdp, g_thread_pdp[0], sizeof(uint64_t) * NO_OF_PDP_ENTRIES);
	g_pml4[0] = (g_thread_pml4[0][0] & X86_FLAGS_MASK) |
			((uint64_t)&g_pdp[0] & X86_PG_PA_FRAME);

	// set up page table for other threads
	for (thread_id=1; thread_id<CFG_NUM_THREADS; thread_id++) {
		memcpy(g_thread_pdp[thread_id], g_thread_pdp[0], sizeof(uint64_t) * NO_OF_PDP_ENTRIES);

		g_thread_pml4[thread_id][0] = (g_thread_pml4[0][0] & X86_FLAGS_MASK) |
			((uint64_t)&g_thread_pdp[thread_id][0] & X86_PG_PA_FRAME);
	}

}

static struct tee_mmap_region *init_xlation_table(struct tee_mmap_region *mm,
				uint64_t base_va __unused, unsigned int level)
{
	int ret;

	assert(level <= 3);

	FMSG("base_va 0x%lx level %u\n", base_va, level);
	FMSG("%s pa 0x%lx va 0x%lx size 0x%zx region_size 0x%x attr %d",
			teecore_memtype_name(mm->type), mm->pa, mm->va,
			mm->size, mm->region_size, mm->attr);

	for ( ; !core_mmap_is_end_of_table(mm) ; mm++) {
		if (core_mmu_is_dynamic_vaspace(mm)) {
			DMSG("SKIP %s", teecore_memtype_name(mm->type));
			continue;
		}

		DMSG("%s (%d) va 0x%lx pa 0x%lx size 0x%zx region_size 0x%x attr 0x%x",
			teecore_memtype_name(mm->type),
			mm->type, mm->va, mm->pa,
			mm->size, mm->region_size, mm->attr);

		print_memory_attr(mm->attr);

		// build kernel MMU table for thread 0 firstly.
		ret = arch_mmu_map(mm->va, mm->pa, mm->size,
						get_x86_arch_flags(mm->attr), 0);

		if (ret) {
			DMSG("%d\n", ret);
			panic("arch_mmu_map FAIL");
		}
	}

	// set up kernel MMU table for other threads.
	init_kernel_mmu_table();

	return mm;
}

bool core_mmu_user_mapping_is_active(void)
{
	bool ret = true;

	if (x86_get_cr3() == ((uint64_t)&g_pml4[0]))
		ret = false;

	return ret;
}

//TODO: this macro should be defined in each platform head file
#define TA_USER_BASE_VA 0xF0000000
/* Function returns user space virtual start address and size of area. */
void core_mmu_get_user_va_range(vaddr_t *base, size_t *size)
{
	if (base)
		*base = TA_USER_BASE_VA;
	if (size)
		*size = TA_RAM_SIZE;
}

static void clear_user_map(short int thread_id)
{
	memset((void *)&g_thread_user_ta_pd[thread_id][0],
			0, sizeof(g_thread_user_ta_pd[thread_id]));

	memset((void *)&g_thread_user_ta_pte[thread_id][0][0], 0,
			(sizeof(uint64_t) * NO_OF_USER_PT_TABLES * NO_OF_PT_ENTRIES));

	pt_user_index[thread_id] = 0;
}

void core_mmu_get_user_map(struct core_mmu_user_map *map)
{
	map->cr3 = x86_get_cr3();
}

void core_mmu_set_user_map(struct core_mmu_user_map *map)
{
	if (map == NULL)
		x86_set_cr3((uint64_t)&g_pml4[0]);
	else
		x86_set_cr3(map->cr3);
}

void core_mmu_create_user_map(struct user_mode_ctx *uctx,
				struct core_mmu_user_map *map)
{
	struct vm_region *r;
	short int thread_id = thread_get_id();
	int ret;

	clear_user_map(thread_id);

	TAILQ_FOREACH(r, &((uctx->vm_info).regions), link) {
		paddr_t pa = 0;

		if (r->mobj && r->va != 0) {

			mobj_get_pa(r->mobj, r->offset, 0, &pa);

			ret = arch_mmu_map(r->va, pa, r->size,
					(X86_MMU_PG_G | get_x86_arch_flags(r->attr)), thread_id);

			if (ret) {
				EMSG("%d\n", ret);
				panic("arch_mmu_map FAIL");
			}
		}
	}

	/* Flush TLB */
	x86_set_cr3(x86_get_cr3());

	map->cr3 = (uint64_t)&g_thread_pml4[thread_id][0];
}

bool core_mmu_mattr_is_ok(uint32_t mattr)
{
	/*
	 * Keep in sync with core_mmu_lpae.c:mattr_to_desc and
	 * core_mmu_v7.c:mattr_to_texcb
	 */

	switch ((mattr >> TEE_MATTR_CACHE_SHIFT) & TEE_MATTR_CACHE_MASK) {
	case TEE_MATTR_CACHE_NONCACHE:
	case TEE_MATTR_CACHE_CACHED:
		return true;
	default:
		return false;
	}
}

/*
 * test attributes of target physical buffer
 *
 * Flags: pbuf_is(SECURE, NOT_SECURE, RAM, IOMEM, KEYVAULT).
 *
 */
bool core_pbuf_is(uint32_t attr, paddr_t pbuf, size_t len)
{
	struct tee_mmap_region *map;

	/* Empty buffers complies with anything */
	if (len == 0)
		return true;

	switch (attr) {
	case CORE_MEM_SEC:
		return pbuf_is_inside(secure_only, pbuf, len);
	case CORE_MEM_NON_SEC:
		return pbuf_is_inside(nsec_shared, pbuf, len) ||
			pbuf_is_nsec_ddr(pbuf, len);
	case CORE_MEM_TEE_RAM:
		return core_is_buffer_inside(pbuf, len, TEE_RAM_START,
							TEE_RAM_PH_SIZE);
	case CORE_MEM_TA_RAM:
		return core_is_buffer_inside(pbuf, len, TA_RAM_START,
							TA_RAM_SIZE);
#ifdef CFG_CORE_RESERVED_SHM
	case CORE_MEM_NSEC_SHM:
		return core_is_buffer_inside(pbuf, len, TEE_SHMEM_START,
							TEE_SHMEM_SIZE);
#endif
	case CORE_MEM_SDP_MEM:
		return pbuf_is_sdp_mem(pbuf, len);
	case CORE_MEM_CACHED:
		map = find_map_by_pa(pbuf);
		if (map == NULL || !pbuf_inside_map_area(pbuf, len, map))
			return false;
		return map->attr >> TEE_MATTR_CACHE_SHIFT ==
		       TEE_MATTR_CACHE_CACHED;
	default:
		return false;
	}
}

/* test attributes of target virtual buffer (in core mapping) */
bool core_vbuf_is(uint32_t attr, const void *vbuf, size_t len)
{
	paddr_t p;

	/* Empty buffers complies with anything */
	if (len == 0)
		return true;

	p = virt_to_phys((void *)vbuf);
	if (!p)
		return false;

	return core_pbuf_is(attr, p, len);
}

static void *map_pa2va(struct tee_mmap_region *map, paddr_t pa)
{
	if (!pa_is_in_map(map, pa))
		return NULL;

	return (void *)(vaddr_t)(map->va + pa - map->pa);
}

/*
 * teecore gets some memory area definitions
 */
void core_mmu_get_mem_by_type(unsigned int type, vaddr_t *s, vaddr_t *e)
{
	struct tee_mmap_region *map = find_map_by_type(type);

	if (map) {
		*s = map->va;
		*e = map->va + map->size;
	} else {
		*s = 0;
		*e = 0;
	}
}

enum teecore_memtypes core_mmu_get_type_by_pa(paddr_t pa)
{
	struct tee_mmap_region *map = find_map_by_pa(pa);

	if (!map)
		return MEM_AREA_MAXTYPE;
	return map->type;
}

struct mmu_partition {
	unsigned int test;
};

bool core_mmu_find_table(struct mmu_partition *prtn, vaddr_t va, unsigned int max_level,
		struct core_mmu_table_info *tbl_info)
{
	//TODO: maybe need to disable interrupt here.
	uint64_t *tbl = &g_thread_pml4[thread_get_id()][0];
	uintptr_t ntbl;
	unsigned int level = 1;
	vaddr_t va_base = 0;
	unsigned int num_entries = NO_OF_PML4_ENTRIES;

	(void) prtn;

	while (true) {
		unsigned int level_size_shift = (level - 1);
		unsigned int n = (va - va_base) >> level_size_shift;

		if (n >= num_entries)
			return false;

		if (level == max_level || level == 3) {
			/*
			 * We've either reached max_level, level 3, a block
			 * mapping entry or an "invalid" mapping entry.
			 */
			tbl_info->table = tbl;
			tbl_info->va_base = va_base;
			tbl_info->level = level;
			tbl_info->shift = level_size_shift;
			tbl_info->num_entries = num_entries;

			return true;
		}

		/* Copy bits 39:12 from tbl[n] to ntbl */
		ntbl = (tbl[n] & ((1ULL << 40) - 1)) & ~((1 << 12) - 1);

		tbl = phys_to_virt(ntbl, MEM_AREA_TEE_RAM_RW_DATA);
		if (!tbl)
			return false;

		va_base += (vaddr_t)n << level_size_shift;
		level++;
		num_entries = NO_OF_PT_ENTRIES;
	}
}

void tlbi_mva_range(vaddr_t va, size_t len, size_t granule)
{
	assert(granule == CORE_MMU_PGDIR_SIZE || granule == SMALL_PAGE_SIZE);
	assert(!(va & (granule - 1)) && !(len & (granule - 1)));

	while (len) {
		tlbi_mva_allasid_nosync(va);
		len -= granule;
		va += granule;
	}
}

void tlbi_mva_range_asid(vaddr_t va, size_t len, size_t granule, uint32_t asid)
{
	assert(granule == CORE_MMU_PGDIR_SIZE || granule == SMALL_PAGE_SIZE);
	assert(!(va & (granule - 1)) && !(len & (granule - 1)));

	while (len) {
		tlbi_mva_asid_nosync(va, asid);
		len -= granule;
		va += granule;
	}
}

static int cache_tlb_inv(void *va, size_t length)
{
	vaddr_t next_aligned_v_addr;
	paddr_t pa;

	pa = virt_to_phys(va);
	if (!pa)
		return TEE_ERROR_ACCESS_DENIED;

	if (length == 0)
		return TEE_SUCCESS;

	next_aligned_v_addr = (vaddr_t)va;
	while (length > 0) {
		__asm__ volatile(
				"invlpg (%0)"
				:: "r" (next_aligned_v_addr)
				: "memory");
		next_aligned_v_addr += PAGE_SIZE;
		length--;
	}

	return TEE_SUCCESS;
}

TEE_Result cache_op_inner(enum cache_op op, void *va, size_t len)
{
	TEE_Result ret = TEE_SUCCESS;

	switch (op) {
	case ICACHE_INVALIDATE:
	case DCACHE_INVALIDATE:
	case ICACHE_AREA_INVALIDATE:
	case DCACHE_AREA_INVALIDATE:
		invd();
		break;
	case DCACHE_CLEAN:
	case DCACHE_CLEAN_INV:
	case DCACHE_AREA_CLEAN:
	case DCACHE_AREA_CLEAN_INV:
		wbinvd();
		break;
	case DCACHE_TLB_INVALIDATE:
		ret = cache_tlb_inv(va, len);
		break;
	default:
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	mfence();
	return ret;
}

void core_mmu_set_entry_primitive(void *table, size_t level __unused,
				size_t idx, paddr_t pa, uint32_t attr)
{
	uint64_t *tbl = table;
	uint64_t desc = get_x86_arch_flags(attr);

	tbl[idx] = desc | pa;
}

void core_mmu_set_entry(struct core_mmu_table_info *tbl_info, unsigned idx,
			paddr_t pa, uint32_t attr)
{
	assert(idx < tbl_info->num_entries);
	core_mmu_set_entry_primitive(tbl_info->table, tbl_info->level,
				     idx, pa, attr);
}

void core_mmu_get_entry_primitive(const void *table,
			size_t level __unused, size_t idx,
			paddr_t *pa, uint32_t *attr)
{
	const uint64_t *tbl = table;

	if (pa)
		*pa = (tbl[idx] & X86_PG_PA_FRAME) >> X86_PD_PA_POS;

	if (attr)
		*attr = get_arch_mmu_flags(tbl[idx]);
}

void core_mmu_get_entry(struct core_mmu_table_info *tbl_info, unsigned idx,
			paddr_t *pa, uint32_t *attr)
{
	assert(idx < tbl_info->num_entries);
	core_mmu_get_entry_primitive(tbl_info->table, tbl_info->level,
				     idx, pa, attr);
}

static void set_region(struct core_mmu_table_info *tbl_info,
		struct tee_mmap_region *region)
{
	unsigned end;
	unsigned idx;
	paddr_t pa;

	/* va, len and pa should be block aligned */
	assert(!core_mmu_get_block_offset(tbl_info, region->va));
	assert(!core_mmu_get_block_offset(tbl_info, region->size));
	assert(!core_mmu_get_block_offset(tbl_info, region->pa));

	idx = core_mmu_va2idx(tbl_info, region->va);
	end = core_mmu_va2idx(tbl_info, region->va + region->size);
	pa = region->pa;

	while (idx < end) {
		core_mmu_set_entry(tbl_info, idx, pa, region->attr);
		idx++;
		pa += 1 << tbl_info->shift;
	}
}

TEE_Result core_mmu_map_pages(vaddr_t vstart, paddr_t *pages, size_t num_pages,
			      enum teecore_memtypes memtype)
{
	TEE_Result ret;
	struct core_mmu_table_info tbl_info;
	struct tee_mmap_region *mm;
	unsigned int idx;
	uint32_t old_attr;
	uint32_t exceptions;
	vaddr_t vaddr = vstart;
	size_t i;

	assert(!(core_mmu_type_to_attr(memtype) & TEE_MATTR_PX));

	if (vaddr & SMALL_PAGE_MASK)
		return TEE_ERROR_BAD_PARAMETERS;

	exceptions = mmu_lock();

	mm = find_map_by_va((void *)vaddr);
	if (!mm || !va_is_in_map(mm, vaddr + num_pages * SMALL_PAGE_SIZE - 1))
		panic("VA does not belong to any known mm region");

	if (!core_mmu_is_dynamic_vaspace(mm))
		panic("Trying to map into static region");

	for (i = 0; i < num_pages; i++) {
		if (pages[i] & SMALL_PAGE_MASK) {
			ret = TEE_ERROR_BAD_PARAMETERS;
			goto err;
		}

		while (true) {
			if (!core_mmu_find_table(NULL, vaddr, UINT_MAX,
						 &tbl_info))
				panic("Can't find pagetable for vaddr ");

			idx = core_mmu_va2idx(&tbl_info, vaddr);
			if (tbl_info.shift == SMALL_PAGE_SHIFT)
				break;
		}

		core_mmu_get_entry(&tbl_info, idx, NULL, &old_attr);
		if (old_attr)
			panic("Page is already mapped");

		core_mmu_set_entry(&tbl_info, idx, pages[i],
				   core_mmu_type_to_attr(memtype));
		vaddr += SMALL_PAGE_SIZE;
	}

	/*
	 * Make sure all the changes to translation tables are visible
	 * before returning. TLB doesn't need to be invalidated as we are
	 * guaranteed that there's no valid mapping in this range.
	 */
	mmu_unlock(exceptions);

	return TEE_SUCCESS;
err:
	mmu_unlock(exceptions);

	if (i)
		core_mmu_unmap_pages(vstart, i);

	return ret;
}

void core_mmu_unmap_pages(vaddr_t vstart, size_t num_pages)
{
	struct core_mmu_table_info tbl_info;
	struct tee_mmap_region *mm;
	size_t i;
	unsigned int idx;
	uint32_t exceptions;

	exceptions = mmu_lock();

	mm = find_map_by_va((void *)vstart);
	if (!mm || !va_is_in_map(mm, vstart + num_pages * SMALL_PAGE_SIZE - 1))
		panic("VA does not belong to any known mm region");

	if (!core_mmu_is_dynamic_vaspace(mm))
		panic("Trying to unmap static region");

	for (i = 0; i < num_pages; i++, vstart += SMALL_PAGE_SIZE) {
		if (!core_mmu_find_table(NULL, vstart, UINT_MAX, &tbl_info))
			panic("Can't find pagetable");

		if (tbl_info.shift != SMALL_PAGE_SHIFT)
			panic("Invalid pagetable level");

		idx = core_mmu_va2idx(&tbl_info, vstart);
		core_mmu_set_entry(&tbl_info, idx, 0, 0);
	}
	tlbi_all();

	mmu_unlock(exceptions);
}

bool core_mmu_add_mapping(enum teecore_memtypes type, paddr_t addr, size_t len)
{
	struct core_mmu_table_info tbl_info;
	struct tee_mmap_region *map;
	size_t n;
	size_t granule;
	paddr_t p;
	size_t l;

	if (!len)
		return true;

	/* Check if the memory is already mapped */
	map = find_map_by_type_and_pa(type, addr);
	if (map && pbuf_inside_map_area(addr, len, map))
		return true;

	/* Find the reserved va space used for late mappings */
	map = find_map_by_type(MEM_AREA_RES_VASPACE);
	if (!map)
		return false;

	if (!core_mmu_find_table(NULL, map->va, UINT_MAX, &tbl_info))
		return false;

	granule = 1 << tbl_info.shift;
	p = ROUNDDOWN(addr, granule);
	l = ROUNDUP(len + addr - p, granule);

	/* Ban overflowing virtual addresses */
	if (map->size < l)
		return false;

	/*
	 * Something is wrong, we can't fit the va range into the selected
	 * table. The reserved va range is possibly missaligned with
	 * granule.
	 */
	if (core_mmu_va2idx(&tbl_info, map->va + len) >= tbl_info.num_entries)
		return false;

	/* Find end of the memory map */
	n = 0;
	while (!core_mmap_is_end_of_table(static_memory_map + n))
		n++;

	if (n < (ARRAY_SIZE(static_memory_map) - 1)) {
		/* There's room for another entry */
		static_memory_map[n].va = map->va;
		static_memory_map[n].size = l;
		static_memory_map[n + 1].type = MEM_AREA_END;
		map->va += l;
		map->size -= l;
		map = static_memory_map + n;
	} else {
		/*
		 * There isn't room for another entry, steal the reserved
		 * entry as it's not useful for anything else any longer.
		 */
		map->size = l;
	}
	map->type = type;
	map->region_size = granule;
	map->attr = core_mmu_type_to_attr(type);
	map->pa = p;

	set_region(&tbl_info, map);

	return true;
}

unsigned int asid_alloc(void)
{
	uint32_t exceptions = cpu_spin_lock_xsave(&g_asid_spinlock);
	unsigned int r;
	int i;

	bit_ffc(g_asid, MMU_NUM_ASID_PAIRS, &i);
	if (i == -1) {
		r = 0;
	} else {
		bit_set(g_asid, i);
		r = (i + 1) * 2;
	}

	cpu_spin_unlock_xrestore(&g_asid_spinlock, exceptions);
	return r;
}

void asid_free(unsigned int asid)
{
	uint32_t exceptions = cpu_spin_lock_xsave(&g_asid_spinlock);

	/* Only even ASIDs are supposed to be allocated */
	assert(!(asid & 1));

	if (asid) {
		int i = (asid - 1) / 2;

		assert(i < MMU_NUM_ASID_PAIRS && bit_test(g_asid, i));
		bit_clear(g_asid, i);
	}

	cpu_spin_unlock_xrestore(&g_asid_spinlock, exceptions);
}

#ifdef CFG_WITH_PAGER
static vaddr_t get_linear_map_end(void)
{
	/* this is synced with the generic linker file kern.ld.S */
	return (vaddr_t)__heap2_end;
}
#endif

paddr_t virt_to_phys(void *va)
{
	paddr_t pa;
	int rc;

	rc = arch_mmu_query((vaddr_t)va, &pa, NULL);
	if (rc)
		return (paddr_t)NULL;

	return pa;
}

#if defined(CFG_TEE_CORE_DEBUG)
static void check_va_matches_pa(paddr_t pa, void *va)
{
	paddr_t p = 0;

	if (!va)
		return;

	p = virt_to_phys(va);
	if (p != pa) {
		DMSG("va %p maps 0x%" PRIxPA " expect 0x%" PRIxPA, va, p, pa);
		panic();
	}
}
#else
static void check_va_matches_pa(paddr_t pa __unused, void *va __unused)
{
}
#endif

static void *phys_to_virt_ta_vaspace(paddr_t pa)
{
	if (!core_mmu_user_mapping_is_active())
		return NULL;

	return vm_pa2va(to_user_mode_ctx(thread_get_tsd()->ctx), pa);
}

#ifdef CFG_WITH_PAGER
static void *phys_to_virt_tee_ram(paddr_t pa)
{
	if (pa >= TEE_LOAD_ADDR && pa < get_linear_map_end())
		return (void *)(vaddr_t)(pa + boot_mmu_config.load_offset);
	return tee_pager_phys_to_virt(pa);
}
#else
static void *phys_to_virt_tee_ram(paddr_t pa)
{
	struct tee_mmap_region *mmap = NULL;

	mmap = find_map_by_type_and_pa(MEM_AREA_TEE_RAM, pa);
	if (!mmap)
		mmap = find_map_by_type_and_pa(MEM_AREA_NEX_RAM_RW, pa);
	if (!mmap)
		mmap = find_map_by_type_and_pa(MEM_AREA_TEE_RAM_RW, pa);
	if (!mmap)
		mmap = find_map_by_type_and_pa(MEM_AREA_TEE_RAM_RO, pa);
	if (!mmap)
		mmap = find_map_by_type_and_pa(MEM_AREA_TEE_RAM_RX, pa);

	return map_pa2va(mmap, pa);
}
#endif

void *phys_to_virt(paddr_t pa, enum teecore_memtypes m)
{
	void *va = NULL;

	switch (m) {
	case MEM_AREA_TA_VASPACE:
		va = phys_to_virt_ta_vaspace(pa);
		break;
	case MEM_AREA_TEE_RAM:
	case MEM_AREA_TEE_RAM_RX:
	case MEM_AREA_TEE_RAM_RO:
	case MEM_AREA_TEE_RAM_RW:
	case MEM_AREA_NEX_RAM_RW:
		va = phys_to_virt_tee_ram(pa);
		break;
	case MEM_AREA_SHM_VASPACE:
		/* Find VA from PA in dynamic SHM is not yet supported */
		va = NULL;
		break;
	default:
		va = map_pa2va(find_map_by_type_and_pa(m, pa), pa);
	}
	if (m != MEM_AREA_SEC_RAM_OVERALL)
		check_va_matches_pa(pa, va);
	return va;
}

void *phys_to_virt_io(paddr_t pa)
{
	struct tee_mmap_region *map = NULL;
	void *va = NULL;

	map = find_map_by_type_and_pa(MEM_AREA_IO_SEC, pa);
	if (!map)
		map = find_map_by_type_and_pa(MEM_AREA_IO_NSEC, pa);
	if (!map)
		return NULL;
	va = map_pa2va(map, pa);
	check_va_matches_pa(pa, va);
	return va;
}

bool cpu_mmu_enabled(void)
{
	if ((X86_CR0_PG & x86_get_cr0()) && optee_mem_structs_ready)
		return true;

	return false;
}

vaddr_t core_mmu_get_va(paddr_t pa, enum teecore_memtypes type)
{
	if (cpu_mmu_enabled())
		return (vaddr_t)phys_to_virt(pa, type);

	return (vaddr_t)pa;
}

#ifdef CFG_WITH_PAGER
bool is_unpaged(void *va)
{
	vaddr_t v = (vaddr_t)va;

	return v >= VCORE_START_VA && v < get_linear_map_end();
}
#else
bool is_unpaged(void *va __unused)
{
	return true;
}
#endif

#ifdef CFG_VIRTUALIZATION
void core_mmu_init_virtualization(void)
{
	virt_init_memory(static_memory_map);
}
#endif

vaddr_t io_pa_or_va(struct io_pa_va *p)
{
	assert(p->pa);
	if (cpu_mmu_enabled()) {
		if (!p->va)
			p->va = (vaddr_t)phys_to_virt_io(p->pa);
		assert(p->va);
		return p->va;
	}
	return p->pa;
}

vaddr_t io_pa_or_va_secure(struct io_pa_va *p)
{
	assert(p->pa);
	if (cpu_mmu_enabled()) {
		if (!p->va)
			p->va = (vaddr_t)phys_to_virt(p->pa, MEM_AREA_IO_SEC);
		assert(p->va);
		return p->va;
	}
	return p->pa;
}

vaddr_t io_pa_or_va_nsec(struct io_pa_va *p)
{
	assert(p->pa);
	if (cpu_mmu_enabled()) {
		if (!p->va)
			p->va = (vaddr_t)phys_to_virt(p->pa, MEM_AREA_IO_NSEC);
		assert(p->va);
		return p->va;
	}
	return p->pa;
}

#ifdef CFG_CORE_RESERVED_SHM
static TEE_Result teecore_init_pub_ram(void)
{
	vaddr_t s = 0;
	vaddr_t e = 0;

	/* get virtual addr/size of NSec shared mem allocated from teecore */
	core_mmu_get_mem_by_type(MEM_AREA_NSEC_SHM, &s, &e);

	if (s >= e || s & SMALL_PAGE_MASK || e & SMALL_PAGE_MASK)
		panic("invalid PUB RAM");

	/* extra check: we could rely on core_mmu_get_mem_by_type() */
	if (!tee_vbuf_is_non_sec(s, e - s))
		panic("PUB RAM is not non-secure");

#ifdef CFG_PL310
	/* Allocate statically the l2cc mutex */
	tee_l2cc_store_mutex_boot_pa(virt_to_phys((void *)s));
	s += sizeof(uint32_t);			/* size of a pl310 mutex */
	s = ROUNDUP(s, SMALL_PAGE_SIZE);	/* keep required alignment */
#endif

	default_nsec_shm_paddr = virt_to_phys((void *)s);
	default_nsec_shm_size = e - s;

	return TEE_SUCCESS;
}
early_init(teecore_init_pub_ram);
#endif /*CFG_CORE_RESERVED_SHM*/

void core_mmu_init_ta_ram(void)
{
	vaddr_t s = 0;
	vaddr_t e = 0;
	paddr_t ps = 0;
	paddr_t pe = 0;

	/*
	 * Get virtual addr/size of RAM where TA are loaded/executedNSec
	 * shared mem allocated from teecore.
	 */
#ifndef CFG_VIRTUALIZATION
	core_mmu_get_mem_by_type(MEM_AREA_TA_RAM, &s, &e);
#else
	virt_get_ta_ram(&s, &e);
#endif
	ps = virt_to_phys((void *)s);
	pe = virt_to_phys((void *)(e - 1)) + 1;

	if (!ps || (ps & CORE_MMU_USER_CODE_MASK) ||
	    !pe || (pe & CORE_MMU_USER_CODE_MASK))
		panic("invalid TA RAM");

	/* extra check: we could rely on core_mmu_get_mem_by_type() */
	if (!tee_pbuf_is_sec(ps, pe - ps))
		panic("TA RAM is not secure");

	if (!tee_mm_is_empty(&tee_mm_sec_ddr))
		panic("TA RAM pool is not empty");

	/* remove previous config and init TA ddr memory pool */
	tee_mm_final(&tee_mm_sec_ddr);
	tee_mm_init(&tee_mm_sec_ddr, ps, pe, CORE_MMU_USER_CODE_SHIFT,
		    TEE_MM_POOL_NO_FLAGS);
}

/*
 * core_mmu_init - early init tee core mmu function
 *
 * this routine makes default setting for tee core mmu.
 */
void core_mmu_init(void)
{
	uint64_t efer_msr, cr4;
	uint32_t addr_width = 0;

	/* enable caches */
	clear_in_cr0(X86_CR0_NW | X86_CR0_CD);

	/* Set WP bit in CR0*/
	set_in_cr0(X86_CR0_WP);

	/* Setting the SMEP & SMAP bit in CR4 */
	cr4 = x86_get_cr4();
	if (check_smep_avail())
		cr4 |= X86_CR4_SMEP;
	/* TODO: will figure out how to enable SMAP */
	/*if (check_smap_avail())
		cr4 |= X86_CR4_SMAP;*/
	x86_set_cr4(cr4);

	/* Set NXE bit in MSR_EFER*/
	efer_msr = read_msr(x86_MSR_EFER);
	efer_msr |= x86_EFER_NXE;
	write_msr(x86_MSR_EFER, efer_msr);

	/* getting the address width from CPUID instr */
	/* Bits 07-00: Physical Address width info */
	/* Bits 15-08: Linear Address width info */
	addr_width = x86_get_address_width();
	g_paddr_width = (uint8_t)(addr_width & 0xFF);
	g_vaddr_width = (uint8_t)((addr_width >> 8) & 0xFF);
}
