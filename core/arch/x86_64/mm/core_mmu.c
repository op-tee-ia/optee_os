// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Intel Corporation
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <kernel/trace_control_by_service.h>
#ifndef TRACE_SERV_MMU
#undef TRACE_LEVEL
#define TRACE_LEVEL 0
#endif

#include <assert.h>
#include <bitstring.h>
#include <kernel/generic_boot.h>
#include <kernel/linker.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <kernel/tlb_helpers.h>
#include <kernel/tee_l2cc_mutex.h>
#include <kernel/tee_misc.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/mobj.h>
#include <mm/pgt_cache.h>
#include <mm/tee_mmu.h>
#include <mm/tee_pager.h>
#include <platform_config.h>
#include <stdlib.h>
#include <trace.h>
#include <util.h>
#include <x86.h>
#include <console.h>
#include <kernel/user_ta.h>


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

/* MMU tables for runtime usage for kernel */
uint64_t g_pml4[NO_OF_PML4_ENTRIES] __aligned(PAGE_SIZE);
uint64_t g_pdp[NO_OF_PDP_ENTRIES] __aligned(PAGE_SIZE);
uint64_t g_pd[NO_OF_PD_ENTRIES] __aligned(PAGE_SIZE);
uint64_t g_pte[NO_OF_PT_TABLES][NO_OF_PT_ENTRIES] __aligned(PAGE_SIZE);

/* MMU tables for runtime usage for user mode */
uint64_t g_user_ta_pd[NO_OF_USER_PD_ENTRIES] __aligned(PAGE_SIZE);
uint64_t g_user_ta_pte[NO_OF_USER_PT_TABLES][NO_OF_PT_ENTRIES]
			__aligned(PAGE_SIZE);
uint32_t pd_user_counter;
uint32_t pt_user_index;


/* Default NSec shared memory allocated from NSec world */
unsigned long default_nsec_shm_size __nex_bss;
unsigned long default_nsec_shm_paddr __nex_bss;

static struct tee_mmap_region
	static_memory_map[CFG_MMAP_REGIONS + 1] __nex_bss;

#define PRINT_MATTR_BIT(value, bit) \
	{FMSG(#bit " %s\n", ((value & bit) ? "SET" : "CLEAR")); }

/* Define the platform's memory layout. */
struct memaccess_area {
	paddr_t paddr;
	size_t size;
};
#define MEMACCESS_AREA(a, s) { .paddr = a, .size = s }

static struct memaccess_area secure_only[] __nex_data= {
#ifdef TZSRAM_BASE
	MEMACCESS_AREA(TZSRAM_BASE, TZSRAM_SIZE),
#endif
	MEMACCESS_AREA(TZDRAM_BASE, TZDRAM_SIZE),
};

static struct memaccess_area nsec_shared[] __nex_data = {
	MEMACCESS_AREA(TEE_SHMEM_START, TEE_SHMEM_SIZE),
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
register_phys_mem_ul(MEM_AREA_TEE_RAM_RX, VCORE_UNPG_RX_PA, VCORE_UNPG_RX_SZ);
register_phys_mem_ul(MEM_AREA_TEE_RAM_RO, VCORE_UNPG_RO_PA, VCORE_UNPG_RO_SZ);
register_phys_mem_ul(MEM_AREA_TEE_RAM_RW, VCORE_UNPG_RW_PA, VCORE_UNPG_RW_SZ);
#ifdef CFG_VIRTUALIZATION
register_phys_mem_ul(MEM_AREA_NEX_RAM_RW, VCORE_NEX_RW_PA, VCORE_NEX_RW_SZ);
#endif
#ifdef CFG_WITH_PAGER
register_phys_mem_ul(MEM_AREA_TEE_RAM_RX, VCORE_INIT_RX_PA, VCORE_INIT_RX_SZ);
register_phys_mem_ul(MEM_AREA_TEE_RAM_RO, VCORE_INIT_RO_PA, VCORE_INIT_RO_SZ);
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

register_phys_mem(MEM_AREA_TA_RAM, TA_RAM_START, TA_RAM_SIZE);
register_phys_mem(MEM_AREA_NSEC_SHM, TEE_SHMEM_START, TEE_SHMEM_SIZE);

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

static void clear_user_map(void)
{
	int row = ARRAY_SIZE(g_user_ta_pte);
	int i;

	memset((void *)&g_user_ta_pd[0], 0, sizeof(g_user_ta_pd));

	for (i = 0 ; i < row ; i++)
		memset((void *)&g_user_ta_pte[i][0], 0,
				sizeof(g_user_ta_pte[0]));

	pd_user_counter = 0;
	pt_user_index = 0;
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

	for (map = static_memory_map; !core_mmap_is_end_of_table(map); map++)
		if (map->type == type)
			return map;
	return NULL;
}

static struct tee_mmap_region *find_map_by_type_and_pa(
			enum teecore_memtypes type, paddr_t pa)
{
	struct tee_mmap_region *map;

	for (map = static_memory_map; !core_mmap_is_end_of_table(map); map++) {
		if (map->type != type)
			continue;
		if (pa_is_in_map(map, pa))
			return map;
	}
	return NULL;
}

static struct tee_mmap_region *find_map_by_va(void *va)
{
	struct tee_mmap_region *map = static_memory_map;
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
	struct tee_mmap_region *map = static_memory_map;

	while (!core_mmap_is_end_of_table(map)) {
		if ((pa >= map->pa) && (pa < (map->pa + map->size)))
			return map;
		map++;
	}
	return NULL;
}

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

#if 0
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
		m = realloc(m, sizeof(*m) * *nelems);
		if (!m)
			panic();
		*mem = m;
	} else if (pa == m[n].addr) {
		m[n].addr += size;
	} else if ((pa + size) == (m[n].addr + m[n].size)) {
		m[n].size -= size;
	} else {
		/* Need to split the memory entry */
		m = realloc(m, sizeof(*m) * (*nelems + 1));
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

void core_mmu_set_discovered_nsec_ddr(struct core_mmu_phys_mem *start,
				      size_t nelems)
{
	struct core_mmu_phys_mem *m = start;
	size_t num_elems = nelems;
	struct tee_mmap_region *map = static_memory_map;
	const struct core_mmu_phys_mem __maybe_unused *pmem;
	paddr_t pa;

	assert(!discovered_nsec_ddr_start);
	assert(m && num_elems);

	qsort(m, num_elems, sizeof(*m), cmp_pmem_by_addr);

	/*
	 * Non-secure shared memory and also secure data
	 * path memory are supposed to reside inside
	 * non-secure memory. Since NSEC_SHM and SDP_MEM
	 * are used for a specific purpose make holes for
	 * those memory in the normal non-secure memory.
	 *
	 * This has to be done since for instance QEMU
	 * isn't aware of which memory range in the
	 * non-secure memory is used for NSEC_SHM.
	 */

#ifdef CFG_SECURE_DATA_PATH
	for (pmem = phys_sdp_mem_begin; pmem < phys_sdp_mem_end; pmem++)
		carve_out_phys_mem(&m, &num_elems, pmem->addr, pmem->size);
#endif

	for (map = static_memory_map; core_mmap_is_end_of_table(map); map++) {
		if (map->type == MEM_AREA_NSEC_SHM)
			carve_out_phys_mem(&m, &num_elems, map->pa, map->size);
		else
			check_phys_mem_is_outside(m, num_elems, map);
	}

	discovered_nsec_ddr_start = m;
	discovered_nsec_ddr_nelems = num_elems;

	if (ADD_OVERFLOW(m[num_elems - 1].addr, m[num_elems - 1].size - 1, &pa))
		panic();
	core_mmu_set_max_pa(pa);
}
#endif

static bool get_discovered_nsec_ddr(const struct core_mmu_phys_mem **start __unused,
			const struct core_mmu_phys_mem **end __unused)
{
	return false;
}

static bool pbuf_is_nsec_ddr(paddr_t pbuf, size_t len)
{
	const struct core_mmu_phys_mem *start;
	const struct core_mmu_phys_mem *end;

	if (!get_discovered_nsec_ddr(&start, &end)) {
			start = phys_nsec_ddr_begin;
			end = phys_nsec_ddr_end;
	}

	return pbuf_is_special_mem(pbuf, len, start, end);
}

bool core_mmu_nsec_ddr_is_defined(void)
{
	const struct core_mmu_phys_mem *start;
	const struct core_mmu_phys_mem *end;

	if (!get_discovered_nsec_ddr(&start, &end)) {
			start = phys_nsec_ddr_begin;
			end = phys_nsec_ddr_end;
	}

	return start != end;
}

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

static void check_sdp_intersection_with_nsec_ddr(void)
{
	const struct core_mmu_phys_mem *sdp_start = phys_sdp_mem_begin;
	const struct core_mmu_phys_mem *sdp_end = phys_sdp_mem_end;
	const struct core_mmu_phys_mem *ddr_start = phys_nsec_ddr_begin;
	const struct core_mmu_phys_mem *ddr_end = phys_nsec_ddr_end;
	const struct core_mmu_phys_mem *sdp;
	const struct core_mmu_phys_mem *nsec_ddr;

	if (sdp_start == sdp_end || ddr_start == ddr_end)
		return;

	for (sdp = sdp_start; sdp < sdp_end; sdp++) {
		for (nsec_ddr = ddr_start; nsec_ddr < ddr_end; nsec_ddr++) {
			if (core_is_buffer_intersect(sdp->addr, sdp->size,
					     nsec_ddr->addr, nsec_ddr->size)) {
				MSG_MEM_INSTERSECT(sdp->addr, sdp->size,
						   nsec_ddr->addr,
						   nsec_ddr->size);
				panic("SDP <-> NSEC DDR memory intersection");
			}
		}
	}
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
	for (mem = start; mem < end - 1; mem++) {
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
	 *
	 * Only exception is with MEM_AREA_RAM_NSEC and MEM_AREA_NSEC_SHM,
	 * which may overlap since they are used for the same purpose
	 * except that MEM_AREA_NSEC_SHM is always mapped and
	 * MEM_AREA_RAM_NSEC only uses a dynamic mapping.
	 */
	for (mem = start; mem < end; mem++) {
		for (mmap = mem_map, n = 0; n < len; mmap++, n++) {
			if (mem->type == MEM_AREA_RAM_NSEC &&
			    mmap->type == MEM_AREA_NSEC_SHM)
				continue;
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
		    ((mem->addr >= pa && mem->addr <= (pa + (size - 1))) ||
		    (pa >= mem->addr && pa <= (mem->addr + (mem->size - 1))))) {
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

static bool map_is_flat_mapped(const struct tee_mmap_region *mm)
{
	return map_is_tee_ram(mm);
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

static int __maybe_unused cmp_mmap_by_secure_attr(const void *a, const void *b)
{
	const struct tee_mmap_region *mm_a = a;
	const struct tee_mmap_region *mm_b = b;

	/* unmapped areas are special */
	if (!core_mmu_type_to_attr(mm_a->type) ||
	    !core_mmu_type_to_attr(mm_b->type))
		return 0;

	return map_is_secure(mm_b) - map_is_secure(mm_a);
}

static int cmp_mmap_by_bigger_region_size(const void *a, const void *b)
{
	const struct tee_mmap_region *mm_a = a;
	const struct tee_mmap_region *mm_b = b;

	return mm_b->region_size - mm_a->region_size;
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

static void add_pager_vaspace(struct tee_mmap_region *mmap, size_t num_elems,
			      vaddr_t begin, vaddr_t *end, size_t *last)
{
	size_t size = TEE_RAM_VA_SIZE - (*end - begin);
	size_t n;
	size_t pos = 0;

	if (!size)
		return;

	if (*last >= (num_elems - 1)) {
		EMSG("Out of entries (%zu) in memory map", num_elems);
		panic();
	}

	for (n = 0; !core_mmap_is_end_of_table(mmap + n); n++)
		if (map_is_flat_mapped(mmap + n))
			pos = n + 1;

	assert(pos <= *last);
	memmove(mmap + pos + 1, mmap + pos,
		sizeof(struct tee_mmap_region) * (*last - pos));
	(*last)++;
	memset(mmap + pos, 0, sizeof(mmap[0]));
	mmap[pos].type = MEM_AREA_PAGER_VASPACE;
	mmap[pos].va = *end;
	mmap[pos].size = size;
	mmap[pos].region_size = SMALL_PAGE_SIZE;
	mmap[pos].attr = core_mmu_type_to_attr(MEM_AREA_PAGER_VASPACE);

	*end += size;
}

static bool core_mmu_place_tee_ram_at_top(paddr_t paddr)
{
	size_t l1size = 1ul << PML4_SHIFT;
	paddr_t l1mask = l1size - 1;

	return (paddr & l1mask) > (l1size / 2);
}

static void init_mem_map(struct tee_mmap_region *memory_map, size_t num_elems)
{
	const struct core_mmu_phys_mem *mem;
	struct tee_mmap_region *map;
	size_t last = 0;
	size_t __maybe_unused count = 0;
	vaddr_t va;
	vaddr_t end;
	bool __maybe_unused va_is_secure = true; /* any init value fits */

	for (mem = phys_mem_map_begin; mem < phys_mem_map_end; mem++) {
		struct core_mmu_phys_mem m = *mem;

		/* Discard null size entries */
		if (!m.size)
			continue;

		/* Only unmapped virtual range may have a null phys addr */
		assert(m.addr || !core_mmu_type_to_attr(m.type));

		if (m.type == MEM_AREA_IO_NSEC || m.type == MEM_AREA_IO_SEC) {
			m.addr = ROUNDDOWN(m.addr, CORE_MMU_PGDIR_SIZE);
			m.size = ROUNDUP(m.size + (mem->addr - m.addr),
					 CORE_MMU_PGDIR_SIZE);
		}
		add_phys_mem(memory_map, num_elems, &m, &last);
	}

#ifdef CFG_SECURE_DATA_PATH
	verify_special_mem_areas(memory_map, num_elems, phys_sdp_mem_begin,
				 phys_sdp_mem_end, "SDP");

	check_sdp_intersection_with_nsec_ddr();
#endif

	verify_special_mem_areas(memory_map, num_elems, phys_nsec_ddr_begin,
				 phys_nsec_ddr_end, "NSEC DDR");

	add_va_space(memory_map, num_elems, MEM_AREA_RES_VASPACE,
		     CFG_RESERVED_VASPACE_SIZE, &last);

	add_va_space(memory_map, num_elems, MEM_AREA_SHM_VASPACE,
		     SHM_VASPACE_SIZE, &last);

	memory_map[last].type = MEM_AREA_END;

	/*
	 * Assign region sizes, note that MEM_AREA_TEE_RAM always uses
	 * SMALL_PAGE_SIZE if paging is enabled.
	 */
	for (map = memory_map; !core_mmap_is_end_of_table(map); map++) {
		paddr_t mask = map->pa | map->size;

		if (!(mask & CORE_MMU_PGDIR_MASK))
			map->region_size = CORE_MMU_PGDIR_SIZE;
		else if (!(mask & SMALL_PAGE_MASK))
			map->region_size = SMALL_PAGE_SIZE;
		else
			panic("Impossible memory alignment");

#ifdef CFG_WITH_PAGER
		if (map_is_tee_ram(map))
			map->region_size = SMALL_PAGE_SIZE;
#endif
	}

	/*
	 * To ease mapping and lower use of xlat tables, sort mapping
	 * description moving small-page regions after the pgdir regions.
	 */
	qsort(memory_map, last, sizeof(struct tee_mmap_region),
		cmp_mmap_by_bigger_region_size);

#if !defined(CFG_WITH_LPAE)
	/*
	 * 32bit MMU descriptors cannot mix secure and non-secure mapping in
	 * the same level2 table. Hence sort secure mapping from non-secure
	 * mapping.
	 */
	for (count = 0, map = memory_map; map_is_pgdir(map); count++, map++)
		;

	qsort(memory_map + count, last - count, sizeof(struct tee_mmap_region),
		cmp_mmap_by_secure_attr);
#endif

	/*
	 * Map flat mapped addresses first.
	 * 'va' (resp. 'end') will store the lower (reps. higher) address of
	 * the flat-mapped areas to later setup the virtual mapping of the non
	 * flat-mapped areas.
	 */
	va = (vaddr_t)~0UL;
	end = 0;
	for (map = memory_map; !core_mmap_is_end_of_table(map); map++) {
		if (!map_is_flat_mapped(map))
			continue;

		map->attr = core_mmu_type_to_attr(map->type);
		map->va = map->pa;
		va = MIN(va, ROUNDDOWN(map->va, map->region_size));
		end = MAX(end, ROUNDUP(map->va + map->size, map->region_size));
	}
	assert(va >= TEE_RAM_VA_START);

	if (!(end <= TEE_RAM_VA_START + TEE_RAM_VA_SIZE))
		assert(end <= TEE_RAM_VA_START + TEE_RAM_VA_SIZE);

	add_pager_vaspace(memory_map, num_elems, va, &end, &last);

	assert(!((va | end) & SMALL_PAGE_MASK));

	if (core_mmu_place_tee_ram_at_top(va)) {
		/* Map non-flat mapped addresses below flat mapped addresses */
		for (map = memory_map; !core_mmap_is_end_of_table(map); map++) {
			if (map->va)
				continue;

#if !defined(CFG_WITH_LPAE)
			if (va_is_secure != map_is_secure(map)) {
				va_is_secure = !va_is_secure;
				va = ROUNDDOWN(va, CORE_MMU_PGDIR_SIZE);
			}
#endif
			map->attr = core_mmu_type_to_attr(map->type);
			va -= map->size;
			va = ROUNDDOWN(va, map->region_size);
			/*
			 * Make sure that va is aligned with pa for
			 * efficient pgdir mapping. Basically pa &
			 * pgdir_mask should be == va & pgdir_mask
			 */
			if (map->size > 2 * CORE_MMU_PGDIR_SIZE)
				va -= CORE_MMU_PGDIR_SIZE -
					((map->pa - va) & CORE_MMU_PGDIR_MASK);
			map->va = va;
		}
	} else {
		/* Map non-flat mapped addresses above flat mapped addresses */
		va = end;
		for (map = memory_map; !core_mmap_is_end_of_table(map); map++) {
			if (map->va)
				continue;

#if !defined(CFG_WITH_LPAE)
			if (va_is_secure != map_is_secure(map)) {
				va_is_secure = !va_is_secure;
				va = ROUNDUP(va, CORE_MMU_PGDIR_SIZE);
			}
#endif
			map->attr = core_mmu_type_to_attr(map->type);
			va = ROUNDUP(va, map->region_size);
			/*
			 * Make sure that va is aligned with pa for
			 * efficient pgdir mapping. Basically pa &
			 * pgdir_mask should be == va & pgdir_mask
			 */
			if (map->size > 2 * CORE_MMU_PGDIR_SIZE)
				va += (map->pa - va) & CORE_MMU_PGDIR_MASK;

			map->va = va;
			va += map->size;
		}
	}

	qsort(memory_map, last, sizeof(struct tee_mmap_region),
		cmp_mmap_by_lower_va);

	dump_mmap_table(memory_map);
}

static void print_memory_attr(uint32_t optee_mmu_flags __unused)
{
#if (TRACE_LEVEL == TRACE_FLOW)
	arch_flags_t x86_mmu_flags __unused = get_x86_arch_flags(optee_mmu_flags);
#endif

	FMSG("OP-TEE MMU flags: 0x%x\n", optee_mmu_flags);
	PRINT_MATTR_BIT(optee_mmu_flags, TEE_MATTR_VALID_BLOCK);
	PRINT_MATTR_BIT(optee_mmu_flags, TEE_MATTR_HIDDEN_BLOCK);
	PRINT_MATTR_BIT(optee_mmu_flags, TEE_MATTR_HIDDEN_DIRTY_BLOCK);
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
	PRINT_MATTR_BIT(optee_mmu_flags, TEE_MATTR_LOCKED);

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

/**
 * @brief Returning the x86 arch flags from OP-TEE MMU flags
 */
arch_flags_t get_x86_arch_flags(arch_flags_t flags)
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
		arch_flags |= (X86_MMU_PG_PCD | X86_MMU_PG_PWT);

	if (!((flags & TEE_MATTR_PX) || (flags & TEE_MATTR_UX)))
		arch_flags |= X86_MMU_PG_NX; // Disable execution

	return arch_flags;
}

/**
 * @brief Returning the generic mmu flags from x86 arch flags
 */
static unsigned int get_arch_mmu_flags(arch_flags_t flags)
{
	arch_flags_t mmu_flags = 0;

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

		ret = arch_mmu_map(mm->va, mm->pa, mm->size,
						get_x86_arch_flags(mm->attr));

		if (ret) {
			DMSG("%d\n", ret);
			panic("arch_mmu_map FAIL");
		}
	}

	return mm;
}

/*
 * core_init_mmu_map - init tee core default memory mapping
 *
 * this routine sets the static default tee core mapping.
 *
 * If an error happend: core_init_mmu_map is expected to reset.
 */
void core_init_mmu_map(void)
{
	struct tee_mmap_region *map;
	size_t n;

	for (n = 0; n < ARRAY_SIZE(secure_only); n++) {
		if (pbuf_intersects(nsec_shared, secure_only[n].paddr,
				    secure_only[n].size))
			panic("Invalid memory access config: sec/nsec");
	}

	COMPILE_TIME_ASSERT(CFG_MMAP_REGIONS >= 13);
	init_mem_map(static_memory_map, ARRAY_SIZE(static_memory_map));

	map = static_memory_map;
	while (!core_mmap_is_end_of_table(map)) {
		switch (map->type) {
		case MEM_AREA_TEE_RAM:
		case MEM_AREA_TEE_RAM_RX:
		case MEM_AREA_TEE_RAM_RO:
		case MEM_AREA_TEE_RAM_RW:
		case MEM_AREA_NEX_RAM_RW:
			if (!pbuf_is_inside(secure_only, map->pa, map->size))
				panic("TEE_RAM can't fit in secure_only");
			break;
		case MEM_AREA_TA_RAM:
			if (!pbuf_is_inside(secure_only, map->pa, map->size))
				panic("TA_RAM can't fit in secure_only");
			break;
		case MEM_AREA_NSEC_SHM:
			if (!pbuf_is_inside(nsec_shared, map->pa, map->size))
				panic("NS_SHM can't fit in nsec_shared");
			break;
		case MEM_AREA_SEC_RAM_OVERALL:
		case MEM_AREA_TEE_COHERENT:
		case MEM_AREA_TEE_ASAN:
		case MEM_AREA_IO_SEC:
		case MEM_AREA_IO_NSEC:
		case MEM_AREA_RAM_SEC:
		case MEM_AREA_RAM_NSEC:
		case MEM_AREA_RES_VASPACE:
		case MEM_AREA_SHM_VASPACE:
		case MEM_AREA_PAGER_VASPACE:
			break;
		default:
			EMSG("Uhandled memtype %d", map->type);
			panic();
		}
		map++;
	}

	core_init_mmu_tables(static_memory_map);

	DMSG("Enable runtime MMU\n");

	x86_set_cr3((uint64_t)&g_pml4[0]);
	optee_mem_structs_ready = 1;
	console_init();
}

void core_init_mmu_tables(struct tee_mmap_region *mm)
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
	case CORE_MEM_NSEC_SHM:
		return core_is_buffer_inside(pbuf, len, TEE_SHMEM_START,
							TEE_SHMEM_SIZE);
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

/* core_va2pa - teecore exported service */
static int __maybe_unused core_va2pa_helper(void *va, paddr_t *pa)
{
	struct tee_mmap_region *map;

	map = find_map_by_va(va);
	if (!va_is_in_map(map, (vaddr_t)va))
		return -1;

	/*
	 * We can calculate PA for static map. Virtual address ranges
	 * reserved to core dynamic mapping return a 'match' (return 0;)
	 * together with an invalid null physical address.
	 */
	if (map->pa)
		*pa = map->pa + (vaddr_t)va  - map->va;
	else
		*pa = 0;

	return 0;
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

bool core_mmu_find_table(vaddr_t va, unsigned int max_level,
		struct core_mmu_table_info *tbl_info)
{
	//TODO: maybe need to disable interrupt here.
	uint64_t *tbl = &g_pml4[0];
	uintptr_t ntbl;
	unsigned int level = 1;
	vaddr_t va_base = 0;
	unsigned int num_entries = NO_OF_PML4_ENTRIES;

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

void tlbi_mva_range(vaddr_t va, size_t size, size_t granule)
{
	size_t sz = size;

	assert(granule == CORE_MMU_PGDIR_SIZE || granule == SMALL_PAGE_SIZE);

	while (sz) {
		tlbi_mva_allasid_nosync(va);
		if (sz < granule)
			break;
		sz -= granule;
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

TEE_Result cache_maintenance(enum cache_op op, void *va, size_t len)
{
	TEE_Result ret = TEE_SUCCESS;

	switch (op) {
	case CACHE_INVALIDATE:
	case CACHE_AREA_INVALIDATE:
		invd();
		break;
	case CACHE_CLEAN:
	case CACHE_CLEAN_INV:
	case CACHE_AREA_CLEAN:
	case CACHE_AREA_CLEAN_INV:
		wbinvd();
		break;
	case CACHE_TLB_INVALIDATE:
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
			if (!core_mmu_find_table(vaddr, UINT_MAX, &tbl_info))
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
		if (!core_mmu_find_table(vstart, UINT_MAX, &tbl_info))
			panic("Can't find pagetable");

		if (tbl_info.shift != SMALL_PAGE_SHIFT)
			panic("Invalid pagetable level");

		idx = core_mmu_va2idx(&tbl_info, vstart);
		core_mmu_set_entry(&tbl_info, idx, 0, 0);
	}
	tlbi_all();

	mmu_unlock(exceptions);
}

static void core_mmu_set_info_table(struct core_mmu_table_info *tbl_info,
		unsigned int level, vaddr_t va_base, void *table)
{
	tbl_info->level = level;
	tbl_info->table = table;
	tbl_info->va_base = va_base;
	tbl_info->shift = 0;
	assert(level <= 3);

	if (level == 1)
		tbl_info->num_entries = 1;
	else
		tbl_info->num_entries = 1;
}

void core_mmu_get_user_pgdir(struct core_mmu_table_info *pgd_info)
{
	vaddr_t va_range_base;
	void *tbl = &g_pml4[0];

	core_mmu_get_user_va_range(&va_range_base, NULL);
	core_mmu_set_info_table(pgd_info, 2, va_range_base, tbl);
}

void core_mmu_create_user_map(struct user_ta_ctx *utc,
				struct core_mmu_user_map *map)
{
	struct core_mmu_table_info dir_info;
	//struct user_ta_ctx *utc_ta = to_user_ta_ctx(&utc->ctx);
	struct vm_region *r;
	//size_t n;
	int ret;

	core_mmu_get_user_pgdir(&dir_info);
    // Clear previous user MMU tables
	clear_user_map();

	TAILQ_FOREACH(r, &utc->vm_info->regions, link) {
		paddr_t pa = 0;

		if (r->mobj && r->va != 0) {

			mobj_get_pa(r->mobj, r->offset, 0, &pa);

			ret = arch_mmu_map(r->va, pa, r->size,
					(X86_MMU_PG_G | get_x86_arch_flags(r->attr)));

			if (ret) {
				EMSG("%d\n", ret);
				panic("arch_mmu_map FAIL");
			}
		}
	}

	/*for (n = 0; n < ARRAY_SIZE(utc_ta->mmu->regions); n++) {
		paddr_t pa = 0;

		if (utc_ta->mmu->regions[n].mobj
				&& (utc_ta->vm_info->regions[n].va != 0)) {

			mobj_get_pa(utc_ta->mmu->regions[n].mobj,
					utc_ta->mmu->regions[n].offset, 0, &pa);

			ret = arch_mmu_map(utc_ta->mmu->regions[n].va, pa,
					utc_ta->mmu->regions[n].size,
					(X86_MMU_PG_G |
				get_x86_arch_flags(utc->mmu->regions[n].attr)));

			if (ret) {
				EMSG("%d\n", ret);
				panic("arch_mmu_map FAIL");
			}
		}
	}*/

    /* Flush TLB */
	x86_set_cr3(x86_get_cr3());

	map->user_map = virt_to_phys(&g_user_ta_pd[0]);
	//map->asid = utc->context & 0xff;
	map->asid = utc->vm_info->asid;
}

void core_mmu_set_user_map(struct core_mmu_user_map *map)
{
	if (map == NULL)
		clear_user_map();
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

	if (!core_mmu_find_table(map->va, UINT_MAX, &tbl_info))
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

bool core_mmu_user_mapping_is_active(void)
{
	bool ret = false;
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	if (pt_user_index)
		ret = true;

	thread_unmask_exceptions(exceptions);

	return ret;
}

/* Function returns user space virtual start address and size of area. */
void core_mmu_get_user_va_range(vaddr_t *base, size_t *size)
{
	if (base)
		*base = TA_USER_BASE_VA;
	if (size)
		*size = TA_RAM_SIZE;
}

void core_mmu_get_user_map(struct core_mmu_user_map *map)
{
	map->user_map = (uint64_t)&g_user_ta_pd[0];
	map->asid = 0;
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
	paddr_t p;

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
	TEE_Result res;
	void *va = NULL;

	if (!core_mmu_user_mapping_is_active())
		return NULL;

	res = tee_mmu_user_pa2va_helper(to_user_ta_ctx(tee_mmu_get_ctx()),
					pa, &va);
	if (res != TEE_SUCCESS)
		return NULL;
	return va;
}

#ifdef CFG_WITH_PAGER
static void *phys_to_virt_tee_ram(paddr_t pa)
{
	if (pa >= TEE_LOAD_ADDR && pa < get_linear_map_end())
		return (void *)(vaddr_t)pa;
	return tee_pager_phys_to_virt(pa);
}
#else
static void *phys_to_virt_tee_ram(paddr_t pa)
{
	struct tee_mmap_region *mmap;

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
	void *va;

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
	struct tee_mmap_region *map;
	void *va;

	map = find_map_by_type_and_pa(MEM_AREA_IO_SEC, pa);
	if (!map)
		map = find_map_by_type_and_pa(MEM_AREA_IO_NSEC, pa);
	if (!map)
		return NULL;
	va = map_pa2va(map, pa);
	check_va_matches_pa(pa, va);
	return va;
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

//  FMSG("pde 0x%lx, pfn 0x%lx\n", pde, pfn);
	return pfn;
}

/**
 * @brief  Walk the page table structures
 *
 * In this scenario,
 * we are considering the paging scheme to be a PAE mode with
 * 4KB pages.
 */
int x86_mmu_get_mapping(map_addr_t pml4, vaddr_t vaddr, uint32_t *ret_level,
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
		*updated_mmu_flags &= ~X86_MMU_PG_NX;
		ret = true;
	}

	/* If current entry has cached disabled and
	 * new entry wants enable caches
	 * let's enable them for page directory entries
	 */
	if ((current_entry & (X86_MMU_PG_PCD | X86_MMU_PG_PWT)) &&
		!(new_entry & (X86_MMU_PG_PCD | X86_MMU_PG_PWT))) {
		*updated_mmu_flags &= ~(X86_MMU_PG_PCD | X86_MMU_PG_PWT);
		ret = true;
	}

	return ret;
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
int x86_mmu_add_mapping(map_addr_t pml4, map_addr_t paddr,
				vaddr_t vaddr, arch_flags_t mmu_flags)
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
		m = &g_pdp[pdp_counter];
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
			m = &g_user_ta_pd[pd_user_counter];
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
			if ((pt_user_index + 1) > NO_OF_USER_PT_TABLES) {
				EMSG("gt_user_index %d\n", pt_user_index);
				panic("TEE_ERROR_OUT_OF_MEMORY");
			}
			m = &g_user_ta_pte[pt_user_index][0];
			pt_user_index++;
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

int x86_mmu_unmap(map_addr_t pml4, vaddr_t vaddr, unsigned int count)
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
int x86_mmu_map_range(map_addr_t pml4, struct map_range *range,
						arch_flags_t flags)
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

	FMSG("no_of_pages %d\n", no_of_pages);

	for (index = 0; index < no_of_pages; index++) {
		map_status = x86_mmu_add_mapping(pml4, next_aligned_p_addr,
						next_aligned_v_addr, flags);
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

int arch_mmu_query(vaddr_t vaddr, paddr_t *paddr, unsigned int *flags)
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

int arch_mmu_map(vaddr_t vaddr, paddr_t paddr,
				unsigned int count, arch_flags_t flags)
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

	return x86_mmu_map_range(virt_to_phys((void *)&g_pml4[0]),
								&range, flags);
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

// ToDo Implement
enum core_mmu_fault core_mmu_get_fault_type(uint32_t fault_descr)
{
	switch (fault_descr) {
	default:
		return CORE_MMU_FAULT_OTHER;
	}
}

#ifdef CFG_WITH_PAGER
bool is_unpaged(void *va)
{
	vaddr_t v = (vaddr_t)va;

	return v >= TEE_TEXT_VA_START && v < get_linear_map_end();
}
#else
bool is_unpaged(void *va __unused)
{
	return true;
}
#endif
