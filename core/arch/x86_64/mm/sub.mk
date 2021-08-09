srcs-y += core_mmu.c
srcs-$(CFG_WITH_PAGER) += tee_pager.c
srcs-y += tee_mm.c
srcs-y += pgt_cache.c
srcs-$(CFG_CORE_FFA) += mobj_ffa.c
ifneq ($(CFG_CORE_FFA),y)
srcs-$(CFG_CORE_DYN_SHM) += mobj_dyn_shm.c
endif
