ifeq ($(CFG_WITH_USER_TA),y)
srcs-y += arch_svc_64.S
srcs-$(CFG_CACHE_API) += svc_cache.c
srcs-y += arch_svc.c
endif
srcs-y += entry_fast.c
cppflags-entry_fast.c-y += -DTEE_IMPL_GIT_SHA1=$(TEE_IMPL_GIT_SHA1)
srcs-y += cache.c
