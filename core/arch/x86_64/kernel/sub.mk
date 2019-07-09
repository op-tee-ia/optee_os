ifeq ($(CFG_WITH_USER_TA),y)
srcs-y += user_ta.c
srcs-$(CFG_REE_FS_TA) += ree_fs_ta.c
srcs-$(CFG_EARLY_TA) += early_ta.c
srcs-$(CFG_SECSTOR_TA) += secstor_ta.c
endif
srcs-y += pseudo_ta.c
srcs-y += elf_load.c
srcs-$(CFG_TA_DYNLINK) += elf_load_dyn.c
srcs-y += tee_time.c
srcs-y += otp_stubs.c
srcs-y += descriptor.c
srcs-y += fault.c
srcs-y += gdt.S
srcs-y += exceptions.S
srcs-y += fpu.c

srcs-$(CFG_SECURE_TIME_SOURCE_REE) += tee_time_ree.c

srcs-y += spin_lock_64.S
srcs-$(CFG_TEE_CORE_DEBUG) += spin_lock_debug.c

srcs-y += thread_64.S
srcs-y += thread.c
srcs-y += trace_ext.c
srcs-y += misc_64.c
srcs-y += mutex.c
srcs-$(CFG_LOCKDEP) += mutex_lockdep.c
srcs-y += wait_queue.c
srcs-$(CFG_PM_STUBS) += pm_stubs.c
cflags-pm_stubs.c-y += -Wno-suggest-attribute=noreturn

srcs-$(CFG_GENERIC_BOOT) += generic_boot.c
ifeq ($(CFG_GENERIC_BOOT),y)
srcs-y += generic_entry_64.S
endif

srcs-y += link_dummies.c

asm-defines-y += asm-defines.c
