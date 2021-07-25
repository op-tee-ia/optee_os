srcs-$(CFG_WITH_USER_TA) += ldelf_loader.c
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
srcs-y += thread_optee_smc.c
srcs-y += trace_ext.c
srcs-y += misc.c

srcs-y += boot.c
srcs-y += entry_64.S

srcs-$(CFG_VIRTUALIZATION) += virtualization.c

srcs-y += link_dummies_paged.c
srcs-y += link_dummies_init.c

asm-defines-y += asm-defines.c

ifeq ($(CFG_SYSCALL_FTRACE),y)
# We would not like to profile thread.c file as it provide common APIs
# that are needed for ftrace framework to trace syscalls. So profiling
# this file could create an incorrect cyclic behaviour.
cflags-remove-thread.c-y += -pg
cflags-remove-spin_lock_debug.c-$(CFG_TEE_CORE_DEBUG) += -pg
# Tracing abort dump files corrupts the stack trace. So exclude them
# from profiling.
cflags-remove-abort.c-y += -pg
ifeq ($(CFG_UNWIND),y)
cflags-remove-unwind_arm32.c-y += -pg
cflags-remove-unwind_arm64.c-$(CFG_ARM64_core) += -pg
endif
endif
