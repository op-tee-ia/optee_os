cppflags-y += -I$(sub-dir)/../..

srcs-y += user_ta_entry.c
srcs-y += utee_misc.c
srcs-y += utee_syscalls_64.S

subdirs-y += gprof
