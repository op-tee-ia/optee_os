global-incdirs-y += include
global-incdirs-y += include/IndustryStandard

srcs-y += Tpm2NVStorage.c
srcs-y += Tpm2Random.c
srcs-y += Tpm2Help.c
srcs-y += Tpm2Context.c
srcs-y += Tpm2EnhancedAuthorization.c
srcs-y += Tpm2Hierarchy.c
srcs-y += Tpm2Integrity.c
srcs-y += Tpm2Sequences.c
srcs-y += Tpm2Session.c
srcs-y += Tpm2Capability.c

ifeq ($(CFG_USE_TPM_EARLY),y)
srcs-y += RegisterFilterLibNull.c
srcs-y += Tpm2Ptp.c
srcs-y += IoLib.c
srcs-y += Tpm2Tis.c
else
srcs-y += Tpm2DeviceLib.c
endif

subdirs-y += libgnuefi
