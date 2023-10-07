global-incdirs-y += lib
global-incdirs-y += inc
global-incdirs-y += inc/protocol
global-incdirs-y += inc/$(ARCH)

SRCS_EFI :=
SRCS_EFI += boxdraw.c
SRCS_EFI += hand.c
SRCS_EFI += guid.c
SRCS_EFI += debug.c
SRCS_EFI += error.c
SRCS_EFI += console.c
SRCS_EFI += init.c
SRCS_EFI += runtime/efirtlib.c
SRCS_EFI += runtime/rtlock.c
SRCS_EFI += runtime/rtstr.c
SRCS_EFI += runtime/rtdata.c
SRCS_EFI += runtime/vm.c
SRCS_EFI += hw.c
SRCS_EFI += data.c
SRCS_EFI += misc.c
SRCS_EFI += lock.c
SRCS_EFI += smbios.c
SRCS_EFI += crc.c
SRCS_EFI += event.c
SRCS_EFI += sread.c
SRCS_EFI += str.c
SRCS_EFI += cmdline.c
SRCS_EFI += print.c
SRCS_EFI += dpath.c
SRCS_EFI += $(ARCH)/initplat.c
SRCS_EFI += $(ARCH)/efi_stub.S
SRCS_EFI += $(ARCH)/math.c

ifeq ($(ARCH),x86_64)
SRCS_EFI +=  $(ARCH)/callwrap.c
endif

cflags-lib-y += -Wno-error

srcs-y += $(addprefix lib/, $(SRCS_EFI))

subdirs-y += gnuefi
