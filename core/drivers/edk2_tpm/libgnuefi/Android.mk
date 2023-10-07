LOCAL_PATH := $(call my-dir)

ifeq ($(TARGET_UEFI_ARCH),x86_64)
    LOADER_ARCH := x86_64
else
    LOADER_ARCH := x86
endif

SHARED_C_INCLUDES := \
    $(LOCAL_PATH)/inc \
    $(LOCAL_PATH)/inc/$(TARGET_EFI_ARCH_NAME) \
    $(LOCAL_PATH)/inc/protocol

include $(CLEAR_VARS)
LOCAL_CFLAGS += -Wno-error
LOCAL_MODULE := libefi
LOCAL_SRC_FILES := \
    lib/boxdraw.c \
    lib/hand.c \
    lib/guid.c \
    lib/debug.c \
    lib/error.c \
    lib/console.c \
    lib/init.c \
    lib/runtime/efirtlib.c \
    lib/runtime/rtlock.c \
    lib/runtime/rtstr.c \
    lib/runtime/rtdata.c \
    lib/runtime/vm.c \
    lib/hw.c \
    lib/data.c \
    lib/misc.c \
    lib/lock.c \
    lib/smbios.c \
    lib/crc.c \
    lib/event.c \
    lib/sread.c \
    lib/str.c \
    lib/cmdline.c \
    lib/print.c \
    lib/dpath.c \
    lib/$(TARGET_EFI_ARCH_NAME)/initplat.c \
    lib/$(TARGET_EFI_ARCH_NAME)/efi_stub.S \
    lib/$(TARGET_EFI_ARCH_NAME)/math.c

LOCAL_EXPORT_C_INCLUDE_DIRS := $(SHARED_C_INCLUDES)

LOCAL_C_INCLUDES := \
    $(SHARED_C_INCLUDES) \
    $(LOCAL_PATH)/lib

ifeq ($(TARGET_UEFI_ARCH),x86_64)
LOCAL_SRC_FILES += \
	lib/x86_64/callwrap.c
endif

include $(BUILD_EFI_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libgnuefi
LOCAL_SRC_FILES := gnuefi/reloc_$(TARGET_EFI_ARCH_NAME).c
LOCAL_C_INCLUDES := \
    $(SHARED_C_INCLUDES) \
    $(LOCAL_PATH)/inc/$(TARGET_EFI_ARCH_NAME) \
    $(LOCAL_PATH)/inc/protocol \
    bionic/libc/include \
    bionic/libc/kernel/uapi \
    bionic/libc/kernel/android/uapi \
    bionic/libc/kernel/uapi/asm-x86 \
    bionic/libc/arch-$(LOADER_ARCH)/include
include $(BUILD_EFI_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := crt0-efi-$(TARGET_EFI_ARCH_NAME)
LOCAL_SRC_FILES = gnuefi/crt0-efi-$(TARGET_EFI_ARCH_NAME).S
include $(BUILD_EFI_STATIC_LIBRARY)
