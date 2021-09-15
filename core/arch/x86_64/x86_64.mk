# Setup compiler for the core module
arch-bits-core := 64
CROSS_COMPILE_core := $(CROSS_COMPILE$(arch-bits-core))
COMPILER_core := $(COMPILER)
include mk/$(COMPILER_core).mk

# Defines the cc-option macro using the compiler set for the core module
include mk/cc-option.mk

#todo: check latest implement
CFG_LTC_OPTEE_THREAD ?= y
CFG_LPAE_ADDR_SPACE_SIZE ?= (1ull << 32)

CFG_MMAP_REGIONS ?= 13
CFG_RESERVED_VASPACE_SIZE ?= (1024 * 1024 * 10)

CFG_KERN_LINKER_FORMAT ?= "elf64-x86-64"
CFG_KERN_LINKER_ARCH ?= "i386:x86-64"

platform-hard-float-enabled := y

$(call force,CFG_X86_64_core,y)

CFG_CORE_RWDATA_NOEXEC ?= y
CFG_CORE_RODATA_NOEXEC ?= n
ifeq ($(CFG_CORE_RODATA_NOEXEC),y)
$(call force,CFG_CORE_RWDATA_NOEXEC,y)
endif
# 'y' to set the Alignment Check Enable bit in SCTLR/SCTLR_EL1, 'n' to clear it
CFG_SCTLR_ALIGNMENT_CHECK ?= y

ifeq ($(CFG_WITH_PAGER),y)
ifeq ($(CFG_CORE_SANITIZE_KADDRESS),y)
$(error Error: CFG_CORE_SANITIZE_KADDRESS not compatible with CFG_WITH_PAGER)
endif
endif

core-platform-cppflags	+= -I$(arch-dir)/include
core-platform-subdirs += \
	$(addprefix $(arch-dir)/, kernel tee mm) $(platform-dir)

core-platform-subdirs += $(arch-dir)/sm

x86-64-platform-cppflags += -DX86_64=1 -D__LP64__=1 -DLTC_NO_ROLC -DLTC_NO_FAST

platform-cflags-generic ?= -g -ffunction-sections -fdata-sections -pipe
platform-aflags-generic ?= -g -pipe -D__ASSEMBLY__

ifeq ($(DEBUG),1)
platform-cflags-optimization ?=  -O0
else
platform-cflags-optimization ?=  -Os
endif

platform-cflags-debug-info ?= -g3
platform-aflags-debug-info ?=

core-platform-cflags += $(platform-cflags-optimization)
core-platform-cflags += $(platform-cflags-generic)
core-platform-cflags += $(platform-cflags-debug-info)

core-platform-aflags += $(platform-aflags-generic)
core-platform-aflags += $(platform-aflags-debug-info)

arch-bits-core := 64
core-platform-cppflags += $(x86-64-platform-cppflags)
core-platform-cflags += $(x86-64-platform-cflags)
core-platform-cflags += $(x86-64-platform-cflags-generic)
core-platform-cflags += $(x86-64-platform-cflags-no-hard-float)
core-platform-aflags += $(x86-64-platform-aflags)

# Provide default supported-ta-targets if not set by the platform config
supported-ta-targets = ta_x86_64

ta-targets := $(if $(CFG_USER_TA_TARGETS),$(filter $(supported-ta-targets),$(CFG_USER_TA_TARGETS)),$(supported-ta-targets))
unsup-targets := $(filter-out $(ta-targets),$(CFG_USER_TA_TARGETS))
ifneq (,$(unsup-targets))
$(error CFG_USER_TA_TARGETS contains unsupported value(s): $(unsup-targets). Valid values: $(supported-ta-targets))
endif

ifneq ($(filter ta_x86_64,$(ta-targets)),)
# Variables for ta-target/sm "ta_x86_64"
CFG_X86_64_ta_x86_64 := y
arch-bits-ta_x86_64 := 64
ta_x86_64-platform-cppflags += $(x86-64-platform-cppflags)
ta_x86_64-platform-cflags += $(x86-64-platform-cflags)
ta_x86_64-platform-cflags += $(platform-cflags-optimization)
ta_x86_64-platform-cflags += $(platform-cflags-debug-info)
ta_x86_64-platform-cflags += -fpic
ta_x86_64-platform-cflags += $(x86-64-platform-cflags-generic)
ifeq ($(platform-hard-float-enabled),y)
ta_x86_64-platform-cflags += $(x86-64-platform-cflags-hard-float)
else
ta_x86_64-platform-cflags += $(x86-64-platform-cflags-no-hard-float)
endif
ta_x86_64-platform-aflags += $(platform-aflags-debug-info)
ta_x86_64-platform-aflags += $(x86-64-platform-aflags)

ta_x86_64-platform-cxxflags += -fpic
ta_x86_64-platform-cxxflags += $(platform-cflags-optimization)
ta_x86_64-platform-cxxflags += $(platform-cflags-debug-info)


ta-mk-file-export-vars-ta_x86_64 += CFG_X86_64_ta_x86_64
ta-mk-file-export-vars-ta_x86_64 += ta_x86_64-platform-cppflags
ta-mk-file-export-vars-ta_x86_64 += ta_x86_64-platform-cflags
ta-mk-file-export-vars-ta_x86_64 += ta_x86_64-platform-aflags
ta-mk-file-export-vars-ta_x86_64 += ta_x86_64-platform-cxxflags

ta-mk-file-export-add-ta_x86_64 += CROSS_COMPILE64 ?= $$(CROSS_COMPILE)_nl_
ta-mk-file-export-add-ta_x86_64 += CROSS_COMPILE_ta_x86_64 ?= $$(CROSS_COMPILE64)_nl_
ta-mk-file-export-add-ta_x86_64 += COMPILER ?= gcc_nl_
ta-mk-file-export-add-ta_x86_64 += COMPILER_ta_x86_64 ?= $$(COMPILER)_nl_
ta-mk-file-export-add-ta_x86_64 += PYTHON3 ?= python3_nl_
endif

# Set cross compiler prefix for each submodule
$(foreach sm, $(ta-targets), $(eval CROSS_COMPILE_$(sm) ?= $(CROSS_COMPILE$(arch-bits-$(sm)))))
