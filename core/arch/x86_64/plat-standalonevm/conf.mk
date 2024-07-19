$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_APIC,y)
$(call force,CFG_UART,y)
$(call force,CFG_PCI,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_SECURE_TIME_SOURCE_REE,y)

$(call force,CFG_WITH_LPAE,y)

CFG_WITH_STACK_CANARIES ?= n
CFG_WITH_STATS ?= y
CFG_TEE_CORE_EMBED_INTERNAL_TESTS ?= y

CFG_TEE_CORE_NB_CORE = 1
CFG_NUM_THREADS ?= 2

CFG_TA_DYNLINK ?= y

CFG_CORE_ASLR ?= n
CFG_CORE_DYN_SHM ?= n

CFG_IVSHMEM ?= y

# use mbedtls lib
CFG_CRYPTOLIB_NAME ?= mbedtls
CFG_CRYPTOLIB_DIR ?= lib/libmbedtls

# use libgnuefi
CFG_EDK2_TPM ?= n
CFG_USE_TPM_EARLY ?= y

# use x86 random generator
CFG_X86_RNG ?= y
ifeq ($(CFG_X86_RNG),y)
$(call force,CFG_WITH_SOFTWARE_PRNG,n)
endif

CFG_TZDRAM_START ?= 0x01000000
CFG_TZDRAM_SIZE  ?= 0x01000000
CFG_SHMEM_START  ?= 0x00200000
CFG_SHMEM_SIZE   ?= 0x00200000

# Enlarge heap size for core to 512 KB
CFG_CORE_HEAP_SIZE ?= 0x80000
CFG_TEE_RAM_VA_SIZE ?= 0x00400000

CFG_IN_TREE_EARLY_TAS += keymaster/dba51a17-0563-11e7-93b1-6fa7b0071a51
CFG_IN_TREE_EARLY_TAS += gatekeeper/4d573443-6a56-4272-ac6f-2425af9ef9bb

$(call force,CFG_BOOT_SECONDARY_REQUEST,n)
$(call force,CFG_DT,n)
