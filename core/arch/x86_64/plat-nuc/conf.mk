$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_APIC,y)
$(call force,CFG_UART,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_SECURE_TIME_SOURCE_REE,y)

$(call force,CFG_WITH_LPAE,y)

CFG_WITH_STACK_CANARIES ?= n
CFG_WITH_STATS ?= y

CFG_TEE_CORE_NB_CORE = 1
# TODO: will fix multi threads issue for x86
CFG_NUM_THREADS ?= 1

# TODO: will investigate this if this can be enabled for x86
CFG_TA_DYNLINK ?= n

# TODO: not support mbedtls yet for x86, will enable it in the future.
CFG_TA_MBEDTLS_MPI ?= n
CFG_TA_MBEDTLS ?= n
CFG_TA_MBEDTLS_SELF_TEST ?= n

CFG_TZDRAM_START ?= 0x32c00000
CFG_TZDRAM_SIZE  ?= 0x00e00000
CFG_SHMEM_START  ?= 0x33a00000
CFG_SHMEM_SIZE   ?= 0x00200000
CFG_TEE_RAM_VA_SIZE ?= 0x00200000

$(call force,CFG_BOOT_SECONDARY_REQUEST,n)
$(call force,CFG_DT,n)
