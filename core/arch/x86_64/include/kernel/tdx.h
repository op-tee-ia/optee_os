/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Intel Corporation
 */
#ifndef TDX_H
#define TDX_H
/*
 * TDCALL leaves defined in <Guest-Host-Communication Interface
 * (GHCI) for Intel Trusty Domain Extension (Intel TDX)> chapter 2.4
 */
#define TDVMCALL        0
#define TDINFO          1
#define TDMRRTMREXTEND  2
#define TDGETVEINFO     3
#define TDREPORT        4
#define TDCPUIDVESET    5
#define TDACCEPTPAGE    6

#define TDVMCALL_GET_TDVMCALL_INFO  0x10000
#define TDVMCALL_MAPGPA             0x10001
#define TDVMCALL_GET_QUOTE          0x10002
#define TDVMCALL_REPORT_FATAL_ERR   0x10003
#define TDVMCALL_SETUP_EVENT_NOTIFY 0x10004

/*
 * VMEXIT reason covered by TDX implementation now.
 */
#define REASON_10_CPUID_INSTR   10
#define REASON_12_HLT_INSTR     12
#define REASON_30_IO_INSTR      30
#define REASON_31_MSR_READ      31
#define REASON_32_MSR_WRITE     32
#define REASON_36_MWAIT_INSTR   36
#define REASON_39_MONITOR_INSTR 39
#define REASON_48_EPT_VIOLATION 48
#define REASON_54_WBINVD_INST   54

/* TDX return error code */
#define TDX_SUCCESS          0
#define TDX_NO_VE_INFO       0x8000000000000000ULL
#define TDX_VE_NOT_HANDLED   0x8000000000000001ULL


/* TDX VMCALL return error code */
#define VMCALL_SUCCESS          0
#define VMCALL_INVALID_OPERAND  0x8000000000000000ULL

#ifndef __ASSEMBLY__

#include <x86.h>
#include <stdint.h>
#include <types_ext.h>

typedef enum tdx_mem_type {
    TDX_MEM_PRIVATE,
    TDX_MEM_SHARED,
} tdx_mem_type_t;

typedef struct td_info {
    uint64_t gpaw;
    uint64_t attr;
    uint32_t maxvcpus;
    uint32_t numvcpus;
    uint64_t resv[3];
} td_info_t;

/*
 * Virtualization Exception Information Area, based on ISDM Vol.3, Table-25-1
 */
typedef struct ve_info {
    uint32_t exit_reason;
    uint32_t rsv;
    uint64_t exit_qual;
    uint64_t gla;
    uint64_t gpa;
    uint32_t instr_len;
    uint32_t instr_info;
    uint8_t  pad[8];
} ve_info_t;


uint64_t tdcall(uint64_t leaf, void *out, uint64_t para0, uint64_t para1,
                uint64_t para2);
uint64_t tdvmcall_io_read(uint64_t port, uint64_t size, uint64_t *val);
uint64_t tdvmcall_io_write(uint64_t port, uint64_t size, uint64_t val);
uint64_t tdvmcall_readmsr(uint64_t msr_id, uint64_t *val);
uint64_t tdvmcall_writemsr(uint64_t msr_id, uint64_t val);
uint64_t tdvmcall_mapgpa(uint64_t paddr, uint64_t size);
void x86_handle_ve(x86_iframe_t *frame);
uint64_t tdx_get_info(td_info_t *info);
uint64_t tdvmcall_mmio_read(uint64_t paddr, uint64_t size, uint64_t *val);
uint64_t tdvmcall_mmio_write(uint64_t paddr, uint64_t size, uint64_t val);
uint64_t tdx_map_gpa(paddr_t paddr, size_t size, tdx_mem_type_t type);

#endif

#endif

