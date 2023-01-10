// SPDX-License-Identifier: BSD-2-Clause
/*
 *  Copyright (c) 2022 Intel Corporation
 */
#include <kernel/tdx.h>
#include <kernel/panic.h>
#include <mm/core_mmu.h>
#include <tee/tee_svc.h>
#include <string.h>
#include <descriptor.h>
#include <trace.h>

#define EXIT_QUAL_IO_SIZE_MASK          0x7
#define EXIT_QUAL_IO_DIRECTION_MASK     0x8
#define EXIT_QUAL_IO_PORT_SHIFT         16

typedef union {
    uint8_t val;
    struct {
        uint8_t rm:3;
        uint8_t reg:3;
        uint8_t mod:2;
    } bits;
} modrm_t;

typedef union {
    uint8_t val;
    struct {
        uint8_t b:1;
        uint8_t x:1;
        uint8_t r:1;
        uint8_t w:1;
    } bits;
} rex_t;

extern uint8_t g_td_shared_bit;

static inline uint64_t tdx_get_ve_info(ve_info_t *ve)
{
    return tdcall(TDGETVEINFO, (void *)ve, 0, 0, 0);
}

uint64_t tdx_get_info(td_info_t *info)
{
    return tdcall(TDINFO, (void *)info, 0, 0, 0);
}

/*
 * Check whether port number is in allow list 
 */
static inline bool tdx_is_port_allowed(short port)
{
    switch (port) {
        /* PIT (8253) */
        case 0x40:
        case 0x43:
            return true;
        /* PIC1 and PIC2 */
        case 0x20:
        case 0x21:
        case 0xa0:
        case 0xA1:
            return true;
        /* PCI port */
        case 0xcf8 ... 0xcff:
            return true;
        /* Serial port */
        case 0x3f8 ... 0x3ff:
            return true;
        default:
            IMSG("TDX disabled port(0x%x) ops\n", port);
            return false;
    }

    return false;
}

static uint64_t tdx_handle_io_ops(x86_iframe_t *frame, uint64_t exit_qual)
{
    uint8_t size = (exit_qual & EXIT_QUAL_IO_SIZE_MASK) + 1;
    uint16_t port = exit_qual >> EXIT_QUAL_IO_PORT_SHIFT;

    if (!tdx_is_port_allowed(port))
        return VMCALL_INVALID_OPERAND;

    if (exit_qual & EXIT_QUAL_IO_DIRECTION_MASK)
        return tdvmcall_io_read(port, size, &frame->ax);
    else
        return tdvmcall_io_write(port, size, frame->ax);
}

static int tdx_handle_readmsr(x86_iframe_t *frame)
{
    uint64_t msr_id = frame->cx;
    uint64_t val = 0;
    uint64_t ret = VMCALL_SUCCESS;

    ret = tdvmcall_readmsr(msr_id, &val);

    if (ret == VMCALL_SUCCESS) {
        frame->dx = (val >> 32) & 0x0FFFFFFFFULL;
        frame->ax = val & 0x0FFFFFFFFULL;
    }

    return ret;
}

static uint64_t tdx_handle_writemsr(x86_iframe_t *frame)
{
    uint64_t msr_id = frame->cx;
    uint64_t dx = frame->dx;
    uint64_t ax = frame->ax;
    uint64_t val;

    val = ((dx << 32) & 0xFFFFFFFF00000000ULL) | (ax & 0x0FFFFFFFFULL);

    return tdvmcall_writemsr(msr_id, val);
}

static uint64_t* get_reg_addr(x86_iframe_t *frame, uint8_t idx)
{
    switch (idx) {
        case 0: return &frame->ax;
        case 1: return &frame->cx;
        case 2: return &frame->dx;
        case 3: return &frame->bx;
        case 5: return &frame->bp;
        case 6: return &frame->si;
        case 7: return &frame->di;
        case 8: return &frame->r8;
        case 9: return &frame->r9;
        case 10: return &frame->r10;
        case 11: return &frame->r11;
        case 12: return &frame->r12;
        case 13: return &frame->r13;
        case 14: return &frame->r14;
        case 15: return &frame->r15;
        default: return NULL;
    }
}

static uint64_t tdx_handle_mmio(x86_iframe_t *frame, ve_info_t *ve)
{
    uint8_t* rip = (uint8_t *)frame->ip;
    uint8_t  opcode = 0;
    uint32_t opsize = 4;
    uint32_t mmio_size = 0;
    uint32_t reg_size = 0;
    uint64_t val = 0;
    uint64_t* reg_addr = NULL;
    modrm_t mod = {0};
    rex_t   rex = {0};
    uint64_t ret = VMCALL_SUCCESS;

    /* Step 1: Panic if MMIO request from User Level */
    if ((frame->cs & USER_RPL) == USER_RPL) {
        syscall_panic(0xdeadbeef);
    }

    /* Step 2: decode */
    /* Set default opsize as 4, it will be updated after decoding */
    do {
        opcode = *rip;
        if (0x66 == opcode) {
            opsize = 2;
        } else if ((opcode >= 0x40) && (opcode <= 0x4f)) {
            rex.val = opcode;
        } else {
            break;
        }
        rip++;
    } while (true);

    opcode = *rip++;

    switch (opcode) {
        case 0x88:
        case 0x8A:
            mmio_size = 1;
            break;
        default:
            mmio_size = rex.bits.w ? 8 : opsize;
            break;
    }

    mod.val = *rip++;

    reg_addr = get_reg_addr(frame, mod.bits.reg | ((int)rex.bits.r << 3));

    if (4 == mod.bits.rm)
        rip++;

    if ((2 == mod.bits.mod) || ((0 == mod.bits.mod) && (5 == mod.bits.rm)))
        rip += 4;
    else if (1 == mod.bits.mod)
        rip++;

    /* Step 3: read/write operation */
    switch (opcode) {
        case 0x88:
        case 0x89:
            memcpy((void*)&val, (void *)reg_addr, mmio_size);
            ret = tdvmcall_mmio_write(ve->gpa, mmio_size, val);
            break;
        case 0x8A:
        case 0x8B:
            reg_size = (mmio_size == 4) ? 8 : mmio_size;
            ret = tdvmcall_mmio_read(ve->gpa, mmio_size, &val);
            if (0 == ret) {
                memset((void *)reg_addr, 0, reg_size);
                memcpy((void *)reg_addr, (void *)&val, mmio_size);
            }
            break;
        default:
            EMSG("opcode:0x%x val:0x%lx gpa:0x%lx with size:0x%x\n",
                    opcode, val, ve->gpa, mmio_size);
            panic("unsupported decode type!\n");
            break;
    }

    if (VMCALL_SUCCESS == ret) {
        ve->instr_len = (uint64_t)((uint64_t)rip - frame->ip);
    }

    return ret;
}

/*
 * TODO: Check whether interrupts are disabled.
 */
void x86_handle_ve(x86_iframe_t *frame) 
{
    ve_info_t ve;
    uint64_t ret = TDX_SUCCESS;

    ret = tdx_get_ve_info(&ve);
    if (ret != TDX_SUCCESS)
        panic("Failed to get #VE info\n");

    switch (ve.exit_reason) {
        case REASON_10_CPUID_INSTR:
        case REASON_12_HLT_INSTR:
            IMSG("unimplemented #VE: reason(%d)\n",  ve.exit_reason);
            ret = TDX_VE_NOT_HANDLED;
            break;
        case REASON_30_IO_INSTR:
            ret = tdx_handle_io_ops(frame, ve.exit_qual);
            break;
        case REASON_31_MSR_READ:
            ret = tdx_handle_readmsr(frame);
            break;
        case REASON_32_MSR_WRITE:
            ret = tdx_handle_writemsr(frame);
            break;
        case REASON_36_MWAIT_INSTR:
        case REASON_39_MONITOR_INSTR:
            IMSG("unimplemented #VE: reason(%d)\n",  ve.exit_reason);
            ret = TDX_VE_NOT_HANDLED;
            break;
        case REASON_48_EPT_VIOLATION:
            ret = tdx_handle_mmio(frame, &ve);
            break;
        case REASON_54_WBINVD_INST:
        default:
            IMSG("Unhandled #VE: reason(%d)\n",  ve.exit_reason);
            ret = TDX_VE_NOT_HANDLED;
            break;
    }

    if (TDX_SUCCESS == ret) {
    /*
     * Continue to execute next instruction since operation should be
     * succeed or ignored in TDX.
     */
        frame->ip += ve.instr_len;
    } else {
        panic("Failed to handle #VE!\n");
    }
}

uint64_t tdx_map_gpa(paddr_t paddr, size_t size, tdx_mem_type_t type)
{
    uint64_t ret;

    if (type == TDX_MEM_SHARED) {
        paddr |= (1ULL << (g_td_shared_bit - 1));
    }

    ret = tdvmcall_mapgpa(paddr, size);

    if (ret || (type == TDX_MEM_SHARED)) {
        return ret;
    }

    // TODO: Accept page again if we map private pages.
    return ret;
}
