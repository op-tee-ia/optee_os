/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2009 Corey Tabaka
 * Copyright (c) 2016 Travis Geiselbrecht
 * Copyright (c) 2018 Intel Corporation
 */
#ifndef X86_H
#define X86_H

#include <compiler.h>
#include <sys/types.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PFEX_P 0x01
#define PFEX_W 0x02
#define PFEX_U 0x04
#define PFEX_RSV 0x08
#define PFEX_I 0x10
#define X86_8BYTE_MASK 0xFFFFFFFF
#define X86_CPUID_ADDR_WIDTH 0x80000008

struct x86_64_iframe {
	/* pushed by common handler */
	uint64_t di, si, bp, bx, dx, cx, ax;
	/* pushed by common handler */
	uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
	/* pushed by stub */
	uint64_t vector;
	/* pushed by interrupt or stub */
	uint64_t err_code;
	/* pushed by interrupt */
	uint64_t ip, cs, flags;
	/* pushed by interrupt if priv change occurs */
	uint64_t user_sp, user_ss;
};

typedef struct x86_64_iframe x86_iframe_t;

struct x86_64_context_switch_frame {
	uint64_t r15, r14, r13, r12;
	uint64_t rbp;
	uint64_t rbx;
	uint64_t rflags;
	uint64_t rip;
};

void x86_64_context_switch(vaddr_t *oldsp, vaddr_t newsp);

/*
 * x86-64 TSS structure
 */
typedef struct {
	uint32_t rsvd0;
	uint64_t rsp0;
	uint64_t rsp1;
	uint64_t rsp2;
	uint32_t rsvd1;
	uint32_t rsvd2;
	uint64_t ist1;
	uint64_t ist2;
	uint64_t ist3;
	uint64_t ist4;
	uint64_t ist5;
	uint64_t ist6;
	uint64_t ist7;
	uint32_t rsvd3;
	uint32_t rsvd4;
	uint16_t rsvd5;
	uint16_t iomap_base;
} __packed tss_64_t;

typedef tss_64_t tss_t;

#define X86_CR0_PE 0x00000001 /* protected mode enable */
#define X86_CR0_MP 0x00000002 /* monitor coprocessor */
#define X86_CR0_EM 0x00000004 /* emulation */
#define X86_CR0_TS 0x00000008 /* task switched */
#define X86_CR0_NE 0x00000020 /* enable x87 exception */
#define X86_CR0_WP 0x00010000 /* supervisor write protect */
#define X86_CR0_NW 0x20000000 /* not write-through */
#define X86_CR0_CD 0x40000000 /* cache disable */
#define X86_CR0_PG 0x80000000 /* enable paging */
#define X86_CR4_PAE 0x00000020 /* PAE paging */
#define X86_CR4_OSFXSR 0x00000200 /* os supports fxsave */
#define X86_CR4_OSXMMEXPT 0x00000400 /* os supports xmm exception */
#define X86_CR4_OSXSAVE 0x00040000 /* os supports xsave */
#define X86_CR4_SMEP 0x00100000 /* SMEP protection enabling */
#define X86_CR4_SMAP 0x00200000 /* SMAP protection enabling */
#define x86_EFER_NXE 0x00000800 /* to enable execute disable bit */
#define x86_MSR_EFER 0xc0000080 /* EFER Model Specific Register id */
#define X86_CR4_PSE 0xffffffef /* Disabling PSE bit in the CR4 */

/* SYSCALL Handling */
#define SYSENTER_CS_MSR    0x174
#define SYSENTER_ESP_MSR   0x175
#define SYSENTER_EIP_MSR   0x176

#define MAX_PHYSICAL_ADDR_MASK \
	GENMASK_64(63, (uint8_t)(x86_get_address_width() & 0xFF))

#define EFLAGS_RESERVED 0x00000002
#define IOPL_MASK       GENMASK_32(13, 12)
#define IF_MASK         GENMASK_32(9, 9)

static inline void set_in_cr0(uint64_t mask)
{
	__asm__ __volatile__ (
		"movq %%cr0,%%rax\n\t"
		"orq %0,%%rax\n\t"
		"movq %%rax,%%cr0\n\t"
		: : "irg" (mask)
		: "ax");
}

static inline void clear_in_cr0(uint64_t mask)
{
	__asm__ __volatile__ (
		"movq %%cr0, %%rax\n\t"
		"andq %0, %%rax\n\t"
		"movq %%rax, %%cr0\n\t"
		: : "irg" (~mask)
		: "ax");
}

static inline void x86_clts(void) {__asm__ __volatile__ ("clts"); }
static inline void x86_hlt(void) {__asm__ __volatile__ ("hlt"); }
static inline void x86_sti(void) {__asm__ __volatile__ ("sti"); }
static inline void x86_cli(void) {__asm__ __volatile__ ("cli"); }
static inline void x86_ltr(uint16_t sel)
{
	__asm__ __volatile__ ("ltr %%ax" :: "a" (sel));
}

static inline uint64_t x86_get_cr2(void)
{
	uint64_t rv;

	__asm__ __volatile__ (
		"movq %%cr2, %0"
		: "=r" (rv)
	);

	return rv;
}

typedef uint64_t x86_flags_t;

static inline uint64_t x86_save_flags(void)
{
	uint64_t state;

	__asm__ volatile(
		"pushfq\n\t"
		"popq %0\n\t"
		: "=rm" (state)
		:: "memory");

	return state;
}

static inline void x86_restore_flags(uint64_t flags)
{
	__asm__ volatile(
		"pushq %0\n\t"
		"popfq\n\t"
		:: "g" (flags)
		: "memory",
		"cc");
}

#define rdtsc(low, high) \
	{__asm__ __volatile__("rdtsc" : "=a" (low), "=d" (high)); }

#define rdtscl(low) \
	{__asm__ __volatile__("rdtsc" : "=a" (low) : : "edx"); }

#define rdtscll(val) \
	{__asm__ __volatile__("rdtsc" : "=A" (val)); }

static inline uint8_t inp(uint16_t _port)
{
	uint8_t rv;

	__asm__ __volatile__ (
		"inb %1, %0"
		: "=a" (rv)
		: "d" (_port));

	return (rv);
}

static inline uint16_t inpw(uint16_t _port)
{
	uint16_t rv;

	__asm__ __volatile__ (
		"inw %1, %0"
		: "=a" (rv)
		: "d" (_port));

	return (rv);
}

static inline uint32_t inpd(uint16_t _port)
{
	uint32_t rv;

	__asm__ __volatile__ (
		"inl %1, %0"
		: "=a" (rv)
		: "d" (_port));

	return (rv);
}

static inline void outp(uint16_t _port, uint8_t _data)
{
	__asm__ __volatile__ (
		"outb %1, %0"
		:
		: "d" (_port),
		"a" (_data));
}

static inline void outpw(uint16_t _port, uint16_t _data)
{
	__asm__ __volatile__ (
		"outw %1, %0"
		:
		: "d" (_port),
		"a" (_data));
}

static inline void outpd(uint16_t _port, uint32_t _data)
{
	__asm__ __volatile__ (
		"outl %1, %0"
		:
		: "d" (_port),
		"a" (_data));
}

static inline void inprep(uint16_t _port, uint8_t *_buffer, uint32_t _reads)
{
	__asm__ __volatile__ (
		"pushfq\n\t"
		"cli\n\t"
		"cld\n\t"
		"rep insb\n\t"
		"popfq\n\t"
		:
		: "d" (_port),
		"D" (_buffer),
		"c" (_reads));
}

static inline void outprep(uint16_t _port, uint8_t *_buffer, uint32_t _writes)
{
	__asm__ __volatile__ (
		"pushfq\n\t"
		"cli\n\t"
		"cld\n\t"
		"rep outsb\n\t"
		"popfq\n\t"
		:
		: "d" (_port),
		"S" (_buffer),
		"c" (_writes));
}

static inline void inpwrep(uint16_t _port, uint16_t *_buffer, uint32_t _reads)
{
	__asm__ __volatile__ (
		"pushfq\n\t"
		"cli\n\t"
		"cld\n\t"
		"rep insw\n\t"
		"popfq\n\t"
		:
		: "d" (_port),
		"D" (_buffer),
		"c" (_reads));
}

static inline void outpwrep(uint16_t _port, uint16_t *_buffer, uint32_t _writes)
{
	__asm__ __volatile__ (
		"pushfq\n\t"
		"cli\n\t"
		"cld\n\t"
		"rep outsw\n\t"
		"popfq\n\t"
		:
		: "d" (_port),
		"S" (_buffer),
		"c" (_writes));
}

static inline void inpdrep(uint16_t _port, uint32_t *_buffer, uint32_t _reads)
{
	__asm__ __volatile__ (
		"pushfq\n\t"
		"cli\n\t"
		"cld\n\t"
		"rep insl\n\t"
		"popfq\n\t"
		:
		: "d" (_port),
		"D" (_buffer),
		"c" (_reads));
}

static inline void outpdrep(uint16_t _port, uint32_t *_buffer, uint32_t _writes)
{
	__asm__ __volatile__ (
		"pushfq\n\t"
		"cli\n\t"
		"cld\n\t"
		"rep outsl\n\t"
		"popfq\n\t"
		:
		: "d" (_port),
		"S" (_buffer),
		"c" (_writes));
}

static inline uint64_t read_msr(uint32_t msr_id)
{
	uint64_t msr_read_val = 0;
	uint32_t low_val = 0;
	uint32_t high_val = 0;

	__asm__ __volatile__ (
		"rdmsr"
		: "=a" (low_val), "=d"(high_val)
		: "c" (msr_id));

	msr_read_val = high_val;
	msr_read_val = (msr_read_val << 32) | low_val;

	return msr_read_val;
}

static inline void write_msr(uint32_t msr_id, uint64_t msr_write_val)
{
	uint32_t low_val = (uint32_t)msr_write_val;
	uint32_t high_val = (uint32_t)(msr_write_val >> 32);

	__asm__ __volatile__ (
		"wrmsr"
		: : "c" (msr_id), "a" (low_val), "d"(high_val));
}

static inline uint64_t x86_get_cr3(void)
{
	uint64_t rv;

	__asm__ __volatile__ (
		"movq %%cr3, %0"
		: "=r" (rv));
	return rv;
}

static inline void x86_set_cr3(uint64_t in_val)
{
	__asm__ __volatile__ (
		"movq %0,%%cr3"
		:
		: "r" (in_val));
}

static inline uint64_t x86_get_cr4(void)
{
	uint64_t rv;

	__asm__ __volatile__ (
		"movq %%cr4, %0"
		: "=r" (rv));

	return rv;
}

static inline void x86_set_cr4(uint64_t in_val)
{
	__asm__ __volatile__ (
		"movq %0,%%cr4"
		:
		: "r" (in_val));
}

static inline uint64_t x86_get_cr0(void)
{
	uint64_t rv;

	__asm__ __volatile__ (
		"movq %%cr0, %0"
		: "=r" (rv));

	return rv;
}

static inline void x86_set_cr0(uint64_t in_val)
{
	__asm__ __volatile__ (
		"movq %0,%%cr0"
		:
		: "r" (in_val));
}

static inline void x86_set_cr8(uint64_t in_val)
{
	__asm__ __volatile__ (
		"movq %0,%%cr8"
		:
		: "r" (in_val));
}

static inline uint32_t x86_get_address_width(void)
{
	uint32_t rv;

	__asm__ __volatile__ (
		"cpuid"
		: "=a" (rv)
		: "a" (X86_CPUID_ADDR_WIDTH));
	/*
	 *Extracting bit 15:0 from eax register
	 *Bits 07-00: #Physical Address Bits
	 *Bits 15-08: #Linear Address Bits
	 */
	return (rv & 0x0000ffff);
}

static inline uint64_t check_smep_avail(void)
{
	uint64_t reg_a = 0x07;
	uint64_t reg_b = 0x0;
	uint64_t reg_c = 0x0;

	__asm__ __volatile__ (
		"cpuid"
		: "=b" (reg_b)
		: "a" (reg_a), "c" (reg_c)
		: "edx");
	return ((reg_b>>0x07) & 0x1);
}

static inline uint64_t check_smap_avail(void)
{
	uint64_t reg_a = 0x07;
	uint64_t reg_b = 0x0;
	uint64_t reg_c = 0x0;

	__asm__ __volatile__ (
		"cpuid"
		: "=b" (reg_b)
		: "a" (reg_a), "c" (reg_c)
		: "edx");
	return ((reg_b>>0x14) & 0x1);
}

static inline void invd(void)
{
	__asm__ __volatile__ ("invd");
}

static inline void wbinvd(void)
{
	__asm__ __volatile__ ("wbinvd");
}

static inline void mfence(void)
{
	__asm__ volatile("mfence");
}

#ifdef __cplusplus
}
#endif

#endif
