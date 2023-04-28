/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Intel Corporation
 */

#ifndef DRIVER_IO_MEM_H
#define DRIVER_IO_MEM_H

#include <types_ext.h>

#define mb()        __asm__ volatile ("mfence":::"memory");
#define wmb()       __asm__ volatile ("sfence":::"memory");
#define rmb()       __asm__ volatile ("lfence":::"memory");

static inline uint8_t io_read_8(const volatile void* addr) {
    uint8_t out;

    __asm__ __volatile__("movb (%%rdx), %%al" : "=a"(out) : "d"(addr));
    rmb();

    return out;
}

static inline uint16_t io_read_16(const volatile void* addr) {
    uint16_t out;

    __asm__ __volatile__("movw (%%rdx), %%ax" : "=a"(out) : "d"(addr));
    rmb();

    return out;
}
static inline uint32_t io_read_32(const volatile void* addr) {
    uint32_t out;

    __asm__ __volatile__("movl (%%rdx), %%eax" : "=a"(out) : "d"(addr));
    rmb();

    return out;
}

static inline uint64_t io_read_64(const volatile void* addr) {
    uint64_t out;

    __asm__ __volatile__("movq (%%rdx), %%rax" : "=a"(out) : "d"(addr));
    rmb();

    return out;
}

static inline void io_write_8(volatile void* addr, uint8_t val) {
    wmb();
    __asm__ __volatile__("movb %%al, (%%rdx)" ::"a"(val), "d"(addr) : "memory");
}

static inline void io_write_16(volatile void* addr, uint16_t val) {
    wmb();
    __asm__ __volatile__("movw %%ax, (%%rdx)" ::"a"(val), "d"(addr) : "memory");
}

static inline void io_write_32(volatile void* addr, uint32_t val) {
    wmb();
    __asm__ __volatile__("movl %%eax, (%%rdx)" ::"a"(val), "d"(addr) : "memory");
}

static inline void io_write_64(volatile void* addr, uint64_t val) {
    wmb();
    __asm__ __volatile__("movq %%rax, (%%rdx)" ::"a"(val), "d"(addr) : "memory");
}

#endif
