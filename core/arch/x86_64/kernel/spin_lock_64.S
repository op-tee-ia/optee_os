/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2013-2014, ARM Limited and Contributors. All rights reserved.
 */

#include <asm.S>
#include <kernel/spinlock.h>

//TODO: will consider SMP later
/* void __cpu_spin_lock(unsigned int *lock); */
FUNC __cpu_spin_lock , :
    movq $SPINLOCK_LOCK, (%rdi)
    retq
END_FUNC __cpu_spin_lock

/* unsigned int __cpu_spin_trylock(unsigned int *lock); */
FUNC __cpu_spin_trylock , :
    movq $0, %rax
    movq $SPINLOCK_LOCK, (%rdi)
    retq
END_FUNC __cpu_spin_trylock

/* void __cpu_spin_unlock(unsigned int *lock); */
FUNC __cpu_spin_unlock , :
    movq  $SPINLOCK_UNLOCK, (%rdi)
    retq
END_FUNC __cpu_spin_unlock
