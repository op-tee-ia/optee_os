/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2013-2014, ARM Limited and Contributors. All rights reserved.
 */

#include <asm.S>
#include <kernel/spinlock.h>

/* void __cpu_spin_lock(unsigned int *lock); */
FUNC __cpu_spin_lock , :
1:
   movq $SPINLOCK_UNLOCK, %rax
   movq $SPINLOCK_LOCK, %rdx
   lock cmpxchgq %rdx, (%rdi)
   jnz 2f
   retq
2:
   pause
   cmp $SPINLOCK_UNLOCK,(%rdi)
   je 1b
   jmp 2b
END_FUNC __cpu_spin_lock

/* unsigned int __cpu_spin_trylock(unsigned int *lock); */
FUNC __cpu_spin_trylock , :
    movq $SPINLOCK_UNLOCK, %rax
    movq $SPINLOCK_LOCK, %rdx
    lock cmpxchgq %rdx, (%rdi)
    retq
END_FUNC __cpu_spin_trylock

/* void __cpu_spin_unlock(unsigned int *lock); */
FUNC __cpu_spin_unlock , :
    movq  $SPINLOCK_UNLOCK, (%rdi)
    retq
END_FUNC __cpu_spin_unlock
