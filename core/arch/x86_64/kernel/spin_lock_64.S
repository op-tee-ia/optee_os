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
   movl $SPINLOCK_UNLOCK, %eax
   movl $SPINLOCK_LOCK, %edx
   lock cmpxchg %edx, (%edi)
   jnz 2f
   ret
2:
   pause
   cmpl $SPINLOCK_UNLOCK,(%edi)
   je 1b
   jmp 2b
END_FUNC __cpu_spin_lock

/* unsigned int __cpu_spin_trylock(unsigned int *lock); */
FUNC __cpu_spin_trylock , :
    movl $SPINLOCK_UNLOCK, %eax
    movl $SPINLOCK_LOCK, %edx
    lock cmpxchg %edx, (%edi)
    ret
END_FUNC __cpu_spin_trylock

/* void __cpu_spin_unlock(unsigned int *lock); */
FUNC __cpu_spin_unlock , :
    movl  $SPINLOCK_UNLOCK, (%edi)
    ret
END_FUNC __cpu_spin_unlock
