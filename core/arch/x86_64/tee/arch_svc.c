// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2020, Arm Limited
 * Copyright (c) 2021, Intel Corporation
 */

#include <x86.h>
#include <assert.h>
#include <kernel/ldelf_syscalls.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <kernel/trace_ta.h>
#include <kernel/user_ta.h>
#include <ldelf.h>
#include <mm/vm.h>
#include <string.h>
#include <tee/arch_svc.h>
#include <tee/svc_cache.h>
#include <tee_syscall_numbers.h>
#include <tee/tee_svc_cryp.h>
#include <tee/tee_svc.h>
#include <tee/tee_svc_storage.h>

#include "arch_svc_private.h"

void syscall_sys_return(unsigned long ret)
{
	vaddr_t sp = 0;

	x86_cli();
	sp = thread_get_kern_sp();
	__syscall_sys_return(ret, sp);
}

void syscall_panic(unsigned long code)
{
	vaddr_t sp = 0;

	x86_cli();
	sp = thread_get_kern_sp();
	__syscall_panic(code, sp);
}

const unsigned long tee_syscall_table[] = {
	(unsigned long)syscall_sys_return,
	(unsigned long)syscall_log,
	(unsigned long)syscall_panic,
	(unsigned long)syscall_get_property,
	(unsigned long)syscall_get_property_name_to_index,
	(unsigned long)syscall_open_ta_session,
	(unsigned long)syscall_close_ta_session,
	(unsigned long)syscall_invoke_ta_command,
	(unsigned long)syscall_check_access_rights,
	(unsigned long)syscall_get_cancellation_flag,
	(unsigned long)syscall_unmask_cancellation,
	(unsigned long)syscall_mask_cancellation,
	(unsigned long)syscall_wait,
	(unsigned long)syscall_get_time,
	(unsigned long)syscall_set_ta_time,
	(unsigned long)syscall_cryp_state_alloc,
	(unsigned long)syscall_cryp_state_copy,
	(unsigned long)syscall_cryp_state_free,
	(unsigned long)syscall_hash_init,
	(unsigned long)syscall_hash_update,
	(unsigned long)syscall_hash_final,
	(unsigned long)syscall_cipher_init,
	(unsigned long)syscall_cipher_update,
	(unsigned long)syscall_cipher_final,
	(unsigned long)syscall_cryp_obj_get_info,
	(unsigned long)syscall_cryp_obj_restrict_usage,
	(unsigned long)syscall_cryp_obj_get_attr,
	(unsigned long)syscall_cryp_obj_alloc,
	(unsigned long)syscall_cryp_obj_close,
	(unsigned long)syscall_cryp_obj_reset,
	(unsigned long)syscall_cryp_obj_populate,
	(unsigned long)syscall_cryp_obj_copy,
	(unsigned long)syscall_cryp_derive_key,
	(unsigned long)syscall_cryp_random_number_generate,
	(unsigned long)syscall_authenc_init,
	(unsigned long)syscall_authenc_update_aad,
	(unsigned long)syscall_authenc_update_payload,
	(unsigned long)syscall_authenc_enc_final,
	(unsigned long)syscall_authenc_dec_final,
	(unsigned long)syscall_asymm_operate,
	(unsigned long)syscall_asymm_verify,
	(unsigned long)syscall_storage_obj_open,
	(unsigned long)syscall_storage_obj_create,
	(unsigned long)syscall_storage_obj_del,
	(unsigned long)syscall_storage_obj_rename,
	(unsigned long)syscall_storage_alloc_enum,
	(unsigned long)syscall_storage_free_enum,
	(unsigned long)syscall_storage_reset_enum,
	(unsigned long)syscall_storage_start_enum,
	(unsigned long)syscall_storage_next_enum,
	(unsigned long)syscall_storage_obj_read,
	(unsigned long)syscall_storage_obj_write,
	(unsigned long)syscall_storage_obj_trunc,
	(unsigned long)syscall_storage_obj_seek,
	(unsigned long)syscall_obj_generate_key,
	(unsigned long)syscall_not_supported,
	(unsigned long)syscall_not_supported,
	(unsigned long)syscall_not_supported,
	(unsigned long)syscall_not_supported,
	(unsigned long)syscall_not_supported,
	(unsigned long)syscall_not_supported,
	(unsigned long)syscall_not_supported,
	(unsigned long)syscall_not_supported,
	(unsigned long)syscall_not_supported,
	(unsigned long)syscall_not_supported,
	(unsigned long)syscall_not_supported,
	(unsigned long)syscall_not_supported,
	(unsigned long)syscall_not_supported,
	(unsigned long)syscall_not_supported,
	(unsigned long)syscall_not_supported,
	(unsigned long)syscall_cache_operation,
};

/*
 * The ldelf return, log, panic syscalls have the same functionality and syscall
 * number as the user TAs'. To avoid unnecessary code duplication, the ldelf SVC
 * handler doesn't implement separate functions for these.
 */
const unsigned long ldelf_syscall_table[] = {
	(unsigned long)syscall_sys_return,
	(unsigned long)syscall_log,
	(unsigned long)syscall_panic,
	(unsigned long)ldelf_syscall_map_zi,
	(unsigned long)ldelf_syscall_unmap,
	(unsigned long)ldelf_syscall_open_bin,
	(unsigned long)ldelf_syscall_close_bin,
	(unsigned long)ldelf_syscall_map_bin,
	(unsigned long)ldelf_syscall_copy_from_bin,
	(unsigned long)ldelf_syscall_set_prot,
	(unsigned long)ldelf_syscall_remap,
	(unsigned long)ldelf_syscall_gen_rnd_num,
};

uint64_t tee_svc_sys_return_helper(uint64_t ret, uint64_t sp)
{
    thread_set_kern_sp(sp);

    write_msr(SYSENTER_ESP_MSR, sp);

    return ret;
}
