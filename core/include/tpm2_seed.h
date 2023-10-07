#ifndef _TPM2TEST_H_
#define _TPM2TEST_H_

#include <efi.h>
#include <lib.h>

EFI_STATUS tpm2_init_seed(void);

EFI_STATUS tpm2_read_lock_seed(OUT UINT8 *Key, IN UINT16 KeySize);

#endif