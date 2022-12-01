/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Intel Corporation
 */

#ifndef DRIVER_VIRTIO_TEE_H
#define DRIVER_VIRTIO_TEE_H

#define VIRTIO_SHM_COPY_REQ         0x5a5a5a5a
#define VIRTIO_VSOCK_BUFF_ALLOC     0x10000

/*
 * Initializes a single VirtIO tee device
 */
void virtio_tee_init(void);

/*
 * SMC virtio recv only
 */
void virtio_smc_recv_first(void);

/*
 * SMC virtio simulation
 */
void virtio_smc_sim(void);

#endif
