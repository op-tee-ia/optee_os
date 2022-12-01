// SPDX-License-Identifier: BSD-2-Clause
/*
 *  Copyright (c) 2022 Intel Corporation
 */
 
#include <mm/core_memprot.h>
#include <trace.h>
#include <assert.h>

#include "virtio.h"

void vq_init(struct virtq* vq,
             struct virtq_raw* raw,
             struct virtio_config* vio,
             bool is_input)
{
    uint16_t flags = 0;

    if (is_input) {
        flags = VIRTQ_DESC_F_WRITE;
    }

    vq->raw = raw;
    vq->num_bufs = VQ_SIZE;
    for (size_t i = 0; i < vq->num_bufs; i++) {
        vq->raw->desc[i].flags = flags;
    }

    vq->vio = vio;
}

void vq_make_avail(struct virtq* vq, uint16_t desc_id)
{
    io_write_16(&vq->raw->avail.ring[vq->raw->avail.idx % vq->num_bufs],
                desc_id);
    io_write_16(&vq->raw->avail.idx, vq->raw->avail.idx + 1);
}

void vq_wait(struct virtq* vq)
{
    while (!vq_ready(vq)) {
    }
}

uint32_t vq_adv(struct virtq* vq)
{
    return vq->raw->used.ring[vq->last_used_idx++ % vq->num_bufs].len;
}

void vq_set_buf(struct virtq* vq,
                  uint16_t desc_id,
                  paddr_t data,
                  size_t len,
                  uint16_t flags)
{
    vq->raw->desc[desc_id].addr = data;
    vq->raw->desc[desc_id].len = len;
    vq->raw->desc[desc_id].flags = flags;
    if (flags & VIRTQ_DESC_F_NEXT) {
        vq->raw->desc[desc_id].next = (desc_id + 1) % vq->num_bufs;
    }
}

void send_vq1(struct virtq* vq, paddr_t data1, size_t len1)
{
    size_t idx = vq->last_used_idx;

    assert(data1 != 0 && len1 != 0);

    vq_set_buf(vq, idx % vq->num_bufs, data1, len1, 0x0);

    vq_make_avail(vq, idx % vq->num_bufs);

    vq_kick(vq);

    vq_wait(vq);

    vq_set_buf(vq, idx % vq->num_bufs, 0, 0, 0x0);

    vq_adv(vq);
}

void send_vq2(struct virtq* vq, paddr_t data1, size_t len1, paddr_t data2, size_t len2)
{
    size_t idx = vq->last_used_idx * 2;

    assert(data1 != 0 && len1 != 0);
    assert(data2 != 0);

    vq_set_buf(vq, idx % vq->num_bufs, data1, len1, VIRTQ_DESC_F_NEXT);
    vq_set_buf(vq, (idx+1) % vq->num_bufs, data2, len2, 0x0);

    vq_make_avail(vq, idx % vq->num_bufs);

    vq_kick(vq);

    vq_wait(vq);

    vq_set_buf(vq, idx % vq->num_bufs, 0, 0, 0x0);
    vq_set_buf(vq, (idx+1) % vq->num_bufs, 0, 0, 0x0);

    vq_adv(vq);
}

uint32_t recv_vq1(struct virtq* vq, paddr_t data1, size_t len1)
{
    size_t idx = vq->last_used_idx;

    assert(data1 != 0 && len1 != 0);

    vq_set_buf(vq, idx % vq->num_bufs, data1, len1, VIRTQ_DESC_F_WRITE);

    vq_make_avail(vq, idx % vq->num_bufs);

    vq_kick(vq);

    vq_wait(vq);

    vq_set_buf(vq, idx % vq->num_bufs, 0, 0, 0x0);

    return vq_adv(vq);
}

uint32_t recv_vq2(struct virtq* vq, paddr_t data1, size_t len1, paddr_t data2, size_t len2)
{
    size_t idx = vq->last_used_idx * 2;

    assert(data1 != 0 && len1 != 0);
    assert(data2 != 0 && len2 != 0);

    vq_set_buf(vq, idx % vq->num_bufs, data1, len1,
        VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT);
    vq_set_buf(vq, (idx+1) % vq->num_bufs, data2, len2, VIRTQ_DESC_F_WRITE);

    vq_make_avail(vq, idx % vq->num_bufs);

    vq_kick(vq);

    vq_wait(vq);

    vq_set_buf(vq, idx % vq->num_bufs, 0, 0, 0x0);
    vq_set_buf(vq, (idx+1) % vq->num_bufs, 0, 0, 0x0);

    return vq_adv(vq);
}
