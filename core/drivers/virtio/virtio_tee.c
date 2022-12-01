// SPDX-License-Identifier: BSD-2-Clause
/*
 *  Copyright (c) 2022 Intel Corporation
 */
#include <drivers/virtio_tee.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <sm/optee_smc.h>
#include <assert.h>
#include <optee_msg.h>
#include <string.h>
#include <trace.h>

#include "virtio.h"
#include "virtio_device.h"

static struct virtq smc_input;
static struct virtq smc_output;
static struct virtq_raw* smc_input_raw;
static struct virtq_raw* smc_output_raw;
static struct virtio_vsock_hdr* smc_pkt_hdr;
static paddr_t smc_pkt_hdr_phys;
static uint64_t tee_cid;
static uint32_t smc_fwd_cnt;

struct thread_smc_args* g_smc_args;
static paddr_t g_smc_args_phys;

#define VIRTIO_VSOCK_HOST_CID           0x2

#define VIRTIO_VSOCK_DST_PORT           1234
#define VIRTIO_VSOCK_SMC_PORT           1234

#define VIRTIO_VSOCK_HDR_LEN    sizeof(struct virtio_vsock_hdr)
#define OPTEE_SMC_ARG_LEN       sizeof(struct thread_smc_args)

static void vq_init_global_vars(void)
{
    size_t size = 0;
    vaddr_t start = 0;
    vaddr_t end = 0;

    core_mmu_get_mem_by_type(MEM_AREA_RAM_NSEC, &start, &end);
    if (!start || !end)
        panic("Can't find region for virtio memory");
    DMSG("IO NSEC range: 0x%lx/0x%lx\n", start, end);

    size = ROUNDUP(sizeof(struct virtq_raw), PAGE_SIZE);
    DMSG("smc input raw: 0x%lx/0x%lx/0x%lx\n", start, size, sizeof(struct virtq_raw));
    memset((void *)start, 0, size);
    smc_input_raw = (struct virtq_raw *)start;

    start = start + size;
    DMSG("smc output raw: 0x%lx/0x%lx\n", start, size);
    memset((void *)start, 0, size);
    smc_output_raw = (struct virtq_raw *)start;

    start = start + size;
    smc_pkt_hdr = (struct virtio_vsock_hdr *)start;
    smc_pkt_hdr_phys = virt_to_phys(smc_pkt_hdr);
    memset((void *)smc_pkt_hdr, 0, VIRTIO_VSOCK_HDR_LEN);
    g_smc_args = (struct thread_smc_args *)(start + VIRTIO_VSOCK_HDR_LEN);
    g_smc_args_phys = virt_to_phys(g_smc_args);
    memset((void *)g_smc_args, 0, VIRTIO_VSOCK_BUFF_ALLOC);
    DMSG("smc_pkt_hdr_phys: 0x%lx/g_smc_args_phys: 0x%lx\n",
        smc_pkt_hdr_phys, g_smc_args_phys);
}

static void virtio_virtqueue_setup(struct virtio_config* vio)
{
    vq_init_global_vars();
    
    vq_init(&smc_input, smc_input_raw, vio, true);
    vq_init(&smc_output, smc_output_raw, vio, false);

    /* Attach the virtqueues to the relevant queue IDs */
    vq_attach(&smc_input, 0);
    vq_attach(&smc_output, 1);
}

static bool virtio_vsock_connect(void)
{
    smc_pkt_hdr->type = 0x1;    //VIRTIO_VSOCK_TYPE_STREAM
    smc_pkt_hdr->op = 0x1;      //VIRTIO_VSOCK_OP_REQUEST
    smc_pkt_hdr->src_cid = tee_cid;
    smc_pkt_hdr->dst_cid = VIRTIO_VSOCK_HOST_CID;
    smc_pkt_hdr->src_port = VIRTIO_VSOCK_SMC_PORT;
    smc_pkt_hdr->dst_port = VIRTIO_VSOCK_DST_PORT;
    smc_pkt_hdr->flags = 0x0;
    smc_pkt_hdr->len = 0x0;
    smc_pkt_hdr->buf_alloc = VIRTIO_VSOCK_BUFF_ALLOC;
    smc_pkt_hdr->fwd_cnt = 0x0;

    IMSG("start to connect\n");
    /* Connect to host */
    send_vq1(&smc_output, smc_pkt_hdr_phys, VIRTIO_VSOCK_HDR_LEN);
    IMSG("connect send ok\n");

    /* Get response from host */
    recv_vq1(&smc_input, smc_pkt_hdr_phys, VIRTIO_VSOCK_HDR_LEN);

    if (smc_pkt_hdr->src_cid == VIRTIO_VSOCK_HOST_CID &&
        smc_pkt_hdr->dst_cid == tee_cid &&
        smc_pkt_hdr->op == 0x2) { //VIRTIO_VSOCK_OP_RESPONSE
        IMSG("connect OK: %d/%d/%d/%ld/%ld/%d\n",
            smc_pkt_hdr->src_port, smc_pkt_hdr->dst_port, smc_pkt_hdr->op,
            smc_pkt_hdr->src_cid, smc_pkt_hdr->dst_cid, smc_pkt_hdr->len);
        return true;
    } else {
        EMSG("connect failed: %d/%d/%d/%ld/%ld/%d\n",
            smc_pkt_hdr->src_port, smc_pkt_hdr->dst_port, smc_pkt_hdr->op,
            smc_pkt_hdr->src_cid, smc_pkt_hdr->dst_cid, smc_pkt_hdr->len);
        return false;
    }
}

void virtio_tee_init(void)
{
    struct virtio_config* tee_vio = virtio_tee_probe();
    if (!tee_vio) {
        /* We didn't find any virtio tee device */
        panic("Virtio VSock probe failed!!!\n");
    }

    tee_cid = virtio_get_device_config();
    IMSG("tee_cid=0x%lx\n", tee_cid);

    /* Reset device */
    virtio_reset_device(tee_vio);

    /* Acknowledge device */
    virtio_or_status(tee_vio, VIRTIO_STATUS_ACKNOWLEDGE);

    /* Set driver bit */
    virtio_or_status(tee_vio, VIRTIO_STATUS_DRIVER);

    /* Set up guest page size */
    virtio_set_guest_page_size(tee_vio, PAGE_SIZE);

    /* Set up virtqueue */
    virtio_virtqueue_setup(tee_vio);

    /* We are now able to drive the device */
    virtio_or_status(tee_vio, VIRTIO_STATUS_DRIVER_OK);

    if (!virtio_vsock_connect()) {
        panic("Virtio vsock connect failed!!!\n");
    }

    virtio_pci_common_cfg_print(tee_vio);
}

//TODO: may need to add cpu id parameter for SMP
void virtio_smc_recv_first(void)
{
    /* Get SMC arguments from host */
    recv_vq1(&smc_input, smc_pkt_hdr_phys, VIRTIO_VSOCK_HDR_LEN + OPTEE_SMC_ARG_LEN);
    smc_fwd_cnt += OPTEE_SMC_ARG_LEN;
    DMSG("recv args: 0x%lx/0x%lx/0x%lx/0x%lx/0x%lx/0x%lx\n", g_smc_args->a0,
        g_smc_args->a1, g_smc_args->a2, g_smc_args->a3, g_smc_args->a4, g_smc_args->a5);
}

//TODO: may need to add cpu id parameter for SMP
void virtio_smc_sim(void)
{
    uint32_t recv_len = 0;

    DMSG("send: 0x%lx/0x%lx/0x%lx/0x%lx/%d\n", g_smc_args->a0, g_smc_args->a1,
        g_smc_args->a2, g_smc_args->a3, smc_fwd_cnt);
    smc_pkt_hdr->type = 0x1; //VIRTIO_VSOCK_TYPE_STREAM
    smc_pkt_hdr->op = 0x5;   //VIRTIO_VSOCK_OP_RW
    smc_pkt_hdr->src_cid = tee_cid;
    smc_pkt_hdr->dst_cid = VIRTIO_VSOCK_HOST_CID;
    smc_pkt_hdr->src_port = VIRTIO_VSOCK_SMC_PORT;
    smc_pkt_hdr->dst_port = VIRTIO_VSOCK_DST_PORT;
    smc_pkt_hdr->flags = 0x0;
    smc_pkt_hdr->len = OPTEE_SMC_ARG_LEN;
    smc_pkt_hdr->buf_alloc = VIRTIO_VSOCK_BUFF_ALLOC;
    smc_pkt_hdr->fwd_cnt = smc_fwd_cnt;

    if (g_smc_args->a0 == VIRTIO_SHM_COPY_REQ) {
        //prepare to copy shared memory to REE
        smc_pkt_hdr->len += g_smc_args->a2;
        memcpy((void *)(g_smc_args + 1), phys_to_virt(g_smc_args->a1, MEM_AREA_NSEC_SHM),
            g_smc_args->a2);
    }
    send_vq1(&smc_output, smc_pkt_hdr_phys, VIRTIO_VSOCK_HDR_LEN + smc_pkt_hdr->len);

    /* Get SMC arguments from host */
    DMSG("start to recv pkt\n");
    recv_len = recv_vq1(&smc_input, smc_pkt_hdr_phys, VIRTIO_VSOCK_HDR_LEN + VIRTIO_VSOCK_BUFF_ALLOC);
    smc_fwd_cnt += (recv_len - VIRTIO_VSOCK_HDR_LEN);
    DMSG("recv 0x%x args: 0x%lx/0x%lx/0x%lx/0x%lx/0x%lx/0x%lx\n", recv_len, g_smc_args->a0,
        g_smc_args->a1, g_smc_args->a2, g_smc_args->a3, g_smc_args->a4, g_smc_args->a5);

    if (recv_len > (OPTEE_SMC_ARG_LEN + VIRTIO_VSOCK_HDR_LEN)) {
            assert((recv_len - OPTEE_SMC_ARG_LEN - VIRTIO_VSOCK_HDR_LEN) == g_smc_args->a2);
            memcpy(phys_to_virt(g_smc_args->a1, MEM_AREA_NSEC_SHM),
                (void *)(g_smc_args + 1), g_smc_args->a2);
    }
}


