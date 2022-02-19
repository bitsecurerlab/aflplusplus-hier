/*
 * Virtio driver bits
 *
 * Copyright (c) 2013 Alexander Graf <agraf@suse.de>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or (at
 * your option) any later version. See the COPYING file in the top-level
 * directory.
 */

#include "s390-ccw.h"
#include "virtio.h"

static struct vring block;

static char chsc_page[PAGE_SIZE] __attribute__((__aligned__(PAGE_SIZE)));

static long kvm_hypercall(unsigned long nr, unsigned long param1,
                          unsigned long param2)
{
    register ulong r_nr asm("1") = nr;
    register ulong r_param1 asm("2") = param1;
    register ulong r_param2 asm("3") = param2;
    register long retval asm("2");

    asm volatile ("diag 2,4,0x500"
                  : "=d" (retval)
                  : "d" (r_nr), "0" (r_param1), "r"(r_param2)
                  : "memory", "cc");

    return retval;
}

static void virtio_notify(struct subchannel_id schid)
{
    kvm_hypercall(KVM_S390_VIRTIO_CCW_NOTIFY, *(u32 *)&schid, 0);
}

/***********************************************
 *             Virtio functions                *
 ***********************************************/

static int drain_irqs(struct subchannel_id schid)
{
    struct irb irb = {};
    int r = 0;

    while (1) {
        /* FIXME: make use of TPI, for that enable subchannel and isc */
        if (tsch(schid, &irb)) {
            /* Might want to differentiate error codes later on. */
            if (irb.scsw.cstat) {
                r = -EIO;
            } else if (irb.scsw.dstat != 0xc) {
                r = -EIO;
            }
            return r;
        }
    }
}

static int run_ccw(struct subchannel_id schid, int cmd, void *ptr, int len)
{
    struct ccw1 ccw = {};
    struct cmd_orb orb = {};
    struct schib schib;
    int r;

    /* start command processing */
    stsch_err(schid, &schib);
    schib.scsw.ctrl = SCSW_FCTL_START_FUNC;
    msch(schid, &schib);

    /* start subchannel command */
    orb.fmt = 1;
    orb.cpa = (u32)(long)&ccw;
    orb.lpm = 0x80;

    ccw.cmd_code = cmd;
    ccw.cda = (long)ptr;
    ccw.count = len;

    r = ssch(schid, &orb);
    /*
     * XXX Wait until device is done processing the CCW. For now we can
     *     assume that a simple tsch will have finished the CCW processing,
     *     but the architecture allows for asynchronous operation
     */
    if (!r) {
        r = drain_irqs(schid);
    }
    return r;
}

static void virtio_set_status(struct subchannel_id schid,
                              unsigned long dev_addr)
{
    unsigned char status = dev_addr;
    if (run_ccw(schid, CCW_CMD_WRITE_STATUS, &status, sizeof(status))) {
        virtio_panic("Could not write status to host!\n");
    }
}

static void virtio_reset(struct subchannel_id schid)
{
    run_ccw(schid, CCW_CMD_VDEV_RESET, NULL, 0);
}

static void vring_init(struct vring *vr, unsigned int num, void *p,
                       unsigned long align)
{
    debug_print_addr("init p", p);
    vr->num = num;
    vr->desc = p;
    vr->avail = p + num*sizeof(struct vring_desc);
    vr->used = (void *)(((unsigned long)&vr->avail->ring[num] + align-1)
                & ~(align - 1));

    /* Zero out all relevant field */
    vr->avail->flags = 0;
    vr->avail->idx = 0;

    /* We're running with interrupts off anyways, so don't bother */
    vr->used->flags = VRING_USED_F_NO_NOTIFY;
    vr->used->idx = 0;
    vr->used_idx = 0;
    vr->next_idx = 0;

    debug_print_addr("init vr", vr);
}

static void vring_notify(struct subchannel_id schid)
{
    virtio_notify(schid);
}

static void vring_send_buf(struct vring *vr, void *p, int len, int flags)
{
    /* For follow-up chains we need to keep the first entry point */
    if (!(flags & VRING_HIDDEN_IS_CHAIN)) {
        vr->avail->ring[vr->avail->idx % vr->num] = vr->next_idx;
    }

    vr->desc[vr->next_idx].addr = (ulong)p;
    vr->desc[vr->next_idx].len = len;
    vr->desc[vr->next_idx].flags = flags & ~VRING_HIDDEN_IS_CHAIN;
    vr->desc[vr->next_idx].next = vr->next_idx;
    vr->desc[vr->next_idx].next++;
    vr->next_idx++;

    /* Chains only have a single ID */
    if (!(flags & VRING_DESC_F_NEXT)) {
        vr->avail->idx++;
    }
}

static u64 get_clock(void)
{
    u64 r;

    asm volatile("stck %0" : "=Q" (r) : : "cc");
    return r;
}

static ulong get_second(void)
{
    return (get_clock() >> 12) / 1000000;
}

/*
 * Wait for the host to reply.
 *
 * timeout is in seconds if > 0.
 *
 * Returns 0 on success, 1 on timeout.
 */
static int vring_wait_reply(struct vring *vr, int timeout)
{
    ulong target_second = get_second() + timeout;
    struct subchannel_id schid = vr->schid;
    int r = 0;

    /* Wait until the used index has moved. */
    while (vr->used->idx == vr->used_idx) {
        vring_notify(schid);
        if (timeout && (get_second() >= target_second)) {
            r = 1;
            break;
        }
        yield();
    }

    vr->used_idx = vr->used->idx;
    vr->next_idx = 0;
    vr->desc[0].len = 0;
    vr->desc[0].flags = 0;

    return r;
}

/***********************************************
 *               Virtio block                  *
 ***********************************************/

int virtio_read_many(ulong sector, void *load_addr, int sec_num)
{
    struct virtio_blk_outhdr out_hdr;
    u8 status;
    int r;

    /* Tell the host we want to read */
    out_hdr.type = VIRTIO_BLK_T_IN;
    out_hdr.ioprio = 99;
    out_hdr.sector = virtio_sector_adjust(sector);

    vring_send_buf(&block, &out_hdr, sizeof(out_hdr), VRING_DESC_F_NEXT);

    /* This is where we want to receive data */
    vring_send_buf(&block, load_addr, virtio_get_block_size() * sec_num,
                   VRING_DESC_F_WRITE | VRING_HIDDEN_IS_CHAIN |
                   VRING_DESC_F_NEXT);

    /* status field */
    vring_send_buf(&block, &status, sizeof(u8), VRING_DESC_F_WRITE |
                   VRING_HIDDEN_IS_CHAIN);

    /* Now we can tell the host to read */
    vring_wait_reply(&block, 0);

    r = drain_irqs(block.schid);
    if (r) {
        /* Well, whatever status is supposed to contain... */
        status = 1;
    }
    return status;
}

unsigned long virtio_load_direct(ulong rec_list1, ulong rec_list2,
                                 ulong subchan_id, void *load_addr)
{
    u8 status;
    int sec = rec_list1;
    int sec_num = ((rec_list2 >> 32) & 0xffff) + 1;
    int sec_len = rec_list2 >> 48;
    ulong addr = (ulong)load_addr;

    if (sec_len != virtio_get_block_size()) {
        return -1;
    }

    sclp_print(".");
    status = virtio_read_many(sec, (void *)addr, sec_num);
    if (status) {
        virtio_panic("I/O Error");
    }
    addr += sec_num * virtio_get_block_size();

    return addr;
}

int virtio_read(ulong sector, void *load_addr)
{
    return virtio_read_many(sector, load_addr, 1);
}

static VirtioBlkConfig blk_cfg = {};
static bool guessed_disk_nature;

bool virtio_guessed_disk_nature(void)
{
    return guessed_disk_nature;
}

void virtio_assume_scsi(void)
{
    guessed_disk_nature = true;
    blk_cfg.blk_size = 512;
    blk_cfg.physical_block_exp = 0;
}

void virtio_assume_eckd(void)
{
    guessed_disk_nature = true;
    blk_cfg.blk_size = 4096;
    blk_cfg.physical_block_exp = 0;

    /* this must be here to calculate code segment position */
    blk_cfg.geometry.heads = 15;
    blk_cfg.geometry.sectors = 12;
}

bool virtio_disk_is_scsi(void)
{
    if (guessed_disk_nature) {
        return (virtio_get_block_size()  == 512);
    }
    return (blk_cfg.geometry.heads == 255)
        && (blk_cfg.geometry.sectors == 63)
        && (virtio_get_block_size()  == 512);
}

/*
 * Other supported value pairs, if any, would need to be added here.
 * Note: head count is always 15.
 */
static inline u8 virtio_eckd_sectors_for_block_size(int size)
{
    switch (size) {
    case 512:
        return 49;
    case 1024:
        return 33;
    case 2048:
        return 21;
    case 4096:
        return 12;
    }
    return 0;
}

bool virtio_disk_is_eckd(void)
{
    const int block_size = virtio_get_block_size();

    if (guessed_disk_nature) {
        return (block_size  == 4096);
    }
    return (blk_cfg.geometry.heads == 15)
        && (blk_cfg.geometry.sectors ==
            virtio_eckd_sectors_for_block_size(block_size));
}

bool virtio_ipl_disk_is_valid(void)
{
    return virtio_disk_is_scsi() || virtio_disk_is_eckd();
}

int virtio_get_block_size(void)
{
    return blk_cfg.blk_size << blk_cfg.physical_block_exp;
}

uint8_t virtio_get_heads(void)
{
    return blk_cfg.geometry.heads;
}

uint8_t virtio_get_sectors(void)
{
    return blk_cfg.geometry.sectors;
}

uint64_t virtio_get_blocks(void)
{
    return blk_cfg.capacity /
           (virtio_get_block_size() / VIRTIO_SECTOR_SIZE);
}

void virtio_setup_block(struct subchannel_id schid)
{
    struct vq_info_block info;
    struct vq_config_block config = {};

    blk_cfg.blk_size = 0; /* mark "illegal" - setup started... */
    guessed_disk_nature = false;

    virtio_reset(schid);

    /*
     * Skipping CCW_CMD_READ_FEAT. We're not doing anything fancy, and
     * we'll just stop dead anyway if anything does not work like we
     * expect it.
     */

    config.index = 0;
    if (run_ccw(schid, CCW_CMD_READ_VQ_CONF, &config, sizeof(config))) {
        virtio_panic("Could not get block device VQ configuration\n");
    }
    if (run_ccw(schid, CCW_CMD_READ_CONF, &blk_cfg, sizeof(blk_cfg))) {
        virtio_panic("Could not get block device configuration\n");
    }
    vring_init(&block, config.num, ring_area,
               KVM_S390_VIRTIO_RING_ALIGN);

    info.queue = (unsigned long long) ring_area;
    info.align = KVM_S390_VIRTIO_RING_ALIGN;
    info.index = 0;
    info.num = config.num;
    block.schid = schid;

    if (!run_ccw(schid, CCW_CMD_SET_VQ, &info, sizeof(info))) {
        virtio_set_status(schid, VIRTIO_CONFIG_S_DRIVER_OK);
    }

    if (!virtio_ipl_disk_is_valid()) {
        /* make sure all getters but blocksize return 0 for invalid IPL disk */
        memset(&blk_cfg, 0, sizeof(blk_cfg));
        virtio_assume_scsi();
    }
}

bool virtio_is_blk(struct subchannel_id schid)
{
    int r;
    struct senseid senseid = {};

    /* run sense id command */
    r = run_ccw(schid, CCW_CMD_SENSE_ID, &senseid, sizeof(senseid));
    if (r) {
        return false;
    }
    if ((senseid.cu_type != 0x3832) || (senseid.cu_model != VIRTIO_ID_BLOCK)) {
        return false;
    }

    return true;
}

int enable_mss_facility(void)
{
    int ret;
    struct chsc_area_sda *sda_area = (struct chsc_area_sda *) chsc_page;

    memset(sda_area, 0, PAGE_SIZE);
    sda_area->request.length = 0x0400;
    sda_area->request.code = 0x0031;
    sda_area->operation_code = 0x2;

    ret = chsc(sda_area);
    if ((ret == 0) && (sda_area->response.code == 0x0001)) {
        return 0;
    }
    return -EIO;
}
