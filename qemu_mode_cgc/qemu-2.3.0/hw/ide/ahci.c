/*
 * QEMU AHCI Emulation
 *
 * Copyright (c) 2010 qiaochong@loongson.cn
 * Copyright (c) 2010 Roland Elek <elek.roland@gmail.com>
 * Copyright (c) 2010 Sebastian Herbszt <herbszt@gmx.de>
 * Copyright (c) 2010 Alexander Graf <agraf@suse.de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <hw/hw.h>
#include <hw/pci/msi.h>
#include <hw/i386/pc.h>
#include <hw/pci/pci.h>
#include <hw/sysbus.h>

#include "monitor/monitor.h"
#include "sysemu/block-backend.h"
#include "sysemu/dma.h"
#include "internal.h"
#include <hw/ide/pci.h>
#include <hw/ide/ahci.h>

#define DEBUG_AHCI 0

#define DPRINTF(port, fmt, ...) \
do { \
    if (DEBUG_AHCI) { \
        fprintf(stderr, "ahci: %s: [%d] ", __func__, port); \
        fprintf(stderr, fmt, ## __VA_ARGS__); \
    } \
} while (0)

static void check_cmd(AHCIState *s, int port);
static int handle_cmd(AHCIState *s,int port,int slot);
static void ahci_reset_port(AHCIState *s, int port);
static void ahci_write_fis_d2h(AHCIDevice *ad, uint8_t *cmd_fis);
static void ahci_init_d2h(AHCIDevice *ad);
static int ahci_dma_prepare_buf(IDEDMA *dma, int is_write);
static void ahci_commit_buf(IDEDMA *dma, uint32_t tx_bytes);
static bool ahci_map_clb_address(AHCIDevice *ad);
static bool ahci_map_fis_address(AHCIDevice *ad);
static void ahci_unmap_clb_address(AHCIDevice *ad);
static void ahci_unmap_fis_address(AHCIDevice *ad);


static uint32_t  ahci_port_read(AHCIState *s, int port, int offset)
{
    uint32_t val;
    AHCIPortRegs *pr;
    pr = &s->dev[port].port_regs;

    switch (offset) {
    case PORT_LST_ADDR:
        val = pr->lst_addr;
        break;
    case PORT_LST_ADDR_HI:
        val = pr->lst_addr_hi;
        break;
    case PORT_FIS_ADDR:
        val = pr->fis_addr;
        break;
    case PORT_FIS_ADDR_HI:
        val = pr->fis_addr_hi;
        break;
    case PORT_IRQ_STAT:
        val = pr->irq_stat;
        break;
    case PORT_IRQ_MASK:
        val = pr->irq_mask;
        break;
    case PORT_CMD:
        val = pr->cmd;
        break;
    case PORT_TFDATA:
        val = pr->tfdata;
        break;
    case PORT_SIG:
        val = pr->sig;
        break;
    case PORT_SCR_STAT:
        if (s->dev[port].port.ifs[0].blk) {
            val = SATA_SCR_SSTATUS_DET_DEV_PRESENT_PHY_UP |
                  SATA_SCR_SSTATUS_SPD_GEN1 | SATA_SCR_SSTATUS_IPM_ACTIVE;
        } else {
            val = SATA_SCR_SSTATUS_DET_NODEV;
        }
        break;
    case PORT_SCR_CTL:
        val = pr->scr_ctl;
        break;
    case PORT_SCR_ERR:
        val = pr->scr_err;
        break;
    case PORT_SCR_ACT:
        pr->scr_act &= ~s->dev[port].finished;
        s->dev[port].finished = 0;
        val = pr->scr_act;
        break;
    case PORT_CMD_ISSUE:
        val = pr->cmd_issue;
        break;
    case PORT_RESERVED:
    default:
        val = 0;
    }
    DPRINTF(port, "offset: 0x%x val: 0x%x\n", offset, val);
    return val;

}

static void ahci_irq_raise(AHCIState *s, AHCIDevice *dev)
{
    AHCIPCIState *d = container_of(s, AHCIPCIState, ahci);
    PCIDevice *pci_dev =
        (PCIDevice *)object_dynamic_cast(OBJECT(d), TYPE_PCI_DEVICE);

    DPRINTF(0, "raise irq\n");

    if (pci_dev && msi_enabled(pci_dev)) {
        msi_notify(pci_dev, 0);
    } else {
        qemu_irq_raise(s->irq);
    }
}

static void ahci_irq_lower(AHCIState *s, AHCIDevice *dev)
{
    AHCIPCIState *d = container_of(s, AHCIPCIState, ahci);
    PCIDevice *pci_dev =
        (PCIDevice *)object_dynamic_cast(OBJECT(d), TYPE_PCI_DEVICE);

    DPRINTF(0, "lower irq\n");

    if (!pci_dev || !msi_enabled(pci_dev)) {
        qemu_irq_lower(s->irq);
    }
}

static void ahci_check_irq(AHCIState *s)
{
    int i;

    DPRINTF(-1, "check irq %#x\n", s->control_regs.irqstatus);

    s->control_regs.irqstatus = 0;
    for (i = 0; i < s->ports; i++) {
        AHCIPortRegs *pr = &s->dev[i].port_regs;
        if (pr->irq_stat & pr->irq_mask) {
            s->control_regs.irqstatus |= (1 << i);
        }
    }

    if (s->control_regs.irqstatus &&
        (s->control_regs.ghc & HOST_CTL_IRQ_EN)) {
            ahci_irq_raise(s, NULL);
    } else {
        ahci_irq_lower(s, NULL);
    }
}

static void ahci_trigger_irq(AHCIState *s, AHCIDevice *d,
                             int irq_type)
{
    DPRINTF(d->port_no, "trigger irq %#x -> %x\n",
            irq_type, d->port_regs.irq_mask & irq_type);

    d->port_regs.irq_stat |= irq_type;
    ahci_check_irq(s);
}

static void map_page(AddressSpace *as, uint8_t **ptr, uint64_t addr,
                     uint32_t wanted)
{
    hwaddr len = wanted;

    if (*ptr) {
        dma_memory_unmap(as, *ptr, len, DMA_DIRECTION_FROM_DEVICE, len);
    }

    *ptr = dma_memory_map(as, addr, &len, DMA_DIRECTION_FROM_DEVICE);
    if (len < wanted) {
        dma_memory_unmap(as, *ptr, len, DMA_DIRECTION_FROM_DEVICE, len);
        *ptr = NULL;
    }
}

static void  ahci_port_write(AHCIState *s, int port, int offset, uint32_t val)
{
    AHCIPortRegs *pr = &s->dev[port].port_regs;

    DPRINTF(port, "offset: 0x%x val: 0x%x\n", offset, val);
    switch (offset) {
        case PORT_LST_ADDR:
            pr->lst_addr = val;
            break;
        case PORT_LST_ADDR_HI:
            pr->lst_addr_hi = val;
            break;
        case PORT_FIS_ADDR:
            pr->fis_addr = val;
            break;
        case PORT_FIS_ADDR_HI:
            pr->fis_addr_hi = val;
            break;
        case PORT_IRQ_STAT:
            pr->irq_stat &= ~val;
            ahci_check_irq(s);
            break;
        case PORT_IRQ_MASK:
            pr->irq_mask = val & 0xfdc000ff;
            ahci_check_irq(s);
            break;
        case PORT_CMD:
            /* Block any Read-only fields from being set;
             * including LIST_ON and FIS_ON. */
            pr->cmd = (pr->cmd & PORT_CMD_RO_MASK) | (val & ~PORT_CMD_RO_MASK);

            if (pr->cmd & PORT_CMD_START) {
                if (ahci_map_clb_address(&s->dev[port])) {
                    pr->cmd |= PORT_CMD_LIST_ON;
                } else {
                    error_report("AHCI: Failed to start DMA engine: "
                                 "bad command list buffer address");
                }
            } else if (pr->cmd & PORT_CMD_LIST_ON) {
                ahci_unmap_clb_address(&s->dev[port]);
                pr->cmd = pr->cmd & ~(PORT_CMD_LIST_ON);
            }

            if (pr->cmd & PORT_CMD_FIS_RX) {
                if (ahci_map_fis_address(&s->dev[port])) {
                    pr->cmd |= PORT_CMD_FIS_ON;
                } else {
                    error_report("AHCI: Failed to start FIS receive engine: "
                                 "bad FIS receive buffer address");
                }
            } else if (pr->cmd & PORT_CMD_FIS_ON) {
                ahci_unmap_fis_address(&s->dev[port]);
                pr->cmd = pr->cmd & ~(PORT_CMD_FIS_ON);
            }

            /* XXX usually the FIS would be pending on the bus here and
                   issuing deferred until the OS enables FIS receival.
                   Instead, we only submit it once - which works in most
                   cases, but is a hack. */
            if ((pr->cmd & PORT_CMD_FIS_ON) &&
                !s->dev[port].init_d2h_sent) {
                ahci_init_d2h(&s->dev[port]);
                s->dev[port].init_d2h_sent = true;
            }

            check_cmd(s, port);
            break;
        case PORT_TFDATA:
            /* Read Only. */
            break;
        case PORT_SIG:
            /* Read Only */
            break;
        case PORT_SCR_STAT:
            /* Read Only */
            break;
        case PORT_SCR_CTL:
            if (((pr->scr_ctl & AHCI_SCR_SCTL_DET) == 1) &&
                ((val & AHCI_SCR_SCTL_DET) == 0)) {
                ahci_reset_port(s, port);
            }
            pr->scr_ctl = val;
            break;
        case PORT_SCR_ERR:
            pr->scr_err &= ~val;
            break;
        case PORT_SCR_ACT:
            /* RW1 */
            pr->scr_act |= val;
            break;
        case PORT_CMD_ISSUE:
            pr->cmd_issue |= val;
            check_cmd(s, port);
            break;
        default:
            break;
    }
}

static uint64_t ahci_mem_read(void *opaque, hwaddr addr,
                              unsigned size)
{
    AHCIState *s = opaque;
    uint32_t val = 0;

    if (addr < AHCI_GENERIC_HOST_CONTROL_REGS_MAX_ADDR) {
        switch (addr) {
        case HOST_CAP:
            val = s->control_regs.cap;
            break;
        case HOST_CTL:
            val = s->control_regs.ghc;
            break;
        case HOST_IRQ_STAT:
            val = s->control_regs.irqstatus;
            break;
        case HOST_PORTS_IMPL:
            val = s->control_regs.impl;
            break;
        case HOST_VERSION:
            val = s->control_regs.version;
            break;
        }

        DPRINTF(-1, "(addr 0x%08X), val 0x%08X\n", (unsigned) addr, val);
    } else if ((addr >= AHCI_PORT_REGS_START_ADDR) &&
               (addr < (AHCI_PORT_REGS_START_ADDR +
                (s->ports * AHCI_PORT_ADDR_OFFSET_LEN)))) {
        val = ahci_port_read(s, (addr - AHCI_PORT_REGS_START_ADDR) >> 7,
                             addr & AHCI_PORT_ADDR_OFFSET_MASK);
    }

    return val;
}



static void ahci_mem_write(void *opaque, hwaddr addr,
                           uint64_t val, unsigned size)
{
    AHCIState *s = opaque;

    /* Only aligned reads are allowed on AHCI */
    if (addr & 3) {
        fprintf(stderr, "ahci: Mis-aligned write to addr 0x"
                TARGET_FMT_plx "\n", addr);
        return;
    }

    if (addr < AHCI_GENERIC_HOST_CONTROL_REGS_MAX_ADDR) {
        DPRINTF(-1, "(addr 0x%08X), val 0x%08"PRIX64"\n", (unsigned) addr, val);

        switch (addr) {
            case HOST_CAP: /* R/WO, RO */
                /* FIXME handle R/WO */
                break;
            case HOST_CTL: /* R/W */
                if (val & HOST_CTL_RESET) {
                    DPRINTF(-1, "HBA Reset\n");
                    ahci_reset(s);
                } else {
                    s->control_regs.ghc = (val & 0x3) | HOST_CTL_AHCI_EN;
                    ahci_check_irq(s);
                }
                break;
            case HOST_IRQ_STAT: /* R/WC, RO */
                s->control_regs.irqstatus &= ~val;
                ahci_check_irq(s);
                break;
            case HOST_PORTS_IMPL: /* R/WO, RO */
                /* FIXME handle R/WO */
                break;
            case HOST_VERSION: /* RO */
                /* FIXME report write? */
                break;
            default:
                DPRINTF(-1, "write to unknown register 0x%x\n", (unsigned)addr);
        }
    } else if ((addr >= AHCI_PORT_REGS_START_ADDR) &&
               (addr < (AHCI_PORT_REGS_START_ADDR +
                (s->ports * AHCI_PORT_ADDR_OFFSET_LEN)))) {
        ahci_port_write(s, (addr - AHCI_PORT_REGS_START_ADDR) >> 7,
                        addr & AHCI_PORT_ADDR_OFFSET_MASK, val);
    }

}

static const MemoryRegionOps ahci_mem_ops = {
    .read = ahci_mem_read,
    .write = ahci_mem_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static uint64_t ahci_idp_read(void *opaque, hwaddr addr,
                              unsigned size)
{
    AHCIState *s = opaque;

    if (addr == s->idp_offset) {
        /* index register */
        return s->idp_index;
    } else if (addr == s->idp_offset + 4) {
        /* data register - do memory read at location selected by index */
        return ahci_mem_read(opaque, s->idp_index, size);
    } else {
        return 0;
    }
}

static void ahci_idp_write(void *opaque, hwaddr addr,
                           uint64_t val, unsigned size)
{
    AHCIState *s = opaque;

    if (addr == s->idp_offset) {
        /* index register - mask off reserved bits */
        s->idp_index = (uint32_t)val & ((AHCI_MEM_BAR_SIZE - 1) & ~3);
    } else if (addr == s->idp_offset + 4) {
        /* data register - do memory write at location selected by index */
        ahci_mem_write(opaque, s->idp_index, val, size);
    }
}

static const MemoryRegionOps ahci_idp_ops = {
    .read = ahci_idp_read,
    .write = ahci_idp_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};


static void ahci_reg_init(AHCIState *s)
{
    int i;

    s->control_regs.cap = (s->ports - 1) |
                          (AHCI_NUM_COMMAND_SLOTS << 8) |
                          (AHCI_SUPPORTED_SPEED_GEN1 << AHCI_SUPPORTED_SPEED) |
                          HOST_CAP_NCQ | HOST_CAP_AHCI;

    s->control_regs.impl = (1 << s->ports) - 1;

    s->control_regs.version = AHCI_VERSION_1_0;

    for (i = 0; i < s->ports; i++) {
        s->dev[i].port_state = STATE_RUN;
    }
}

static void check_cmd(AHCIState *s, int port)
{
    AHCIPortRegs *pr = &s->dev[port].port_regs;
    int slot;

    if ((pr->cmd & PORT_CMD_START) && pr->cmd_issue) {
        for (slot = 0; (slot < 32) && pr->cmd_issue; slot++) {
            if ((pr->cmd_issue & (1U << slot)) &&
                !handle_cmd(s, port, slot)) {
                pr->cmd_issue &= ~(1U << slot);
            }
        }
    }
}

static void ahci_check_cmd_bh(void *opaque)
{
    AHCIDevice *ad = opaque;

    qemu_bh_delete(ad->check_bh);
    ad->check_bh = NULL;

    if ((ad->busy_slot != -1) &&
        !(ad->port.ifs[0].status & (BUSY_STAT|DRQ_STAT))) {
        /* no longer busy */
        ad->port_regs.cmd_issue &= ~(1 << ad->busy_slot);
        ad->busy_slot = -1;
    }

    check_cmd(ad->hba, ad->port_no);
}

static void ahci_init_d2h(AHCIDevice *ad)
{
    uint8_t init_fis[20];
    IDEState *ide_state = &ad->port.ifs[0];

    memset(init_fis, 0, sizeof(init_fis));

    init_fis[4] = 1;
    init_fis[12] = 1;

    if (ide_state->drive_kind == IDE_CD) {
        init_fis[5] = ide_state->lcyl;
        init_fis[6] = ide_state->hcyl;
    }

    ahci_write_fis_d2h(ad, init_fis);
}

static void ahci_reset_port(AHCIState *s, int port)
{
    AHCIDevice *d = &s->dev[port];
    AHCIPortRegs *pr = &d->port_regs;
    IDEState *ide_state = &d->port.ifs[0];
    int i;

    DPRINTF(port, "reset port\n");

    ide_bus_reset(&d->port);
    ide_state->ncq_queues = AHCI_MAX_CMDS;

    pr->scr_stat = 0;
    pr->scr_err = 0;
    pr->scr_act = 0;
    pr->tfdata = 0x7F;
    pr->sig = 0xFFFFFFFF;
    d->busy_slot = -1;
    d->init_d2h_sent = false;

    ide_state = &s->dev[port].port.ifs[0];
    if (!ide_state->blk) {
        return;
    }

    /* reset ncq queue */
    for (i = 0; i < AHCI_MAX_CMDS; i++) {
        NCQTransferState *ncq_tfs = &s->dev[port].ncq_tfs[i];
        if (!ncq_tfs->used) {
            continue;
        }

        if (ncq_tfs->aiocb) {
            blk_aio_cancel(ncq_tfs->aiocb);
            ncq_tfs->aiocb = NULL;
        }

        /* Maybe we just finished the request thanks to blk_aio_cancel() */
        if (!ncq_tfs->used) {
            continue;
        }

        qemu_sglist_destroy(&ncq_tfs->sglist);
        ncq_tfs->used = 0;
    }

    s->dev[port].port_state = STATE_RUN;
    if (!ide_state->blk) {
        pr->sig = 0;
        ide_state->status = SEEK_STAT | WRERR_STAT;
    } else if (ide_state->drive_kind == IDE_CD) {
        pr->sig = SATA_SIGNATURE_CDROM;
        ide_state->lcyl = 0x14;
        ide_state->hcyl = 0xeb;
        DPRINTF(port, "set lcyl = %d\n", ide_state->lcyl);
        ide_state->status = SEEK_STAT | WRERR_STAT | READY_STAT;
    } else {
        pr->sig = SATA_SIGNATURE_DISK;
        ide_state->status = SEEK_STAT | WRERR_STAT;
    }

    ide_state->error = 1;
    ahci_init_d2h(d);
}

static void debug_print_fis(uint8_t *fis, int cmd_len)
{
#if DEBUG_AHCI
    int i;

    fprintf(stderr, "fis:");
    for (i = 0; i < cmd_len; i++) {
        if ((i & 0xf) == 0) {
            fprintf(stderr, "\n%02x:",i);
        }
        fprintf(stderr, "%02x ",fis[i]);
    }
    fprintf(stderr, "\n");
#endif
}

static bool ahci_map_fis_address(AHCIDevice *ad)
{
    AHCIPortRegs *pr = &ad->port_regs;
    map_page(ad->hba->as, &ad->res_fis,
             ((uint64_t)pr->fis_addr_hi << 32) | pr->fis_addr, 256);
    return ad->res_fis != NULL;
}

static void ahci_unmap_fis_address(AHCIDevice *ad)
{
    dma_memory_unmap(ad->hba->as, ad->res_fis, 256,
                     DMA_DIRECTION_FROM_DEVICE, 256);
    ad->res_fis = NULL;
}

static bool ahci_map_clb_address(AHCIDevice *ad)
{
    AHCIPortRegs *pr = &ad->port_regs;
    ad->cur_cmd = NULL;
    map_page(ad->hba->as, &ad->lst,
             ((uint64_t)pr->lst_addr_hi << 32) | pr->lst_addr, 1024);
    return ad->lst != NULL;
}

static void ahci_unmap_clb_address(AHCIDevice *ad)
{
    dma_memory_unmap(ad->hba->as, ad->lst, 1024,
                     DMA_DIRECTION_FROM_DEVICE, 1024);
    ad->lst = NULL;
}

static void ahci_write_fis_sdb(AHCIState *s, int port, uint32_t finished)
{
    AHCIDevice *ad = &s->dev[port];
    AHCIPortRegs *pr = &ad->port_regs;
    IDEState *ide_state;
    SDBFIS *sdb_fis;

    if (!s->dev[port].res_fis ||
        !(pr->cmd & PORT_CMD_FIS_RX)) {
        return;
    }

    sdb_fis = (SDBFIS *)&ad->res_fis[RES_FIS_SDBFIS];
    ide_state = &ad->port.ifs[0];

    sdb_fis->type = SATA_FIS_TYPE_SDB;
    /* Interrupt pending & Notification bit */
    sdb_fis->flags = (ad->hba->control_regs.irqstatus ? (1 << 6) : 0);
    sdb_fis->status = ide_state->status & 0x77;
    sdb_fis->error = ide_state->error;
    /* update SAct field in SDB_FIS */
    s->dev[port].finished |= finished;
    sdb_fis->payload = cpu_to_le32(ad->finished);

    /* Update shadow registers (except BSY 0x80 and DRQ 0x08) */
    pr->tfdata = (ad->port.ifs[0].error << 8) |
        (ad->port.ifs[0].status & 0x77) |
        (pr->tfdata & 0x88);

    ahci_trigger_irq(s, ad, PORT_IRQ_SDB_FIS);
}

static void ahci_write_fis_pio(AHCIDevice *ad, uint16_t len)
{
    AHCIPortRegs *pr = &ad->port_regs;
    uint8_t *pio_fis, *cmd_fis;
    uint64_t tbl_addr;
    dma_addr_t cmd_len = 0x80;
    IDEState *s = &ad->port.ifs[0];

    if (!ad->res_fis || !(pr->cmd & PORT_CMD_FIS_RX)) {
        return;
    }

    /* map cmd_fis */
    tbl_addr = le64_to_cpu(ad->cur_cmd->tbl_addr);
    cmd_fis = dma_memory_map(ad->hba->as, tbl_addr, &cmd_len,
                             DMA_DIRECTION_TO_DEVICE);

    if (cmd_fis == NULL) {
        DPRINTF(ad->port_no, "dma_memory_map failed in ahci_write_fis_pio");
        ahci_trigger_irq(ad->hba, ad, PORT_IRQ_HBUS_ERR);
        return;
    }

    if (cmd_len != 0x80) {
        DPRINTF(ad->port_no,
                "dma_memory_map mapped too few bytes in ahci_write_fis_pio");
        dma_memory_unmap(ad->hba->as, cmd_fis, cmd_len,
                         DMA_DIRECTION_TO_DEVICE, cmd_len);
        ahci_trigger_irq(ad->hba, ad, PORT_IRQ_HBUS_ERR);
        return;
    }

    pio_fis = &ad->res_fis[RES_FIS_PSFIS];

    pio_fis[0] = SATA_FIS_TYPE_PIO_SETUP;
    pio_fis[1] = (ad->hba->control_regs.irqstatus ? (1 << 6) : 0);
    pio_fis[2] = s->status;
    pio_fis[3] = s->error;

    pio_fis[4] = s->sector;
    pio_fis[5] = s->lcyl;
    pio_fis[6] = s->hcyl;
    pio_fis[7] = s->select;
    pio_fis[8] = s->hob_sector;
    pio_fis[9] = s->hob_lcyl;
    pio_fis[10] = s->hob_hcyl;
    pio_fis[11] = 0;
    pio_fis[12] = cmd_fis[12];
    pio_fis[13] = cmd_fis[13];
    pio_fis[14] = 0;
    pio_fis[15] = s->status;
    pio_fis[16] = len & 255;
    pio_fis[17] = len >> 8;
    pio_fis[18] = 0;
    pio_fis[19] = 0;

    /* Update shadow registers: */
    pr->tfdata = (ad->port.ifs[0].error << 8) |
        ad->port.ifs[0].status;

    if (pio_fis[2] & ERR_STAT) {
        ahci_trigger_irq(ad->hba, ad, PORT_IRQ_TF_ERR);
    }

    ahci_trigger_irq(ad->hba, ad, PORT_IRQ_PIOS_FIS);

    dma_memory_unmap(ad->hba->as, cmd_fis, cmd_len,
                     DMA_DIRECTION_TO_DEVICE, cmd_len);
}

static void ahci_write_fis_d2h(AHCIDevice *ad, uint8_t *cmd_fis)
{
    AHCIPortRegs *pr = &ad->port_regs;
    uint8_t *d2h_fis;
    int i;
    dma_addr_t cmd_len = 0x80;
    int cmd_mapped = 0;
    IDEState *s = &ad->port.ifs[0];

    if (!ad->res_fis || !(pr->cmd & PORT_CMD_FIS_RX)) {
        return;
    }

    if (!cmd_fis) {
        /* map cmd_fis */
        uint64_t tbl_addr = le64_to_cpu(ad->cur_cmd->tbl_addr);
        cmd_fis = dma_memory_map(ad->hba->as, tbl_addr, &cmd_len,
                                 DMA_DIRECTION_TO_DEVICE);
        cmd_mapped = 1;
    }

    d2h_fis = &ad->res_fis[RES_FIS_RFIS];

    d2h_fis[0] = SATA_FIS_TYPE_REGISTER_D2H;
    d2h_fis[1] = (ad->hba->control_regs.irqstatus ? (1 << 6) : 0);
    d2h_fis[2] = s->status;
    d2h_fis[3] = s->error;

    d2h_fis[4] = s->sector;
    d2h_fis[5] = s->lcyl;
    d2h_fis[6] = s->hcyl;
    d2h_fis[7] = s->select;
    d2h_fis[8] = s->hob_sector;
    d2h_fis[9] = s->hob_lcyl;
    d2h_fis[10] = s->hob_hcyl;
    d2h_fis[11] = 0;
    d2h_fis[12] = cmd_fis[12];
    d2h_fis[13] = cmd_fis[13];
    for (i = 14; i < 20; i++) {
        d2h_fis[i] = 0;
    }

    /* Update shadow registers: */
    pr->tfdata = (ad->port.ifs[0].error << 8) |
        ad->port.ifs[0].status;

    if (d2h_fis[2] & ERR_STAT) {
        ahci_trigger_irq(ad->hba, ad, PORT_IRQ_TF_ERR);
    }

    ahci_trigger_irq(ad->hba, ad, PORT_IRQ_D2H_REG_FIS);

    if (cmd_mapped) {
        dma_memory_unmap(ad->hba->as, cmd_fis, cmd_len,
                         DMA_DIRECTION_TO_DEVICE, cmd_len);
    }
}

static int prdt_tbl_entry_size(const AHCI_SG *tbl)
{
    return (le32_to_cpu(tbl->flags_size) & AHCI_PRDT_SIZE_MASK) + 1;
}

static int ahci_populate_sglist(AHCIDevice *ad, QEMUSGList *sglist,
                                int32_t offset)
{
    AHCICmdHdr *cmd = ad->cur_cmd;
    uint32_t opts = le32_to_cpu(cmd->opts);
    uint64_t prdt_addr = le64_to_cpu(cmd->tbl_addr) + 0x80;
    int sglist_alloc_hint = opts >> AHCI_CMD_HDR_PRDT_LEN;
    dma_addr_t prdt_len = (sglist_alloc_hint * sizeof(AHCI_SG));
    dma_addr_t real_prdt_len = prdt_len;
    uint8_t *prdt;
    int i;
    int r = 0;
    uint64_t sum = 0;
    int off_idx = -1;
    int64_t off_pos = -1;
    int tbl_entry_size;
    IDEBus *bus = &ad->port;
    BusState *qbus = BUS(bus);

    /*
     * Note: AHCI PRDT can describe up to 256GiB. SATA/ATA only support
     * transactions of up to 32MiB as of ATA8-ACS3 rev 1b, assuming a
     * 512 byte sector size. We limit the PRDT in this implementation to
     * a reasonably large 2GiB, which can accommodate the maximum transfer
     * request for sector sizes up to 32K.
     */

    if (!sglist_alloc_hint) {
        DPRINTF(ad->port_no, "no sg list given by guest: 0x%08x\n", opts);
        return -1;
    }

    /* map PRDT */
    if (!(prdt = dma_memory_map(ad->hba->as, prdt_addr, &prdt_len,
                                DMA_DIRECTION_TO_DEVICE))){
        DPRINTF(ad->port_no, "map failed\n");
        return -1;
    }

    if (prdt_len < real_prdt_len) {
        DPRINTF(ad->port_no, "mapped less than expected\n");
        r = -1;
        goto out;
    }

    /* Get entries in the PRDT, init a qemu sglist accordingly */
    if (sglist_alloc_hint > 0) {
        AHCI_SG *tbl = (AHCI_SG *)prdt;
        sum = 0;
        for (i = 0; i < sglist_alloc_hint; i++) {
            /* flags_size is zero-based */
            tbl_entry_size = prdt_tbl_entry_size(&tbl[i]);
            if (offset <= (sum + tbl_entry_size)) {
                off_idx = i;
                off_pos = offset - sum;
                break;
            }
            sum += tbl_entry_size;
        }
        if ((off_idx == -1) || (off_pos < 0) || (off_pos > tbl_entry_size)) {
            DPRINTF(ad->port_no, "%s: Incorrect offset! "
                            "off_idx: %d, off_pos: %"PRId64"\n",
                            __func__, off_idx, off_pos);
            r = -1;
            goto out;
        }

        qemu_sglist_init(sglist, qbus->parent, (sglist_alloc_hint - off_idx),
                         ad->hba->as);
        qemu_sglist_add(sglist, le64_to_cpu(tbl[off_idx].addr) + off_pos,
                        prdt_tbl_entry_size(&tbl[off_idx]) - off_pos);

        for (i = off_idx + 1; i < sglist_alloc_hint; i++) {
            /* flags_size is zero-based */
            qemu_sglist_add(sglist, le64_to_cpu(tbl[i].addr),
                            prdt_tbl_entry_size(&tbl[i]));
            if (sglist->size > INT32_MAX) {
                error_report("AHCI Physical Region Descriptor Table describes "
                             "more than 2 GiB.\n");
                qemu_sglist_destroy(sglist);
                r = -1;
                goto out;
            }
        }
    }

out:
    dma_memory_unmap(ad->hba->as, prdt, prdt_len,
                     DMA_DIRECTION_TO_DEVICE, prdt_len);
    return r;
}

static void ncq_cb(void *opaque, int ret)
{
    NCQTransferState *ncq_tfs = (NCQTransferState *)opaque;
    IDEState *ide_state = &ncq_tfs->drive->port.ifs[0];

    if (ret == -ECANCELED) {
        return;
    }
    /* Clear bit for this tag in SActive */
    ncq_tfs->drive->port_regs.scr_act &= ~(1 << ncq_tfs->tag);

    if (ret < 0) {
        /* error */
        ide_state->error = ABRT_ERR;
        ide_state->status = READY_STAT | ERR_STAT;
        ncq_tfs->drive->port_regs.scr_err |= (1 << ncq_tfs->tag);
    } else {
        ide_state->status = READY_STAT | SEEK_STAT;
    }

    ahci_write_fis_sdb(ncq_tfs->drive->hba, ncq_tfs->drive->port_no,
                       (1 << ncq_tfs->tag));

    DPRINTF(ncq_tfs->drive->port_no, "NCQ transfer tag %d finished\n",
            ncq_tfs->tag);

    block_acct_done(blk_get_stats(ncq_tfs->drive->port.ifs[0].blk),
                    &ncq_tfs->acct);
    qemu_sglist_destroy(&ncq_tfs->sglist);
    ncq_tfs->used = 0;
}

static int is_ncq(uint8_t ata_cmd)
{
    /* Based on SATA 3.2 section 13.6.3.2 */
    switch (ata_cmd) {
    case READ_FPDMA_QUEUED:
    case WRITE_FPDMA_QUEUED:
    case NCQ_NON_DATA:
    case RECEIVE_FPDMA_QUEUED:
    case SEND_FPDMA_QUEUED:
        return 1;
    default:
        return 0;
    }
}

static void process_ncq_command(AHCIState *s, int port, uint8_t *cmd_fis,
                                int slot)
{
    NCQFrame *ncq_fis = (NCQFrame*)cmd_fis;
    uint8_t tag = ncq_fis->tag >> 3;
    NCQTransferState *ncq_tfs = &s->dev[port].ncq_tfs[tag];

    if (ncq_tfs->used) {
        /* error - already in use */
        fprintf(stderr, "%s: tag %d already used\n", __FUNCTION__, tag);
        return;
    }

    ncq_tfs->used = 1;
    ncq_tfs->drive = &s->dev[port];
    ncq_tfs->slot = slot;
    ncq_tfs->lba = ((uint64_t)ncq_fis->lba5 << 40) |
                   ((uint64_t)ncq_fis->lba4 << 32) |
                   ((uint64_t)ncq_fis->lba3 << 24) |
                   ((uint64_t)ncq_fis->lba2 << 16) |
                   ((uint64_t)ncq_fis->lba1 << 8) |
                   (uint64_t)ncq_fis->lba0;

    /* Note: We calculate the sector count, but don't currently rely on it.
     * The total size of the DMA buffer tells us the transfer size instead. */
    ncq_tfs->sector_count = ((uint16_t)ncq_fis->sector_count_high << 8) |
                                ncq_fis->sector_count_low;

    DPRINTF(port, "NCQ transfer LBA from %"PRId64" to %"PRId64", "
            "drive max %"PRId64"\n",
            ncq_tfs->lba, ncq_tfs->lba + ncq_tfs->sector_count - 2,
            s->dev[port].port.ifs[0].nb_sectors - 1);

    ahci_populate_sglist(&s->dev[port], &ncq_tfs->sglist, 0);
    ncq_tfs->tag = tag;

    switch(ncq_fis->command) {
        case READ_FPDMA_QUEUED:
            DPRINTF(port, "NCQ reading %d sectors from LBA %"PRId64", "
                    "tag %d\n",
                    ncq_tfs->sector_count-1, ncq_tfs->lba, ncq_tfs->tag);

            DPRINTF(port, "tag %d aio read %"PRId64"\n",
                    ncq_tfs->tag, ncq_tfs->lba);

            dma_acct_start(ncq_tfs->drive->port.ifs[0].blk, &ncq_tfs->acct,
                           &ncq_tfs->sglist, BLOCK_ACCT_READ);
            ncq_tfs->aiocb = dma_blk_read(ncq_tfs->drive->port.ifs[0].blk,
                                          &ncq_tfs->sglist, ncq_tfs->lba,
                                          ncq_cb, ncq_tfs);
            break;
        case WRITE_FPDMA_QUEUED:
            DPRINTF(port, "NCQ writing %d sectors to LBA %"PRId64", tag %d\n",
                    ncq_tfs->sector_count-1, ncq_tfs->lba, ncq_tfs->tag);

            DPRINTF(port, "tag %d aio write %"PRId64"\n",
                    ncq_tfs->tag, ncq_tfs->lba);

            dma_acct_start(ncq_tfs->drive->port.ifs[0].blk, &ncq_tfs->acct,
                           &ncq_tfs->sglist, BLOCK_ACCT_WRITE);
            ncq_tfs->aiocb = dma_blk_write(ncq_tfs->drive->port.ifs[0].blk,
                                           &ncq_tfs->sglist, ncq_tfs->lba,
                                           ncq_cb, ncq_tfs);
            break;
        default:
            if (is_ncq(cmd_fis[2])) {
                DPRINTF(port,
                        "error: unsupported NCQ command (0x%02x) received\n",
                        cmd_fis[2]);
            } else {
                DPRINTF(port,
                        "error: tried to process non-NCQ command as NCQ\n");
            }
            qemu_sglist_destroy(&ncq_tfs->sglist);
    }
}

static void handle_reg_h2d_fis(AHCIState *s, int port,
                               int slot, uint8_t *cmd_fis)
{
    IDEState *ide_state = &s->dev[port].port.ifs[0];
    AHCICmdHdr *cmd = s->dev[port].cur_cmd;
    uint32_t opts = le32_to_cpu(cmd->opts);

    if (cmd_fis[1] & 0x0F) {
        DPRINTF(port, "Port Multiplier not supported."
                " cmd_fis[0]=%02x cmd_fis[1]=%02x cmd_fis[2]=%02x\n",
                cmd_fis[0], cmd_fis[1], cmd_fis[2]);
        return;
    }

    if (cmd_fis[1] & 0x70) {
        DPRINTF(port, "Reserved flags set in H2D Register FIS."
                " cmd_fis[0]=%02x cmd_fis[1]=%02x cmd_fis[2]=%02x\n",
                cmd_fis[0], cmd_fis[1], cmd_fis[2]);
        return;
    }

    if (!(cmd_fis[1] & SATA_FIS_REG_H2D_UPDATE_COMMAND_REGISTER)) {
        switch (s->dev[port].port_state) {
        case STATE_RUN:
            if (cmd_fis[15] & ATA_SRST) {
                s->dev[port].port_state = STATE_RESET;
            }
            break;
        case STATE_RESET:
            if (!(cmd_fis[15] & ATA_SRST)) {
                ahci_reset_port(s, port);
            }
            break;
        }
        return;
    }

    /* Check for NCQ command */
    if (is_ncq(cmd_fis[2])) {
        process_ncq_command(s, port, cmd_fis, slot);
        return;
    }

    /* Decompose the FIS:
     * AHCI does not interpret FIS packets, it only forwards them.
     * SATA 1.0 describes how to decode LBA28 and CHS FIS packets.
     * Later specifications, e.g, SATA 3.2, describe LBA48 FIS packets.
     *
     * ATA4 describes sector number for LBA28/CHS commands.
     * ATA6 describes sector number for LBA48 commands.
     * ATA8 deprecates CHS fully, describing only LBA28/48.
     *
     * We dutifully convert the FIS into IDE registers, and allow the
     * core layer to interpret them as needed. */
    ide_state->feature = cmd_fis[3];
    ide_state->sector = cmd_fis[4];      /* LBA 7:0 */
    ide_state->lcyl = cmd_fis[5];        /* LBA 15:8  */
    ide_state->hcyl = cmd_fis[6];        /* LBA 23:16 */
    ide_state->select = cmd_fis[7];      /* LBA 27:24 (LBA28) */
    ide_state->hob_sector = cmd_fis[8];  /* LBA 31:24 */
    ide_state->hob_lcyl = cmd_fis[9];    /* LBA 39:32 */
    ide_state->hob_hcyl = cmd_fis[10];   /* LBA 47:40 */
    ide_state->hob_feature = cmd_fis[11];
    ide_state->nsector = (int64_t)((cmd_fis[13] << 8) | cmd_fis[12]);
    /* 14, 16, 17, 18, 19: Reserved (SATA 1.0) */
    /* 15: Only valid when UPDATE_COMMAND not set. */

    /* Copy the ACMD field (ATAPI packet, if any) from the AHCI command
     * table to ide_state->io_buffer */
    if (opts & AHCI_CMD_ATAPI) {
        memcpy(ide_state->io_buffer, &cmd_fis[AHCI_COMMAND_TABLE_ACMD], 0x10);
        debug_print_fis(ide_state->io_buffer, 0x10);
        s->dev[port].done_atapi_packet = false;
        /* XXX send PIO setup FIS */
    }

    ide_state->error = 0;

    /* Reset transferred byte counter */
    cmd->status = 0;

    /* We're ready to process the command in FIS byte 2. */
    ide_exec_cmd(&s->dev[port].port, cmd_fis[2]);
}

static int handle_cmd(AHCIState *s, int port, int slot)
{
    IDEState *ide_state;
    uint64_t tbl_addr;
    AHCICmdHdr *cmd;
    uint8_t *cmd_fis;
    dma_addr_t cmd_len;

    if (s->dev[port].port.ifs[0].status & (BUSY_STAT|DRQ_STAT)) {
        /* Engine currently busy, try again later */
        DPRINTF(port, "engine busy\n");
        return -1;
    }

    if (!s->dev[port].lst) {
        DPRINTF(port, "error: lst not given but cmd handled");
        return -1;
    }
    cmd = &((AHCICmdHdr *)s->dev[port].lst)[slot];
    /* remember current slot handle for later */
    s->dev[port].cur_cmd = cmd;

    /* The device we are working for */
    ide_state = &s->dev[port].port.ifs[0];
    if (!ide_state->blk) {
        DPRINTF(port, "error: guest accessed unused port");
        return -1;
    }

    tbl_addr = le64_to_cpu(cmd->tbl_addr);
    cmd_len = 0x80;
    cmd_fis = dma_memory_map(s->as, tbl_addr, &cmd_len,
                             DMA_DIRECTION_FROM_DEVICE);
    if (!cmd_fis) {
        DPRINTF(port, "error: guest passed us an invalid cmd fis\n");
        return -1;
    } else if (cmd_len != 0x80) {
        ahci_trigger_irq(s, &s->dev[port], PORT_IRQ_HBUS_ERR);
        DPRINTF(port, "error: dma_memory_map failed: "
                "(len(%02"PRIx64") != 0x80)\n",
                cmd_len);
        goto out;
    }
    debug_print_fis(cmd_fis, 0x80);

    switch (cmd_fis[0]) {
        case SATA_FIS_TYPE_REGISTER_H2D:
            handle_reg_h2d_fis(s, port, slot, cmd_fis);
            break;
        default:
            DPRINTF(port, "unknown command cmd_fis[0]=%02x cmd_fis[1]=%02x "
                          "cmd_fis[2]=%02x\n", cmd_fis[0], cmd_fis[1],
                          cmd_fis[2]);
            break;
    }

out:
    dma_memory_unmap(s->as, cmd_fis, cmd_len, DMA_DIRECTION_FROM_DEVICE,
                     cmd_len);

    if (s->dev[port].port.ifs[0].status & (BUSY_STAT|DRQ_STAT)) {
        /* async command, complete later */
        s->dev[port].busy_slot = slot;
        return -1;
    }

    /* done handling the command */
    return 0;
}

/* DMA dev <-> ram */
static void ahci_start_transfer(IDEDMA *dma)
{
    AHCIDevice *ad = DO_UPCAST(AHCIDevice, dma, dma);
    IDEState *s = &ad->port.ifs[0];
    uint32_t size = (uint32_t)(s->data_end - s->data_ptr);
    /* write == ram -> device */
    uint32_t opts = le32_to_cpu(ad->cur_cmd->opts);
    int is_write = opts & AHCI_CMD_WRITE;
    int is_atapi = opts & AHCI_CMD_ATAPI;
    int has_sglist = 0;

    if (is_atapi && !ad->done_atapi_packet) {
        /* already prepopulated iobuffer */
        ad->done_atapi_packet = true;
        size = 0;
        goto out;
    }

    if (ahci_dma_prepare_buf(dma, is_write)) {
        has_sglist = 1;
    }

    DPRINTF(ad->port_no, "%sing %d bytes on %s w/%s sglist\n",
            is_write ? "writ" : "read", size, is_atapi ? "atapi" : "ata",
            has_sglist ? "" : "o");

    if (has_sglist && size) {
        if (is_write) {
            dma_buf_write(s->data_ptr, size, &s->sg);
        } else {
            dma_buf_read(s->data_ptr, size, &s->sg);
        }
    }

out:
    /* declare that we processed everything */
    s->data_ptr = s->data_end;

    /* Update number of transferred bytes, destroy sglist */
    ahci_commit_buf(dma, size);

    s->end_transfer_func(s);

    if (!(s->status & DRQ_STAT)) {
        /* done with PIO send/receive */
        ahci_write_fis_pio(ad, le32_to_cpu(ad->cur_cmd->status));
    }
}

static void ahci_start_dma(IDEDMA *dma, IDEState *s,
                           BlockCompletionFunc *dma_cb)
{
    AHCIDevice *ad = DO_UPCAST(AHCIDevice, dma, dma);
    DPRINTF(ad->port_no, "\n");
    s->io_buffer_offset = 0;
    dma_cb(s, 0);
}

static void ahci_restart_dma(IDEDMA *dma)
{
    /* Nothing to do, ahci_start_dma already resets s->io_buffer_offset.  */
}

/**
 * Called in DMA R/W chains to read the PRDT, utilizing ahci_populate_sglist.
 * Not currently invoked by PIO R/W chains,
 * which invoke ahci_populate_sglist via ahci_start_transfer.
 */
static int32_t ahci_dma_prepare_buf(IDEDMA *dma, int is_write)
{
    AHCIDevice *ad = DO_UPCAST(AHCIDevice, dma, dma);
    IDEState *s = &ad->port.ifs[0];

    if (ahci_populate_sglist(ad, &s->sg, s->io_buffer_offset) == -1) {
        DPRINTF(ad->port_no, "ahci_dma_prepare_buf failed.\n");
        return -1;
    }
    s->io_buffer_size = s->sg.size;

    DPRINTF(ad->port_no, "len=%#x\n", s->io_buffer_size);
    return s->io_buffer_size;
}

/**
 * Destroys the scatter-gather list,
 * and updates the command header with a bytes-read value.
 * called explicitly via ahci_dma_rw_buf (ATAPI DMA),
 * and ahci_start_transfer (PIO R/W),
 * and called via callback from ide_dma_cb for DMA R/W paths.
 */
static void ahci_commit_buf(IDEDMA *dma, uint32_t tx_bytes)
{
    AHCIDevice *ad = DO_UPCAST(AHCIDevice, dma, dma);
    IDEState *s = &ad->port.ifs[0];

    tx_bytes += le32_to_cpu(ad->cur_cmd->status);
    ad->cur_cmd->status = cpu_to_le32(tx_bytes);

    qemu_sglist_destroy(&s->sg);
}

static int ahci_dma_rw_buf(IDEDMA *dma, int is_write)
{
    AHCIDevice *ad = DO_UPCAST(AHCIDevice, dma, dma);
    IDEState *s = &ad->port.ifs[0];
    uint8_t *p = s->io_buffer + s->io_buffer_index;
    int l = s->io_buffer_size - s->io_buffer_index;

    if (ahci_populate_sglist(ad, &s->sg, s->io_buffer_offset)) {
        return 0;
    }

    if (is_write) {
        dma_buf_read(p, l, &s->sg);
    } else {
        dma_buf_write(p, l, &s->sg);
    }

    /* free sglist, update byte count */
    ahci_commit_buf(dma, l);

    s->io_buffer_index += l;
    s->io_buffer_offset += l;

    DPRINTF(ad->port_no, "len=%#x\n", l);

    return 1;
}

static void ahci_cmd_done(IDEDMA *dma)
{
    AHCIDevice *ad = DO_UPCAST(AHCIDevice, dma, dma);

    DPRINTF(ad->port_no, "cmd done\n");

    /* update d2h status */
    ahci_write_fis_d2h(ad, NULL);

    if (!ad->check_bh) {
        /* maybe we still have something to process, check later */
        ad->check_bh = qemu_bh_new(ahci_check_cmd_bh, ad);
        qemu_bh_schedule(ad->check_bh);
    }
}

static void ahci_irq_set(void *opaque, int n, int level)
{
}

static const IDEDMAOps ahci_dma_ops = {
    .start_dma = ahci_start_dma,
    .restart_dma = ahci_restart_dma,
    .start_transfer = ahci_start_transfer,
    .prepare_buf = ahci_dma_prepare_buf,
    .commit_buf = ahci_commit_buf,
    .rw_buf = ahci_dma_rw_buf,
    .cmd_done = ahci_cmd_done,
};

void ahci_init(AHCIState *s, DeviceState *qdev, AddressSpace *as, int ports)
{
    qemu_irq *irqs;
    int i;

    s->as = as;
    s->ports = ports;
    s->dev = g_new0(AHCIDevice, ports);
    ahci_reg_init(s);
    /* XXX BAR size should be 1k, but that breaks, so bump it to 4k for now */
    memory_region_init_io(&s->mem, OBJECT(qdev), &ahci_mem_ops, s,
                          "ahci", AHCI_MEM_BAR_SIZE);
    memory_region_init_io(&s->idp, OBJECT(qdev), &ahci_idp_ops, s,
                          "ahci-idp", 32);

    irqs = qemu_allocate_irqs(ahci_irq_set, s, s->ports);

    for (i = 0; i < s->ports; i++) {
        AHCIDevice *ad = &s->dev[i];

        ide_bus_new(&ad->port, sizeof(ad->port), qdev, i, 1);
        ide_init2(&ad->port, irqs[i]);

        ad->hba = s;
        ad->port_no = i;
        ad->port.dma = &ad->dma;
        ad->port.dma->ops = &ahci_dma_ops;
        ide_register_restart_cb(&ad->port);
    }
}

void ahci_uninit(AHCIState *s)
{
    g_free(s->dev);
}

void ahci_reset(AHCIState *s)
{
    AHCIPortRegs *pr;
    int i;

    s->control_regs.irqstatus = 0;
    /* AHCI Enable (AE)
     * The implementation of this bit is dependent upon the value of the
     * CAP.SAM bit. If CAP.SAM is '0', then GHC.AE shall be read-write and
     * shall have a reset value of '0'. If CAP.SAM is '1', then AE shall be
     * read-only and shall have a reset value of '1'.
     *
     * We set HOST_CAP_AHCI so we must enable AHCI at reset.
     */
    s->control_regs.ghc = HOST_CTL_AHCI_EN;

    for (i = 0; i < s->ports; i++) {
        pr = &s->dev[i].port_regs;
        pr->irq_stat = 0;
        pr->irq_mask = 0;
        pr->scr_ctl = 0;
        pr->cmd = PORT_CMD_SPIN_UP | PORT_CMD_POWER_ON;
        ahci_reset_port(s, i);
    }
}

static const VMStateDescription vmstate_ahci_device = {
    .name = "ahci port",
    .version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_IDE_BUS(port, AHCIDevice),
        VMSTATE_IDE_DRIVE(port.ifs[0], AHCIDevice),
        VMSTATE_UINT32(port_state, AHCIDevice),
        VMSTATE_UINT32(finished, AHCIDevice),
        VMSTATE_UINT32(port_regs.lst_addr, AHCIDevice),
        VMSTATE_UINT32(port_regs.lst_addr_hi, AHCIDevice),
        VMSTATE_UINT32(port_regs.fis_addr, AHCIDevice),
        VMSTATE_UINT32(port_regs.fis_addr_hi, AHCIDevice),
        VMSTATE_UINT32(port_regs.irq_stat, AHCIDevice),
        VMSTATE_UINT32(port_regs.irq_mask, AHCIDevice),
        VMSTATE_UINT32(port_regs.cmd, AHCIDevice),
        VMSTATE_UINT32(port_regs.tfdata, AHCIDevice),
        VMSTATE_UINT32(port_regs.sig, AHCIDevice),
        VMSTATE_UINT32(port_regs.scr_stat, AHCIDevice),
        VMSTATE_UINT32(port_regs.scr_ctl, AHCIDevice),
        VMSTATE_UINT32(port_regs.scr_err, AHCIDevice),
        VMSTATE_UINT32(port_regs.scr_act, AHCIDevice),
        VMSTATE_UINT32(port_regs.cmd_issue, AHCIDevice),
        VMSTATE_BOOL(done_atapi_packet, AHCIDevice),
        VMSTATE_INT32(busy_slot, AHCIDevice),
        VMSTATE_BOOL(init_d2h_sent, AHCIDevice),
        VMSTATE_END_OF_LIST()
    },
};

static int ahci_state_post_load(void *opaque, int version_id)
{
    int i;
    struct AHCIDevice *ad;
    AHCIState *s = opaque;

    for (i = 0; i < s->ports; i++) {
        ad = &s->dev[i];

        ahci_map_clb_address(ad);
        ahci_map_fis_address(ad);
        /*
         * If an error is present, ad->busy_slot will be valid and not -1.
         * In this case, an operation is waiting to resume and will re-check
         * for additional AHCI commands to execute upon completion.
         *
         * In the case where no error was present, busy_slot will be -1,
         * and we should check to see if there are additional commands waiting.
         */
        if (ad->busy_slot == -1) {
            check_cmd(s, i);
        } else {
            /* We are in the middle of a command, and may need to access
             * the command header in guest memory again. */
            if (ad->busy_slot < 0 || ad->busy_slot >= AHCI_MAX_CMDS) {
                return -1;
            }
            ad->cur_cmd = &((AHCICmdHdr *)ad->lst)[ad->busy_slot];
        }
    }

    return 0;
}

const VMStateDescription vmstate_ahci = {
    .name = "ahci",
    .version_id = 1,
    .post_load = ahci_state_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_STRUCT_VARRAY_POINTER_INT32(dev, AHCIState, ports,
                                     vmstate_ahci_device, AHCIDevice),
        VMSTATE_UINT32(control_regs.cap, AHCIState),
        VMSTATE_UINT32(control_regs.ghc, AHCIState),
        VMSTATE_UINT32(control_regs.irqstatus, AHCIState),
        VMSTATE_UINT32(control_regs.impl, AHCIState),
        VMSTATE_UINT32(control_regs.version, AHCIState),
        VMSTATE_UINT32(idp_index, AHCIState),
        VMSTATE_INT32_EQUAL(ports, AHCIState),
        VMSTATE_END_OF_LIST()
    },
};

#define TYPE_SYSBUS_AHCI "sysbus-ahci"
#define SYSBUS_AHCI(obj) OBJECT_CHECK(SysbusAHCIState, (obj), TYPE_SYSBUS_AHCI)

typedef struct SysbusAHCIState {
    /*< private >*/
    SysBusDevice parent_obj;
    /*< public >*/

    AHCIState ahci;
    uint32_t num_ports;
} SysbusAHCIState;

static const VMStateDescription vmstate_sysbus_ahci = {
    .name = "sysbus-ahci",
    .unmigratable = 1, /* Still buggy under I/O load */
    .fields = (VMStateField[]) {
        VMSTATE_AHCI(ahci, SysbusAHCIState),
        VMSTATE_END_OF_LIST()
    },
};

static void sysbus_ahci_reset(DeviceState *dev)
{
    SysbusAHCIState *s = SYSBUS_AHCI(dev);

    ahci_reset(&s->ahci);
}

static void sysbus_ahci_realize(DeviceState *dev, Error **errp)
{
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    SysbusAHCIState *s = SYSBUS_AHCI(dev);

    ahci_init(&s->ahci, dev, &address_space_memory, s->num_ports);

    sysbus_init_mmio(sbd, &s->ahci.mem);
    sysbus_init_irq(sbd, &s->ahci.irq);
}

static Property sysbus_ahci_properties[] = {
    DEFINE_PROP_UINT32("num-ports", SysbusAHCIState, num_ports, 1),
    DEFINE_PROP_END_OF_LIST(),
};

static void sysbus_ahci_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = sysbus_ahci_realize;
    dc->vmsd = &vmstate_sysbus_ahci;
    dc->props = sysbus_ahci_properties;
    dc->reset = sysbus_ahci_reset;
    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
}

static const TypeInfo sysbus_ahci_info = {
    .name          = TYPE_SYSBUS_AHCI,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(SysbusAHCIState),
    .class_init    = sysbus_ahci_class_init,
};

static void sysbus_ahci_register_types(void)
{
    type_register_static(&sysbus_ahci_info);
}

type_init(sysbus_ahci_register_types)

void ahci_ide_create_devs(PCIDevice *dev, DriveInfo **hd)
{
    AHCIPCIState *d = ICH_AHCI(dev);
    AHCIState *ahci = &d->ahci;
    int i;

    for (i = 0; i < ahci->ports; i++) {
        if (hd[i] == NULL) {
            continue;
        }
        ide_create_drive(&ahci->dev[i].port, 0, hd[i]);
    }

}
