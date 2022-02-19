/*
 * QEMU JAZZ RC4030 chipset
 *
 * Copyright (c) 2007-2009 Herve Poussineau
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "hw/hw.h"
#include "hw/mips/mips.h"
#include "qemu/timer.h"

/********************************************************/
/* debug rc4030 */

//#define DEBUG_RC4030
//#define DEBUG_RC4030_DMA

#ifdef DEBUG_RC4030
#define DPRINTF(fmt, ...) \
do { printf("rc4030: " fmt , ## __VA_ARGS__); } while (0)
static const char* irq_names[] = { "parallel", "floppy", "sound", "video",
            "network", "scsi", "keyboard", "mouse", "serial0", "serial1" };
#else
#define DPRINTF(fmt, ...)
#endif

#define RC4030_ERROR(fmt, ...) \
do { fprintf(stderr, "rc4030 ERROR: %s: " fmt, __func__ , ## __VA_ARGS__); } while (0)

/********************************************************/
/* rc4030 emulation                                     */

typedef struct dma_pagetable_entry {
    int32_t frame;
    int32_t owner;
} QEMU_PACKED dma_pagetable_entry;

#define DMA_PAGESIZE    4096
#define DMA_REG_ENABLE  1
#define DMA_REG_COUNT   2
#define DMA_REG_ADDRESS 3

#define DMA_FLAG_ENABLE     0x0001
#define DMA_FLAG_MEM_TO_DEV 0x0002
#define DMA_FLAG_TC_INTR    0x0100
#define DMA_FLAG_MEM_INTR   0x0200
#define DMA_FLAG_ADDR_INTR  0x0400

typedef struct rc4030State
{
    uint32_t config; /* 0x0000: RC4030 config register */
    uint32_t revision; /* 0x0008: RC4030 Revision register */
    uint32_t invalid_address_register; /* 0x0010: Invalid Address register */

    /* DMA */
    uint32_t dma_regs[8][4];
    uint32_t dma_tl_base; /* 0x0018: DMA transl. table base */
    uint32_t dma_tl_limit; /* 0x0020: DMA transl. table limit */

    /* cache */
    uint32_t cache_maint; /* 0x0030: Cache Maintenance */
    uint32_t remote_failed_address; /* 0x0038: Remote Failed Address */
    uint32_t memory_failed_address; /* 0x0040: Memory Failed Address */
    uint32_t cache_ptag; /* 0x0048: I/O Cache Physical Tag */
    uint32_t cache_ltag; /* 0x0050: I/O Cache Logical Tag */
    uint32_t cache_bmask; /* 0x0058: I/O Cache Byte Mask */

    uint32_t nmi_interrupt; /* 0x0200: interrupt source */
    uint32_t offset210;
    uint32_t nvram_protect; /* 0x0220: NV ram protect register */
    uint32_t rem_speed[16];
    uint32_t imr_jazz; /* Local bus int enable mask */
    uint32_t isr_jazz; /* Local bus int source */

    /* timer */
    QEMUTimer *periodic_timer;
    uint32_t itr; /* Interval timer reload */

    qemu_irq timer_irq;
    qemu_irq jazz_bus_irq;

    MemoryRegion iomem_chipset;
    MemoryRegion iomem_jazzio;
} rc4030State;

static void set_next_tick(rc4030State *s)
{
    qemu_irq_lower(s->timer_irq);
    uint32_t tm_hz;

    tm_hz = 1000 / (s->itr + 1);

    timer_mod(s->periodic_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                   get_ticks_per_sec() / tm_hz);
}

/* called for accesses to rc4030 */
static uint32_t rc4030_readl(void *opaque, hwaddr addr)
{
    rc4030State *s = opaque;
    uint32_t val;

    addr &= 0x3fff;
    switch (addr & ~0x3) {
    /* Global config register */
    case 0x0000:
        val = s->config;
        break;
    /* Revision register */
    case 0x0008:
        val = s->revision;
        break;
    /* Invalid Address register */
    case 0x0010:
        val = s->invalid_address_register;
        break;
    /* DMA transl. table base */
    case 0x0018:
        val = s->dma_tl_base;
        break;
    /* DMA transl. table limit */
    case 0x0020:
        val = s->dma_tl_limit;
        break;
    /* Remote Failed Address */
    case 0x0038:
        val = s->remote_failed_address;
        break;
    /* Memory Failed Address */
    case 0x0040:
        val = s->memory_failed_address;
        break;
    /* I/O Cache Byte Mask */
    case 0x0058:
        val = s->cache_bmask;
        /* HACK */
        if (s->cache_bmask == (uint32_t)-1)
            s->cache_bmask = 0;
        break;
    /* Remote Speed Registers */
    case 0x0070:
    case 0x0078:
    case 0x0080:
    case 0x0088:
    case 0x0090:
    case 0x0098:
    case 0x00a0:
    case 0x00a8:
    case 0x00b0:
    case 0x00b8:
    case 0x00c0:
    case 0x00c8:
    case 0x00d0:
    case 0x00d8:
    case 0x00e0:
    case 0x00e8:
        val = s->rem_speed[(addr - 0x0070) >> 3];
        break;
    /* DMA channel base address */
    case 0x0100:
    case 0x0108:
    case 0x0110:
    case 0x0118:
    case 0x0120:
    case 0x0128:
    case 0x0130:
    case 0x0138:
    case 0x0140:
    case 0x0148:
    case 0x0150:
    case 0x0158:
    case 0x0160:
    case 0x0168:
    case 0x0170:
    case 0x0178:
    case 0x0180:
    case 0x0188:
    case 0x0190:
    case 0x0198:
    case 0x01a0:
    case 0x01a8:
    case 0x01b0:
    case 0x01b8:
    case 0x01c0:
    case 0x01c8:
    case 0x01d0:
    case 0x01d8:
    case 0x01e0:
    case 0x01e8:
    case 0x01f0:
    case 0x01f8:
        {
            int entry = (addr - 0x0100) >> 5;
            int idx = (addr & 0x1f) >> 3;
            val = s->dma_regs[entry][idx];
        }
        break;
    /* Interrupt source */
    case 0x0200:
        val = s->nmi_interrupt;
        break;
    /* Error type */
    case 0x0208:
        val = 0;
        break;
    /* Offset 0x0210 */
    case 0x0210:
        val = s->offset210;
        break;
    /* NV ram protect register */
    case 0x0220:
        val = s->nvram_protect;
        break;
    /* Interval timer count */
    case 0x0230:
        val = 0;
        qemu_irq_lower(s->timer_irq);
        break;
    /* EISA interrupt */
    case 0x0238:
        val = 7; /* FIXME: should be read from EISA controller */
        break;
    default:
        RC4030_ERROR("invalid read [" TARGET_FMT_plx "]\n", addr);
        val = 0;
        break;
    }

    if ((addr & ~3) != 0x230) {
        DPRINTF("read 0x%02x at " TARGET_FMT_plx "\n", val, addr);
    }

    return val;
}

static uint32_t rc4030_readw(void *opaque, hwaddr addr)
{
    uint32_t v = rc4030_readl(opaque, addr & ~0x3);
    if (addr & 0x2)
        return v >> 16;
    else
        return v & 0xffff;
}

static uint32_t rc4030_readb(void *opaque, hwaddr addr)
{
    uint32_t v = rc4030_readl(opaque, addr & ~0x3);
    return (v >> (8 * (addr & 0x3))) & 0xff;
}

static void rc4030_writel(void *opaque, hwaddr addr, uint32_t val)
{
    rc4030State *s = opaque;
    addr &= 0x3fff;

    DPRINTF("write 0x%02x at " TARGET_FMT_plx "\n", val, addr);

    switch (addr & ~0x3) {
    /* Global config register */
    case 0x0000:
        s->config = val;
        break;
    /* DMA transl. table base */
    case 0x0018:
        s->dma_tl_base = val;
        break;
    /* DMA transl. table limit */
    case 0x0020:
        s->dma_tl_limit = val;
        break;
    /* DMA transl. table invalidated */
    case 0x0028:
        break;
    /* Cache Maintenance */
    case 0x0030:
        s->cache_maint = val;
        break;
    /* I/O Cache Physical Tag */
    case 0x0048:
        s->cache_ptag = val;
        break;
    /* I/O Cache Logical Tag */
    case 0x0050:
        s->cache_ltag = val;
        break;
    /* I/O Cache Byte Mask */
    case 0x0058:
        s->cache_bmask |= val; /* HACK */
        break;
    /* I/O Cache Buffer Window */
    case 0x0060:
        /* HACK */
        if (s->cache_ltag == 0x80000001 && s->cache_bmask == 0xf0f0f0f) {
            hwaddr dest = s->cache_ptag & ~0x1;
            dest += (s->cache_maint & 0x3) << 3;
            cpu_physical_memory_write(dest, &val, 4);
        }
        break;
    /* Remote Speed Registers */
    case 0x0070:
    case 0x0078:
    case 0x0080:
    case 0x0088:
    case 0x0090:
    case 0x0098:
    case 0x00a0:
    case 0x00a8:
    case 0x00b0:
    case 0x00b8:
    case 0x00c0:
    case 0x00c8:
    case 0x00d0:
    case 0x00d8:
    case 0x00e0:
    case 0x00e8:
        s->rem_speed[(addr - 0x0070) >> 3] = val;
        break;
    /* DMA channel base address */
    case 0x0100:
    case 0x0108:
    case 0x0110:
    case 0x0118:
    case 0x0120:
    case 0x0128:
    case 0x0130:
    case 0x0138:
    case 0x0140:
    case 0x0148:
    case 0x0150:
    case 0x0158:
    case 0x0160:
    case 0x0168:
    case 0x0170:
    case 0x0178:
    case 0x0180:
    case 0x0188:
    case 0x0190:
    case 0x0198:
    case 0x01a0:
    case 0x01a8:
    case 0x01b0:
    case 0x01b8:
    case 0x01c0:
    case 0x01c8:
    case 0x01d0:
    case 0x01d8:
    case 0x01e0:
    case 0x01e8:
    case 0x01f0:
    case 0x01f8:
        {
            int entry = (addr - 0x0100) >> 5;
            int idx = (addr & 0x1f) >> 3;
            s->dma_regs[entry][idx] = val;
        }
        break;
    /* Offset 0x0210 */
    case 0x0210:
        s->offset210 = val;
        break;
    /* Interval timer reload */
    case 0x0228:
        s->itr = val;
        qemu_irq_lower(s->timer_irq);
        set_next_tick(s);
        break;
    /* EISA interrupt */
    case 0x0238:
        break;
    default:
        RC4030_ERROR("invalid write of 0x%02x at [" TARGET_FMT_plx "]\n", val, addr);
        break;
    }
}

static void rc4030_writew(void *opaque, hwaddr addr, uint32_t val)
{
    uint32_t old_val = rc4030_readl(opaque, addr & ~0x3);

    if (addr & 0x2)
        val = (val << 16) | (old_val & 0x0000ffff);
    else
        val = val | (old_val & 0xffff0000);
    rc4030_writel(opaque, addr & ~0x3, val);
}

static void rc4030_writeb(void *opaque, hwaddr addr, uint32_t val)
{
    uint32_t old_val = rc4030_readl(opaque, addr & ~0x3);

    switch (addr & 3) {
    case 0:
        val = val | (old_val & 0xffffff00);
        break;
    case 1:
        val = (val << 8) | (old_val & 0xffff00ff);
        break;
    case 2:
        val = (val << 16) | (old_val & 0xff00ffff);
        break;
    case 3:
        val = (val << 24) | (old_val & 0x00ffffff);
        break;
    }
    rc4030_writel(opaque, addr & ~0x3, val);
}

static const MemoryRegionOps rc4030_ops = {
    .old_mmio = {
        .read = { rc4030_readb, rc4030_readw, rc4030_readl, },
        .write = { rc4030_writeb, rc4030_writew, rc4030_writel, },
    },
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void update_jazz_irq(rc4030State *s)
{
    uint16_t pending;

    pending = s->isr_jazz & s->imr_jazz;

#ifdef DEBUG_RC4030
    if (s->isr_jazz != 0) {
        uint32_t irq = 0;
        DPRINTF("pending irqs:");
        for (irq = 0; irq < ARRAY_SIZE(irq_names); irq++) {
            if (s->isr_jazz & (1 << irq)) {
                printf(" %s", irq_names[irq]);
                if (!(s->imr_jazz & (1 << irq))) {
                    printf("(ignored)");
                }
            }
        }
        printf("\n");
    }
#endif

    if (pending != 0)
        qemu_irq_raise(s->jazz_bus_irq);
    else
        qemu_irq_lower(s->jazz_bus_irq);
}

static void rc4030_irq_jazz_request(void *opaque, int irq, int level)
{
    rc4030State *s = opaque;

    if (level) {
        s->isr_jazz |= 1 << irq;
    } else {
        s->isr_jazz &= ~(1 << irq);
    }

    update_jazz_irq(s);
}

static void rc4030_periodic_timer(void *opaque)
{
    rc4030State *s = opaque;

    set_next_tick(s);
    qemu_irq_raise(s->timer_irq);
}

static uint32_t jazzio_readw(void *opaque, hwaddr addr)
{
    rc4030State *s = opaque;
    uint32_t val;
    uint32_t irq;
    addr &= 0xfff;

    switch (addr) {
    /* Local bus int source */
    case 0x00: {
        uint32_t pending = s->isr_jazz & s->imr_jazz;
        val = 0;
        irq = 0;
        while (pending) {
            if (pending & 1) {
                DPRINTF("returning irq %s\n", irq_names[irq]);
                val = (irq + 1) << 2;
                break;
            }
            irq++;
            pending >>= 1;
        }
        break;
    }
    /* Local bus int enable mask */
    case 0x02:
        val = s->imr_jazz;
        break;
    default:
        RC4030_ERROR("(jazz io controller) invalid read [" TARGET_FMT_plx "]\n", addr);
        val = 0;
    }

    DPRINTF("(jazz io controller) read 0x%04x at " TARGET_FMT_plx "\n", val, addr);

    return val;
}

static uint32_t jazzio_readb(void *opaque, hwaddr addr)
{
    uint32_t v;
    v = jazzio_readw(opaque, addr & ~0x1);
    return (v >> (8 * (addr & 0x1))) & 0xff;
}

static uint32_t jazzio_readl(void *opaque, hwaddr addr)
{
    uint32_t v;
    v = jazzio_readw(opaque, addr);
    v |= jazzio_readw(opaque, addr + 2) << 16;
    return v;
}

static void jazzio_writew(void *opaque, hwaddr addr, uint32_t val)
{
    rc4030State *s = opaque;
    addr &= 0xfff;

    DPRINTF("(jazz io controller) write 0x%04x at " TARGET_FMT_plx "\n", val, addr);

    switch (addr) {
    /* Local bus int enable mask */
    case 0x02:
        s->imr_jazz = val;
        update_jazz_irq(s);
        break;
    default:
        RC4030_ERROR("(jazz io controller) invalid write of 0x%04x at [" TARGET_FMT_plx "]\n", val, addr);
        break;
    }
}

static void jazzio_writeb(void *opaque, hwaddr addr, uint32_t val)
{
    uint32_t old_val = jazzio_readw(opaque, addr & ~0x1);

    switch (addr & 1) {
    case 0:
        val = val | (old_val & 0xff00);
        break;
    case 1:
        val = (val << 8) | (old_val & 0x00ff);
        break;
    }
    jazzio_writew(opaque, addr & ~0x1, val);
}

static void jazzio_writel(void *opaque, hwaddr addr, uint32_t val)
{
    jazzio_writew(opaque, addr, val & 0xffff);
    jazzio_writew(opaque, addr + 2, (val >> 16) & 0xffff);
}

static const MemoryRegionOps jazzio_ops = {
    .old_mmio = {
        .read = { jazzio_readb, jazzio_readw, jazzio_readl, },
        .write = { jazzio_writeb, jazzio_writew, jazzio_writel, },
    },
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void rc4030_reset(void *opaque)
{
    rc4030State *s = opaque;
    int i;

    s->config = 0x410; /* some boards seem to accept 0x104 too */
    s->revision = 1;
    s->invalid_address_register = 0;

    memset(s->dma_regs, 0, sizeof(s->dma_regs));
    s->dma_tl_base = s->dma_tl_limit = 0;

    s->remote_failed_address = s->memory_failed_address = 0;
    s->cache_maint = 0;
    s->cache_ptag = s->cache_ltag = 0;
    s->cache_bmask = 0;

    s->offset210 = 0x18186;
    s->nvram_protect = 7;
    for (i = 0; i < 15; i++)
        s->rem_speed[i] = 7;
    s->imr_jazz = 0x10; /* XXX: required by firmware, but why? */
    s->isr_jazz = 0;

    s->itr = 0;

    qemu_irq_lower(s->timer_irq);
    qemu_irq_lower(s->jazz_bus_irq);
}

static int rc4030_load(QEMUFile *f, void *opaque, int version_id)
{
    rc4030State* s = opaque;
    int i, j;

    if (version_id != 2)
        return -EINVAL;

    s->config = qemu_get_be32(f);
    s->invalid_address_register = qemu_get_be32(f);
    for (i = 0; i < 8; i++)
        for (j = 0; j < 4; j++)
            s->dma_regs[i][j] = qemu_get_be32(f);
    s->dma_tl_base = qemu_get_be32(f);
    s->dma_tl_limit = qemu_get_be32(f);
    s->cache_maint = qemu_get_be32(f);
    s->remote_failed_address = qemu_get_be32(f);
    s->memory_failed_address = qemu_get_be32(f);
    s->cache_ptag = qemu_get_be32(f);
    s->cache_ltag = qemu_get_be32(f);
    s->cache_bmask = qemu_get_be32(f);
    s->offset210 = qemu_get_be32(f);
    s->nvram_protect = qemu_get_be32(f);
    for (i = 0; i < 15; i++)
        s->rem_speed[i] = qemu_get_be32(f);
    s->imr_jazz = qemu_get_be32(f);
    s->isr_jazz = qemu_get_be32(f);
    s->itr = qemu_get_be32(f);

    set_next_tick(s);
    update_jazz_irq(s);

    return 0;
}

static void rc4030_save(QEMUFile *f, void *opaque)
{
    rc4030State* s = opaque;
    int i, j;

    qemu_put_be32(f, s->config);
    qemu_put_be32(f, s->invalid_address_register);
    for (i = 0; i < 8; i++)
        for (j = 0; j < 4; j++)
            qemu_put_be32(f, s->dma_regs[i][j]);
    qemu_put_be32(f, s->dma_tl_base);
    qemu_put_be32(f, s->dma_tl_limit);
    qemu_put_be32(f, s->cache_maint);
    qemu_put_be32(f, s->remote_failed_address);
    qemu_put_be32(f, s->memory_failed_address);
    qemu_put_be32(f, s->cache_ptag);
    qemu_put_be32(f, s->cache_ltag);
    qemu_put_be32(f, s->cache_bmask);
    qemu_put_be32(f, s->offset210);
    qemu_put_be32(f, s->nvram_protect);
    for (i = 0; i < 15; i++)
        qemu_put_be32(f, s->rem_speed[i]);
    qemu_put_be32(f, s->imr_jazz);
    qemu_put_be32(f, s->isr_jazz);
    qemu_put_be32(f, s->itr);
}

void rc4030_dma_memory_rw(void *opaque, hwaddr addr, uint8_t *buf, int len, int is_write)
{
    rc4030State *s = opaque;
    hwaddr entry_addr;
    hwaddr phys_addr;
    dma_pagetable_entry entry;
    int index;
    int ncpy, i;

    i = 0;
    for (;;) {
        if (i == len) {
            break;
        }

        ncpy = DMA_PAGESIZE - (addr & (DMA_PAGESIZE - 1));
        if (ncpy > len - i)
            ncpy = len - i;

        /* Get DMA translation table entry */
        index = addr / DMA_PAGESIZE;
        if (index >= s->dma_tl_limit / sizeof(dma_pagetable_entry)) {
            break;
        }
        entry_addr = s->dma_tl_base + index * sizeof(dma_pagetable_entry);
        /* XXX: not sure. should we really use only lowest bits? */
        entry_addr &= 0x7fffffff;
        cpu_physical_memory_read(entry_addr, &entry, sizeof(entry));

        /* Read/write data at right place */
        phys_addr = entry.frame + (addr & (DMA_PAGESIZE - 1));
        cpu_physical_memory_rw(phys_addr, &buf[i], ncpy, is_write);

        i += ncpy;
        addr += ncpy;
    }
}

static void rc4030_do_dma(void *opaque, int n, uint8_t *buf, int len, int is_write)
{
    rc4030State *s = opaque;
    hwaddr dma_addr;
    int dev_to_mem;

    s->dma_regs[n][DMA_REG_ENABLE] &= ~(DMA_FLAG_TC_INTR | DMA_FLAG_MEM_INTR | DMA_FLAG_ADDR_INTR);

    /* Check DMA channel consistency */
    dev_to_mem = (s->dma_regs[n][DMA_REG_ENABLE] & DMA_FLAG_MEM_TO_DEV) ? 0 : 1;
    if (!(s->dma_regs[n][DMA_REG_ENABLE] & DMA_FLAG_ENABLE) ||
        (is_write != dev_to_mem)) {
        s->dma_regs[n][DMA_REG_ENABLE] |= DMA_FLAG_MEM_INTR;
        s->nmi_interrupt |= 1 << n;
        return;
    }

    /* Get start address and len */
    if (len > s->dma_regs[n][DMA_REG_COUNT])
        len = s->dma_regs[n][DMA_REG_COUNT];
    dma_addr = s->dma_regs[n][DMA_REG_ADDRESS];

    /* Read/write data at right place */
    rc4030_dma_memory_rw(opaque, dma_addr, buf, len, is_write);

    s->dma_regs[n][DMA_REG_ENABLE] |= DMA_FLAG_TC_INTR;
    s->dma_regs[n][DMA_REG_COUNT] -= len;

#ifdef DEBUG_RC4030_DMA
    {
        int i, j;
        printf("rc4030 dma: Copying %d bytes %s host %p\n",
            len, is_write ? "from" : "to", buf);
        for (i = 0; i < len; i += 16) {
            int n = 16;
            if (n > len - i) {
                n = len - i;
            }
            for (j = 0; j < n; j++)
                printf("%02x ", buf[i + j]);
            while (j++ < 16)
                printf("   ");
            printf("| ");
            for (j = 0; j < n; j++)
                printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
            printf("\n");
        }
    }
#endif
}

struct rc4030DMAState {
    void *opaque;
    int n;
};

void rc4030_dma_read(void *dma, uint8_t *buf, int len)
{
    rc4030_dma s = dma;
    rc4030_do_dma(s->opaque, s->n, buf, len, 0);
}

void rc4030_dma_write(void *dma, uint8_t *buf, int len)
{
    rc4030_dma s = dma;
    rc4030_do_dma(s->opaque, s->n, buf, len, 1);
}

static rc4030_dma *rc4030_allocate_dmas(void *opaque, int n)
{
    rc4030_dma *s;
    struct rc4030DMAState *p;
    int i;

    s = (rc4030_dma *)g_malloc0(sizeof(rc4030_dma) * n);
    p = (struct rc4030DMAState *)g_malloc0(sizeof(struct rc4030DMAState) * n);
    for (i = 0; i < n; i++) {
        p->opaque = opaque;
        p->n = i;
        s[i] = p;
        p++;
    }
    return s;
}

void *rc4030_init(qemu_irq timer, qemu_irq jazz_bus,
                  qemu_irq **irqs, rc4030_dma **dmas,
                  MemoryRegion *sysmem)
{
    rc4030State *s;

    s = g_malloc0(sizeof(rc4030State));

    *irqs = qemu_allocate_irqs(rc4030_irq_jazz_request, s, 16);
    *dmas = rc4030_allocate_dmas(s, 4);

    s->periodic_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, rc4030_periodic_timer, s);
    s->timer_irq = timer;
    s->jazz_bus_irq = jazz_bus;

    qemu_register_reset(rc4030_reset, s);
    register_savevm(NULL, "rc4030", 0, 2, rc4030_save, rc4030_load, s);
    rc4030_reset(s);

    memory_region_init_io(&s->iomem_chipset, NULL, &rc4030_ops, s,
                          "rc4030.chipset", 0x300);
    memory_region_add_subregion(sysmem, 0x80000000, &s->iomem_chipset);
    memory_region_init_io(&s->iomem_jazzio, NULL, &jazzio_ops, s,
                          "rc4030.jazzio", 0x00001000);
    memory_region_add_subregion(sysmem, 0xf0000000, &s->iomem_jazzio);

    return s;
}
