/*
 * QEMU S390 virtio target
 *
 * Copyright (c) 2009 Alexander Graf <agraf@suse.de>
 * Copyright IBM Corp 2012
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
 * Contributions after 2012-10-29 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 *
 * You should have received a copy of the GNU (Lesser) General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "hw/hw.h"
#include "sysemu/block-backend.h"
#include "sysemu/blockdev.h"
#include "sysemu/sysemu.h"
#include "net/net.h"
#include "hw/boards.h"
#include "monitor/monitor.h"
#include "hw/loader.h"
#include "hw/virtio/virtio.h"
#include "hw/sysbus.h"
#include "sysemu/kvm.h"
#include "exec/address-spaces.h"

#include "hw/s390x/s390-virtio-bus.h"
#include "hw/s390x/sclp.h"
#include "hw/s390x/s390_flic.h"
#include "hw/s390x/s390-virtio.h"
#include "cpu.h"

//#define DEBUG_S390

#ifdef DEBUG_S390
#define DPRINTF(fmt, ...) \
    do { fprintf(stderr, fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

#define MAX_BLK_DEVS                    10
#define ZIPL_FILENAME                   "s390-zipl.rom"
#define TYPE_S390_MACHINE               "s390-machine"

#define S390_TOD_CLOCK_VALUE_MISSING    0x00
#define S390_TOD_CLOCK_VALUE_PRESENT    0x01

static VirtIOS390Bus *s390_bus;
static S390CPU **ipi_states;

S390CPU *s390_cpu_addr2state(uint16_t cpu_addr)
{
    if (cpu_addr >= smp_cpus) {
        return NULL;
    }

    return ipi_states[cpu_addr];
}

static int s390_virtio_hcall_notify(const uint64_t *args)
{
    uint64_t mem = args[0];
    int r = 0, i;

    if (mem > ram_size) {
        VirtIOS390Device *dev = s390_virtio_bus_find_vring(s390_bus, mem, &i);
        if (dev) {
            virtio_queue_notify(dev->vdev, i);
        } else {
            r = -EINVAL;
        }
    } else {
        /* Early printk */
    }
    return r;
}

static int s390_virtio_hcall_reset(const uint64_t *args)
{
    uint64_t mem = args[0];
    VirtIOS390Device *dev;

    dev = s390_virtio_bus_find_mem(s390_bus, mem);
    if (dev == NULL) {
        return -EINVAL;
    }
    virtio_reset(dev->vdev);
    stb_phys(&address_space_memory, dev->dev_offs + VIRTIO_DEV_OFFS_STATUS, 0);
    s390_virtio_device_sync(dev);
    s390_virtio_reset_idx(dev);

    return 0;
}

static int s390_virtio_hcall_set_status(const uint64_t *args)
{
    uint64_t mem = args[0];
    int r = 0;
    VirtIOS390Device *dev;

    dev = s390_virtio_bus_find_mem(s390_bus, mem);
    if (dev) {
        s390_virtio_device_update_status(dev);
    } else {
        r = -EINVAL;
    }
    return r;
}

static void s390_virtio_register_hcalls(void)
{
    s390_register_virtio_hypercall(KVM_S390_VIRTIO_NOTIFY,
                                   s390_virtio_hcall_notify);
    s390_register_virtio_hypercall(KVM_S390_VIRTIO_RESET,
                                   s390_virtio_hcall_reset);
    s390_register_virtio_hypercall(KVM_S390_VIRTIO_SET_STATUS,
                                   s390_virtio_hcall_set_status);
}

void s390_init_ipl_dev(const char *kernel_filename,
                       const char *kernel_cmdline,
                       const char *initrd_filename,
                       const char *firmware,
                       bool enforce_bios)
{
    DeviceState *dev;

    dev  = qdev_create(NULL, "s390-ipl");
    if (kernel_filename) {
        qdev_prop_set_string(dev, "kernel", kernel_filename);
    }
    if (initrd_filename) {
        qdev_prop_set_string(dev, "initrd", initrd_filename);
    }
    qdev_prop_set_string(dev, "cmdline", kernel_cmdline);
    qdev_prop_set_string(dev, "firmware", firmware);
    qdev_prop_set_bit(dev, "enforce_bios", enforce_bios);
    object_property_add_child(qdev_get_machine(), "s390-ipl",
                              OBJECT(dev), NULL);
    qdev_init_nofail(dev);
}

void s390_init_cpus(const char *cpu_model, uint8_t *storage_keys)
{
    int i;

    if (cpu_model == NULL) {
        cpu_model = "host";
    }

    ipi_states = g_malloc(sizeof(S390CPU *) * smp_cpus);

    for (i = 0; i < smp_cpus; i++) {
        S390CPU *cpu;
        CPUState *cs;

        cpu = cpu_s390x_init(cpu_model);
        cs = CPU(cpu);

        ipi_states[i] = cpu;
        cs->halted = 1;
        cs->exception_index = EXCP_HLT;
        cpu->env.storage_keys = storage_keys;
    }
}


void s390_create_virtio_net(BusState *bus, const char *name)
{
    int i;

    for (i = 0; i < nb_nics; i++) {
        NICInfo *nd = &nd_table[i];
        DeviceState *dev;

        if (!nd->model) {
            nd->model = g_strdup("virtio");
        }

        if (strcmp(nd->model, "virtio")) {
            fprintf(stderr, "S390 only supports VirtIO nics\n");
            exit(1);
        }

        dev = qdev_create(bus, name);
        qdev_set_nic_properties(dev, nd);
        qdev_init_nofail(dev);
    }
}

void gtod_save(QEMUFile *f, void *opaque)
{
    uint64_t tod_low;
    uint8_t tod_high;
    int r;

    r = s390_get_clock(&tod_high, &tod_low);
    if (r) {
        fprintf(stderr, "WARNING: Unable to get guest clock for migration. "
                        "Error code %d. Guest clock will not be migrated "
                        "which could cause the guest to hang.\n", r);
        qemu_put_byte(f, S390_TOD_CLOCK_VALUE_MISSING);
        return;
    }

    qemu_put_byte(f, S390_TOD_CLOCK_VALUE_PRESENT);
    qemu_put_byte(f, tod_high);
    qemu_put_be64(f, tod_low);
}

int gtod_load(QEMUFile *f, void *opaque, int version_id)
{
    uint64_t tod_low;
    uint8_t tod_high;
    int r;

    if (qemu_get_byte(f) == S390_TOD_CLOCK_VALUE_MISSING) {
        fprintf(stderr, "WARNING: Guest clock was not migrated. This could "
                        "cause the guest to hang.\n");
        return 0;
    }

    tod_high = qemu_get_byte(f);
    tod_low = qemu_get_be64(f);

    r = s390_set_clock(&tod_high, &tod_low);
    if (r) {
        fprintf(stderr, "WARNING: Unable to set guest clock value. "
                        "s390_get_clock returned error %d. This could cause "
                        "the guest to hang.\n", r);
    }

    return 0;
}

/* PC hardware initialisation */
static void s390_init(MachineState *machine)
{
    ram_addr_t my_ram_size = machine->ram_size;
    MemoryRegion *sysmem = get_system_memory();
    MemoryRegion *ram = g_new(MemoryRegion, 1);
    int increment_size = 20;
    uint8_t *storage_keys;
    void *virtio_region;
    hwaddr virtio_region_len;
    hwaddr virtio_region_start;

    /*
     * The storage increment size is a multiple of 1M and is a power of 2.
     * The number of storage increments must be MAX_STORAGE_INCREMENTS or
     * fewer.
     */
    while ((my_ram_size >> increment_size) > MAX_STORAGE_INCREMENTS) {
        increment_size++;
    }
    my_ram_size = my_ram_size >> increment_size << increment_size;

    /* let's propagate the changed ram size into the global variable. */
    ram_size = my_ram_size;

    /* get a BUS */
    s390_bus = s390_virtio_bus_init(&my_ram_size);
    s390_sclp_init();
    s390_init_ipl_dev(machine->kernel_filename, machine->kernel_cmdline,
                      machine->initrd_filename, ZIPL_FILENAME, false);
    s390_flic_init();

    /* register hypercalls */
    s390_virtio_register_hcalls();

    /* allocate RAM */
    memory_region_init_ram(ram, NULL, "s390.ram", my_ram_size, &error_abort);
    vmstate_register_ram_global(ram);
    memory_region_add_subregion(sysmem, 0, ram);

    /* clear virtio region */
    virtio_region_len = my_ram_size - ram_size;
    virtio_region_start = ram_size;
    virtio_region = cpu_physical_memory_map(virtio_region_start,
                                            &virtio_region_len, true);
    memset(virtio_region, 0, virtio_region_len);
    cpu_physical_memory_unmap(virtio_region, virtio_region_len, 1,
                              virtio_region_len);

    /* allocate storage keys */
    storage_keys = g_malloc0(my_ram_size / TARGET_PAGE_SIZE);

    /* init CPUs */
    s390_init_cpus(machine->cpu_model, storage_keys);

    /* Create VirtIO network adapters */
    s390_create_virtio_net((BusState *)s390_bus, "virtio-net-s390");

    /* Register savevm handler for guest TOD clock */
    register_savevm(NULL, "todclock", 0, 1, gtod_save, gtod_load, NULL);
}

void s390_nmi(NMIState *n, int cpu_index, Error **errp)
{
    CPUState *cs = qemu_get_cpu(cpu_index);

    if (s390_cpu_restart(S390_CPU(cs))) {
        error_set(errp, QERR_UNSUPPORTED);
    }
}

static void s390_machine_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);
    NMIClass *nc = NMI_CLASS(oc);

    mc->name = "s390-virtio";
    mc->alias = "s390";
    mc->desc = "VirtIO based S390 machine";
    mc->init = s390_init;
    mc->block_default_type = IF_VIRTIO;
    mc->max_cpus = 255;
    mc->no_serial = 1;
    mc->no_parallel = 1;
    mc->use_virtcon = 1;
    mc->no_floppy = 1;
    mc->no_cdrom = 1;
    mc->no_sdcard = 1;
    mc->is_default = 1;
    nc->nmi_monitor_handler = s390_nmi;
}

static const TypeInfo s390_machine_info = {
    .name          = TYPE_S390_MACHINE,
    .parent        = TYPE_MACHINE,
    .class_init    = s390_machine_class_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_NMI },
        { }
    },
};

static void s390_machine_register_types(void)
{
    type_register_static(&s390_machine_info);
}

type_init(s390_machine_register_types)
