/*
 * QEMU ACPI hotplug utilities
 *
 * Copyright (C) 2013 Red Hat Inc
 *
 * Authors:
 *   Igor Mammedov <imammedo@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef ACPI_HOTPLUG_H
#define ACPI_HOTPLUG_H

#include "hw/acpi/acpi.h"
#include "hw/acpi/pc-hotplug.h"

typedef struct AcpiCpuHotplug {
    MemoryRegion io;
    uint8_t sts[ACPI_GPE_PROC_LEN];
} AcpiCpuHotplug;

void acpi_cpu_plug_cb(ACPIREGS *ar, qemu_irq irq,
                      AcpiCpuHotplug *g, DeviceState *dev, Error **errp);

void acpi_cpu_hotplug_init(MemoryRegion *parent, Object *owner,
                           AcpiCpuHotplug *gpe_cpu, uint16_t base);
#endif
