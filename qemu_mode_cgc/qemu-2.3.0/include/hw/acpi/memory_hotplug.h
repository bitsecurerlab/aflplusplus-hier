#ifndef QEMU_HW_ACPI_MEMORY_HOTPLUG_H
#define QEMU_HW_ACPI_MEMORY_HOTPLUG_H

#include "hw/qdev-core.h"
#include "hw/acpi/acpi.h"
#include "migration/vmstate.h"

#define ACPI_MEMORY_HOTPLUG_STATUS 8

typedef struct MemStatus {
    DeviceState *dimm;
    bool is_enabled;
    bool is_inserting;
    uint32_t ost_event;
    uint32_t ost_status;
} MemStatus;

typedef struct MemHotplugState {
    bool is_enabled; /* true if memory hotplug is supported */
    MemoryRegion io;
    uint32_t selector;
    uint32_t dev_count;
    MemStatus *devs;
} MemHotplugState;

void acpi_memory_hotplug_init(MemoryRegion *as, Object *owner,
                              MemHotplugState *state);

void acpi_memory_plug_cb(ACPIREGS *ar, qemu_irq irq, MemHotplugState *mem_st,
                         DeviceState *dev, Error **errp);

extern const VMStateDescription vmstate_memory_hotplug;
#define VMSTATE_MEMORY_HOTPLUG(memhp, state) \
    VMSTATE_STRUCT(memhp, state, 1, \
                   vmstate_memory_hotplug, MemHotplugState)

void acpi_memory_ospm_status(MemHotplugState *mem_st, ACPIOSTInfoList ***list);
#endif
