/*
 * virtio ccw target implementation
 *
 * Copyright 2012,2014 IBM Corp.
 * Author(s): Cornelia Huck <cornelia.huck@de.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or (at
 * your option) any later version. See the COPYING file in the top-level
 * directory.
 */

#include "hw/hw.h"
#include "sysemu/block-backend.h"
#include "sysemu/blockdev.h"
#include "sysemu/sysemu.h"
#include "net/net.h"
#include "monitor/monitor.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-serial.h"
#include "hw/virtio/virtio-net.h"
#include "hw/sysbus.h"
#include "qemu/bitops.h"
#include "hw/virtio/virtio-bus.h"
#include "hw/s390x/adapter.h"
#include "hw/s390x/s390_flic.h"

#include "ioinst.h"
#include "css.h"
#include "virtio-ccw.h"
#include "trace.h"

static QTAILQ_HEAD(, IndAddr) indicator_addresses =
    QTAILQ_HEAD_INITIALIZER(indicator_addresses);

static IndAddr *get_indicator(hwaddr ind_addr, int len)
{
    IndAddr *indicator;

    QTAILQ_FOREACH(indicator, &indicator_addresses, sibling) {
        if (indicator->addr == ind_addr) {
            indicator->refcnt++;
            return indicator;
        }
    }
    indicator = g_new0(IndAddr, 1);
    indicator->addr = ind_addr;
    indicator->len = len;
    indicator->refcnt = 1;
    QTAILQ_INSERT_TAIL(&indicator_addresses, indicator, sibling);
    return indicator;
}

static int s390_io_adapter_map(AdapterInfo *adapter, uint64_t map_addr,
                               bool do_map)
{
    S390FLICState *fs = s390_get_flic();
    S390FLICStateClass *fsc = S390_FLIC_COMMON_GET_CLASS(fs);

    return fsc->io_adapter_map(fs, adapter->adapter_id, map_addr, do_map);
}

static void release_indicator(AdapterInfo *adapter, IndAddr *indicator)
{
    assert(indicator->refcnt > 0);
    indicator->refcnt--;
    if (indicator->refcnt > 0) {
        return;
    }
    QTAILQ_REMOVE(&indicator_addresses, indicator, sibling);
    if (indicator->map) {
        s390_io_adapter_map(adapter, indicator->map, false);
    }
    g_free(indicator);
}

static int map_indicator(AdapterInfo *adapter, IndAddr *indicator)
{
    int ret;

    if (indicator->map) {
        return 0; /* already mapped is not an error */
    }
    indicator->map = indicator->addr;
    ret = s390_io_adapter_map(adapter, indicator->map, true);
    if ((ret != 0) && (ret != -ENOSYS)) {
        goto out_err;
    }
    return 0;

out_err:
    indicator->map = 0;
    return ret;
}

static void virtio_ccw_bus_new(VirtioBusState *bus, size_t bus_size,
                               VirtioCcwDevice *dev);

static void virtual_css_bus_reset(BusState *qbus)
{
    /* This should actually be modelled via the generic css */
    css_reset();
}


static void virtual_css_bus_class_init(ObjectClass *klass, void *data)
{
    BusClass *k = BUS_CLASS(klass);

    k->reset = virtual_css_bus_reset;
}

static const TypeInfo virtual_css_bus_info = {
    .name = TYPE_VIRTUAL_CSS_BUS,
    .parent = TYPE_BUS,
    .instance_size = sizeof(VirtualCssBus),
    .class_init = virtual_css_bus_class_init,
};

VirtIODevice *virtio_ccw_get_vdev(SubchDev *sch)
{
    VirtIODevice *vdev = NULL;
    VirtioCcwDevice *dev = sch->driver_data;

    if (dev) {
        vdev = virtio_bus_get_device(&dev->bus);
    }
    return vdev;
}

static int virtio_ccw_set_guest2host_notifier(VirtioCcwDevice *dev, int n,
                                              bool assign, bool set_handler)
{
    VirtIODevice *vdev = virtio_bus_get_device(&dev->bus);
    VirtQueue *vq = virtio_get_queue(vdev, n);
    EventNotifier *notifier = virtio_queue_get_host_notifier(vq);
    int r = 0;
    SubchDev *sch = dev->sch;
    uint32_t sch_id = (css_build_subchannel_id(sch) << 16) | sch->schid;

    if (assign) {
        r = event_notifier_init(notifier, 1);
        if (r < 0) {
            error_report("%s: unable to init event notifier: %d", __func__, r);
            return r;
        }
        virtio_queue_set_host_notifier_fd_handler(vq, true, set_handler);
        r = s390_assign_subch_ioeventfd(notifier, sch_id, n, assign);
        if (r < 0) {
            error_report("%s: unable to assign ioeventfd: %d", __func__, r);
            virtio_queue_set_host_notifier_fd_handler(vq, false, false);
            event_notifier_cleanup(notifier);
            return r;
        }
    } else {
        virtio_queue_set_host_notifier_fd_handler(vq, false, false);
        s390_assign_subch_ioeventfd(notifier, sch_id, n, assign);
        event_notifier_cleanup(notifier);
    }
    return r;
}

static void virtio_ccw_start_ioeventfd(VirtioCcwDevice *dev)
{
    VirtIODevice *vdev;
    int n, r;

    if (!(dev->flags & VIRTIO_CCW_FLAG_USE_IOEVENTFD) ||
        dev->ioeventfd_disabled ||
        dev->ioeventfd_started) {
        return;
    }
    vdev = virtio_bus_get_device(&dev->bus);
    for (n = 0; n < VIRTIO_PCI_QUEUE_MAX; n++) {
        if (!virtio_queue_get_num(vdev, n)) {
            continue;
        }
        r = virtio_ccw_set_guest2host_notifier(dev, n, true, true);
        if (r < 0) {
            goto assign_error;
        }
    }
    dev->ioeventfd_started = true;
    return;

  assign_error:
    while (--n >= 0) {
        if (!virtio_queue_get_num(vdev, n)) {
            continue;
        }
        r = virtio_ccw_set_guest2host_notifier(dev, n, false, false);
        assert(r >= 0);
    }
    dev->ioeventfd_started = false;
    /* Disable ioeventfd for this device. */
    dev->flags &= ~VIRTIO_CCW_FLAG_USE_IOEVENTFD;
    error_report("%s: failed. Fallback to userspace (slower).", __func__);
}

static void virtio_ccw_stop_ioeventfd(VirtioCcwDevice *dev)
{
    VirtIODevice *vdev;
    int n, r;

    if (!dev->ioeventfd_started) {
        return;
    }
    vdev = virtio_bus_get_device(&dev->bus);
    for (n = 0; n < VIRTIO_PCI_QUEUE_MAX; n++) {
        if (!virtio_queue_get_num(vdev, n)) {
            continue;
        }
        r = virtio_ccw_set_guest2host_notifier(dev, n, false, false);
        assert(r >= 0);
    }
    dev->ioeventfd_started = false;
}

VirtualCssBus *virtual_css_bus_init(void)
{
    VirtualCssBus *cbus;
    BusState *bus;
    DeviceState *dev;

    /* Create bridge device */
    dev = qdev_create(NULL, "virtual-css-bridge");
    qdev_init_nofail(dev);

    /* Create bus on bridge device */
    bus = qbus_create(TYPE_VIRTUAL_CSS_BUS, dev, "virtual-css");
    cbus = VIRTUAL_CSS_BUS(bus);

    /* Enable hotplugging */
    qbus_set_hotplug_handler(bus, dev, &error_abort);

    return cbus;
}

/* Communication blocks used by several channel commands. */
typedef struct VqInfoBlock {
    uint64_t queue;
    uint32_t align;
    uint16_t index;
    uint16_t num;
} QEMU_PACKED VqInfoBlock;

typedef struct VqConfigBlock {
    uint16_t index;
    uint16_t num_max;
} QEMU_PACKED VqConfigBlock;

typedef struct VirtioFeatDesc {
    uint32_t features;
    uint8_t index;
} QEMU_PACKED VirtioFeatDesc;

typedef struct VirtioThinintInfo {
    hwaddr summary_indicator;
    hwaddr device_indicator;
    uint64_t ind_bit;
    uint8_t isc;
} QEMU_PACKED VirtioThinintInfo;

/* Specify where the virtqueues for the subchannel are in guest memory. */
static int virtio_ccw_set_vqs(SubchDev *sch, uint64_t addr, uint32_t align,
                              uint16_t index, uint16_t num)
{
    VirtIODevice *vdev = virtio_ccw_get_vdev(sch);

    if (index >= VIRTIO_PCI_QUEUE_MAX) {
        return -EINVAL;
    }

    /* Current code in virtio.c relies on 4K alignment. */
    if (addr && (align != 4096)) {
        return -EINVAL;
    }

    if (!vdev) {
        return -EINVAL;
    }

    virtio_queue_set_addr(vdev, index, addr);
    if (!addr) {
        virtio_queue_set_vector(vdev, index, 0);
    } else {
        /* Fail if we don't have a big enough queue. */
        /* TODO: Add interface to handle vring.num changing */
        if (virtio_queue_get_num(vdev, index) > num) {
            return -EINVAL;
        }
        virtio_queue_set_vector(vdev, index, index);
    }
    /* tell notify handler in case of config change */
    vdev->config_vector = VIRTIO_PCI_QUEUE_MAX;
    return 0;
}

static int virtio_ccw_cb(SubchDev *sch, CCW1 ccw)
{
    int ret;
    VqInfoBlock info;
    uint8_t status;
    VirtioFeatDesc features;
    void *config;
    hwaddr indicators;
    VqConfigBlock vq_config;
    VirtioCcwDevice *dev = sch->driver_data;
    VirtIODevice *vdev = virtio_ccw_get_vdev(sch);
    bool check_len;
    int len;
    hwaddr hw_len;
    VirtioThinintInfo *thinint;

    if (!dev) {
        return -EINVAL;
    }

    trace_virtio_ccw_interpret_ccw(sch->cssid, sch->ssid, sch->schid,
                                   ccw.cmd_code);
    check_len = !((ccw.flags & CCW_FLAG_SLI) && !(ccw.flags & CCW_FLAG_DC));

    /* Look at the command. */
    switch (ccw.cmd_code) {
    case CCW_CMD_SET_VQ:
        if (check_len) {
            if (ccw.count != sizeof(info)) {
                ret = -EINVAL;
                break;
            }
        } else if (ccw.count < sizeof(info)) {
            /* Can't execute command. */
            ret = -EINVAL;
            break;
        }
        if (!ccw.cda) {
            ret = -EFAULT;
        } else {
            info.queue = ldq_phys(&address_space_memory, ccw.cda);
            info.align = ldl_phys(&address_space_memory,
                                  ccw.cda + sizeof(info.queue));
            info.index = lduw_phys(&address_space_memory,
                                   ccw.cda + sizeof(info.queue)
                                   + sizeof(info.align));
            info.num = lduw_phys(&address_space_memory,
                                 ccw.cda + sizeof(info.queue)
                                 + sizeof(info.align)
                                 + sizeof(info.index));
            ret = virtio_ccw_set_vqs(sch, info.queue, info.align, info.index,
                                     info.num);
            sch->curr_status.scsw.count = 0;
        }
        break;
    case CCW_CMD_VDEV_RESET:
        virtio_ccw_stop_ioeventfd(dev);
        virtio_reset(vdev);
        ret = 0;
        break;
    case CCW_CMD_READ_FEAT:
        if (check_len) {
            if (ccw.count != sizeof(features)) {
                ret = -EINVAL;
                break;
            }
        } else if (ccw.count < sizeof(features)) {
            /* Can't execute command. */
            ret = -EINVAL;
            break;
        }
        if (!ccw.cda) {
            ret = -EFAULT;
        } else {
            features.index = ldub_phys(&address_space_memory,
                                       ccw.cda + sizeof(features.features));
            if (features.index < ARRAY_SIZE(dev->host_features)) {
                features.features = dev->host_features[features.index];
            } else {
                /* Return zeroes if the guest supports more feature bits. */
                features.features = 0;
            }
            stl_le_phys(&address_space_memory, ccw.cda, features.features);
            sch->curr_status.scsw.count = ccw.count - sizeof(features);
            ret = 0;
        }
        break;
    case CCW_CMD_WRITE_FEAT:
        if (check_len) {
            if (ccw.count != sizeof(features)) {
                ret = -EINVAL;
                break;
            }
        } else if (ccw.count < sizeof(features)) {
            /* Can't execute command. */
            ret = -EINVAL;
            break;
        }
        if (!ccw.cda) {
            ret = -EFAULT;
        } else {
            features.index = ldub_phys(&address_space_memory,
                                       ccw.cda + sizeof(features.features));
            features.features = ldl_le_phys(&address_space_memory, ccw.cda);
            if (features.index < ARRAY_SIZE(dev->host_features)) {
                virtio_set_features(vdev, features.features);
            } else {
                /*
                 * If the guest supports more feature bits, assert that it
                 * passes us zeroes for those we don't support.
                 */
                if (features.features) {
                    fprintf(stderr, "Guest bug: features[%i]=%x (expected 0)\n",
                            features.index, features.features);
                    /* XXX: do a unit check here? */
                }
            }
            sch->curr_status.scsw.count = ccw.count - sizeof(features);
            ret = 0;
        }
        break;
    case CCW_CMD_READ_CONF:
        if (check_len) {
            if (ccw.count > vdev->config_len) {
                ret = -EINVAL;
                break;
            }
        }
        len = MIN(ccw.count, vdev->config_len);
        if (!ccw.cda) {
            ret = -EFAULT;
        } else {
            virtio_bus_get_vdev_config(&dev->bus, vdev->config);
            /* XXX config space endianness */
            cpu_physical_memory_write(ccw.cda, vdev->config, len);
            sch->curr_status.scsw.count = ccw.count - len;
            ret = 0;
        }
        break;
    case CCW_CMD_WRITE_CONF:
        if (check_len) {
            if (ccw.count > vdev->config_len) {
                ret = -EINVAL;
                break;
            }
        }
        len = MIN(ccw.count, vdev->config_len);
        hw_len = len;
        if (!ccw.cda) {
            ret = -EFAULT;
        } else {
            config = cpu_physical_memory_map(ccw.cda, &hw_len, 0);
            if (!config) {
                ret = -EFAULT;
            } else {
                len = hw_len;
                /* XXX config space endianness */
                memcpy(vdev->config, config, len);
                cpu_physical_memory_unmap(config, hw_len, 0, hw_len);
                virtio_bus_set_vdev_config(&dev->bus, vdev->config);
                sch->curr_status.scsw.count = ccw.count - len;
                ret = 0;
            }
        }
        break;
    case CCW_CMD_WRITE_STATUS:
        if (check_len) {
            if (ccw.count != sizeof(status)) {
                ret = -EINVAL;
                break;
            }
        } else if (ccw.count < sizeof(status)) {
            /* Can't execute command. */
            ret = -EINVAL;
            break;
        }
        if (!ccw.cda) {
            ret = -EFAULT;
        } else {
            status = ldub_phys(&address_space_memory, ccw.cda);
            if (!(status & VIRTIO_CONFIG_S_DRIVER_OK)) {
                virtio_ccw_stop_ioeventfd(dev);
            }
            virtio_set_status(vdev, status);
            if (vdev->status == 0) {
                virtio_reset(vdev);
            }
            if (status & VIRTIO_CONFIG_S_DRIVER_OK) {
                virtio_ccw_start_ioeventfd(dev);
            }
            sch->curr_status.scsw.count = ccw.count - sizeof(status);
            ret = 0;
        }
        break;
    case CCW_CMD_SET_IND:
        if (check_len) {
            if (ccw.count != sizeof(indicators)) {
                ret = -EINVAL;
                break;
            }
        } else if (ccw.count < sizeof(indicators)) {
            /* Can't execute command. */
            ret = -EINVAL;
            break;
        }
        if (sch->thinint_active) {
            /* Trigger a command reject. */
            ret = -ENOSYS;
            break;
        }
        if (!ccw.cda) {
            ret = -EFAULT;
        } else {
            indicators = ldq_be_phys(&address_space_memory, ccw.cda);
            dev->indicators = get_indicator(indicators, sizeof(uint64_t));
            sch->curr_status.scsw.count = ccw.count - sizeof(indicators);
            ret = 0;
        }
        break;
    case CCW_CMD_SET_CONF_IND:
        if (check_len) {
            if (ccw.count != sizeof(indicators)) {
                ret = -EINVAL;
                break;
            }
        } else if (ccw.count < sizeof(indicators)) {
            /* Can't execute command. */
            ret = -EINVAL;
            break;
        }
        if (!ccw.cda) {
            ret = -EFAULT;
        } else {
            indicators = ldq_be_phys(&address_space_memory, ccw.cda);
            dev->indicators2 = get_indicator(indicators, sizeof(uint64_t));
            sch->curr_status.scsw.count = ccw.count - sizeof(indicators);
            ret = 0;
        }
        break;
    case CCW_CMD_READ_VQ_CONF:
        if (check_len) {
            if (ccw.count != sizeof(vq_config)) {
                ret = -EINVAL;
                break;
            }
        } else if (ccw.count < sizeof(vq_config)) {
            /* Can't execute command. */
            ret = -EINVAL;
            break;
        }
        if (!ccw.cda) {
            ret = -EFAULT;
        } else {
            vq_config.index = lduw_be_phys(&address_space_memory, ccw.cda);
            if (vq_config.index >= VIRTIO_PCI_QUEUE_MAX) {
                ret = -EINVAL;
                break;
            }
            vq_config.num_max = virtio_queue_get_num(vdev,
                                                     vq_config.index);
            stw_be_phys(&address_space_memory,
                        ccw.cda + sizeof(vq_config.index), vq_config.num_max);
            sch->curr_status.scsw.count = ccw.count - sizeof(vq_config);
            ret = 0;
        }
        break;
    case CCW_CMD_SET_IND_ADAPTER:
        if (check_len) {
            if (ccw.count != sizeof(*thinint)) {
                ret = -EINVAL;
                break;
            }
        } else if (ccw.count < sizeof(*thinint)) {
            /* Can't execute command. */
            ret = -EINVAL;
            break;
        }
        len = sizeof(*thinint);
        hw_len = len;
        if (!ccw.cda) {
            ret = -EFAULT;
        } else if (dev->indicators && !sch->thinint_active) {
            /* Trigger a command reject. */
            ret = -ENOSYS;
        } else {
            thinint = cpu_physical_memory_map(ccw.cda, &hw_len, 0);
            if (!thinint) {
                ret = -EFAULT;
            } else {
                uint64_t ind_bit = ldq_be_p(&thinint->ind_bit);

                len = hw_len;
                dev->summary_indicator =
                    get_indicator(ldq_be_p(&thinint->summary_indicator),
                                  sizeof(uint8_t));
                dev->indicators =
                    get_indicator(ldq_be_p(&thinint->device_indicator),
                                  ind_bit / 8 + 1);
                dev->thinint_isc = thinint->isc;
                dev->routes.adapter.ind_offset = ind_bit;
                dev->routes.adapter.summary_offset = 7;
                cpu_physical_memory_unmap(thinint, hw_len, 0, hw_len);
                ret = css_register_io_adapter(CSS_IO_ADAPTER_VIRTIO,
                                              dev->thinint_isc, true, false,
                                              &dev->routes.adapter.adapter_id);
                assert(ret == 0);
                sch->thinint_active = ((dev->indicators != NULL) &&
                                       (dev->summary_indicator != NULL));
                sch->curr_status.scsw.count = ccw.count - len;
                ret = 0;
            }
        }
        break;
    default:
        ret = -ENOSYS;
        break;
    }
    return ret;
}

static void virtio_ccw_device_realize(VirtioCcwDevice *dev,
                                      VirtIODevice *vdev, Error **errp)
{
    unsigned int cssid = 0;
    unsigned int ssid = 0;
    unsigned int schid;
    unsigned int devno;
    bool have_devno = false;
    bool found = false;
    SubchDev *sch;
    int num;
    DeviceState *parent = DEVICE(dev);

    sch = g_malloc0(sizeof(SubchDev));

    sch->driver_data = dev;
    dev->sch = sch;

    dev->indicators = NULL;

    /* Initialize subchannel structure. */
    sch->channel_prog = 0x0;
    sch->last_cmd_valid = false;
    sch->thinint_active = false;
    /*
     * Use a device number if provided. Otherwise, fall back to subchannel
     * number.
     */
    if (dev->bus_id) {
        num = sscanf(dev->bus_id, "%x.%x.%04x", &cssid, &ssid, &devno);
        if (num == 3) {
            if ((cssid > MAX_CSSID) || (ssid > MAX_SSID)) {
                error_setg(errp, "Invalid cssid or ssid: cssid %x, ssid %x",
                           cssid, ssid);
                goto out_err;
            }
            /* Enforce use of virtual cssid. */
            if (cssid != VIRTUAL_CSSID) {
                error_setg(errp, "cssid %x not valid for virtio devices",
                           cssid);
                goto out_err;
            }
            if (css_devno_used(cssid, ssid, devno)) {
                error_setg(errp, "Device %x.%x.%04x already exists",
                           cssid, ssid, devno);
                goto out_err;
            }
            sch->cssid = cssid;
            sch->ssid = ssid;
            sch->devno = devno;
            have_devno = true;
        } else {
            error_setg(errp, "Malformed devno parameter '%s'", dev->bus_id);
            goto out_err;
        }
    }

    /* Find the next free id. */
    if (have_devno) {
        for (schid = 0; schid <= MAX_SCHID; schid++) {
            if (!css_find_subch(1, cssid, ssid, schid)) {
                sch->schid = schid;
                css_subch_assign(cssid, ssid, schid, devno, sch);
                found = true;
                break;
            }
        }
        if (!found) {
            error_setg(errp, "No free subchannel found for %x.%x.%04x",
                       cssid, ssid, devno);
            goto out_err;
        }
        trace_virtio_ccw_new_device(cssid, ssid, schid, devno,
                                    "user-configured");
    } else {
        cssid = VIRTUAL_CSSID;
        for (ssid = 0; ssid <= MAX_SSID; ssid++) {
            for (schid = 0; schid <= MAX_SCHID; schid++) {
                if (!css_find_subch(1, cssid, ssid, schid)) {
                    sch->cssid = cssid;
                    sch->ssid = ssid;
                    sch->schid = schid;
                    devno = schid;
                    /*
                     * If the devno is already taken, look further in this
                     * subchannel set.
                     */
                    while (css_devno_used(cssid, ssid, devno)) {
                        if (devno == MAX_SCHID) {
                            devno = 0;
                        } else if (devno == schid - 1) {
                            error_setg(errp, "No free devno found");
                            goto out_err;
                        } else {
                            devno++;
                        }
                    }
                    sch->devno = devno;
                    css_subch_assign(cssid, ssid, schid, devno, sch);
                    found = true;
                    break;
                }
            }
            if (found) {
                break;
            }
        }
        if (!found) {
            error_setg(errp, "Virtual channel subsystem is full!");
            goto out_err;
        }
        trace_virtio_ccw_new_device(cssid, ssid, schid, devno,
                                    "auto-configured");
    }

    /* Build initial schib. */
    css_sch_build_virtual_schib(sch, 0, VIRTIO_CCW_CHPID_TYPE);

    sch->ccw_cb = virtio_ccw_cb;

    /* Build senseid data. */
    memset(&sch->id, 0, sizeof(SenseId));
    sch->id.reserved = 0xff;
    sch->id.cu_type = VIRTIO_CCW_CU_TYPE;
    sch->id.cu_model = vdev->device_id;

    /* Only the first 32 feature bits are used. */
    dev->host_features[0] = virtio_bus_get_vdev_features(&dev->bus,
                                                         dev->host_features[0]);

    virtio_add_feature(&dev->host_features[0], VIRTIO_F_NOTIFY_ON_EMPTY);
    virtio_add_feature(&dev->host_features[0], VIRTIO_F_BAD_FEATURE);

    css_generate_sch_crws(sch->cssid, sch->ssid, sch->schid,
                          parent->hotplugged, 1);
    return;

out_err:
    dev->sch = NULL;
    g_free(sch);
}

static int virtio_ccw_exit(VirtioCcwDevice *dev)
{
    SubchDev *sch = dev->sch;

    if (sch) {
        css_subch_assign(sch->cssid, sch->ssid, sch->schid, sch->devno, NULL);
        g_free(sch);
    }
    if (dev->indicators) {
        release_indicator(&dev->routes.adapter, dev->indicators);
        dev->indicators = NULL;
    }
    return 0;
}

static void virtio_ccw_net_realize(VirtioCcwDevice *ccw_dev, Error **errp)
{
    DeviceState *qdev = DEVICE(ccw_dev);
    VirtIONetCcw *dev = VIRTIO_NET_CCW(ccw_dev);
    DeviceState *vdev = DEVICE(&dev->vdev);
    Error *err = NULL;

    virtio_net_set_config_size(&dev->vdev, ccw_dev->host_features[0]);
    virtio_net_set_netclient_name(&dev->vdev, qdev->id,
                                  object_get_typename(OBJECT(qdev)));
    qdev_set_parent_bus(vdev, BUS(&ccw_dev->bus));
    object_property_set_bool(OBJECT(vdev), true, "realized", &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }

    virtio_ccw_device_realize(ccw_dev, VIRTIO_DEVICE(vdev), errp);
}

static void virtio_ccw_net_instance_init(Object *obj)
{
    VirtIONetCcw *dev = VIRTIO_NET_CCW(obj);

    virtio_instance_init_common(obj, &dev->vdev, sizeof(dev->vdev),
                                TYPE_VIRTIO_NET);
    object_property_add_alias(obj, "bootindex", OBJECT(&dev->vdev),
                              "bootindex", &error_abort);
}

static void virtio_ccw_blk_realize(VirtioCcwDevice *ccw_dev, Error **errp)
{
    VirtIOBlkCcw *dev = VIRTIO_BLK_CCW(ccw_dev);
    DeviceState *vdev = DEVICE(&dev->vdev);
    Error *err = NULL;

    qdev_set_parent_bus(vdev, BUS(&ccw_dev->bus));
    object_property_set_bool(OBJECT(vdev), true, "realized", &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }

    virtio_ccw_device_realize(ccw_dev, VIRTIO_DEVICE(vdev), errp);
}

static void virtio_ccw_blk_instance_init(Object *obj)
{
    VirtIOBlkCcw *dev = VIRTIO_BLK_CCW(obj);

    virtio_instance_init_common(obj, &dev->vdev, sizeof(dev->vdev),
                                TYPE_VIRTIO_BLK);
    object_property_add_alias(obj, "iothread", OBJECT(&dev->vdev),"iothread",
                              &error_abort);
    object_property_add_alias(obj, "bootindex", OBJECT(&dev->vdev),
                              "bootindex", &error_abort);
}

static void virtio_ccw_serial_realize(VirtioCcwDevice *ccw_dev, Error **errp)
{
    VirtioSerialCcw *dev = VIRTIO_SERIAL_CCW(ccw_dev);
    DeviceState *vdev = DEVICE(&dev->vdev);
    DeviceState *proxy = DEVICE(ccw_dev);
    Error *err = NULL;
    char *bus_name;

    /*
     * For command line compatibility, this sets the virtio-serial-device bus
     * name as before.
     */
    if (proxy->id) {
        bus_name = g_strdup_printf("%s.0", proxy->id);
        virtio_device_set_child_bus_name(VIRTIO_DEVICE(vdev), bus_name);
        g_free(bus_name);
    }

    qdev_set_parent_bus(vdev, BUS(&ccw_dev->bus));
    object_property_set_bool(OBJECT(vdev), true, "realized", &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }

    virtio_ccw_device_realize(ccw_dev, VIRTIO_DEVICE(vdev), errp);
}


static void virtio_ccw_serial_instance_init(Object *obj)
{
    VirtioSerialCcw *dev = VIRTIO_SERIAL_CCW(obj);

    virtio_instance_init_common(obj, &dev->vdev, sizeof(dev->vdev),
                                TYPE_VIRTIO_SERIAL);
}

static void virtio_ccw_balloon_realize(VirtioCcwDevice *ccw_dev, Error **errp)
{
    VirtIOBalloonCcw *dev = VIRTIO_BALLOON_CCW(ccw_dev);
    DeviceState *vdev = DEVICE(&dev->vdev);
    Error *err = NULL;

    qdev_set_parent_bus(vdev, BUS(&ccw_dev->bus));
    object_property_set_bool(OBJECT(vdev), true, "realized", &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }

    virtio_ccw_device_realize(ccw_dev, VIRTIO_DEVICE(vdev), errp);
}

static void balloon_ccw_stats_get_all(Object *obj, struct Visitor *v,
                                      void *opaque, const char *name,
                                      Error **errp)
{
    VirtIOBalloonCcw *dev = opaque;
    object_property_get(OBJECT(&dev->vdev), v, "guest-stats", errp);
}

static void balloon_ccw_stats_get_poll_interval(Object *obj, struct Visitor *v,
                                                void *opaque, const char *name,
                                                Error **errp)
{
    VirtIOBalloonCcw *dev = opaque;
    object_property_get(OBJECT(&dev->vdev), v, "guest-stats-polling-interval",
                        errp);
}

static void balloon_ccw_stats_set_poll_interval(Object *obj, struct Visitor *v,
                                                void *opaque, const char *name,
                                                Error **errp)
{
    VirtIOBalloonCcw *dev = opaque;
    object_property_set(OBJECT(&dev->vdev), v, "guest-stats-polling-interval",
                        errp);
}

static void virtio_ccw_balloon_instance_init(Object *obj)
{
    VirtIOBalloonCcw *dev = VIRTIO_BALLOON_CCW(obj);
    virtio_instance_init_common(obj, &dev->vdev, sizeof(dev->vdev),
                                TYPE_VIRTIO_BALLOON);
    object_property_add(obj, "guest-stats", "guest statistics",
                        balloon_ccw_stats_get_all, NULL, NULL, dev, NULL);

    object_property_add(obj, "guest-stats-polling-interval", "int",
                        balloon_ccw_stats_get_poll_interval,
                        balloon_ccw_stats_set_poll_interval,
                        NULL, dev, NULL);
}

static void virtio_ccw_scsi_realize(VirtioCcwDevice *ccw_dev, Error **errp)
{
    VirtIOSCSICcw *dev = VIRTIO_SCSI_CCW(ccw_dev);
    DeviceState *vdev = DEVICE(&dev->vdev);
    DeviceState *qdev = DEVICE(ccw_dev);
    Error *err = NULL;
    char *bus_name;

    /*
     * For command line compatibility, this sets the virtio-scsi-device bus
     * name as before.
     */
    if (qdev->id) {
        bus_name = g_strdup_printf("%s.0", qdev->id);
        virtio_device_set_child_bus_name(VIRTIO_DEVICE(vdev), bus_name);
        g_free(bus_name);
    }

    qdev_set_parent_bus(vdev, BUS(&ccw_dev->bus));
    object_property_set_bool(OBJECT(vdev), true, "realized", &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }

    virtio_ccw_device_realize(ccw_dev, VIRTIO_DEVICE(vdev), errp);
}

static void virtio_ccw_scsi_instance_init(Object *obj)
{
    VirtIOSCSICcw *dev = VIRTIO_SCSI_CCW(obj);

    virtio_instance_init_common(obj, &dev->vdev, sizeof(dev->vdev),
                                TYPE_VIRTIO_SCSI);
    object_property_add_alias(obj, "iothread", OBJECT(&dev->vdev), "iothread",
                              &error_abort);
}

#ifdef CONFIG_VHOST_SCSI
static void vhost_ccw_scsi_realize(VirtioCcwDevice *ccw_dev, Error **errp)
{
    VHostSCSICcw *dev = VHOST_SCSI_CCW(ccw_dev);
    DeviceState *vdev = DEVICE(&dev->vdev);
    Error *err = NULL;

    qdev_set_parent_bus(vdev, BUS(&ccw_dev->bus));
    object_property_set_bool(OBJECT(vdev), true, "realized", &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }

    virtio_ccw_device_realize(ccw_dev, VIRTIO_DEVICE(vdev), errp);
}

static void vhost_ccw_scsi_instance_init(Object *obj)
{
    VHostSCSICcw *dev = VHOST_SCSI_CCW(obj);

    virtio_instance_init_common(obj, &dev->vdev, sizeof(dev->vdev),
                                TYPE_VHOST_SCSI);
}
#endif

static void virtio_ccw_rng_realize(VirtioCcwDevice *ccw_dev, Error **errp)
{
    VirtIORNGCcw *dev = VIRTIO_RNG_CCW(ccw_dev);
    DeviceState *vdev = DEVICE(&dev->vdev);
    Error *err = NULL;

    qdev_set_parent_bus(vdev, BUS(&ccw_dev->bus));
    object_property_set_bool(OBJECT(vdev), true, "realized", &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }

    object_property_set_link(OBJECT(dev),
                             OBJECT(dev->vdev.conf.rng), "rng",
                             NULL);

    virtio_ccw_device_realize(ccw_dev, VIRTIO_DEVICE(vdev), errp);
}

/* DeviceState to VirtioCcwDevice. Note: used on datapath,
 * be careful and test performance if you change this.
 */
static inline VirtioCcwDevice *to_virtio_ccw_dev_fast(DeviceState *d)
{
    return container_of(d, VirtioCcwDevice, parent_obj);
}

static uint8_t virtio_set_ind_atomic(SubchDev *sch, uint64_t ind_loc,
                                     uint8_t to_be_set)
{
    uint8_t ind_old, ind_new;
    hwaddr len = 1;
    uint8_t *ind_addr;

    ind_addr = cpu_physical_memory_map(ind_loc, &len, 1);
    if (!ind_addr) {
        error_report("%s(%x.%x.%04x): unable to access indicator",
                     __func__, sch->cssid, sch->ssid, sch->schid);
        return -1;
    }
    do {
        ind_old = *ind_addr;
        ind_new = ind_old | to_be_set;
    } while (atomic_cmpxchg(ind_addr, ind_old, ind_new) != ind_old);
    cpu_physical_memory_unmap(ind_addr, len, 1, len);

    return ind_old;
}

static void virtio_ccw_notify(DeviceState *d, uint16_t vector)
{
    VirtioCcwDevice *dev = to_virtio_ccw_dev_fast(d);
    SubchDev *sch = dev->sch;
    uint64_t indicators;

    if (vector >= 128) {
        return;
    }

    if (vector < VIRTIO_PCI_QUEUE_MAX) {
        if (!dev->indicators) {
            return;
        }
        if (sch->thinint_active) {
            /*
             * In the adapter interrupt case, indicators points to a
             * memory area that may be (way) larger than 64 bit and
             * ind_bit indicates the start of the indicators in a big
             * endian notation.
             */
            uint64_t ind_bit = dev->routes.adapter.ind_offset;

            virtio_set_ind_atomic(sch, dev->indicators->addr +
                                  (ind_bit + vector) / 8,
                                  0x80 >> ((ind_bit + vector) % 8));
            if (!virtio_set_ind_atomic(sch, dev->summary_indicator->addr,
                                       0x01)) {
                css_adapter_interrupt(dev->thinint_isc);
            }
        } else {
            indicators = ldq_phys(&address_space_memory, dev->indicators->addr);
            indicators |= 1ULL << vector;
            stq_phys(&address_space_memory, dev->indicators->addr, indicators);
            css_conditional_io_interrupt(sch);
        }
    } else {
        if (!dev->indicators2) {
            return;
        }
        vector = 0;
        indicators = ldq_phys(&address_space_memory, dev->indicators2->addr);
        indicators |= 1ULL << vector;
        stq_phys(&address_space_memory, dev->indicators2->addr, indicators);
        css_conditional_io_interrupt(sch);
    }
}

static unsigned virtio_ccw_get_features(DeviceState *d)
{
    VirtioCcwDevice *dev = VIRTIO_CCW_DEVICE(d);

    /* Only the first 32 feature bits are used. */
    return dev->host_features[0];
}

static void virtio_ccw_reset(DeviceState *d)
{
    VirtioCcwDevice *dev = VIRTIO_CCW_DEVICE(d);
    VirtIODevice *vdev = virtio_bus_get_device(&dev->bus);

    virtio_ccw_stop_ioeventfd(dev);
    virtio_reset(vdev);
    css_reset_sch(dev->sch);
    if (dev->indicators) {
        release_indicator(&dev->routes.adapter, dev->indicators);
        dev->indicators = NULL;
    }
    if (dev->indicators2) {
        release_indicator(&dev->routes.adapter, dev->indicators2);
        dev->indicators2 = NULL;
    }
    if (dev->summary_indicator) {
        release_indicator(&dev->routes.adapter, dev->summary_indicator);
        dev->summary_indicator = NULL;
    }
}

static void virtio_ccw_vmstate_change(DeviceState *d, bool running)
{
    VirtioCcwDevice *dev = VIRTIO_CCW_DEVICE(d);

    if (running) {
        virtio_ccw_start_ioeventfd(dev);
    } else {
        virtio_ccw_stop_ioeventfd(dev);
    }
}

static bool virtio_ccw_query_guest_notifiers(DeviceState *d)
{
    VirtioCcwDevice *dev = VIRTIO_CCW_DEVICE(d);

    return !!(dev->sch->curr_status.pmcw.flags & PMCW_FLAGS_MASK_ENA);
}

static int virtio_ccw_set_host_notifier(DeviceState *d, int n, bool assign)
{
    VirtioCcwDevice *dev = VIRTIO_CCW_DEVICE(d);

    /* Stop using the generic ioeventfd, we are doing eventfd handling
     * ourselves below */
    dev->ioeventfd_disabled = assign;
    if (assign) {
        virtio_ccw_stop_ioeventfd(dev);
    }
    return virtio_ccw_set_guest2host_notifier(dev, n, assign, false);
}

static int virtio_ccw_get_mappings(VirtioCcwDevice *dev)
{
    int r;

    if (!dev->sch->thinint_active) {
        return -EINVAL;
    }

    r = map_indicator(&dev->routes.adapter, dev->summary_indicator);
    if (r) {
        return r;
    }
    r = map_indicator(&dev->routes.adapter, dev->indicators);
    if (r) {
        return r;
    }
    dev->routes.adapter.summary_addr = dev->summary_indicator->map;
    dev->routes.adapter.ind_addr = dev->indicators->map;

    return 0;
}

static int virtio_ccw_setup_irqroutes(VirtioCcwDevice *dev, int nvqs)
{
    int i;
    VirtIODevice *vdev = virtio_bus_get_device(&dev->bus);
    int ret;
    S390FLICState *fs = s390_get_flic();
    S390FLICStateClass *fsc = S390_FLIC_COMMON_GET_CLASS(fs);

    ret = virtio_ccw_get_mappings(dev);
    if (ret) {
        return ret;
    }
    for (i = 0; i < nvqs; i++) {
        if (!virtio_queue_get_num(vdev, i)) {
            break;
        }
    }
    dev->routes.num_routes = i;
    return fsc->add_adapter_routes(fs, &dev->routes);
}

static void virtio_ccw_release_irqroutes(VirtioCcwDevice *dev, int nvqs)
{
    S390FLICState *fs = s390_get_flic();
    S390FLICStateClass *fsc = S390_FLIC_COMMON_GET_CLASS(fs);

    fsc->release_adapter_routes(fs, &dev->routes);
}

static int virtio_ccw_add_irqfd(VirtioCcwDevice *dev, int n)
{
    VirtIODevice *vdev = virtio_bus_get_device(&dev->bus);
    VirtQueue *vq = virtio_get_queue(vdev, n);
    EventNotifier *notifier = virtio_queue_get_guest_notifier(vq);

    return kvm_irqchip_add_irqfd_notifier(kvm_state, notifier, NULL,
                                          dev->routes.gsi[n]);
}

static void virtio_ccw_remove_irqfd(VirtioCcwDevice *dev, int n)
{
    VirtIODevice *vdev = virtio_bus_get_device(&dev->bus);
    VirtQueue *vq = virtio_get_queue(vdev, n);
    EventNotifier *notifier = virtio_queue_get_guest_notifier(vq);
    int ret;

    ret = kvm_irqchip_remove_irqfd_notifier(kvm_state, notifier,
                                            dev->routes.gsi[n]);
    assert(ret == 0);
}

static int virtio_ccw_set_guest_notifier(VirtioCcwDevice *dev, int n,
                                         bool assign, bool with_irqfd)
{
    VirtIODevice *vdev = virtio_bus_get_device(&dev->bus);
    VirtQueue *vq = virtio_get_queue(vdev, n);
    EventNotifier *notifier = virtio_queue_get_guest_notifier(vq);
    VirtioDeviceClass *k = VIRTIO_DEVICE_GET_CLASS(vdev);

    if (assign) {
        int r = event_notifier_init(notifier, 0);

        if (r < 0) {
            return r;
        }
        virtio_queue_set_guest_notifier_fd_handler(vq, true, with_irqfd);
        if (with_irqfd) {
            r = virtio_ccw_add_irqfd(dev, n);
            if (r) {
                virtio_queue_set_guest_notifier_fd_handler(vq, false,
                                                           with_irqfd);
                return r;
            }
        }
        /*
         * We do not support individual masking for channel devices, so we
         * need to manually trigger any guest masking callbacks here.
         */
        if (k->guest_notifier_mask) {
            k->guest_notifier_mask(vdev, n, false);
        }
        /* get lost events and re-inject */
        if (k->guest_notifier_pending &&
            k->guest_notifier_pending(vdev, n)) {
            event_notifier_set(notifier);
        }
    } else {
        if (k->guest_notifier_mask) {
            k->guest_notifier_mask(vdev, n, true);
        }
        if (with_irqfd) {
            virtio_ccw_remove_irqfd(dev, n);
        }
        virtio_queue_set_guest_notifier_fd_handler(vq, false, with_irqfd);
        event_notifier_cleanup(notifier);
    }
    return 0;
}

static int virtio_ccw_set_guest_notifiers(DeviceState *d, int nvqs,
                                          bool assigned)
{
    VirtioCcwDevice *dev = VIRTIO_CCW_DEVICE(d);
    VirtIODevice *vdev = virtio_bus_get_device(&dev->bus);
    bool with_irqfd = dev->sch->thinint_active && kvm_irqfds_enabled();
    int r, n;

    if (with_irqfd && assigned) {
        /* irq routes need to be set up before assigning irqfds */
        r = virtio_ccw_setup_irqroutes(dev, nvqs);
        if (r < 0) {
            goto irqroute_error;
        }
    }
    for (n = 0; n < nvqs; n++) {
        if (!virtio_queue_get_num(vdev, n)) {
            break;
        }
        r = virtio_ccw_set_guest_notifier(dev, n, assigned, with_irqfd);
        if (r < 0) {
            goto assign_error;
        }
    }
    if (with_irqfd && !assigned) {
        /* release irq routes after irqfds have been released */
        virtio_ccw_release_irqroutes(dev, nvqs);
    }
    return 0;

assign_error:
    while (--n >= 0) {
        virtio_ccw_set_guest_notifier(dev, n, !assigned, false);
    }
irqroute_error:
    if (with_irqfd && assigned) {
        virtio_ccw_release_irqroutes(dev, nvqs);
    }
    return r;
}

static void virtio_ccw_save_queue(DeviceState *d, int n, QEMUFile *f)
{
    VirtioCcwDevice *dev = VIRTIO_CCW_DEVICE(d);
    VirtIODevice *vdev = virtio_bus_get_device(&dev->bus);

    qemu_put_be16(f, virtio_queue_vector(vdev, n));
}

static int virtio_ccw_load_queue(DeviceState *d, int n, QEMUFile *f)
{
    VirtioCcwDevice *dev = VIRTIO_CCW_DEVICE(d);
    VirtIODevice *vdev = virtio_bus_get_device(&dev->bus);
    uint16_t vector;

    qemu_get_be16s(f, &vector);
    virtio_queue_set_vector(vdev, n , vector);

    return 0;
}

static void virtio_ccw_save_config(DeviceState *d, QEMUFile *f)
{
    VirtioCcwDevice *dev = VIRTIO_CCW_DEVICE(d);
    SubchDev *s = dev->sch;

    subch_device_save(s, f);
    if (dev->indicators != NULL) {
        qemu_put_be32(f, dev->indicators->len);
        qemu_put_be64(f, dev->indicators->addr);
    } else {
        qemu_put_be32(f, 0);
        qemu_put_be64(f, 0UL);
    }
    if (dev->indicators2 != NULL) {
        qemu_put_be32(f, dev->indicators2->len);
        qemu_put_be64(f, dev->indicators2->addr);
    } else {
        qemu_put_be32(f, 0);
        qemu_put_be64(f, 0UL);
    }
    if (dev->summary_indicator != NULL) {
        qemu_put_be32(f, dev->summary_indicator->len);
        qemu_put_be64(f, dev->summary_indicator->addr);
    } else {
        qemu_put_be32(f, 0);
        qemu_put_be64(f, 0UL);
    }
    qemu_put_be64(f, dev->routes.adapter.ind_offset);
    qemu_put_byte(f, dev->thinint_isc);
}

static int virtio_ccw_load_config(DeviceState *d, QEMUFile *f)
{
    VirtioCcwDevice *dev = VIRTIO_CCW_DEVICE(d);
    SubchDev *s = dev->sch;
    int len;

    s->driver_data = dev;
    subch_device_load(s, f);
    len = qemu_get_be32(f);
    if (len != 0) {
        dev->indicators = get_indicator(qemu_get_be64(f), len);
    } else {
        qemu_get_be64(f);
        dev->indicators = NULL;
    }
    len = qemu_get_be32(f);
    if (len != 0) {
        dev->indicators2 = get_indicator(qemu_get_be64(f), len);
    } else {
        qemu_get_be64(f);
        dev->indicators2 = NULL;
    }
    len = qemu_get_be32(f);
    if (len != 0) {
        dev->summary_indicator = get_indicator(qemu_get_be64(f), len);
    } else {
        qemu_get_be64(f);
        dev->summary_indicator = NULL;
    }
    dev->routes.adapter.ind_offset = qemu_get_be64(f);
    dev->thinint_isc = qemu_get_byte(f);
    if (s->thinint_active) {
        return css_register_io_adapter(CSS_IO_ADAPTER_VIRTIO,
                                       dev->thinint_isc, true, false,
                                       &dev->routes.adapter.adapter_id);
    }

    return 0;
}

/**************** Virtio-ccw Bus Device Descriptions *******************/

static Property virtio_ccw_net_properties[] = {
    DEFINE_PROP_STRING("devno", VirtioCcwDevice, bus_id),
    DEFINE_VIRTIO_NET_FEATURES(VirtioCcwDevice, host_features[0]),
    DEFINE_PROP_BIT("ioeventfd", VirtioCcwDevice, flags,
                    VIRTIO_CCW_FLAG_USE_IOEVENTFD_BIT, true),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_ccw_net_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtIOCCWDeviceClass *k = VIRTIO_CCW_DEVICE_CLASS(klass);

    k->realize = virtio_ccw_net_realize;
    k->exit = virtio_ccw_exit;
    dc->reset = virtio_ccw_reset;
    dc->props = virtio_ccw_net_properties;
}

static const TypeInfo virtio_ccw_net = {
    .name          = TYPE_VIRTIO_NET_CCW,
    .parent        = TYPE_VIRTIO_CCW_DEVICE,
    .instance_size = sizeof(VirtIONetCcw),
    .instance_init = virtio_ccw_net_instance_init,
    .class_init    = virtio_ccw_net_class_init,
};

static Property virtio_ccw_blk_properties[] = {
    DEFINE_PROP_STRING("devno", VirtioCcwDevice, bus_id),
    DEFINE_PROP_BIT("ioeventfd", VirtioCcwDevice, flags,
                    VIRTIO_CCW_FLAG_USE_IOEVENTFD_BIT, true),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_ccw_blk_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtIOCCWDeviceClass *k = VIRTIO_CCW_DEVICE_CLASS(klass);

    k->realize = virtio_ccw_blk_realize;
    k->exit = virtio_ccw_exit;
    dc->reset = virtio_ccw_reset;
    dc->props = virtio_ccw_blk_properties;
}

static const TypeInfo virtio_ccw_blk = {
    .name          = TYPE_VIRTIO_BLK_CCW,
    .parent        = TYPE_VIRTIO_CCW_DEVICE,
    .instance_size = sizeof(VirtIOBlkCcw),
    .instance_init = virtio_ccw_blk_instance_init,
    .class_init    = virtio_ccw_blk_class_init,
};

static Property virtio_ccw_serial_properties[] = {
    DEFINE_PROP_STRING("devno", VirtioCcwDevice, bus_id),
    DEFINE_PROP_BIT("ioeventfd", VirtioCcwDevice, flags,
                    VIRTIO_CCW_FLAG_USE_IOEVENTFD_BIT, true),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_ccw_serial_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtIOCCWDeviceClass *k = VIRTIO_CCW_DEVICE_CLASS(klass);

    k->realize = virtio_ccw_serial_realize;
    k->exit = virtio_ccw_exit;
    dc->reset = virtio_ccw_reset;
    dc->props = virtio_ccw_serial_properties;
}

static const TypeInfo virtio_ccw_serial = {
    .name          = TYPE_VIRTIO_SERIAL_CCW,
    .parent        = TYPE_VIRTIO_CCW_DEVICE,
    .instance_size = sizeof(VirtioSerialCcw),
    .instance_init = virtio_ccw_serial_instance_init,
    .class_init    = virtio_ccw_serial_class_init,
};

static Property virtio_ccw_balloon_properties[] = {
    DEFINE_PROP_STRING("devno", VirtioCcwDevice, bus_id),
    DEFINE_PROP_BIT("ioeventfd", VirtioCcwDevice, flags,
                    VIRTIO_CCW_FLAG_USE_IOEVENTFD_BIT, true),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_ccw_balloon_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtIOCCWDeviceClass *k = VIRTIO_CCW_DEVICE_CLASS(klass);

    k->realize = virtio_ccw_balloon_realize;
    k->exit = virtio_ccw_exit;
    dc->reset = virtio_ccw_reset;
    dc->props = virtio_ccw_balloon_properties;
}

static const TypeInfo virtio_ccw_balloon = {
    .name          = TYPE_VIRTIO_BALLOON_CCW,
    .parent        = TYPE_VIRTIO_CCW_DEVICE,
    .instance_size = sizeof(VirtIOBalloonCcw),
    .instance_init = virtio_ccw_balloon_instance_init,
    .class_init    = virtio_ccw_balloon_class_init,
};

static Property virtio_ccw_scsi_properties[] = {
    DEFINE_PROP_STRING("devno", VirtioCcwDevice, bus_id),
    DEFINE_VIRTIO_SCSI_FEATURES(VirtioCcwDevice, host_features[0]),
    DEFINE_PROP_BIT("ioeventfd", VirtioCcwDevice, flags,
                    VIRTIO_CCW_FLAG_USE_IOEVENTFD_BIT, true),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_ccw_scsi_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtIOCCWDeviceClass *k = VIRTIO_CCW_DEVICE_CLASS(klass);

    k->realize = virtio_ccw_scsi_realize;
    k->exit = virtio_ccw_exit;
    dc->reset = virtio_ccw_reset;
    dc->props = virtio_ccw_scsi_properties;
}

static const TypeInfo virtio_ccw_scsi = {
    .name          = TYPE_VIRTIO_SCSI_CCW,
    .parent        = TYPE_VIRTIO_CCW_DEVICE,
    .instance_size = sizeof(VirtIOSCSICcw),
    .instance_init = virtio_ccw_scsi_instance_init,
    .class_init    = virtio_ccw_scsi_class_init,
};

#ifdef CONFIG_VHOST_SCSI
static Property vhost_ccw_scsi_properties[] = {
    DEFINE_PROP_STRING("devno", VirtioCcwDevice, bus_id),
    DEFINE_PROP_END_OF_LIST(),
};

static void vhost_ccw_scsi_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtIOCCWDeviceClass *k = VIRTIO_CCW_DEVICE_CLASS(klass);

    k->realize = vhost_ccw_scsi_realize;
    k->exit = virtio_ccw_exit;
    dc->reset = virtio_ccw_reset;
    dc->props = vhost_ccw_scsi_properties;
}

static const TypeInfo vhost_ccw_scsi = {
    .name          = TYPE_VHOST_SCSI_CCW,
    .parent        = TYPE_VIRTIO_CCW_DEVICE,
    .instance_size = sizeof(VHostSCSICcw),
    .instance_init = vhost_ccw_scsi_instance_init,
    .class_init    = vhost_ccw_scsi_class_init,
};
#endif

static void virtio_ccw_rng_instance_init(Object *obj)
{
    VirtIORNGCcw *dev = VIRTIO_RNG_CCW(obj);

    virtio_instance_init_common(obj, &dev->vdev, sizeof(dev->vdev),
                                TYPE_VIRTIO_RNG);
    object_property_add_alias(obj, "rng", OBJECT(&dev->vdev),
                              "rng", &error_abort);
}

static Property virtio_ccw_rng_properties[] = {
    DEFINE_PROP_STRING("devno", VirtioCcwDevice, bus_id),
    DEFINE_PROP_BIT("ioeventfd", VirtioCcwDevice, flags,
                    VIRTIO_CCW_FLAG_USE_IOEVENTFD_BIT, true),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_ccw_rng_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtIOCCWDeviceClass *k = VIRTIO_CCW_DEVICE_CLASS(klass);

    k->realize = virtio_ccw_rng_realize;
    k->exit = virtio_ccw_exit;
    dc->reset = virtio_ccw_reset;
    dc->props = virtio_ccw_rng_properties;
}

static const TypeInfo virtio_ccw_rng = {
    .name          = TYPE_VIRTIO_RNG_CCW,
    .parent        = TYPE_VIRTIO_CCW_DEVICE,
    .instance_size = sizeof(VirtIORNGCcw),
    .instance_init = virtio_ccw_rng_instance_init,
    .class_init    = virtio_ccw_rng_class_init,
};

static void virtio_ccw_busdev_realize(DeviceState *dev, Error **errp)
{
    VirtioCcwDevice *_dev = (VirtioCcwDevice *)dev;
    VirtIOCCWDeviceClass *_info = VIRTIO_CCW_DEVICE_GET_CLASS(dev);

    virtio_ccw_bus_new(&_dev->bus, sizeof(_dev->bus), _dev);
    _info->realize(_dev, errp);
}

static int virtio_ccw_busdev_exit(DeviceState *dev)
{
    VirtioCcwDevice *_dev = (VirtioCcwDevice *)dev;
    VirtIOCCWDeviceClass *_info = VIRTIO_CCW_DEVICE_GET_CLASS(dev);

    return _info->exit(_dev);
}

static void virtio_ccw_busdev_unplug(HotplugHandler *hotplug_dev,
                                     DeviceState *dev, Error **errp)
{
    VirtioCcwDevice *_dev = (VirtioCcwDevice *)dev;
    SubchDev *sch = _dev->sch;

    virtio_ccw_stop_ioeventfd(_dev);

    /*
     * We should arrive here only for device_del, since we don't support
     * direct hot(un)plug of channels, but only through virtio.
     */
    assert(sch != NULL);
    /* Subchannel is now disabled and no longer valid. */
    sch->curr_status.pmcw.flags &= ~(PMCW_FLAGS_MASK_ENA |
                                     PMCW_FLAGS_MASK_DNV);

    css_generate_sch_crws(sch->cssid, sch->ssid, sch->schid, 1, 0);

    object_unparent(OBJECT(dev));
}

static Property virtio_ccw_properties[] = {
    DEFINE_VIRTIO_COMMON_FEATURES(VirtioCcwDevice, host_features[0]),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_ccw_device_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->props = virtio_ccw_properties;
    dc->realize = virtio_ccw_busdev_realize;
    dc->exit = virtio_ccw_busdev_exit;
    dc->bus_type = TYPE_VIRTUAL_CSS_BUS;
}

static const TypeInfo virtio_ccw_device_info = {
    .name = TYPE_VIRTIO_CCW_DEVICE,
    .parent = TYPE_DEVICE,
    .instance_size = sizeof(VirtioCcwDevice),
    .class_init = virtio_ccw_device_class_init,
    .class_size = sizeof(VirtIOCCWDeviceClass),
    .abstract = true,
};

/***************** Virtual-css Bus Bridge Device ********************/
/* Only required to have the virtio bus as child in the system bus */

static int virtual_css_bridge_init(SysBusDevice *dev)
{
    /* nothing */
    return 0;
}

static void virtual_css_bridge_class_init(ObjectClass *klass, void *data)
{
    SysBusDeviceClass *k = SYS_BUS_DEVICE_CLASS(klass);
    HotplugHandlerClass *hc = HOTPLUG_HANDLER_CLASS(klass);

    k->init = virtual_css_bridge_init;
    hc->unplug = virtio_ccw_busdev_unplug;
}

static const TypeInfo virtual_css_bridge_info = {
    .name          = "virtual-css-bridge",
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(SysBusDevice),
    .class_init    = virtual_css_bridge_class_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_HOTPLUG_HANDLER },
        { }
    }
};

/* virtio-ccw-bus */

static void virtio_ccw_bus_new(VirtioBusState *bus, size_t bus_size,
                               VirtioCcwDevice *dev)
{
    DeviceState *qdev = DEVICE(dev);
    char virtio_bus_name[] = "virtio-bus";

    qbus_create_inplace(bus, bus_size, TYPE_VIRTIO_CCW_BUS,
                        qdev, virtio_bus_name);
}

static void virtio_ccw_bus_class_init(ObjectClass *klass, void *data)
{
    VirtioBusClass *k = VIRTIO_BUS_CLASS(klass);
    BusClass *bus_class = BUS_CLASS(klass);

    bus_class->max_dev = 1;
    k->notify = virtio_ccw_notify;
    k->get_features = virtio_ccw_get_features;
    k->vmstate_change = virtio_ccw_vmstate_change;
    k->query_guest_notifiers = virtio_ccw_query_guest_notifiers;
    k->set_host_notifier = virtio_ccw_set_host_notifier;
    k->set_guest_notifiers = virtio_ccw_set_guest_notifiers;
    k->save_queue = virtio_ccw_save_queue;
    k->load_queue = virtio_ccw_load_queue;
    k->save_config = virtio_ccw_save_config;
    k->load_config = virtio_ccw_load_config;
}

static const TypeInfo virtio_ccw_bus_info = {
    .name = TYPE_VIRTIO_CCW_BUS,
    .parent = TYPE_VIRTIO_BUS,
    .instance_size = sizeof(VirtioCcwBusState),
    .class_init = virtio_ccw_bus_class_init,
};

static void virtio_ccw_register(void)
{
    type_register_static(&virtio_ccw_bus_info);
    type_register_static(&virtual_css_bus_info);
    type_register_static(&virtio_ccw_device_info);
    type_register_static(&virtio_ccw_serial);
    type_register_static(&virtio_ccw_blk);
    type_register_static(&virtio_ccw_net);
    type_register_static(&virtio_ccw_balloon);
    type_register_static(&virtio_ccw_scsi);
#ifdef CONFIG_VHOST_SCSI
    type_register_static(&vhost_ccw_scsi);
#endif
    type_register_static(&virtio_ccw_rng);
    type_register_static(&virtual_css_bridge_info);
}

type_init(virtio_ccw_register)
