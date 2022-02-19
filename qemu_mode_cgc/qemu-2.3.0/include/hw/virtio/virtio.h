/*
 * Virtio Support
 *
 * Copyright IBM, Corp. 2007
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#ifndef _QEMU_VIRTIO_H
#define _QEMU_VIRTIO_H

#include "hw/hw.h"
#include "net/net.h"
#include "hw/qdev.h"
#include "sysemu/sysemu.h"
#include "qemu/event_notifier.h"
#include "standard-headers/linux/virtio_config.h"
#include "standard-headers/linux/virtio_ring.h"

/* A guest should never accept this.  It implies negotiation is broken. */
#define VIRTIO_F_BAD_FEATURE		30

struct VirtQueue;

static inline hwaddr vring_align(hwaddr addr,
                                             unsigned long align)
{
    return (addr + align - 1) & ~(align - 1);
}

typedef struct VirtQueue VirtQueue;

#define VIRTQUEUE_MAX_SIZE 1024

typedef struct VirtQueueElement
{
    unsigned int index;
    unsigned int out_num;
    unsigned int in_num;
    hwaddr in_addr[VIRTQUEUE_MAX_SIZE];
    hwaddr out_addr[VIRTQUEUE_MAX_SIZE];
    struct iovec in_sg[VIRTQUEUE_MAX_SIZE];
    struct iovec out_sg[VIRTQUEUE_MAX_SIZE];
} VirtQueueElement;

#define VIRTIO_PCI_QUEUE_MAX 64

#define VIRTIO_NO_VECTOR 0xffff

#define TYPE_VIRTIO_DEVICE "virtio-device"
#define VIRTIO_DEVICE_GET_CLASS(obj) \
        OBJECT_GET_CLASS(VirtioDeviceClass, obj, TYPE_VIRTIO_DEVICE)
#define VIRTIO_DEVICE_CLASS(klass) \
        OBJECT_CLASS_CHECK(VirtioDeviceClass, klass, TYPE_VIRTIO_DEVICE)
#define VIRTIO_DEVICE(obj) \
        OBJECT_CHECK(VirtIODevice, (obj), TYPE_VIRTIO_DEVICE)

enum virtio_device_endian {
    VIRTIO_DEVICE_ENDIAN_UNKNOWN,
    VIRTIO_DEVICE_ENDIAN_LITTLE,
    VIRTIO_DEVICE_ENDIAN_BIG,
};

struct VirtIODevice
{
    DeviceState parent_obj;
    const char *name;
    uint8_t status;
    uint8_t isr;
    uint16_t queue_sel;
    uint32_t guest_features;
    size_t config_len;
    void *config;
    uint16_t config_vector;
    int nvectors;
    VirtQueue *vq;
    uint16_t device_id;
    bool vm_running;
    VMChangeStateEntry *vmstate;
    char *bus_name;
    uint8_t device_endian;
};

typedef struct VirtioDeviceClass {
    /*< private >*/
    DeviceClass parent;
    /*< public >*/

    /* This is what a VirtioDevice must implement */
    DeviceRealize realize;
    DeviceUnrealize unrealize;
    uint32_t (*get_features)(VirtIODevice *vdev, uint32_t requested_features);
    uint32_t (*bad_features)(VirtIODevice *vdev);
    void (*set_features)(VirtIODevice *vdev, uint32_t val);
    void (*get_config)(VirtIODevice *vdev, uint8_t *config);
    void (*set_config)(VirtIODevice *vdev, const uint8_t *config);
    void (*reset)(VirtIODevice *vdev);
    void (*set_status)(VirtIODevice *vdev, uint8_t val);
    /* Test and clear event pending status.
     * Should be called after unmask to avoid losing events.
     * If backend does not support masking,
     * must check in frontend instead.
     */
    bool (*guest_notifier_pending)(VirtIODevice *vdev, int n);
    /* Mask/unmask events from this vq. Any events reported
     * while masked will become pending.
     * If backend does not support masking,
     * must mask in frontend instead.
     */
    void (*guest_notifier_mask)(VirtIODevice *vdev, int n, bool mask);
    void (*save)(VirtIODevice *vdev, QEMUFile *f);
    int (*load)(VirtIODevice *vdev, QEMUFile *f, int version_id);
} VirtioDeviceClass;

void virtio_instance_init_common(Object *proxy_obj, void *data,
                                 size_t vdev_size, const char *vdev_name);

void virtio_init(VirtIODevice *vdev, const char *name,
                         uint16_t device_id, size_t config_size);
void virtio_cleanup(VirtIODevice *vdev);

/* Set the child bus name. */
void virtio_device_set_child_bus_name(VirtIODevice *vdev, char *bus_name);

VirtQueue *virtio_add_queue(VirtIODevice *vdev, int queue_size,
                            void (*handle_output)(VirtIODevice *,
                                                  VirtQueue *));

void virtio_del_queue(VirtIODevice *vdev, int n);

void virtqueue_push(VirtQueue *vq, const VirtQueueElement *elem,
                    unsigned int len);
void virtqueue_flush(VirtQueue *vq, unsigned int count);
void virtqueue_fill(VirtQueue *vq, const VirtQueueElement *elem,
                    unsigned int len, unsigned int idx);

void virtqueue_map_sg(struct iovec *sg, hwaddr *addr,
    size_t num_sg, int is_write);
int virtqueue_pop(VirtQueue *vq, VirtQueueElement *elem);
int virtqueue_avail_bytes(VirtQueue *vq, unsigned int in_bytes,
                          unsigned int out_bytes);
void virtqueue_get_avail_bytes(VirtQueue *vq, unsigned int *in_bytes,
                               unsigned int *out_bytes,
                               unsigned max_in_bytes, unsigned max_out_bytes);

void virtio_notify(VirtIODevice *vdev, VirtQueue *vq);

void virtio_save(VirtIODevice *vdev, QEMUFile *f);

int virtio_load(VirtIODevice *vdev, QEMUFile *f, int version_id);

void virtio_notify_config(VirtIODevice *vdev);

void virtio_queue_set_notification(VirtQueue *vq, int enable);

int virtio_queue_ready(VirtQueue *vq);

int virtio_queue_empty(VirtQueue *vq);

/* Host binding interface.  */

uint32_t virtio_config_readb(VirtIODevice *vdev, uint32_t addr);
uint32_t virtio_config_readw(VirtIODevice *vdev, uint32_t addr);
uint32_t virtio_config_readl(VirtIODevice *vdev, uint32_t addr);
void virtio_config_writeb(VirtIODevice *vdev, uint32_t addr, uint32_t data);
void virtio_config_writew(VirtIODevice *vdev, uint32_t addr, uint32_t data);
void virtio_config_writel(VirtIODevice *vdev, uint32_t addr, uint32_t data);
void virtio_queue_set_addr(VirtIODevice *vdev, int n, hwaddr addr);
hwaddr virtio_queue_get_addr(VirtIODevice *vdev, int n);
void virtio_queue_set_num(VirtIODevice *vdev, int n, int num);
int virtio_queue_get_num(VirtIODevice *vdev, int n);
void virtio_queue_set_align(VirtIODevice *vdev, int n, int align);
void virtio_queue_notify(VirtIODevice *vdev, int n);
uint16_t virtio_queue_vector(VirtIODevice *vdev, int n);
void virtio_queue_set_vector(VirtIODevice *vdev, int n, uint16_t vector);
void virtio_set_status(VirtIODevice *vdev, uint8_t val);
void virtio_reset(void *opaque);
void virtio_update_irq(VirtIODevice *vdev);
int virtio_set_features(VirtIODevice *vdev, uint32_t val);

/* Base devices.  */
typedef struct VirtIOBlkConf VirtIOBlkConf;
struct virtio_net_conf;
typedef struct virtio_serial_conf virtio_serial_conf;
typedef struct VirtIOSCSIConf VirtIOSCSIConf;
typedef struct VirtIORNGConf VirtIORNGConf;

#define DEFINE_VIRTIO_COMMON_FEATURES(_state, _field) \
	DEFINE_PROP_BIT("indirect_desc", _state, _field, \
			VIRTIO_RING_F_INDIRECT_DESC, true), \
	DEFINE_PROP_BIT("event_idx", _state, _field, \
			VIRTIO_RING_F_EVENT_IDX, true)

hwaddr virtio_queue_get_desc_addr(VirtIODevice *vdev, int n);
hwaddr virtio_queue_get_avail_addr(VirtIODevice *vdev, int n);
hwaddr virtio_queue_get_used_addr(VirtIODevice *vdev, int n);
hwaddr virtio_queue_get_ring_addr(VirtIODevice *vdev, int n);
hwaddr virtio_queue_get_desc_size(VirtIODevice *vdev, int n);
hwaddr virtio_queue_get_avail_size(VirtIODevice *vdev, int n);
hwaddr virtio_queue_get_used_size(VirtIODevice *vdev, int n);
hwaddr virtio_queue_get_ring_size(VirtIODevice *vdev, int n);
uint16_t virtio_queue_get_last_avail_idx(VirtIODevice *vdev, int n);
void virtio_queue_set_last_avail_idx(VirtIODevice *vdev, int n, uint16_t idx);
void virtio_queue_invalidate_signalled_used(VirtIODevice *vdev, int n);
VirtQueue *virtio_get_queue(VirtIODevice *vdev, int n);
uint16_t virtio_get_queue_index(VirtQueue *vq);
int virtio_queue_get_id(VirtQueue *vq);
EventNotifier *virtio_queue_get_guest_notifier(VirtQueue *vq);
void virtio_queue_set_guest_notifier_fd_handler(VirtQueue *vq, bool assign,
                                                bool with_irqfd);
EventNotifier *virtio_queue_get_host_notifier(VirtQueue *vq);
void virtio_queue_set_host_notifier_fd_handler(VirtQueue *vq, bool assign,
                                               bool set_handler);
void virtio_queue_notify_vq(VirtQueue *vq);
void virtio_irq(VirtQueue *vq);

static inline void virtio_add_feature(uint32_t *features, unsigned int fbit)
{
    assert(fbit < 32);
    *features |= (1 << fbit);
}

static inline void virtio_clear_feature(uint32_t *features, unsigned int fbit)
{
    assert(fbit < 32);
    *features &= ~(1 << fbit);
}

static inline bool __virtio_has_feature(uint32_t features, unsigned int fbit)
{
    assert(fbit < 32);
    return !!(features & (1 << fbit));
}

static inline bool virtio_has_feature(VirtIODevice *vdev, unsigned int fbit)
{
    return __virtio_has_feature(vdev->guest_features, fbit);
}

static inline bool virtio_is_big_endian(VirtIODevice *vdev)
{
    assert(vdev->device_endian != VIRTIO_DEVICE_ENDIAN_UNKNOWN);
    return vdev->device_endian == VIRTIO_DEVICE_ENDIAN_BIG;
}
#endif
