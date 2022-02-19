/*
 * Virtio SCSI HBA
 *
 * Copyright IBM, Corp. 2010
 *
 * Authors:
 *  Stefan Hajnoczi    <stefanha@linux.vnet.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#ifndef _QEMU_VIRTIO_SCSI_H
#define _QEMU_VIRTIO_SCSI_H

/* Override CDB/sense data size: they are dynamic (guest controlled) in QEMU */
#define VIRTIO_SCSI_CDB_SIZE 0
#define VIRTIO_SCSI_SENSE_SIZE 0
#include "standard-headers/linux/virtio_scsi.h"
#include "hw/virtio/virtio.h"
#include "hw/pci/pci.h"
#include "hw/scsi/scsi.h"
#include "sysemu/iothread.h"
#include "hw/virtio/dataplane/vring.h"

#define TYPE_VIRTIO_SCSI_COMMON "virtio-scsi-common"
#define VIRTIO_SCSI_COMMON(obj) \
        OBJECT_CHECK(VirtIOSCSICommon, (obj), TYPE_VIRTIO_SCSI_COMMON)

#define TYPE_VIRTIO_SCSI "virtio-scsi-device"
#define VIRTIO_SCSI(obj) \
        OBJECT_CHECK(VirtIOSCSI, (obj), TYPE_VIRTIO_SCSI)

#define VIRTIO_SCSI_VQ_SIZE     128
#define VIRTIO_SCSI_MAX_CHANNEL 0
#define VIRTIO_SCSI_MAX_TARGET  255
#define VIRTIO_SCSI_MAX_LUN     16383

typedef struct virtio_scsi_cmd_req VirtIOSCSICmdReq;
typedef struct virtio_scsi_cmd_resp VirtIOSCSICmdResp;
typedef struct virtio_scsi_ctrl_tmf_req VirtIOSCSICtrlTMFReq;
typedef struct virtio_scsi_ctrl_tmf_resp VirtIOSCSICtrlTMFResp;
typedef struct virtio_scsi_ctrl_an_req VirtIOSCSICtrlANReq;
typedef struct virtio_scsi_ctrl_an_resp VirtIOSCSICtrlANResp;
typedef struct virtio_scsi_event VirtIOSCSIEvent;
typedef struct virtio_scsi_config VirtIOSCSIConfig;

struct VirtIOSCSIConf {
    uint32_t num_queues;
    uint32_t max_sectors;
    uint32_t cmd_per_lun;
    char *vhostfd;
    char *wwpn;
    uint32_t boot_tpgt;
    IOThread *iothread;
};

struct VirtIOSCSI;

typedef struct {
    struct VirtIOSCSI *parent;
    Vring vring;
    EventNotifier host_notifier;
    EventNotifier guest_notifier;
} VirtIOSCSIVring;

typedef struct VirtIOSCSICommon {
    VirtIODevice parent_obj;
    VirtIOSCSIConf conf;

    uint32_t sense_size;
    uint32_t cdb_size;
    VirtQueue *ctrl_vq;
    VirtQueue *event_vq;
    VirtQueue **cmd_vqs;
} VirtIOSCSICommon;

typedef struct VirtIOSCSI {
    VirtIOSCSICommon parent_obj;

    SCSIBus bus;
    int resetting;
    bool events_dropped;

    /* Fields for dataplane below */
    AioContext *ctx; /* one iothread per virtio-scsi-pci for now */

    /* Vring is used instead of vq in dataplane code, because of the underlying
     * memory layer thread safety */
    VirtIOSCSIVring *ctrl_vring;
    VirtIOSCSIVring *event_vring;
    VirtIOSCSIVring **cmd_vrings;
    bool dataplane_started;
    bool dataplane_starting;
    bool dataplane_stopping;
    bool dataplane_disabled;
    bool dataplane_fenced;
    Error *blocker;
    Notifier migration_state_notifier;
} VirtIOSCSI;

typedef struct VirtIOSCSIReq {
    VirtIOSCSI *dev;
    VirtQueue *vq;
    QEMUSGList qsgl;
    QEMUIOVector resp_iov;

    /* Note:
     * - fields before elem are initialized by virtio_scsi_init_req;
     * - elem is uninitialized at the time of allocation.
     * - fields after elem are zeroed by virtio_scsi_init_req.
     * */

    VirtQueueElement elem;
    /* Set by dataplane code. */
    VirtIOSCSIVring *vring;

    union {
        /* Used for two-stage request submission */
        QTAILQ_ENTRY(VirtIOSCSIReq) next;

        /* Used for cancellation of request during TMFs */
        int remaining;
    };

    SCSIRequest *sreq;
    size_t resp_size;
    enum SCSIXferMode mode;
    union {
        VirtIOSCSICmdResp     cmd;
        VirtIOSCSICtrlTMFResp tmf;
        VirtIOSCSICtrlANResp  an;
        VirtIOSCSIEvent       event;
    } resp;
    union {
        VirtIOSCSICmdReq      cmd;
        VirtIOSCSICtrlTMFReq  tmf;
        VirtIOSCSICtrlANReq   an;
    } req;
} VirtIOSCSIReq;

#define DEFINE_VIRTIO_SCSI_PROPERTIES(_state, _conf_field)                     \
    DEFINE_PROP_UINT32("num_queues", _state, _conf_field.num_queues, 1),       \
    DEFINE_PROP_UINT32("max_sectors", _state, _conf_field.max_sectors, 0xFFFF),\
    DEFINE_PROP_UINT32("cmd_per_lun", _state, _conf_field.cmd_per_lun, 128)

#define DEFINE_VIRTIO_SCSI_FEATURES(_state, _feature_field)                    \
    DEFINE_PROP_BIT("any_layout", _state, _feature_field,                      \
                    VIRTIO_F_ANY_LAYOUT, true),                                \
    DEFINE_PROP_BIT("hotplug", _state, _feature_field, VIRTIO_SCSI_F_HOTPLUG,  \
                                                       true),                  \
    DEFINE_PROP_BIT("param_change", _state, _feature_field,                    \
                                            VIRTIO_SCSI_F_CHANGE, true)

typedef void (*HandleOutput)(VirtIODevice *, VirtQueue *);

void virtio_scsi_common_realize(DeviceState *dev, Error **errp,
                                HandleOutput ctrl, HandleOutput evt,
                                HandleOutput cmd);

void virtio_scsi_common_unrealize(DeviceState *dev, Error **errp);
void virtio_scsi_handle_ctrl_req(VirtIOSCSI *s, VirtIOSCSIReq *req);
bool virtio_scsi_handle_cmd_req_prepare(VirtIOSCSI *s, VirtIOSCSIReq *req);
void virtio_scsi_handle_cmd_req_submit(VirtIOSCSI *s, VirtIOSCSIReq *req);
VirtIOSCSIReq *virtio_scsi_init_req(VirtIOSCSI *s, VirtQueue *vq);
void virtio_scsi_free_req(VirtIOSCSIReq *req);
void virtio_scsi_push_event(VirtIOSCSI *s, SCSIDevice *dev,
                            uint32_t event, uint32_t reason);

void virtio_scsi_set_iothread(VirtIOSCSI *s, IOThread *iothread);
void virtio_scsi_dataplane_start(VirtIOSCSI *s);
void virtio_scsi_dataplane_stop(VirtIOSCSI *s);
void virtio_scsi_vring_push_notify(VirtIOSCSIReq *req);
VirtIOSCSIReq *virtio_scsi_pop_req_vring(VirtIOSCSI *s,
                                         VirtIOSCSIVring *vring);

#endif /* _QEMU_VIRTIO_SCSI_H */
