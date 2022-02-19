/*
 * Virtio SCSI HBA
 *
 * Copyright IBM, Corp. 2010
 * Copyright Red Hat, Inc. 2011
 *
 * Authors:
 *   Stefan Hajnoczi    <stefanha@linux.vnet.ibm.com>
 *   Paolo Bonzini      <pbonzini@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "standard-headers/linux/virtio_ids.h"
#include "hw/virtio/virtio-scsi.h"
#include "qemu/error-report.h"
#include "qemu/iov.h"
#include "sysemu/block-backend.h"
#include <hw/scsi/scsi.h>
#include <block/scsi.h>
#include <hw/virtio/virtio-bus.h>
#include "hw/virtio/virtio-access.h"
#include "migration/migration.h"

static inline int virtio_scsi_get_lun(uint8_t *lun)
{
    return ((lun[2] << 8) | lun[3]) & 0x3FFF;
}

static inline SCSIDevice *virtio_scsi_device_find(VirtIOSCSI *s, uint8_t *lun)
{
    if (lun[0] != 1) {
        return NULL;
    }
    if (lun[2] != 0 && !(lun[2] >= 0x40 && lun[2] < 0x80)) {
        return NULL;
    }
    return scsi_device_find(&s->bus, 0, lun[1], virtio_scsi_get_lun(lun));
}

VirtIOSCSIReq *virtio_scsi_init_req(VirtIOSCSI *s, VirtQueue *vq)
{
    VirtIOSCSIReq *req;
    VirtIOSCSICommon *vs = (VirtIOSCSICommon *)s;
    const size_t zero_skip = offsetof(VirtIOSCSIReq, elem)
                             + sizeof(VirtQueueElement);

    req = g_slice_alloc(sizeof(*req) + vs->cdb_size);
    req->vq = vq;
    req->dev = s;
    qemu_sglist_init(&req->qsgl, DEVICE(s), 8, &address_space_memory);
    qemu_iovec_init(&req->resp_iov, 1);
    memset((uint8_t *)req + zero_skip, 0, sizeof(*req) - zero_skip);
    return req;
}

void virtio_scsi_free_req(VirtIOSCSIReq *req)
{
    VirtIOSCSICommon *vs = (VirtIOSCSICommon *)req->dev;

    qemu_iovec_destroy(&req->resp_iov);
    qemu_sglist_destroy(&req->qsgl);
    g_slice_free1(sizeof(*req) + vs->cdb_size, req);
}

static void virtio_scsi_complete_req(VirtIOSCSIReq *req)
{
    VirtIOSCSI *s = req->dev;
    VirtQueue *vq = req->vq;
    VirtIODevice *vdev = VIRTIO_DEVICE(s);

    qemu_iovec_from_buf(&req->resp_iov, 0, &req->resp, req->resp_size);
    if (req->vring) {
        assert(req->vq == NULL);
        virtio_scsi_vring_push_notify(req);
    } else {
        virtqueue_push(vq, &req->elem, req->qsgl.size + req->resp_iov.size);
        virtio_notify(vdev, vq);
    }

    if (req->sreq) {
        req->sreq->hba_private = NULL;
        scsi_req_unref(req->sreq);
    }
    virtio_scsi_free_req(req);
}

static void virtio_scsi_bad_req(void)
{
    error_report("wrong size for virtio-scsi headers");
    exit(1);
}

static size_t qemu_sgl_concat(VirtIOSCSIReq *req, struct iovec *iov,
                              hwaddr *addr, int num, size_t skip)
{
    QEMUSGList *qsgl = &req->qsgl;
    size_t copied = 0;

    while (num) {
        if (skip >= iov->iov_len) {
            skip -= iov->iov_len;
        } else {
            qemu_sglist_add(qsgl, *addr + skip, iov->iov_len - skip);
            copied += iov->iov_len - skip;
            skip = 0;
        }
        iov++;
        addr++;
        num--;
    }

    assert(skip == 0);
    return copied;
}

static int virtio_scsi_parse_req(VirtIOSCSIReq *req,
                                 unsigned req_size, unsigned resp_size)
{
    VirtIODevice *vdev = (VirtIODevice *) req->dev;
    size_t in_size, out_size;

    if (iov_to_buf(req->elem.out_sg, req->elem.out_num, 0,
                   &req->req, req_size) < req_size) {
        return -EINVAL;
    }

    if (qemu_iovec_concat_iov(&req->resp_iov,
                              req->elem.in_sg, req->elem.in_num, 0,
                              resp_size) < resp_size) {
        return -EINVAL;
    }

    req->resp_size = resp_size;

    /* Old BIOSes left some padding by mistake after the req_size/resp_size.
     * As a workaround, always consider the first buffer as the virtio-scsi
     * request/response, making the payload start at the second element
     * of the iovec.
     *
     * The actual length of the response header, stored in req->resp_size,
     * does not change.
     *
     * TODO: always disable this workaround for virtio 1.0 devices.
     */
    if (!virtio_has_feature(vdev, VIRTIO_F_ANY_LAYOUT)) {
        if (req->elem.out_num) {
            req_size = req->elem.out_sg[0].iov_len;
        }
        if (req->elem.in_num) {
            resp_size = req->elem.in_sg[0].iov_len;
        }
    }

    out_size = qemu_sgl_concat(req, req->elem.out_sg,
                               &req->elem.out_addr[0], req->elem.out_num,
                               req_size);
    in_size = qemu_sgl_concat(req, req->elem.in_sg,
                              &req->elem.in_addr[0], req->elem.in_num,
                              resp_size);

    if (out_size && in_size) {
        return -ENOTSUP;
    }

    if (out_size) {
        req->mode = SCSI_XFER_TO_DEV;
    } else if (in_size) {
        req->mode = SCSI_XFER_FROM_DEV;
    }

    return 0;
}

static VirtIOSCSIReq *virtio_scsi_pop_req(VirtIOSCSI *s, VirtQueue *vq)
{
    VirtIOSCSIReq *req = virtio_scsi_init_req(s, vq);
    if (!virtqueue_pop(vq, &req->elem)) {
        virtio_scsi_free_req(req);
        return NULL;
    }
    return req;
}

static void virtio_scsi_save_request(QEMUFile *f, SCSIRequest *sreq)
{
    VirtIOSCSIReq *req = sreq->hba_private;
    VirtIOSCSICommon *vs = VIRTIO_SCSI_COMMON(req->dev);
    uint32_t n = virtio_queue_get_id(req->vq) - 2;

    assert(n < vs->conf.num_queues);
    qemu_put_be32s(f, &n);
    qemu_put_buffer(f, (unsigned char *)&req->elem, sizeof(req->elem));
}

static void *virtio_scsi_load_request(QEMUFile *f, SCSIRequest *sreq)
{
    SCSIBus *bus = sreq->bus;
    VirtIOSCSI *s = container_of(bus, VirtIOSCSI, bus);
    VirtIOSCSICommon *vs = VIRTIO_SCSI_COMMON(s);
    VirtIOSCSIReq *req;
    uint32_t n;

    qemu_get_be32s(f, &n);
    assert(n < vs->conf.num_queues);
    req = virtio_scsi_init_req(s, vs->cmd_vqs[n]);
    qemu_get_buffer(f, (unsigned char *)&req->elem, sizeof(req->elem));
    /* TODO: add a way for SCSIBusInfo's load_request to fail,
     * and fail migration instead of asserting here.
     * When we do, we might be able to re-enable NDEBUG below.
     */
#ifdef NDEBUG
#error building with NDEBUG is not supported
#endif
    assert(req->elem.in_num <= ARRAY_SIZE(req->elem.in_sg));
    assert(req->elem.out_num <= ARRAY_SIZE(req->elem.out_sg));

    if (virtio_scsi_parse_req(req, sizeof(VirtIOSCSICmdReq) + vs->cdb_size,
                              sizeof(VirtIOSCSICmdResp) + vs->sense_size) < 0) {
        error_report("invalid SCSI request migration data");
        exit(1);
    }

    scsi_req_ref(sreq);
    req->sreq = sreq;
    if (req->sreq->cmd.mode != SCSI_XFER_NONE) {
        assert(req->sreq->cmd.mode == req->mode);
    }
    return req;
}

typedef struct {
    Notifier        notifier;
    VirtIOSCSIReq  *tmf_req;
} VirtIOSCSICancelNotifier;

static void virtio_scsi_cancel_notify(Notifier *notifier, void *data)
{
    VirtIOSCSICancelNotifier *n = container_of(notifier,
                                               VirtIOSCSICancelNotifier,
                                               notifier);

    if (--n->tmf_req->remaining == 0) {
        virtio_scsi_complete_req(n->tmf_req);
    }
    g_slice_free(VirtIOSCSICancelNotifier, n);
}

/* Return 0 if the request is ready to be completed and return to guest;
 * -EINPROGRESS if the request is submitted and will be completed later, in the
 *  case of async cancellation. */
static int virtio_scsi_do_tmf(VirtIOSCSI *s, VirtIOSCSIReq *req)
{
    SCSIDevice *d = virtio_scsi_device_find(s, req->req.tmf.lun);
    SCSIRequest *r, *next;
    BusChild *kid;
    int target;
    int ret = 0;

    if (s->dataplane_started) {
        assert(blk_get_aio_context(d->conf.blk) == s->ctx);
    }
    /* Here VIRTIO_SCSI_S_OK means "FUNCTION COMPLETE".  */
    req->resp.tmf.response = VIRTIO_SCSI_S_OK;

    virtio_tswap32s(VIRTIO_DEVICE(s), &req->req.tmf.subtype);
    switch (req->req.tmf.subtype) {
    case VIRTIO_SCSI_T_TMF_ABORT_TASK:
    case VIRTIO_SCSI_T_TMF_QUERY_TASK:
        if (!d) {
            goto fail;
        }
        if (d->lun != virtio_scsi_get_lun(req->req.tmf.lun)) {
            goto incorrect_lun;
        }
        QTAILQ_FOREACH_SAFE(r, &d->requests, next, next) {
            VirtIOSCSIReq *cmd_req = r->hba_private;
            if (cmd_req && cmd_req->req.cmd.tag == req->req.tmf.tag) {
                break;
            }
        }
        if (r) {
            /*
             * Assert that the request has not been completed yet, we
             * check for it in the loop above.
             */
            assert(r->hba_private);
            if (req->req.tmf.subtype == VIRTIO_SCSI_T_TMF_QUERY_TASK) {
                /* "If the specified command is present in the task set, then
                 * return a service response set to FUNCTION SUCCEEDED".
                 */
                req->resp.tmf.response = VIRTIO_SCSI_S_FUNCTION_SUCCEEDED;
            } else {
                VirtIOSCSICancelNotifier *notifier;

                req->remaining = 1;
                notifier = g_slice_new(VirtIOSCSICancelNotifier);
                notifier->tmf_req = req;
                notifier->notifier.notify = virtio_scsi_cancel_notify;
                scsi_req_cancel_async(r, &notifier->notifier);
                ret = -EINPROGRESS;
            }
        }
        break;

    case VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET:
        if (!d) {
            goto fail;
        }
        if (d->lun != virtio_scsi_get_lun(req->req.tmf.lun)) {
            goto incorrect_lun;
        }
        s->resetting++;
        qdev_reset_all(&d->qdev);
        s->resetting--;
        break;

    case VIRTIO_SCSI_T_TMF_ABORT_TASK_SET:
    case VIRTIO_SCSI_T_TMF_CLEAR_TASK_SET:
    case VIRTIO_SCSI_T_TMF_QUERY_TASK_SET:
        if (!d) {
            goto fail;
        }
        if (d->lun != virtio_scsi_get_lun(req->req.tmf.lun)) {
            goto incorrect_lun;
        }

        /* Add 1 to "remaining" until virtio_scsi_do_tmf returns.
         * This way, if the bus starts calling back to the notifiers
         * even before we finish the loop, virtio_scsi_cancel_notify
         * will not complete the TMF too early.
         */
        req->remaining = 1;
        QTAILQ_FOREACH_SAFE(r, &d->requests, next, next) {
            if (r->hba_private) {
                if (req->req.tmf.subtype == VIRTIO_SCSI_T_TMF_QUERY_TASK_SET) {
                    /* "If there is any command present in the task set, then
                     * return a service response set to FUNCTION SUCCEEDED".
                     */
                    req->resp.tmf.response = VIRTIO_SCSI_S_FUNCTION_SUCCEEDED;
                    break;
                } else {
                    VirtIOSCSICancelNotifier *notifier;

                    req->remaining++;
                    notifier = g_slice_new(VirtIOSCSICancelNotifier);
                    notifier->notifier.notify = virtio_scsi_cancel_notify;
                    notifier->tmf_req = req;
                    scsi_req_cancel_async(r, &notifier->notifier);
                }
            }
        }
        if (--req->remaining > 0) {
            ret = -EINPROGRESS;
        }
        break;

    case VIRTIO_SCSI_T_TMF_I_T_NEXUS_RESET:
        target = req->req.tmf.lun[1];
        s->resetting++;
        QTAILQ_FOREACH(kid, &s->bus.qbus.children, sibling) {
             d = DO_UPCAST(SCSIDevice, qdev, kid->child);
             if (d->channel == 0 && d->id == target) {
                qdev_reset_all(&d->qdev);
             }
        }
        s->resetting--;
        break;

    case VIRTIO_SCSI_T_TMF_CLEAR_ACA:
    default:
        req->resp.tmf.response = VIRTIO_SCSI_S_FUNCTION_REJECTED;
        break;
    }

    return ret;

incorrect_lun:
    req->resp.tmf.response = VIRTIO_SCSI_S_INCORRECT_LUN;
    return ret;

fail:
    req->resp.tmf.response = VIRTIO_SCSI_S_BAD_TARGET;
    return ret;
}

void virtio_scsi_handle_ctrl_req(VirtIOSCSI *s, VirtIOSCSIReq *req)
{
    VirtIODevice *vdev = (VirtIODevice *)s;
    uint32_t type;
    int r = 0;

    if (iov_to_buf(req->elem.out_sg, req->elem.out_num, 0,
                &type, sizeof(type)) < sizeof(type)) {
        virtio_scsi_bad_req();
        return;
    }

    virtio_tswap32s(vdev, &type);
    if (type == VIRTIO_SCSI_T_TMF) {
        if (virtio_scsi_parse_req(req, sizeof(VirtIOSCSICtrlTMFReq),
                    sizeof(VirtIOSCSICtrlTMFResp)) < 0) {
            virtio_scsi_bad_req();
        } else {
            r = virtio_scsi_do_tmf(s, req);
        }

    } else if (type == VIRTIO_SCSI_T_AN_QUERY ||
               type == VIRTIO_SCSI_T_AN_SUBSCRIBE) {
        if (virtio_scsi_parse_req(req, sizeof(VirtIOSCSICtrlANReq),
                    sizeof(VirtIOSCSICtrlANResp)) < 0) {
            virtio_scsi_bad_req();
        } else {
            req->resp.an.event_actual = 0;
            req->resp.an.response = VIRTIO_SCSI_S_OK;
        }
    }
    if (r == 0) {
        virtio_scsi_complete_req(req);
    } else {
        assert(r == -EINPROGRESS);
    }
}

static void virtio_scsi_handle_ctrl(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOSCSI *s = (VirtIOSCSI *)vdev;
    VirtIOSCSIReq *req;

    if (s->ctx && !s->dataplane_disabled) {
        virtio_scsi_dataplane_start(s);
        return;
    }
    while ((req = virtio_scsi_pop_req(s, vq))) {
        virtio_scsi_handle_ctrl_req(s, req);
    }
}

static void virtio_scsi_complete_cmd_req(VirtIOSCSIReq *req)
{
    /* Sense data is not in req->resp and is copied separately
     * in virtio_scsi_command_complete.
     */
    req->resp_size = sizeof(VirtIOSCSICmdResp);
    virtio_scsi_complete_req(req);
}

static void virtio_scsi_command_complete(SCSIRequest *r, uint32_t status,
                                         size_t resid)
{
    VirtIOSCSIReq *req = r->hba_private;
    uint8_t sense[SCSI_SENSE_BUF_SIZE];
    uint32_t sense_len;
    VirtIODevice *vdev = VIRTIO_DEVICE(req->dev);

    if (r->io_canceled) {
        return;
    }

    req->resp.cmd.response = VIRTIO_SCSI_S_OK;
    req->resp.cmd.status = status;
    if (req->resp.cmd.status == GOOD) {
        req->resp.cmd.resid = virtio_tswap32(vdev, resid);
    } else {
        req->resp.cmd.resid = 0;
        sense_len = scsi_req_get_sense(r, sense, sizeof(sense));
        sense_len = MIN(sense_len, req->resp_iov.size - sizeof(req->resp.cmd));
        qemu_iovec_from_buf(&req->resp_iov, sizeof(req->resp.cmd),
                            sense, sense_len);
        req->resp.cmd.sense_len = virtio_tswap32(vdev, sense_len);
    }
    virtio_scsi_complete_cmd_req(req);
}

static int virtio_scsi_parse_cdb(SCSIDevice *dev, SCSICommand *cmd,
                                 uint8_t *buf, void *hba_private)
{
    VirtIOSCSIReq *req = hba_private;

    if (cmd->len == 0) {
        cmd->len = MIN(VIRTIO_SCSI_CDB_DEFAULT_SIZE, SCSI_CMD_BUF_SIZE);
        memcpy(cmd->buf, buf, cmd->len);
    }

    /* Extract the direction and mode directly from the request, for
     * host device passthrough.
     */
    cmd->xfer = req->qsgl.size;
    cmd->mode = req->mode;
    return 0;
}

static QEMUSGList *virtio_scsi_get_sg_list(SCSIRequest *r)
{
    VirtIOSCSIReq *req = r->hba_private;

    return &req->qsgl;
}

static void virtio_scsi_request_cancelled(SCSIRequest *r)
{
    VirtIOSCSIReq *req = r->hba_private;

    if (!req) {
        return;
    }
    if (req->dev->resetting) {
        req->resp.cmd.response = VIRTIO_SCSI_S_RESET;
    } else {
        req->resp.cmd.response = VIRTIO_SCSI_S_ABORTED;
    }
    virtio_scsi_complete_cmd_req(req);
}

static void virtio_scsi_fail_cmd_req(VirtIOSCSIReq *req)
{
    req->resp.cmd.response = VIRTIO_SCSI_S_FAILURE;
    virtio_scsi_complete_cmd_req(req);
}

bool virtio_scsi_handle_cmd_req_prepare(VirtIOSCSI *s, VirtIOSCSIReq *req)
{
    VirtIOSCSICommon *vs = &s->parent_obj;
    SCSIDevice *d;
    int rc;

    rc = virtio_scsi_parse_req(req, sizeof(VirtIOSCSICmdReq) + vs->cdb_size,
                               sizeof(VirtIOSCSICmdResp) + vs->sense_size);
    if (rc < 0) {
        if (rc == -ENOTSUP) {
            virtio_scsi_fail_cmd_req(req);
        } else {
            virtio_scsi_bad_req();
        }
        return false;
    }

    d = virtio_scsi_device_find(s, req->req.cmd.lun);
    if (!d) {
        req->resp.cmd.response = VIRTIO_SCSI_S_BAD_TARGET;
        virtio_scsi_complete_cmd_req(req);
        return false;
    }
    if (s->dataplane_started) {
        assert(blk_get_aio_context(d->conf.blk) == s->ctx);
    }
    req->sreq = scsi_req_new(d, req->req.cmd.tag,
                             virtio_scsi_get_lun(req->req.cmd.lun),
                             req->req.cmd.cdb, req);

    if (req->sreq->cmd.mode != SCSI_XFER_NONE
        && (req->sreq->cmd.mode != req->mode ||
            req->sreq->cmd.xfer > req->qsgl.size)) {
        req->resp.cmd.response = VIRTIO_SCSI_S_OVERRUN;
        virtio_scsi_complete_cmd_req(req);
        return false;
    }
    scsi_req_ref(req->sreq);
    blk_io_plug(d->conf.blk);
    return true;
}

void virtio_scsi_handle_cmd_req_submit(VirtIOSCSI *s, VirtIOSCSIReq *req)
{
    SCSIRequest *sreq = req->sreq;
    if (scsi_req_enqueue(sreq)) {
        scsi_req_continue(sreq);
    }
    blk_io_unplug(sreq->dev->conf.blk);
    scsi_req_unref(sreq);
}

static void virtio_scsi_handle_cmd(VirtIODevice *vdev, VirtQueue *vq)
{
    /* use non-QOM casts in the data path */
    VirtIOSCSI *s = (VirtIOSCSI *)vdev;
    VirtIOSCSIReq *req, *next;
    QTAILQ_HEAD(, VirtIOSCSIReq) reqs = QTAILQ_HEAD_INITIALIZER(reqs);

    if (s->ctx && !s->dataplane_disabled) {
        virtio_scsi_dataplane_start(s);
        return;
    }
    while ((req = virtio_scsi_pop_req(s, vq))) {
        if (virtio_scsi_handle_cmd_req_prepare(s, req)) {
            QTAILQ_INSERT_TAIL(&reqs, req, next);
        }
    }

    QTAILQ_FOREACH_SAFE(req, &reqs, next, next) {
        virtio_scsi_handle_cmd_req_submit(s, req);
    }
}

static void virtio_scsi_get_config(VirtIODevice *vdev,
                                   uint8_t *config)
{
    VirtIOSCSIConfig *scsiconf = (VirtIOSCSIConfig *)config;
    VirtIOSCSICommon *s = VIRTIO_SCSI_COMMON(vdev);

    virtio_stl_p(vdev, &scsiconf->num_queues, s->conf.num_queues);
    virtio_stl_p(vdev, &scsiconf->seg_max, 128 - 2);
    virtio_stl_p(vdev, &scsiconf->max_sectors, s->conf.max_sectors);
    virtio_stl_p(vdev, &scsiconf->cmd_per_lun, s->conf.cmd_per_lun);
    virtio_stl_p(vdev, &scsiconf->event_info_size, sizeof(VirtIOSCSIEvent));
    virtio_stl_p(vdev, &scsiconf->sense_size, s->sense_size);
    virtio_stl_p(vdev, &scsiconf->cdb_size, s->cdb_size);
    virtio_stw_p(vdev, &scsiconf->max_channel, VIRTIO_SCSI_MAX_CHANNEL);
    virtio_stw_p(vdev, &scsiconf->max_target, VIRTIO_SCSI_MAX_TARGET);
    virtio_stl_p(vdev, &scsiconf->max_lun, VIRTIO_SCSI_MAX_LUN);
}

static void virtio_scsi_set_config(VirtIODevice *vdev,
                                   const uint8_t *config)
{
    VirtIOSCSIConfig *scsiconf = (VirtIOSCSIConfig *)config;
    VirtIOSCSICommon *vs = VIRTIO_SCSI_COMMON(vdev);

    if ((uint32_t) virtio_ldl_p(vdev, &scsiconf->sense_size) >= 65536 ||
        (uint32_t) virtio_ldl_p(vdev, &scsiconf->cdb_size) >= 256) {
        error_report("bad data written to virtio-scsi configuration space");
        exit(1);
    }

    vs->sense_size = virtio_ldl_p(vdev, &scsiconf->sense_size);
    vs->cdb_size = virtio_ldl_p(vdev, &scsiconf->cdb_size);
}

static uint32_t virtio_scsi_get_features(VirtIODevice *vdev,
                                         uint32_t requested_features)
{
    return requested_features;
}

static void virtio_scsi_reset(VirtIODevice *vdev)
{
    VirtIOSCSI *s = VIRTIO_SCSI(vdev);
    VirtIOSCSICommon *vs = VIRTIO_SCSI_COMMON(vdev);

    if (s->ctx) {
        virtio_scsi_dataplane_stop(s);
    }
    s->resetting++;
    qbus_reset_all(&s->bus.qbus);
    s->resetting--;

    vs->sense_size = VIRTIO_SCSI_SENSE_DEFAULT_SIZE;
    vs->cdb_size = VIRTIO_SCSI_CDB_DEFAULT_SIZE;
    s->events_dropped = false;
}

/* The device does not have anything to save beyond the virtio data.
 * Request data is saved with callbacks from SCSI devices.
 */
static void virtio_scsi_save(QEMUFile *f, void *opaque)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(opaque);
    virtio_save(vdev, f);
}

static int virtio_scsi_load(QEMUFile *f, void *opaque, int version_id)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(opaque);
    int ret;

    ret = virtio_load(vdev, f, version_id);
    if (ret) {
        return ret;
    }
    return 0;
}

void virtio_scsi_push_event(VirtIOSCSI *s, SCSIDevice *dev,
                            uint32_t event, uint32_t reason)
{
    VirtIOSCSICommon *vs = VIRTIO_SCSI_COMMON(s);
    VirtIOSCSIReq *req;
    VirtIOSCSIEvent *evt;
    VirtIODevice *vdev = VIRTIO_DEVICE(s);

    if (!(vdev->status & VIRTIO_CONFIG_S_DRIVER_OK)) {
        return;
    }

    if (s->dataplane_started) {
        assert(s->ctx);
        aio_context_acquire(s->ctx);
    }

    if (s->dataplane_started) {
        req = virtio_scsi_pop_req_vring(s, s->event_vring);
    } else {
        req = virtio_scsi_pop_req(s, vs->event_vq);
    }
    if (!req) {
        s->events_dropped = true;
        goto out;
    }

    if (s->events_dropped) {
        event |= VIRTIO_SCSI_T_EVENTS_MISSED;
        s->events_dropped = false;
    }

    if (virtio_scsi_parse_req(req, 0, sizeof(VirtIOSCSIEvent))) {
        virtio_scsi_bad_req();
    }

    evt = &req->resp.event;
    memset(evt, 0, sizeof(VirtIOSCSIEvent));
    evt->event = virtio_tswap32(vdev, event);
    evt->reason = virtio_tswap32(vdev, reason);
    if (!dev) {
        assert(event == VIRTIO_SCSI_T_EVENTS_MISSED);
    } else {
        evt->lun[0] = 1;
        evt->lun[1] = dev->id;

        /* Linux wants us to keep the same encoding we use for REPORT LUNS.  */
        if (dev->lun >= 256) {
            evt->lun[2] = (dev->lun >> 8) | 0x40;
        }
        evt->lun[3] = dev->lun & 0xFF;
    }
    virtio_scsi_complete_req(req);
out:
    if (s->dataplane_started) {
        aio_context_release(s->ctx);
    }
}

static void virtio_scsi_handle_event(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOSCSI *s = VIRTIO_SCSI(vdev);

    if (s->ctx && !s->dataplane_disabled) {
        virtio_scsi_dataplane_start(s);
        return;
    }
    if (s->events_dropped) {
        virtio_scsi_push_event(s, NULL, VIRTIO_SCSI_T_NO_EVENT, 0);
    }
}

static void virtio_scsi_change(SCSIBus *bus, SCSIDevice *dev, SCSISense sense)
{
    VirtIOSCSI *s = container_of(bus, VirtIOSCSI, bus);
    VirtIODevice *vdev = VIRTIO_DEVICE(s);

    if (virtio_has_feature(vdev, VIRTIO_SCSI_F_CHANGE) &&
        dev->type != TYPE_ROM) {
        virtio_scsi_push_event(s, dev, VIRTIO_SCSI_T_PARAM_CHANGE,
                               sense.asc | (sense.ascq << 8));
    }
}

static void virtio_scsi_hotplug(HotplugHandler *hotplug_dev, DeviceState *dev,
                                Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(hotplug_dev);
    VirtIOSCSI *s = VIRTIO_SCSI(vdev);
    SCSIDevice *sd = SCSI_DEVICE(dev);

    if (s->ctx && !s->dataplane_disabled) {
        if (blk_op_is_blocked(sd->conf.blk, BLOCK_OP_TYPE_DATAPLANE, errp)) {
            return;
        }
        blk_op_block_all(sd->conf.blk, s->blocker);
        aio_context_acquire(s->ctx);
        blk_set_aio_context(sd->conf.blk, s->ctx);
        aio_context_release(s->ctx);
    }

    if (virtio_has_feature(vdev, VIRTIO_SCSI_F_HOTPLUG)) {
        virtio_scsi_push_event(s, sd,
                               VIRTIO_SCSI_T_TRANSPORT_RESET,
                               VIRTIO_SCSI_EVT_RESET_RESCAN);
    }
}

static void virtio_scsi_hotunplug(HotplugHandler *hotplug_dev, DeviceState *dev,
                                  Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(hotplug_dev);
    VirtIOSCSI *s = VIRTIO_SCSI(vdev);
    SCSIDevice *sd = SCSI_DEVICE(dev);

    if (virtio_has_feature(vdev, VIRTIO_SCSI_F_HOTPLUG)) {
        virtio_scsi_push_event(s, sd,
                               VIRTIO_SCSI_T_TRANSPORT_RESET,
                               VIRTIO_SCSI_EVT_RESET_REMOVED);
    }

    if (s->ctx) {
        blk_op_unblock_all(sd->conf.blk, s->blocker);
    }
    qdev_simple_device_unplug_cb(hotplug_dev, dev, errp);
}

static struct SCSIBusInfo virtio_scsi_scsi_info = {
    .tcq = true,
    .max_channel = VIRTIO_SCSI_MAX_CHANNEL,
    .max_target = VIRTIO_SCSI_MAX_TARGET,
    .max_lun = VIRTIO_SCSI_MAX_LUN,

    .complete = virtio_scsi_command_complete,
    .cancel = virtio_scsi_request_cancelled,
    .change = virtio_scsi_change,
    .parse_cdb = virtio_scsi_parse_cdb,
    .get_sg_list = virtio_scsi_get_sg_list,
    .save_request = virtio_scsi_save_request,
    .load_request = virtio_scsi_load_request,
};

void virtio_scsi_common_realize(DeviceState *dev, Error **errp,
                                HandleOutput ctrl, HandleOutput evt,
                                HandleOutput cmd)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOSCSICommon *s = VIRTIO_SCSI_COMMON(dev);
    int i;

    virtio_init(vdev, "virtio-scsi", VIRTIO_ID_SCSI,
                sizeof(VirtIOSCSIConfig));

    if (s->conf.num_queues == 0 ||
            s->conf.num_queues > VIRTIO_PCI_QUEUE_MAX - 2) {
        error_setg(errp, "Invalid number of queues (= %" PRIu32 "), "
                         "must be a positive integer less than %d.",
                   s->conf.num_queues, VIRTIO_PCI_QUEUE_MAX - 2);
        virtio_cleanup(vdev);
        return;
    }
    s->cmd_vqs = g_new0(VirtQueue *, s->conf.num_queues);
    s->sense_size = VIRTIO_SCSI_SENSE_DEFAULT_SIZE;
    s->cdb_size = VIRTIO_SCSI_CDB_DEFAULT_SIZE;

    s->ctrl_vq = virtio_add_queue(vdev, VIRTIO_SCSI_VQ_SIZE,
                                  ctrl);
    s->event_vq = virtio_add_queue(vdev, VIRTIO_SCSI_VQ_SIZE,
                                   evt);
    for (i = 0; i < s->conf.num_queues; i++) {
        s->cmd_vqs[i] = virtio_add_queue(vdev, VIRTIO_SCSI_VQ_SIZE,
                                         cmd);
    }

    if (s->conf.iothread) {
        virtio_scsi_set_iothread(VIRTIO_SCSI(s), s->conf.iothread);
    }
}

/* Disable dataplane thread during live migration since it does not
 * update the dirty memory bitmap yet.
 */
static void virtio_scsi_migration_state_changed(Notifier *notifier, void *data)
{
    VirtIOSCSI *s = container_of(notifier, VirtIOSCSI,
                                 migration_state_notifier);
    MigrationState *mig = data;

    if (migration_in_setup(mig)) {
        if (!s->dataplane_started) {
            return;
        }
        virtio_scsi_dataplane_stop(s);
        s->dataplane_disabled = true;
    } else if (migration_has_finished(mig) ||
               migration_has_failed(mig)) {
        if (s->dataplane_started) {
            return;
        }
        blk_drain_all(); /* complete in-flight non-dataplane requests */
        s->dataplane_disabled = false;
    }
}

static void virtio_scsi_device_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOSCSI *s = VIRTIO_SCSI(dev);
    static int virtio_scsi_id;
    Error *err = NULL;

    virtio_scsi_common_realize(dev, &err, virtio_scsi_handle_ctrl,
                               virtio_scsi_handle_event,
                               virtio_scsi_handle_cmd);
    if (err != NULL) {
        error_propagate(errp, err);
        return;
    }

    scsi_bus_new(&s->bus, sizeof(s->bus), dev,
                 &virtio_scsi_scsi_info, vdev->bus_name);
    /* override default SCSI bus hotplug-handler, with virtio-scsi's one */
    qbus_set_hotplug_handler(BUS(&s->bus), dev, &error_abort);

    if (!dev->hotplugged) {
        scsi_bus_legacy_handle_cmdline(&s->bus, &err);
        if (err != NULL) {
            error_propagate(errp, err);
            return;
        }
    }

    register_savevm(dev, "virtio-scsi", virtio_scsi_id++, 1,
                    virtio_scsi_save, virtio_scsi_load, s);
    s->migration_state_notifier.notify = virtio_scsi_migration_state_changed;
    add_migration_state_change_notifier(&s->migration_state_notifier);

    error_setg(&s->blocker, "block device is in use by data plane");
}

static void virtio_scsi_instance_init(Object *obj)
{
    VirtIOSCSICommon *vs = VIRTIO_SCSI_COMMON(obj);

    object_property_add_link(obj, "iothread", TYPE_IOTHREAD,
                             (Object **)&vs->conf.iothread,
                             qdev_prop_allow_set_link_before_realize,
                             OBJ_PROP_LINK_UNREF_ON_RELEASE, &error_abort);
}

void virtio_scsi_common_unrealize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOSCSICommon *vs = VIRTIO_SCSI_COMMON(dev);

    g_free(vs->cmd_vqs);
    virtio_cleanup(vdev);
}

static void virtio_scsi_device_unrealize(DeviceState *dev, Error **errp)
{
    VirtIOSCSI *s = VIRTIO_SCSI(dev);

    error_free(s->blocker);

    unregister_savevm(dev, "virtio-scsi", s);
    remove_migration_state_change_notifier(&s->migration_state_notifier);

    virtio_scsi_common_unrealize(dev, errp);
}

static Property virtio_scsi_properties[] = {
    DEFINE_VIRTIO_SCSI_PROPERTIES(VirtIOSCSI, parent_obj.conf),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_scsi_common_class_init(ObjectClass *klass, void *data)
{
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);
    DeviceClass *dc = DEVICE_CLASS(klass);

    vdc->get_config = virtio_scsi_get_config;
    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
}

static void virtio_scsi_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);
    HotplugHandlerClass *hc = HOTPLUG_HANDLER_CLASS(klass);

    dc->props = virtio_scsi_properties;
    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    vdc->realize = virtio_scsi_device_realize;
    vdc->unrealize = virtio_scsi_device_unrealize;
    vdc->set_config = virtio_scsi_set_config;
    vdc->get_features = virtio_scsi_get_features;
    vdc->reset = virtio_scsi_reset;
    hc->plug = virtio_scsi_hotplug;
    hc->unplug = virtio_scsi_hotunplug;
}

static const TypeInfo virtio_scsi_common_info = {
    .name = TYPE_VIRTIO_SCSI_COMMON,
    .parent = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtIOSCSICommon),
    .abstract = true,
    .class_init = virtio_scsi_common_class_init,
};

static const TypeInfo virtio_scsi_info = {
    .name = TYPE_VIRTIO_SCSI,
    .parent = TYPE_VIRTIO_SCSI_COMMON,
    .instance_size = sizeof(VirtIOSCSI),
    .instance_init = virtio_scsi_instance_init,
    .class_init = virtio_scsi_class_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_HOTPLUG_HANDLER },
        { }
    }
};

static void virtio_register_types(void)
{
    type_register_static(&virtio_scsi_common_info);
    type_register_static(&virtio_scsi_info);
}

type_init(virtio_register_types)
