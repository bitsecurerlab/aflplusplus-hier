/*
 * QEMU host block devices
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 *
 * This file incorporates work covered by the following copyright and
 * permission notice:
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
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

#include "sysemu/block-backend.h"
#include "sysemu/blockdev.h"
#include "hw/block/block.h"
#include "block/blockjob.h"
#include "monitor/monitor.h"
#include "qemu/option.h"
#include "qemu/config-file.h"
#include "qapi/qmp/types.h"
#include "qapi-visit.h"
#include "qapi/qmp-output-visitor.h"
#include "qapi/util.h"
#include "sysemu/sysemu.h"
#include "block/block_int.h"
#include "qmp-commands.h"
#include "trace.h"
#include "sysemu/arch_init.h"

static const char *const if_name[IF_COUNT] = {
    [IF_NONE] = "none",
    [IF_IDE] = "ide",
    [IF_SCSI] = "scsi",
    [IF_FLOPPY] = "floppy",
    [IF_PFLASH] = "pflash",
    [IF_MTD] = "mtd",
    [IF_SD] = "sd",
    [IF_VIRTIO] = "virtio",
    [IF_XEN] = "xen",
};

static int if_max_devs[IF_COUNT] = {
    /*
     * Do not change these numbers!  They govern how drive option
     * index maps to unit and bus.  That mapping is ABI.
     *
     * All controllers used to imlement if=T drives need to support
     * if_max_devs[T] units, for any T with if_max_devs[T] != 0.
     * Otherwise, some index values map to "impossible" bus, unit
     * values.
     *
     * For instance, if you change [IF_SCSI] to 255, -drive
     * if=scsi,index=12 no longer means bus=1,unit=5, but
     * bus=0,unit=12.  With an lsi53c895a controller (7 units max),
     * the drive can't be set up.  Regression.
     */
    [IF_IDE] = 2,
    [IF_SCSI] = 7,
};

/**
 * Boards may call this to offer board-by-board overrides
 * of the default, global values.
 */
void override_max_devs(BlockInterfaceType type, int max_devs)
{
    BlockBackend *blk;
    DriveInfo *dinfo;

    if (max_devs <= 0) {
        return;
    }

    for (blk = blk_next(NULL); blk; blk = blk_next(blk)) {
        dinfo = blk_legacy_dinfo(blk);
        if (dinfo->type == type) {
            fprintf(stderr, "Cannot override units-per-bus property of"
                    " the %s interface, because a drive of that type has"
                    " already been added.\n", if_name[type]);
            g_assert_not_reached();
        }
    }

    if_max_devs[type] = max_devs;
}

/*
 * We automatically delete the drive when a device using it gets
 * unplugged.  Questionable feature, but we can't just drop it.
 * Device models call blockdev_mark_auto_del() to schedule the
 * automatic deletion, and generic qdev code calls blockdev_auto_del()
 * when deletion is actually safe.
 */
void blockdev_mark_auto_del(BlockBackend *blk)
{
    DriveInfo *dinfo = blk_legacy_dinfo(blk);
    BlockDriverState *bs = blk_bs(blk);
    AioContext *aio_context;

    if (!dinfo) {
        return;
    }

    aio_context = bdrv_get_aio_context(bs);
    aio_context_acquire(aio_context);

    if (bs->job) {
        block_job_cancel(bs->job);
    }

    aio_context_release(aio_context);

    dinfo->auto_del = 1;
}

void blockdev_auto_del(BlockBackend *blk)
{
    DriveInfo *dinfo = blk_legacy_dinfo(blk);

    if (dinfo && dinfo->auto_del) {
        blk_unref(blk);
    }
}

/**
 * Returns the current mapping of how many units per bus
 * a particular interface can support.
 *
 *  A positive integer indicates n units per bus.
 *  0 implies the mapping has not been established.
 * -1 indicates an invalid BlockInterfaceType was given.
 */
int drive_get_max_devs(BlockInterfaceType type)
{
    if (type >= IF_IDE && type < IF_COUNT) {
        return if_max_devs[type];
    }

    return -1;
}

static int drive_index_to_bus_id(BlockInterfaceType type, int index)
{
    int max_devs = if_max_devs[type];
    return max_devs ? index / max_devs : 0;
}

static int drive_index_to_unit_id(BlockInterfaceType type, int index)
{
    int max_devs = if_max_devs[type];
    return max_devs ? index % max_devs : index;
}

QemuOpts *drive_def(const char *optstr)
{
    return qemu_opts_parse(qemu_find_opts("drive"), optstr, 0);
}

QemuOpts *drive_add(BlockInterfaceType type, int index, const char *file,
                    const char *optstr)
{
    QemuOpts *opts;

    opts = drive_def(optstr);
    if (!opts) {
        return NULL;
    }
    if (type != IF_DEFAULT) {
        qemu_opt_set(opts, "if", if_name[type], &error_abort);
    }
    if (index >= 0) {
        qemu_opt_set_number(opts, "index", index, &error_abort);
    }
    if (file)
        qemu_opt_set(opts, "file", file, &error_abort);
    return opts;
}

DriveInfo *drive_get(BlockInterfaceType type, int bus, int unit)
{
    BlockBackend *blk;
    DriveInfo *dinfo;

    for (blk = blk_next(NULL); blk; blk = blk_next(blk)) {
        dinfo = blk_legacy_dinfo(blk);
        if (dinfo && dinfo->type == type
            && dinfo->bus == bus && dinfo->unit == unit) {
            return dinfo;
        }
    }

    return NULL;
}

bool drive_check_orphaned(void)
{
    BlockBackend *blk;
    DriveInfo *dinfo;
    bool rs = false;

    for (blk = blk_next(NULL); blk; blk = blk_next(blk)) {
        dinfo = blk_legacy_dinfo(blk);
        /* If dinfo->bdrv->dev is NULL, it has no device attached. */
        /* Unless this is a default drive, this may be an oversight. */
        if (!blk_get_attached_dev(blk) && !dinfo->is_default &&
            dinfo->type != IF_NONE) {
            fprintf(stderr, "Warning: Orphaned drive without device: "
                    "id=%s,file=%s,if=%s,bus=%d,unit=%d\n",
                    blk_name(blk), blk_bs(blk)->filename, if_name[dinfo->type],
                    dinfo->bus, dinfo->unit);
            rs = true;
        }
    }

    return rs;
}

DriveInfo *drive_get_by_index(BlockInterfaceType type, int index)
{
    return drive_get(type,
                     drive_index_to_bus_id(type, index),
                     drive_index_to_unit_id(type, index));
}

int drive_get_max_bus(BlockInterfaceType type)
{
    int max_bus;
    BlockBackend *blk;
    DriveInfo *dinfo;

    max_bus = -1;
    for (blk = blk_next(NULL); blk; blk = blk_next(blk)) {
        dinfo = blk_legacy_dinfo(blk);
        if (dinfo && dinfo->type == type && dinfo->bus > max_bus) {
            max_bus = dinfo->bus;
        }
    }
    return max_bus;
}

/* Get a block device.  This should only be used for single-drive devices
   (e.g. SD/Floppy/MTD).  Multi-disk devices (scsi/ide) should use the
   appropriate bus.  */
DriveInfo *drive_get_next(BlockInterfaceType type)
{
    static int next_block_unit[IF_COUNT];

    return drive_get(type, 0, next_block_unit[type]++);
}

static void bdrv_format_print(void *opaque, const char *name)
{
    error_printf(" %s", name);
}

typedef struct {
    QEMUBH *bh;
    BlockDriverState *bs;
} BDRVPutRefBH;

static void bdrv_put_ref_bh(void *opaque)
{
    BDRVPutRefBH *s = opaque;

    bdrv_unref(s->bs);
    qemu_bh_delete(s->bh);
    g_free(s);
}

/*
 * Release a BDS reference in a BH
 *
 * It is not safe to use bdrv_unref() from a callback function when the callers
 * still need the BlockDriverState.  In such cases we schedule a BH to release
 * the reference.
 */
static void bdrv_put_ref_bh_schedule(BlockDriverState *bs)
{
    BDRVPutRefBH *s;

    s = g_new(BDRVPutRefBH, 1);
    s->bh = qemu_bh_new(bdrv_put_ref_bh, s);
    s->bs = bs;
    qemu_bh_schedule(s->bh);
}

static int parse_block_error_action(const char *buf, bool is_read, Error **errp)
{
    if (!strcmp(buf, "ignore")) {
        return BLOCKDEV_ON_ERROR_IGNORE;
    } else if (!is_read && !strcmp(buf, "enospc")) {
        return BLOCKDEV_ON_ERROR_ENOSPC;
    } else if (!strcmp(buf, "stop")) {
        return BLOCKDEV_ON_ERROR_STOP;
    } else if (!strcmp(buf, "report")) {
        return BLOCKDEV_ON_ERROR_REPORT;
    } else {
        error_setg(errp, "'%s' invalid %s error action",
                   buf, is_read ? "read" : "write");
        return -1;
    }
}

static bool check_throttle_config(ThrottleConfig *cfg, Error **errp)
{
    if (throttle_conflicting(cfg)) {
        error_setg(errp, "bps/iops/max total values and read/write values"
                         " cannot be used at the same time");
        return false;
    }

    if (!throttle_is_valid(cfg)) {
        error_setg(errp, "bps/iops/maxs values must be 0 or greater");
        return false;
    }

    return true;
}

typedef enum { MEDIA_DISK, MEDIA_CDROM } DriveMediaType;

/* Takes the ownership of bs_opts */
static BlockBackend *blockdev_init(const char *file, QDict *bs_opts,
                                   Error **errp)
{
    const char *buf;
    int ro = 0;
    int bdrv_flags = 0;
    int on_read_error, on_write_error;
    BlockBackend *blk;
    BlockDriverState *bs;
    ThrottleConfig cfg;
    int snapshot = 0;
    bool copy_on_read;
    Error *error = NULL;
    QemuOpts *opts;
    const char *id;
    bool has_driver_specific_opts;
    BlockdevDetectZeroesOptions detect_zeroes;

    /* Check common options by copying from bs_opts to opts, all other options
     * stay in bs_opts for processing by bdrv_open(). */
    id = qdict_get_try_str(bs_opts, "id");
    opts = qemu_opts_create(&qemu_common_drive_opts, id, 1, &error);
    if (error) {
        error_propagate(errp, error);
        goto err_no_opts;
    }

    qemu_opts_absorb_qdict(opts, bs_opts, &error);
    if (error) {
        error_propagate(errp, error);
        goto early_err;
    }

    if (id) {
        qdict_del(bs_opts, "id");
    }

    has_driver_specific_opts = !!qdict_size(bs_opts);

    /* extract parameters */
    snapshot = qemu_opt_get_bool(opts, "snapshot", 0);
    ro = qemu_opt_get_bool(opts, "read-only", 0);
    copy_on_read = qemu_opt_get_bool(opts, "copy-on-read", false);

    if ((buf = qemu_opt_get(opts, "discard")) != NULL) {
        if (bdrv_parse_discard_flags(buf, &bdrv_flags) != 0) {
            error_setg(errp, "invalid discard option");
            goto early_err;
        }
    }

    if (qemu_opt_get_bool(opts, "cache.writeback", true)) {
        bdrv_flags |= BDRV_O_CACHE_WB;
    }
    if (qemu_opt_get_bool(opts, "cache.direct", false)) {
        bdrv_flags |= BDRV_O_NOCACHE;
    }
    if (qemu_opt_get_bool(opts, "cache.no-flush", false)) {
        bdrv_flags |= BDRV_O_NO_FLUSH;
    }

#ifdef CONFIG_LINUX_AIO
    if ((buf = qemu_opt_get(opts, "aio")) != NULL) {
        if (!strcmp(buf, "native")) {
            bdrv_flags |= BDRV_O_NATIVE_AIO;
        } else if (!strcmp(buf, "threads")) {
            /* this is the default */
        } else {
           error_setg(errp, "invalid aio option");
           goto early_err;
        }
    }
#endif

    if ((buf = qemu_opt_get(opts, "format")) != NULL) {
        if (is_help_option(buf)) {
            error_printf("Supported formats:");
            bdrv_iterate_format(bdrv_format_print, NULL);
            error_printf("\n");
            goto early_err;
        }

        if (qdict_haskey(bs_opts, "driver")) {
            error_setg(errp, "Cannot specify both 'driver' and 'format'");
            goto early_err;
        }
        qdict_put(bs_opts, "driver", qstring_from_str(buf));
    }

    /* disk I/O throttling */
    memset(&cfg, 0, sizeof(cfg));
    cfg.buckets[THROTTLE_BPS_TOTAL].avg =
        qemu_opt_get_number(opts, "throttling.bps-total", 0);
    cfg.buckets[THROTTLE_BPS_READ].avg  =
        qemu_opt_get_number(opts, "throttling.bps-read", 0);
    cfg.buckets[THROTTLE_BPS_WRITE].avg =
        qemu_opt_get_number(opts, "throttling.bps-write", 0);
    cfg.buckets[THROTTLE_OPS_TOTAL].avg =
        qemu_opt_get_number(opts, "throttling.iops-total", 0);
    cfg.buckets[THROTTLE_OPS_READ].avg =
        qemu_opt_get_number(opts, "throttling.iops-read", 0);
    cfg.buckets[THROTTLE_OPS_WRITE].avg =
        qemu_opt_get_number(opts, "throttling.iops-write", 0);

    cfg.buckets[THROTTLE_BPS_TOTAL].max =
        qemu_opt_get_number(opts, "throttling.bps-total-max", 0);
    cfg.buckets[THROTTLE_BPS_READ].max  =
        qemu_opt_get_number(opts, "throttling.bps-read-max", 0);
    cfg.buckets[THROTTLE_BPS_WRITE].max =
        qemu_opt_get_number(opts, "throttling.bps-write-max", 0);
    cfg.buckets[THROTTLE_OPS_TOTAL].max =
        qemu_opt_get_number(opts, "throttling.iops-total-max", 0);
    cfg.buckets[THROTTLE_OPS_READ].max =
        qemu_opt_get_number(opts, "throttling.iops-read-max", 0);
    cfg.buckets[THROTTLE_OPS_WRITE].max =
        qemu_opt_get_number(opts, "throttling.iops-write-max", 0);

    cfg.op_size = qemu_opt_get_number(opts, "throttling.iops-size", 0);

    if (!check_throttle_config(&cfg, &error)) {
        error_propagate(errp, error);
        goto early_err;
    }

    on_write_error = BLOCKDEV_ON_ERROR_ENOSPC;
    if ((buf = qemu_opt_get(opts, "werror")) != NULL) {
        on_write_error = parse_block_error_action(buf, 0, &error);
        if (error) {
            error_propagate(errp, error);
            goto early_err;
        }
    }

    on_read_error = BLOCKDEV_ON_ERROR_REPORT;
    if ((buf = qemu_opt_get(opts, "rerror")) != NULL) {
        on_read_error = parse_block_error_action(buf, 1, &error);
        if (error) {
            error_propagate(errp, error);
            goto early_err;
        }
    }

    detect_zeroes =
        qapi_enum_parse(BlockdevDetectZeroesOptions_lookup,
                        qemu_opt_get(opts, "detect-zeroes"),
                        BLOCKDEV_DETECT_ZEROES_OPTIONS_MAX,
                        BLOCKDEV_DETECT_ZEROES_OPTIONS_OFF,
                        &error);
    if (error) {
        error_propagate(errp, error);
        goto early_err;
    }

    if (detect_zeroes == BLOCKDEV_DETECT_ZEROES_OPTIONS_UNMAP &&
        !(bdrv_flags & BDRV_O_UNMAP)) {
        error_setg(errp, "setting detect-zeroes to unmap is not allowed "
                         "without setting discard operation to unmap");
        goto early_err;
    }

    /* init */
    if ((!file || !*file) && !has_driver_specific_opts) {
        blk = blk_new_with_bs(qemu_opts_id(opts), errp);
        if (!blk) {
            goto early_err;
        }

        bs = blk_bs(blk);
        bs->open_flags = snapshot ? BDRV_O_SNAPSHOT : 0;
        bs->read_only = ro;

        QDECREF(bs_opts);
    } else {
        if (file && !*file) {
            file = NULL;
        }

        if (snapshot) {
            /* always use cache=unsafe with snapshot */
            bdrv_flags &= ~BDRV_O_CACHE_MASK;
            bdrv_flags |= (BDRV_O_SNAPSHOT|BDRV_O_CACHE_WB|BDRV_O_NO_FLUSH);
        }

        if (copy_on_read) {
            bdrv_flags |= BDRV_O_COPY_ON_READ;
        }

        if (runstate_check(RUN_STATE_INMIGRATE)) {
            bdrv_flags |= BDRV_O_INCOMING;
        }

        bdrv_flags |= ro ? 0 : BDRV_O_RDWR;

        blk = blk_new_open(qemu_opts_id(opts), file, NULL, bs_opts, bdrv_flags,
                           errp);
        if (!blk) {
            goto err_no_bs_opts;
        }
        bs = blk_bs(blk);
    }

    bs->detect_zeroes = detect_zeroes;

    bdrv_set_on_error(bs, on_read_error, on_write_error);

    /* disk I/O throttling */
    if (throttle_enabled(&cfg)) {
        bdrv_io_limits_enable(bs);
        bdrv_set_io_limits(bs, &cfg);
    }

    if (bdrv_key_required(bs)) {
        autostart = 0;
    }

err_no_bs_opts:
    qemu_opts_del(opts);
    return blk;

early_err:
    qemu_opts_del(opts);
err_no_opts:
    QDECREF(bs_opts);
    return NULL;
}

static void qemu_opt_rename(QemuOpts *opts, const char *from, const char *to,
                            Error **errp)
{
    const char *value;

    value = qemu_opt_get(opts, from);
    if (value) {
        if (qemu_opt_find(opts, to)) {
            error_setg(errp, "'%s' and its alias '%s' can't be used at the "
                       "same time", to, from);
            return;
        }
    }

    /* rename all items in opts */
    while ((value = qemu_opt_get(opts, from))) {
        qemu_opt_set(opts, to, value, &error_abort);
        qemu_opt_unset(opts, from);
    }
}

QemuOptsList qemu_legacy_drive_opts = {
    .name = "drive",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_legacy_drive_opts.head),
    .desc = {
        {
            .name = "bus",
            .type = QEMU_OPT_NUMBER,
            .help = "bus number",
        },{
            .name = "unit",
            .type = QEMU_OPT_NUMBER,
            .help = "unit number (i.e. lun for scsi)",
        },{
            .name = "index",
            .type = QEMU_OPT_NUMBER,
            .help = "index number",
        },{
            .name = "media",
            .type = QEMU_OPT_STRING,
            .help = "media type (disk, cdrom)",
        },{
            .name = "if",
            .type = QEMU_OPT_STRING,
            .help = "interface (ide, scsi, sd, mtd, floppy, pflash, virtio)",
        },{
            .name = "cyls",
            .type = QEMU_OPT_NUMBER,
            .help = "number of cylinders (ide disk geometry)",
        },{
            .name = "heads",
            .type = QEMU_OPT_NUMBER,
            .help = "number of heads (ide disk geometry)",
        },{
            .name = "secs",
            .type = QEMU_OPT_NUMBER,
            .help = "number of sectors (ide disk geometry)",
        },{
            .name = "trans",
            .type = QEMU_OPT_STRING,
            .help = "chs translation (auto, lba, none)",
        },{
            .name = "boot",
            .type = QEMU_OPT_BOOL,
            .help = "(deprecated, ignored)",
        },{
            .name = "addr",
            .type = QEMU_OPT_STRING,
            .help = "pci address (virtio only)",
        },{
            .name = "serial",
            .type = QEMU_OPT_STRING,
            .help = "disk serial number",
        },{
            .name = "file",
            .type = QEMU_OPT_STRING,
            .help = "file name",
        },

        /* Options that are passed on, but have special semantics with -drive */
        {
            .name = "read-only",
            .type = QEMU_OPT_BOOL,
            .help = "open drive file as read-only",
        },{
            .name = "rerror",
            .type = QEMU_OPT_STRING,
            .help = "read error action",
        },{
            .name = "werror",
            .type = QEMU_OPT_STRING,
            .help = "write error action",
        },{
            .name = "copy-on-read",
            .type = QEMU_OPT_BOOL,
            .help = "copy read data from backing file into image file",
        },

        { /* end of list */ }
    },
};

DriveInfo *drive_new(QemuOpts *all_opts, BlockInterfaceType block_default_type)
{
    const char *value;
    BlockBackend *blk;
    DriveInfo *dinfo = NULL;
    QDict *bs_opts;
    QemuOpts *legacy_opts;
    DriveMediaType media = MEDIA_DISK;
    BlockInterfaceType type;
    int cyls, heads, secs, translation;
    int max_devs, bus_id, unit_id, index;
    const char *devaddr;
    const char *werror, *rerror;
    bool read_only = false;
    bool copy_on_read;
    const char *serial;
    const char *filename;
    Error *local_err = NULL;
    int i;

    /* Change legacy command line options into QMP ones */
    static const struct {
        const char *from;
        const char *to;
    } opt_renames[] = {
        { "iops",           "throttling.iops-total" },
        { "iops_rd",        "throttling.iops-read" },
        { "iops_wr",        "throttling.iops-write" },

        { "bps",            "throttling.bps-total" },
        { "bps_rd",         "throttling.bps-read" },
        { "bps_wr",         "throttling.bps-write" },

        { "iops_max",       "throttling.iops-total-max" },
        { "iops_rd_max",    "throttling.iops-read-max" },
        { "iops_wr_max",    "throttling.iops-write-max" },

        { "bps_max",        "throttling.bps-total-max" },
        { "bps_rd_max",     "throttling.bps-read-max" },
        { "bps_wr_max",     "throttling.bps-write-max" },

        { "iops_size",      "throttling.iops-size" },

        { "readonly",       "read-only" },
    };

    for (i = 0; i < ARRAY_SIZE(opt_renames); i++) {
        qemu_opt_rename(all_opts, opt_renames[i].from, opt_renames[i].to,
                        &local_err);
        if (local_err) {
            error_report_err(local_err);
            return NULL;
        }
    }

    value = qemu_opt_get(all_opts, "cache");
    if (value) {
        int flags = 0;

        if (bdrv_parse_cache_flags(value, &flags) != 0) {
            error_report("invalid cache option");
            return NULL;
        }

        /* Specific options take precedence */
        if (!qemu_opt_get(all_opts, "cache.writeback")) {
            qemu_opt_set_bool(all_opts, "cache.writeback",
                              !!(flags & BDRV_O_CACHE_WB), &error_abort);
        }
        if (!qemu_opt_get(all_opts, "cache.direct")) {
            qemu_opt_set_bool(all_opts, "cache.direct",
                              !!(flags & BDRV_O_NOCACHE), &error_abort);
        }
        if (!qemu_opt_get(all_opts, "cache.no-flush")) {
            qemu_opt_set_bool(all_opts, "cache.no-flush",
                              !!(flags & BDRV_O_NO_FLUSH), &error_abort);
        }
        qemu_opt_unset(all_opts, "cache");
    }

    /* Get a QDict for processing the options */
    bs_opts = qdict_new();
    qemu_opts_to_qdict(all_opts, bs_opts);

    legacy_opts = qemu_opts_create(&qemu_legacy_drive_opts, NULL, 0,
                                   &error_abort);
    qemu_opts_absorb_qdict(legacy_opts, bs_opts, &local_err);
    if (local_err) {
        error_report_err(local_err);
        goto fail;
    }

    /* Deprecated option boot=[on|off] */
    if (qemu_opt_get(legacy_opts, "boot") != NULL) {
        fprintf(stderr, "qemu-kvm: boot=on|off is deprecated and will be "
                "ignored. Future versions will reject this parameter. Please "
                "update your scripts.\n");
    }

    /* Media type */
    value = qemu_opt_get(legacy_opts, "media");
    if (value) {
        if (!strcmp(value, "disk")) {
            media = MEDIA_DISK;
        } else if (!strcmp(value, "cdrom")) {
            media = MEDIA_CDROM;
            read_only = true;
        } else {
            error_report("'%s' invalid media", value);
            goto fail;
        }
    }

    /* copy-on-read is disabled with a warning for read-only devices */
    read_only |= qemu_opt_get_bool(legacy_opts, "read-only", false);
    copy_on_read = qemu_opt_get_bool(legacy_opts, "copy-on-read", false);

    if (read_only && copy_on_read) {
        error_report("warning: disabling copy-on-read on read-only drive");
        copy_on_read = false;
    }

    qdict_put(bs_opts, "read-only",
              qstring_from_str(read_only ? "on" : "off"));
    qdict_put(bs_opts, "copy-on-read",
              qstring_from_str(copy_on_read ? "on" :"off"));

    /* Controller type */
    value = qemu_opt_get(legacy_opts, "if");
    if (value) {
        for (type = 0;
             type < IF_COUNT && strcmp(value, if_name[type]);
             type++) {
        }
        if (type == IF_COUNT) {
            error_report("unsupported bus type '%s'", value);
            goto fail;
        }
    } else {
        type = block_default_type;
    }

    /* Geometry */
    cyls  = qemu_opt_get_number(legacy_opts, "cyls", 0);
    heads = qemu_opt_get_number(legacy_opts, "heads", 0);
    secs  = qemu_opt_get_number(legacy_opts, "secs", 0);

    if (cyls || heads || secs) {
        if (cyls < 1) {
            error_report("invalid physical cyls number");
            goto fail;
        }
        if (heads < 1) {
            error_report("invalid physical heads number");
            goto fail;
        }
        if (secs < 1) {
            error_report("invalid physical secs number");
            goto fail;
        }
    }

    translation = BIOS_ATA_TRANSLATION_AUTO;
    value = qemu_opt_get(legacy_opts, "trans");
    if (value != NULL) {
        if (!cyls) {
            error_report("'%s' trans must be used with cyls, heads and secs",
                         value);
            goto fail;
        }
        if (!strcmp(value, "none")) {
            translation = BIOS_ATA_TRANSLATION_NONE;
        } else if (!strcmp(value, "lba")) {
            translation = BIOS_ATA_TRANSLATION_LBA;
        } else if (!strcmp(value, "large")) {
            translation = BIOS_ATA_TRANSLATION_LARGE;
        } else if (!strcmp(value, "rechs")) {
            translation = BIOS_ATA_TRANSLATION_RECHS;
        } else if (!strcmp(value, "auto")) {
            translation = BIOS_ATA_TRANSLATION_AUTO;
        } else {
            error_report("'%s' invalid translation type", value);
            goto fail;
        }
    }

    if (media == MEDIA_CDROM) {
        if (cyls || secs || heads) {
            error_report("CHS can't be set with media=cdrom");
            goto fail;
        }
    }

    /* Device address specified by bus/unit or index.
     * If none was specified, try to find the first free one. */
    bus_id  = qemu_opt_get_number(legacy_opts, "bus", 0);
    unit_id = qemu_opt_get_number(legacy_opts, "unit", -1);
    index   = qemu_opt_get_number(legacy_opts, "index", -1);

    max_devs = if_max_devs[type];

    if (index != -1) {
        if (bus_id != 0 || unit_id != -1) {
            error_report("index cannot be used with bus and unit");
            goto fail;
        }
        bus_id = drive_index_to_bus_id(type, index);
        unit_id = drive_index_to_unit_id(type, index);
    }

    if (unit_id == -1) {
       unit_id = 0;
       while (drive_get(type, bus_id, unit_id) != NULL) {
           unit_id++;
           if (max_devs && unit_id >= max_devs) {
               unit_id -= max_devs;
               bus_id++;
           }
       }
    }

    if (max_devs && unit_id >= max_devs) {
        error_report("unit %d too big (max is %d)", unit_id, max_devs - 1);
        goto fail;
    }

    if (drive_get(type, bus_id, unit_id) != NULL) {
        error_report("drive with bus=%d, unit=%d (index=%d) exists",
                     bus_id, unit_id, index);
        goto fail;
    }

    /* Serial number */
    serial = qemu_opt_get(legacy_opts, "serial");

    /* no id supplied -> create one */
    if (qemu_opts_id(all_opts) == NULL) {
        char *new_id;
        const char *mediastr = "";
        if (type == IF_IDE || type == IF_SCSI) {
            mediastr = (media == MEDIA_CDROM) ? "-cd" : "-hd";
        }
        if (max_devs) {
            new_id = g_strdup_printf("%s%i%s%i", if_name[type], bus_id,
                                     mediastr, unit_id);
        } else {
            new_id = g_strdup_printf("%s%s%i", if_name[type],
                                     mediastr, unit_id);
        }
        qdict_put(bs_opts, "id", qstring_from_str(new_id));
        g_free(new_id);
    }

    /* Add virtio block device */
    devaddr = qemu_opt_get(legacy_opts, "addr");
    if (devaddr && type != IF_VIRTIO) {
        error_report("addr is not supported by this bus type");
        goto fail;
    }

    if (type == IF_VIRTIO) {
        QemuOpts *devopts;
        devopts = qemu_opts_create(qemu_find_opts("device"), NULL, 0,
                                   &error_abort);
        if (arch_type == QEMU_ARCH_S390X) {
            qemu_opt_set(devopts, "driver", "virtio-blk-s390", &error_abort);
        } else {
            qemu_opt_set(devopts, "driver", "virtio-blk-pci", &error_abort);
        }
        qemu_opt_set(devopts, "drive", qdict_get_str(bs_opts, "id"),
                     &error_abort);
        if (devaddr) {
            qemu_opt_set(devopts, "addr", devaddr, &error_abort);
        }
    }

    filename = qemu_opt_get(legacy_opts, "file");

    /* Check werror/rerror compatibility with if=... */
    werror = qemu_opt_get(legacy_opts, "werror");
    if (werror != NULL) {
        if (type != IF_IDE && type != IF_SCSI && type != IF_VIRTIO &&
            type != IF_NONE) {
            error_report("werror is not supported by this bus type");
            goto fail;
        }
        qdict_put(bs_opts, "werror", qstring_from_str(werror));
    }

    rerror = qemu_opt_get(legacy_opts, "rerror");
    if (rerror != NULL) {
        if (type != IF_IDE && type != IF_VIRTIO && type != IF_SCSI &&
            type != IF_NONE) {
            error_report("rerror is not supported by this bus type");
            goto fail;
        }
        qdict_put(bs_opts, "rerror", qstring_from_str(rerror));
    }

    /* Actual block device init: Functionality shared with blockdev-add */
    blk = blockdev_init(filename, bs_opts, &local_err);
    bs_opts = NULL;
    if (!blk) {
        if (local_err) {
            error_report_err(local_err);
        }
        goto fail;
    } else {
        assert(!local_err);
    }

    /* Create legacy DriveInfo */
    dinfo = g_malloc0(sizeof(*dinfo));
    dinfo->opts = all_opts;

    dinfo->cyls = cyls;
    dinfo->heads = heads;
    dinfo->secs = secs;
    dinfo->trans = translation;

    dinfo->type = type;
    dinfo->bus = bus_id;
    dinfo->unit = unit_id;
    dinfo->devaddr = devaddr;
    dinfo->serial = g_strdup(serial);

    blk_set_legacy_dinfo(blk, dinfo);

    switch(type) {
    case IF_IDE:
    case IF_SCSI:
    case IF_XEN:
    case IF_NONE:
        dinfo->media_cd = media == MEDIA_CDROM;
        break;
    default:
        break;
    }

fail:
    qemu_opts_del(legacy_opts);
    QDECREF(bs_opts);
    return dinfo;
}

void hmp_commit(Monitor *mon, const QDict *qdict)
{
    const char *device = qdict_get_str(qdict, "device");
    BlockBackend *blk;
    int ret;

    if (!strcmp(device, "all")) {
        ret = bdrv_commit_all();
    } else {
        blk = blk_by_name(device);
        if (!blk) {
            monitor_printf(mon, "Device '%s' not found\n", device);
            return;
        }
        ret = bdrv_commit(blk_bs(blk));
    }
    if (ret < 0) {
        monitor_printf(mon, "'commit' error for '%s': %s\n", device,
                       strerror(-ret));
    }
}

static void blockdev_do_action(int kind, void *data, Error **errp)
{
    TransactionAction action;
    TransactionActionList list;

    action.kind = kind;
    action.data = data;
    list.value = &action;
    list.next = NULL;
    qmp_transaction(&list, errp);
}

void qmp_blockdev_snapshot_sync(bool has_device, const char *device,
                                bool has_node_name, const char *node_name,
                                const char *snapshot_file,
                                bool has_snapshot_node_name,
                                const char *snapshot_node_name,
                                bool has_format, const char *format,
                                bool has_mode, NewImageMode mode, Error **errp)
{
    BlockdevSnapshot snapshot = {
        .has_device = has_device,
        .device = (char *) device,
        .has_node_name = has_node_name,
        .node_name = (char *) node_name,
        .snapshot_file = (char *) snapshot_file,
        .has_snapshot_node_name = has_snapshot_node_name,
        .snapshot_node_name = (char *) snapshot_node_name,
        .has_format = has_format,
        .format = (char *) format,
        .has_mode = has_mode,
        .mode = mode,
    };
    blockdev_do_action(TRANSACTION_ACTION_KIND_BLOCKDEV_SNAPSHOT_SYNC,
                       &snapshot, errp);
}

void qmp_blockdev_snapshot_internal_sync(const char *device,
                                         const char *name,
                                         Error **errp)
{
    BlockdevSnapshotInternal snapshot = {
        .device = (char *) device,
        .name = (char *) name
    };

    blockdev_do_action(TRANSACTION_ACTION_KIND_BLOCKDEV_SNAPSHOT_INTERNAL_SYNC,
                       &snapshot, errp);
}

SnapshotInfo *qmp_blockdev_snapshot_delete_internal_sync(const char *device,
                                                         bool has_id,
                                                         const char *id,
                                                         bool has_name,
                                                         const char *name,
                                                         Error **errp)
{
    BlockDriverState *bs;
    BlockBackend *blk;
    AioContext *aio_context;
    QEMUSnapshotInfo sn;
    Error *local_err = NULL;
    SnapshotInfo *info = NULL;
    int ret;

    blk = blk_by_name(device);
    if (!blk) {
        error_set(errp, QERR_DEVICE_NOT_FOUND, device);
        return NULL;
    }
    bs = blk_bs(blk);

    if (!has_id) {
        id = NULL;
    }

    if (!has_name) {
        name = NULL;
    }

    if (!id && !name) {
        error_setg(errp, "Name or id must be provided");
        return NULL;
    }

    aio_context = bdrv_get_aio_context(bs);
    aio_context_acquire(aio_context);

    if (bdrv_op_is_blocked(bs, BLOCK_OP_TYPE_INTERNAL_SNAPSHOT_DELETE, errp)) {
        goto out_aio_context;
    }

    ret = bdrv_snapshot_find_by_id_and_name(bs, id, name, &sn, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        goto out_aio_context;
    }
    if (!ret) {
        error_setg(errp,
                   "Snapshot with id '%s' and name '%s' does not exist on "
                   "device '%s'",
                   STR_OR_NULL(id), STR_OR_NULL(name), device);
        goto out_aio_context;
    }

    bdrv_snapshot_delete(bs, id, name, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        goto out_aio_context;
    }

    aio_context_release(aio_context);

    info = g_new0(SnapshotInfo, 1);
    info->id = g_strdup(sn.id_str);
    info->name = g_strdup(sn.name);
    info->date_nsec = sn.date_nsec;
    info->date_sec = sn.date_sec;
    info->vm_state_size = sn.vm_state_size;
    info->vm_clock_nsec = sn.vm_clock_nsec % 1000000000;
    info->vm_clock_sec = sn.vm_clock_nsec / 1000000000;

    return info;

out_aio_context:
    aio_context_release(aio_context);
    return NULL;
}

/* New and old BlockDriverState structs for atomic group operations */

typedef struct BlkTransactionState BlkTransactionState;

/* Only prepare() may fail. In a single transaction, only one of commit() or
   abort() will be called, clean() will always be called if it present. */
typedef struct BdrvActionOps {
    /* Size of state struct, in bytes. */
    size_t instance_size;
    /* Prepare the work, must NOT be NULL. */
    void (*prepare)(BlkTransactionState *common, Error **errp);
    /* Commit the changes, can be NULL. */
    void (*commit)(BlkTransactionState *common);
    /* Abort the changes on fail, can be NULL. */
    void (*abort)(BlkTransactionState *common);
    /* Clean up resource in the end, can be NULL. */
    void (*clean)(BlkTransactionState *common);
} BdrvActionOps;

/*
 * This structure must be arranged as first member in child type, assuming
 * that compiler will also arrange it to the same address with parent instance.
 * Later it will be used in free().
 */
struct BlkTransactionState {
    TransactionAction *action;
    const BdrvActionOps *ops;
    QSIMPLEQ_ENTRY(BlkTransactionState) entry;
};

/* internal snapshot private data */
typedef struct InternalSnapshotState {
    BlkTransactionState common;
    BlockDriverState *bs;
    AioContext *aio_context;
    QEMUSnapshotInfo sn;
} InternalSnapshotState;

static void internal_snapshot_prepare(BlkTransactionState *common,
                                      Error **errp)
{
    Error *local_err = NULL;
    const char *device;
    const char *name;
    BlockBackend *blk;
    BlockDriverState *bs;
    QEMUSnapshotInfo old_sn, *sn;
    bool ret;
    qemu_timeval tv;
    BlockdevSnapshotInternal *internal;
    InternalSnapshotState *state;
    int ret1;

    g_assert(common->action->kind ==
             TRANSACTION_ACTION_KIND_BLOCKDEV_SNAPSHOT_INTERNAL_SYNC);
    internal = common->action->blockdev_snapshot_internal_sync;
    state = DO_UPCAST(InternalSnapshotState, common, common);

    /* 1. parse input */
    device = internal->device;
    name = internal->name;

    /* 2. check for validation */
    blk = blk_by_name(device);
    if (!blk) {
        error_set(errp, QERR_DEVICE_NOT_FOUND, device);
        return;
    }
    bs = blk_bs(blk);

    /* AioContext is released in .clean() */
    state->aio_context = bdrv_get_aio_context(bs);
    aio_context_acquire(state->aio_context);

    if (!bdrv_is_inserted(bs)) {
        error_set(errp, QERR_DEVICE_HAS_NO_MEDIUM, device);
        return;
    }

    if (bdrv_op_is_blocked(bs, BLOCK_OP_TYPE_INTERNAL_SNAPSHOT, errp)) {
        return;
    }

    if (bdrv_is_read_only(bs)) {
        error_set(errp, QERR_DEVICE_IS_READ_ONLY, device);
        return;
    }

    if (!bdrv_can_snapshot(bs)) {
        error_set(errp, QERR_BLOCK_FORMAT_FEATURE_NOT_SUPPORTED,
                  bs->drv->format_name, device, "internal snapshot");
        return;
    }

    if (!strlen(name)) {
        error_setg(errp, "Name is empty");
        return;
    }

    /* check whether a snapshot with name exist */
    ret = bdrv_snapshot_find_by_id_and_name(bs, NULL, name, &old_sn,
                                            &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    } else if (ret) {
        error_setg(errp,
                   "Snapshot with name '%s' already exists on device '%s'",
                   name, device);
        return;
    }

    /* 3. take the snapshot */
    sn = &state->sn;
    pstrcpy(sn->name, sizeof(sn->name), name);
    qemu_gettimeofday(&tv);
    sn->date_sec = tv.tv_sec;
    sn->date_nsec = tv.tv_usec * 1000;
    sn->vm_clock_nsec = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);

    ret1 = bdrv_snapshot_create(bs, sn);
    if (ret1 < 0) {
        error_setg_errno(errp, -ret1,
                         "Failed to create snapshot '%s' on device '%s'",
                         name, device);
        return;
    }

    /* 4. succeed, mark a snapshot is created */
    state->bs = bs;
}

static void internal_snapshot_abort(BlkTransactionState *common)
{
    InternalSnapshotState *state =
                             DO_UPCAST(InternalSnapshotState, common, common);
    BlockDriverState *bs = state->bs;
    QEMUSnapshotInfo *sn = &state->sn;
    Error *local_error = NULL;

    if (!bs) {
        return;
    }

    if (bdrv_snapshot_delete(bs, sn->id_str, sn->name, &local_error) < 0) {
        error_report("Failed to delete snapshot with id '%s' and name '%s' on "
                     "device '%s' in abort: %s",
                     sn->id_str,
                     sn->name,
                     bdrv_get_device_name(bs),
                     error_get_pretty(local_error));
        error_free(local_error);
    }
}

static void internal_snapshot_clean(BlkTransactionState *common)
{
    InternalSnapshotState *state = DO_UPCAST(InternalSnapshotState,
                                             common, common);

    if (state->aio_context) {
        aio_context_release(state->aio_context);
    }
}

/* external snapshot private data */
typedef struct ExternalSnapshotState {
    BlkTransactionState common;
    BlockDriverState *old_bs;
    BlockDriverState *new_bs;
    AioContext *aio_context;
} ExternalSnapshotState;

static void external_snapshot_prepare(BlkTransactionState *common,
                                      Error **errp)
{
    BlockDriver *drv;
    int flags, ret;
    QDict *options = NULL;
    Error *local_err = NULL;
    bool has_device = false;
    const char *device;
    bool has_node_name = false;
    const char *node_name;
    bool has_snapshot_node_name = false;
    const char *snapshot_node_name;
    const char *new_image_file;
    const char *format = "qcow2";
    enum NewImageMode mode = NEW_IMAGE_MODE_ABSOLUTE_PATHS;
    ExternalSnapshotState *state =
                             DO_UPCAST(ExternalSnapshotState, common, common);
    TransactionAction *action = common->action;

    /* get parameters */
    g_assert(action->kind == TRANSACTION_ACTION_KIND_BLOCKDEV_SNAPSHOT_SYNC);

    has_device = action->blockdev_snapshot_sync->has_device;
    device = action->blockdev_snapshot_sync->device;
    has_node_name = action->blockdev_snapshot_sync->has_node_name;
    node_name = action->blockdev_snapshot_sync->node_name;
    has_snapshot_node_name =
        action->blockdev_snapshot_sync->has_snapshot_node_name;
    snapshot_node_name = action->blockdev_snapshot_sync->snapshot_node_name;

    new_image_file = action->blockdev_snapshot_sync->snapshot_file;
    if (action->blockdev_snapshot_sync->has_format) {
        format = action->blockdev_snapshot_sync->format;
    }
    if (action->blockdev_snapshot_sync->has_mode) {
        mode = action->blockdev_snapshot_sync->mode;
    }

    /* start processing */
    drv = bdrv_find_format(format);
    if (!drv) {
        error_set(errp, QERR_INVALID_BLOCK_FORMAT, format);
        return;
    }

    state->old_bs = bdrv_lookup_bs(has_device ? device : NULL,
                                   has_node_name ? node_name : NULL,
                                   &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    if (has_node_name && !has_snapshot_node_name) {
        error_setg(errp, "New snapshot node name missing");
        return;
    }

    if (has_snapshot_node_name && bdrv_find_node(snapshot_node_name)) {
        error_setg(errp, "New snapshot node name already existing");
        return;
    }

    /* Acquire AioContext now so any threads operating on old_bs stop */
    state->aio_context = bdrv_get_aio_context(state->old_bs);
    aio_context_acquire(state->aio_context);

    if (!bdrv_is_inserted(state->old_bs)) {
        error_set(errp, QERR_DEVICE_HAS_NO_MEDIUM, device);
        return;
    }

    if (bdrv_op_is_blocked(state->old_bs,
                           BLOCK_OP_TYPE_EXTERNAL_SNAPSHOT, errp)) {
        return;
    }

    if (!bdrv_is_read_only(state->old_bs)) {
        if (bdrv_flush(state->old_bs)) {
            error_set(errp, QERR_IO_ERROR);
            return;
        }
    }

    if (!bdrv_is_first_non_filter(state->old_bs)) {
        error_set(errp, QERR_FEATURE_DISABLED, "snapshot");
        return;
    }

    flags = state->old_bs->open_flags;

    /* create new image w/backing file */
    if (mode != NEW_IMAGE_MODE_EXISTING) {
        bdrv_img_create(new_image_file, format,
                        state->old_bs->filename,
                        state->old_bs->drv->format_name,
                        NULL, -1, flags, &local_err, false);
        if (local_err) {
            error_propagate(errp, local_err);
            return;
        }
    }

    if (has_snapshot_node_name) {
        options = qdict_new();
        qdict_put(options, "node-name",
                  qstring_from_str(snapshot_node_name));
    }

    /* TODO Inherit bs->options or only take explicit options with an
     * extended QMP command? */
    assert(state->new_bs == NULL);
    ret = bdrv_open(&state->new_bs, new_image_file, NULL, options,
                    flags | BDRV_O_NO_BACKING, drv, &local_err);
    /* We will manually add the backing_hd field to the bs later */
    if (ret != 0) {
        error_propagate(errp, local_err);
    }
}

static void external_snapshot_commit(BlkTransactionState *common)
{
    ExternalSnapshotState *state =
                             DO_UPCAST(ExternalSnapshotState, common, common);

    bdrv_set_aio_context(state->new_bs, state->aio_context);

    /* This removes our old bs and adds the new bs */
    bdrv_append(state->new_bs, state->old_bs);
    /* We don't need (or want) to use the transactional
     * bdrv_reopen_multiple() across all the entries at once, because we
     * don't want to abort all of them if one of them fails the reopen */
    bdrv_reopen(state->new_bs, state->new_bs->open_flags & ~BDRV_O_RDWR,
                NULL);

    aio_context_release(state->aio_context);
}

static void external_snapshot_abort(BlkTransactionState *common)
{
    ExternalSnapshotState *state =
                             DO_UPCAST(ExternalSnapshotState, common, common);
    if (state->new_bs) {
        bdrv_unref(state->new_bs);
    }
    if (state->aio_context) {
        aio_context_release(state->aio_context);
    }
}

typedef struct DriveBackupState {
    BlkTransactionState common;
    BlockDriverState *bs;
    AioContext *aio_context;
    BlockJob *job;
} DriveBackupState;

static void drive_backup_prepare(BlkTransactionState *common, Error **errp)
{
    DriveBackupState *state = DO_UPCAST(DriveBackupState, common, common);
    BlockDriverState *bs;
    BlockBackend *blk;
    DriveBackup *backup;
    Error *local_err = NULL;

    assert(common->action->kind == TRANSACTION_ACTION_KIND_DRIVE_BACKUP);
    backup = common->action->drive_backup;

    blk = blk_by_name(backup->device);
    if (!blk) {
        error_set(errp, QERR_DEVICE_NOT_FOUND, backup->device);
        return;
    }
    bs = blk_bs(blk);

    /* AioContext is released in .clean() */
    state->aio_context = bdrv_get_aio_context(bs);
    aio_context_acquire(state->aio_context);

    qmp_drive_backup(backup->device, backup->target,
                     backup->has_format, backup->format,
                     backup->sync,
                     backup->has_mode, backup->mode,
                     backup->has_speed, backup->speed,
                     backup->has_on_source_error, backup->on_source_error,
                     backup->has_on_target_error, backup->on_target_error,
                     &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    state->bs = bs;
    state->job = state->bs->job;
}

static void drive_backup_abort(BlkTransactionState *common)
{
    DriveBackupState *state = DO_UPCAST(DriveBackupState, common, common);
    BlockDriverState *bs = state->bs;

    /* Only cancel if it's the job we started */
    if (bs && bs->job && bs->job == state->job) {
        block_job_cancel_sync(bs->job);
    }
}

static void drive_backup_clean(BlkTransactionState *common)
{
    DriveBackupState *state = DO_UPCAST(DriveBackupState, common, common);

    if (state->aio_context) {
        aio_context_release(state->aio_context);
    }
}

typedef struct BlockdevBackupState {
    BlkTransactionState common;
    BlockDriverState *bs;
    BlockJob *job;
    AioContext *aio_context;
} BlockdevBackupState;

static void blockdev_backup_prepare(BlkTransactionState *common, Error **errp)
{
    BlockdevBackupState *state = DO_UPCAST(BlockdevBackupState, common, common);
    BlockdevBackup *backup;
    BlockDriverState *bs, *target;
    BlockBackend *blk;
    Error *local_err = NULL;

    assert(common->action->kind == TRANSACTION_ACTION_KIND_BLOCKDEV_BACKUP);
    backup = common->action->blockdev_backup;

    blk = blk_by_name(backup->device);
    if (!blk) {
        error_setg(errp, "Device '%s' not found", backup->device);
        return;
    }
    bs = blk_bs(blk);

    blk = blk_by_name(backup->target);
    if (!blk) {
        error_setg(errp, "Device '%s' not found", backup->target);
        return;
    }
    target = blk_bs(blk);

    /* AioContext is released in .clean() */
    state->aio_context = bdrv_get_aio_context(bs);
    if (state->aio_context != bdrv_get_aio_context(target)) {
        state->aio_context = NULL;
        error_setg(errp, "Backup between two IO threads is not implemented");
        return;
    }
    aio_context_acquire(state->aio_context);

    qmp_blockdev_backup(backup->device, backup->target,
                        backup->sync,
                        backup->has_speed, backup->speed,
                        backup->has_on_source_error, backup->on_source_error,
                        backup->has_on_target_error, backup->on_target_error,
                        &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    state->bs = bs;
    state->job = state->bs->job;
}

static void blockdev_backup_abort(BlkTransactionState *common)
{
    BlockdevBackupState *state = DO_UPCAST(BlockdevBackupState, common, common);
    BlockDriverState *bs = state->bs;

    /* Only cancel if it's the job we started */
    if (bs && bs->job && bs->job == state->job) {
        block_job_cancel_sync(bs->job);
    }
}

static void blockdev_backup_clean(BlkTransactionState *common)
{
    BlockdevBackupState *state = DO_UPCAST(BlockdevBackupState, common, common);

    if (state->aio_context) {
        aio_context_release(state->aio_context);
    }
}

static void abort_prepare(BlkTransactionState *common, Error **errp)
{
    error_setg(errp, "Transaction aborted using Abort action");
}

static void abort_commit(BlkTransactionState *common)
{
    g_assert_not_reached(); /* this action never succeeds */
}

static const BdrvActionOps actions[] = {
    [TRANSACTION_ACTION_KIND_BLOCKDEV_SNAPSHOT_SYNC] = {
        .instance_size = sizeof(ExternalSnapshotState),
        .prepare  = external_snapshot_prepare,
        .commit   = external_snapshot_commit,
        .abort = external_snapshot_abort,
    },
    [TRANSACTION_ACTION_KIND_DRIVE_BACKUP] = {
        .instance_size = sizeof(DriveBackupState),
        .prepare = drive_backup_prepare,
        .abort = drive_backup_abort,
        .clean = drive_backup_clean,
    },
    [TRANSACTION_ACTION_KIND_BLOCKDEV_BACKUP] = {
        .instance_size = sizeof(BlockdevBackupState),
        .prepare = blockdev_backup_prepare,
        .abort = blockdev_backup_abort,
        .clean = blockdev_backup_clean,
    },
    [TRANSACTION_ACTION_KIND_ABORT] = {
        .instance_size = sizeof(BlkTransactionState),
        .prepare = abort_prepare,
        .commit = abort_commit,
    },
    [TRANSACTION_ACTION_KIND_BLOCKDEV_SNAPSHOT_INTERNAL_SYNC] = {
        .instance_size = sizeof(InternalSnapshotState),
        .prepare  = internal_snapshot_prepare,
        .abort = internal_snapshot_abort,
        .clean = internal_snapshot_clean,
    },
};

/*
 * 'Atomic' group operations.  The operations are performed as a set, and if
 * any fail then we roll back all operations in the group.
 */
void qmp_transaction(TransactionActionList *dev_list, Error **errp)
{
    TransactionActionList *dev_entry = dev_list;
    BlkTransactionState *state, *next;
    Error *local_err = NULL;

    QSIMPLEQ_HEAD(snap_bdrv_states, BlkTransactionState) snap_bdrv_states;
    QSIMPLEQ_INIT(&snap_bdrv_states);

    /* drain all i/o before any operations */
    bdrv_drain_all();

    /* We don't do anything in this loop that commits us to the operations */
    while (NULL != dev_entry) {
        TransactionAction *dev_info = NULL;
        const BdrvActionOps *ops;

        dev_info = dev_entry->value;
        dev_entry = dev_entry->next;

        assert(dev_info->kind < ARRAY_SIZE(actions));

        ops = &actions[dev_info->kind];
        assert(ops->instance_size > 0);

        state = g_malloc0(ops->instance_size);
        state->ops = ops;
        state->action = dev_info;
        QSIMPLEQ_INSERT_TAIL(&snap_bdrv_states, state, entry);

        state->ops->prepare(state, &local_err);
        if (local_err) {
            error_propagate(errp, local_err);
            goto delete_and_fail;
        }
    }

    QSIMPLEQ_FOREACH(state, &snap_bdrv_states, entry) {
        if (state->ops->commit) {
            state->ops->commit(state);
        }
    }

    /* success */
    goto exit;

delete_and_fail:
    /* failure, and it is all-or-none; roll back all operations */
    QSIMPLEQ_FOREACH(state, &snap_bdrv_states, entry) {
        if (state->ops->abort) {
            state->ops->abort(state);
        }
    }
exit:
    QSIMPLEQ_FOREACH_SAFE(state, &snap_bdrv_states, entry, next) {
        if (state->ops->clean) {
            state->ops->clean(state);
        }
        g_free(state);
    }
}


static void eject_device(BlockBackend *blk, int force, Error **errp)
{
    BlockDriverState *bs = blk_bs(blk);
    AioContext *aio_context;

    aio_context = bdrv_get_aio_context(bs);
    aio_context_acquire(aio_context);

    if (bdrv_op_is_blocked(bs, BLOCK_OP_TYPE_EJECT, errp)) {
        goto out;
    }
    if (!blk_dev_has_removable_media(blk)) {
        error_setg(errp, "Device '%s' is not removable",
                   bdrv_get_device_name(bs));
        goto out;
    }

    if (blk_dev_is_medium_locked(blk) && !blk_dev_is_tray_open(blk)) {
        blk_dev_eject_request(blk, force);
        if (!force) {
            error_setg(errp, "Device '%s' is locked",
                       bdrv_get_device_name(bs));
            goto out;
        }
    }

    bdrv_close(bs);

out:
    aio_context_release(aio_context);
}

void qmp_eject(const char *device, bool has_force, bool force, Error **errp)
{
    BlockBackend *blk;

    blk = blk_by_name(device);
    if (!blk) {
        error_set(errp, QERR_DEVICE_NOT_FOUND, device);
        return;
    }

    eject_device(blk, force, errp);
}

void qmp_block_passwd(bool has_device, const char *device,
                      bool has_node_name, const char *node_name,
                      const char *password, Error **errp)
{
    Error *local_err = NULL;
    BlockDriverState *bs;
    AioContext *aio_context;

    bs = bdrv_lookup_bs(has_device ? device : NULL,
                        has_node_name ? node_name : NULL,
                        &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    aio_context = bdrv_get_aio_context(bs);
    aio_context_acquire(aio_context);

    bdrv_add_key(bs, password, errp);

    aio_context_release(aio_context);
}

/* Assumes AioContext is held */
static void qmp_bdrv_open_encrypted(BlockDriverState *bs, const char *filename,
                                    int bdrv_flags, BlockDriver *drv,
                                    const char *password, Error **errp)
{
    Error *local_err = NULL;
    int ret;

    ret = bdrv_open(&bs, filename, NULL, NULL, bdrv_flags, drv, &local_err);
    if (ret < 0) {
        error_propagate(errp, local_err);
        return;
    }

    bdrv_add_key(bs, password, errp);
}

void qmp_change_blockdev(const char *device, const char *filename,
                         const char *format, Error **errp)
{
    BlockBackend *blk;
    BlockDriverState *bs;
    AioContext *aio_context;
    BlockDriver *drv = NULL;
    int bdrv_flags;
    Error *err = NULL;

    blk = blk_by_name(device);
    if (!blk) {
        error_set(errp, QERR_DEVICE_NOT_FOUND, device);
        return;
    }
    bs = blk_bs(blk);

    aio_context = bdrv_get_aio_context(bs);
    aio_context_acquire(aio_context);

    if (format) {
        drv = bdrv_find_whitelisted_format(format, bs->read_only);
        if (!drv) {
            error_set(errp, QERR_INVALID_BLOCK_FORMAT, format);
            goto out;
        }
    }

    eject_device(blk, 0, &err);
    if (err) {
        error_propagate(errp, err);
        goto out;
    }

    bdrv_flags = bdrv_is_read_only(bs) ? 0 : BDRV_O_RDWR;
    bdrv_flags |= bdrv_is_snapshot(bs) ? BDRV_O_SNAPSHOT : 0;

    qmp_bdrv_open_encrypted(bs, filename, bdrv_flags, drv, NULL, errp);

out:
    aio_context_release(aio_context);
}

/* throttling disk I/O limits */
void qmp_block_set_io_throttle(const char *device, int64_t bps, int64_t bps_rd,
                               int64_t bps_wr,
                               int64_t iops,
                               int64_t iops_rd,
                               int64_t iops_wr,
                               bool has_bps_max,
                               int64_t bps_max,
                               bool has_bps_rd_max,
                               int64_t bps_rd_max,
                               bool has_bps_wr_max,
                               int64_t bps_wr_max,
                               bool has_iops_max,
                               int64_t iops_max,
                               bool has_iops_rd_max,
                               int64_t iops_rd_max,
                               bool has_iops_wr_max,
                               int64_t iops_wr_max,
                               bool has_iops_size,
                               int64_t iops_size, Error **errp)
{
    ThrottleConfig cfg;
    BlockDriverState *bs;
    BlockBackend *blk;
    AioContext *aio_context;

    blk = blk_by_name(device);
    if (!blk) {
        error_set(errp, QERR_DEVICE_NOT_FOUND, device);
        return;
    }
    bs = blk_bs(blk);

    memset(&cfg, 0, sizeof(cfg));
    cfg.buckets[THROTTLE_BPS_TOTAL].avg = bps;
    cfg.buckets[THROTTLE_BPS_READ].avg  = bps_rd;
    cfg.buckets[THROTTLE_BPS_WRITE].avg = bps_wr;

    cfg.buckets[THROTTLE_OPS_TOTAL].avg = iops;
    cfg.buckets[THROTTLE_OPS_READ].avg  = iops_rd;
    cfg.buckets[THROTTLE_OPS_WRITE].avg = iops_wr;

    if (has_bps_max) {
        cfg.buckets[THROTTLE_BPS_TOTAL].max = bps_max;
    }
    if (has_bps_rd_max) {
        cfg.buckets[THROTTLE_BPS_READ].max = bps_rd_max;
    }
    if (has_bps_wr_max) {
        cfg.buckets[THROTTLE_BPS_WRITE].max = bps_wr_max;
    }
    if (has_iops_max) {
        cfg.buckets[THROTTLE_OPS_TOTAL].max = iops_max;
    }
    if (has_iops_rd_max) {
        cfg.buckets[THROTTLE_OPS_READ].max = iops_rd_max;
    }
    if (has_iops_wr_max) {
        cfg.buckets[THROTTLE_OPS_WRITE].max = iops_wr_max;
    }

    if (has_iops_size) {
        cfg.op_size = iops_size;
    }

    if (!check_throttle_config(&cfg, errp)) {
        return;
    }

    aio_context = bdrv_get_aio_context(bs);
    aio_context_acquire(aio_context);

    if (!bs->io_limits_enabled && throttle_enabled(&cfg)) {
        bdrv_io_limits_enable(bs);
    } else if (bs->io_limits_enabled && !throttle_enabled(&cfg)) {
        bdrv_io_limits_disable(bs);
    }

    if (bs->io_limits_enabled) {
        bdrv_set_io_limits(bs, &cfg);
    }

    aio_context_release(aio_context);
}

int hmp_drive_del(Monitor *mon, const QDict *qdict, QObject **ret_data)
{
    const char *id = qdict_get_str(qdict, "id");
    BlockBackend *blk;
    BlockDriverState *bs;
    AioContext *aio_context;
    Error *local_err = NULL;

    blk = blk_by_name(id);
    if (!blk) {
        error_report("Device '%s' not found", id);
        return -1;
    }
    bs = blk_bs(blk);

    if (!blk_legacy_dinfo(blk)) {
        error_report("Deleting device added with blockdev-add"
                     " is not supported");
        return -1;
    }

    aio_context = bdrv_get_aio_context(bs);
    aio_context_acquire(aio_context);

    if (bdrv_op_is_blocked(bs, BLOCK_OP_TYPE_DRIVE_DEL, &local_err)) {
        error_report_err(local_err);
        aio_context_release(aio_context);
        return -1;
    }

    /* quiesce block driver; prevent further io */
    bdrv_drain_all();
    bdrv_flush(bs);
    bdrv_close(bs);

    /* if we have a device attached to this BlockDriverState
     * then we need to make the drive anonymous until the device
     * can be removed.  If this is a drive with no device backing
     * then we can just get rid of the block driver state right here.
     */
    if (blk_get_attached_dev(blk)) {
        blk_hide_on_behalf_of_hmp_drive_del(blk);
        /* Further I/O must not pause the guest */
        bdrv_set_on_error(bs, BLOCKDEV_ON_ERROR_REPORT,
                          BLOCKDEV_ON_ERROR_REPORT);
    } else {
        blk_unref(blk);
    }

    aio_context_release(aio_context);
    return 0;
}

void qmp_block_resize(bool has_device, const char *device,
                      bool has_node_name, const char *node_name,
                      int64_t size, Error **errp)
{
    Error *local_err = NULL;
    BlockDriverState *bs;
    AioContext *aio_context;
    int ret;

    bs = bdrv_lookup_bs(has_device ? device : NULL,
                        has_node_name ? node_name : NULL,
                        &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    aio_context = bdrv_get_aio_context(bs);
    aio_context_acquire(aio_context);

    if (!bdrv_is_first_non_filter(bs)) {
        error_set(errp, QERR_FEATURE_DISABLED, "resize");
        goto out;
    }

    if (size < 0) {
        error_set(errp, QERR_INVALID_PARAMETER_VALUE, "size", "a >0 size");
        goto out;
    }

    if (bdrv_op_is_blocked(bs, BLOCK_OP_TYPE_RESIZE, NULL)) {
        error_set(errp, QERR_DEVICE_IN_USE, device);
        goto out;
    }

    /* complete all in-flight operations before resizing the device */
    bdrv_drain_all();

    ret = bdrv_truncate(bs, size);
    switch (ret) {
    case 0:
        break;
    case -ENOMEDIUM:
        error_set(errp, QERR_DEVICE_HAS_NO_MEDIUM, device);
        break;
    case -ENOTSUP:
        error_set(errp, QERR_UNSUPPORTED);
        break;
    case -EACCES:
        error_set(errp, QERR_DEVICE_IS_READ_ONLY, device);
        break;
    case -EBUSY:
        error_set(errp, QERR_DEVICE_IN_USE, device);
        break;
    default:
        error_setg_errno(errp, -ret, "Could not resize");
        break;
    }

out:
    aio_context_release(aio_context);
}

static void block_job_cb(void *opaque, int ret)
{
    /* Note that this function may be executed from another AioContext besides
     * the QEMU main loop.  If you need to access anything that assumes the
     * QEMU global mutex, use a BH or introduce a mutex.
     */

    BlockDriverState *bs = opaque;
    const char *msg = NULL;

    trace_block_job_cb(bs, bs->job, ret);

    assert(bs->job);

    if (ret < 0) {
        msg = strerror(-ret);
    }

    if (block_job_is_cancelled(bs->job)) {
        block_job_event_cancelled(bs->job);
    } else {
        block_job_event_completed(bs->job, msg);
    }

    bdrv_put_ref_bh_schedule(bs);
}

void qmp_block_stream(const char *device,
                      bool has_base, const char *base,
                      bool has_backing_file, const char *backing_file,
                      bool has_speed, int64_t speed,
                      bool has_on_error, BlockdevOnError on_error,
                      Error **errp)
{
    BlockBackend *blk;
    BlockDriverState *bs;
    BlockDriverState *base_bs = NULL;
    AioContext *aio_context;
    Error *local_err = NULL;
    const char *base_name = NULL;

    if (!has_on_error) {
        on_error = BLOCKDEV_ON_ERROR_REPORT;
    }

    blk = blk_by_name(device);
    if (!blk) {
        error_set(errp, QERR_DEVICE_NOT_FOUND, device);
        return;
    }
    bs = blk_bs(blk);

    aio_context = bdrv_get_aio_context(bs);
    aio_context_acquire(aio_context);

    if (bdrv_op_is_blocked(bs, BLOCK_OP_TYPE_STREAM, errp)) {
        goto out;
    }

    if (has_base) {
        base_bs = bdrv_find_backing_image(bs, base);
        if (base_bs == NULL) {
            error_set(errp, QERR_BASE_NOT_FOUND, base);
            goto out;
        }
        assert(bdrv_get_aio_context(base_bs) == aio_context);
        base_name = base;
    }

    /* if we are streaming the entire chain, the result will have no backing
     * file, and specifying one is therefore an error */
    if (base_bs == NULL && has_backing_file) {
        error_setg(errp, "backing file specified, but streaming the "
                         "entire chain");
        goto out;
    }

    /* backing_file string overrides base bs filename */
    base_name = has_backing_file ? backing_file : base_name;

    stream_start(bs, base_bs, base_name, has_speed ? speed : 0,
                 on_error, block_job_cb, bs, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        goto out;
    }

    trace_qmp_block_stream(bs, bs->job);

out:
    aio_context_release(aio_context);
}

void qmp_block_commit(const char *device,
                      bool has_base, const char *base,
                      bool has_top, const char *top,
                      bool has_backing_file, const char *backing_file,
                      bool has_speed, int64_t speed,
                      Error **errp)
{
    BlockBackend *blk;
    BlockDriverState *bs;
    BlockDriverState *base_bs, *top_bs;
    AioContext *aio_context;
    Error *local_err = NULL;
    /* This will be part of the QMP command, if/when the
     * BlockdevOnError change for blkmirror makes it in
     */
    BlockdevOnError on_error = BLOCKDEV_ON_ERROR_REPORT;

    if (!has_speed) {
        speed = 0;
    }

    /* Important Note:
     *  libvirt relies on the DeviceNotFound error class in order to probe for
     *  live commit feature versions; for this to work, we must make sure to
     *  perform the device lookup before any generic errors that may occur in a
     *  scenario in which all optional arguments are omitted. */
    blk = blk_by_name(device);
    if (!blk) {
        error_set(errp, QERR_DEVICE_NOT_FOUND, device);
        return;
    }
    bs = blk_bs(blk);

    aio_context = bdrv_get_aio_context(bs);
    aio_context_acquire(aio_context);

    /* drain all i/o before commits */
    bdrv_drain_all();

    if (bdrv_op_is_blocked(bs, BLOCK_OP_TYPE_COMMIT_SOURCE, errp)) {
        goto out;
    }

    /* default top_bs is the active layer */
    top_bs = bs;

    if (has_top && top) {
        if (strcmp(bs->filename, top) != 0) {
            top_bs = bdrv_find_backing_image(bs, top);
        }
    }

    if (top_bs == NULL) {
        error_setg(errp, "Top image file %s not found", top ? top : "NULL");
        goto out;
    }

    assert(bdrv_get_aio_context(top_bs) == aio_context);

    if (has_base && base) {
        base_bs = bdrv_find_backing_image(top_bs, base);
    } else {
        base_bs = bdrv_find_base(top_bs);
    }

    if (base_bs == NULL) {
        error_set(errp, QERR_BASE_NOT_FOUND, base ? base : "NULL");
        goto out;
    }

    assert(bdrv_get_aio_context(base_bs) == aio_context);

    if (bdrv_op_is_blocked(base_bs, BLOCK_OP_TYPE_COMMIT_TARGET, errp)) {
        goto out;
    }

    /* Do not allow attempts to commit an image into itself */
    if (top_bs == base_bs) {
        error_setg(errp, "cannot commit an image into itself");
        goto out;
    }

    if (top_bs == bs) {
        if (has_backing_file) {
            error_setg(errp, "'backing-file' specified,"
                             " but 'top' is the active layer");
            goto out;
        }
        commit_active_start(bs, base_bs, speed, on_error, block_job_cb,
                            bs, &local_err);
    } else {
        commit_start(bs, base_bs, top_bs, speed, on_error, block_job_cb, bs,
                     has_backing_file ? backing_file : NULL, &local_err);
    }
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        goto out;
    }

out:
    aio_context_release(aio_context);
}

void qmp_drive_backup(const char *device, const char *target,
                      bool has_format, const char *format,
                      enum MirrorSyncMode sync,
                      bool has_mode, enum NewImageMode mode,
                      bool has_speed, int64_t speed,
                      bool has_on_source_error, BlockdevOnError on_source_error,
                      bool has_on_target_error, BlockdevOnError on_target_error,
                      Error **errp)
{
    BlockBackend *blk;
    BlockDriverState *bs;
    BlockDriverState *target_bs;
    BlockDriverState *source = NULL;
    AioContext *aio_context;
    BlockDriver *drv = NULL;
    Error *local_err = NULL;
    int flags;
    int64_t size;
    int ret;

    if (!has_speed) {
        speed = 0;
    }
    if (!has_on_source_error) {
        on_source_error = BLOCKDEV_ON_ERROR_REPORT;
    }
    if (!has_on_target_error) {
        on_target_error = BLOCKDEV_ON_ERROR_REPORT;
    }
    if (!has_mode) {
        mode = NEW_IMAGE_MODE_ABSOLUTE_PATHS;
    }

    blk = blk_by_name(device);
    if (!blk) {
        error_set(errp, QERR_DEVICE_NOT_FOUND, device);
        return;
    }
    bs = blk_bs(blk);

    aio_context = bdrv_get_aio_context(bs);
    aio_context_acquire(aio_context);

    /* Although backup_run has this check too, we need to use bs->drv below, so
     * do an early check redundantly. */
    if (!bdrv_is_inserted(bs)) {
        error_set(errp, QERR_DEVICE_HAS_NO_MEDIUM, device);
        goto out;
    }

    if (!has_format) {
        format = mode == NEW_IMAGE_MODE_EXISTING ? NULL : bs->drv->format_name;
    }
    if (format) {
        drv = bdrv_find_format(format);
        if (!drv) {
            error_set(errp, QERR_INVALID_BLOCK_FORMAT, format);
            goto out;
        }
    }

    /* Early check to avoid creating target */
    if (bdrv_op_is_blocked(bs, BLOCK_OP_TYPE_BACKUP_SOURCE, errp)) {
        goto out;
    }

    flags = bs->open_flags | BDRV_O_RDWR;

    /* See if we have a backing HD we can use to create our new image
     * on top of. */
    if (sync == MIRROR_SYNC_MODE_TOP) {
        source = bs->backing_hd;
        if (!source) {
            sync = MIRROR_SYNC_MODE_FULL;
        }
    }
    if (sync == MIRROR_SYNC_MODE_NONE) {
        source = bs;
    }

    size = bdrv_getlength(bs);
    if (size < 0) {
        error_setg_errno(errp, -size, "bdrv_getlength failed");
        goto out;
    }

    if (mode != NEW_IMAGE_MODE_EXISTING) {
        assert(format && drv);
        if (source) {
            bdrv_img_create(target, format, source->filename,
                            source->drv->format_name, NULL,
                            size, flags, &local_err, false);
        } else {
            bdrv_img_create(target, format, NULL, NULL, NULL,
                            size, flags, &local_err, false);
        }
    }

    if (local_err) {
        error_propagate(errp, local_err);
        goto out;
    }

    target_bs = NULL;
    ret = bdrv_open(&target_bs, target, NULL, NULL, flags, drv, &local_err);
    if (ret < 0) {
        error_propagate(errp, local_err);
        goto out;
    }

    bdrv_set_aio_context(target_bs, aio_context);

    backup_start(bs, target_bs, speed, sync, on_source_error, on_target_error,
                 block_job_cb, bs, &local_err);
    if (local_err != NULL) {
        bdrv_unref(target_bs);
        error_propagate(errp, local_err);
        goto out;
    }

out:
    aio_context_release(aio_context);
}

BlockDeviceInfoList *qmp_query_named_block_nodes(Error **errp)
{
    return bdrv_named_nodes_list();
}

void qmp_blockdev_backup(const char *device, const char *target,
                         enum MirrorSyncMode sync,
                         bool has_speed, int64_t speed,
                         bool has_on_source_error,
                         BlockdevOnError on_source_error,
                         bool has_on_target_error,
                         BlockdevOnError on_target_error,
                         Error **errp)
{
    BlockBackend *blk;
    BlockDriverState *bs;
    BlockDriverState *target_bs;
    Error *local_err = NULL;
    AioContext *aio_context;

    if (!has_speed) {
        speed = 0;
    }
    if (!has_on_source_error) {
        on_source_error = BLOCKDEV_ON_ERROR_REPORT;
    }
    if (!has_on_target_error) {
        on_target_error = BLOCKDEV_ON_ERROR_REPORT;
    }

    blk = blk_by_name(device);
    if (!blk) {
        error_setg(errp, "Device '%s' not found", device);
        return;
    }
    bs = blk_bs(blk);

    aio_context = bdrv_get_aio_context(bs);
    aio_context_acquire(aio_context);

    blk = blk_by_name(target);
    if (!blk) {
        error_setg(errp, "Device '%s' not found", target);
        goto out;
    }
    target_bs = blk_bs(blk);

    bdrv_ref(target_bs);
    bdrv_set_aio_context(target_bs, aio_context);
    backup_start(bs, target_bs, speed, sync, on_source_error, on_target_error,
                 block_job_cb, bs, &local_err);
    if (local_err != NULL) {
        bdrv_unref(target_bs);
        error_propagate(errp, local_err);
    }
out:
    aio_context_release(aio_context);
}

#define DEFAULT_MIRROR_BUF_SIZE   (10 << 20)

void qmp_drive_mirror(const char *device, const char *target,
                      bool has_format, const char *format,
                      bool has_node_name, const char *node_name,
                      bool has_replaces, const char *replaces,
                      enum MirrorSyncMode sync,
                      bool has_mode, enum NewImageMode mode,
                      bool has_speed, int64_t speed,
                      bool has_granularity, uint32_t granularity,
                      bool has_buf_size, int64_t buf_size,
                      bool has_on_source_error, BlockdevOnError on_source_error,
                      bool has_on_target_error, BlockdevOnError on_target_error,
                      Error **errp)
{
    BlockBackend *blk;
    BlockDriverState *bs;
    BlockDriverState *source, *target_bs;
    AioContext *aio_context;
    BlockDriver *drv = NULL;
    Error *local_err = NULL;
    QDict *options = NULL;
    int flags;
    int64_t size;
    int ret;

    if (!has_speed) {
        speed = 0;
    }
    if (!has_on_source_error) {
        on_source_error = BLOCKDEV_ON_ERROR_REPORT;
    }
    if (!has_on_target_error) {
        on_target_error = BLOCKDEV_ON_ERROR_REPORT;
    }
    if (!has_mode) {
        mode = NEW_IMAGE_MODE_ABSOLUTE_PATHS;
    }
    if (!has_granularity) {
        granularity = 0;
    }
    if (!has_buf_size) {
        buf_size = DEFAULT_MIRROR_BUF_SIZE;
    }

    if (granularity != 0 && (granularity < 512 || granularity > 1048576 * 64)) {
        error_set(errp, QERR_INVALID_PARAMETER_VALUE, "granularity",
                  "a value in range [512B, 64MB]");
        return;
    }
    if (granularity & (granularity - 1)) {
        error_set(errp, QERR_INVALID_PARAMETER_VALUE, "granularity", "power of 2");
        return;
    }

    blk = blk_by_name(device);
    if (!blk) {
        error_set(errp, QERR_DEVICE_NOT_FOUND, device);
        return;
    }
    bs = blk_bs(blk);

    aio_context = bdrv_get_aio_context(bs);
    aio_context_acquire(aio_context);

    if (!bdrv_is_inserted(bs)) {
        error_set(errp, QERR_DEVICE_HAS_NO_MEDIUM, device);
        goto out;
    }

    if (!has_format) {
        format = mode == NEW_IMAGE_MODE_EXISTING ? NULL : bs->drv->format_name;
    }
    if (format) {
        drv = bdrv_find_format(format);
        if (!drv) {
            error_set(errp, QERR_INVALID_BLOCK_FORMAT, format);
            goto out;
        }
    }

    if (bdrv_op_is_blocked(bs, BLOCK_OP_TYPE_MIRROR, errp)) {
        goto out;
    }

    flags = bs->open_flags | BDRV_O_RDWR;
    source = bs->backing_hd;
    if (!source && sync == MIRROR_SYNC_MODE_TOP) {
        sync = MIRROR_SYNC_MODE_FULL;
    }
    if (sync == MIRROR_SYNC_MODE_NONE) {
        source = bs;
    }

    size = bdrv_getlength(bs);
    if (size < 0) {
        error_setg_errno(errp, -size, "bdrv_getlength failed");
        goto out;
    }

    if (has_replaces) {
        BlockDriverState *to_replace_bs;
        AioContext *replace_aio_context;
        int64_t replace_size;

        if (!has_node_name) {
            error_setg(errp, "a node-name must be provided when replacing a"
                             " named node of the graph");
            goto out;
        }

        to_replace_bs = check_to_replace_node(replaces, &local_err);

        if (!to_replace_bs) {
            error_propagate(errp, local_err);
            goto out;
        }

        replace_aio_context = bdrv_get_aio_context(to_replace_bs);
        aio_context_acquire(replace_aio_context);
        replace_size = bdrv_getlength(to_replace_bs);
        aio_context_release(replace_aio_context);

        if (size != replace_size) {
            error_setg(errp, "cannot replace image with a mirror image of "
                             "different size");
            goto out;
        }
    }

    if ((sync == MIRROR_SYNC_MODE_FULL || !source)
        && mode != NEW_IMAGE_MODE_EXISTING)
    {
        /* create new image w/o backing file */
        assert(format && drv);
        bdrv_img_create(target, format,
                        NULL, NULL, NULL, size, flags, &local_err, false);
    } else {
        switch (mode) {
        case NEW_IMAGE_MODE_EXISTING:
            break;
        case NEW_IMAGE_MODE_ABSOLUTE_PATHS:
            /* create new image with backing file */
            bdrv_img_create(target, format,
                            source->filename,
                            source->drv->format_name,
                            NULL, size, flags, &local_err, false);
            break;
        default:
            abort();
        }
    }

    if (local_err) {
        error_propagate(errp, local_err);
        goto out;
    }

    if (has_node_name) {
        options = qdict_new();
        qdict_put(options, "node-name", qstring_from_str(node_name));
    }

    /* Mirroring takes care of copy-on-write using the source's backing
     * file.
     */
    target_bs = NULL;
    ret = bdrv_open(&target_bs, target, NULL, options,
                    flags | BDRV_O_NO_BACKING, drv, &local_err);
    if (ret < 0) {
        error_propagate(errp, local_err);
        goto out;
    }

    bdrv_set_aio_context(target_bs, aio_context);

    /* pass the node name to replace to mirror start since it's loose coupling
     * and will allow to check whether the node still exist at mirror completion
     */
    mirror_start(bs, target_bs,
                 has_replaces ? replaces : NULL,
                 speed, granularity, buf_size, sync,
                 on_source_error, on_target_error,
                 block_job_cb, bs, &local_err);
    if (local_err != NULL) {
        bdrv_unref(target_bs);
        error_propagate(errp, local_err);
        goto out;
    }

out:
    aio_context_release(aio_context);
}

/* Get the block job for a given device name and acquire its AioContext */
static BlockJob *find_block_job(const char *device, AioContext **aio_context,
                                Error **errp)
{
    BlockBackend *blk;
    BlockDriverState *bs;

    blk = blk_by_name(device);
    if (!blk) {
        goto notfound;
    }
    bs = blk_bs(blk);

    *aio_context = bdrv_get_aio_context(bs);
    aio_context_acquire(*aio_context);

    if (!bs->job) {
        aio_context_release(*aio_context);
        goto notfound;
    }

    return bs->job;

notfound:
    error_set(errp, ERROR_CLASS_DEVICE_NOT_ACTIVE,
              "No active block job on device '%s'", device);
    *aio_context = NULL;
    return NULL;
}

void qmp_block_job_set_speed(const char *device, int64_t speed, Error **errp)
{
    AioContext *aio_context;
    BlockJob *job = find_block_job(device, &aio_context, errp);

    if (!job) {
        return;
    }

    block_job_set_speed(job, speed, errp);
    aio_context_release(aio_context);
}

void qmp_block_job_cancel(const char *device,
                          bool has_force, bool force, Error **errp)
{
    AioContext *aio_context;
    BlockJob *job = find_block_job(device, &aio_context, errp);

    if (!job) {
        return;
    }

    if (!has_force) {
        force = false;
    }

    if (job->paused && !force) {
        error_setg(errp, "The block job for device '%s' is currently paused",
                   device);
        goto out;
    }

    trace_qmp_block_job_cancel(job);
    block_job_cancel(job);
out:
    aio_context_release(aio_context);
}

void qmp_block_job_pause(const char *device, Error **errp)
{
    AioContext *aio_context;
    BlockJob *job = find_block_job(device, &aio_context, errp);

    if (!job) {
        return;
    }

    trace_qmp_block_job_pause(job);
    block_job_pause(job);
    aio_context_release(aio_context);
}

void qmp_block_job_resume(const char *device, Error **errp)
{
    AioContext *aio_context;
    BlockJob *job = find_block_job(device, &aio_context, errp);

    if (!job) {
        return;
    }

    trace_qmp_block_job_resume(job);
    block_job_resume(job);
    aio_context_release(aio_context);
}

void qmp_block_job_complete(const char *device, Error **errp)
{
    AioContext *aio_context;
    BlockJob *job = find_block_job(device, &aio_context, errp);

    if (!job) {
        return;
    }

    trace_qmp_block_job_complete(job);
    block_job_complete(job, errp);
    aio_context_release(aio_context);
}

void qmp_change_backing_file(const char *device,
                             const char *image_node_name,
                             const char *backing_file,
                             Error **errp)
{
    BlockBackend *blk;
    BlockDriverState *bs = NULL;
    AioContext *aio_context;
    BlockDriverState *image_bs = NULL;
    Error *local_err = NULL;
    bool ro;
    int open_flags;
    int ret;

    blk = blk_by_name(device);
    if (!blk) {
        error_set(errp, QERR_DEVICE_NOT_FOUND, device);
        return;
    }
    bs = blk_bs(blk);

    aio_context = bdrv_get_aio_context(bs);
    aio_context_acquire(aio_context);

    image_bs = bdrv_lookup_bs(NULL, image_node_name, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        goto out;
    }

    if (!image_bs) {
        error_setg(errp, "image file not found");
        goto out;
    }

    if (bdrv_find_base(image_bs) == image_bs) {
        error_setg(errp, "not allowing backing file change on an image "
                         "without a backing file");
        goto out;
    }

    /* even though we are not necessarily operating on bs, we need it to
     * determine if block ops are currently prohibited on the chain */
    if (bdrv_op_is_blocked(bs, BLOCK_OP_TYPE_CHANGE, errp)) {
        goto out;
    }

    /* final sanity check */
    if (!bdrv_chain_contains(bs, image_bs)) {
        error_setg(errp, "'%s' and image file are not in the same chain",
                   device);
        goto out;
    }

    /* if not r/w, reopen to make r/w */
    open_flags = image_bs->open_flags;
    ro = bdrv_is_read_only(image_bs);

    if (ro) {
        bdrv_reopen(image_bs, open_flags | BDRV_O_RDWR, &local_err);
        if (local_err) {
            error_propagate(errp, local_err);
            goto out;
        }
    }

    ret = bdrv_change_backing_file(image_bs, backing_file,
                               image_bs->drv ? image_bs->drv->format_name : "");

    if (ret < 0) {
        error_setg_errno(errp, -ret, "Could not change backing file to '%s'",
                         backing_file);
        /* don't exit here, so we can try to restore open flags if
         * appropriate */
    }

    if (ro) {
        bdrv_reopen(image_bs, open_flags, &local_err);
        if (local_err) {
            error_propagate(errp, local_err); /* will preserve prior errp */
        }
    }

out:
    aio_context_release(aio_context);
}

void qmp_blockdev_add(BlockdevOptions *options, Error **errp)
{
    QmpOutputVisitor *ov = qmp_output_visitor_new();
    BlockBackend *blk;
    QObject *obj;
    QDict *qdict;
    Error *local_err = NULL;

    /* Require an ID in the top level */
    if (!options->has_id) {
        error_setg(errp, "Block device needs an ID");
        goto fail;
    }

    /* TODO Sort it out in raw-posix and drive_new(): Reject aio=native with
     * cache.direct=false instead of silently switching to aio=threads, except
     * when called from drive_new().
     *
     * For now, simply forbidding the combination for all drivers will do. */
    if (options->has_aio && options->aio == BLOCKDEV_AIO_OPTIONS_NATIVE) {
        bool direct = options->has_cache &&
                      options->cache->has_direct &&
                      options->cache->direct;
        if (!direct) {
            error_setg(errp, "aio=native requires cache.direct=true");
            goto fail;
        }
    }

    visit_type_BlockdevOptions(qmp_output_get_visitor(ov),
                               &options, NULL, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        goto fail;
    }

    obj = qmp_output_get_qobject(ov);
    qdict = qobject_to_qdict(obj);

    qdict_flatten(qdict);

    blk = blockdev_init(NULL, qdict, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        goto fail;
    }

    if (bdrv_key_required(blk_bs(blk))) {
        blk_unref(blk);
        error_setg(errp, "blockdev-add doesn't support encrypted devices");
        goto fail;
    }

fail:
    qmp_output_visitor_cleanup(ov);
}

BlockJobInfoList *qmp_query_block_jobs(Error **errp)
{
    BlockJobInfoList *head = NULL, **p_next = &head;
    BlockDriverState *bs;

    for (bs = bdrv_next(NULL); bs; bs = bdrv_next(bs)) {
        AioContext *aio_context = bdrv_get_aio_context(bs);

        aio_context_acquire(aio_context);

        if (bs->job) {
            BlockJobInfoList *elem = g_new0(BlockJobInfoList, 1);
            elem->value = block_job_query(bs->job);
            *p_next = elem;
            p_next = &elem->next;
        }

        aio_context_release(aio_context);
    }

    return head;
}

QemuOptsList qemu_common_drive_opts = {
    .name = "drive",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_common_drive_opts.head),
    .desc = {
        {
            .name = "snapshot",
            .type = QEMU_OPT_BOOL,
            .help = "enable/disable snapshot mode",
        },{
            .name = "discard",
            .type = QEMU_OPT_STRING,
            .help = "discard operation (ignore/off, unmap/on)",
        },{
            .name = "cache.writeback",
            .type = QEMU_OPT_BOOL,
            .help = "enables writeback mode for any caches",
        },{
            .name = "cache.direct",
            .type = QEMU_OPT_BOOL,
            .help = "enables use of O_DIRECT (bypass the host page cache)",
        },{
            .name = "cache.no-flush",
            .type = QEMU_OPT_BOOL,
            .help = "ignore any flush requests for the device",
        },{
            .name = "aio",
            .type = QEMU_OPT_STRING,
            .help = "host AIO implementation (threads, native)",
        },{
            .name = "format",
            .type = QEMU_OPT_STRING,
            .help = "disk format (raw, qcow2, ...)",
        },{
            .name = "rerror",
            .type = QEMU_OPT_STRING,
            .help = "read error action",
        },{
            .name = "werror",
            .type = QEMU_OPT_STRING,
            .help = "write error action",
        },{
            .name = "read-only",
            .type = QEMU_OPT_BOOL,
            .help = "open drive file as read-only",
        },{
            .name = "throttling.iops-total",
            .type = QEMU_OPT_NUMBER,
            .help = "limit total I/O operations per second",
        },{
            .name = "throttling.iops-read",
            .type = QEMU_OPT_NUMBER,
            .help = "limit read operations per second",
        },{
            .name = "throttling.iops-write",
            .type = QEMU_OPT_NUMBER,
            .help = "limit write operations per second",
        },{
            .name = "throttling.bps-total",
            .type = QEMU_OPT_NUMBER,
            .help = "limit total bytes per second",
        },{
            .name = "throttling.bps-read",
            .type = QEMU_OPT_NUMBER,
            .help = "limit read bytes per second",
        },{
            .name = "throttling.bps-write",
            .type = QEMU_OPT_NUMBER,
            .help = "limit write bytes per second",
        },{
            .name = "throttling.iops-total-max",
            .type = QEMU_OPT_NUMBER,
            .help = "I/O operations burst",
        },{
            .name = "throttling.iops-read-max",
            .type = QEMU_OPT_NUMBER,
            .help = "I/O operations read burst",
        },{
            .name = "throttling.iops-write-max",
            .type = QEMU_OPT_NUMBER,
            .help = "I/O operations write burst",
        },{
            .name = "throttling.bps-total-max",
            .type = QEMU_OPT_NUMBER,
            .help = "total bytes burst",
        },{
            .name = "throttling.bps-read-max",
            .type = QEMU_OPT_NUMBER,
            .help = "total bytes read burst",
        },{
            .name = "throttling.bps-write-max",
            .type = QEMU_OPT_NUMBER,
            .help = "total bytes write burst",
        },{
            .name = "throttling.iops-size",
            .type = QEMU_OPT_NUMBER,
            .help = "when limiting by iops max size of an I/O in bytes",
        },{
            .name = "copy-on-read",
            .type = QEMU_OPT_BOOL,
            .help = "copy read data from backing file into image file",
        },{
            .name = "detect-zeroes",
            .type = QEMU_OPT_STRING,
            .help = "try to optimize zero writes (off, on, unmap)",
        },
        { /* end of list */ }
    },
};

QemuOptsList qemu_drive_opts = {
    .name = "drive",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_drive_opts.head),
    .desc = {
        /*
         * no elements => accept any params
         * validation will happen later
         */
        { /* end of list */ }
    },
};
