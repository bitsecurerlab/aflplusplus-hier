/*
 * PowerPC KVM support
 *
 * Copyright IBM Corp. 2008
 *
 * Authors:
 *  Hollis Blanchard <hollisb@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu-common.h"
#include "qemu/timer.h"
#include "kvm_ppc.h"
#include "sysemu/device_tree.h"
#include "qemu/main-loop.h"

#define PROC_DEVTREE_PATH "/proc/device-tree"

static QEMUTimer *kvmppc_timer;
static unsigned int kvmppc_timer_rate;

static void kvmppc_timer_hack(void *opaque)
{
    qemu_notify_event();
    timer_mod(kvmppc_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + kvmppc_timer_rate);
}

void kvmppc_init(void)
{
    /* XXX The only reason KVM yields control back to qemu is device IO. Since
     * an idle guest does no IO, qemu's device model will never get a chance to
     * run. So, until QEMU gains IO threads, we create this timer to ensure
     * that the device model gets a chance to run. */
    kvmppc_timer_rate = get_ticks_per_sec() / 10;
    kvmppc_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, &kvmppc_timer_hack, NULL);
    timer_mod(kvmppc_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + kvmppc_timer_rate);
}

