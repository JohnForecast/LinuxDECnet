/* SPDX-License-Identifier: GPL-2.0 */

/*
 *      John Forecast (C) 2023
 *
 * Re-implementation of the kernel code from DECnet for Linux with the
 * following changes/restrictions:
 *
 *      Ethernet (or WLAN) endnode only
 *      Latent support for Phase IV Prime
 *      Designed to be built as an external module
 */

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/kernel.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <linux/version.h>
#include <asm/ioctls.h>
#include "dnet.h"

#ifdef DEBUG
#define TRACESIZE       32
static char *tracebuf[TRACESIZE];
static int traceidx = 0;
static DEFINE_SPINLOCK(tracelock);

void DBGtrace(
  char *txt
)
{
        spin_lock(&tracelock);
        tracebuf[traceidx] = txt;
        traceidx = (traceidx + 1) & (TRACESIZE - 1);
        spin_unlock(&tracelock);
}

void DBGtrace_bh(
  char *txt
)
{
        spin_lock_bh(&tracelock);
        tracebuf[traceidx] = txt;
        traceidx = (traceidx + 1) & (TRACESIZE - 1);
        spin_unlock_bh(&tracelock);
}

void DBGtrace_dump(
  int count
)
{
        int i, idx;

        spin_lock(&tracelock);
        idx = traceidx;

        for (i = 0; i < count; i++) {
                idx = (idx - 1) & (TRACESIZE - 1);
                pr_info(" %i: %s\n", i, tracebuf[idx]);
        }
        spin_unlock(&tracelock);
}

void DBGtrace_dump_bh(
  int count
)
{
        int i, idx;

        spin_lock_bh(&tracelock);
        idx = traceidx;

        for (i = 0; i < count; i++) {
                idx = (idx - 1) & (TRACESIZE - 1);
                pr_info(" %i: %s\n", i, tracebuf[idx]);
        }
        spin_unlock_bh(&tracelock);
}

void __init trc_init(void)
{
        int i;

        for (i = 0; i < TRACESIZE; i++)
                tracebuf[i] = NULL;
}
#endif
