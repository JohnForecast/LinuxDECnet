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

#ifdef DEBUG
#ifndef __DNET_TRC_H__
#define __DNET_TRC_H__

void DBGtrace(char *);
void DBGtrace_bh(char *);
void DBGtrace_dump(int);
void DBGtrace_dump_bh(int);

void __init trc_init(void);

#endif
#endif
