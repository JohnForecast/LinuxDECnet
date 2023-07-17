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

#ifndef __DNET_SYS_H__
#define __DNET_SYS_H__

#define DN_ASCBUF_LEN           9

void dn_register_sysctl(void);
void dn_unregister_sysctl(void);

extern int decnet_debug_level;
extern int decnet_log_malformed;
extern int decnet_dlyack_seq;
extern int decnet_segbufsize;
extern int decnet_outgoing_timer;
extern int decnet_NSPdelay;
extern int decnet_NSPweight;
extern int decnet_NSPretrans;
extern int decnet_ACKdelay;
extern int decnet_maxWindow;

extern char node_name[7];

#endif
