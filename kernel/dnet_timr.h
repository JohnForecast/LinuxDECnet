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

#ifndef __DNET_TIMR_H__
#define __DNET_TIMR_H__

void dn_keepalive(struct sock *);
void dn_start_slow_timer(struct sock *);
void dn_stop_slow_timer(struct sock *);

#endif
