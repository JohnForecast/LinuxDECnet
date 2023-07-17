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

#ifndef __DNET_ROUTE_H__
#define __DNET_ROUTE_H__

#ifdef DNET_COMPAT
#define dn_IVprime      0
#else
extern int dn_IVprime;
#endif

extern uint16_t decnet_address;
extern uint64_t dn_rtrchange;

int dn_routing_rcv(struct sk_buff *, struct net_device *,
                   struct packet_type *, struct net_device *);
void dn_routing_tx_endnode_hello(struct net_device *);
int dn_routing_tx_long(struct sk_buff *, struct dn_next_entry *);

#endif
