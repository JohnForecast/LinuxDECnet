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

#ifndef __DNET_DEV_H__
#define __DNET_DEV_H__

struct dn_device {
        struct net_device       *dev;
        struct timer_list       timer;
        char                    *type;
        struct dn_next_entry    *router;
        uint8_t                 *macAddr;
        uint16_t                t3;
        uint16_t                t4;
        uint16_t                hello;
        uint16_t                listen;
        uint16_t                multiplier;
        uint16_t                blksize;
        uint8_t                 iinfo;
};

extern struct dn_device dn_devices[2];
#define LOOPINDEX               0
#define ETHINDEX                1
#define LOOPDEVICE              dn_devices[LOOPINDEX]
#define ETHDEVICE               dn_devices[ETHINDEX]

extern uint8_t dn_all_endnodes[6];
extern uint8_t dn_all_routers[6];
extern uint8_t dn_hiord[6];
extern uint8_t dn_all_primertr[6];
extern uint8_t dn_unknown_dest[6];

extern char *dn_ifname;
extern char *dn_nodeaddr;
extern char *dn_nodename;

void dn_dev_timer(struct timer_list *);
uint16_t mtu2blksize(struct net_device *);
int dn_dev_unknown_mcast(struct sk_buff *);

#endif
