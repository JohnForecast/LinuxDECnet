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
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/if_arp.h>
#include <net/sock.h>
#include <linux/version.h>
#include "dnet.h"

uint8_t dn_all_endnodes[ETH_ALEN] = { 0xAB, 0x00, 0x00, 0x04, 0x00, 0x00 };
uint8_t dn_all_routers[ETH_ALEN] = { 0xAB, 0x00, 0x00, 0x03, 0x00, 0x00 };
uint8_t dn_hiord[ETH_ALEN] = { 0xAA, 0x00, 0x04, 0x00, 0x00, 0x00 };

/*
 * The following multicast addresses are defined for Phase IV Prime
 */
uint8_t dn_all_primertr[ETH_ALEN] = { 0x09, 0x00, 0x2B, 0x02, 0x01, 0x0A };
uint8_t dn_unknown_dest[ETH_ALEN] = { 0x09, 0x00, 0x2B, 0x02, 0x01, 0x0B };

char *dn_ifname = NULL;
char *dn_nodeaddr = NULL;
char *dn_nodename = NULL;

struct dn_device dn_devices[2];
struct net_device *loopback_device, *default_device;

/*
 * Callback routine for device timer.
 */
void dn_dev_timer(
  struct timer_list *t
)
{
        struct dn_device *device = from_timer(device, t, timer);

        if (device->t3) {
                if (--device->t3 == 0) {
                        if (decnet_address)
                                dn_routing_tx_endnode_hello(device->dev);
                        device->t3 = device->hello;
                }
        }

        if (device->t4) {
                if (--device->t4 == 0) {
                        dn_next_entry *router;

                        if ((router = xchg(&device->router, NULL)) != NULL)
                                dn_next_release(router);
                }
        }
        device->timer.expires = jiffies + HZ;
        add_timer(&device->timer);
}

/*
 * Determine DECnet blocksize from device mtu size
 */
uint16_t mtu2blksize(
  struct net_device *dev
)
{
        uint32_t blksize = dev->mtu;

        if (blksize > 0xFFFF)
                blksize = 0xFFFF;

        blksize -= 2;

        return (uint16_t)blksize;
}

/*
 * Check if a message was received via the unknown destination multicast
 * address.
 */
int dn_dev_unknown_mcast(
  struct sk_buff *skb
)
{
        if (skb->dev->type == ARPHRD_ETHER)
                return memcmp(eth_hdr(skb)->h_dest, dn_unknown_dest, ETH_ALEN) == 0;

        return 0;
}

/*
 * Display which DECnet Phase we are currently running
 */
static int dn_phase_show(
  struct seq_file *seq,
  void *v
)
{
        seq_puts(seq, dn_IVprime ? "IV Prime\n" : "IV\n");
        return 0;
}

/*
 * Display information about a single device
 */
static void dn_display_dev(
  struct dn_device *dndev,
  struct seq_file *seq
)
{
        struct dn_next_entry *nextp = dndev->router;
        char router_buf[DN_ASCBUF_LEN];
        
        seq_printf(seq, "%-8s %1s     %04u %04u   %04lu %04lu   %04lu %04lu"
                   "   %-5hu   %03d %02x    %-10s %-7s %-7s\n",
                   dndev->dev->name ? dndev->dev->name : "???",
                   "B",
                   0, 0,
                   (unsigned long)dndev->t3, (unsigned long)dndev->hello,
                   (unsigned long)dndev->t4, (unsigned long)dndev->listen,
                   dndev->blksize,
                   0,
                   0, dndev->type,
                   nextp ? dn_addr2asc(nextp->addr, router_buf) : "",
                   "");
}

/*
 * Display information about the devices DECnet is using (can only be lo and
 * an ethernet or wifi interface).
 */
static int dn_dev_show(
  struct seq_file *seq,
  void *v
)
{
        seq_puts(seq, "Name     Flags T1   Timer1 T3   Timer3 T4   Timer4 BlkSize Pri State DevType    Router Peer\n");

        dn_display_dev(&LOOPDEVICE, seq);
        dn_display_dev(&ETHDEVICE, seq);
        return 0;
}

/*
 * Display the current revision number of the kernel module.
 */
static int dn_revision_show(
  struct seq_file *seq,
  void *v
)
{
        seq_puts(seq, DNET_REVISION "\n");
        return 0;
}

module_param(dn_nodeaddr, charp, 0);
MODULE_PARM_DESC(dn_nodeaddr, "The DECnet address of this machine as a string");

module_param(dn_nodename, charp, 0);
MODULE_PARM_DESC(dn_nodename, "The DECnet node name of this machine as a string");

module_param(dn_ifname, charp, 0444);
MODULE_PARM_DESC(dn_ifname, "The network interface to use for DECnet");

#define ISNUM(x)        (((x) >= '0') && ((x) <= '9'))
#define ISLOWER(x)      (((x) >= 'a') && ((x) <= 'z'))
#define ISUPPER(x)      (((x) >= 'A') && ((x) <= 'Z'))
#define ISALPHA(x)      (ISLOWER(x) || ISUPPER(x))
#define ISALPHANUM(x)   (ISNUM(x) || ISALPHA(x))
#define TOUPPER(x)      (ISLOWER(x) ? ((x) + ('A' - 'a')) : (x))

/*
 * Simple routine to parse an ASCII DECnet address.
 */
static int __init parse_addr(
  uint16_t *addr,
  char *str
)
{
        uint16_t area, node;

        while (*str && !(ISNUM(*str))) str++;

        if (*str == 0)
                return -1;

        if (!ISNUM(*str))
                return -1;
        area = *str++ - '0';
        if (ISNUM(*str)) {
                area *= 10;
                area += *str++ -'0';
        }

        if (*str++ != '.')
                return -1;

        if (!ISNUM(*str))
                return -1;
        node = *str++ -'0';
        if (ISNUM(*str)) {
                node *= 10;
                node += *str++ - '0';
        }
        if (ISNUM(*str)) {
                node *= 10;
                node += *str++ - '0';
        }
        if (ISNUM(*str)) {
                node *= 10;
                node += *str++ - '0';
        }

        if ((node == 0) || (node > 1023) || (area == 0) || (area > 63))
                return -1;

        if (ISALPHANUM(*str))
                return -1;

        *addr = (area << 10) | node;
        return 0;
}

/*
 * Simple routine to parse a DECnet node name.
 */
static int __init parse_name(
  char *str
)
{
        int valid = 0;
        char *cp = str;

        if ((strlen(str) > 0) && (strlen(str) <= 6)) {
                while (*str != 0) {
                        if (!ISALPHANUM(*str))
                                return -1;
                        if (ISALPHA(*str++))
                                valid = 1;
                }

                if (valid) {
                        int i = 0;

                        do {
                                node_name[i++] = TOUPPER(*cp);
                        } while (*cp++ != 0);
                        return 0;
                }
        }
        return -1;
}

int __init dn_dev_init(void)
{
        struct net_device *dev, *lo = NULL, *eth = NULL;
        int rc = 0;
        
        /*
         * Find the devices we are going to use. We already know that
         * "ifname=xxx" has been specified on the command line.
         */
        for_each_netdev(&init_net, dev) {
                if (dev->type == ARPHRD_LOOPBACK)
                        lo = dev;

                if ((dev->type == ARPHRD_ETHER) &&
                    (strcmp(dev->name, dn_ifname) == 0))
                        eth = dev;
        }

        if (lo == NULL) {
                pr_err("DECnet: loopback device not found\n");
                return -ENODEV;
        }

        if (eth == NULL) {
                pr_err("DECnet: ethernet device \"%s\" not found\n", dn_ifname);
                return -ENODEV;
        }

        memset(dn_devices, 0, sizeof(dn_devices));

        dev_hold(lo);
        dev_hold(eth);

        /*
         * Set up the loopback device
         */
        LOOPDEVICE.dev = lo;
        LOOPDEVICE.type = "loopback";
        LOOPDEVICE.blksize = mtu2blksize(lo);
        LOOPDEVICE.macAddr = loopMacAddr;

        /*
         * Set up the ethernet device
         */
        ETHDEVICE.dev = eth;
        ETHDEVICE.type = "ethernet";
        ETHDEVICE.multiplier = eth->ieee80211_ptr == NULL ? DN_BCT3MULT : DN_WT3MULT;
        ETHDEVICE.hello = DN_DEFAULT_HELLO;
        ETHDEVICE.blksize = mtu2blksize(eth);
        ETHDEVICE.macAddr = NULL;
        
        timer_setup(&ETHDEVICE.timer, dn_dev_timer, 0);
        
        dev_mc_add(eth, dn_all_endnodes);
        if (dn_IVprime)
                dev_mc_add(eth, dn_unknown_dest);

        /*
         * If the MAC address of the ethernet device does not start with
         * "AA:00:04:00" we need to operate as an Phase IV prime node
         */
#ifndef DNET_COMPAT
        if (memcmp(eth->dev_addr, dn_hiord, 4) != 0)
                dn_IVprime = 1;
#endif
        
        pr_info("DECnet: Phase IV%s, started on %s\n",
                dn_IVprime ? " Prime" : "", dn_ifname);
        
        if (dn_nodeaddr != NULL)
                if (parse_addr(&decnet_address, dn_nodeaddr)) {
                        pr_info("Invalid DECnet node address \"%s\"\n",
                                dn_nodeaddr);
                        rc = -EINVAL;
                }
        
        if (dn_nodename != NULL)
                if (parse_name(dn_nodename)) {
                        pr_info("Invalid DECnet node name \"%s\"\n",
                                dn_nodename);
                        rc = -EINVAL;
                }

        if (decnet_address) {
#ifdef DNET_COMPAT
		uint8_t ethaddr[ETH_ALEN];

		dn_dn2eth(ethaddr, decnet_address);
		if (memcmp(ethaddr, eth->addr, ETH_ALEN) != 0) {
			pr_info("DECnet address mismatch with %s device\n",
				eth->name);
			decnet_address = 0;
			rc = -EINVAL;
		} else 
#endif
		{
                	/*
                	 * Special case the first hello timer so that we
			 * only wait 2 seconds.
                	 */
                	ETHDEVICE.t3 = 2;
                	ETHDEVICE.t4 = 0;
                	ETHDEVICE.timer.expires = jiffies + HZ;
                	add_timer(&ETHDEVICE.timer);
		}
        }

#ifdef CONFIG_PROC_FS
        proc_create_single("decnet_phase", 0444, init_net.proc_net, &dn_phase_show);
        proc_create_single("decnet_dev", 0444, init_net.proc_net, &dn_dev_show);
        proc_create_single("decnet_revision", 0444, init_net.proc_net, &dn_revision_show);
#endif
        
        if (rc)
                pr_info("dn_dev_init() failed (%d)\n", rc);
        return rc;
}

void __exit dn_dev_exit(void)
{
#ifdef CONFIG_PROC_FS
        remove_proc_entry("decnet_phase", NULL);
        remove_proc_entry("decnet_dev", NULL);
        remove_proc_entry("decnet_revision", NULL);
#endif
}
