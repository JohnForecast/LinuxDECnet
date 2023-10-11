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
#include "dnet.h"

#ifndef DNET_COMPAT
int dn_IVprime = 0;
#endif

uint16_t decnet_address;
uint64_t dn_rtrchange;

static uint8_t dn_eco_version[3] = { 0x02, 0x00, 0x00 };

/*
 * Process ethernet control packets. As an endnode, the only control packet
 * we handle "Ethernet Router Hello Message".
 */
static int dn_routing_ctl(
  struct sk_buff *skb
)
{
        struct dn_skb_cb *cb = DN_SKB_CB(skb);
        struct rt_eth_rtr_hello *hp;
        struct dn_next_entry *nextp;
        uint8_t fval = RT_FLG_RHELLO | (dn_IVprime ? RT_FLG_FP : 0);
        uint16_t src;

        if ((cb->rt_flags & (RT_FLG_RSVD | RT_FLG_CNTL_MSK)) == fval) {
                if (pskb_may_pull(skb, sizeof(struct rt_eth_rtr_hello))) {
                        hp = (struct rt_eth_rtr_hello *)skb->data;
                        src = dn_eth2dn(hp->id);

                        /*
                         * Only use routers in our area
                         */
                        if ((src & 0xFC00) != (decnet_address & 0xFC00))
                                goto out;

                        /*
                         * Routing control messages may only be received from
                         * directly connected systems.
                         */
                        nextp = dn_next_update_and_hold(src, eth_hdr(skb)->h_source, 1);
                        if (nextp != NULL) {
                                /*
                                 * Check if designated router has changed or
                                 * we do not have a reference to a router.
                                 */
                                if (ETHDEVICE.router != nextp) {
                                        struct dn_next_entry *old;
                                        struct dn_device *device = &ETHDEVICE;
                                        
                                        old = xchg(&ETHDEVICE.router, dn_next_clone(nextp));
                                        if (old != NULL) {
                                                dn_next_release(old);
                                        }
                                        device->iinfo = hp->iinfo;
                                        nextp->blksize = le16_to_cpu(hp->blksize);
                                        device->listen = device->multiplier * le16_to_cpu(hp->timer);
                                        dn_rtrchange = get_jiffies_64();
                                }
                                ETHDEVICE.t4 = ETHDEVICE.listen;
                                dn_next_release(nextp);
                        }
                }
        }

 out:
        kfree_skb(skb);
        return NET_RX_DROP;
}

/*
 * Process a received packet with a long header
 */
static int dn_routing_rx_long(
  struct sk_buff *skb
)
{
        struct dn_skb_cb *cb = DN_SKB_CB(skb);
        struct rt_long_hdr *hdr;
        uint8_t *ethaddr;
        
        /*
         * Check for a long header + shortest NSP packet
         */
        if (!pskb_may_pull(skb, sizeof(struct rt_long_hdr) + 1))
                goto drop;

        hdr = (struct rt_long_hdr *)skb->data;
        skb_pull(skb, sizeof(struct rt_long_hdr));
        skb_reset_transport_header(skb);

        cb->rt_flags = hdr->flags;
        
        /*
         * Destination address
         */
        if (memcmp(hdr->d_id, dn_hiord, 4) != 0)
                goto drop;
        cb->dst = dn_eth2dn(hdr->d_id);

        /*
         * Source address
         */
        if (memcmp(hdr->s_id, dn_hiord, 4) != 0)
                goto drop;
        cb->src = dn_eth2dn(hdr->s_id);

        cb->hops = hdr->visit_ct & RT_VISIT_CT;

        if (skb->dev != LOOPDEVICE.dev) {
                if (dn_IVprime) {
                        uint8_t onEthernet  = (cb->rt_flags & RT_FLG_IE) ? 1 : 0;
                        
                        /*
                         * If this packet was sent to the "Unknown Destination"
                         * multicast address, check if this packet is addressed
                         * to this node and discard the packet if not.
                         */
                        if (dn_dev_unknown_mcast(skb))
                                if (cb->dst != decnet_address)
                                        goto drop;

                        /*
                         * Update the nexthop cache
                         */
                        ethaddr = eth_hdr(skb)->h_source;
                        if (onEthernet && (cb->hops != 0))
                                ethaddr = dn_unknown_dest;
                        dn_next_update(cb->src, ethaddr, onEthernet);
                } else {
                        /*
                         * Update the nexthop cache.
                         */
                        dn_next_update(cb->src, eth_hdr(skb)->h_source, (cb->rt_flags & RT_FLG_IE) ? 1 : 0);
                }
        }

        /*
         * Pass the packet on to NSP
         */
        dn_nsp_rcv(skb);
        return NET_RX_SUCCESS;
 drop:
        kfree_skb(skb);
        return NET_RX_DROP;
}

/*
 * Process a packet received from the ethernet or loopback interface
 */
int dn_routing_rcv(
  struct sk_buff *skb,
  struct net_device *dev,
  struct packet_type *pt,
  struct net_device *orig_dev
)
{
        struct dn_skb_cb *cb = DN_SKB_CB(skb);
        uint16_t len = le16_to_cpu(*(uint16_t *)skb->data);
        uint8_t flags = 0;
        uint8_t padlen = 0;
        
        /*
         * Discard messages if we don't have an address set yet.
         */
        if (decnet_address == 0) {
                kfree_skb(skb);
                return 0;
        }
        
        /*
         * Timestamp this packet as soon as possible since it may be used to
         * compute a round-trip time for NSP.
         */
        cb->stamp = jiffies;

        if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)
                goto out;

        if ((dev == ETHDEVICE.dev) || (dev == LOOPDEVICE.dev)) {
                if (pskb_may_pull(skb, 3)) {
                        skb_pull(skb, sizeof(uint16_t));

                        if (len <= skb->len) {
                                skb_trim(skb, len);

                                flags = *skb->data;

                                /*
                                 * Remove any padding
                                 */
                                if (flags & RT_FLG_PAD) {
                                        padlen = flags & RT_FLG_PADM;
                                        if (!pskb_may_pull(skb, padlen + 1))
                                                goto drop;
                                        skb_pull(skb, padlen);
                                        flags = *skb->data;
                                }

                                skb_reset_network_header(skb);

                                cb->rt_flags = flags;

                                if (flags & RT_FLG_CONTROL)
                                        return dn_routing_ctl(skb);

                                if (((flags & RT_FLG_VER) == 0) &&
                                    ((flags & RT_FLG_LFDP) == RT_FLG_LONG))
                                        return dn_routing_rx_long(skb);
                        }
                }
        }
 drop:
        kfree_skb(skb);

 out:
        return NET_RX_DROP;
}

/*
 * Transmit an endnode hello message
 */
void dn_routing_tx_endnode_hello(
  struct net_device *dev
)
{
        struct rt_eth_end_hello *msg;
        struct sk_buff *skb;
        dn_next_entry *nextp;
        uint16_t *pktlen;
        uint8_t *dst = dn_IVprime ? dn_all_primertr : dn_all_routers;
        uint8_t flags = dn_IVprime ? RT_FLG_EHELLOP : RT_FLG_EHELLO;
        
        if ((skb = dn_alloc_skb(NULL, sizeof(*msg), GFP_ATOMIC)) != NULL) {
                skb->dev = dev;

                msg = skb_put(skb, sizeof(*msg));
                msg->flags = RT_FLG_CONTROL | flags;
                memcpy(msg->tiver, dn_eco_version, sizeof(msg->tiver));
                dn_dn2eth(msg->id, decnet_address);
                msg->iinfo = RT_II_ENDNODE;
                msg->blksize = cpu_to_le16(mtu2blksize(dev));
                msg->area = 0;
                memset(msg->seed, 0, sizeof(msg->seed));
                memset(msg->neighbor, 0, sizeof(msg->neighbor));

                if ((nextp = ETHDEVICE.router) != NULL)
                        dn_dn2eth(msg->neighbor, nextp->addr);
                msg->timer = cpu_to_le16(ETHDEVICE.hello);
                msg->mpd = 0;
                msg->datalen = 2;
                memset(msg->data, 0xAA, 2);

                pktlen = skb_push(skb, sizeof(uint16_t));
                *pktlen = cpu_to_le16(skb->len - sizeof(uint16_t));

                skb_reset_network_header(skb);

                if (dev_hard_header(skb, dev, ETH_P_DNA_RT, dst, NULL, skb->len) >= 0)
                        dev_queue_xmit(skb);
                else
                        kfree_skb(skb);
        }
}

/*
 * Transmit a message using a long routing header. Note the + 3 below is
 * because a long header occupies 21 bytes so we add a padding byte to make
 * it even.
 */
int dn_routing_tx_long(
  struct sk_buff *skb,
  struct dn_next_entry *nextp
)
{
        uint8_t *data;
        struct rt_long_hdr *hdr;
        struct dn_skb_cb *cb = DN_SKB_CB(skb);
        struct net_device *dev;
        int err, headroom;
        uint8_t *macAddr = dn_devices[nextp->deviceIndex].macAddr;
        
        skb->dev = dev = dn_devices[nextp->deviceIndex].dev;
        
        headroom = dev->hard_header_len + sizeof(struct rt_long_hdr) + 3;
        
        if (skb_headroom(skb) < headroom) {
                /*
                 * This should never occur.
                 */
                struct sk_buff *skb2 = skb_realloc_headroom(skb, headroom);

                if (skb2 == NULL) {
                        net_crit_ratelimited("dn_routing_tx_long: No memory\n");
                        kfree_skb(skb);
                        return -ENOBUFS;
                }
                consume_skb(skb);
                skb = skb2;
                net_info_ratelimited("dn_routing_tx_long: Increasing headroom\n");
        }

        data = skb_push(skb, sizeof(struct rt_long_hdr) + 3);
        hdr = (struct rt_long_hdr *)(data + 3);

        *((uint16_t *)data) = cpu_to_le16(skb->len - sizeof(uint16_t));
        *(data + sizeof(uint16_t)) = RT_FLG_PAD | 1;

        hdr->flags = RT_FLG_LONG | RT_FLG_IE | (cb->rt_flags & RT_FLG_RQR);
        hdr->d_area = hdr->d_subarea = 0;
        dn_dn2eth(hdr->d_id, cb->dst);
        hdr->s_area = hdr->s_subarea = 0;
        dn_dn2eth(hdr->s_id, cb->src);
        hdr->nl2 = 0;
        hdr->visit_ct = cb->hops & RT_VISIT_CT;
        hdr->s_class = 0;
        hdr->pt = 0;

        skb_reset_network_header(skb);

        if ((err = dev_hard_header(skb, dev, ETH_P_DNA_RT, nextp->nexthop, macAddr, skb->len)) >= 0)
                dev_queue_xmit(skb);
        else
                kfree_skb(skb);

        return err;
}

/***/
/*
 * **-Phase IV-Prime only
 */
