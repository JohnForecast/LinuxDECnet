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

#ifndef __DNET_H__
#define __DNET_H__

/*
 * This is a temporary definition to build a DECnet kernel module which:
 *
 *      - Only has Phase IV support
 *      - /proc files are (mostly) backward compatible with the previous
 *        DECnet on Linux implementation
 */
#define DNET_COMPAT

/*
 * Enable/disable debugging output (via defined/undefined and dedicated
 * debugging code e.g. dnet_trc.c)
 */
#define DEBUG

/*
 * Define the kernel revision. Note that we skipped 2.0.0 so the userland and
 * kernel can be aligned.
 */
#define DNET_REVISION   "3.0.24"

/*
 * Define the cost to be returned by network management for the ethernet
 * device.
 */
#define DNET_COST       3

struct dn_scp;

#include <net/sock.h>

#include "uapi/dn.h"

#include "dnet_proto.h"
#include "dnet_dev.h"
#include "dnet_next.h"
#include "dnet_node.h"
#include "dnet_nsp.h"
#include "dnet_route.h"
#include "dnet_sock.h"
#include "dnet_sys.h"
#include "dnet_timr.h"
#include "dnet_trc.h"

extern const struct proto_ops dnet_proto_ops;
extern struct proto dnet_proto;

/*
 * The following states MUST use the same values as the TCP_xxx states.
 */
#define DNET_ESTABLISHED        1
#define DNET_CLOSE              7
#define DNET_LISTEN             10

/*
 * Sub-channel (data or other) specific variables
 */
struct dn_subchannel {
        struct sk_buff_head     xmit_queue;

        uint16_t                num;
        uint16_t                num_rcv;
        uint16_t                ack_xmt;
        uint16_t                ack_rcv;
        uint8_t                 flowrem_sw;
        uint8_t                 flowloc_sw;
#define DN_FCVAL_DATA           0
#define DN_FCVAL_INTR           4

#define DN_SEND                 2
#define DN_DONTSEND             1
#define DN_NOCHANGE             0

        int16_t                 flowrem;
        int16_t                 flowloc;

        uint8_t                 services_rem;
        uint8_t                 services_loc;
};

/*
 * Session Control Port
 */
struct dn_scp {
        uint8_t                 state;
#define DN_O     1                      /* Open                 */
#define DN_CR    2                      /* Connect Receive      */
#define DN_DR    3                      /* Disconnect Reject    */
#define DN_DRC   4                      /* Discon. Rej. Complete*/
#define DN_CC    5                      /* Connect Confirm      */
#define DN_CI    6                      /* Connect Initiate     */
#define DN_NR    7                      /* No resources         */
#define DN_NC    8                      /* No communication     */
#define DN_CD    9                      /* Connect Delivery     */
#define DN_RJ    10                     /* Rejected             */
#define DN_RUN   11                     /* Running              */
#define DN_DI    12                     /* Disconnect Initiate  */
#define DN_DIC   13                     /* Disconnect Complete  */
#define DN_DN    14                     /* Disconnect Notificat */
#define DN_CL    15                     /* Closed               */
#define DN_CN    16                     /* Closed Notification  */

        struct dn_next_entry    *nextEntry;
        struct dn_node_entry    *nodeEntry;

        struct dn_subchannel    data;
        struct dn_subchannel    other;
  
        uint16_t                addrloc;
        uint16_t                addrrem;

        uint8_t                 info_rem;
        uint8_t                 info_loc;

        uint16_t                segsize_rem;
        uint16_t                segsize_loc;

        /*
         * Pending transactions for link service requests. In order of
         * priority to send.
         */
        uint8_t                 pending;
#define DN_PEND_INTR    0x80            /* Interrupt flow control +1 */
#define DN_PEND_SW      0x40            /* Current setting of flowloc_sw */
#define DN_PEND_IDLE    0x20            /* Idle link service message */
#define DN_PEND_NONE    0x00            /* Nothing to do */

        uint8_t                 accept_mode;
        uint8_t                 last_ci;
  
        struct optdata_dn       conndata_in;
        struct optdata_dn       conndata_out;
        struct optdata_dn       discdata_in;
        struct optdata_dn       discdata_out;
        struct accessdata_dn    accessdata;

        struct sockaddr_dn      addr;
        struct sockaddr_dn      peer;

        uint16_t                snd_window;
#define NSP_MIN_WINDOW          1
#define NSP_MAX_WINDOW          256
  
        /*
         * Count of consecutive delayed acks
         */
        int                     delayedacks;

        /*
         * Running totaal of bytes sent for current data segment
         */
        unsigned long           seg_total;
  
        struct sk_buff_head     other_receive_queue;
  
        /*
         * Fields related to the slow timer
         */
        unsigned long           stamp;
        unsigned long           persist;
        unsigned long           persist_count;
        int                     (*persist_fcn)(struct sock *);
#define PERSIST(scp, fcn) \
                  scp->persist_fcn = fcn; \
                  scp->persist_count = decnet_NSPretrans; \
                  scp->persist = dn_nsp_persist(scp)
        unsigned long           keepalive;
        void                    (*keepalive_fcn)(struct sock *);
#define DN_KEEPALIVE            (10 * HZ)
        unsigned long           ackdelay;
        unsigned long           conntimer;

        uint32_t                strTime;
};

struct dn_sock {
        struct sock             sk;
        struct dn_scp           scp;
};

static inline struct dn_scp *DN_SK(
  struct sock *sk
)
{
        return (struct dn_scp *)(sk + 1);
}

/*
 * sk_buff control buffer for DECnet.
 */
struct dn_skb_cb {
        uint16_t                dst;
        uint16_t                src;
        uint16_t                hops;
        uint16_t                dst_port;
        uint16_t                src_port;
        uint8_t                 services;
        uint8_t                 info;
        uint8_t                 rt_flags;
        uint8_t                 nsp_flags;
        uint8_t                 ack_delay;
        uint16_t                segsize;
        uint16_t                segnum;
        uint16_t                xmit_count;
        uint16_t                datalen;
        uint32_t                stamp;
        uint32_t                deadline;
};
#define DN_SKB_CB(skb)  ((struct dn_skb_cb *)(skb)->cb)

/*
 * Utility routines
 */
static inline uint16_t dn_eth2dn(
  uint8_t *ethaddr
)
{
  return (ethaddr[5] << 8) | ethaddr[4];
}

static inline uint16_t dn_saddr2dn(
  struct sockaddr_dn *saddr
)
{
        return le16_to_cpu(*(uint16_t *)saddr->sdn_nodeaddr);
}

static inline char *dn_addr2asc(
  uint16_t addr,
  char *buf
)
{
        uint16_t node, area;

        node = addr & 0x03FF;
        area = addr >> 10;
        sprintf(buf, "%hd.%hd", area, node);
        return buf;
}

static inline void dn_dn2eth(
  uint8_t *ethaddr,
  uint16_t addr
)
{
  ethaddr[0] = 0xAA;
  ethaddr[1] = 0x00;
  ethaddr[2] = 0x04;
  ethaddr[3] = 0x00;
  ethaddr[4] = addr & 0xFF;
  ethaddr[5] = addr >> 8;
}

static inline char *dn_eth2asc(
  uint8_t *ethaddr,
  char *buf
)
{
        sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
                 ethaddr[0], ethaddr[1], ethaddr[2],
                 ethaddr[3], ethaddr[4], ethaddr[5]);
        return buf;
}

/*
 * Is the receive side of the socket congested? If the buffer space
 * consumed by receive buffers is > 50% of the receive buffer space set by
 * the user (SO_RCVBUF).
 */
static __inline__ int dn_congested(
  struct sock *sk
)
{
        return atomic_read(&sk->sk_rmem_alloc) > (sk->sk_rcvbuf >> 1);
}

/*
 * Backwards compatibility for compilers earlier than GCC7
 */
#ifndef fallthrough
#define fallthrough     do {} while (0)         /* fallthrough */
#endif

#define ZEROSOCKADDR_DN(p)      memset((p), 0, sizeof(*p));     \
  (p)->sdn_family = AF_DECnet

int dn_sockaddr2username(struct sockaddr_dn *, uint8_t *, uint8_t);
int dn_username2sockaddr(uint8_t *, int, struct sockaddr_dn *, uint8_t *);
struct sk_buff *dn_alloc_skb(struct sock *, int, gfp_t);

extern long decnet_mem[3];
extern int decnet_wmem[3];
extern int decnet_rmem[3];

#endif
