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
#include <linux/if_arp.h>
#include <linux/filter.h>
#include <net/sock.h>
#include <linux/version.h>
#include <linux/swap.h>
#include "dnet.h"

struct sockaddr_dn dummyname = {
        AF_DECnet,
        0,
        0,
        5, "Linux"
};

static int dn_nsp_rcv_gen(struct sock *, struct sk_buff *, uint8_t *);
static int dn_nsp_rcv_data(struct sock *, struct sk_buff *, uint8_t *);
static int dn_nsp_rcv_ls(struct sock *, struct sk_buff *, uint8_t *);
static int dn_nsp_rcv_ci(struct sock *, struct sk_buff *, uint8_t *);
static int dn_nsp_rcv_ciack(struct sock *, struct sk_buff *, uint8_t *);
static int dn_nsp_rcv_cc(struct sock *, struct sk_buff *, uint8_t *);
static int dn_nsp_rcv_interrupt(struct sock *, struct sk_buff *, uint8_t *);
static int dn_nsp_rcv_di(struct sock *, struct sk_buff *, uint8_t *);
static int dn_nsp_rcv_dc(struct sock *, struct sk_buff *, uint8_t *);
  
/*
 * Table of minimum lengths for NSP message types. A value of -1 indicates an
 * invalid message type, 0 means a valid message type but not supported by
 * this implementation. This table is indexed by the SUBTYPE and TYPE
 * fields of the message flags byte.
 */
static int16_t minlen[32] = {
        sizeof(nsp_header) + 1, /* 00000 - data segment (middle segment) */
        sizeof(nsp_header) + 1, /* 00001 - data acknowledgement */
        0,                      /* 00010 - no operation */
        -1,                     /* 00011 - reserved */
        sizeof(nsp_header) + 1, /* 00100 - link service */
        sizeof(nsp_header) + 1, /* 00101 - other-data acknowledgement */
        sizeof(nsp_ci) + 1,     /* 00110 - connect initiate */
        -1,                     /* 00111 - reserved */
        sizeof(nsp_header) + 1, /* 01000 - data segment (first segment) */
        sizeof(nsp_ciack),      /* 01001 - connect acknowledgement */
        sizeof(nsp_cc),         /* 01010 - connect confirm */
        -1,                     /* 01011 - reserved */
        sizeof(nsp_header) + 1, /* 01100 - interrupt */
        -1,                     /* 01101 - reserved */
        sizeof(nsp_di),         /* 01110 - disconnect initiate */
        -1,                     /* 01111 - reserved */
        sizeof(nsp_header) + 1, /* 10000 - data segment (last segment) */
        -1,                     /* 10001 - reserved */
        sizeof(nsp_dc),         /* 10010 - disconnect confirm */
        -1,                     /* 10011 - reserved */
        -1,                     /* 10100 - reserved */
        -1,                     /* 10101 - reserved */
        0,                      /* 10110 - phase II node init */
        -1,                     /* 10111 - reserved */
        sizeof(nsp_header) + 1, /* 11000 - data segment (single segment) */
        -1,                     /* 11001 - reserved */
        sizeof(nsp_ci) + 1,     /* 11010 - retransmitted connect initiate */
        -1,                     /* 11011 - reserved */
        -1,                     /* 11100 - reserved */
        -1,                     /* 11101 - reserved */
        -1,                     /* 11110 - reserved */
        -1                      /* 11111 - reserved */
};

/*
 * Message dispatch table.
 */
static int (*dispatch[32])(struct sock *, struct sk_buff *, uint8_t *) = {
        dn_nsp_rcv_gen,         /* 00000 - data segment (middle segment) */
        dn_nsp_rcv_gen,         /* 00001 - data acknowledgement */
        NULL,                   /* 00010 - no operation */
        NULL,                   /* 00011 - reserved */
        dn_nsp_rcv_gen,         /* 00100 - link service */
        dn_nsp_rcv_gen,         /* 00101 - other-data acknowledgement */
        dn_nsp_rcv_ci,          /* 00110 - connect initiate */
        NULL,                   /* 00111 - reserved */
        dn_nsp_rcv_gen,         /* 01000 - data segment (first segment) */
        dn_nsp_rcv_ciack,       /* 01001 - connect acknowledgement */
        dn_nsp_rcv_cc,          /* 01010 - connect confirm */
        NULL,                   /* 01011 - reserved */
        dn_nsp_rcv_gen,         /* 01100 - interrupt */
        NULL,                   /* 01101 - reserved */
        dn_nsp_rcv_di,          /* 01110 - disconnect initiate */
        NULL,                   /* 01111 - reserved */
        dn_nsp_rcv_gen,         /* 10000 - data segment (last segment) */
        NULL,                   /* 10001 - reserved */
        dn_nsp_rcv_dc,          /* 10010 - disconnect confirm */
        NULL,                   /* 10011 - reserved */
        NULL,                   /* 10100 - reserved */
        NULL,                   /* 10101 - reserved */
        NULL,                   /* 10110 - phase II node init */
        NULL,                   /* 10111 - reserved */
        dn_nsp_rcv_gen,         /* 11000 - data segment (single segment) */
        NULL,                   /* 11001 - reserved */
        NULL,                   /* 11010 - retransmitted connect initiate */
        NULL,                   /* 11011 - reserved */
        NULL,                   /* 11100 - reserved */
        NULL,                   /* 11101 - reserved */
        NULL,                   /* 11110 - reserved */
        NULL                    /* 11111 - reserved */
};

/*
 * Table of error codes to be returned when we receive a malformed connect
 * initiate message. A zero entry means "don't reply" otherwise a disconnect
 * initiate message is sent with the specified reason code.
 */
static struct {
        uint16_t                reason;
        const char              *text;
} ci_err_table[] = {
  { 0,                  "CI: Truncated message" },
  { NSP_REASON_ID,      "CI: Destination username error" },
  { NSP_REASON_ID,      "CI: Destination username type" },
  { NSP_REASON_US,      "CI: Source username error" },
  { 0,                  "CI: Truncated at menuver" },
  { 0,                  "CI: Truncated before access or user data" },
  { NSP_REASON_IO,      "CI: Access data format error" },
  { NSP_REASON_IO,      "CI: User data format error" }
};

/*
 * Log a malformed NSP message
 */
static void dn_nsp_log_malformed(
  struct sk_buff *skb,
  const char *msg
)
{
        if (decnet_log_malformed) {
                char *devname = skb->dev ? skb->dev->name : "???";
                struct dn_skb_cb *cb = DN_SKB_CB(skb);

                net_info_ratelimited("DECnet: Bad packet (%s) dev=%s "
                                     "src=0x%04hx dst=0x%04hx "
                                     "srcport=0x%04hx dstport=0x%04hx\n",
                                     msg, devname,
                                     cb->src, cb->dst,
                                     cb->src_port, cb->dst_port);
        }
}

/*
 * Drop packets which have been acknowledged
 */
static int dn_nsp_check_xmt_q(
  struct sock *sk,
  struct sk_buff *skb,
  struct sk_buff_head *q,
  uint16_t acknum,
  int oth
)
{
        struct dn_skb_cb *cb = DN_SKB_CB(skb);
        struct dn_scp *scp = DN_SK(sk);
        struct sk_buff *skb2, *n;
        int wakeup = 0;
        int try_retrans = 0;
        uint32_t acktime = cb->stamp;
        uint32_t pkttime;
        uint16_t xmit_count;
        uint16_t segnum;

        skb_queue_walk_safe(q, skb2, n) {
                struct dn_skb_cb *cb2 = DN_SKB_CB(skb2);

                segnum = cb2->segnum;
                
                if (dn_before_or_equal(segnum, acknum)) {
			uint8_t delayed = cb2->ack_delay;

                        /*
                         * A packet is being acknowledged so wakeup the
                         * sending process.
                         */
                        wakeup = 1;

                        pkttime = cb2->stamp;
                        xmit_count = cb2->xmit_count;

                        /*
                         * Remove the ack'd packet and free it. Don't reference
			 * skb2 or cb2 after this point
                         */
                        skb_unlink(skb2, q);
                        kfree_skb(skb2);

                        /*
                         * We shouldn't see acknowledgements for packets
                         * which haven't been sent yet.
                         */
                        WARN_ON(xmit_count == 0);

			/*
			 * If the packet was orginally sent without the delay
			 * ack option, we can use it to update the round-trip
			 * estimate.
			 */
			if (delayed == 0) {
				uint32_t delay = acktime - pkttime;

				dn_node_update_delay(scp->nodeEntry, delay);
			}

			/*
			 * Open the window a little further if this is a
			 * data ack.
			 */
			if (!oth)
				if (scp->snd_window < decnet_maxWindow)
					scp->snd_window++;

                        /*
                         * If this packet is the last one to be acknowledged
                         * and has been sent more than once then we want to
                         * send the next packet in the queue again (assumes
                         * the remote host does go-back-N error control).
                         */
                        try_retrans = xmit_count > 1;
                } else break;
        }

        /*
         * If there is another buffer waiting for acknowledgement, update
         * the persist timer.
         */
        if (skb2 != (struct sk_buff *)q) {
		unsigned long deadline = (unsigned long)(DN_SKB_CB(skb2)->deadline);
                unsigned long delta = deadline - jiffies;

		/*
		 * If the deadline for this message has already passed,
		 * force the delay to 1 tick so the retransmission will
		 * happen at the next timeout and try to retransmit it as
		 * soon as possible.
		 */
		if (time_after_eq(jiffies, deadline)) {
			delta = 1;
			try_retrans = 1;
		}

                if ((scp->persist == 0) || (delta < scp->persist))
                        scp->persist = delta;
        }
        
        /*
         * If both transmit queues are now empty, cancel the persist timer
         */
        if (skb_queue_empty(&scp->data.xmit_queue) &&
            skb_queue_empty(&scp->other.xmit_queue))
                scp->persist = 0;
        
        if (oth)
                dn_nsp_sched_pending(sk, DN_PEND_NONE);

        if (try_retrans)
                dn_nsp_xmt_socket(sk);

        return wakeup;
}

/*
 * Process an ACK from a received message
 */
static void dn_nsp_ack(
  struct sock *sk,
  struct sk_buff *skb,
  uint16_t ack
)
{
        struct dn_scp *scp = DN_SK(sk);
        uint16_t type = ((ack >> 12) & 0x0003);
        int wakeup = 0;

        /*
         * Before calling this routine, we have flipped the cross channel bit
         * if the received message was on the other subchannel. This way we
         * can use a combination of NSP_ACK_CROSS/NSP_ACK_NAK to determine
         * the type of the ACK.
         */
        switch (type) {
                case 0: /* ACK - Data */
                        if (dn_after(ack, scp->data.ack_rcv)) {
                                scp->data.ack_rcv = ack & NSP_SEG_MASK;
                                wakeup |= dn_nsp_check_xmt_q(sk, skb,
                                                             &scp->data.xmit_queue,
                                                             ack, 0);
                        }
                        break;
                        
                case 1: /* NAK - Data */
                        break;
                        
                case 2: /* ACK - Other */
                        if (dn_after(ack, scp->other.ack_rcv)) {
                                scp->other.ack_rcv = ack & NSP_SEG_MASK;
                                wakeup |= dn_nsp_check_xmt_q(sk, skb,
                                                             &scp->other.xmit_queue,
                                                             ack, 1);
                        }
                        break;
                        
                case 3: /* NAK - Other */
                        break;
        }

        if (wakeup && !sock_flag(sk, SOCK_DEAD))
                sk->sk_state_change(sk);
}

/*
 * General purpose ACK processor
 */
static int dn_nsp_process_ack(
  struct sock *sk,
  struct sk_buff *skb,
  int oth
)
{
        uint16_t *ptr = (uint16_t *)skb->data;
        int len = 0;
        uint16_t ack;

        if (skb->len < sizeof(uint16_t))
                return len;

        if (((ack = le16_to_cpu(*ptr)) & NSP_ACK_PRESENT) != 0) {
                skb_pull(skb, sizeof(uint16_t));
                ptr++;
                len += sizeof(uint16_t);
                ack &= ~NSP_ACK_CROSS;
                
                if (oth)
                        ack ^= NSP_ACK_CROSS;
                dn_nsp_ack(sk, skb, ack);

                if (skb->len < sizeof(uint16_t))
                        return len;

                if (((ack = le16_to_cpu(*ptr)) & NSP_ACK_PRESENT) != 0) {
                        skb_pull(skb, sizeof(uint16_t));
                        len += sizeof(uint16_t);
                        ack |= NSP_ACK_CROSS;
                        
                        if (oth)
                                ack ^= NSP_ACK_CROSS;
                        dn_nsp_ack(sk, skb, ack);
                }
        }
        return len;
}

/*
 * Check the validity of a image field in an incoming NSP message
 */
static inline int dn_nsp_check_if(
  uint8_t **pptr,
  int *len,
  uint8_t max
)
{
        uint8_t *ptr = *pptr;
        uint8_t flen = *ptr++;

        (*len)--;

        if (flen > max)
                return -1;
        if (flen > *len)
                return -1;

        *len -= flen;
        *pptr = ptr + flen;
        return 0;
}

/*
 * Validate an incoming connect initiate message and find a socket which
 * is listening on the target object.
 */
static struct sock *dn_nsp_find_listener(
  struct sk_buff *skb,
  uint16_t *reason
)
{
        struct dn_skb_cb *cb = DN_SKB_CB(skb);
        struct nsp_ci *msg;
        struct sockaddr_dn dstaddr, srcaddr;
        int dstlen, srclen;
        uint8_t type = 0;
        uint8_t *ptr;
        int len;
        int err = 0;
        uint8_t menuver;

        /*
         * Push the NSP header which we removed in dn_nsp_rcv() back
         * onto the skb
         */
        skb_push(skb, sizeof(struct nsp_header));
        msg = (struct nsp_ci *)skb->data;
        
        memset(&dstaddr, 0, sizeof(struct sockaddr_dn));
        memset(&srcaddr, 0, sizeof(struct sockaddr_dn));

        /*
         * 1. Decode and remove remaining message header
         */
        cb->services = msg->services;
        cb->info = msg->info;
        cb->segsize = le16_to_cpu(msg->segsize);

        if (!pskb_may_pull(skb, sizeof(struct nsp_ci)))
                goto err_out;

        skb_pull(skb, sizeof(struct nsp_ci));

        len = skb->len;
        ptr = skb->data;

        /*
         * 2. Check destination end username format
         */
        dstlen = dn_username2sockaddr(ptr, len, &dstaddr, &type);
        err++;
        if (dstlen < 0)
                goto err_out;

        err++;
        if (type > 1)
                goto err_out;

        len -= dstlen;
        ptr += dstlen;

        /*
         * 3. Check source end username format
         */
        srclen = dn_username2sockaddr(ptr, len, &srcaddr, &type);
        err++;
        if (srclen < 0)
                goto err_out;

        len -= srclen;
        ptr += srclen;
        err++;
        if (len < 1)
                goto err_out;

        menuver = *ptr++;
        len--;

        /*
         * 4. Check that optional data actually exists if menuver says it does
         */
        err++;
        if (((menuver & (NSP_MENU_ACC | NSP_MENU_USR)) != 0) && (len < 1))
                goto err_out;

        /*
         * 5. Check optional access data format
         */
        err++;
        if ((menuver & NSP_MENU_ACC) != 0) {
                if (dn_nsp_check_if(&ptr, &len, 39))
                        goto err_out;
                if (dn_nsp_check_if(&ptr, &len, 39))
                        goto err_out;
                if (dn_nsp_check_if(&ptr, &len, 39))
                        goto err_out;
        }

        /*
         * 6. Check optional data format
         */
        err++;
        if ((menuver & NSP_MENU_USR) != 0)
                if (dn_nsp_check_if(&ptr, &len, 16))
                        goto err_out;

        /*
         * 7. Lookup socket based on destination username
         */
        return dn_sk_find_listener(&dstaddr);
        
 err_out:
        dn_nsp_log_malformed(skb, ci_err_table[err].text);
        *reason = ci_err_table[err].reason;
        return NULL;
}

/*
 * Generate an apprpriate response if there was no socket associated
 * with an incoming message.
 */
static int dn_nsp_no_sock(
  struct sk_buff *skb,
  uint16_t reason
)
{
        struct dn_skb_cb *cb = DN_SKB_CB(skb);
        int ret = NET_RX_DROP;

        if (reason != NSP_REASON_OK) {
                switch (cb->nsp_flags) {
                        case NSP_MSG_CI:
                        case NSP_MSG_RCI:
                                dn_nsp_return_disc(skb, NSP_MSG_DI, reason);
                                ret = NET_RX_SUCCESS;
                                break;
                                
                        case NSP_MSG_CC:
                                dn_nsp_return_disc(skb, NSP_MSG_DC, reason);
                                ret = NET_RX_SUCCESS;
                                break;
                }
        }
        kfree_skb(skb);
        return ret;
}

/*
 *  Process a returned Connect Initiate message
 */
static void dn_nsp_returned_ci(
  struct sock *sk
)
{
        struct dn_scp *scp = DN_SK(sk);

        if (scp->state == DN_CI) {
                scp->state = DN_NC;
                sk->sk_state = DNET_CLOSE;
                sk->sk_err = EHOSTUNREACH;
                if (!sock_flag(sk, SOCK_DEAD))
                        sk->sk_state_change(sk);
        }
}

/*
 * Process a received message with a standard NSP data-type header (data,
 * ack, other-ack, other-data).
 */
int dn_nsp_rcv_gen(
  struct sock *sk,
  struct sk_buff *skb,
  uint8_t *ptr
)
{
        struct dn_scp *scp = DN_SK(sk);
        struct dn_skb_cb *cb = DN_SKB_CB(skb);
        int other = 1;

        /*
         * Any of these message types can kick a CC socket into the
         * RUN state.
         */
        if ((scp->state == DN_CC) && !sock_flag(sk, SOCK_DEAD)) {
                scp->state = DN_RUN;
                scp->persist = 0;

                sk->sk_state = DNET_ESTABLISHED;
                sk->sk_state_change(sk);

                /*
                 * If the message was received with the Intra-Ethernet bit
                 * clear, revert to the "SEGMENT BUFFER SIZE" parameter
                 * since traffic will be going off ethernet.
                 */
                if ((cb->rt_flags & RT_FLG_IE) == 0)
                        scp->segsize_rem =
                                decnet_segbufsize - NSP_MAX_DATAHDR;
        }

        if ((cb->nsp_flags & (NSP_TYP_MASK|NSP_MSG_ILS)) == NSP_TYP_DATA)
                other = 0;
        if (cb->nsp_flags == NSP_TYP_ACK)
                other = 0;

        /*
         * Process the ACK fields from the message
         */
        dn_nsp_process_ack(sk, skb, other);

        /*
         * Check for messages which carry some additional data.
         */
        if ((cb->nsp_flags & NSP_TYP_MASK) == NSP_TYP_DATA) {
                if (scp->state != DN_RUN)
                        goto drop;

                ptr = skb->data;
                
                switch (cb->nsp_flags) {
                        case NSP_MSG_LS:
                                dn_nsp_rcv_ls(sk, skb, ptr);
                                break;
                                
                        case NSP_MSG_INTR:
                                dn_nsp_rcv_interrupt(sk, skb, ptr);
                                break;
                                
                        default:
                                dn_nsp_rcv_data(sk, skb, ptr);
                }
                return NET_RX_SUCCESS;
        }
 drop:
        kfree_skb(skb);
        return NET_RX_SUCCESS;
}

/*
 * Process a received data segment message.
 */
int dn_nsp_rcv_data(
  struct sock *sk,
  struct sk_buff *skb,
  uint8_t *ptr
)
{
        int queued = 0;
        uint16_t segnum;
        struct dn_skb_cb *cb = DN_SKB_CB(skb);
        struct dn_scp *scp = DN_SK(sk);

        if (skb->len >= sizeof(uint16_t)) {
                cb->segnum = segnum = le16_to_cpu(*(uint16_t *)ptr);
                skb_pull(skb, sizeof(uint16_t));

                if (seq_next(scp->data.num_rcv, segnum)) {
                        rcu_read_lock();
                        if (sock_queue_rcv_skb(sk, skb) == 0) {
                                seq_add(&scp->data.num_rcv, 1);
                                queued = 1;
                                Count_user_rcvd(scp->nodeEntry, skb->len);
                        }
                        rcu_read_unlock();

                        if ((scp->data.flowloc_sw == DN_SEND) &&
                            dn_congested(sk)) {
                                scp->data.flowloc_sw = DN_DONTSEND;
                                dn_nsp_sched_pending(sk, DN_PEND_SW);
                        }
                }

                if (queued && delayack(segnum)) {
                        scp->ackdelay = decnet_ACKdelay * HZ;
                } else dn_nsp_xmt_ack_data(sk);
        }

        if (!queued)
                kfree_skb(skb);
        return NET_RX_SUCCESS;
}

/*
 * Process a received link service message.
 */
int dn_nsp_rcv_ls(
  struct sock *sk,
  struct sk_buff *skb,
  uint8_t *ptr
)
{
        struct dn_scp *scp = DN_SK(sk);
        uint16_t segnum;
        uint8_t lsflags;
        int8_t fcval;
        int wakeup = 0;
        uint8_t fctype = scp->data.services_rem & NSP_FCOPT_MASK;

        if (skb->len < (sizeof(uint16_t) + (2 * sizeof(uint8_t))))
                goto drop;

        segnum = le16_to_cpu(*(uint16_t *)ptr);
        ptr += sizeof(uint16_t);
        lsflags = *ptr++;
        fcval = *ptr;

        if (seq_next(scp->other.num_rcv, segnum)) {
		if ((lsflags & NSP_FCVAL_MASK) == NSP_FCVAL_DATA) {
                        switch (lsflags & NSP_FCMOD_MASK) {
				case NSP_FCMOD_NOC:
					if (fcval < 0) {
						unsigned char pfcval = -fcval;

						if ((scp->data.flowrem > pfcval) &&
						    (fctype == NSP_FCOPT_MSG)) {
							scp->data.flowrem -= pfcval;
						}
					} else if (fcval > 0) {
						scp->data.flowrem += fcval;
						wakeup = 1;
					}
					break;
                                                
				case NSP_FCMOD_NOSND:
					scp->data.flowrem_sw = DN_DONTSEND;
					break;
                                                
				case NSP_FCMOD_SND:
					scp->data.flowrem_sw = DN_SEND;
					dn_nsp_xmt_socket(sk);
					wakeup = 1;
					break;
                                                
				default:
					goto drop;
			}
		} else {
			if ((lsflags & NSP_FCVAL_MASK) == NSP_FCVAL_INTR) {
				if (fcval > 0) {
					scp->other.flowrem += fcval;
					wakeup = 1;
				}
			}
		}
                                
		seq_add(&scp->other.num_rcv, 1);

                if (wakeup && !sock_flag(sk, SOCK_DEAD))
                        sk->sk_state_change(sk);
        }

        dn_nsp_xmt_ack_oth(sk);
        kfree_skb(skb);
        return NET_RX_SUCCESS;
        
 drop:
        kfree_skb(skb);
        return NET_RX_DROP;
}

/*
 * Process a received connect initiate message
 */
int dn_nsp_rcv_ci(
  struct sock *sk,
  struct sk_buff *skb,
  uint8_t *ptr
)
{
        if (sk_acceptq_is_full(sk)) {
                kfree_skb(skb);
                return NET_RX_DROP;
        }

        sk_acceptq_added(sk);
        skb_queue_tail(&sk->sk_receive_queue, skb);
        sk->sk_state_change(sk);

        return NET_RX_SUCCESS;
}

/*
 * Pre-process a received connect initiate message when we do not yet have
 * a socket.
 */
static int dn_nsp_preprocess_ci(
  struct sk_buff *skb
)
{
        struct dn_skb_cb *cb = DN_SKB_CB(skb);
        struct sock *sk;
        uint16_t reason;
        
        if ((cb->rt_flags & RT_FLG_RTS) != 0) {
                if ((sk = dn_sk_check_returned(skb)) != NULL) {
                        dn_nsp_returned_ci(sk);
                        sock_put(sk);
                }
                kfree_skb(skb);
                return NET_RX_SUCCESS;
        }

        sk = dn_nsp_find_listener(skb, &reason);
        if (sk != NULL) {
                struct dn_scp *scp = DN_SK(sk);
                
                scp->stamp = jiffies;

                if (unlikely(skb_linearize(skb)))
                        goto drop;

                return sk_receive_skb(sk, skb, 0);
        }
 drop:
        kfree_skb(skb);
        return NET_RX_DROP;
}

/*
 * Process a received connect initiate acknowledgement message.
 */
int dn_nsp_rcv_ciack(
  struct sock *sk,
  struct sk_buff *skb,
  uint8_t *ptr
)
{
        struct dn_scp *scp = DN_SK(sk);

        if (scp->state == DN_CI) {
                uint32_t delta = jiffies - scp->strTime;
                
                scp->state = DN_CD;
                scp->persist = 0;

                if (scp->last_ci == NSP_MSG_CI)
                        dn_node_update_delay(scp->nodeEntry, delta);
                /* start outgoing timer */
        }
        kfree_skb(skb);
        return NET_RX_SUCCESS;
}

/*
 * Process a received connect confirm message.
 */
int dn_nsp_rcv_cc(
  struct sock *sk,
  struct sk_buff *skb,
  uint8_t *ptr
)
{
        struct dn_skb_cb *cb = DN_SKB_CB(skb);
        struct dn_scp *scp = DN_SK(sk);

        if (skb->len < 4)
                goto out;

        cb->services = *ptr++;
        cb->info = *ptr++;
        cb->segsize = le16_to_cpu(*(__le16 *)ptr);
        skb_pull(skb, 4);

        if ((scp->state == DN_CI) || (scp->state == DN_CD)) {
                /*
                 * Cancel outstanding timers
                 */
                scp->persist = 0;
                scp->conntimer = 0;

                scp->addrrem = cb->src_port;
                sk->sk_state = DNET_ESTABLISHED;

                scp->state = DN_RUN;
                scp->data.services_rem = cb->services;
                scp->info_rem = cb->info;
                scp->segsize_rem = cb->segsize;

		/*
		 * If the Connect Confirm message was received with the
		 * Intra-Ethernet bit clear, revert to the "SEGMENT BUFFER
		 * SIZE" parameter since traffic will be going off ethernet.
		 */
		if ((cb->rt_flags & RT_FLG_IE) == 0)
			scp->segsize_rem =
			  decnet_segbufsize - NSP_MAX_DATAHDR;

		/*
		 * Update the local segment size in case it has changed.
		 */
		scp->segsize_loc = dn_eth2segsize(scp->nextEntry);

                if (skb->len > 0) {
                        uint16_t dlen = *skb->data;

                        if ((dlen <= 16) && (dlen <= skb->len)) {
                                scp->conndata_in.opt_optl = cpu_to_le16(dlen);
                                skb_copy_from_linear_data_offset(skb, 1,
                                             scp->conndata_in.opt_data, dlen);
                        }
                }
                dn_nsp_sched_pending(sk, DN_PEND_IDLE);
                if (!sock_flag(sk, SOCK_DEAD))
                        sk->sk_state_change(sk);
                
        }
        
 out:
        kfree_skb(skb);
        return NET_RX_SUCCESS;
}

/*
 * Simplified version of sock_queue_rcv_skb() (from sock.c) to queue a
 * received interrupt message.
 */
static __inline__ int dn_queue_oth_skb(
  struct sock *sk,
  struct sk_buff *skb
)
{
        struct dn_scp *scp = DN_SK(sk);
        int err;
        unsigned long flags;

        err = sk_filter(sk, skb);
        if (err)
                return err;

        skb->dev = NULL;
        skb_set_owner_r(skb, sk);

        spin_lock_irqsave(&scp->other_receive_queue.lock, flags);
        sock_skb_set_dropcount(sk, skb);
        __skb_queue_tail(&scp->other_receive_queue, skb);
        spin_unlock_irqrestore(&scp->other_receive_queue.lock, flags);

        if (!sock_flag(sk, SOCK_DEAD))
                sk->sk_data_ready(sk);

        return 0;
}

/*
 * Process a received interrupt message.
 *
 * Ideally this should be the same as dn_nsp_rcv_data() except using a
 * different socket buffer queue. Since the flow control mechanism limits
 * the number of interrupt messages to 1, we can simplify the logic by not
 * checking for queue full and allow the receive memory allocation to
 * overflow by 16 + overhead. This also means that interrupt messages will
 * not be blocked by the data subchannel.
 */
int dn_nsp_rcv_interrupt(
  struct sock *sk,
  struct sk_buff *skb,
  uint8_t *ptr
)
{
        struct dn_scp *scp = DN_SK(sk);
        struct dn_skb_cb *cb = DN_SKB_CB(skb);
        uint16_t segnum;
        int queued = 0;

        if (skb->len >= sizeof(uint16_t)) {
                cb->segnum = segnum = le16_to_cpu(*(uint16_t *)ptr);
                skb_pull(skb, sizeof(uint16_t));

                if (seq_next(scp->other.num_rcv, segnum)) {
                        rcu_read_lock();
                        if (dn_queue_oth_skb(sk, skb) == 0) {
                                seq_add(&scp->other.num_rcv, 1);
                                /*** other_report? ***/
                                queued = 1;
                        }
                        rcu_read_unlock();
                }

                dn_nsp_xmt_ack_oth(sk);
        }

        if (!queued)
                kfree_skb(skb);
        return NET_RX_SUCCESS;
}

/*
 * Process a received disconnect initiate message.
 */
int dn_nsp_rcv_di(
  struct sock *sk,
  struct sk_buff *skb,
  uint8_t *ptr
)
{
        struct dn_scp *scp = DN_SK(sk);
        struct dn_skb_cb *cb = DN_SKB_CB(skb);
        uint16_t reason;

        if (skb->len < sizeof(uint16_t))
                goto drop;

        reason = le16_to_cpu(*(uint16_t *)ptr);
        skb_pull(skb, sizeof(uint16_t));
        
        memset(&scp->discdata_in, 0, sizeof(struct optdata_dn));
        scp->discdata_in.opt_status = cpu_to_le16(reason);

        if (skb->len > 0) {
                uint16_t dlen = *skb->data;

                if ((dlen <= 16) && (dlen <= skb->len)) {
                        scp->discdata_in.opt_optl = cpu_to_le16(dlen);
                        skb_copy_from_linear_data_offset(skb, 1, scp->discdata_in.opt_data, dlen);
                }
        }

        scp->addrrem = cb->src_port;
        sk->sk_state = DNET_CLOSE;

        switch (scp->state) {
                case DN_CI:
                case DN_CD:
                        scp->state = DN_RJ;
                        sk->sk_err = ECONNREFUSED;
                        scp->conntimer = 0;
                        break;
                        
                case DN_RUN:
                        sk->sk_shutdown |= SHUTDOWN_MASK;
                        scp->state = DN_DN;
                        break;
                        
                case DN_DI:
                        scp->state = DN_DIC;
                        break;
        }

        if (!sock_flag(sk, SOCK_DEAD)) {
                if (sk->sk_socket->state != SS_UNCONNECTED)
                        sk->sk_socket->state = SS_DISCONNECTING;
                sk->sk_state_change(sk);
        }

        /*
         * Only send a disconnect confirm if we have a valid remote port
         * address.
         */
        if (scp->addrrem != 0)
                dn_nsp_xmt_disc(sk, NSP_MSG_DC, NSP_REASON_DC, GFP_ATOMIC);

        PERSIST(scp, dn_sk_destroy_timer);
        kfree_skb(skb);
        return NET_RX_SUCCESS;
        
 drop:
        kfree_skb(skb);
        return NET_RX_DROP;
}

/*
 * Process a received disconnect confirm message.
 */
int dn_nsp_rcv_dc(
  struct sock *sk,
  struct sk_buff *skb,
  uint8_t *ptr
)
{
        struct dn_scp *scp = DN_SK(sk);
        uint16_t reason;

        if (skb->len == sizeof(uint16_t)) {

                reason = le16_to_cpu(*(uint16_t *)ptr);

                sk->sk_state = DNET_CLOSE;

                switch (scp->state) {
                        case DN_CI:
                                scp->state = DN_NR;
                                break;
                                
                        case DN_DR:
                                if (reason == NSP_REASON_DC)
                                        scp->state = DN_DRC;
                                if (reason == NSP_REASON_NL)
                                        scp->state = DN_CN;
                                break;
                                
                        case DN_DI:
                                scp->state = DN_DIC;
                                break;
                                
                        case DN_RUN:
                                sk->sk_shutdown |= SHUTDOWN_MASK;
                                fallthrough;
                                
                        case DN_CC:
                                scp->state = DN_CN;
                                break;
                }

                if (!sock_flag(sk, SOCK_DEAD)) {
                        if (sk->sk_socket->state != SS_UNCONNECTED)
                                sk->sk_socket->state = SS_DISCONNECTING;
                        sk->sk_state_change(sk);
                }
                
                PERSIST(scp, dn_sk_destroy_timer);
        }

        kfree_skb(skb);
        return NET_RX_SUCCESS;
}

/*
 * Process a packet received from the routing layer.
 */
int dn_nsp_rcv(
  struct sk_buff *skb
)
{
        struct dn_skb_cb *cb = DN_SKB_CB(skb);
        struct sock *sk = NULL;
        uint8_t flags, *ptr = skb->data;
        int16_t len;

        if (pskb_may_pull(skb, sizeof(uint8_t))) {
                skb_reset_transport_header(skb);

                cb->datalen = skb->len;
                cb->nsp_flags = flags = *ptr++;

                if (((flags & NSP_MBZ) == 0) &&
                    ((len = minlen[flags >> 2]) > 0)) {
                        if (pskb_may_pull(skb, len)) {
                                /*
                                 * All of the supported message formats start
                                 * off with destination and source ports (with
                                 * the exception of Connect Initiate Acks,
                                 * which we will handle specially).
                                 */
                                cb->dst_port = *(uint16_t *)ptr;
                                ptr += sizeof(uint16_t);
                                if (flags != NSP_MSG_CIACK) {
                                        cb->src_port = *(uint16_t *)ptr;
                                        ptr += sizeof(uint16_t);
                                        skb_pull(skb, sizeof(struct nsp_header));
                                } else {
                                        cb->src_port = 0;
                                        skb_pull(skb, sizeof(struct nsp_ciack));
                                }

                                /*
                                 * We have to handle Connect Initiate messages
                                 * here since they will, typically, not have an
                                 * associated socket structure.
                                 */
                                if ((flags == NSP_MSG_CI) ||
                                    (flags == NSP_MSG_RCI))
                                        return dn_nsp_preprocess_ci(skb);
                                
                                /*
                                 * We only support "Return to Sender" for
                                 * Connect Initiate and Retransmitted Connect
                                 * Initiate messages, all others are dropped.
                                 */
                                if ((cb->rt_flags & RT_FLG_RTS) != 0) {
                                        kfree_skb(skb);
                                        return NET_RX_SUCCESS;
                                }
                        
                                /*
                                 * Linearize everything except data segments
                                 */
                                if ((flags & NSP_TYP_MASK) != NSP_TYP_DATA)
                                        if (unlikely(skb_linearize(skb)))
                                                goto drop;
                        
                                /*
                                 * Look up socket
                                 */
                                sk = dn_sk_lookup_by_skb(skb);

                                if (sk != NULL) {
                                        struct dn_scp *scp = DN_SK(sk);

                                        if (scp->nodeEntry != NULL)
                                                Count_total_rcvd(scp->nodeEntry, skb->len);
                                        return sk_receive_skb(sk, skb, 0);
                                }

                                return dn_nsp_no_sock(skb, NSP_REASON_NL);
                        }
                }
        }
 drop:
        kfree_skb(skb);
        return NET_RX_DROP;
}

/*
 * Main receive routine for sockets.
 */
int dn_nsp_rcv_backlog(
  struct sock *sk,
  struct sk_buff *skb
)
{
        struct dn_skb_cb *cb = DN_SKB_CB(skb);
        
        /*
         * Dispatch to message handling routine
         */
        return dispatch[cb->nsp_flags >> 2](sk, skb, skb->data);
}

/*
 * NULL destructor for cloned messages
 */
static void dn_nsp_null_destructor(
  struct sk_buff *skb
)
{
}

/*
 * Calculate the persist time (retransmit timer).
 */
unsigned long dn_nsp_persist(
  struct dn_scp *scp
)
{
        struct dn_node_entry *nodep = scp->nodeEntry;

        if (nodep->delay == 0)
                return 5 * HZ;

        return (nodep->delay * decnet_NSPdelay) / 16;
}

/*
 * Create a common NSP header
 */
static inline uint8_t *dn_nsp_mk_header(
  struct dn_scp *scp,
  struct sk_buff *skb,
  uint8_t msgflag,
  int len
)
{
        uint8_t *ptr = skb_push(skb, len);

        BUG_ON(len < 5);

        *ptr++ = msgflag;
        *((uint16_t *)ptr) = scp->addrrem;
        ptr += sizeof(uint16_t);
        *((uint16_t *)ptr) = scp->addrloc;
        ptr += sizeof(uint16_t);

        return ptr;
}

/*
 * Create ack/sequence part of a data message
 */
static uint16_t *dn_nsp_mk_ack_hdr(
  struct sock *sk,
  struct sk_buff *skb,
  uint8_t msgflag,
  int hlen,
  int other
)
{
        struct dn_scp *scp = DN_SK(sk);
        uint16_t acknum = scp->data.num_rcv & NSP_SEG_MASK;
        uint16_t ackcrs = scp->other.num_rcv & NSP_SEG_MASK;
        uint16_t *ptr;

        BUG_ON(hlen < 9);

        scp->data.ack_xmt = acknum;
        scp->other.ack_xmt = ackcrs;
        acknum |= NSP_ACK_PRESENT;
        ackcrs |= NSP_ACK_PRESENT;

        /*
         * If this is an "other data/ack" message, swap acknum and ackcrs
         */
        if (other)
                swap(acknum, ackcrs);

        /*
         * Set "cross subchannel" bit in ackcrs
         */
        ackcrs |= NSP_ACK_CROSS;

        ptr = (uint16_t *)dn_nsp_mk_header(scp, skb, msgflag, hlen);

        *ptr++ = cpu_to_le16(acknum);
        *ptr++ = cpu_to_le16(ackcrs);

        /*
         * Cancel any ack delay timer since we are about to send an explicit
         * ACK.
         */
        scp->ackdelay = 0;

        return ptr;
}

/*
 * Build a data/interrupt message header
 */
static void dn_nsp_mk_data_hdr(
  struct sock *sk,
  struct sk_buff *skb,
  int oth
)
{
        struct dn_skb_cb *cb = DN_SKB_CB(skb);
        uint16_t *ptr = dn_nsp_mk_ack_hdr(sk, skb, cb->nsp_flags, NSP_MAX_DATAHDR, oth);
	uint16_t segnum = cb->segnum;

	if ((cb->ack_delay != 0) && !oth)
		segnum |= NSP_ACK_DELAY;

	*ptr++ = cpu_to_le16(segnum);
}

/*
 * Transmit an NSP message
 */
void dn_nsp_xmt(
  struct sk_buff *skb
)
{
        struct sock *sk = skb->sk;
        struct dn_skb_cb *cb = DN_SKB_CB(skb);
        struct dn_scp *scp = DN_SK(sk);

        skb_reset_transport_header(skb);
        scp->stamp = jiffies;

        cb->src = decnet_address;
        cb->dst = scp->nodeEntry->addr;

        if (scp->nodeEntry != NULL)
                Count_total_sent(scp->nodeEntry, skb->len);
        dn_routing_tx_long(skb, scp->nextEntry);
}

/*
 * Clone a queued data or other data message and transmit it. Returns the
 * number of times the message has been transmitted (including this one), 0
 * if buffer allocation failure.
 */
static inline unsigned int dn_nsp_clone_xmt(
  struct sk_buff *skb,
  gfp_t gfp,
  int oth
)
{
        struct sock *sk = skb->sk;
        struct dn_skb_cb *cb = DN_SKB_CB(skb);
        struct sk_buff *skb2;
        unsigned int ret = 0;

        if ((skb2 = skb_clone(skb, gfp)) != NULL) {
		struct dn_skb_cb *cb2 = DN_SKB_CB(skb2);
                struct dn_scp *scp = DN_SK(sk);
                unsigned long persist = dn_nsp_persist(scp);
                
                ret = ++cb->xmit_count;

                cb->stamp = jiffies;
                cb->deadline = cb->stamp + persist;

		/*
		 * Disable delayed ack if this is a retransmit
		 */
		if (ret > 1)
			cb2->ack_delay = 0;

                skb2->sk = sk;
                skb2->destructor = dn_nsp_null_destructor;

		/*
		 * Back-build an NSP header
		 */
		dn_nsp_mk_data_hdr(sk, skb2, oth);

                dn_nsp_xmt(skb2);

                if (ret == 1)
                        Count_user_sent(scp->nodeEntry, cb->datalen);
                
                if (scp->persist == 0)
                        scp->persist = persist;
        }
        return ret;
}

/*
 * Try to transmit/retransmit data from both socket queues.
 */
void dn_nsp_xmt_socket(
  struct sock *sk
)
{
        struct dn_scp *scp = DN_SK(sk);
        struct sk_buff *skb;
        unsigned int reduce_win = 0;

        /*
         * First check for otherdata/linkservice messages
         */
        if ((skb = skb_peek(&scp->other.xmit_queue)) != NULL) {
                struct dn_skb_cb *cb = DN_SKB_CB(skb);

                if (cb->xmit_count >= decnet_NSPretrans)
                        goto lost;
                
                reduce_win = dn_nsp_clone_xmt(skb, GFP_ATOMIC, 1);
        }
        
        if (reduce_win || (scp->data.flowrem_sw != DN_SEND))
                goto recalc_window;
        
        if ((skb = skb_peek(&scp->data.xmit_queue)) != NULL) {
                struct dn_skb_cb *cb = DN_SKB_CB(skb);

                if (cb->xmit_count >= decnet_NSPretrans)
                        goto lost;
                
                reduce_win += dn_nsp_clone_xmt(skb, GFP_ATOMIC, 0);
        }
        /*
         * If we re-transmitted one of these messages, cut the window in
         * half since we had a timeout.
         */
 recalc_window:
        if (reduce_win) {
                scp->snd_window >>= 1;
                if (scp->snd_window < NSP_MIN_WINDOW)
                        scp->snd_window = NSP_MIN_WINDOW;
        }
        return;

        /*
         * The transmit count has exceeded the NSP retransmission
         * limit - terminate the logical link.
         */
 lost:
        scp->persist = 0;
        sk->sk_err = EHOSTUNREACH;
        scp->state = DN_NC;
        sk->sk_state = DNET_CLOSE;

        if (!sock_flag(sk, SOCK_DEAD))
                sk->sk_state_change(sk);
}

/*
 * Queue a message for transmission
 */
void dn_nsp_queue_xmt(
  struct sock *sk,
  struct sk_buff *skb,
  gfp_t gfp,
  int oth
)
{
        struct dn_scp *scp = DN_SK(sk);
        struct dn_skb_cb *cb = DN_SKB_CB(skb);

        cb->xmit_count = 0;

	/*
	 * Slow start: If we have been idle for more than one RTT, then
	 * reset window to min size.
	 */
	if ((jiffies - scp->stamp) > scp->nodeEntry->delay)
		scp->snd_window = NSP_MIN_WINDOW;

        if (oth) {
		cb->segnum = scp->other.num;
		seq_add(&scp->other.num, 1);
                skb_queue_tail(&scp->other.xmit_queue, skb);
        } else {
		cb->segnum = scp->data.num;
		seq_add(&scp->data.num, 1);
                skb_queue_tail(&scp->data.xmit_queue, skb);

                /*
                 * SEND/DONTSEND flow control only applies to the data
                 * channel
                 */
                if (scp->data.flowrem_sw != DN_SEND)
                        return;
        }
        dn_nsp_clone_xmt(skb, gfp, oth);
}

/*
 * Build and send a connect initiate acknowledgement message.
 */
void dn_nsp_xmt_ack_ci(
  struct sock *sk
)
{
        struct dn_scp *scp = DN_SK(sk);
        struct sk_buff *skb = dn_alloc_skb(sk, sizeof(struct nsp_ciack), sk->sk_allocation);
        struct nsp_ciack *msg;

        if (skb != NULL) {
                msg = skb_put(skb, sizeof(struct nsp_ciack));
                msg->msgflg = NSP_MSG_CIACK;
                msg->dstaddr = scp->addrrem;
                dn_nsp_xmt(skb);
        }
}

/*
 * Build and transmit a data ack
 */
void dn_nsp_xmt_ack_data(
  struct sock *sk
)
{
        struct sk_buff *skb;

        if ((skb = dn_alloc_skb(sk, NSP_MAX_ACK, GFP_ATOMIC)) != NULL) {
                skb_reserve(skb, NSP_MAX_ACK);
                dn_nsp_mk_ack_hdr(sk, skb, NSP_MSG_DATACK, NSP_MAX_ACK, 0);
                dn_nsp_xmt(skb);
        }
}

/*
 * Build and transmit an other ack
 */
void dn_nsp_xmt_ack_oth(
  struct sock *sk
)
{
        struct sk_buff *skb;

        if ((skb = dn_alloc_skb(sk, NSP_MAX_ACK, GFP_ATOMIC)) != NULL) {
                skb_reserve(skb, NSP_MAX_ACK);
                dn_nsp_mk_ack_hdr(sk, skb, NSP_MSG_OTHACK, NSP_MAX_ACK, 1);
                dn_nsp_xmt(skb);
        }
}

/*
 * Build and send a connect confirm message.
 */
void dn_nsp_xmt_cc(
  struct sock *sk,
  gfp_t gfp
)
{
        struct dn_scp *scp = DN_SK(sk);
        struct sk_buff *skb;
        struct nsp_cc *msg;
        uint8_t len = le16_to_cpu(scp->conndata_out.opt_optl);
        
        if ((skb = dn_alloc_skb(sk, sizeof(struct nsp_cc) + len, gfp)) != NULL) {
          msg = skb_put(skb, sizeof(struct nsp_cc));
          msg->msgflg = NSP_MSG_CC;
          msg->dstaddr = scp->addrrem;
          msg->srcaddr = scp->addrloc;
          msg->services = scp->data.services_loc;
          msg->info = scp->info_loc;
          msg->segsize = cpu_to_le16(scp->segsize_loc);
          msg->data_ctl[0] = len;

          if (len > 0)
                skb_put_data(skb, scp->conndata_out.opt_data, len);

          dn_nsp_xmt(skb);
        }
}

/*
 * Build and retransmit a connect confirm message.
 */
int dn_nsp_rexmt_cc(
  struct sock *sk
)
{
        struct dn_scp *scp = DN_SK(sk);

        if (scp->state == DN_CC) {
                if (scp->persist_count-- != 0) {
                        dn_nsp_xmt_cc(sk, GFP_ATOMIC);
                        Count_timeouts(scp->nodeEntry);
                        scp->persist = dn_nsp_persist(scp);
                        return 0;
                }
                scp->persist = 0;
                sk->sk_err = EHOSTUNREACH;
                scp->state = DN_NC;
                sk->sk_state = DNET_CLOSE;

                if (!sock_flag(sk, SOCK_DEAD))
                        sk->sk_state_change(sk);
        }
        return 0;
}

/*
 * Build and send a connect initiate message. This also handles sending a
 * retransmitted connect initiate message.
 */
void dn_nsp_xmt_ci(
  struct sock *sk,
  uint8_t msgflg,
  uint8_t startTimer
)
{
        struct dn_scp *scp = DN_SK(sk);
        struct nsp_ci *msg;
        struct dn_skb_cb *cb;
        struct sockaddr_dn *saddr;
        uint8_t aux, menuver = 0, type = 1;
        gfp_t allocation = msgflg == NSP_MSG_CI ? sk->sk_allocation : GFP_ATOMIC;
        struct sk_buff *skb = dn_alloc_skb(sk, 200, allocation);

        if (!skb)
                return;

        cb = DN_SKB_CB(skb);
        msg = skb_put(skb, sizeof(struct nsp_ci));

        msg->msgflg = msgflg;
        msg->dstaddr = 0x0000;
        msg->srcaddr = scp->addrloc;
        msg->services = scp->data.services_loc;
        msg->info = scp->info_loc;
        msg->segsize = cpu_to_le16(scp->segsize_loc);

        if (scp->peer.sdn_objnum)
                type = 0;

        skb_put(skb, dn_sockaddr2username(&scp->peer, skb_tail_pointer(skb), type));

        /*
         * If there is no name bound to the socket, use a generic name
         * ("Linux") so that the remote system is happy.
         */
        saddr = scp->addr.sdn_objnamel != 0 ? &scp->addr : &dummyname;
        skb_put(skb, dn_sockaddr2username(saddr, skb_tail_pointer(skb), 1));

	if ((scp->accessdata.acc_userl != 0) ||
	    (scp->accessdata.acc_passl != 0) ||
	    (scp->accessdata.acc_accl != 0))
		menuver |= NSP_MENU_ACC;
	if (scp->conndata_out.opt_optl != 0)
		menuver |= NSP_MENU_USR;
        if (scp->peer.sdn_flags & SDF_PROXY)
                menuver |= NSP_MENU_PROXY;
        if (scp->peer.sdn_flags & SDF_UICPROXY)
                menuver |= NSP_MENU_UIC;

        skb_put_u8(skb, menuver);

	if ((menuver & NSP_MENU_ACC) != 0) {
        	aux = scp->accessdata.acc_userl;
        	skb_put_u8(skb, aux);
        	if (aux > 0)
                	skb_put_data(skb, scp->accessdata.acc_user, aux);

        	aux = scp->accessdata.acc_passl;
        	skb_put_u8(skb, aux);
        	if (aux > 0)
                	skb_put_data(skb, scp->accessdata.acc_pass, aux);

        	aux = scp->accessdata.acc_accl;
        	skb_put_u8(skb, aux);
        	if (aux > 0)
                	skb_put_data(skb, scp->accessdata.acc_acc, aux);
	}

	if ((menuver & NSP_MENU_USR) != 0) {
        	aux = le16_to_cpu(scp->conndata_out.opt_optl);
		skb_put_u8(skb, aux);
                skb_put_data(skb, scp->conndata_out.opt_data, aux);
	}
        
        cb->rt_flags = RT_FLG_RQR;

        dn_nsp_xmt(skb);

        if (startTimer)
                scp->strTime = jiffies;

        scp->last_ci = msgflg;
}

/*
 * Build and transmit a retransmitted connect initiate message.
 */
int dn_nsp_rexmt_ci(
  struct sock *sk
)
{
        struct dn_scp *scp = DN_SK(sk);

        if (scp->state == DN_CI) {
                if (scp->persist_count-- != 0) {
                        dn_nsp_xmt_ci(sk, NSP_MSG_RCI, 0);
                        Count_timeouts(scp->nodeEntry);
                        scp->persist = dn_nsp_persist(scp);
                        return 0;
                }
                scp->persist = 0;
                sk->sk_err = EHOSTUNREACH;
                scp->state = DN_NC;
                sk->sk_state = DNET_CLOSE;

                if (!sock_flag(sk, SOCK_DEAD))
                        sk->sk_state_change(sk);
        }
        return 0;
}

/*
 * Timeout callback for data and/or interrupt message retransmission
 */
int dn_nsp_xmt_timeout(
  struct sock *sk
)
{
        struct dn_scp *scp = DN_SK(sk);

	/*
	 * If there is a pending transmit, increment the count of timeouts
	 * and try to retransmit the message.
	 */
	if ((skb_peek(&scp->other.xmit_queue) != NULL) ||
	    (skb_peek(&scp->data.xmit_queue) != NULL)) {
		Count_timeouts(scp->nodeEntry);
		dn_nsp_xmt_socket(sk);
		return 0;
	}

        scp->persist = 0;
        return 0;
}

/*
 * Low-level send a disconnect in initiate or disconnect confirm message
 */
static void dn_nsp_disconnect(
  struct sock *sk,
  uint8_t msgflg,
  uint16_t reason,
  struct dn_next_entry *nextp,
  gfp_t gfp,
  int ddl,
  uint8_t *dd,
  uint16_t rem,
  uint16_t loc
)
{
        int size = ddl + (msgflg == NSP_MSG_DI ? sizeof(nsp_di) : sizeof(nsp_dc));
        struct sk_buff *skb;

        if ((skb = dn_alloc_skb(sk, size, gfp)) != NULL) {
                struct dn_skb_cb *cb = DN_SKB_CB(skb);
                uint8_t *msg = skb_put(skb, size);

                *msg++ = msgflg;
                *(uint16_t *)msg = rem;
                msg += sizeof(uint16_t);
                *(uint16_t *)msg = loc;
                msg += sizeof(uint16_t);
                *(uint16_t *)msg = cpu_to_le16(reason);
                msg += sizeof(uint16_t);

                if (msgflg == NSP_MSG_DI) {
                        *msg++ = ddl;
                        if (ddl != 0)
                                memcpy(msg, dd, ddl);
                }

                cb->src = decnet_address;
                cb->dst = nextp->addr;

                if (sk != NULL) {
                        struct dn_scp *scp = DN_SK(sk);

                        if (scp->nodeEntry != NULL)
                                Count_total_sent(scp->nodeEntry, skb->len);
                }
                
                dn_routing_tx_long(skb, nextp);
        }
}

/*
 * Send a disconnect initiate or disconnect confirm message
 */
void dn_nsp_xmt_disc(
  struct sock *sk,
  uint8_t msgflg,
  uint16_t reason,
  gfp_t gfp
)
{
        struct dn_scp *scp = DN_SK(sk);
        int ddl = 0;

        if (msgflg == NSP_MSG_DI)
                ddl = le16_to_cpu(scp->discdata_out.opt_optl);

        if (reason == 0)
                reason = scp->discdata_out.opt_status;

        dn_nsp_disconnect(sk, msgflg, reason, scp->nextEntry, gfp, ddl,
                            scp->discdata_out.opt_data,
                            scp->addrrem, scp->addrloc);
}

/*
 * Send a disconnect initiate or disconnect confirm without a socket structure
 */
void dn_nsp_return_disc(
  struct sk_buff *skb,
  uint8_t msgflg,
  uint16_t reason
)
{
        struct dn_skb_cb *cb = DN_SKB_CB(skb);
        struct dn_next_entry *nextp;

        nextp = dn_next_update_and_hold(cb->src, NULL, 0);

        if (nextp != NULL) {
                dn_nsp_disconnect(NULL, msgflg, reason, nextp, GFP_ATOMIC, 0,
                                  NULL, cb->src_port, cb->dst_port);
                dn_next_release(nextp);
        }
}

/*
 * Send a link service message
 */
int dn_nsp_xmt_ls(
  struct sock *sk,
  uint8_t lsflags,
  uint8_t fcval
)
{
        struct dn_scp *scp = DN_SK(sk);
        struct sk_buff *skb;
        uint8_t *ptr;
        gfp_t gfp = GFP_ATOMIC;

        if ((skb = dn_alloc_skb(sk, NSP_MAX_DATAHDR + (2 * sizeof(uint8_t)), gfp)) == NULL)
                return 0;

        skb_reserve(skb, NSP_MAX_DATAHDR);
        ptr = skb_put(skb, 2 * sizeof(uint8_t));
        DN_SKB_CB(skb)->nsp_flags = NSP_MSG_LS;

        *ptr++ = lsflags;
        *ptr = fcval;
        
        dn_nsp_queue_xmt(sk, skb, gfp, 1);

        PERSIST(scp, dn_nsp_xmt_timeout);

        return 1;
}
/*
 * Schedule pending link service message(s).
 */
void dn_nsp_sched_pending(
  struct sock *sk,
  int what
)
{
        struct dn_scp *scp = DN_SK(sk);

        scp->pending |= what;

        if ((scp->pending != DN_PEND_NONE) &&
            skb_queue_empty(&scp->other.xmit_queue)) {
                if ((scp->pending & DN_PEND_INTR) != 0) {
                        if (dn_nsp_xmt_ls(sk, DN_FCVAL_INTR, 1))
                                scp->pending &= ~DN_PEND_INTR;
                        return;
                }

                if ((scp->pending & DN_PEND_SW) != 0) {
                        if (dn_nsp_xmt_ls(sk, DN_FCVAL_DATA | scp->data.flowloc_sw, 0))
                                scp->pending &= ~DN_PEND_SW;
                        return;
                }
                if ((scp->pending & DN_PEND_IDLE) != 0) {
                        if (dn_nsp_xmt_ls(sk, DN_NOCHANGE, 0))
                                scp->pending &= ~DN_PEND_IDLE;
                        return;
                }
        }
}

