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

#include <linux/net.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <net/sock.h>
#include <linux/atomic.h>
#include <linux/jiffies.h>
#include <linux/version.h>
#include "dnet.h"

static void dn_slow_timer(
  struct timer_list *t
)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,16,0)
        struct sock *sk = timer_container_of(sk, t, sk_timer);
#else
        struct sock *sk = from_timer(sk, t, sk_timer);
#endif
        struct dn_scp *scp = DN_SK(sk);

        bh_lock_sock(sk);

        /*
         * If we are unable to gain access to the socket, start a short timer
         * to try again
         */
        if (sock_owned_by_user(sk)) {
                sk_reset_timer(sk, &sk->sk_timer, jiffies + ( HZ / 10));
                goto done;
        }

        /*
         * The persist timer is the standard slow timer used for
         * retransmissions. We allow the persist function to permanently
         * turn off the timer by returning non-zero so that timer-based
         * routines may remove sockets.
         */
        if (scp->persist && scp->persist_fcn) {
                if (scp->persist < TIMER_INTERVAL) {
                        scp->persist = 0;

                        if (scp->persist_fcn(sk))
                                goto done;
                } else scp->persist -=TIMER_INTERVAL;
        }

        /*
         * Check for outgoing connection timeout. If it expires we want to
         * terminate the logical link.
         */
        if (scp->conntimer) {
                if (scp->state == DN_CD) {
                        if (scp->conntimer <= TIMER_INTERVAL) {
                                scp->conntimer = 0;
                                scp->state = DN_NC;
                                sk->sk_state = DNET_CLOSE;
                                if (!sock_flag(sk, SOCK_DEAD))
                                        sk->sk_state_change(sk);
                        } else scp->conntimer -= TIMER_INTERVAL;
                } else scp->conntimer = 0;
        }

        /*
         * Check for keepalive timeout. This comes after the persist timer
         * which may cause a retransmission delaying the need for a keepalive
         * message. scp->stamp is the last time that we sent a packet. The
         * keepalive function sends a "no change" linkservice message to the
         * other end. If it remains unacknowledged, the standard socket timers
         * will terminate the logical link.
         */
        if (scp->keepalive && scp->keepalive_fcn && (scp->state == DN_RUN)) {
                if (time_after_eq(jiffies, scp->stamp + scp->keepalive))
                        scp->keepalive_fcn(sk);
        }

        /*
         * Check for delayed ack. We do this after all the other cases since
         * they may generate retransmissions which will pick up delayed
         * acks.
         */
        if (scp->ackdelay && (scp->state == DN_RUN)) {
                if (scp->ackdelay <= TIMER_INTERVAL) {
                        scp->ackdelay = 0;
                        dn_nsp_xmt_ack_data(sk);
                } else scp->ackdelay -= TIMER_INTERVAL;
        }
        
        sk_reset_timer(sk, &sk->sk_timer, jiffies + TIMER_INTERVAL);
 done:
        bh_unlock_sock(sk);
        sock_put(sk);
}

/*
 * Keepalive function - periodically sends data to the other end of the
 * connection when no other transfers are present.
 */
void dn_keepalive(
  struct sock *sk
)
{
        struct dn_scp *scp = DN_SK(sk);

        if (skb_queue_empty(&scp->other.xmit_queue))
                dn_nsp_xmt_ls(sk, DN_NOCHANGE, 0);
}

void dn_start_slow_timer(
  struct sock *sk
)
{
        timer_setup(&sk->sk_timer, dn_slow_timer, 0);
        sk_reset_timer(sk, &sk->sk_timer, jiffies + TIMER_INTERVAL);
}

void dn_stop_slow_timer(
  struct sock *sk
)
{
        sk_stop_timer(sk, &sk->sk_timer);
}
