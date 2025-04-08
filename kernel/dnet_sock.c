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
#include <net/sock.h>
#include <linux/version.h>
#include "dnet.h"

#define DN_SK_HASH_SHIFT        8
#define DN_SK_HASH_SIZE         (1 << DN_SK_HASH_SHIFT)
#define DN_SK_HASH_MASK         (DN_SK_HASH_SIZE - 1)

static DEFINE_RWLOCK(dn_sk_hash_lock);
static struct hlist_head dn_sk_hash[DN_SK_HASH_SIZE];
static struct hlist_head dn_sk_wild;

/*
 * Socket hash routines.
 */

/*
 * Find a hash list to be used for storing a "struct sock".
 */
static struct hlist_head *dn_sk_find_list(
  struct sock *sk
)
{
        struct dn_scp *scp = DN_SK(sk);

        if ((scp->addr.sdn_flags & SDF_WILD) != 0)
                return hlist_empty(&dn_sk_wild) ? &dn_sk_wild : NULL;
        
        return &dn_sk_hash[scp->addrloc & DN_SK_HASH_MASK];
}

/*
 * Find a hash list based on an object identifier.
 */
static struct hlist_head *dn_sk_find_listen_list(
  struct sockaddr_dn *addr
)
{
        int i;
        unsigned int hash = addr->sdn_objnum;

        if (hash == 0) {
                hash = addr->sdn_objnamel;

                for (i = 0; i < addr->sdn_objnamel; i++) {
                        hash ^= addr->sdn_objname[i];
                        hash ^= (hash << 3);
                }
        }
        return &dn_sk_hash[hash & DN_SK_HASH_MASK];
}

/*
 * Insert a "struct sock" into a hash chain.
 */
int dn_sk_hash_sock(
  struct sock *sk
)
{
        struct dn_scp *scp = DN_SK(sk);
        struct hlist_head *list;
        int rv = -EUSERS;

        BUG_ON(sk_hashed(sk));

        write_lock_bh(&dn_sk_hash_lock);
        if ((scp->addrloc != 0) || dn_sk_alloc_port(sk)) {
                rv = -EADDRINUSE;

                if ((list = dn_sk_find_list(sk)) != NULL) {
                        sk_add_node(sk, list);
                        rv = 0;
                }
        }
        write_unlock_bh(&dn_sk_hash_lock);

        return rv;
}

/*
 * Remove a socket from it's hash chain.
 */
void dn_sk_unhash_sock_bh(
  struct sock *sk
)
{
        write_lock_bh(&dn_sk_hash_lock);
        sk_del_node_init(sk);
        write_unlock_bh(&dn_sk_hash_lock);
}

/*
 * Transform a socket from bound (i.e. with a local address) into a
 * listening socket (doesn't need a local port number) while rehashing
 * based on the object name/number.
 */
void dn_sk_rehash_sock(
  struct sock *sk
)
{
        struct dn_scp *scp = DN_SK(sk);
        struct hlist_head *list;

        if ((scp->addr.sdn_flags & SDF_WILD) == 0) {
                write_lock_bh(&dn_sk_hash_lock);
                sk_del_node_init(sk);
                scp->addrloc = 0;
                list = dn_sk_find_listen_list(&scp->addr);
                sk_add_node(sk, list);
                write_unlock_bh(&dn_sk_hash_lock);
        }
}

/*
 * Find a listening socket given a sockaddr_dn structure.
 */
struct sock *dn_sk_find_listener(
  struct sockaddr_dn *addr
)
{
        struct hlist_head *list = dn_sk_find_listen_list(addr);
        struct sock *sk;

        read_lock_bh(&dn_sk_hash_lock);
        sk_for_each(sk, list) {
                struct dn_scp *scp = DN_SK(sk);

                if (sk->sk_state != DNET_LISTEN)
                        continue;
                if (scp->addr.sdn_objnum) {
                        if (scp->addr.sdn_objnum != addr->sdn_objnum)
                                continue;
                } else {
                        if (addr->sdn_objnum != 0)
                                continue;
                        if (scp->addr.sdn_objnamel != addr->sdn_objnamel)
                                continue;
                        if (memcmp(scp->addr.sdn_objname, addr->sdn_objname, addr->sdn_objnamel) != 0)
                                continue;
                }
                sock_hold(sk);
                read_unlock_bh(&dn_sk_hash_lock);
                return sk;
        }

        sk = sk_head(&dn_sk_wild);
        if (sk) {
                if (sk->sk_state == DNET_LISTEN)
                        sock_hold(sk);
                else
                        sk = NULL;
        }
        read_unlock_bh(&dn_sk_hash_lock);
        return sk;
}

/*
 * Lookup a sock structure based on parameters available in an sk_buff
 */
struct sock *dn_sk_lookup_by_skb(
  struct sk_buff *skb
)
{
        struct dn_skb_cb *cb = DN_SKB_CB(skb);
        struct sock *sk;

        read_lock_bh(&dn_sk_hash_lock);
        sk_for_each(sk, &dn_sk_hash[cb->dst_port & DN_SK_HASH_MASK]) {
                struct dn_scp *scp = DN_SK(sk);

                if (cb->src != dn_saddr2dn(&scp->peer))
                        continue;
                if (cb->dst_port != scp->addrloc)
                        continue;
                if (scp->addrrem && (cb->src_port != scp->addrrem))
                        continue;

                sock_hold(sk);
                read_unlock_bh(&dn_sk_hash_lock);
                return sk;
        }
        read_unlock_bh(&dn_sk_hash_lock);
        return NULL;
}

/*
 * Check to see if a port is in use
 */
int dn_sk_port_in_use(
  uint16_t port
)
{
        struct sock *sk;

        if (port == 0)
                return -1;

        sk_for_each(sk, &dn_sk_hash[port & DN_SK_HASH_MASK]) {
                struct dn_scp *scp = DN_SK(sk);

                if (scp->addrloc == port)
                        return -1;
        }
        return 0;
}

/*
 * Allocate an unused port
 */
static uint16_t port = 0x2000;

uint16_t dn_sk_alloc_port(
  struct sock *sk
)
{
        struct dn_scp *scp = DN_SK(sk);
        uint16_t i_port = port;

        while (dn_sk_port_in_use(++port) != 0) {
                if (port == i_port)
                        return 0;
        }

        scp->addrloc = port;
        return 1;
}

/*
 * Check for a duplicate connection. This is used to check for duplicate
 * incoming Connect Initiate messages.
 */
int dn_sk_check_duplicate(
  struct sk_buff *skb
)
{
        struct sock *sk;
        struct dn_skb_cb *cb = DN_SKB_CB(skb);
        int i, found = 0;

        read_lock_bh(&dn_sk_hash_lock);
        for (i = 0; i < DN_SK_HASH_SIZE; i++) {
                sk_for_each(sk, &dn_sk_hash[i]) {
                        if (sk->sk_state != DNET_LISTEN) {
                                struct dn_scp *scp = DN_SK(sk);

                                if (cb->src != dn_saddr2dn(&scp->peer))
                                        continue;
                                if (cb->src_port != scp->addrrem)
                                        continue;

                                found = 1;
                                goto done;
                        }
                }
        }
 done:
        read_unlock_bh(&dn_sk_hash_lock);
        return found;
}

/*
 * Check if there is a socket which matches the port number of a returned
 * Connect Initiate message.
 */
struct sock *dn_sk_check_returned(
  struct sk_buff *skb
)
{
        struct dn_skb_cb *cb = DN_SKB_CB(skb);
        struct sock *sk;

        read_lock_bh(&dn_sk_hash_lock);
        sk_for_each(sk, &dn_sk_hash[cb->src_port & DN_SK_HASH_MASK]) {
                if (sk->sk_state != DNET_LISTEN) {
                        struct dn_scp *scp = DN_SK(sk);

                        if (cb->src_port != scp->addrloc)
                                continue;

                        sock_hold(sk);
                        read_unlock_bh(&dn_sk_hash_lock);
                        return sk;
                }
        }
        read_unlock_bh(&dn_sk_hash_lock);
        return NULL;
}

/*
 * Allocate and initialize a new DECnet sock structure.
 */
struct sock *dn_alloc_sock(
  struct net *net,
  struct socket *sock,
  gfp_t gfp,
  int kern
)
{
        struct dn_scp *scp;
        struct sock *sk = sk_alloc(net, PF_DECnet, gfp, &dnet_proto, kern);


        if (sk) {
                if (sock)
                        sock->ops = &dnet_proto_ops;

                sock_init_data(sock, sk);

                sk->sk_backlog_rcv = dn_nsp_rcv_backlog;
                sk->sk_destruct = dn_sk_destruct;
                sk->sk_no_check_tx = 1;
                sk->sk_family = PF_DECnet;
                sk->sk_protocol = 0;
                sk->sk_allocation = gfp;
                sk->sk_sndbuf = READ_ONCE(decnet_wmem[1]);
                sk->sk_rcvbuf = READ_ONCE(decnet_rmem[1]);

                scp = DN_SK(sk);
                scp->state = DN_O;

                scp->nextEntry = NULL;
                scp->nodeEntry = NULL;
        
                scp->data.num = 1;
                scp->other.num = 1;
                scp->data.ack_xmt = 0;
                scp->other.ack_xmt = 0;
                scp->data.ack_rcv = 0;
                scp->other.ack_rcv = 0;
                scp->data.flowrem_sw = DN_SEND;
                scp->data.flowloc_sw = DN_SEND;
                scp->other.flowrem_sw = DN_SEND;
                scp->other.flowloc_sw = DN_SEND;
                scp->data.flowrem = 0;
                scp->other.flowrem = 1;
                scp->data.flowloc = 0;
                scp->other.flowloc = 1;
                scp->data.services_rem = 0;
                scp->data.services_loc = NSP_FCOPT_NONE;
                scp->other.services_rem = NSP_FCOPT_MSG;
                scp->other.services_loc = NSP_FCOPT_MSG;
                scp->info_rem = 0;
                scp->info_loc = NSP_INFO_4_0;
                scp->segsize_rem = 230 - NSP_MAX_DATAHDR;
                scp->pending = 0;
                scp->accept_mode = ACC_IMMED;
                scp->addr.sdn_family = AF_DECnet;
                scp->peer.sdn_family = AF_DECnet;
                scp->conndata_in.opt_optl = 0;
                scp->conndata_out.opt_optl = 0;
                memset(&scp->discdata_in, 0, sizeof(scp->discdata_in));
                memset(&scp->discdata_out, 0, sizeof(scp->discdata_out));
                memset(&scp->accessdata, 0, sizeof(scp->accessdata));
        
                scp->snd_window = NSP_MIN_WINDOW;
        
                scp->delayedacks = 0;

                skb_queue_head_init(&scp->data.xmit_queue);
                skb_queue_head_init(&scp->other.xmit_queue);

                skb_queue_head_init(&scp->other_receive_queue);
        
                scp->keepalive = DN_KEEPALIVE;
                scp->keepalive_fcn = dn_keepalive;

                scp->ackdelay = 0;
                scp->conntimer = 0;

                scp->strTime = 0;

                dn_start_slow_timer(sk);
        }
        return sk;
}

/*
 * Clean up a DECnet sock structure ready for deletion
 */
void dn_sk_destruct(
  struct sock *sk
)
{
        struct dn_scp *scp = DN_SK(sk);

        if (scp->nextEntry != NULL) {
                dn_next_release(scp->nextEntry);
                scp->nextEntry = NULL;
        }

        if (scp->nodeEntry != NULL) {
                dn_node_release(scp->nodeEntry, 0);
                scp->nodeEntry = NULL;
        }

        skb_queue_purge(&scp->data.xmit_queue);
        skb_queue_purge(&scp->other.xmit_queue);
        
        skb_queue_purge(&scp->other_receive_queue);
}

/*
 * Timer callback for destroying sockets.
 */
int dn_sk_destroy_timer(
  struct sock *sk
)
{
        struct dn_scp *scp = DN_SK(sk);

        scp->persist = dn_nsp_persist(scp);

        /*
         * Determine if we need to send out a disconnect initiate or confirm
         */
        switch (scp->state) {
                case DN_DI:
                        dn_nsp_xmt_disc(sk, NSP_MSG_DI, 0, GFP_NOWAIT);
                        Count_timeouts(scp->nodeEntry);
                        if (scp->persist_count-- != 0)
                                scp->state = DN_CN;
                        scp->persist_count = 0;
                        scp->stamp = jiffies;
                        return 0;
                        
                case DN_DR:
                        dn_nsp_xmt_disc(sk, NSP_MSG_DC, 0, GFP_NOWAIT);
                        scp->state = DN_DRC;
                        scp->persist_count = 0;
                        scp->stamp = jiffies;
                        return 0;
        }

        /*
         * Give the underlying stack a couple of seconds to send out the
         * disconnect initiate/confirm before dropping the connecttion.
         */
        scp->persist = HZ;

        if (sk->sk_socket == NULL) {
                if (time_after_eq(jiffies, scp->stamp + (2 * HZ))) {
                        dn_sk_unhash_sock_bh(sk);
                        sock_put(sk);
                        return 1;
                }
        }
        return 0;
}

#ifdef CONFIG_PROC_FS

static struct sock *dn_socket_get_first(
  struct seq_file *seq
)
{
        struct dn_sock_seq_state *s = seq->private;
        struct sock *sk = NULL;

        for (s->bucket = 0; s->bucket < DN_SK_HASH_SIZE; ++s->bucket) {
                sk = sk_head(&dn_sk_hash[s->bucket]);
                if (sk)
                        break;
        }
        return sk;
}

static struct sock *dn_socket_get_next(
  struct seq_file *seq,
  struct sock *sk
)
{
        struct dn_sock_seq_state *s = seq->private;

        sk = sk_next(sk);
        while (!sk) {
                if (++s->bucket >= DN_SK_HASH_SIZE)
                        break;
                sk = sk_head(&dn_sk_hash[s->bucket]);
        }
        return sk;
}

static struct sock *socket_get_idx(
  struct seq_file *seq,
  loff_t *pos
)
{
        struct sock *sk = dn_socket_get_first(seq);

        if (sk) {
          while (*pos && (sk = dn_socket_get_next(seq, sk)))
                --*pos;
        }
        return *pos ? NULL : sk;
}

static void *dn_socket_get_idx(
  struct seq_file *seq,
  loff_t pos
)
{
        void *rc;

        read_lock_bh(&dn_sk_hash_lock);
        rc = socket_get_idx(seq, &pos);
        if (!rc)
                read_unlock_bh(&dn_sk_hash_lock);

        return rc;
}

static void *dn_socket_seq_start(
  struct seq_file *seq,
  loff_t *pos
)
{
        return *pos ? dn_socket_get_idx(seq, *pos - 1) : SEQ_START_TOKEN;
}

static void *dn_socket_seq_next(
  struct seq_file *seq,
  void *v,
  loff_t *pos
)
{
        void *rc;

        if (v == SEQ_START_TOKEN) {
                rc = dn_socket_get_idx(seq, 0);
                goto out;
        }

        rc = dn_socket_get_next(seq, v);
        if (rc)
                goto out;
        read_unlock_bh(&dn_sk_hash_lock);

 out:
        ++*pos;
        return rc;
}

static void dn_socket_seq_stop(
  struct seq_file *seq,
  void *v
)
{
        if (v && v != SEQ_START_TOKEN)
                read_unlock_bh(&dn_sk_hash_lock);
}

static char *dn_state2asc(
  uint8_t state
)
{
        switch (state) {
                case DN_O:
                        return "OPEN";
                        
                case DN_CR:
                        return "  CR";
                        
                case DN_DR:
                        return "  DR";
                        
                case DN_DRC:
                        return " DRC";
                        
                case DN_CC:
                        return "  CC";
                        
                case DN_CI:
                        return "  CI";
                        
                case DN_NR:
                        return "  NR";
                        
                case DN_NC:
                        return "  NC";
                        
                case DN_CD:
                        return "  CD";
                        
                case DN_RJ:
                        return "  RJ";
                        
                case DN_RUN:
                        return " RUN";
                        
                case DN_DI:
                        return "  DI";
                        
                case DN_DIC:
                        return " DIC";
                        
                case DN_DN:
                        return "  DN";
                        
                case DN_CL:
                        return "  CL";
                        
                case DN_CN:
                        return "  CL";
        }
        return "????";
}

#ifdef DNET_COMPAT
#define IS_NOT_PRINTABLE(x)     (((x) < 32) || ((x) > 126))

static void dn_printable_object(
  struct sockaddr_dn *dn,
  uint8_t *buf
)
{
        int i;

        switch (le16_to_cpu(dn->sdn_objnamel)) {
                case 0:
                        sprintf(buf, "%d", dn->sdn_objnum);
                        break;
                        
                default:
                        for (i = 0; i < le16_to_cpu(dn->sdn_objnamel); i++) {
                                buf[i] = dn->sdn_objname[i];
                                if (IS_NOT_PRINTABLE(buf[i]))
                                        buf[i] = '.';
                        }
                        buf[i] = 0;
        }
}

static void dn_socket_format_entry(
  struct seq_file *seq,
  struct sock *sk
)
{
        struct dn_scp *scp = DN_SK(sk);
        char buf1[DN_ASCBUF_LEN];
        char buf2[DN_ASCBUF_LEN];
        char local_object[DN_MAXOBJL+3];
        char remote_object[DN_MAXOBJL+3];

        dn_printable_object(&scp->addr, local_object);
        dn_printable_object(&scp->peer, remote_object);

        seq_printf(seq,
                   "%6s/%04X %04d:%04d %04d:%04d %01d %-16s "
                   "%6s/%04X %04d:%04d %04d:%04d %01d %-16s %4s %s\n",
                   dn_addr2asc(le16_to_cpu(dn_saddr2dn(&scp->addr)), buf1),
                   scp->addrloc,
                   scp->data.num,
                   scp->other.num,
                   scp->data.ack_xmt,
                   scp->other.ack_xmt,
                   scp->data.flowloc_sw,
                   local_object,
                   dn_addr2asc(le16_to_cpu(dn_saddr2dn(&scp->peer)), buf2),
                   scp->addrrem,
                   scp->data.num_rcv,
                   scp->other.num_rcv,
                   scp->data.ack_rcv,
                   scp->other.ack_rcv,
                   scp->data.flowrem_sw,
                   remote_object,
                   dn_state2asc(scp->state),
                   ((scp->accept_mode == ACC_IMMED) ? "IMMED" : "DEFER"));
}

#endif

static int dn_socket_seq_show(
  struct seq_file *seq,
  void *v
)
{
        if (v == SEQ_START_TOKEN) {
                seq_puts(seq, "Local                                              Remote\n");
        } else {
                dn_socket_format_entry(seq, v);
        }
        return 0;
}

static const struct seq_operations dn_socket_seq_ops = {
        .start = dn_socket_seq_start,
        .next = dn_socket_seq_next,
        .stop = dn_socket_seq_stop,
        .show = dn_socket_seq_show,
};

void __init dn_sock_init(void)
{
        proc_create_seq_private("decnet", 0444, init_net.proc_net,
                                &dn_socket_seq_ops,
                                sizeof(struct dn_sock_seq_state), NULL);
}

void __exit dn_sock_exit(void)
{
}

#endif
