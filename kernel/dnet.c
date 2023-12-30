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
#include <linux/swap.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <linux/version.h>
#include <asm/ioctls.h>
#include "dnet.h"

static int dn_create(struct net *, struct socket *, int, int);

static int dn_release(struct socket *);
static int dn_bind(struct socket *, struct sockaddr *, int);
static int dn_connect(struct socket *, struct sockaddr *, int, int);
static int dn_accept(struct socket *, struct socket *, int, bool);
static int dn_getname(struct socket *, struct sockaddr *, int);
static __poll_t dn_poll(struct file *, struct socket *, poll_table *);
static int dn_ioctl(struct socket *, unsigned int, unsigned long);
static int dn_listen(struct socket *, int);
static int dn_shutdown(struct socket *, int);
static int dn_setsockopt(struct socket *, int, int,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0)
                         sockptr_t,
#else
                         char __user *,
#endif
                         unsigned int);
static int dn_getsockopt(struct socket *, int, int, char __user *, int __user *);
static int dn_recvmsg(struct socket *, struct msghdr *, size_t, int);
static int dn_sendmsg(struct socket *, struct msghdr *, size_t);

/*
 * The DECnet kernel module
 */
static unsigned long dn_memory_pressure;
long decnet_mem[3];
int decnet_wmem[3];
int decnet_rmem[3];

static atomic_long_t decnet_memory_allocated;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
static DEFINE_PER_CPU(int, decnet_memory_per_cpu_fw_alloc);
#endif

static const struct net_proto_family dnet_family_ops = {
        .family =       AF_DECnet,
        .create =       dn_create,
        .owner =        THIS_MODULE,
};

const struct proto_ops dnet_proto_ops = {
        .family =       AF_DECnet,
        .owner =        THIS_MODULE,
        .release =      dn_release,
        .bind =         dn_bind,
        .connect =      dn_connect,
        .socketpair =   sock_no_socketpair,
        .accept =       dn_accept,
        .getname =      dn_getname,
        .poll =         dn_poll,
        .ioctl =        dn_ioctl,
        .listen =       dn_listen,
        .shutdown =     dn_shutdown,
        .setsockopt =   dn_setsockopt,
        .getsockopt =   dn_getsockopt,
        .sendmsg =      dn_sendmsg,
        .recvmsg =      dn_recvmsg,
        .mmap =         sock_no_mmap,
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,5,0)
        .sendpage =     sock_no_sendpage,
#endif
};

struct proto dnet_proto = {
        .name                   = "DECnet",
        .owner                  = THIS_MODULE,
        .memory_pressure        = &dn_memory_pressure,
        .memory_allocated       = &decnet_memory_allocated,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
        .per_cpu_fw_alloc       = &decnet_memory_per_cpu_fw_alloc,
#endif
        .sysctl_mem             = decnet_mem,
        .sysctl_wmem            = decnet_wmem,
        .sysctl_rmem            = decnet_rmem,
        .max_header             = NSP_MAX_DATAHDR + 64,
        .obj_size               = sizeof(struct dn_sock),
};

static struct packet_type dn_dix_packet_type __read_mostly = {
        .type =         cpu_to_be16(ETH_P_DNA_RT),
        .func =         dn_routing_rcv,
};

/*
 * Copy access control data from an sk_buff
 */
static void dn_access_copy(
  struct sk_buff *skb,
  struct accessdata_dn *acc
)
{
        uint8_t *ptr = skb->data;

        acc->acc_userl = *ptr++;
        memcpy(&acc->acc_user, ptr, acc->acc_userl);
        ptr += acc->acc_userl;

        acc->acc_passl = *ptr++;
        memcpy(&acc->acc_pass, ptr, acc->acc_passl);
        ptr += acc->acc_passl;

        acc->acc_accl = *ptr++;
        memcpy(&acc->acc_acc, ptr, acc->acc_accl);

        skb_pull(skb, acc->acc_accl + acc->acc_passl + acc->acc_userl + 3);
}

/*
 * Copy optional data from an sk_buff
 */
static void dn_user_copy(
  struct sk_buff *skb,
  struct optdata_dn *opt
)
{
        uint8_t *ptr = skb->data;

        opt->opt_optl = *ptr++;
        opt->opt_status = 0;
        memcpy(opt->opt_data, ptr, le16_to_cpu(opt->opt_optl));
        skb_pull(skb, le16_to_cpu(opt->opt_optl) + 1);
}

/*
 * Copy a struct sockaddr_dn into a connect initiate message
 */
int dn_sockaddr2username(
  struct sockaddr_dn *sdn,
  uint8_t *buf,
  uint8_t type
)
{
        int len = 2;

        *buf++ = type;

        switch (type) {
                case 0:
                        *buf++ = sdn->sdn_objnum;
                        break;
                        
                case 1:
                        *buf++ = 0;
                        *buf++ = (uint8_t)sdn->sdn_objnamel;
                        memcpy(buf, sdn->sdn_objname, sdn->sdn_objnamel);
                        len = 3 + sdn->sdn_objnamel;
                        break;
                        
                case 2:
                        memset(buf, 0, 5);
                        buf += 5;
                        *buf++ = (uint8_t)sdn->sdn_objnamel;
                        memcpy(buf, sdn->sdn_objname, sdn->sdn_objnamel);
                        len = 7 + sdn->sdn_objnamel;
                        break;
        }
        return len;
}

/*
 * Create a struct sockaddr_dn from an incoming connect initiate message
 */
int dn_username2sockaddr(
  uint8_t *data,
  int len,
  struct sockaddr_dn *sdn,
  uint8_t *fmt
)
{
        uint8_t type;
        int size = len;
        int namel = 12;

        ZEROSOCKADDR_DN(sdn);
        
        if (len < 2)
                return -1;

        len -= 2;
        *fmt = *data++;
        type = *data++;

        switch (*fmt) {
                case 0:
                        sdn->sdn_objnum = type;
                        return 2;
                        
                case 1:
                        namel = 16;
                        break;
                        
                case 2:
                        len -= 4;
                        data += 4;
                        break;

                case 4:
                        len -= 8;
                        data += 8;
                        break;

                default:
                        return -1;
        }

        len -= 1;

        if (len < 0)
                return -1;

        sdn->sdn_objnamel = *data++;
        len -= sdn->sdn_objnamel;

        if ((len < 0) || (sdn->sdn_objnamel > namel))
                return -1;

        memcpy(sdn->sdn_objname, data, sdn->sdn_objnamel);

        return size - len;
}

/*
 * Allocate an skb for message transmission. If sk != NULL the skb will
 * be associated with a socket. The "64" should be sufficient for NSP,
 * routing and ethernet headers.
 */
struct sk_buff *dn_alloc_skb(
  struct sock *sk,
  int size,
  gfp_t pri
)
{
        struct sk_buff *skb;
        int hdr = 64;

        if ((skb = alloc_skb(size + hdr, pri)) != NULL) {
                skb->protocol = htons(ETH_P_DNA_RT);
                skb->pkt_type = PACKET_OUTGOING;

                if (sk)
                        skb_set_owner_w(skb, sk);

                skb_reserve(skb, hdr);
        }
        return skb;
}

/*
 * Wait for connection to complete or fail
 */
static struct sk_buff *dn_wait_for_connect(
  struct sock *sk,
  long *timeo
)
{
        DEFINE_WAIT(wait);
        struct sk_buff *skb = NULL;
        int err = 0;

        prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
        for (;;) {
                release_sock(sk);
                skb = skb_dequeue(&sk->sk_receive_queue);
                if (skb == NULL) {
                        *timeo = schedule_timeout(*timeo);
                        skb = skb_dequeue(&sk->sk_receive_queue);
                }
                lock_sock(sk);
                if (skb != NULL)
                        break;

                err = -EINVAL;
                if (sk->sk_state != DNET_LISTEN)
                        break;
                err = sock_intr_errno(*timeo);
                if (signal_pending(current))
                        break;

                err = -EAGAIN;
                if (!*timeo)
                        break;
                prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
        }
        finish_wait(sk_sleep(sk), &wait);

        return skb == NULL ? ERR_PTR(err) : skb;
}

/*
 * Wait for connect accept to complete.
 */
static int dn_wait_for_accept(
  struct sock *sk,
  long *timeo,
  gfp_t allocation
)
{
        struct dn_scp *scp = DN_SK(sk);
        DEFINE_WAIT(wait);
        int err;

        if (scp->state != DN_CR)
                return -EINVAL;

        scp->state = DN_CC;
        scp->segsize_loc = dn_eth2segsize(scp->nextEntry);

        dn_nsp_xmt_cc(sk, allocation);

        PERSIST(scp, dn_nsp_rexmt_cc);

        prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
        for(;;) {
                release_sock(sk);
                if (scp->state == DN_CC)
                        *timeo = schedule_timeout(*timeo);
                lock_sock(sk);

                err = 0;
                if (scp->state == DN_RUN)
                        break;

                err = sock_error(sk);
                if (err)
                        break;

                err = sock_intr_errno(*timeo);
                if (signal_pending(current))
                        break;

                err = -EAGAIN;
                if (!*timeo)
                        break;

                prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
        }
        finish_wait(sk_sleep(sk), &wait);


        if (err == 0) {
                sk->sk_socket->state = SS_CONNECTED;
        } else if (scp->state != DN_CC) {
                sk->sk_socket->state = SS_UNCONNECTED;
        }
        return err;
}

/*
 * Wait for an incoming connection request
 */
static int dn_wait_run(
  struct sock *sk,
  long *timeo
)
{
        struct dn_scp *scp = DN_SK(sk);
        DEFINE_WAIT(wait);
        int err = 0;

        if (scp->state != DN_RUN) {
                if (!*timeo)
                        return -EALREADY;

                prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
                for (;;) {
                        release_sock(sk);
                        if ((scp->state == DN_CI) || (scp->state == DN_CC))
                                *timeo = schedule_timeout(*timeo);
                        lock_sock(sk);

                        err = 0;
                        if (scp->state == DN_RUN)
                                break;
                        err = sock_error(sk);
                        if (err)
                                break;
                        err = sock_intr_errno(*timeo);
                        if (signal_pending(current))
                                break;

                        err = -ETIMEDOUT;
                        if (!*timeo)
                                break;
                        prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
                }
                finish_wait(sk_sleep(sk), &wait);
        }
 
        if (err == 0) {
                sk->sk_socket->state = SS_CONNECTED;
        } else if ((scp->state != DN_CI) && (scp->state != DN_CC)) {
                sk->sk_socket->state = SS_UNCONNECTED;
        }
        
        return err;
}

/*
 * Socket layer hooks
 */

/*
 * Create address family dependent extension for the socket.
 */
static int dn_create(
  struct net *net,
  struct socket *sock,
  int protocol,
  int kern
)
{
        struct sock *sk;

        if ((protocol < 0) || (protocol > U8_MAX))
                return -EINVAL;

        if (!net_eq(net, &init_net))
                return -EAFNOSUPPORT;

        switch (sock->type) {
                case SOCK_SEQPACKET:
                        if (protocol != DNPROTO_NSP)
                                return -EPROTONOSUPPORT;

                        break;

                case SOCK_STREAM:
                        break;

                default:
                        return -ESOCKTNOSUPPORT;
        }

        if ((sk = dn_alloc_sock(net, sock, GFP_KERNEL, kern)) == NULL)
                return -ENOBUFS;

        sk->sk_protocol = protocol;
        return 0;
}

static void dn_destroy_sock(
  struct sock *sk
)
{
        struct dn_scp *scp = DN_SK(sk);

        if (sk->sk_socket) {
                if (sk->sk_socket->state != SS_UNCONNECTED)
                        sk->sk_socket->state = SS_DISCONNECTING;
        }

        sk->sk_state = DNET_CLOSE;

        switch (scp->state) {
                case DN_DN:
                        dn_nsp_xmt_disc(sk, NSP_MSG_DC, NSP_REASON_DC, sk->sk_allocation);
                        PERSIST(scp, dn_sk_destroy_timer);
                        break;
                        
                case DN_CR:
                        scp->state = DN_DR;
                        goto disc_reject;
                        
                case DN_RUN:
                        scp->state = DN_DI;
                        fallthrough;
                        
                case DN_DI:
                case DN_DR:
        disc_reject:
                        dn_nsp_xmt_disc(sk, NSP_MSG_DI, 0, sk->sk_allocation);
                        fallthrough;
                        
                case DN_NC:
                case DN_NR:
                case DN_RJ:
                case DN_DIC:
                case DN_CN:
                case DN_CD:
                        PERSIST(scp, dn_sk_destroy_timer);
                        break;
                        
                default:
                  pr_debug("DECnet: dn_destroy_sock passed socket in invalid state\n");
                  fallthrough;
                case DN_O:
                        dn_stop_slow_timer(sk);
                        dn_sk_unhash_sock_bh(sk);
                        sock_put(sk);
                        break;
        }
}

/*
 * Perform address family dependent close for the socket.
 */
static int dn_release(
  struct socket *sock
)
{
        struct sock *sk = sock->sk;

        if (sk) {
                sock_orphan(sk);
                sock_hold(sk);
                lock_sock(sk);
                dn_destroy_sock(sk);
                release_sock(sk);
                sock_put(sk);
        }
        return 0;
}

/*
 * Bind a name to a socket
 */
static int dn_bind(
  struct socket *sock,
  struct sockaddr *uaddr,
  int addr_len
)
{
        struct sock *sk = sock->sk;
        struct dn_scp *scp = DN_SK(sk);
        struct sockaddr_dn *saddr = (struct sockaddr_dn *)uaddr;
        int rv;
        
        /*
         * Validate the sockaddr_dn structure
         */
        if ((addr_len != sizeof(struct sockaddr_dn)) ||
            (saddr->sdn_family != AF_DECnet) ||
            ((le16_to_cpu(saddr->sdn_nodeaddrl) != 0) &&
             (le16_to_cpu(saddr->sdn_nodeaddrl) != 2)) ||
            (le16_to_cpu(saddr->sdn_objnamel) > DN_MAXOBJL) ||
            ((saddr->sdn_flags & ~SDF_WILD) != 0))
                return -EINVAL;

        if (!capable(CAP_NET_BIND_SERVICE) &&
            ((saddr->sdn_objnum != 0) || ((saddr->sdn_flags & SDF_WILD) != 0)))
                return -EACCES;

        if ((saddr->sdn_flags & SDF_WILD) == 0) {
                if (le16_to_cpu(saddr->sdn_nodeaddrl) != 0) {
                        if (dn_saddr2dn(saddr) != decnet_address)
                                return -EADDRNOTAVAIL;
                }
        }

        rv = -EINVAL;
        lock_sock(sk);
        if (sock_flag(sk, SOCK_ZAPPED)) {
                memcpy(&scp->addr, saddr, addr_len);
                sock_reset_flag(sk, SOCK_ZAPPED);

                rv = dn_sk_hash_sock(sk);
                if (rv)
                        sock_set_flag(sk, SOCK_ZAPPED);
        }
        release_sock(sk);
        return rv;
}

/*
 * Bind a generated name to a socket if one is not already bound
 */
static int dn_auto_bind(
  struct socket *sock
)
{
        struct sock *sk = sock->sk;
        struct dn_scp *scp = DN_SK(sk);
        int rv;

        sock_reset_flag(sk, SOCK_ZAPPED);

        ZEROSOCKADDR_DN(&scp->addr);
        
        /*
         * Build a unique name binding for this socket.
         */
        scp->addr.sdn_objnamel = 9;
        sprintf(scp->addr.sdn_objname, "Linux%04x", scp->addrloc);

        scp->addr.sdn_nodeaddrl = 2;
        *(uint16_t *)&scp->addr.sdn_nodeaddr = decnet_address;

        rv = dn_sk_hash_sock(sk);
        if (rv)
                sock_set_flag(sk, SOCK_ZAPPED);

        return rv;
}

static int __dn_connect(
  struct sock *sk,
  struct sockaddr_dn *saddr,
  int addrlen,
  long *timeo,
  int flags
)
{
        struct socket *sock = sk->sk_socket;
        struct dn_scp *scp = DN_SK(sk);
        int err = -EISCONN;
        uint16_t dstaddr;
        
        if (sock->state == SS_CONNECTED)
                goto out;

        if (sock->state == SS_CONNECTING) {
                err = 0;
                if (scp->state == DN_RUN) {
                        sock->state = SS_CONNECTED;
                        goto out;
                }

                err = -ECONNREFUSED;
                if ((scp->state != DN_CI) && (scp->state != DN_CC)) {
                        sock->state = SS_UNCONNECTED;
                        goto out;
                }

                return dn_wait_run(sk, timeo);
        }

        err = -EINVAL;

        if (scp->state != DN_O)
                goto out;

        /*
         * Validate the sockaddr_dn structure
         */
        if ((saddr == NULL) ||
            (addrlen != sizeof(struct sockaddr_dn)) ||
            (saddr->sdn_family != AF_DECnet) ||
            ((saddr->sdn_flags & SDF_WILD) != 0))
                goto out;

        if (sock_flag(sk, SOCK_ZAPPED)) {
                err = dn_auto_bind(sk->sk_socket);
                if (err)
                        goto out;
        }

        dstaddr = dn_saddr2dn(saddr);

        /*
         * Check for special handling of zero address fields:
         *
         *      0.0     => connect to this node
         *      0.n     => connect to address n in this node's area
         *      a.0     => invalid address
         */
        if (dstaddr == 0)
                dstaddr = decnet_address;
        else if ((dstaddr & 0xFC00) == 0)
                dstaddr |= decnet_address & 0xFC00;
        else if ((dstaddr & 0x3FF) == 0)
                goto out;

        memcpy(&scp->peer, saddr, sizeof(struct sockaddr_dn));
        *(uint16_t *)&scp->peer.sdn_nodeaddr = dstaddr;

        err = -ENOMEM;

        if ((scp->nextEntry = dn_next_update_and_hold(dstaddr, NULL, 0)) == NULL)
                goto out;
        if ((scp->nodeEntry = dn_node_lookup(dstaddr)) == NULL)
                goto out;

        err = -EHOSTUNREACH;

        sock->state = SS_CONNECTING;
        scp->state = DN_CI;

        scp->segsize_loc = dn_eth2segsize(scp->nextEntry);

        dn_nsp_xmt_ci(sk, NSP_MSG_CI, 1);
        Count_connect_sent(scp->nodeEntry);

        PERSIST(scp, dn_nsp_rexmt_ci);

        err = -EINPROGRESS;
        if (*timeo)
                err = dn_wait_run(sk, timeo);
 out:
        return err;
}

static int dn_connect(
  struct socket *sock,
  struct sockaddr *uaddr,
  int addrlen,
  int flags
)
{
        struct sock *sk = sock->sk;
        long timeo = sock_sndtimeo(sk, flags & O_NONBLOCK);
        int err;

        lock_sock(sk);
        err = __dn_connect(sk, (struct sockaddr_dn *)uaddr, addrlen, &timeo, 0);
        release_sock(sk);
        return err;
}

static int dn_accept(
  struct socket *sock,
  struct socket *newsock,
  int flags,
  bool kern
)
{
        struct sock *sk = sock->sk, *newsk;
        struct dn_scp *scp = DN_SK(sk), *newscp;
        struct sk_buff *skb = NULL;
        struct dn_skb_cb *cb;
        struct dn_node_entry *nodep = NULL;
        struct dn_next_entry *nextp = NULL;
        int err = 0;
        long timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);
        uint8_t menuver, type;

        lock_sock(sk);
        if ((sk->sk_state != DNET_LISTEN) || (scp->state != DN_O)) {
                release_sock(sk);
                return -EINVAL;
        }

 try_again:
        skb = skb_dequeue(&sk->sk_receive_queue);
        if (skb == NULL) {
                skb = dn_wait_for_connect(sk, &timeo);
                if (IS_ERR(skb)) {
                        release_sock(sk);
                        return PTR_ERR(skb);
                }
        }

        cb = DN_SKB_CB(skb);
        sk_acceptq_removed(sk);

        /*
         * Now we can check if this is a duplicate Connect-Initiate and
         * there is already a socket set up for this logical link. Note
         * we perform this check for all inbound messages (Connect-Initiate
         * and Retransmitted Connect-Initiate) since a routing topology
         * change may have re-ordered the message sequence.
         */
        if (dn_sk_check_duplicate(skb)) {
                kfree_skb(skb);
                goto try_again;
        }

        nodep = dn_node_lookup(cb->src);
        nextp = dn_next_update_and_hold(cb->src, NULL, 0);
        if ((nodep == NULL) || (nextp == NULL)) {
                if (nodep != NULL)
                        dn_node_release(nodep, 0);
                if (nextp != NULL)
                        dn_next_release(nextp);
                release_sock(sk);
                kfree_skb(skb);
                return -ENOMEM;
        }

        newsk = dn_alloc_sock(sock_net(sk), newsock, sk->sk_allocation, kern);
        if (newsk == NULL) {
                dn_node_release(nodep, 0);
                dn_next_release(nextp);
                release_sock(sk);
                kfree_skb(skb);
                return -ENOBUFS;
        }
        release_sock(sk);

        newscp = DN_SK(newsk);
        newscp->state = DN_CR;
        newscp->nodeEntry = nodep;
        newscp->nextEntry = nextp;
        newscp->addrrem = cb->src_port;
        newscp->data.services_rem = cb->services;
        newscp->data.services_loc = NSP_FCOPT_NONE;
        newscp->info_rem = cb->info;
        newscp->segsize_rem = cb->segsize;
        if ((cb->rt_flags & RT_FLG_IE) != 0)
                newscp->segsize_rem = dn_eth2segsize(newscp->nextEntry);
        else dn_segsize2eth(newscp->nextEntry, newscp->segsize_rem);
        newscp->accept_mode = scp->accept_mode;

        newsk->sk_state = DNET_LISTEN;
        memcpy(&newscp->addr, &scp->addr, sizeof(struct sockaddr_dn));

        /*
         * If we are listening on a wild card socket, we don't want the newly
         * created socket on the wrong hash queue.
         */
        newscp->addr.sdn_flags &= ~SDF_WILD;

        skb_pull(skb, dn_username2sockaddr(skb->data, skb->len, &newscp->addr, &type));
        skb_pull(skb, dn_username2sockaddr(skb->data, skb->len, &newscp->peer, &type));

        *(uint16_t *)(newscp->peer.sdn_add.a_addr) = cb->src;
        *(uint16_t *)(newscp->addr.sdn_add.a_addr) = cb->dst;

        menuver = *skb->data;
        skb_pull(skb, 1);

        if ((menuver & NSP_MENU_ACC) != 0)
                dn_access_copy(skb, &newscp->accessdata);

        if ((menuver  & NSP_MENU_USR) != 0)
                dn_user_copy(skb, &newscp->conndata_in);

        if ((menuver & NSP_MENU_PROXY) != 0)
                newscp->peer.sdn_flags |= SDF_PROXY;

        if ((menuver & NSP_MENU_UIC) != 0)
                newscp->peer.sdn_flags |= SDF_UICPROXY;

        kfree_skb(skb);

        memcpy(&newscp->conndata_out, &scp->conndata_out, sizeof(struct optdata_dn));
        memcpy(&newscp->discdata_out, &scp->discdata_out, sizeof(struct optdata_dn));

        lock_sock(newsk);
        err = dn_sk_hash_sock(newsk);
        if (err == 0) {
                sock_reset_flag(newsk, SOCK_ZAPPED);
                dn_nsp_xmt_ack_ci(newsk);
                Count_connect_rcvd(newscp->nodeEntry);
                
                /*
                 * Here we use sk->sk_allocation since, although the connect
                 * confirm is for the newsk, the context is the old socket.
                 */
                if (newscp->accept_mode == ACC_IMMED)
                        err = dn_wait_for_accept(newsk, &timeo, sk->sk_allocation);
        }
        release_sock(newsk);

        return err;
}

/*
 * Get local or remote sockaddr_dn structure
 */
static int dn_getname(
  struct socket *sock,
  struct sockaddr *uaddr,
  int peer
)
{
        struct sockaddr_dn *sa = (struct sockaddr_dn *)uaddr;
        struct sock *sk = sock->sk;
        struct dn_scp *scp = DN_SK(sk);

        lock_sock(sk);

        if (peer) {
                if (((sock->state != SS_CONNECTED) &&
                     (sock->state != SS_CONNECTING)) &&
                    (scp->accept_mode == ACC_IMMED)) {
                        release_sock(sk);
                        return -ENOTCONN;
                }
                memcpy(sa, &scp->peer, sizeof(struct sockaddr_dn));
        } else {
                memcpy(sa, &scp->addr, sizeof(struct sockaddr_dn));
        }
        
        release_sock(sk);
        return sizeof(struct sockaddr_dn);
}

static __poll_t dn_poll(
  struct file *file,
  struct socket *sock,
  poll_table *wait
)
{
        struct sock *sk = sock->sk;
        struct dn_scp *scp = DN_SK(sk);
        __poll_t mask = datagram_poll(file, sock, wait);

        if (!skb_queue_empty(&scp->other_receive_queue))
                mask |= EPOLLRDBAND;

        return mask;
}

static int dn_ioctl(
  struct socket *sock,
  unsigned int cmd,
  unsigned long arg
)
{
        struct sock *sk = sock->sk;
        struct dn_scp *scp = DN_SK(sk);
        struct sk_buff *skb;
        long amount = 0;
        int err, val;

        switch (cmd) {
                case SIOCGIFADDR:
                case SIOCSIFADDR:
                        return -EINVAL;

                case SIOCATMARK:
                        lock_sock(sk);
                        val = !skb_queue_empty(&scp->other_receive_queue);
                        if (scp->state != DN_RUN)
                                val = -ENOTCONN;
                        release_sock(sk);
                        return val;

                case TIOCOUTQ:
                        amount = sk->sk_sndbuf - sk_wmem_alloc_get(sk);
                        if (amount < 0)
                                amount = 0;
                        err = put_user(amount, (int __user *)arg);
                        break;

                case TIOCINQ:
                        lock_sock(sk);
                        skb = skb_peek(&scp->other_receive_queue);
                        if (skb) {
                                amount = skb->len;
                        } else {
                                skb_queue_walk(&sk->sk_receive_queue, skb)
                                        amount += skb->len;
                        }
                        release_sock(sk);
                        err = put_user(amount, (int __user *)arg);
                        break;

                default:
                        err = -ENOIOCTLCMD;
                        break;
        }
        return err;
}

static int dn_listen(
  struct socket *sock,
  int backlog
)
{
        struct sock *sk = sock->sk;
        int err = -EINVAL;

        lock_sock(sk);
        if (!sock_flag(sk, SOCK_ZAPPED)) {
                if ((DN_SK(sk)->state == DN_O) && (sk->sk_state != DNET_LISTEN)) {
                        sk->sk_max_ack_backlog = backlog;
                        sk->sk_ack_backlog = 0;
                        sk->sk_state = DNET_LISTEN;
                        err = 0;
                        dn_sk_rehash_sock(sk);
                }
        }
        release_sock(sk);

        return err;
}

static int dn_shutdown(
  struct socket *sock,
  int how
)
{
        struct sock *sk = sock->sk;
        struct dn_scp *scp = DN_SK(sk);
        int err = -ENOTCONN;

        lock_sock(sk);
        if (sock->state != SS_UNCONNECTED) {
                err = 0;
                if (sock->state != SS_DISCONNECTING) {
                        err = -EINVAL;
                        if (scp->state != DN_O) {
                                if (how == SHUT_RDWR) {
                                        sk->sk_shutdown = SHUTDOWN_MASK;
                                        dn_destroy_sock(sk);
                                        err = 0;
                                }
                        }
                }
        }
        release_sock(sk);

        return err;
}

static int __dn_setsockopt(
  struct socket *sock,
  int level,
  int optname,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0)
  sockptr_t optval,
#else
  char __user *optval,
#endif
  unsigned int optlen
)
{
        struct sock *sk = sock->sk;
        struct dn_scp *scp = DN_SK(sk);
        long timeo;
        union {
                struct optdata_dn       opt;
                struct accessdata_dn    acc;
                int                     mode;
        } u;
        int err;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0)
        if (optlen && sockptr_is_null(optval))
                return -EINVAL;

        if (optlen > sizeof(u))
                return -EINVAL;

        if (copy_from_sockptr(&u, optval, optlen))
                return -EINVAL;
#else
        if (optlen && !optval)
                return -EINVAL;

        if (optlen > sizeof(u))
                return -EINVAL;

        if (copy_from_user(&u, optval, optlen))
                return -EINVAL;
#endif

        switch (optname) {
                case DSO_CONDATA:
                        if (sock->state == SS_CONNECTED)
                                return -EISCONN;
                        if ((scp->state != DN_O) && (scp->state != DN_CR))
                                return -EINVAL;

                        if (optlen !=  sizeof(struct optdata_dn))
                                return -EINVAL;

                        if (le16_to_cpu(u.opt.opt_optl) > 16)
                                return -EINVAL;

                        memcpy(&scp->conndata_out, &u.opt, optlen);
                        break;

                case DSO_DISDATA:
                        if ((sock->state != SS_CONNECTED) &&
                            (scp->accept_mode == ACC_IMMED))
                                return -ENOTCONN;

                        if (optlen != sizeof(struct optdata_dn))
                                return -EINVAL;

                        if (le16_to_cpu(u.opt.opt_optl) > 16)
                                return -EINVAL;

                        memcpy(&scp->discdata_out, &u.opt, optlen);
                        break;

                case DSO_CONACCESS:
                        if (sock->state == SS_CONNECTED)
                                return -EISCONN;
                        if (scp->state != DN_O)
                                return -EINVAL;

                        if (optlen != sizeof(struct accessdata_dn))
                                return -EINVAL;

                        if ((u.acc.acc_accl > DN_MAXACCL) ||
                            (u.acc.acc_passl > DN_MAXACCL) ||
                            (u.acc.acc_userl > DN_MAXACCL))
                                return -EINVAL;

                        memcpy(&scp->accessdata, &u.acc, optlen);
                        break;

                case DSO_ACCEPTMODE:
                        if (sock->state == SS_CONNECTED)
                                return -EISCONN;
                        if (scp->state != DN_O)
                                return -EINVAL;

                        if (optlen != sizeof(int))
                                return -EINVAL;

                        scp->accept_mode = (unsigned char)u.mode;
                        break;

                case DSO_CONACCEPT:
                        if (scp->state != DN_CR)
                                return -EINVAL;
                        timeo = sock_rcvtimeo(sk, 0);
                        err = dn_wait_for_accept(sk, &timeo, sk->sk_allocation);
                        return err;

                case DSO_CONREJECT:
                        if (scp->state != DN_CR)
                                return -EINVAL;

                        scp->state = DN_DR;
                        sk->sk_shutdown = SHUTDOWN_MASK;
                        dn_nsp_xmt_disc(sk, NSP_MSG_DI, 0, sk->sk_allocation);
                        break;

                default:
                        return -ENOPROTOOPT;
        }

        return 0;
}

static int dn_setsockopt(
  struct socket *sock,
  int level,
  int optname,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0)
  sockptr_t optval,
#else
  char __user *optval,
#endif
  unsigned int optlen
)
{
        int err;
        
        lock_sock(sock->sk);
        err = __dn_setsockopt(sock, level, optname, optval, optlen);
        release_sock(sock->sk);
        return err;
}

static int __dn_getsockopt(
  struct socket *sock,
  int level,
  int optname,
  char __user *optval,
  int __user *optlen
)
{
        struct sock *sk = sock->sk;
        struct dn_scp *scp = DN_SK(sk);
        struct linkinfo_dn link;
        unsigned int r_len;
        void *r_data = NULL;

        if (get_user(r_len, optlen))
                return -EFAULT;

        switch (optname) {
                case DSO_CONDATA:
                        if (r_len > sizeof(struct optdata_dn))
                                r_len = sizeof(struct optdata_dn);
                        r_data = &scp->conndata_in;
                        break;

                case DSO_DISDATA:
                        if (r_len > sizeof(struct optdata_dn))
                                r_len = sizeof(struct optdata_dn);
                        r_data = &scp->discdata_in;
                        break;

                case DSO_CONACCESS:
                        if (r_len > sizeof(struct accessdata_dn))
                                r_len = sizeof(struct accessdata_dn);
                        r_data = &scp->accessdata;
                        break;

                case DSO_ACCEPTMODE:
                        if (r_len > sizeof(unsigned char))
                                r_len = sizeof(unsigned char);
                        r_data = &scp->accept_mode;
                        break;

                case DSO_LINKINFO:
                        if (r_len > sizeof(struct linkinfo_dn))
                                r_len = sizeof(struct linkinfo_dn);

                        memset(&link, 0, sizeof(link));

                        switch (sock->state) {
                                case SS_CONNECTING:
                                        link.idn_linkstate = LL_CONNECTING;
                                        break;

                                case SS_DISCONNECTING:
                                        link.idn_linkstate = LL_DISCONNECTING;
                                        break;

                                case SS_CONNECTED:
                                        link.idn_linkstate = LL_RUNNING;
                                        break;

                                default:
                                        link.idn_linkstate = LL_INACTIVE;
                                        break;
                        }
                        link.idn_segsize = scp->segsize_rem;
                        r_data = &link;
                        break;
                        
                default:
                        return -ENOPROTOOPT;
        }

        if (r_data) {
                /*
                 * Copy the data through a bounce buffer in case
                 * CONFIG_HARDENED_USERCOPY is defined.
                 */
                union {
                        struct optdata_dn       optdata;
                        struct accessdata_dn    accessdata;
                        unsigned char           mode;
                        struct linkinfo_dn      linkinfo;
                } bounce;

                memcpy(&bounce, r_data, r_len);
                if (copy_to_user(optval, &bounce, r_len))
                        return -EFAULT;
                if (put_user(r_len, optlen))
                        return -EFAULT;
        }

        return 0;
}

static int dn_getsockopt(
  struct socket *sock,
  int level,
  int optname,
  char __user *optval,
  int __user *optlen
)
{
        int err;

        lock_sock(sock->sk);
        err = __dn_getsockopt(sock, level, optname, optval, optlen);
        release_sock(sock->sk);
        return err;
}

/*
 * Determine if there is some data which can be read
 */
static int dn_data_ready(
  struct sock *sk,
  struct sk_buff_head *q,
  int flags,
  int target,
  int framing
)
{
        struct sk_buff *skb;
        int len = 0;

        if ((flags & MSG_OOB) != 0)
                return !skb_queue_empty(q) ? 1 : 0;

        skb_queue_walk(q, skb) {
                struct dn_skb_cb *cb = DN_SKB_CB(skb);

                len += skb->len;

                if ((cb->nsp_flags & NSP_MSG_EOM) != 0) {
			/*
			 * If we are using message framing (SOCK_SEQPACKET
	`		 * of WAITALL) we read to EOM.
			 */
			if (framing != 0)
				return 1;
                }

                /*
                 * Only SOCK_STREAM  terminates on a length check.
                 */
                if (sk->sk_type == SOCK_STREAM) {
                        /*
                         * Minimum read data length exceeded?
                         */
                        if (len >= target)
                                return 1;
                }
        }
        return 0;
}

/*
 * State dependent processing for recvmsg/sendmsg. Note that socket is locked.
 */
static inline int dn_check_state(
  struct sock *sk,
  struct sockaddr_dn *addr,
  int addrlen,
  long *timeo,
  int flags
)
{
        struct dn_scp *scp = DN_SK(sk);

        switch (scp->state) {
                case DN_RUN:
                        return 0;
                        
                case DN_CR:
                        return dn_wait_for_accept(sk, timeo, sk->sk_allocation);
                        
                case DN_CI:
                case DN_CC:
                        return dn_wait_run(sk, timeo);
                        
                case DN_O:
                        return __dn_connect(sk, addr, addrlen, timeo, flags);
        }
        return -EINVAL;
}

/*
 * Process read operations
 */
static int dn_recvmsg(
  struct socket *sock,
  struct msghdr *msg,
  size_t size,
  int flags
)
{
        struct sock *sk = sock->sk;
        struct dn_scp *scp = DN_SK(sk);
        struct sk_buff_head *queue = &sk->sk_receive_queue;
        size_t target = size > 1 ? 1 : 0;
        size_t copied = 0;
        int rv = 0;
        struct sk_buff *skb, *n;
        long timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);
	int msg_framing = 1;

	if ((sock->type == SOCK_STREAM) &&
	    ((flags & (MSG_WAITALL | MSG_OOB)) == 0))
		msg_framing = 0;

        lock_sock(sk);

        if (sock_flag(sk, SOCK_ZAPPED)) {
                rv = -EADDRNOTAVAIL;
                goto out;
        }

        if ((sk->sk_shutdown & RCV_SHUTDOWN) != 0) {
                rv = 0;
                goto out;
        }

        rv = dn_check_state(sk, NULL, 0, &timeo, flags);
        if (rv)
                goto out;

        if (flags & ~(MSG_CMSG_COMPAT|MSG_PEEK|MSG_OOB|MSG_WAITALL|MSG_DONTWAIT|MSG_NOSIGNAL)) {
                rv = -EOPNOTSUPP;
                goto out;
        }

        if ((flags & MSG_OOB) != 0)
                queue = &scp->other_receive_queue;

        if ((flags & MSG_WAITALL) != 0)
                target = size;

        /*
         * See if the requested data can be read, sleep if not
         */
        for (;;) {
                DEFINE_WAIT_FUNC(wait, woken_wake_function);

                if (sk->sk_err)
                        goto out;

                rv = 0;
                
                if (!skb_queue_empty(&scp->other_receive_queue)) {
                        if ((flags & MSG_OOB) == 0) {
                                /*
                                 * Tell the user that an interupt message is
                                 * available.
                                 */
                                msg->msg_flags |= MSG_OOB;
                        }
                }

                if (scp->state != DN_RUN)
                        goto out;

                if (signal_pending(current)) {
                        rv = sock_intr_errno(timeo);
                        goto out;
                }

                if (dn_data_ready(sk, queue, flags, target, msg_framing))
                        break;

                if ((flags & MSG_DONTWAIT) != 0) {
                        rv = -EWOULDBLOCK;
                        goto out;
                }

                add_wait_queue(sk_sleep(sk), &wait);
                sk_set_bit(SOCKWQ_ASYNC_WAITDATA, sk);
                sk_wait_event(sk, &timeo, dn_data_ready(sk, queue, flags, target, msg_framing), &wait);
                sk_clear_bit(SOCKWQ_ASYNC_WAITDATA, sk);
                remove_wait_queue(sk_sleep(sk), &wait);
        }
        
        /*
         * Copy the data from the buffer(s) into the user's buffer
         */
        skb_queue_walk_safe(queue, skb, n) {
                unsigned int chunk = skb->len;
                struct dn_skb_cb *cb = DN_SKB_CB(skb);
                uint8_t eor = cb->nsp_flags & NSP_MSG_EOM;

                if ((chunk + copied) > size)
                        chunk = size - copied;

                if (chunk != 0) {
                        if (memcpy_to_msg(msg, skb->data, chunk)) {
                                rv = -EFAULT;
                                break;
                        }
                        copied += chunk;

                        /*
                         * If we consumed all of this buffer and EOM is set
                         * indicate an End-Of_Record to the user.
                         */
                        if (eor && (skb->len == chunk))
                                msg->msg_flags |= MSG_EOR;

                        if ((flags & MSG_PEEK) == 0)
                                skb_pull(skb, chunk);
                }

		/*
		 * Decide if we need to unlink and free this skb
		 */
		if ((flags & MSG_PEEK) == 0) {
			if ((skb->len == 0) ||
			     ((copied == size) && (msg_framing != 0))) {
                        	skb_unlink(skb, queue);
                        	kfree_skb(skb);

                        	if ((flags & MSG_OOB) != 0) {
                                	dn_nsp_sched_pending(sk, DN_PEND_INTR);
                        	} else {
                                	if ((scp->data.flowloc_sw == DN_DONTSEND) &&
                                    	     !dn_congested(sk)) {
                                        	scp->data.flowloc_sw = DN_SEND;
                                        	dn_nsp_sched_pending(sk, DN_PEND_SW);
                                	}
				}
                        }
                }

		if (eor && (msg_framing != 0))
			break;

                if ((flags & MSG_OOB) != 0)
                        break;

		if (sock->type == SOCK_STREAM)
                	if (copied >= target)
                        	break;
        }

        rv = copied;
        
 out:
        if (rv == 0)
                rv = (flags & MSG_PEEK) ? -sk->sk_err : sock_error(sk);

        if ((rv >= 0) && msg->msg_name) {
                __sockaddr_check_size(sizeof(struct sockaddr_dn));
                memcpy(msg->msg_name, &scp->peer, sizeof(struct sockaddr_dn));
                msg->msg_namelen = sizeof(struct sockaddr_dn);
        }
                  
        release_sock(sk);
        return rv;
}

/*
 * Check if an interrupt message is queued for transmission
 */
static inline int dn_intr_xmt_pending(
  struct sk_buff_head *queue
)
{
        struct sk_buff *skb;

        skb_queue_walk(queue, skb) {
                if (DN_SKB_CB(skb)->nsp_flags == NSP_MSG_INTR)
                        return 1;
        }
        return 0;
}

/*
 * Check if channel is blocked from transmitting by flow control
 */
static inline int dn_is_blocked(
  struct sock *sk,
  struct dn_scp *scp,
  struct sk_buff_head *queue,
  int flags
)
{
        if ((flags & MSG_OOB) != 0) {
                if ((scp->other.flowrem == 0) || dn_intr_xmt_pending(queue))
                        return 1;
        } else {
        	if (sk_wmem_alloc_get(sk) >= READ_ONCE(sk->sk_sndbuf))
               		return 1;
        
                if (skb_queue_len(queue) >= scp->snd_window)
                        return 1;

                if (scp->data.services_rem != NSP_FCOPT_NONE) {
                        if (scp->data.flowrem == 0)
                                return 1;
                } else {
                        if (scp->data.flowrem_sw == DN_DONTSEND)
                                return 1;
                }
        }
        return 0;
}

static inline unsigned int dn_current_mss(
  struct sock *sk,
  int flags
)
{
        struct dn_scp *scp = DN_SK(sk);
        int mss = min_t(int, scp->segsize_loc, scp->segsize_rem);

        if ((flags & MSG_OOB) != 0)
                return 16;

        return min_t(int, dn_devices[scp->nextEntry->deviceIndex].blksize, mss);
}


/*
 * Allocate an skb to transmit a data segment
 */
static inline struct sk_buff *dn_alloc_xmt_pskb(
  struct sock *sk,
  unsigned long datalen,
  int noblock,
  int *errcode
)
{
        struct sk_buff *skb = sock_alloc_send_skb(sk, datalen, noblock, errcode);

        if (skb) {
                skb->protocol = htons(ETH_P_DNA_RT);
                skb->pkt_type = PACKET_OUTGOING;
        }
        return skb;
}

static int dn_sendmsg(
  struct socket *sock,
  struct msghdr *msg,
  size_t size
)
{
        struct sock *sk = sock->sk;
        struct dn_scp *scp = DN_SK(sk);
        struct sk_buff_head *queue = &scp->data.xmit_queue;
        int flags = msg->msg_flags;
        int err = 0;
        size_t mss, len;
        size_t sent = 0;
        int addr_len = msg->msg_namelen;
        DECLARE_SOCKADDR(struct sockaddr_dn *, addr, msg->msg_name);
        struct sk_buff *skb = NULL;
        struct dn_skb_cb *cb;
        long timeo;

        if (flags & ~(MSG_TRYHARD|MSG_OOB|MSG_DONTWAIT|MSG_EOR|MSG_NOSIGNAL|MSG_MORE|MSG_CMSG_COMPAT))
                return -EOPNOTSUPP;

        if (addr_len && (addr_len != sizeof(struct sockaddr_dn)))
                return -EINVAL;

        lock_sock(sk);

        timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

        /*
         * SOCK_STREAM sockets should not include MSG_EOR in their flags but
         * sendmsg should operate as though it was set.
         */
        if (sock->type == SOCK_STREAM) {
                if ((flags & MSG_EOR) != 0) {
                        err = -EINVAL;
                        goto out;
                }
                flags |= MSG_EOR;
        }

        err = dn_check_state(sk, addr, addr_len, &timeo, flags);
        if (err)
                goto out_err;

        if ((sk->sk_shutdown & SEND_SHUTDOWN) != 0) {
                err = -EPIPE;
                if (!(flags & MSG_NOSIGNAL))
                        send_sig(SIGPIPE, current, 0);
                goto out_err;
        }

        if ((flags & MSG_TRYHARD) != 0)
                dn_next_tryhard(scp->nextEntry);

        mss = dn_current_mss(sk, flags);

        if ((flags & MSG_OOB) != 0) {
                queue = &scp->other.xmit_queue;
                if (size > mss) {
                        err = -EMSGSIZE;
                        goto out;
                }
        }

        PERSIST(scp, dn_nsp_xmt_timeout);

        while (sent < size) {
                err = sock_error(sk);
                if (err)
                        goto out;

                if (signal_pending(current)) {
                        err = sock_intr_errno(timeo);
                        goto out;
                }

                /*
                 * Calculate how much we can send
                 */
                len = size - sent;

                if (len > mss)
                        len = mss;

                /*
                 * Wait for the queue to drop below the window size
                 */
                if (dn_is_blocked(sk, scp, queue, flags)) {
                        DEFINE_WAIT_FUNC(wait, woken_wake_function);

                        if ((flags & MSG_DONTWAIT) != 0) {
                                err = -EWOULDBLOCK;
                                goto out;
                        }

                        add_wait_queue(sk_sleep(sk), &wait);
                        sk_set_bit(SOCKWQ_ASYNC_WAITDATA, sk);
                        sk_wait_event(sk, &timeo,
                                      !dn_is_blocked(sk, scp, queue, flags), &wait);
                        sk_clear_bit(SOCKWQ_ASYNC_WAITDATA, sk);
                        remove_wait_queue(sk_sleep(sk), &wait);
                        continue;
                }

                /*
                 * Allocate a suitable skb
                 */
                skb = dn_alloc_xmt_pskb(sk, len + 64 + NSP_MAX_DATAHDR,
                                        flags & MSG_DONTWAIT, &err);

                if (!skb)
                        break;

                cb = DN_SKB_CB(skb);

                skb_reserve(skb, 64 + NSP_MAX_DATAHDR);

                if (memcpy_from_msg(skb_put(skb, len), msg, len)) {
                        err = -EFAULT;
                        goto out;
                }

                cb->datalen = len;
                
                if ((flags & MSG_OOB) != 0) {
                        cb->nsp_flags = NSP_MSG_INTR;
                        scp->other.flowrem--;
                } else {
                        cb->nsp_flags = NSP_MSG_DATA;
                        if (scp->seg_total == 0)
                                cb->nsp_flags |= NSP_MSG_BOM;

                        scp->seg_total += len;

                        if (((sent + len) == size) &&
                            ((flags & MSG_EOR) != 0)) {
                                cb->nsp_flags |= NSP_MSG_EOM;
                                scp->seg_total = 0;
                                if (scp->data.services_rem == NSP_FCOPT_SEG)
                                        scp->data.flowrem--;
                        }

                        if (scp->data.services_rem == NSP_FCOPT_MSG)
                                scp->data.flowrem--;
                }

                sent += len;

                /*
                 * Decide if we should allow the ack for this segment to
                 * be delayed.
                 */
                if ((flags & MSG_OOB) == 0) {
                        int acksallowed = min_t(int, decnet_dlyack_seq, scp->snd_window);

                        if ((++scp->delayedacks < acksallowed) &&
                            (sent != size))
                                cb->ack_delay = 1;
                        else scp->delayedacks = 0;
                }

                dn_nsp_queue_xmt(sk, skb, sk->sk_allocation, flags & MSG_OOB);
                skb = NULL;
        }

 out:
        kfree_skb(skb);
        release_sock(sk);

        return sent ? sent : err;

 out_err:
        err = sk_stream_error(sk, flags, err);
        release_sock(sk);
        return err;
}

#ifdef CONFIG_PROC_FS

#define ISNUM(x)        (((x) >= '0') && ((x) <= '9'))
#define ISLOWER(x)      (((x) >= 'a') && ((x) <= 'z'))
#define ISUPPER(x)      (((x) >= 'A') && ((x) <= 'Z'))
#define ISALPHA(x)      (ISLOWER(x) || ISUPPER(x))
#define ISALPHANUM(x)   (ISNUM(x) || ISALPHA(x))
#define TOUPPER(x)      (ISLOWER(x) ? ((x) + ('A' - 'a')) : (x))

/*
 * /proc entry to handle "zero" operations:
 *
 *      /proc/net/decnet_zero_node
 *
 *              write node address to this file to zero counters for
 *              this specific address. Write "*" to zero counter for
 *              all entries in the node cache.
 */
int dnet_zero_write(
  struct file *filep,
  char *buf,
  size_t count
)
{
        char *str = buf;
        uint16_t addr, area, node;

        if (count >= DN_ASCBUF_LEN)
                return -EMSGSIZE;

        if (strcmp(buf, "*") != 0) {
                while (*str && !(ISNUM(*str))) str++;

                if (*str == 0)
                        return -EINVAL;

                if (!ISNUM(*str))
                        return -EINVAL;
                area = *str++ - '0';
                if (ISNUM(*str)) {
                        area *= 10;
                        area += *str++ -'0';
                }

                if (*str++ != '.')
                        return -EINVAL;

                if (!ISNUM(*str))
                	return -EINVAL;
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
                	return -EINVAL;

                if (ISALPHANUM(*str))
                        return -EINVAL;

                addr = (area << 10) | node;
        } else addr = 0;

        dn_node_zero_counters(addr);

        return 0;
}

#endif

MODULE_DESCRIPTION("DECnet Ethernet Endnode Implementation");
MODULE_AUTHOR("John Forecast");
MODULE_LICENSE("GPL");
MODULE_ALIAS_NETPROTO(PF_DECnet);

extern int dn_dev_init(void), dn_next_init(void), dn_node_init(void);
extern void dn_dev_exit(void);

static const char banner[] __initconst = KERN_INFO
        "DECnet Ethernet Endnode for Linux V" DNET_REVISION " (C) 2023 John Forecast\n";

static int __init dnet_init(void)
{
        int max_rshare, max_wshare, rc = 0;
        unsigned long limit;

        limit = max(nr_free_buffer_pages() / 16, 128UL);
        decnet_mem[0] = limit / 4 * 3;
        decnet_mem[1] = limit;
        decnet_mem[2] = decnet_mem[0] * 2;

        limit = nr_free_buffer_pages() << (PAGE_SHIFT - 7);
        max_wshare = min(4UL * 1024 * 1024, limit);
        max_rshare = min(6UL * 1024 * 1024, limit);

        decnet_wmem[0] = PAGE_SIZE;
        decnet_wmem[1] = 16 * 1024;
        decnet_wmem[2] = max(64 * 1024, max_wshare);

        decnet_rmem[0] = PAGE_SIZE;
        decnet_rmem[1] = 128 * 1024;
        decnet_rmem[2] = max(128 * 1024, max_rshare);

#ifdef DEBUG
        trc_init();
#endif
        
        dn_rtrchange = get_jiffies_64();
        
        /*
         * Make sure mandatory parameters are present.
         */
        if ((dn_ifname != NULL ) && (dn_nodeaddr != NULL)) {
                printk(banner);

                if ((rc = proto_register(&dnet_proto, 1)) == 0) {
                        if ((rc = dn_dev_init() == 0) &&
                            (rc = dn_next_init() == 0) &&
                            (rc = dn_node_init() == 0)) {
                                dn_sock_init();
                                sock_register(&dnet_family_ops);
                                dev_add_pack(&dn_dix_packet_type);
                                dn_register_sysctl();

#ifdef CONFIG_PROC_FS
				proc_create_net_single_write("decnet_zero_node",
							      0222,
							      init_net.proc_net,
							      NULL,
							      dnet_zero_write,
							      NULL);
#endif
                                return 0;
                        }
                }
        } else {
                if (dn_ifname == NULL)
                        pr_info("Required DECnet parameter \"ifname\" missing\n");
                if (dn_nodeaddr == NULL)
                        pr_info("Required DECnet parameter \"nodeaddr\" missing\n");
                rc = -ENODEV;
        }
        pr_info("DECnet load failed (%d)\n", rc);
        return rc;
}

void __exit dnet_exit(void)
{
#ifdef CONFIG_PROC_FS
        remove_proc_entry("decnet_zero_node", NULL);
#endif
        dn_dev_exit();
}

module_init(dnet_init);
module_exit(dnet_exit);
