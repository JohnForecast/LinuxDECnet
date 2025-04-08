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

#ifndef __DNET_SOCK_H__
#define __DNET_SOCK_H__

struct dn_sock_seq_state {
        int                     bucket;
};

int dn_sk_hash_sock(struct sock *);
void dn_sk_unhash_sock_bh(struct sock *);
void dn_sk_rehash_sock(struct sock *);
struct sock *dn_sk_find_listener(struct sockaddr_dn *);
struct sock *dn_sk_lookup_by_skb(struct sk_buff *);
int dn_sk_port_in_use(uint16_t);
uint16_t dn_sk_alloc_port(struct sock *);
int dn_sk_check_duplicate(struct sk_buff *);
struct sock *dn_sk_check_returned(struct sk_buff *);
struct sock *dn_alloc_sock(struct net *, struct socket *, gfp_t, int);
void dn_sk_destruct(struct sock *);
int dn_sk_destroy_timer(struct sock *);
void __init dn_sock_init(void);
void __exit dn_sock_exit(void);

#endif
