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

#ifndef __DNET_NSP_H__
#define __DNET_NSP_H__

int dn_nsp_rcv(struct sk_buff *);
int dn_nsp_rcv_backlog(struct sock *, struct sk_buff *);

unsigned long dn_nsp_persist(struct dn_scp *);
void dn_nsp_xmt(struct sk_buff *);
void dn_nsp_xmt_socket(struct sock *);
void dn_nsp_queue_xmt(struct sock *, struct sk_buff *, gfp_t, int);

void dn_nsp_xmt_ack_ci(struct sock *);
void dn_nsp_xmt_ack_data(struct sock *);
void dn_nsp_xmt_ack_oth(struct sock *);
void dn_nsp_xmt_cc(struct sock *, gfp_t);
int dn_nsp_rexmt_cc(struct sock *);
void dn_nsp_xmt_ci(struct sock *, uint8_t, uint8_t);
int dn_nsp_rexmt_ci(struct sock *);
int dn_nsp_xmt_timeout(struct sock *);
void dn_nsp_xmt_disc(struct sock *, uint8_t, uint16_t, gfp_t);
void dn_nsp_return_disc(struct sk_buff *, uint8_t, uint16_t);
int dn_nsp_xmt_ls(struct sock *, uint8_t, uint8_t);
void dn_nsp_sched_pending(struct sock *, int);

#endif
