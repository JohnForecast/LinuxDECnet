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

#ifndef __DNET_NEXT_H__
#define __DNET_NEXT_H__

/*
 * Nexthop cache implementation
 *
 * The "nexthop" field contains the MAC address to be used when communicating
 * with DECnet address "addr". This value incombination with the "onEthernet"
 * flag may change as the systems learns more about the network topology.
 *
 * Possible values are:
 *
 * Phase IV operation:
 *
 *  1. - HIORD address of DECnet node "addr"
 *  2. - HIORD address of a router on the LAN, typically the designated router
 *
 * Phase IV prime operation:
 *
 *  1. - MAC address of DECnet node "addr"
 *  2. - MAC address of a router on the LAN, typically the designated router
 *  3. - "Unknown destination" multicast address
 */
typedef struct dn_next_entry {
        struct dn_next_entry    *next;
        refcount_t              refcount;
        uint64_t                creation;
        uint16_t                addr;
        uint16_t                blksize;
        uint8_t                 onEthernet;
        uint8_t                 deviceIndex;
        uint8_t                 nexthop[ETH_ALEN];
        unsigned long           timeout;
} dn_next_entry;
#define NEXT_CACHE_ENTRY_SIZE   sizeof(struct dn_next_entry)

struct dn_next_hash_bucket {
        struct dn_next_entry    *chain;
        spinlock_t              lock;
};
#define NEXT_BUCKET_SIZE        sizeof(struct dn_next_hash_bucket)

struct dn_next_seq_state {
        int                     bucket;
        int                     hdrDone;
};

extern int dn_next_init(void);
extern int dn_next_cleanup(void);

extern struct dn_next_hash_bucket *dn_next_cache;
extern int dn_next_hash_mask;

extern uint8_t loopMacAddr[ETH_ALEN];

extern int dn_next_in_cache(uint16_t, uint8_t *, uint8_t *);
extern int dn_next_update(uint16_t, uint8_t *, uint8_t);
extern struct dn_next_entry *dn_next_update_and_hold(uint16_t, uint8_t *, uint8_t);
extern void dn_next_tryhard(struct dn_next_entry *);
extern struct dn_next_entry *dn_next_clone(struct dn_next_entry *);
extern void dn_next_release(struct dn_next_entry *);
extern uint16_t dn_eth2segsize(struct dn_next_entry *);
extern void dn_segsize2eth(struct dn_next_entry *, uint16_t);

#endif
