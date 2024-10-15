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

#ifndef __DNET_NODE_H__
#define __DNET_NODE_H__

/*
 * Node database implementation. Note that the counters are twice as wide
 * as in the network management specification. NML is expected to truncate the
 * value appropriately. This allows for simple addition/increments.
 */
typedef struct dn_node_entry {
        struct dn_node_entry    *next;
        refcount_t              refcount;
        uint16_t                hash;
        uint16_t                addr;
        unsigned long           timeout;
        uint32_t                delay;
        struct dn_node_counters {
                time64_t        timezeroed;
                uint64_t        user_bytes_rcv;
                uint64_t        user_bytes_xmt;
		uint64_t	user_msg_rcv;
		uint64_t	user_msg_xmt;
		uint64_t	total_bytes_rcv;
		uint64_t	total_bytes_xmt;
                uint64_t        total_msg_rcv;
                uint64_t        total_msg_xmt;
                uint32_t        connects_rcv;
                uint32_t        connects_xmt;
                uint32_t        timeouts;
        }                       counters;
} dn_node_entry;
#define NODE_CACHE_ENTRY_SIZE   sizeof(struct dn_node_entry)

struct dn_node_hash_bucket {
        struct dn_node_entry    *chain;
        spinlock_t              lock;
};
#define NODE_BUCKET_SIZE        sizeof(struct dn_node_hash_bucket)

struct dn_node_seq_state {
        int                     bucket;
};

extern struct dn_node_hash_bucket *dn_node_db;
extern int dn_node_hash_mask;

/*
 * Counter update routines
 */
static inline void Inc64(
  uint64_t *ctr
)
{
        if (*ctr < 0xFFFFFFFF)
                *ctr += 1;
        else *ctr = 0xFFFFFFFF;
}

static inline void Inc32(
  uint32_t *ctr
)
{
        if (*ctr < 0xFFFF)
                *ctr += 1;
        else *ctr = 0xFFFF;
}
static inline void Add64(
  uint64_t *ctr,
  uint32_t val
)
{
        if (*ctr < 0xFFFFFFFF)
                *ctr += val;
        else *ctr = 0xFFFFFFFF;
}

static inline void Count_user_rcvd(
  struct dn_node_entry *nodep,
  uint32_t len
)
{
        Add64(&nodep->counters.user_bytes_rcv, len);
	Inc64(&nodep->counters.user_msg_rcv);
}

static inline void Count_user_sent(
  struct dn_node_entry *nodep,
  uint32_t len
)
{
        Add64(&nodep->counters.user_bytes_xmt, len);
	Inc64(&nodep->counters.user_msg_xmt);
}

static inline void Count_total_rcvd(
  struct dn_node_entry *nodep,
  uint32_t len
)
{
	Add64(&nodep->counters.total_bytes_rcv, len);
        Inc64(&nodep->counters.total_msg_rcv);
}

static inline void Count_total_sent(
  struct dn_node_entry *nodep,
  uint32_t len
)
{
	Add64(&nodep->counters.total_bytes_xmt, len);
        Inc64(&nodep->counters.total_msg_xmt);
}

static inline void Count_connect_rcvd(
  struct dn_node_entry *nodep
)
{
        Inc32(&nodep->counters.connects_rcv);
}

static inline void Count_connect_sent(
  struct dn_node_entry *nodep
)
{
        Inc32(&nodep->counters.connects_xmt);
}

static inline void Count_timeouts(
  struct dn_node_entry *nodep
)
{
        Inc32(&nodep->counters.timeouts);
}

extern int dn_node_init(void);

struct dn_node_entry *dn_node_lookup(uint16_t);
void dn_node_release(dn_node_entry *, int);
void dn_node_update_delay(struct dn_node_entry *, uint32_t);
#ifdef CONFIG_PROC_FS
void dn_node_zero_counters(uint16_t);
#endif

#endif
