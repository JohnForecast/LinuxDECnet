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
#include <linux/timekeeping.h>
#include "dnet.h"

struct dn_node_hash_bucket *dn_node_db;
int dn_node_hash_mask;
static struct timer_list dn_node_timer;

#define CACHE_ORDER             4
#define CACHE_TIMEOUT           (15UL * 60UL)

/*
 * Lookup a node entry. If an entry does not exist, a new entry will be
 * created.
 */
struct dn_node_entry *dn_node_lookup(
  uint16_t addr
)
{
        uint16_t hash = addr & dn_node_hash_mask;
        struct dn_node_hash_bucket *bucket = &dn_node_db[hash];
        dn_node_entry *entry;

        spin_lock(&bucket->lock);
        if ((entry = bucket->chain) != NULL) {
                do {
                        if (entry->addr == addr) {
                                /*
                                 * Ignore this entry if it has timed out
                                 */
                                if (time_after(jiffies, entry->timeout))
                                        break;
                        }
                } while ((entry = entry->next) != NULL);
        }

        if (entry == NULL) {
                if ((entry = kzalloc(NODE_CACHE_ENTRY_SIZE, GFP_ATOMIC)) != NULL) {
                        refcount_set(&entry->refcount, 1);
                        entry->hash = hash;
                        entry->addr = addr;
                        entry->delay = 0;
                        
                        memset(&entry->counters, 0, sizeof(struct dn_node_counters));
                        entry->counters.timezeroed = ktime_get_real_seconds();

                        entry->next = bucket->chain;
                        bucket->chain = entry;
                }
        }

        if (entry != NULL)
                refcount_inc(&entry->refcount);
        spin_unlock(&bucket->lock);

        return entry;
}

/*
 * Release reference on a node entry. If timedout is non-zero, the logical
 * link was terminated due to a communications failure and we should cancel
 * this node entry by timing it out.
 */
void dn_node_release(
  dn_node_entry *entry,
  int timedout
)
{
        spin_lock(&dn_node_db[entry->hash].lock);
        entry->timeout = jiffies + (CACHE_TIMEOUT * HZ);
        refcount_dec(&entry->refcount);
        if (timedout && (refcount_read(&entry->refcount) == 1))
                entry->timeout = jiffies - 1;
        spin_unlock(&dn_node_db[entry->hash].lock);
}

/*
 * Update the delay value stored in the node entry
 */
void dn_node_update_delay(
  struct dn_node_entry *nodep,
  uint32_t delta
)
{
        if (nodep->delay == 0)
                nodep->delay = delta;
        else nodep->delay += ((int32_t)(delta - nodep->delay)) / (decnet_NSPweight + 1);
}

/*
 * Scan the node cache and remove entries which have expired. The "forced"
 * argument may be set to force all entries to be removed (e.g. when unloading
 * the module).
 */
static void dn_node_scan(
  int forced
)
{
        int i;
        dn_node_entry **ppe;

        for (i = 0; i <= dn_node_hash_mask; i++) {
                struct dn_node_hash_bucket *bucket = &dn_node_db[i];

                spin_lock(&bucket->lock);
                ppe = &bucket->chain;

                while (*ppe != NULL) {
                        dn_node_entry *nodep = *ppe;

                        if (refcount_read(&nodep->refcount) == 1) {
                                if (forced || time_after(jiffies, nodep->timeout)) {
                                        *ppe = nodep->next;
                                        if (!forced)
                                                /*** Log event ***/;
                                        kfree(nodep);
                                } else ppe = &nodep->next;
                        }
                }
                spin_unlock(&bucket->lock);
        }
}

/*
 * Scan the node cache and remove entries which have expired.
 */
void dn_node_timeout(
  struct timer_list *unused
)
{
        dn_node_scan(0);
        mod_timer(&dn_node_timer, jiffies + (60 * HZ));
}

#ifdef CONFIG_PROC_FS
static struct dn_node_entry *dn_node_get_first(
  struct seq_file *seq
)
{
        struct dn_node_entry *nodep = NULL;
        struct dn_node_seq_state *s = seq->private;

        for (s->bucket = dn_node_hash_mask; s->bucket >= 0; --s->bucket) {
                if (dn_node_db[s->bucket].chain) {
                        spin_lock_bh(&dn_node_db[s->bucket].lock);
                        nodep = dn_node_db[s->bucket].chain;
                        if (nodep)
                                break;
                        spin_unlock_bh(&dn_node_db[s->bucket].lock);
                }
        }
        return nodep;
}

static struct dn_node_entry *dn_node_get_next(
  struct seq_file *seq,
  struct dn_node_entry *nodep
)
{
        struct dn_node_seq_state *s = seq->private;

        nodep = nodep->next;
        while (!nodep) {
                spin_unlock_bh(&dn_node_db[s->bucket].lock);
                if (--s->bucket < 0)
                        break;
                spin_lock_bh(&dn_node_db[s->bucket].lock);
                nodep = dn_node_db[s->bucket].chain;
        }
        return nodep;
}

static void *dn_node_seq_start(
  struct seq_file *seq,
  loff_t *pos
)
{
        struct dn_node_entry *nodep = dn_node_get_first(seq);

        if (nodep) {
                while (*pos && (nodep = dn_node_get_next(seq, nodep)))
                        --*pos;
        }
        return *pos ? NULL : nodep;
}

static void *dn_node_seq_next(
  struct seq_file *seq,
  void *v,
  loff_t *pos
)
{
        struct dn_node_entry *nodep = dn_node_get_next(seq, v);

        ++*pos;
        return nodep;
}

static void dn_node_seq_stop(
  struct seq_file *seq,
  void *v
)
{
        struct dn_node_seq_state *s = seq->private;

        if (v)
                spin_unlock_bh(&dn_node_db[s->bucket].lock);
}

static int dn_node_seq_show(
  struct seq_file *seq,
  void *v
)
{
        struct dn_node_entry *nodep = v;
        struct dn_node_counters *ctrp = &nodep->counters;
        char buf1[DN_ASCBUF_LEN];
        uint32_t delay;
	time64_t delta = ktime_get_real_seconds() - ctrp->timezeroed;

        delay = (nodep->delay + HZ - 1) / HZ;
#define VALOF(v, limit) (v) < limit ? v : limit
        seq_printf(seq, "%-7s %-3u %-11llu "
                   "0x%08llx 0x%08llx 0x%08llx 0x%08llx "
                   "0x%08llx 0x%08llx 0x%08llx 0x%08llx "
                   "0x%04x 0x%04x 0x%04x\n",
                   dn_addr2asc(nodep->addr, buf1),
                   delay > 255 ? 255 : delay,
		   delta > 0xFFFE ? 0xFFFF : delta,
                   VALOF(ctrp->user_bytes_rcv, 0xFFFFFFFF),
                   VALOF(ctrp->user_bytes_xmt, 0xFFFFFFFF),
		   VALOF(ctrp->user_msg_rcv, 0xFFFFFFFF),
		   VALOF(ctrp->user_msg_xmt, 0xFFFFFFFF),
		   VALOF(ctrp->total_bytes_rcv, 0xFFFFFFFF),
		   VALOF(ctrp->total_bytes_xmt, 0xFFFFFFFF),
                   VALOF(ctrp->total_msg_rcv, 0xFFFFFFFF),
                   VALOF(ctrp->total_msg_xmt, 0xFFFFFFFF),
                   VALOF(ctrp->connects_rcv, 0xFFFF),
                   VALOF(ctrp->connects_xmt, 0xFFFF),
                   VALOF(ctrp->timeouts, 0xFFFF));
        return 0;
}

static const struct seq_operations dn_node_seq_ops = {
        .start = dn_node_seq_start,
        .next = dn_node_seq_next,
        .stop = dn_node_seq_stop,
        .show = dn_node_seq_show,
};

/*
 * Zero the node counters for a single node entry or all entries.
 */
void dn_node_zero_counters(
  uint16_t addr
)
{
        struct dn_node_entry *nodep;
        int i;

        for (i = 0; i <= dn_node_hash_mask; i++) {
                if (dn_node_db[i].chain != NULL) {
                        spin_lock_bh(&dn_node_db[i].lock);
                        nodep = dn_node_db[i].chain;

                        while (nodep != NULL) {
                                if ((addr == 0) || (nodep->addr == addr)) {
                                        memset(&nodep->counters, 0, sizeof(struct dn_node_counters));
                                        nodep->counters.timezeroed = ktime_get_real_seconds();
                                }
                                nodep = nodep->next;
                        }
                        spin_unlock_bh(&dn_node_db[i].lock);
                }
        }
}

#endif

int __init dn_node_init(void)
{
        int i, order = CACHE_ORDER;

        /*
         * Try to allocate as large node cache as possible, we can always
         * run with a smaller one.
         */
        do {
                dn_node_hash_mask =
                        ((1UL << order) * PAGE_SIZE) / NODE_BUCKET_SIZE;
                while (dn_node_hash_mask & (dn_node_hash_mask - 1))
                        dn_node_hash_mask--;
                dn_node_db =
                        (struct dn_node_hash_bucket *)__get_free_pages(GFP_ATOMIC, order);
        } while ((dn_node_db == NULL) && (--order > 0));

        if (!dn_node_db)
                panic("Failed to allocate DECnet node database\n");

        pr_info("DECnet: Node database hash table of %u buckets, %ld Kbytes\n",
                dn_node_hash_mask,
                (long)((dn_node_hash_mask * NODE_BUCKET_SIZE) / 1024));

        dn_node_hash_mask--;
        for (i = 0; i <= dn_node_hash_mask; i++) {
                spin_lock_init(&dn_node_db[i].lock);
                dn_node_db[i].chain = NULL;
        }

	timer_setup(&dn_node_timer, dn_node_timeout, 0);
	dn_node_timer.expires = jiffies + (HZ / 2);
	add_timer(&dn_node_timer);

#ifdef CONFIG_PROC_FS
        proc_create_seq_private("decnet_nodes", 0444, init_net.proc_net,
                                &dn_node_seq_ops,
                                sizeof(struct dn_node_seq_state), NULL);
#endif

        return 0;
}

void __exit dn_node_cleanup(void)
{
	del_timer(&dn_node_timer);

        /*** Flush node db entries ***/
#ifdef CONFIG_PROC_FS
        remove_proc_entry("decnet_nodes", init_net.proc_net);
#endif
}
