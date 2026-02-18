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

struct dn_next_hash_bucket *dn_next_cache;
int dn_next_hash_mask;
static struct timer_list dn_next_timer;

#define CACHE_ORDER               4                     /* static for now */
#define CACHE_TIMEOUT           120UL

struct dn_next_entry *loop = NULL;
uint8_t loopMacAddr[ETH_ALEN];

/*
 * Create a dn_next_entry and link it into the hash table. Note the spinlock
 * on the bucket must be held across this call.
 */
static struct dn_next_entry *create_next_entry(
  uint16_t hash,
  uint16_t addr,
  uint8_t *ethaddr,
  uint8_t onEthernet
)
{
        struct dn_next_entry *nextp;
        uint8_t macaddr[ETH_ALEN];
        struct dn_next_hash_bucket *bucket = &dn_next_cache[hash];
        
        if ((nextp = kmalloc(NEXT_CACHE_ENTRY_SIZE, GFP_NOWAIT)) != NULL) {
                refcount_set(&nextp->refcount, 1);
                nextp->addr = addr;
                nextp->blksize = ETHDEVICE.blksize;
                nextp->onEthernet = onEthernet;
                nextp->deviceIndex = ETHINDEX;
                nextp->timeout = jiffies + (CACHE_TIMEOUT * HZ);

                if (ethaddr == NULL) {
                        /*
                         * If no ethernet address is supplied, use the
                         * Phase-dependent algorithm to construct an
                         * appropriate nexthop MAC address.
                         */
                        if (ETHDEVICE.router == NULL) {
                                nextp->onEthernet = 1;
                                if (!dn_IVprime) {
                                        dn_dn2eth(macaddr, addr);
                                        ethaddr = macaddr;
                                } else ethaddr = dn_unknown_dest;
                        } else {
                                nextp->blksize = ETHDEVICE.router->blksize;
                                nextp->onEthernet = 0;
                                ethaddr = ETHDEVICE.router->nexthop;
                        }
                }
                memcpy(nextp->nexthop, ethaddr, ETH_ALEN);

                nextp->next = bucket->chain;
                bucket->chain = nextp;
        }
        return nextp;
}

/*
 * Check if node address is present in the nexthop cache.
 */
int dn_next_in_cache(
  uint16_t addr,
  uint8_t *ethaddr,
  uint8_t *onEthernet
)
{
        int res = 0;
        uint16_t hash = addr & dn_next_hash_mask;
        struct dn_next_hash_bucket *bucket = &dn_next_cache[hash];
        dn_next_entry *nextp;

        spin_lock_bh(&bucket->lock);
        if ((nextp = bucket->chain) != NULL) {
                do {
                        if (nextp->addr == addr) {
                                if (ethaddr != NULL)
                                        memcpy(ethaddr, nextp->nexthop, ETH_ALEN);
                                if (onEthernet)
                                        *onEthernet = nextp->onEthernet;
                                res = 1;
                                break;
                        }
                } while ((nextp = nextp->next) != NULL);
        }
        spin_unlock_bh(&bucket->lock);

        return res;
}

/*
 * Update nexthop cache entry because we just received a message from
 * the node. If an entry does not exist, a new entry will be created. Note
 * that if the MAC address changes, we will always update the entry to the
 * latest value.
 */
int dn_next_update(
  uint16_t addr,
  uint8_t *ethaddr,
  uint8_t onEthernet
)
{
        int res = 1;
        uint16_t hash = addr & dn_next_hash_mask;
        struct dn_next_hash_bucket *bucket = &dn_next_cache[hash];
        dn_next_entry *nextp;

        spin_lock_bh(&bucket->lock);
        if ((nextp = bucket->chain) != NULL) {
                do {
                        if (nextp->addr == addr) {
                                nextp->timeout = jiffies + (CACHE_TIMEOUT * HZ);
                                memcpy(nextp->nexthop, ethaddr, ETH_ALEN);
                                nextp->onEthernet = onEthernet;
                                break;
                        }
                } while ((nextp = nextp->next) != NULL);
        }

        if (nextp == NULL) {
                if ((nextp = create_next_entry(hash, addr, ethaddr, onEthernet)) == NULL)
                        res = 0;
        }

        if ((nextp != ETHDEVICE.router) && onEthernet)
                nextp->blksize = ETHDEVICE.blksize;
        
        spin_unlock_bh(&bucket->lock);

        return res;
}

/*
 * Update nexthop cache entry and take out a reference on the entry. If an
 * entry does not exist, a new entry will be created.
 */
dn_next_entry *dn_next_update_and_hold(
  uint16_t addr,
  uint8_t *ethaddr,
  uint8_t onEthernet
)
{
        uint16_t hash = addr & dn_next_hash_mask;
        struct dn_next_hash_bucket *bucket = &dn_next_cache[hash];
        dn_next_entry *nextp;

        spin_lock_bh(&bucket->lock);
        if ((nextp = bucket->chain) != NULL) {
                do {
                        if (nextp->addr == addr) {
                                nextp->timeout = jiffies + (CACHE_TIMEOUT * HZ);
                                if (ethaddr != NULL)
                                        memcpy(nextp->nexthop, ethaddr, ETH_ALEN);
                                break;
                        }
                } while ((nextp = nextp->next) != NULL);
        }

        if (nextp == NULL)
                nextp = create_next_entry(hash, addr, ethaddr, onEthernet);

        if (nextp != NULL) {
                nextp->onEthernet = onEthernet;
                if ((nextp != ETHDEVICE.router) && onEthernet)
                        nextp->blksize = ETHDEVICE.blksize;
                refcount_inc(&nextp->refcount);
        }
        
        spin_unlock_bh(&bucket->lock);

        return nextp;
}

/*
 * Switch the MAC address in a dn_next_entry structure as a result of a
 * TRYHARD request.
 */
void dn_next_tryhard(
  struct dn_next_entry *nextp
)
{
	uint8_t macaddr[ETH_ALEN];
	uint8_t *ethaddr = macaddr;

	if (ETHDEVICE.router != NULL) {
		nextp->onEthernet = 0;
		ethaddr = ETHDEVICE.router->nexthop;
	} else {
		nextp->onEthernet = 1;
        	if (!dn_IVprime)
                	dn_dn2eth(macaddr, nextp->addr);
		else ethaddr = dn_unknown_dest;
	}
	memcpy(nextp->nexthop, ethaddr, ETH_ALEN);
}

/*
 * Take an extra reference on a nexthop cache entry.
 */
dn_next_entry *dn_next_clone(
  dn_next_entry *nextp
)
{
        refcount_inc(&nextp->refcount);
        return nextp;
}

/*
 * Release a reference on a nexthop cache entry.
 */
void dn_next_release(
  dn_next_entry *nextp
)
{
        refcount_dec(&nextp->refcount);
}

/*
 * Scan the nexthop cache and remove entries which have expired. The
 * "forced" argument may be set to force all entries to be removed (e.g. when
 * unloading the module).
 */
static void dn_next_scan(
  int forced
)
{
        int i;
        dn_next_entry **ppe;

        for (i = 0; i <= dn_next_hash_mask; i++) {
                struct dn_next_hash_bucket *bucket = &dn_next_cache[i];

                if (!forced) {
                        if (spin_trylock(&bucket->lock) == 0)
                                continue;
                } else spin_lock(&bucket->lock);
                ppe = &bucket->chain;

                while (*ppe != NULL) {
                        dn_next_entry *nextp = *ppe;

                        if ((refcount_read(&nextp->refcount) == 1) &&
                            (forced || time_after(jiffies, nextp->timeout))) {
                                *ppe = nextp->next;
                                kfree(nextp);
                        } else ppe = &nextp->next;
                }
                spin_unlock(&bucket->lock);
        }
}

/*
 * Scan the nexthop cache and remove entries which have expired.
 */
static void dn_next_timeout(
  struct timer_list *unused
)
{
        dn_next_scan(0);
        mod_timer(&dn_next_timer, jiffies + HZ);
}

/*
 * Compute the data segment size associated with a dn_next_entry
 */
uint16_t dn_eth2segsize(
  struct dn_next_entry *nextp
)
{
        uint16_t segsize = nextp->blksize;

        segsize -= sizeof(struct rt_long_hdr);
        segsize -= NSP_MAX_DATAHDR;

        return segsize;
}

/*
 * Update a dn_next_entry blksize given a data segment size.
 */
void dn_segsize2eth(
  struct dn_next_entry *nextp,
  uint16_t segsize
)
{
        segsize += sizeof(struct rt_long_hdr) + 1;
        segsize += NSP_MAX_DATAHDR;

        nextp->blksize = segsize;
}

#ifdef CONFIG_PROC_FS

static void dn_next_format_entry(
  struct seq_file *seq,
  struct dn_next_entry *nextp
)
{
        char buf[DN_ASCBUF_LEN], eth[18];
        uint8_t iinfo = 0;

        if (nextp == ETHDEVICE.router)
                iinfo = ETHDEVICE.iinfo & RT_II_RTR_MASK;
        
        seq_printf(seq, "%-7s %s%s%s   %02x    %02d  %07d %-8s %s\n",
                   dn_addr2asc(nextp->addr, buf),
                   ((iinfo & RT_II_LEVEL_1) != 0) ? "1" : "-",
                   ((iinfo & RT_II_LEVEL_2) != 0) ? "2" : "-",
                   "-",
                   0,
                   refcount_read(&nextp->refcount),
                   nextp->blksize,
                   dn_devices[nextp->deviceIndex].dev->name,
                   dn_eth2asc(nextp->nexthop, eth));
}

static struct dn_next_entry *dn_next_get_first(
  struct seq_file *seq
)
{
        struct dn_next_entry *nextp = NULL;
        struct dn_next_seq_state *s = seq->private;

        for (s->bucket = dn_next_hash_mask; s->bucket >= 0; --s->bucket) {
                if (dn_next_cache[s->bucket].chain) {
                        spin_lock_bh(&dn_next_cache[s->bucket].lock);
                        nextp = dn_next_cache[s->bucket].chain;
                        if (nextp)
                                break;
                        spin_unlock_bh(&dn_next_cache[s->bucket].lock);
                }
        }
        return nextp;
}

static struct dn_next_entry *dn_next_get_next(
  struct seq_file *seq,
  struct dn_next_entry *nextp
)
{
        struct dn_next_seq_state *s = seq->private;

        nextp = nextp->next;
        while (!nextp) {
                spin_unlock_bh(&dn_next_cache[s->bucket].lock);
                if (--s->bucket < 0)
                        break;
                spin_lock_bh(&dn_next_cache[s->bucket].lock);
                nextp = dn_next_cache[s->bucket].chain;
        }
        return nextp;
}

static void *dn_next_seq_start(
  struct seq_file *seq,
  loff_t *pos
)
{
        struct dn_next_entry *nextp = dn_next_get_first(seq);
        struct dn_next_seq_state *s = seq->private;

        s->hdrDone = 0;
        
        if (nextp) {
                while (*pos && (nextp = dn_next_get_next(seq, nextp)))
                        --*pos;
        }
        return *pos ? NULL : nextp;
}

static void *dn_next_seq_next(
  struct seq_file *seq,
  void *v,
  loff_t *pos
)
{
        struct dn_next_entry *nextp = dn_next_get_next(seq, v);

        ++*pos;
        return nextp;
}

static void dn_next_seq_stop(
  struct seq_file *seq,
  void *v
)
{
        struct dn_next_seq_state *s = seq->private;

        if (v)
                spin_unlock_bh(&dn_next_cache[s->bucket].lock);
}

static int dn_next_seq_show(
  struct seq_file *seq,
  void *v
)
{
        struct dn_next_seq_state *s = seq->private;
        int skipRtn = SEQ_SKIP;
        
        if (s->hdrDone == 0) {
                seq_puts(seq, "Addr    Flags State Use Blksize Dev\n");
                s->hdrDone++;

                /*
                 * Make sure the loopback and designated router entries
                 * are the first 2 printed
                 */
                dn_next_format_entry(seq, loop);
                if (ETHDEVICE.router != NULL)
                        dn_next_format_entry(seq, ETHDEVICE.router);
                skipRtn = 0;
        }

        if ((v == loop) || (v == ETHDEVICE.router))
                return skipRtn;
        
        dn_next_format_entry(seq, v);
        return 0;
}

static const struct seq_operations dn_next_seq_ops = {
        .start = dn_next_seq_start,
        .next = dn_next_seq_next,
        .stop = dn_next_seq_stop,
        .show = dn_next_seq_show,
};

static int dn_next_cache_seq_show(
  struct seq_file *seq,
  void *v
)
{
        struct dn_next_entry *nextp = v;
        char buf1[DN_ASCBUF_LEN], buf2[DN_ASCBUF_LEN], buf3[DN_ASCBUF_LEN];

        seq_printf(seq, "%-8s %-7s %-7s %-7s %04d %04d %04d\n",
                   dn_devices[nextp->deviceIndex].dev->name,
                   dn_addr2asc(nextp->addr, buf1),
                   dn_addr2asc(decnet_address, buf2),
                   dn_addr2asc(dn_eth2dn(nextp->nexthop), buf3),
                   atomic_read(&nextp->refcount.refs),
                   0, 0);
        return 0;
}

static const struct seq_operations dn_next_cache_seq_ops = {
        .start = dn_next_seq_start,
        .next = dn_next_seq_next,
        .stop = dn_next_seq_stop,
        .show = dn_next_cache_seq_show,
};

#endif

int __init dn_next_init(void)
{
        int i, order = CACHE_ORDER;
        
        /*
         * Try to allocate as large nexthop cache as possible, we can
         * always run with a smaller one.
         */
        do {
                dn_next_hash_mask =
                        ((1UL << order) * PAGE_SIZE) / NEXT_BUCKET_SIZE;
                while (dn_next_hash_mask & (dn_next_hash_mask - 1))
                        dn_next_hash_mask--;
                dn_next_cache =
                        (struct dn_next_hash_bucket *)__get_free_pages(GFP_KERNEL, order);
        } while ((dn_next_cache == NULL) && (--order > 0));

        if (!dn_next_cache)
                panic("Failed to allocate DECnet nexthop cache\n");

        pr_info("DECnet: Nexthop cache hash table of %u buckets, %ld Kbytes\n",
                dn_next_hash_mask,
                (long)((dn_next_hash_mask * NEXT_BUCKET_SIZE) / 1024));

        dn_next_hash_mask--;
        for (i = 0; i <= dn_next_hash_mask; i++) {
                spin_lock_init(&dn_next_cache[i].lock);
                dn_next_cache[i].chain = NULL;
        }

        timer_setup(&dn_next_timer, dn_next_timeout, 0);
        dn_next_timer.expires = jiffies + HZ;
        add_timer(&dn_next_timer);

        /*
         * Create a nexthop entry for the local DECnet address. Note
         * that MAC address should never leak out to other interfaces so
         * we can use a Phase IV style address, even for Phase IV Prime
         * hosts. This entry is the one and only entry for the loopback device.
         */
        dn_dn2eth(loopMacAddr, decnet_address);
        loop = create_next_entry(decnet_address & dn_next_hash_mask,
                                 decnet_address, loopMacAddr, 1);
        if (loop == NULL) {
          pr_info("Unable to allocate nexthop entry to self (lo)\n");
          return -ENOMEM;
        }

        /*
         * Take an extra reference count on this entry to lock it in the
         * cache.
         */
        refcount_inc(&loop->refcount);
        
        loop->deviceIndex = LOOPINDEX;
        loop->blksize = LOOPDEVICE.blksize;
        
#ifdef CONFIG_PROC_FS
#ifdef DNET_COMPAT
        proc_create_seq_private("decnet_neigh", 0444, init_net.proc_net,
                                &dn_next_seq_ops,
                                sizeof(struct dn_next_seq_state), NULL);
        proc_create_seq_private("decnet_cache", 0444, init_net.proc_net,
                                &dn_next_cache_seq_ops,
                                sizeof(struct dn_next_seq_state), NULL);
#endif
#endif
        return 0;
}

void __exit dn_next_cleanup(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,15,0)
        timer_delete(&dn_next_timer);
#else
        del_timer(&dn_next_timer);
#endif
        refcount_dec(&loop->refcount);
        dn_next_scan(1);

#ifdef CONFIG_PROC_FS
#ifdef DNET_COMPAT
        remove_proc_entry("decnet_neigh", init_net.proc_net);
        remove_proc_entry("decnet_cache", init_net.proc_net);
#endif
#endif
}
