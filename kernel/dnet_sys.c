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

#include <linux/mm.h>
#include <linux/sysctl.h>
#include <linux/fs.h>
#include <linux/netdevice.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include "dnet.h"

int decnet_debug_level = 0;
int decnet_log_malformed = 1;
int decnet_dlyack_seq = 3;
int decnet_segbufsize = 576;
int decnet_outgoing_timer = 60;
int decnet_NSPdelay = 80;
int decnet_NSPweight = 5;
int decnet_NSPretrans = 5;
int decnet_ACKdelay = 3;
int decnet_maxWindow = NSP_MAX_WINDOW / 2;

char node_name[7] = "???";

#ifdef CONFIG_SYSCTL
static int min_decnet_dlyack_seq[] = { NSP_MIN_WINDOW };
static int max_decnet_dlyack_seq[] = { NSP_MAX_WINDOW };
static int min_decnet_segbufsize[] = { 230 };
static int max_decnet_segbufsize[] = { ETH_DATA_LEN - sizeof(struct rt_long_hdr) };
static int min_decnet_timer[] = { 1 };
static int max_decnet_timer[] = { 65535 };
static int min_decnet_NSPdelay[] = { 0 };
static int max_decnet_NSPdelay[] = { 255 };
static int min_decnet_NSPweight[] = { 0 };
static int max_decnet_NSPweight[] = { 255 };
static int min_decnet_NSPretrans[] = { 2 };
static int max_decnet_NSPretrans[] = { 255 };
static int min_decnet_ACKdelay[] = { 1 };
static int max_decnet_ACKdelay[] = { 255 };
static int min_decnet_maxWindow[] = { 1 };
static int max_decnet_maxWindow[] = { NSP_MAX_WINDOW };

static struct ctl_table_header *dn_table_header = NULL;

/*
 * Utility routines.
 */
static void strip_it(
  char *str
)
{
        for (;;) {
                switch (*str) {
                        case ' ':
                        case '\n':
                        case '\r':
                        case ':':
                                *str = 0;
                                fallthrough;
                                
                        case 0:
                                return;
                }
                str++;
        }
}

/*
 * Simple routine to parse an ASCII DECnet address into a network order
 * address.
 */
static int parse_addr(
  uint16_t *addr,
  char *str
)
{
        uint16_t area, node;

        while (*str && !isdigit(*str)) str++;

        if (*str == 0)
                return -1;

        area = *str++ - '0';
        if (isdigit(*str)) {
                area *= 10;
                area += *str++ - '0';
        }

        if (*str++ != '.')
                return -1;

        if (!isdigit(*str))
                return -1;

        node = *str++ -'0';
        if (isdigit(*str)) {
                node *= 10;
                node += *str++ -'0';
        }
        if (isdigit(*str)) {
                node *= 10;
                node += *str++ - '0';
        }
        if (isdigit(*str)) {
                node *= 10;
                node += *str++ - '0';
        }

        if ((node == 0) || (node > 1023) || (area == 0) || (area > 63))
                return -1;

        if (isalnum(*str))
                return -1;

        *addr = cpu_to_le16((area << 10) | node);

        return 0;
}

static int dn_node_address_handler(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,11,0)
  const struct ctl_table *table,
#else
  struct ctl_table *table,
#endif
  int write,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
  void *buffer,
#else
  void __user *buffer,
#endif
  size_t *lenp,
  loff_t *ppos
)
{
        char addr[DN_ASCBUF_LEN];
        size_t len;
        uint16_t dnaddr;

        if (!*lenp || (*ppos && !write)) {
                *lenp = 0;
                return 0;
        }

        if (write) {
                len = (*lenp < DN_ASCBUF_LEN) ? *lenp : (DN_ASCBUF_LEN - 1);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
                memcpy(addr, buffer, len);
#else
                if (copy_from_user(addr, buffer, len))
                        return -EFAULT;
#endif
                addr[len] = 0;
                strip_it(addr);

                if (parse_addr(&dnaddr, addr))
                        return -EINVAL;

                /*** Turn devices off ***/
                decnet_address = dnaddr;
                /*** Turn devices on ***/

                *ppos += len;
                return 0;
        }

        /*
         * Must be a read of the node address
         */
        dn_addr2asc(le16_to_cpu(decnet_address), addr);
        len = strlen(addr);
        addr[len++] = '\n';

        if (len > *lenp)
                len = *lenp;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
        memcpy(buffer, addr, len);
#else
        if (copy_to_user(buffer, addr, len))
                return -EFAULT;
#endif
        *lenp = len;
        *ppos += len;
        return 0;
}

static struct ctl_table dn_table[] = {
        {
                .procname = "node_address",
                .maxlen = 7,
                .mode = 0644,
                .proc_handler = dn_node_address_handler,
        },
        {
                .procname = "node_name",
                .data = node_name,
                .maxlen = 7,
                .mode = 0644,
                .proc_handler = proc_dostring,
        },       
        {
                .procname = "dlyack_seq",
                .data = &decnet_dlyack_seq,
                .maxlen = sizeof(int),
                .mode = 0644,
                .proc_handler = proc_dointvec_minmax,
                .extra1 = &min_decnet_dlyack_seq,
                .extra2 = &max_decnet_dlyack_seq,
        },
        {
                .procname = "segbufsize",
                .data = &decnet_segbufsize,
                .maxlen = sizeof(int),
                .mode = 0644,
                .proc_handler = proc_dointvec_minmax,
                .extra1 = &min_decnet_segbufsize,
                .extra2 = &max_decnet_segbufsize,
        },
        {
                .procname = "outgoing_timer",
                .data = &decnet_outgoing_timer,
                .maxlen = sizeof(int),
                .mode = 0644,
                .proc_handler = proc_dointvec_minmax,
                .extra1 = &min_decnet_timer,
                .extra2 = &max_decnet_timer,
        },
        {
                .procname = "NSPdelay",
                .data = &decnet_NSPdelay,
                .maxlen = sizeof(int),
                .mode = 0666,
                .proc_handler = proc_dointvec_minmax,
                .extra1 = &min_decnet_NSPdelay,
                .extra2 = &max_decnet_NSPdelay,
        },
        {
                .procname = "NSPweight",
                .data = &decnet_NSPweight,
                .maxlen = sizeof(int),
                .mode = 0666,
                .proc_handler = proc_dointvec_minmax,
                .extra1 = &min_decnet_NSPweight,
                .extra2 = &max_decnet_NSPweight,
        },
        {
                .procname = "NSPretrans",
                .data = &decnet_NSPretrans,
                .maxlen = sizeof(int),
                .mode = 0666,
                .proc_handler = proc_dointvec_minmax,
                .extra1 = &min_decnet_NSPretrans,
                .extra2 = &max_decnet_NSPretrans,
        },
        {
                .procname = "ACKdelay",
                .data = &decnet_ACKdelay,
                .maxlen = sizeof(int),
                .mode = 0666,
                .proc_handler = proc_dointvec_minmax,
                .extra1 = &min_decnet_ACKdelay,
                .extra2 = &max_decnet_ACKdelay,
        },
        {
                .procname = "maxWindow",
                .data = &decnet_maxWindow,
                .maxlen = sizeof(int),
                .mode = 0666,
                .proc_handler = proc_dointvec_minmax,
                .extra1 = &min_decnet_maxWindow,
                .extra2 = &max_decnet_maxWindow,
        },
        { }
};

void dn_register_sysctl(void)
{
  dn_table_header = register_net_sysctl(&init_net, "net/decnet", dn_table);
}

void dn_unregister_sysctl(void)
{
  unregister_net_sysctl_table(dn_table_header);
}

#else
void dn_register_sysctl(void)
{
}

void dn_unregister_sysctl(void)
{
}

#endif
