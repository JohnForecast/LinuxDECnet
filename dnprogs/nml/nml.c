/******************************************************************************
    (C) John Forecast                           john@forecast.name

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
******************************************************************************/

/*** Note: This code assumes a DECnet endnode implementation ***/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>
#include <fcntl.h>
#include "nice.h"

extern int verbosity;

#define IDENT_STRING            "Linux DECnet"

#define PROC_DECNET_DEV         "/proc/net/decnet_dev"
#define PROC_DECNET_CACHE       "/proc/net/decnet_cache"
#define PROC_DECNET_COST	"/proc/net/decnet_cost"
#define PROC_DECNET_NODES	"/proc/net/decnet_nodes"
#define PROC_DECNET_PHASE	"/proc/net/decnet_phase"
#define PROC_REVISION		"/proc/net/decnet_revision"
#define PROC_DECNET             "/proc/net/decnet"
#define PROC_ZERO_NODE		"/proc/net/decnet_zero_node"
#define PROC_SEGBUFSIZE         "/proc/sys/net/decnet/segbufsize"
#define PROC_INCOMINGTIMER	"/proc/sys/net/decnet/incoming_timer"
#define PROC_OUTGOINGTIMER	"/proc/sys/net/decnet/outgoing_timer"

static uint8_t revision[3];
static uint16_t localaddr, router = 0;
static uint8_t localarea;
static char routername[NICE_MAXNODEL + 1] = "";
static char circuit[NICE_MAXCIRCUITL + 1] = "";
static uint16_t hellotmr, listentmr;

#define MAX_ACTIVE_NODES        1024

static struct links {
  uint16_t      addr;
  uint16_t      count;
} links[MAX_ACTIVE_NODES];
static uint16_t num_nodes = 0, num_links = 0;

#define MAX_NODES               65536
uint16_t knownaddr[MAX_NODES + 1];
uint16_t nodecount;

#define MAX_NODEADDRESS         65536
uint16_t nexthop[MAX_NODEADDRESS];

static struct nodectrs {
  uint8_t	valid;
  uint8_t	delay;
  uint16_t	sincezeroed;
  uint32_t	usrbytesrcvd;
  uint32_t	usrbytessent;
  uint32_t	usrmsgrcvd;
  uint32_t	usrmsgsent;
  uint32_t	totalbytesrcvd;
  uint32_t	totalbytessent;
  uint32_t	totalmsgrcvd;
  uint32_t	totalmsgsent;
  uint16_t	connectsrcvd;
  uint16_t	connectssent;
  uint16_t	timeouts;
} nodectrs[MAX_NODEADDRESS];

/*
 * Read a single integer value from a file (typically /proc/sys/...).
 */
static int get_value(
  char *name,
  int *result
)
{
  FILE *file = fopen(name, "r");
  char buf[128];
  
  if (file) {
    if (fgets(buf, sizeof(buf), file)) {
      if (sscanf(buf, "%d", result) == 1) {
        fclose(file);
        return 1;
      }
    }
    fclose(file);
  }
  return 0;
}

/*
 * Get the DECnet phase information. If the file does not exist assume
 * Phase IV non-router.
 */
static uint8_t get_phase(void)
{
  FILE *file = fopen(PROC_DECNET_PHASE, "r");
  uint8_t type = NICE_P_N_RTYPE_NRTR_IV;
  char buf[128];

  if (file) {
    if (fgets(buf, sizeof(buf), file)) {
      if (strcmp(buf, "IV Prime") == 0)
	type = NICE_P_N_RTYPE_NRTR_IVP;
    }
    fclose(file);
  }
  return type;
}

/*
 * Get the revision of the kernel module. If the file does not exist, we
 * assume a revision number of 1.0.0
 */
static int get_revision(void)
{
  FILE *file = fopen(PROC_REVISION, "r");
  char buf[64];

  if (file) {
    if (fgets(buf, sizeof(buf), file)) {
      if (sscanf(buf, "%hhu.%hhu.%hhu\n",
                 &revision[0], &revision[1], &revision[2]) == 3) {
        fclose(file);
        return 1;
      }
    }
    fclose(file);
  } else {
    revision[0] = 1;
    revision[1] = 0;
    revision[2] = 0;
  }
  return 0;
}

/*
 * Get the current designated router's address and the circuit being used.
 */
static void get_router(void)
{
  char buf[256];
  char var1[32], var2[32], var3[32], var4[32], var5[32], var6[32], var7[32];
  char var8[32], var9[32], var10[32], var11[32], var12[32], var13[32];
  FILE *procfile = fopen(PROC_DECNET_DEV, "r");

  if (procfile) {
    while (!feof(procfile)) {
      if (!fgets(buf, sizeof(buf), procfile))
        break;

      if (strstr(buf, "ethernet") != NULL) {
        if (sscanf(buf, "%s %s %s %s %s %s %s %s %s %s %s",
                 var1, var2, var3, var4, var5, var6, var7,
                 var8, var9, var10, var11) == 11) {
          int t;

          strncpy(circuit, var1, sizeof(circuit));

          sscanf(var6, "%d", &t);
          hellotmr = t;

          sscanf(var8, "%d", &t);
          listentmr = t;

          if (sscanf(buf, "%s %s %s %s %s %s %s %s %s %s %s ethernet %s",
                     var1, var2, var3, var4, var5, var6, var7, var8,
                     var9, var10, var11, var13) == 12) {
            int area, node;
            struct nodeent *dp;

            sscanf(var13, "%d.%d", &area, &node);
            router = (area << 10) | node;

            if ((dp = getnodebyaddr((char *)&router, sizeof(router), PF_DECnet)) != NULL)
              strncpy(routername, dp->n_name, sizeof(routername));

          }
	  if (verbosity > 0)
            dnetlog(LOG_DEBUG, "Router is %u.%u (%s) on %s\n",
                    (router >> 10) & 0x3F, router & 0x3FF, routername, circuit);
        }
        break;
      }
    }
    fclose(procfile);
  }
}

/*
 * Scan the active links to find the number of links to each remote node.
 */
static void scan_links(void)
{
  char buf[256];
  char var1[32], var2[32], var3[32], var4[32], var5[32], var6[32];
  char var7[32], var8[32], var9[32], var10[32], var11[32];
  int i;
  FILE *procfile = fopen(PROC_DECNET, "r");

  if (procfile) {
    while (!feof(procfile)) {
      if (!fgets(buf, sizeof(buf), procfile))
        break;

      if (sscanf(buf, "%s %s %s %s %s %s %s %s %s %s %s\n",
                 var1, var2, var3, var4, var5, var6, var7, var8,
                 var9, var10, var11) == 11) {
        int area, node;
        uint16_t addr;
        struct links *lnode = NULL;

        sscanf(var6, "%d.%d", &area, &node);

        /*
         * Ignore 0.0 links (listeners) and anything not in the RUN state
         */
        if ((area == 0) || (node == 0) || strcmp(var11, "RUN"))
          continue;

        addr = (area << 10) | node;

        /*
         * Check if we've already seen this node.
         */
        for (i = 0; i < num_nodes; i++) {
          if (links[i].addr == addr) {
            lnode = &links[i];
            break;
          }
        }

        if (!lnode && (i < MAX_ACTIVE_NODES)) {
          lnode = &links[num_nodes++];
          lnode->addr = addr;
          lnode->count = 0;
        }

        if (lnode)
          lnode->count++;
        num_links++;
      }
    }
    fclose(procfile);
  }
}

/*
 * Determine how many active links there are to a specific node
 */
uint16_t get_count(
  uint16_t addr
)
{
  int i;

  for (i = 0; i < num_nodes; i++)
    if (links[i].addr == addr)
      return links[i].count;

  return 0;
}

/*
 * Check if there are active connections to a specific node
 */
uint8_t active_connections(
  uint16_t addr
)
{
  int i;

  for (i = 0; i < num_nodes; i++)
    if (links[i].addr == addr)
      return TRUE;

  return FALSE;
}

/*
 * Add a specified node address to the node address table if it is not
 * already present.
 */
static void add_to_node_table(
  uint16_t addr
)
{
  int i;

  for (i = 0; i < nodecount; i++)
    if (knownaddr[i] == addr)
        return;

  if (nodecount < MAX_NODES)
    knownaddr[nodecount++] = addr;
}

static int nodecompare(
  const void *paddr1,
  const void *paddr2
)
{
  uint16_t addr1 = *((uint16_t *)paddr1);
  uint16_t addr2 = *((uint16_t *)paddr2);

  if (addr1 != addr2) {
    if (addr1 < addr2)
      return -1;
    return 1;
  }
  return 0;
}

/*
 * Build node address table with entries that are relavent for the
 * specified group identification.
 */
static void build_node_table(
  unsigned char entity
)
{
  int i;

  nodecount = 0;

  /*
   * Start with those nodes which have active logical links
   */
  for (i = 0; i < num_nodes; i++)
    knownaddr[nodecount++] = links[i].addr;

  /*
   * ACTIVE and KNOWN nodes include the designated router is any.
   */
  if ((entity == NICE_NFMT_ACTIVE) || (entity == NICE_NFMT_KNOWN))
    if (router)
      add_to_node_table(router);

  /*
   * KNOWN nodes includes any named nodes.
   */
  if (entity == NICE_NFMT_KNOWN) {
    void *opaque = dnet_getnode();
    char *nodename = dnet_nextnode(opaque);

    while (nodename) {
      struct nodeent *dp = getnodebyname(nodename);
      
      add_to_node_table(*((uint16_t *)dp->n_addr));
      nodename = dnet_nextnode(opaque);
    }
    dnet_endnode(opaque);
  }

  /*
   * Now we sort the array to get it into ascending order
   */
  if (nodecount)
    qsort(knownaddr, nodecount, sizeof(uint16_t), nodecompare);
}

/*
 * Build the nexy hop table indexed by source node address. Each entry
 * contains the next hop to get to the destination address. A value of 0
 * indicates that we have no information available.
 */
static void build_nexthop_table(void)
{
  char buf[256];
  char var1[32], var2[32], var3[32], var4[32], var5[32], var6[32], var7[32];
  FILE *procfile = fopen(PROC_DECNET_CACHE, "r");
  
  memset(nexthop, 0, sizeof(nexthop));

  if (procfile) {
    while (!feof(procfile)) {
      if (!fgets(buf, sizeof(buf), procfile))
        break;

      if (sscanf(buf, "%s %s %s %s %s %s %s\n",
                 var1, var2, var3, var4, var5, var6, var7) == 7) {
        int area, node;
        uint16_t addr, next;

        sscanf(var2, "%d.%d", &area, &node);
        addr = (area << 10) | node;

        sscanf(var4, "%d.%d", &area, &node);
        next = (area << 10) | node;

        /*
         * There may be multiple entries in the cache for a particular
         * destination node, entries with a gateway == destination always
         * take precedent.
         */
        if ((nexthop[addr] == 0) || (addr == next))
          nexthop[addr] = next;
      }
    }
    fclose(procfile);
  }
}

/*
 * Load node information (delay, counters).
 */
static void load_node_info(void)
{
  char buf[256], var1[32];
  uint8_t delay;
  uint16_t since;
  uint32_t usrbytesrcvd, usrbytessent, usrmsgrcvd, usrmsgsent;
  uint32_t totalbytesrcvd, totalbytessent, totalmsgrcvd, totalmsgsent;
  uint16_t connectsrcvd, connectssent, timeouts;

  FILE *procfile = fopen(PROC_DECNET_NODES, "r");

  memset(nodectrs, 0, sizeof(nodectrs));

  if (procfile) {
    while (!feof(procfile)) {
      if (!fgets(buf, sizeof(buf), procfile))
	break;

      if (sscanf(buf, "%s %hhu %hu "
		      "0x%x 0x%x 0x%x 0x%x "
		      "0x%x 0x%x 0x%x 0x%x "
		      "0x%hx 0x%hx 0x%hx\n",
		      var1, &delay, &since, &usrbytesrcvd, &usrbytessent,
		      &usrmsgrcvd, &usrmsgsent, &totalbytesrcvd,
		      &totalbytessent, &totalmsgrcvd, &totalmsgsent,
		      &connectsrcvd, &connectssent, &timeouts) == 14) {
	int area, node, addr;

	sscanf(var1, "%d.%d", &area, &node);
	addr = (area << 10) | node;

	nodectrs[addr].valid = 1;
	nodectrs[addr].delay = delay;
	nodectrs[addr].sincezeroed = since;
	nodectrs[addr].usrbytesrcvd = usrbytesrcvd;
	nodectrs[addr].usrbytessent = usrbytessent;
	nodectrs[addr].usrmsgrcvd = usrmsgrcvd;
	nodectrs[addr].usrmsgsent = usrmsgsent;
	nodectrs[addr].totalbytesrcvd = totalbytesrcvd;
	nodectrs[addr].totalbytessent = totalbytessent;
	nodectrs[addr].totalmsgrcvd = totalmsgrcvd;
	nodectrs[addr].totalmsgsent = totalmsgsent;
	nodectrs[addr].connectsrcvd = connectsrcvd;
	nodectrs[addr].connectssent = connectssent;
	nodectrs[addr].timeouts = timeouts;
      }
    }
    fclose(procfile);
  }
}

/*
 * Process read information requests about the executor node
 */
static void read_node_executor(
  unsigned char how
)
{
  struct nodeent *node;
  char physaddr[6] = { 0xAA, 0x00, 0x04, 0x00, 0x00, 0x00 };
  struct utsname un;
  char ident[256];
  int segbufsize, timer;
  
  node = getnodebyaddr((char *)&localaddr, sizeof(localaddr), PF_DECnet);

  uname(&un);
  sprintf(ident, "%s V%s on %s", IDENT_STRING, VERSION, un.machine);

  /*
   * Limit the length of the identification string according to the
   * protocol specification.
   */
  if (strlen(ident) > 32)
    ident[32] = '\0';

  physaddr[4] = localaddr & 0xFF;
  physaddr[5] = (localaddr >> 8) & 0xFF;

  switch (how) {
    case NICE_READ_OPT_SUM:
    case NICE_READ_OPT_STATUS:
    case NICE_READ_OPT_CHAR:
      NICEsuccessResponse();
      NICEnodeEntity(localaddr, node ? node->n_name : NULL, TRUE);

      if (how == NICE_READ_OPT_SUM)
        NICEparamC1(NICE_P_N_STATE, NICE_P_N_STATE_ON);

      if (how == NICE_READ_OPT_STATUS)
        NICEparamHIn(NICE_P_N_PA, sizeof(physaddr), physaddr);

      NICEparamAIn(NICE_P_N_IDENTIFICATION, ident);

      if ((how == NICE_READ_OPT_SUM) || (how == NICE_READ_OPT_STATUS))
        NICEparamDU2(NICE_P_N_ACTIVELINKS, num_links);

      if (how == NICE_READ_OPT_CHAR) {
        NICEparamCMn(NICE_P_N_MGMTVERS, 3);
          NICEvalueDU1(4);
          NICEvalueDU1(0);
          NICEvalueDU1(0);
	if (get_value(PROC_INCOMINGTIMER, &timer))
	  NICEparamDU2(NICE_P_N_INC_TIMER, timer);
	if (get_value(PROC_OUTGOINGTIMER, &timer))
	  NICEparamDU2(NICE_P_N_OUT_TIMER, timer);
        NICEparamCMn(NICE_P_N_NSPVERSION, 3);
          NICEvalueDU1(4);
          NICEvalueDU1(0);
          NICEvalueDU1(0);
        NICEparamCMn(NICE_P_N_RTRVERSION, 3);
          NICEvalueDU1(2);
          NICEvalueDU1(0);
          NICEvalueDU1(0);
	NICEparamC1(NICE_P_N_RTYPE, get_phase());
        NICEparamDU2(NICE_P_N_MAXCIRCUITS, 1);

        if (get_value(PROC_SEGBUFSIZE, &segbufsize))
          NICEparamDU2(NICE_P_N_SEGBUFFERSIZE, segbufsize);
        /*** TODO - more ***/
        /*** add /proc/sys/net/decnet entries ***/
      }
      NICEflush();
      break;

    case NICE_READ_OPT_CTRS:
      /*
       * For now, just fake the response
       */
      NICEsuccessResponse();
      NICEnodeEntity(localaddr, node ? node->n_name : NULL, TRUE);
      NICEcounter8(NICE_C_N_OVERSIZELOSS, 0);
      NICEcounter8(NICE_C_N_FORMATERR, 0);
      NICEcounter8(NICE_C_N_VERIFREJECT, 0);
      NICEflush();
      break;

    default:
      NICEunsupportedResponse();
  }
}

/*
 * Process read information requests about a single node
 */
static void read_node_single(
  uint16_t address,
  char *name,
  unsigned char how
)
{
  struct nodeent *dp;
  uint16_t next;
  
  /*
   * If we only have a nodename, try to get it's associated address. If this
   * fails we just have to give up. If we only have a nodeaddress, try to
   * find it's associated name. We can continue if this fails.
   */
  if (name) {
    int i;

    for (i = 0; name[i]; i++)
      name[i] = tolower(name[i]);

    if ((dp = getnodebyname(name)) == NULL)
      return;

    address = *((uint16_t *)dp->n_addr);
  } else {
    if ((dp = getnodebyaddr((char *)&address, 2, PF_DECnet)) != NULL)
      name = dp->n_name;
  }

  if (address == localaddr) {
    read_node_executor(how);
    return;
  }

  switch (how) {
    case NICE_READ_OPT_SUM:
    case NICE_READ_OPT_STATUS:
    case NICE_READ_OPT_CHAR:
      NICEsuccessResponse();
      NICEnodeEntity(address, name, FALSE);

      if ((how == NICE_READ_OPT_SUM) || (how == NICE_READ_OPT_STATUS)) {
        uint8_t active = active_connections(address);

        if (active || (address == router))
          NICEparamC1(NICE_P_N_STATE, NICE_P_N_STATE_REACH);

        if (active)
          NICEparamDU2(NICE_P_N_ACTIVELINKS, get_count(address));

	if ((revision[0] >= 3) && nodectrs[address].valid)
	  NICEparamDU2(NICE_P_N_DELAY, nodectrs[address].delay);

        if (active || (address == router))
          if (circuit[0])
            NICEparamAIn(NICE_P_N_CIRCUIT, circuit);

        next = nexthop[address] != 0 ? nexthop[address] : router;
        if (next) {
          char *nextname = routername;

          if (next != router) {
            if ((dp = getnodebyaddr((char *)&next, 2, PF_DECnet)) != NULL)
              nextname = dp->n_name;
            else nextname = NULL;
          }
          NICEparamNodeID(NICE_P_N_NEXTNODE, next, nextname);
        }
      }
      /*** TODO ***/
      NICEflush();
      break;

    case NICE_READ_OPT_CTRS:
      NICEsuccessResponse();
      NICEnodeEntity(address, name, FALSE);

      if (nodectrs[address].valid) {
	NICEcounter16(NICE_C_N_SECONDS, nodectrs[address].sincezeroed);
	NICEcounter32(NICE_C_N_USERBYTESRCVD, nodectrs[address].usrbytesrcvd);
	NICEcounter32(NICE_C_N_USERBYTESSENT, nodectrs[address].usrbytessent);
	NICEcounter32(NICE_C_N_USERMSGSRCVD, nodectrs[address].usrmsgrcvd);
	NICEcounter32(NICE_C_N_USERMSGSSENT, nodectrs[address].usrmsgsent);
	NICEcounter32(NICE_C_N_TOTBYTESRCVD, nodectrs[address].totalbytesrcvd);
	NICEcounter32(NICE_C_N_TOTBYTESSENT, nodectrs[address].totalbytessent);
	NICEcounter32(NICE_C_N_TOTMSGSRCVD, nodectrs[address].totalmsgrcvd);
	NICEcounter32(NICE_C_N_TOTMSGSSENT, nodectrs[address].totalmsgsent);
	NICEcounter16(NICE_C_N_CONNRCVD, nodectrs[address].connectsrcvd);
	NICEcounter16(NICE_C_N_CONNSENT, nodectrs[address].connectssent);
	NICEcounter16(NICE_C_N_RESP_TMO, nodectrs[address].timeouts);
      }
      NICEflush();
      break;

    default:
      NICEunsupportedResponse();
  }
}

/*
 * Process read information requests about, potentially, multiple nodes
 */
static void read_node_multi(
  unsigned char subset,
  unsigned char how
)
{
  int i;

  build_node_table(subset);

  /*
   * For KNOWN nodes we include the executor
   */
  if (subset == NICE_NFMT_KNOWN)
    read_node_executor(how);

  /*
   * Iterate over the table of addressses.
   */
  for (i = 0; i < nodecount; i++)
    if (knownaddr[i] != localaddr)
      read_node_single(knownaddr[i], NULL, how);
}

/*
 * Process read information requests about nodes
 */
static void read_node(
  uint8_t option,
  uint8_t entity
)
{
  uint16_t addr;
  uint8_t length, name[NICE_MAXNODEL + 1];

  scan_links();
  build_nexthop_table();

  if (revision[0] >= 3)
    load_node_info();
  
  if ((signed char)entity > 0) {
    /*
     * Node is specified by name
     */
    NICEbackup(sizeof(uint8_t));
    memset(name, 0, sizeof(name));
    if (NICEgetAI(&length, name, NICE_MAXNODEL))
      read_node_single(0, (char *)name, option & NICE_READ_OPT_TYPE);
    return;
  }

  switch (entity) {
    case NICE_NFMT_SIGNIFICANT:
    case NICE_NFMT_ACTIVE:
    case NICE_NFMT_KNOWN:
      read_node_multi(entity, option & NICE_READ_OPT_TYPE);
      break;

    case NICE_NFMT_ADJACENT:
      if (router)
        read_node_single(router, NULL, option & NICE_READ_OPT_TYPE);
      break;

    case NICE_NFMT_ADDRESS:
      if (NICEget2(&addr)) {
        if (addr == 0)
          read_node_executor(option & NICE_READ_OPT_TYPE);
        else read_node_single(addr, NULL, option & NICE_READ_OPT_TYPE);
      }
      break;

    default:
      break;
  }
}

/*
 * Process read information requests about the one and only circuit
 */
static void read_circuit_info(
  unsigned char how
)
{
  int cost;

  switch (how) {
    case NICE_READ_OPT_SUM:
    case NICE_READ_OPT_STATUS:
    case NICE_READ_OPT_CHAR:
      NICEsuccessResponse();
      NICEcircuitEntity(circuit);

      if ((how == NICE_READ_OPT_SUM) || (how == NICE_READ_OPT_STATUS)) {
        NICEparamC1(NICE_P_C_STATE, NICE_P_C_STATE_ON);
	if (router != 0)
          NICEparamNodeID(NICE_P_C_ADJNODE, router, routername);
      }

      if (how == NICE_READ_OPT_STATUS)
        if (router)
          NICEparamNodeID(NICE_P_C_DR, router, routername);

      if (how == NICE_READ_OPT_CHAR) {
        NICEparamC1(NICE_P_C_TYPE, NICE_P_C_TYPE_ETHER);
	if (get_value(PROC_DECNET_COST, &cost))
	  NICEparamDU1(NICE_P_C_COST, cost);
        NICEparamDU2(NICE_P_C_HELLO, hellotmr);
        NICEparamDU2(NICE_P_C_LISTEN, listentmr);
      }

      NICEflush();
      break;

    default:
      NICEunsupportedResponse();
  }
}

/*
 * Process read information requests about circuits
 */
static void read_circuit(
  uint8_t option,
  uint8_t entity
)
{
  uint8_t length, name[NICE_MAXCIRCUITL + 1];

  if ((signed char)entity > 0) {
    /*
     * Circuit is specified by name
     */
    NICEbackup(sizeof(uint8_t));
    memset(name, 0, sizeof(name));
    if (NICEgetAI(&length, name, NICE_MAXCIRCUITL)) {
      if (strcasecmp((char *)name, circuit) == 0)
        read_circuit_info(option & NICE_READ_OPT_TYPE);
      else NICEunrecognizedComponentResponse(NICE_ENT_CIRCUIT);
    }
    return;
  }

  switch (entity) {
    case NICE_SFMT_SIGNIFICANT:
    case NICE_SFMT_ACTIVE:
    case NICE_SFMT_KNOWN:
      read_circuit_info(option & NICE_READ_OPT_TYPE);
      break;

    default:
      break;
  }
}

/*
 * Process read information requests about the one and only area we
 * know about
 */
static void read_area_info(
  unsigned char how
)
{
  uint8_t area = (localaddr >> 10) & 0x3F;

  switch (how) {
    case NICE_READ_OPT_SUM:
    case NICE_READ_OPT_STATUS:
      NICEsuccessResponse();
      NICEareaEntity(area);

      NICEparamC1(NICE_P_A_STATE, NICE_P_A_STATE_REACH);
      if (circuit[0])
        NICEparamAIn(NICE_P_A_CIRCUIT, circuit);
      if (router)
        NICEparamNodeID(NICE_P_A_NEXTNODE, router, routername);

      NICEflush();
      break;

    default:
      NICEunsupportedResponse();
      break;
  }
}

/*
 * Process read information requests about areas
 */
static void read_area(
  unsigned char option,
  unsigned char entity
)
{
  uint8_t area;

  switch (entity) {
    case NICE_AFMT_ACTIVE:
    case NICE_AFMT_KNOWN:
      read_area_info(option & NICE_READ_OPT_TYPE);
      break;

    case NICE_AFMT_ADDRESS:
      if (NICEget1(&area))
        if (area == ((localaddr >> 10) & 0x3F))
          read_area_info(option & NICE_READ_OPT_TYPE);
      break;

    default:
      break;
  }
}

/*
 * Process read information requests
 */
static void read_information(void)
{
  unsigned char option, entity;

  if (NICEget1(&option) && NICEget1(&entity)) {
    NICEacceptedResponse();

    if (verbosity > 0)
      dnetlog(LOG_DEBUG, "read: option=0x%02x, entity=%d\n", option, entity);

    switch (option & NICE_READ_OPT_ENTITY) {
      case NICE_ENT_NODE:
        read_node(option, entity);
        break;

      case NICE_ENT_CIRCUIT:
        read_circuit(option, entity);
        break;

      case NICE_ENT_AREA:
        read_area(option, entity);
        break;

      default:
        break;
    }
    NICEdoneResponse();
  }
}

/*
 * Issue a "zero counters" command to the decnet module
 */
static int zero_command(
  char *command
)
{
  int fd = open(PROC_ZERO_NODE, O_WRONLY);

  if (fd != -1) {
    if (write(fd, command, strlen(command)) == strlen(command)) {
      close(fd);
      return TRUE;
    }
    close(fd);
  }
  NICEoperationFailureResponse();
  return FALSE;
}

/*
 * Process a zero counters operation for a single node.
 */
static void zero_node_single(
  uint16_t address,
  char *name
)
{
  struct nodeent *dp;
  char addr[8];

  /*
   * If we only have a nodename, try to get it's associated address. If this
   * fails we just have to give up.
   */
  if (name) {
    int i;

    for (i = 0; name[i]; i++)
      name[i] = tolower(name[i]);

    if ((dp = getnodebyname(name)) == NULL)
      return;

    address = *((uint16_t *)dp->n_addr);
  }

  sprintf(addr, "%u.%u", (address >> 10) & 0x3F, address & 0x3FF);

  if (zero_command(addr)) {
    NICEsuccessResponse();
    NICEflush();
  }
}

/*
 * Process a zero counters operation for all nodes
 */
static void zero_node_all(void)
{
  if (zero_command("*")) {
    NICEsuccessResponse();
    NICEflush();
  }
}

/*
 * Process zero counters for a single or all (known) nodes.
 */
static void zero_node(
  uint8_t option,
  uint8_t entity
)
{
  uint16_t addr;
  uint8_t length, name[NICE_MAXNODEL + 1];

  if (revision[0] >= 3)
    load_node_info();

  if ((signed char)entity > 0) {
    /*
     * Node is specified by name
     */
    NICEbackup(sizeof(uint8_t));
    memset(name, 0, sizeof(name));
    if (NICEgetAI(&length, name, NICE_MAXNODEL))
      zero_node_single(0, (char *)name);
    return;
  }

  switch (entity) {
    case NICE_NFMT_KNOWN:
      zero_node_all();
      break;

    case NICE_NFMT_ADDRESS:
      if (NICEget2(&addr)) {
	if (addr == 0)
	  addr = localaddr;
	zero_node_single(addr, NULL);
      }
      break;

    default:
      break;
  }
}

/*
 * Process zero counters requests
 */
static void zero_counters(void)
{
  unsigned char option, entity;

  if (NICEget1(&option) && NICEget1(&entity)) {
    NICEacceptedResponse();

    if (verbosity > 0)
      dnetlog(LOG_DEBUG, "zero: option=0x%02x, entity=%d\n", option, entity);

    switch (option & NICE_ZERO_OPT_ENTITY) {
      case NICE_ENT_NODE:
	zero_node(option, entity);
	break;

      default:
	break;
    }
    NICEdoneResponse();
  }
}

/*
 * Perform a loop node test.
 */
static int loopNode(
  uint16_t addr,
  struct accessdata_dn *access,
  uint16_t count,
  uint16_t length,
  uint8_t with
)
{
  int lsock = -1;
  uint16_t i, remmax;
  uint8_t sndbuf[NICE_LOOP_MAX_LEN + 1], rcvbuf[NICE_LOOP_MAX_LEN + 1];
  struct sockaddr_dn saddr;
  struct optdata_dn opt;
  socklen_t optlen = sizeof(struct optdata_dn);
  uint16_t detail = NICE_MIR_DET_UNREACHABLE;

  if (verbosity > 1)
    dnetlog(LOG_DEBUG, "loop: node %u.%u, count=%u, length=%u, with=%u\n",
	    (addr >> 10) & 0xFF, addr & 0x3FF, count, length, with);

  memset(&saddr, 0, sizeof(struct sockaddr_dn));
  saddr.sdn_family = AF_DECnet;
  saddr.sdn_objnum = DNOBJECT_MIRROR;
  saddr.sdn_nodeaddrl = sizeof(addr);
  memcpy(saddr.sdn_nodeaddr, &addr, sizeof(addr));

  if ((lsock = socket(PF_DECnet, SOCK_SEQPACKET, DNPROTO_NSP)) >= 0) {
    if (access)
      if (setsockopt(lsock, DNPROTO_NSP, DSO_CONACCESS, access, sizeof(*access)) < 0)
	goto fail;

    if (connect(lsock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
      if (errno == ECONNREFUSED) {
	struct optdata_dn rejdata;
	socklen_t rejlen = sizeof(struct optdata_dn);

	if (getsockopt(lsock, DNPROTO_NSP, DSO_CONDATA, &rejdata, &rejlen) == 0) {
	  switch (rejdata.opt_status) {
	    case DNSTAT_ACCCONTROL:
	      detail = NICE_MIR_DET_ACCESS;
	      break;

	    case DNSTAT_NORESPONSE:
	      detail = NICE_MIR_DET_NORESP;
	      break;
	  }
	}
      }

      NICEmirrorConnectFailedResponse(detail);
      close(lsock);
      return -1;
    }

    if ((getsockopt(lsock, DNPROTO_NSP, DSO_CONDATA, &opt, &optlen) < 0) ||
	(opt.opt_optl != sizeof(uint16_t))) {
      NICEoperationFailureResponse();
      close(lsock);
      return -1;
    }

    remmax = (opt.opt_data[1] << 8) | opt.opt_data[0];
    if (length > remmax) {
      NICEinvalidParameterValueResponse(NICE_P_N_LL);
      close(lsock);
      return -1;
    }

    sndbuf[0] = NICE_LOOP_FUNC_SEND;
    rcvbuf[0] = NICE_LOOP_FUNC_SUCCESS;

    switch (with) {
      case NICE_P_N_LW_ZEROES:
	memset(&sndbuf[1], 0, length);
	break;

      case NICE_P_N_LW_ONES:
	memset(&sndbuf[1], 0xFF, length);
	break;

      case NICE_P_N_LW_MIXED:
	srandom((unsigned int)time(NULL));
	for (i = 0; i < length; i++)
	  sndbuf[i + 1] = random() & 0xFF;
	break;
    }

    while ((count-- != 0) && (rcvbuf[0] == NICE_LOOP_FUNC_SUCCESS)) {
      ssize_t result;

      if ((result = write(lsock, sndbuf, length + 1)) != (length + 1)) {
	struct optdata_dn discdata;
	socklen_t disclen = sizeof(struct optdata_dn);

	if (getsockopt(lsock, DNPROTO_NSP, DSO_DISDATA, &discdata, &disclen) ==  0) {
	  switch (discdata.opt_status) {
	    case DNSTAT_MANAGEMENT:
	      detail = NICE_MIR_DET_MGMTABORT;
	      break;

	    case DNSTAT_ABORTOBJECT:
	      detail = NICE_MIR_DET_ABORT;
	      break;

	    case DNSTAT_FAILED:
	      detail = NICE_MIR_DET_FAILED;
	      break;
	  }
	  NICEmirrorLinkDisconnectedResponse(detail);
	  close(lsock);
	  return -1;
	}
	goto fail;
      }
      if (((result = read(lsock, rcvbuf, length + 1)) != (length + 1)) ||
	  (rcvbuf[0] != NICE_LOOP_FUNC_SUCCESS) ||
	  (memcmp(&rcvbuf[1], &sndbuf[1], length) != 0)) {
	NICEbadLoopbackResponse();
	close(lsock);
	return -1;
      }
    }
    close(lsock);
    return 0;
  }
fail:
  NICEoperationFailureResponse();
  if (lsock >= 0)
    close(lsock);
  return -1;
}

/*
 * Process test requests
 */
static void test(void)
{
  uint8_t option, format, with = NICE_P_N_LW_MIXED;
  uint16_t param;
  uint16_t count = NICE_LOOP_DEF_COUNT, length = NICE_LOOP_DEF_LEN;

  if (NICEget1(&option)) {
    if (verbosity > 0)
      dnetlog(LOG_DEBUG, "loop: option=0x%02x\n", option);

    if ((option & 0x03) == NICE_LOOP_OPT_NODE) {
      struct accessdata_dn access, *accp = NULL;
      uint8_t nodename[6];
      uint16_t addr;

      memset(&access, 0, sizeof(struct accessdata_dn));
      memset(&nodename, 0, sizeof(nodename));

      if (!NICEget1(&format) ||
	  (format > sizeof(nodename))) {
	NICEformatResponse();
	return;
      }

      /*
       * The node may be specified as a node address or node name
       */
      if (format > 0) {
	uint8_t i;
	struct nodeent *dp;

	for (i = 0; i < format; i++)
	  if (!NICEget1(&nodename[i])) {
	    NICEformatResponse();
	    return;
	  }

	if ((dp = getnodebyname((char *)nodename)) == NULL) {
	  NICEmirrorConnectFailedResponse(NICE_MIR_DET_NONAME);
	  return;
	}
	memcpy(&addr, dp->n_addr, sizeof(uint16_t));
      } else {
	if (!NICEget2(&addr)) {
	  NICEformatResponse();
	  return;
	}
      }

      if ((option & NICE_LOOP_OPT_ACCESS) != 0) {
	accp = &access;

	if (!NICEgetAI(&access.acc_userl, access.acc_user, DN_MAXACCL) ||
	    !NICEgetAI(&access.acc_passl, access.acc_pass, DN_MAXACCL) ||
	    !NICEgetAI(&access.acc_accl, access.acc_acc, DN_MAXACCL))
	  return;
      }

      while (NICEdataAvailable()) {
	if (!NICEget2(&param))
	  return;

	switch (param) {
	  case NICE_P_N_LC:
	    if (!NICEget2(&count))
	      return;
	    break;

	  case NICE_P_N_LL:
	    if (!NICEget2(&length))
	      return;
	    if (length > NICE_LOOP_MAX_LEN) {
	      NICEinvalidParameterValueResponse(NICE_P_N_LL);
	      return;
	    }
	    break;

	  case NICE_P_N_LW:
	    if (!NICEget1(&with))
	      return;
	    if ((with != NICE_P_N_LW_ZEROES) &&
		(with != NICE_P_N_LW_ONES) &&
		(with != NICE_P_N_LW_MIXED)) {
	      NICEinvalidParameterValueResponse(NICE_P_N_LW);
	      return;
	    }
	    break;

	  default:
	    NICEunrecognizedParameterTypeResponse(param);
	    return;
	}
      }

      if (loopNode(addr, accp, count, length, with) == 0) {
	NICEsuccessResponse();
	NICEflush();
      }
    } else NICEunsupportedResponse();
  }
}

/*
 * Process requests from a socket until we get an error or the socket is
 * closed by the other end.
 */
void process_request(
  int sock
)
{
  struct dn_naddr *execaddr = getnodeadd();

  /*
   * Get some information about the current state of this node
   */
  localaddr = (execaddr->a_addr[1] << 8) | execaddr->a_addr[0];
  localarea = (localaddr >> 10) & 0x3F;
  get_revision();
  get_router();

  NICEinit(sock);

  for (;;) {
    int status = NICEread();
    uint8_t func;

    if ((status == -1) || (status == 0))
      break;

    if (NICEget1(&func)) {
      switch (func) {
        case NICE_FC_READ:                      /* Read information */
          read_information();
          break;

        case NICE_FC_ZERO:                      /* Zero counters */
	  if (revision[0] >= 3)
	    zero_counters();
	  else NICEunsupportedResponse();
	  break;

        case NICE_FC_TEST:                      /* Test */
	  test();
	  break;

        case NICE_FC_DLL:                       /* Request down-line load */
        case NICE_FC_ULD:                       /* Request up-line dump */
        case NICE_FC_BOOT:                      /* Trigger bootstrap */
        case NICE_FC_CHANGE:                    /* Change parameter */
        case NICE_FC_SYS:                       /* System specific function */
        default:
          NICEunsupportedResponse();
      }
    }
  }
  close(sock);
}

