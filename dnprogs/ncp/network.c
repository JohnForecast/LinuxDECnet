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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/socket.h>
#include <string.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>

#include "ncp.h"
#include "nice.h"

uint8_t tellvalid = 0;
uint16_t telladdr;
struct accessdata_dn tellaccess;

uint8_t setexecvalid = 0;
uint16_t setexecaddr;
struct accessdata_dn setexecaccess;

#define NML_OBJ		19

static int dnConnect(
  uint16_t addr,
  struct accessdata_dn *access,
  struct optdata_dn *optdata
)
{
  int sock = -1;
  struct optdata_dn ver = { 0, 3, { 4, 0, 0 } };
  socklen_t optlen = sizeof(struct optdata_dn);
  struct sockaddr_dn saddr;

  memset(&saddr, 0, sizeof(saddr));
  saddr.sdn_family = AF_DECnet;

  if ((sock = socket(PF_DECnet, SOCK_SEQPACKET, DNPROTO_NSP)) >= 0) {
    if (access) {
      if (setsockopt(sock, DNPROTO_NSP, DSO_CONACCESS, access, sizeof(*access)) < 0) {
	fprintf(stderr, "Unable to set access control information on socket\n");
	goto fail;
      }
    }

    if (setsockopt(sock, DNPROTO_NSP, DSO_CONDATA, &ver, sizeof(ver)) < 0) {
      fprintf(stderr, "Unable to set optional data on socket\n");
      goto fail;
    }

    saddr.sdn_nodeaddrl = sizeof(addr);
    memcpy(&saddr.sdn_nodeaddr, &addr, sizeof(addr));
    saddr.sdn_objnum = NML_OBJ;

    if (connect(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
      fprintf(stderr, "Unable to connect to listener\n");
      goto fail;
    }

    if (optdata) {
      optdata->opt_optl = DN_MAXOPTL;

      if (getsockopt(sock, DNPROTO_NSP, DSO_CONDATA, optdata, &optlen) < 0) {
	fprintf(stderr, "Failed to get optional data on connect\n");
  fail:
	close(sock);
	return -1;
      }
    }
  }
  return sock;
}

/*
 * Connect to network management listener on correct system.
 */
int netConnect(void)
{
  int sock;
  struct optdata_dn optdata;

  if (tellvalid)
    sock = dnConnect(telladdr, &tellaccess, &optdata);
  else if (setexecvalid)
    sock = dnConnect(setexecaddr, &setexecaccess, &optdata);
  else sock = dnConnect(0, NULL, &optdata);

  tellvalid = 0;

  if (sock >= 0) {
    if ((optdata.opt_optl < 3) || (optdata.opt_data[0] != 4)) {
      fprintf(stderr, "Version mismatch\n");
      close(sock);
      return -1;
    }
  } else return -1;
  NICEsock(sock);
  return sock;
}

/*
 * Parse a nodename/node address with optional access control information.
 * Both DECnet-VMS syntax:
 *
 *	node"username password account"::
 *
 * or DECnet-Ultrix (and RSX-11) syntax"
 *
 *	node/username/password/account::
 *
 * where the "::" is optional.
 *
 * The access control information may also be provided by subsequent keywords:
 *
 *	USER user-id
 *	PASSWORD password
 *	ACCOUNT account
 */
static int parseRemote(
  uint16_t *addr,
  struct accessdata_dn *access
)
{
#define STATE_NODE	1
#define STATE_USER	2
#define STATE_PASSWORD	3
#define STATE_ACCOUNT	4
#define STATE_DONE	5
  int state = STATE_NODE, n0 = 0, n1 = 0;
  char *str = wds[idx];
  char sep, term, name[8];
  uint16_t area = 0, node, valid = 0;

  memset(access, 0, sizeof(struct accessdata_dn));
  memset(name, 0, sizeof(name));

  while (state != STATE_DONE) {
    switch (state) {
      case STATE_NODE:
	if ((str[n0] != ':') && (str[n0] != '\"') &&
	    (str[n0] != '\'') && (str[n0] != '/') &&
	    (str[n0] != '\0')) {
	  if (n1 >= (sizeof(name) - 1))
	    return 0;

	  name[n1++] = str[n0++];
	} else {
	  n1 = 0;
	  switch (str[n0]) {
	    case '\"':
	    case '\'':
	      sep = ' ';
	      term = str[n0++];
	      state = STATE_USER;
	      break;

	    case '/':
	      sep = '/';
	      term = 0;
	      n0++;
	      state = STATE_USER;
	      break;

	    case '\0':
	      state = STATE_DONE;
	      break;

	    default:
	      n0++;
	      if (str[n0++] != ':')
		return 0;
	      state = STATE_DONE;
	      break;
	  }
	}
	break;

      case STATE_USER:
	if ((str[n0] != sep) &&
	    (str[n0] != '\0') &&
	    (str[n0] != (term ? term : ':'))) {
	  if (n1 >= (DN_MAXACCL - 1))
	    return 0;

	  access->acc_user[n1++] = str[n0++];
	} else {
	  access->acc_userl = n1;
	  n1 = 0;
	  if (str[n0] == sep) {
	    n0++;
	    state = STATE_PASSWORD;
	  } else {
	    if (str[n0++] == ':')
	      if (str[n0] != ':')
		return 0;
	    state = STATE_DONE;
	  }
	}
	break;

      case STATE_PASSWORD:
	if ((str[n0] != sep) &&
	    (str[n0] != '\0') &&
	    (str[n0] != (term ? term : ':'))) {
	  if (n1 >= (DN_MAXACCL - 1))
	    return 0;

	  access->acc_pass[n1++] = str[n0++];
	} else {
	  access->acc_passl = n1;
	  n1 = 0;
	  if (str[n0] == sep) {
	    n0++;
	    state = STATE_ACCOUNT;
	  } else {
	    if (str[n0++] == ':')
	      if (str[n0] != ':')
		return 0;
	    state = STATE_DONE;
	  }
	}
	break;

      case STATE_ACCOUNT:
	if ((str[n0] != sep) &&
	    (str[n0] != '\0') &&
	    (str[n0] != (term ? term : ':'))) {
	  if (n1 >= (DN_MAXACCL - 1))
	    return 0;

	  access->acc_acc[n1++] = str[n0++];
	} else {
	  access->acc_accl = n1;
	  n1 = 0;
	  if (str[n0] == sep) {
	    n0++;
	    state = STATE_ACCOUNT;
	  } else {
	    if (str[n0++] == ':')
	      if (str[n0] != ':')
		return 0;
	    state = STATE_DONE;
	  }
	}
	break;

      case STATE_DONE:
	break;
    }
  }

  idx++;

  while (idx < args) {
    if (vmatch(wds[idx], "user") == 0) {
      idx++;
      if ((strlen(wds[idx]) >= DN_MAXACCL) || (idx >= args))
	return 0;
      access->acc_userl = strlen(wds[idx]);
      memcpy(access->acc_user, wds[idx], access->acc_userl);
      idx;
      continue;
    }
    if (vmatch(wds[idx], "password") == 0) {
      idx++;
      if ((strlen(wds[idx]) >= DN_MAXACCL) || (idx >= args))
	return 0;
      access->acc_passl = strlen(wds[idx]);
      memcpy(access->acc_pass, wds[idx], access->acc_passl);
      idx;
      continue;
    }
    if (vmatch(wds[idx], "account") == 0) {
      idx++;
      if ((strlen(wds[idx]) >= DN_MAXACCL) || (idx >= args))
	return 0;
      access->acc_accl = strlen(wds[idx]);
      memcpy(access->acc_acc, wds[idx], access->acc_accl);
      idx;
      continue;
    }
    break;
  }

  /*
   * Now we need to determine whether the node was specified as an address
   * or a node name.
   */
  str = name;

  if (*str != 0) {
    if (strchr(name, '.') != NULL) {
      if (!isdigit(*str))
	goto notaddr;

      area = *str++ - '0';
      if (isdigit(*str)) {
	area *= 10;
	area += *str++ - '0';
      }
      if (*str++ != '.')
	goto notaddr;
    }

    if (isdigit(*str)) {
      node = *str++ - '0';
      if (isdigit(*str)) {
	node *= 10;
	node += *str++ - '0';
      }
      if (isdigit(*str)) {
	node *= 10;
	node += *str++ - '0';
      }
      if (isdigit(*str)) {
	node *= 10;
	node += *str++ - '0';
      }

      if (*str == 0) {
	if ((node <= 1023) && (area <= 63)) {
	  *addr = (area << 10) | node;
	  return 1;
	}
      }
    }
  }

notaddr:
  /*
   * Try to parse the input as a node name
   */
  if (strlen(name) <= 6) {
    str = name;

    while (*str != 0) {
      if (!isalnum(*str))
	return 0;
      if (isalpha(*str)) {
	valid = 1;
	*str = toupper(*str);
      }
      str++;
    }

    if (valid) {
      struct nodeent *dp;

      if ((dp = getnodebyname(name)) != NULL) {
	memcpy(addr, dp->n_addr, sizeof(uint16_t));
	return 1;
      }
    }
  }
  return 0;
}

int parseForTell(void)
{
  if (parseRemote(&telladdr, &tellaccess)) {
    tellvalid = 1;
    return 1;
  }
  return 0;
}

int parseForSetexec(void)
{
  if (parseRemote(&setexecaddr, &setexecaccess)) {
    setexecvalid = 1;
    return 1;
  }
  return 0;
}

