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
#include <string.h>
#include <syslog.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>
#include "dn_endian.h"

/*
 * The requested test is passed in the connect optional data:
 *
 * Byte 0:              Test #
 *			Bit 7 set requests DTR to display statistics
 * Byte 1:              Subtest/flags
 * Byte 2:              Flow control type (Data/Interrupt tests)
 * Byte 2:              Interrupt flow control value (always 1)
 * Byte 3:              Flow control value (Data test)
 * Byte 3:              Message length (Interrupt test)
 * Byte 4,5:            Unknown
 * Byte 6,7:            Message length (Data test)
 */
#define DTS_TEST_CONNECT        0x00    /* Connect test */
#define DTS_TEST_DATA           0x01    /* Data transfer test */
#define DTS_TEST_DISCONNECT     0x02    /* Disconnect test */
#define DTS_TEST_INTERRUPT      0x03    /* Interrupt transfer test */

#define DTS_SUBTEST_REJ         0x00    /* Reject subtest of connect */
#define DTS_SUBTEST_ACC         0x01    /* Accept subtest of connect */

#define DTS_SUBTEST_DSC         0x00    /* Disconnect subtest of disconnect */
#define DTS_SUBTEST_ABT         0x01    /* Abort subtest of disconnect */

#define DTS_SUBTEST_MASK        0x01    /* Mask for subtest type */

                                        /* Connect/disconnect flags */
#define DTS_CONNDIS_NONE        0x00    /* No optional data to send */
#define DTS_CONNDIS_STD         0x02    /* Send standard optional data */
#define DTS_CONNDIS_RCVD        0x04    /* Send received optional data */

                                        /* Data/Interrupt test options */
#define DTS_DATAINT_SINK        0x00    /* Drop all received data */
#define DTS_DATAINT_SEQ         0x01    /* Validate sequence numbers */
#define DTS_DATAINT_PAT         0x02    /* Validate data pattern */
#define DTS_DATAINT_ECHO        0x03    /* Echo data back to sender */

#define DTS_DATA_NONE           0x00    /* Use no flow control */
#define DTS_DATA_SEGMENT        0x01    /* Use segment flow control */
#define DTS_DATA_MESSAGE        0x02    /* Use message flow control */

#define DTS_DATA_MAXSIZE        4096
#define DTS_INT_MAXSIZE           16

#define DTS_PATTERN             "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

char std_optdata[16] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P'
};

char *tests[] = {
  "accept",
  "reject",
  "disc",
  "abort",
  "data",
  "interrupt",
  NULL
};
#define CMD_ACCEPT              0
#define CMD_REJECT              1
#define CMD_DISC                2
#define CMD_ABORT               3
#define CMD_DATA                4
#define CMD_INTERRUPT           5

char *options[] = {
  "o:", "o:", "o:", "o:", "c:f:v:l:r:st:", "c:l:r:st:"
};

struct switchval {
  char          *name;
  int           value;
};

struct switchval oswitch[] = {
  { "none", DTS_CONNDIS_NONE },
  { "std", DTS_CONNDIS_STD },
  { "rcvd", DTS_CONNDIS_RCVD },
  { NULL }
};

struct switchval fswitch[] = {
  { "none", DTS_DATA_NONE },
  { "seg", DTS_DATA_SEGMENT },
  { "msg", DTS_DATA_MESSAGE },
  { NULL }
};

struct switchval rswitch[] = {
  { "sink", DTS_DATAINT_SINK },
  { "seq", DTS_DATAINT_SEQ },
  { "pat", DTS_DATAINT_PAT },
  { "echo", DTS_DATAINT_ECHO },
  { NULL }
};

#define MAX_NODE                6

char *remote = "0.0::";

int sock;
struct sockaddr_dn sockaddr;
struct accessdata_dn accessdata;

extern char *optarg;

/*
 * Test parameters
 */
unsigned long long cvalue;
int ovalue, fvalue, rvalue, lvalue, vvalue, tvalue;
int sswitch = 0;

void run_test(int);
void parse(void);

void usage(
  char *prog,
  FILE *f
)
{
  fprintf(f, "\n%s TEST [OPTIONS] [remote[::]]\n\n", prog);
  fprintf(f, " where:\n");
  fprintf(f, "  TEST is:\n");
  fprintf(f, "   accept            - Accept a connection request\n");
  fprintf(f, "   reject            - Reject a connection request\n");
  fprintf(f, "   disc              - Disconnect a connection\n");
  fprintf(f, "   abort             - Abort a connection\n");
  fprintf(f, "   data              - Test data transfer\n");
  fprintf(f, "   interrupt         - Test interrupt message transfer\n\n");
  fprintf(f, "  OPTIONS is:\n");
  fprintf(f, "   accept/reject/disc/abort:\n");
  fprintf(f, "    -o none|std|rcvd - Type of returned optional data\n\n");
  fprintf(f, "   data:\n");
  fprintf(f, "    -c n             - Limit count of data messages sent\n");
  fprintf(f, "    -f none|seg|msg  - Flow control type\n");
  fprintf(f, "    -v n             - Msg or seg flow control value\n");
  fprintf(f, "    -l n             - Data message size\n");
  fprintf(f, "    -r sink|seq|pat|echo\n");
  fprintf(f, "                     - Received message processing options\n");
  fprintf(f, "    -s               - Print test statistics\n");
  fprintf(f, "    -t n             - Test duration in seconds\n\n");
  fprintf(f, "   interrupt:\n");
  fprintf(f, "    -c n             - Limit count of interrupt messages sent\n");
  fprintf(f, "    -l n             - Interrupt message size\n");
  fprintf(f, "    -r sink|seq|pat|echo\n");
  fprintf(f, "                     - Received message processing options\n");
  fprintf(f, "    -s               - Print test statistics\n");
  fprintf(f, "    -t n             - Test duration in seconds\n\n");
  fprintf(f, "Default options:\n");
  fprintf(f, " -o none -c 0 -f none -v 1 -l 1024 -t 30\n\n");
  fprintf(f, "The remote node defaults to the local system and may contain\n");
  fprintf(f, "control information in either VMS or Ultrix format:\n\n");
  fprintf(f, "    node\"user password\"[::]   or\n");
  fprintf(f, "    node/user/password[::]\n\n");
}

int switchidx(
  char *key,
  struct switchval *tbl
)
{
  int i = 0;

  do {
    if (strcmp(key, tbl[i].name) == 0)
      return i;
  } while (tbl[++i].name != NULL);
  return -1;
}

int main(
  int argc,
  char **argv
)
{
  int cmd = 0;
  char *progname = argv[0];
  int maxsize = DTS_DATA_MAXSIZE;
  char opt, *endptr;
  unsigned long val;
  unsigned long long vall;

  if (argc >= 2) {
    /*
     * Determine if we have a valid test
     */
    do {
      if (strcmp(argv[1], tests[cmd]) == 0) {
        argv++, argc--;

        /*
         * Initialize test parameters
         */
        cvalue = 0;
        ovalue = DTS_CONNDIS_NONE;
        fvalue = DTS_DATA_NONE;
        rvalue = DTS_DATAINT_SINK;
        lvalue = 1024;
        vvalue = 1;
        tvalue = 30;

        if (cmd == CMD_INTERRUPT)
          lvalue = maxsize = DTS_INT_MAXSIZE;

        /*
         * Process options which are relevant to this particular test.
         */
        while ((opt = getopt(argc, argv, options[cmd])) != EOF) {
          int idx;

          switch (opt) {
            case 'c':
              vall = strtoull(optarg, &endptr, 10);
              if (*endptr != '\0')
                goto done;
              cvalue = vall;
              break;

            case 'f':
              if ((idx = switchidx(optarg, fswitch)) == -1)
                goto done;
              fvalue = fswitch[idx].value;
              break;

            case 'l':
              val = strtoul(optarg, &endptr, 10);
              if ((*endptr != '\0') || (val > maxsize))
                goto done;
              lvalue = val;
              break;

            case 'o':
              if ((idx = switchidx(optarg, oswitch)) == -1)
                goto done;
              ovalue = oswitch[idx].value;
              break;

            case 'r':
              if ((idx = switchidx(optarg, rswitch)) == -1)
                goto done;
              rvalue = rswitch[idx].value;
              break;

            case 's':
              sswitch = 1;
              break;

            case 't':
              val = strtoul(optarg, &endptr, 10);
              if (*endptr != '\0')
                goto done;
              tvalue = val;
              break;

            case 'v':
              val = strtoul(optarg, &endptr, 10);
              if ((*endptr != '\0') || ((val & ~0xFF) != 0))
                goto done;
              vvalue = val;
              break;
          }
        }
        argc -= optind;
        argv += optind;

        if (argc == 1)
          remote = argv[0];

        parse();
        run_test(cmd);
        exit(0);
      }
    } while (tests[++cmd] != NULL);
  }
 done:
  usage(progname, stdout);
  exit(0);
}

void parse(void)
{
  enum { NODE, USER, PASSWORD, ACCOUNT, FINISHED } state = NODE;
  char *ptr = remote;
  char sep, term, node[MAX_NODE + 1];
  int idx = 0;
  struct nodeent *dn;
  unsigned int area, addr;
  uint16_t nodeaddr;

  memset(&sockaddr, 0, sizeof(sockaddr));
  memset(&accessdata, 0, sizeof(accessdata));

  memset(node, 0, sizeof(node));

  while (state != FINISHED) {
    switch (state) {
      case NODE:
        switch (*ptr) {
          default:
            if ((idx >= MAX_NODE) || !(isalnum(*ptr) || (*ptr == '.'))) {
            badnode:
              fprintf(stderr, "Invalid node name/address\n");
              exit(1);
            }
            node[idx++] = *ptr++;
            break;

          case ':':
            if (*++ptr != ':')
              goto badnode;
            /* FALLTHROUGH */

          case '\0':
            state = FINISHED;
            break;

          case '"':
            sep = ' ';
            term = *ptr++;
            goto usercommon;

          case '/':
            sep = '/';
            term = 0;
            ptr++;
        usercommon:
            state = USER;
            break;
        }
        break;

      default:
        if (*ptr == '\0')
          state = FINISHED;
        
        switch (state) {
          case USER:
            if ((*ptr != sep) && (*ptr != (term ? term : ':'))) {
              if (accessdata.acc_userl >= (DN_MAXACCL - 1)) {
              baduser:
                fprintf(stderr, "Invalid user name\n");
                exit(1);
              }
              accessdata.acc_user[accessdata.acc_userl++] = *ptr++;
            } else {
              if (*ptr++ == sep)
                state = PASSWORD;
              else {
                if (!term && (*ptr != ':'))
                  goto baduser;
                state = FINISHED;
              }
            }
            break;
            
          case PASSWORD:
            if ((*ptr != sep) && (*ptr != (term ? term : ':'))) {
              if (accessdata.acc_passl >= (DN_MAXACCL - 1)) {
              badpass:
                fprintf(stderr, "Invalid password\n");
                exit(1);
              }
              accessdata.acc_pass[accessdata.acc_passl++] = *ptr++;
            } else {
              if (*ptr++ == sep)
                state = ACCOUNT;
              else {
                if (!term && (*ptr != ':'))
                  goto badpass;
                state = FINISHED;
              }
            }
            break;

          case ACCOUNT:
            if ((*ptr != sep) && (*ptr != (term ? term : ':'))) {
              if (accessdata.acc_accl >= (DN_MAXACCL - 1)) {
              badacc:
                fprintf(stderr, "Invalid account\n");
                exit(1);
              }
              accessdata.acc_acc[accessdata.acc_accl++] = *ptr++;
            } else state = FINISHED;
            break;

          case FINISHED:
            break;

          default:
            fprintf(stderr, "Internal error parsing node information\n");
            exit(1);
        }
    }
  }

  /*
   * Now contruct the sockaddr structure for the remote node
   */
  sockaddr.sdn_family = AF_DECnet;
  sockaddr.sdn_objnum = DNOBJECT_DTR;
  sockaddr.sdn_nodeaddrl = DN_MAXADDL;

  if ((dn = getnodebyname(node)) != NULL) {
    memcpy(sockaddr.sdn_nodeaddr, dn->n_addr, sizeof(sockaddr.sdn_nodeaddr));
    return;
  }

  /*
   * Unknown node name, maybe it's a node address
   */
  if ((sscanf(node, "%u.%u", &area, &addr) != 2) ||
      (area > 63) || (addr > 1023)) {
    fprintf(stdout, "Unknown node name or invalid address - %s\n", node);
    exit(1);
  }
  nodeaddr = dn_htons((area << 10) | addr);
  memcpy(sockaddr.sdn_nodeaddr, &nodeaddr, sizeof(nodeaddr));
}

static void test_accept(
  struct optdata_dn *optdata
)
{
  if (connect(sock, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == 0) {
    struct optdata_dn accdata;
    socklen_t acclen = sizeof(accdata);
    void *checkdata = std_optdata;
    size_t checklen = sizeof(std_optdata);

    if ((getsockopt(sock, DNPROTO_NSP, DSO_CONDATA, &accdata, &acclen) < 0) ||
        (acclen != sizeof(accdata))) {
      perror("getsockopt(DSO_CONDATA)");
      exit(1);
    }

    switch (ovalue) {
      case DTS_CONNDIS_NONE:
        break;

      case DTS_CONNDIS_RCVD:
        checkdata = optdata->opt_data;
        checklen = optdata->opt_optl;
        /* FALLTHROUGH */

      case DTS_CONNDIS_STD:
        if ((accdata.opt_optl != checklen) ||
            (memcmp(accdata.opt_data, checkdata, checklen) != 0)) 
          fprintf(stderr, "Accept: Returned optional data mismatch\n");
        break;
    }
    close(sock);
    return;
  }

  switch (errno) {
    case EINPROGRESS:
      fprintf(stderr, "Accept: Connection timed out\n");
      close(sock);
      break;

    case ECONNREFUSED:
      fprintf(stderr, "Accept: Remote system rejected connection request\n");
      break;

    default:
      perror("Accept: Connect");
      break;
  }
}

static void test_reject(
  struct optdata_dn *optdata
)
{
  if (connect(sock, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) != 0) {
    struct optdata_dn rejdata;
    socklen_t rejlen = sizeof(rejdata);
    void *checkdata = std_optdata;
    size_t checklen = sizeof(std_optdata);

    switch (errno) {
      case ECONNREFUSED:
        break;

      case EINPROGRESS:
        fprintf(stderr, "Accept: Connection timed out\n");
        close(sock);
        return;

      default:
        perror("Reject: Connect");
        return;
    }

    if ((getsockopt(sock, DNPROTO_NSP, DSO_DISDATA, &rejdata, &rejlen) < 0) ||
        (rejlen != sizeof(rejdata))) {
      perror("getsockopt(DSO_DISDATA)");
      exit(1);
    }

    switch (ovalue) {
      case DTS_CONNDIS_NONE:
        break;

      case DTS_CONNDIS_RCVD:
        checkdata = optdata->opt_data;
        checklen = optdata->opt_optl;
        /* FALLTHROUGH */

      case DTS_CONNDIS_STD:
        if ((rejdata.opt_optl != checklen) ||
            (memcmp(rejdata.opt_data, checkdata, checklen) != 0)) 
          fprintf(stderr, "Reject: Returned optional data mismatch\n");
        break;
    }
    return;
  }

  fprintf(stderr, "Reject: Remote system accepted connection request\n");
  close(sock);
}

static void test_disc(
  struct optdata_dn *optdata
)
{
  if (connect(sock, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == 0) {
    char dummy;
    ssize_t status;

    /*
     * Issue a read request to wait for the expected disconnect.
     */
    if ((status = read(sock, &dummy, sizeof(dummy))) == 0) {
      struct optdata_dn disdata;
      socklen_t dislen = sizeof(disdata);
      void *checkdata = std_optdata;
      size_t checklen = sizeof(std_optdata);

      if ((getsockopt(sock, DNPROTO_NSP, DSO_DISDATA, &disdata, &dislen) < 0) ||
          (dislen != sizeof(disdata))) {
        perror("getsockopt(DSO_DISDATA)");
        close(sock);
        exit(1);
      }

      if (disdata.opt_status != 0) {
        fprintf(stderr, "Unexpected disconnect status - %d\n",
                disdata.opt_status);
        close(sock);
        return;
      }

      switch (ovalue) {
        case DTS_CONNDIS_NONE:
          break;

        case DTS_CONNDIS_RCVD:
          checkdata = optdata->opt_data;
          checklen = optdata->opt_optl;
          /* FALLTHROUGH */

        case DTS_CONNDIS_STD:
          if ((disdata.opt_optl != checklen) ||
              (memcmp(disdata.opt_data, checkdata, checklen) != 0)) 
            fprintf(stderr, "Disc: Returned optional data mismatch\n");
          break;
      }
      close(sock);
      return;
    }

    if (errno == EWOULDBLOCK)
      fprintf(stderr, "Disc: timeout waiting for disconnect\n");
    else perror("Disc: read");
    close(sock);
    return;
  }

  switch (errno) {
    case EINPROGRESS:
      fprintf(stderr, "Disc: Connection timed out\n");
      close(sock);
      break;

    case ECONNREFUSED:
      fprintf(stderr, "Disc: Remote system rejected connection request\n");
      break;

    default:
      perror("Disc: Connect");
      break;
  }
}

static void test_abort(
  struct optdata_dn *optdata
)
{
  if (connect(sock, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == 0) {
    char dummy;
    ssize_t status;

    /*
     * Issue a read request to wait for the expected abort.
     */
    if ((status = read(sock, &dummy, sizeof(dummy))) == 0) {
      struct optdata_dn abodata;
      socklen_t abolen = sizeof(abodata);
      void *checkdata = std_optdata;
      size_t checklen = sizeof(std_optdata);

      if ((getsockopt(sock, DNPROTO_NSP, DSO_DISDATA, &abodata, &abolen) < 0) ||
          (abolen != sizeof(abodata))) {
        perror("getsockopt(DSO_DISDATA)");
        close(sock);
        exit(1);
      }

      if (abodata.opt_status != DNSTAT_ABORTOBJECT) {
        fprintf(stderr, "Unexpected abort status - %d\n",
                abodata.opt_status);
        close(sock);
        return;
      }

      switch (ovalue) {
        case DTS_CONNDIS_NONE:
          break;

        case DTS_CONNDIS_RCVD:
          checkdata = optdata->opt_data;
          checklen = optdata->opt_optl;
          /* FALLTHROUGH */

        case DTS_CONNDIS_STD:
          if ((abodata.opt_optl != checklen) ||
              (memcmp(abodata.opt_data, checkdata, checklen) != 0)) 
            fprintf(stderr, "Abort: Returned optional data mismatch\n");
          break;
      }
      close(sock);
      return;
    }

    if (errno == EWOULDBLOCK)
      fprintf(stderr, "Abort: timeout waiting for abort\n");
    else perror("Abort: read");
    close(sock);
    return;
  }

  switch (errno) {
    case EINPROGRESS:
      fprintf(stderr, "Abort: Connection timed out\n");
      close(sock);
      break;

    case ECONNREFUSED:
      fprintf(stderr, "Abort: Remote system rejected connection request\n");
      break;

    default:
      perror("Abort: Connect");
      break;
  }
}

static void test_interrupt(
  struct optdata_dn *optdata
)
{
  if (connect(sock, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == 0) {
    struct timeval timeout = { 0, 0 };
    struct timeval starttime, currenttime;
    long long elapsed, testtime = tvalue * 1000000;
    unsigned long long msgsent = 0, bytesent = 0, msgrcvd = 0;
    uint32_t seqno = 1;
    char buf[DTS_INT_MAXSIZE];

    /*
     * Reset timeouts since we will be using synchronous reads/writes
     */
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
      perror("setsockopt(SO_RCVTIMEO)");
      exit(1);
    }

    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
      perror("setsockopt(SO_SNDTIMEO)");
      exit(1);
    }

    /*
     * Construct the buffer we will be sending.
     */
    switch (rvalue) {
      case DTS_DATAINT_SINK:
        memcpy(buf, DTS_PATTERN, sizeof(buf));
        break;

      case DTS_DATAINT_SEQ:
      case DTS_DATAINT_PAT:
      case DTS_DATAINT_ECHO:
        *((uint32_t *)buf) = seqno;
        memcpy(&buf[sizeof(uint32_t)], DTS_PATTERN, sizeof(buf) - sizeof(uint32_t));
        break;
    }

    gettimeofday(&starttime, NULL);

    do {
      int status;
      ssize_t rlen;
      char rbuf[DTS_INT_MAXSIZE];

      if (send(sock, buf, lvalue, MSG_OOB) != lvalue)
        break;

      msgsent++;
      bytesent += lvalue;

      if (rvalue == DTS_DATAINT_ECHO) {
        if ((rlen = recv(sock, rbuf, sizeof(rbuf), MSG_OOB)) == -1)
          break;

        if (rlen != lvalue) {
          fprintf(stderr, "Interrupt: echo response has incorrect length\n");
          break;
        }

        if (memcmp(rbuf, buf, lvalue) != 0) {
          fprintf(stderr, "Interrupt: echo response incorrect data\n");
          break;
        }
        msgrcvd++;
      }

      if (rvalue != DTS_DATAINT_SINK)
        *((uint32_t *)buf) = ++seqno;

      if (cvalue)
        if (msgsent >= cvalue)
          break;

      gettimeofday(&currenttime, NULL);
      elapsed = ((currenttime.tv_sec - starttime.tv_sec) * 1000000) +
        (currenttime.tv_usec - starttime.tv_usec);
    } while (elapsed < testtime);

    if (sswitch && !cvalue) {
      float msgpersec = msgsent / tvalue;

      printf("Total messages XMIT   %10llu  RECV %10llu\n", msgsent, msgrcvd);
      printf("Total bytes XMIT %15llu\n", bytesent);
      printf("Messages per second %12.2f\n", msgpersec);
      printf("Bytes per second %15llu\n", bytesent / tvalue);
    }

    close(sock);
    return;
  }

  switch (errno) {
    case EINPROGRESS:
      fprintf(stderr, "Interrupt: Connection timed out\n");
      close(sock);
      break;

    case ECONNREFUSED:
      fprintf(stderr, "Interrupt: Remote system rejected connection request\n");
      break;

    default:
      perror("Interrupt: Connect");
      break;
  }
}

static void test_data(
  struct optdata_dn *optdata
)
{
  if (connect(sock, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == 0) {
    struct timeval timeout = { 0, 0 };
    struct timeval starttime, currenttime;
    long long elapsed, testtime = tvalue * 1000000;
    unsigned long long msgsent = 0, bytesent = 0, msgrcvd = 0;
    uint32_t seqno = 1;
    char buf[DTS_DATA_MAXSIZE];
    char *ptr = buf;
    int remain = lvalue;

    /*
     * Reset timeouts since we will be using synchronous reads/writes
     */
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
      perror("setsockopt(SO_RCVTIMEO)");
      exit(1);
    }

    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
      perror("setsockopt(SO_SNDTIMEO)");
      exit(1);
    }

    /*
     * Construct the buffer we will be sending.
     */
    if (rvalue != DTS_DATAINT_SINK) {
      *((uint32_t *)ptr) = seqno;
      ptr += sizeof(uint32_t);
      remain -= sizeof(uint32_t);
    }

    while (remain) {
      size_t len = remain > strlen(DTS_PATTERN) ? strlen(DTS_PATTERN) : remain;

      memcpy(ptr, DTS_PATTERN, len);
      ptr += len;
      remain -= len;
    }

    gettimeofday(&starttime, NULL);

    do {
      int status;
      ssize_t rlen;
      char rbuf[DTS_DATA_MAXSIZE];

      if (send(sock, buf, lvalue, MSG_EOR) != lvalue)
        break;

      msgsent++;
      bytesent += lvalue;

      if (rvalue == DTS_DATAINT_ECHO) {
        if ((rlen = recv(sock, rbuf, sizeof(rbuf), 0)) == -1)
          break;

        if (rlen != lvalue) {
          fprintf(stderr, "Data: echo response has incorrect length\n");
          break;
        }

        if (memcmp(rbuf, buf, lvalue) != 0) {
          fprintf(stderr, "Data: echo response incorrect data\n");
          break;
        }
        msgrcvd++;
      }

      if (rvalue != DTS_DATAINT_SINK)
        *((uint32_t *)buf) = ++seqno;

      if (cvalue)
        if (msgsent >= cvalue)
          break;

      gettimeofday(&currenttime, NULL);
      elapsed = ((currenttime.tv_sec - starttime.tv_sec) * 1000000) +
        (currenttime.tv_usec - starttime.tv_usec);
    } while (elapsed < testtime);

    if (sswitch && !cvalue) {
      float msgpersec = msgsent / tvalue;

      printf("Total messages XMIT   %10llu  RECV %10llu\n", msgsent, msgrcvd);
      printf("Total bytes XMIT %15llu\n", bytesent);
      printf("Messages per second %12.2f\n", msgpersec);
      printf("Bytes per second %15llu\n", bytesent / tvalue);
    }

    close(sock);
    return;
  }

  switch (errno) {
    case EINPROGRESS:
      fprintf(stderr, "Data: Connection timed out\n");
      close(sock);
      break;

    case ECONNREFUSED:
      fprintf(stderr, "Data: Remote system rejected connection request\n");
      break;

    default:
      perror("Data: Connect");
      break;
  }
}

void run_test(int cmd)
{
  struct optdata_dn optdata;
  struct timeval timeout = { 10, 0 };

  if ((sock = socket(AF_DECnet, SOCK_SEQPACKET, DNPROTO_NSP)) != -1) {
    /*
     * Build the test request block
     */
    switch (cmd) {
      case CMD_ACCEPT:
      case CMD_REJECT:
        optdata.opt_data[0] = DTS_TEST_CONNECT;
        optdata.opt_data[1] =
          cmd == CMD_ACCEPT ? DTS_SUBTEST_ACC : DTS_SUBTEST_REJ;
        optdata.opt_data[1] |= ovalue;
        if (ovalue != DTS_CONNDIS_NONE) {
          memcpy(&optdata.opt_data[2], std_optdata, 14);
          optdata.opt_optl = 16;
        } else optdata.opt_optl = 2;
        break;

      case CMD_DISC:
      case CMD_ABORT:
        optdata.opt_data[0] = DTS_TEST_DISCONNECT;
        optdata.opt_data[1] =
          cmd == CMD_DISC ? DTS_SUBTEST_DSC : DTS_SUBTEST_ABT;
        optdata.opt_data[1] |= ovalue;
        if (ovalue != DTS_CONNDIS_NONE) {
          memcpy(&optdata.opt_data[2], std_optdata, 14);
          optdata.opt_optl = 16;
        } else optdata.opt_optl = 2;
        break;

      case CMD_DATA:
        optdata.opt_data[0] = DTS_TEST_DATA;
        optdata.opt_data[1] = rvalue;
        optdata.opt_data[2] = fvalue;
        optdata.opt_data[3] = vvalue;
        optdata.opt_data[4] = optdata.opt_data[5] = 0;
        optdata.opt_data[6] = lvalue & 0xFF;
        optdata.opt_data[7] = (lvalue >> 8) & 0xFF;
        optdata.opt_optl = 8;
        break;

      case CMD_INTERRUPT:
        optdata.opt_data[0] = DTS_TEST_INTERRUPT;
        optdata.opt_data[1] = rvalue;
        optdata.opt_data[2] = 1;
        optdata.opt_data[3] = lvalue;
        optdata.opt_data[4] = 0;
        optdata.opt_optl = 5;
        break;
    }

    /*
     * Set up access control information and the control block as connect
     * optional data.
     */
    if (setsockopt(sock, DNPROTO_NSP, DSO_CONACCESS, &accessdata, sizeof(accessdata)) < 0) {
      perror("setsockopt(DSO_CONACCESS)");
      exit(1);
    }

    if (setsockopt(sock, DNPROTO_NSP, DSO_CONDATA, &optdata, sizeof(optdata)) < 0) {
      perror("setsockopt(DSO_CONDATA)");
      exit(1);
    }

    /*
     * Set timeouts for connect/transmit/receive so that we don't have to
     * wait too long for failures.
     */
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
      perror("setsockopt(SO_RCVTIMEO)");
      exit(1);
    }

    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
      perror("setsockopt(SO_SNDTIMEO)");
      exit(1);
    }

    /*
     * Initiate the test.
     */
    switch (cmd) {
      case CMD_ACCEPT:
        test_accept(&optdata);
        break;

      case CMD_REJECT:
        test_reject(&optdata);
        break;

      case CMD_DISC:
        test_disc(&optdata);
        break;

      case CMD_ABORT:
        test_abort(&optdata);
        break;

      case CMD_DATA:
        test_data(&optdata);
        break;

      case CMD_INTERRUPT:
        test_interrupt(&optdata);
        break;
    }
    return;
  } else perror("socket() failed");
  exit(1);
}
