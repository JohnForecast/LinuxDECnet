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
#include <sys/types.h>
#include <sys/socket.h>
#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>

/*
* The requested test is passed in the connect optional data:
*
* Byte 0:              Test #
*                      Bit 7 requests DTR to display statistics
* Byte 1:              Subtest/flags
* Byte 2:              Flow control type (Data/Interrupt tests)
* Byte 2:              Interrupt flow control value (always 1)
* Byte 3:              Flow control value (Data test)
* Byte 3:              Message length (Interrupt test)
* Byte 4,5:            Unknown
* Byte 6,7:            Message length (Data test)
*/
#define DTS_TEST_MASK		0x7F	/* Mask for test type */

#define DTS_TEST_CONNECT        0x00    /* Connect test */
#define DTS_TEST_DATA           0x01    /* Data transfer test */
#define DTS_TEST_DISCONNECT     0x02    /* Disconnect test */
#define DTS_TEST_INTERRUPT      0x03    /* Interrupt transfer test */

#define DTS_TEST_PRINT		0x80	/* Request DTR display statistics */

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

/*
* Note that RSX sends a short request block for interrupt tests (3 bytes)
* so in this case we need to handle whatever interrupt message the client
* sends us.
*/

void perform_test(int, unsigned short, unsigned char *);
int check_pattern(char *, int);
void wait_for_disconnect(int);
void dnet_abort(int);

int verbosity = 0;

void usage(
char *prog,
FILE *f
)
{
fprintf(f, "\n%s options:\n", prog);
fprintf(f, " -v        Verbose messages\n");
fprintf(f, " -h        Display this message\n");
fprintf(f, " -d        Show debug logging\n");
  fprintf(f, " -V        Show version number\n\n");
}

int main(
  int argc,
  char **argv
)
{
  int debug = 0;
  int sock;
  char opt;

  while ((opt = getopt(argc, argv, "?vVdh")) != EOF) {
    switch (opt) {
    case '?':
    case 'h':
      usage(argv[0], stdout);
      exit(0);

    case 'v':
      verbosity++;
      break;

    case 'd':
      debug++;
      break;

    case 'V':
      printf("\ndtr from dnprogs version %s\n\n", VERSION);
      exit(1);
    }
  }

  init_daemon_logging("dtr", debug ? 'e' : 's');

  sock = dnet_daemon(DNOBJECT_DTR, NULL, verbosity, !debug);

  if (sock > -1) {
    struct optdata_dn optdata;
    socklen_t optlen = sizeof(optdata);

    memset(&optdata, 0, sizeof(optdata));

    if (getsockopt(sock, DNPROTO_NSP, DSO_CONDATA, &optdata, &optlen) == 0) {
      /*
       * DTS sends its requests via optional connect data - must be at least
       * 2 bytes present.
       */
      if (optdata.opt_optl >= 2)
        perform_test(sock, optdata.opt_optl, optdata.opt_data);
    }
  }
  return 0;
}

void perform_test(
  int sock,
  unsigned short len,
  unsigned char *req
)
{
  struct optdata_dn optdata;
  size_t datalen;
  char buf[DTS_DATA_MAXSIZE];
  ssize_t readlen;
  int flags = MSG_OOB;
  unsigned short maxsize = DTS_INT_MAXSIZE;
  int bufsize = 131072;
  uint32_t seq = 1;
  int anylen = 0;
  int prdata = (req[0] & DTS_TEST_PRINT) != 0 ? 1 : 00;

  memset(&optdata, 0, sizeof(optdata));

  req[0] &= DTS_TEST_MASK;

  switch (req[0]) {
    case DTS_TEST_DISCONNECT:
      if ((req[1] & DTS_SUBTEST_MASK) == DTS_SUBTEST_ABT)
        optdata.opt_status = DNSTAT_ABORTOBJECT;
      /* FALLTHROUGH */

    case DTS_TEST_CONNECT:
      switch (req[1] & ~DTS_SUBTEST_MASK) {
        case DTS_CONNDIS_NONE:
          break;

        case DTS_CONNDIS_STD:
          optdata.opt_optl = sizeof(optdata.opt_data);
          memcpy(optdata.opt_data, std_optdata, sizeof(optdata.opt_data));
          break;

        case DTS_CONNDIS_RCVD:
          optdata.opt_optl = len;
          memcpy(optdata.opt_data, req, len);
          break;

        default:
          dnetlog(LOG_INFO, "Bad return data type for connect test\n");
          dnet_reject(sock, DNSTAT_REJECTED, NULL, 0);
          return;
      }
      setsockopt(sock, DNPROTO_NSP,
                 req[0] == DTS_TEST_CONNECT ? DSO_CONDATA : DSO_DISDATA,
                 &optdata, sizeof(optdata));

      switch (req[0]) {
        case DTS_TEST_CONNECT:
          switch (req[1] & DTS_SUBTEST_MASK) {
            case DTS_SUBTEST_REJ:
              dnet_reject(sock, 0, (char *)optdata.opt_data, optdata.opt_optl);
              break;

            case DTS_SUBTEST_ACC:
              dnet_accept(sock, 0, (char *)optdata.opt_data, optdata.opt_optl);
              wait_for_disconnect(sock);
              break;
          }
          break;

        case DTS_TEST_DISCONNECT:
          dnet_accept(sock, 0, NULL, 0);

          /*
           * Perform the appropriate disconnect when we close the socket
           * below.
           */
          break;
      }
      break;

    case DTS_TEST_DATA:
      flags = 0;
      maxsize = DTS_DATA_MAXSIZE;

      /*
       * Set up sufficient socket buffering to handle worst case.
       */
      setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
      setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

      /*
       * For the data test, we require a minimum of 8 bytes of control data.
       */
      if (len < 8) {
        dnetlog(LOG_INFO, "Insufficient control data for data test\n");
        dnet_reject(sock, DNSTAT_REJECTED, NULL, 0);
        return;
      }

      datalen = (req[7] << 8) | req[6];
      goto dataint_common;

    case DTS_TEST_INTERRUPT:
      /*
       * For the interrupt test, we require a minimum of 5 bytes of control
       * data. However, RSX only sends 3 bytes and does not include the
       * buffer size so we have to accept any length in this case.
       */
      if (len < 5) {
        if (len != 3) {
          dnetlog(LOG_INFO, "Insufficient control data for interrupt test\n");
          dnet_reject(sock, DNSTAT_REJECTED, NULL, 0);
          return;
        }
        datalen = 16;
        anylen = 1;
      } else datalen = (req[4] << 8) | req[3];

  dataint_common:
      switch (req[1]) {
        case DTS_DATAINT_SINK:
        case DTS_DATAINT_SEQ:
        case DTS_DATAINT_PAT:
        case DTS_DATAINT_ECHO:
          break;

        default:
          dnetlog(LOG_INFO, "Bad subtest type for data/interrupt test\n");
          dnet_reject(sock, DNSTAT_REJECTED, NULL, 0);
          return;
      }

      /*
       * Check for valid parameters
       */
      switch (req[1]) {
        case DTS_DATAINT_SINK:
        case DTS_DATAINT_ECHO:
          if ((datalen == 0) || (datalen > maxsize)) {
            dnetlog(LOG_INFO, "Bad message length for sink/echo test\n");
            dnet_reject(sock, DNSTAT_REJECTED, NULL, 0);
            return;
          }
          break;

        case DTS_DATAINT_SEQ:
          if ((datalen < 4) || (datalen > maxsize)) {
            dnetlog(LOG_INFO, "Bad message length for sequence test\n");
            dnet_reject(sock, DNSTAT_REJECTED, NULL, 0);
            return;
          }
          break;

        case DTS_DATAINT_PAT:
          if ((datalen < 5) || (datalen > maxsize)) {
            dnetlog(LOG_INFO, "Bad message length for pattern test\n");
            dnet_reject(sock, DNSTAT_REJECTED, NULL, 0);
            return;
          }
          break;
      }

      /*
       * Perform the actual data/interrupt test.
       */
      switch (req[1]) {
        case DTS_DATAINT_SINK:
          while ((readlen = recv(sock, buf, datalen, flags)) != 0) {
            int invalidlen = anylen ? 0 : (readlen != datalen);

            if (invalidlen) {
              dnetlog(LOG_INFO, "Sink test - short message received\n");
              dnet_abort(sock);
              return;
            }
          }
          wait_for_disconnect(sock);
          break;

        case DTS_DATAINT_SEQ:
          while ((readlen = recv(sock, buf, datalen, flags)) != 0) {
            int invalidlen = anylen ? (readlen < 4) : (readlen != datalen);
            uint32_t msgseq = *(uint32_t *)buf;
            
            if (invalidlen || (msgseq != seq)) {
              if (readlen != datalen)
                dnetlog(LOG_INFO,
                        "Sequence test - short message received\n");
              else dnetlog(LOG_INFO,
                           "Sequence test - bad sequence #\n");
              dnet_abort(sock);
              return;
            }
            seq++;
          }
          wait_for_disconnect(sock);
          break;

        case DTS_DATAINT_PAT:
          while ((readlen = recv(sock, buf, datalen, flags)) != 0) {
            int invalidlen = anylen ? (readlen < 5) : (readlen != datalen);
            uint32_t msgseq = *(uint32_t *)buf;

            if (invalidlen || (msgseq != seq) ||
                !check_pattern(&buf[4], readlen - sizeof(uint32_t))) {
              if (readlen != datalen)
                dnetlog(LOG_INFO,
                        "Pattern test - short message received\n");
              else if (msgseq != seq)
                dnetlog(LOG_INFO,
                        "Pattern test - bad sequence #\n");
              else dnetlog(LOG_INFO,
                           "Pattern test - pattern mismatch\n");
              dnet_abort(sock);
              return;
            }
            seq++;
          }
          wait_for_disconnect(sock);
          break;

        case DTS_DATAINT_ECHO:
          while ((readlen = recv(sock, buf, datalen, flags)) != 0) {
            int invalidlen = anylen ? 0 : (readlen != datalen);

            if (invalidlen) {
              dnetlog(LOG_INFO, "Echo test - short message received\n");
              dnet_abort(sock);
              return;
            }

            if (send(sock, buf, readlen, flags | MSG_EOR) == -1) {
              dnetlog(LOG_INFO, "Echo test - send failed\n");
              dnet_abort(sock);
              return;
            }
          }
          wait_for_disconnect(sock);
          break;
      }
      break;

    default:
      dnetlog(LOG_INFO, "Invalid test code\n");
      dnet_reject(sock, DNSTAT_REJECTED, NULL, 0);
      return;
  }
  close(sock);
}

int check_pattern(
  char *buf,
  int len
)
{
  int patlen = strlen(DTS_PATTERN);

  while (len >= patlen) {
    if (memcmp(buf, DTS_PATTERN, patlen) != 0)
      return 0;
    len -= patlen;
    buf += patlen;
  }

  if (len) {
    if (memcmp(buf, DTS_PATTERN, len) != 0)
      return 0;
  }
  return 1;
}

void wait_for_disconnect(int sock)
{
  int i;

  /*
   * Wait for the link to be remotely disconnected. Give up waiting after
   * 5 seconds.
   */
  for (i = 0; i < 5; i++) {
    struct linkinfo_dn info;
    socklen_t len = sizeof(info);

    if ((getsockopt(sock, DNPROTO_NSP, DSO_LINKINFO, &info, &len) == -1) ||
        (len != sizeof(info)) ||
        (info.idn_linkstate != LL_RUNNING))
      break;

    sleep(1);
  }
}

void dnet_abort(int sock)
{
  struct optdata_dn optdata;

  memset(&optdata, 0, sizeof(optdata));

  optdata.opt_sts = DNSTAT_ABORTOBJECT;
  close(sock);
}
