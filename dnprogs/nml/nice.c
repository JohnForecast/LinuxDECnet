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
#include <string.h>
#include <syslog.h>
#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>
#include "nice.h"

extern int verbosity;

/*
 * All access to the outbound NICE response buffer MUST go through these
 * routines.
 */
static unsigned char outbuf[300], inbuf[300];
static int outptr, inptr, entptr;
static ssize_t inlen;
static int sock;

/*
 * Initial use of the outbound buffer for a new connection.
 */
void NICEinit(
  int insock
)
{
  sock = insock;
  outptr = 0;
}

/*
 * Flush any data in the outbound buffer
 */
void NICEflush(void)
{
  if (outptr) {
    if (verbosity > 1) {
      int i;
      char buf[2048];

      dnetlog(LOG_DEBUG, "Sent NICE Response message %d bytes:\n", outptr);

      buf[0] = '\0';

      for (i = 0; i < outptr; i++)
        sprintf(&buf[strlen(buf)], "0x%02x ", outbuf[i]);
      
      dnetlog(LOG_DEBUG, "%s\n", buf);
    }
    write(sock, outbuf, outptr);
  }
  outptr = 0;
}

/*
 * Flush any data in the outbound buffer, converting the current message to
 * a "Partial" response.
 */
void NICEflushPartial(void)
{
  if (outptr) {
    uint8_t save = outbuf[0];

    outbuf[0] = NICE_RET_PARTIAL;

    if (verbosity > 1) {
      int i;
      char buf[2048];

      dnetlog(LOG_DEBUG, "Sent NICE Response message %d bytes:\n", outptr);

      buf[0] = '\0';

      for (i = 0; i < outptr; i++)
        sprintf(&buf[strlen(buf)], "0x%02x ", outbuf[i]);
      
      dnetlog(LOG_DEBUG, "%s\n", buf);
    }
    write(sock, outbuf, outptr);

    outbuf[0] = save;
    outptr = entptr;
  }
}

/*
 * Write parameter + data to outbound buffer
 */
void NICEparamDU1(
  uint16_t param,
  uint8_t value
)
{
  outbuf[outptr++] = param & 0xFF;
  outbuf[outptr++] = (param >> 8) & 0xFF;
  outbuf[outptr++] = NICE_TYPE_DU1;
  outbuf[outptr++] = value;
}

void NICEparamDU2(
  uint16_t param,
  uint16_t value
)
{
  outbuf[outptr++] = param & 0xFF;
  outbuf[outptr++] = (param >> 8) & 0xFF;
  outbuf[outptr++] = NICE_TYPE_DU2;
  outbuf[outptr++] = value & 0xFF;
  outbuf[outptr++] = (value >> 8) & 0xFF;
}

void NICEparamAIn(
  uint16_t param,
  char *value
)
{
  size_t len = strlen(value);

  outbuf[outptr++] = param & 0xFF;
  outbuf[outptr++] = (param >> 8) & 0xFF;
  outbuf[outptr++] = NICE_TYPE_AI;
  outbuf[outptr++] = len;
  strcpy((char *)&outbuf[outptr], value);
  outptr += len;
}

void NICEparamHIn(
  uint16_t param,
  char len,
  char *value
)
{
  outbuf[outptr++] = param & 0xFF;
  outbuf[outptr++] = (param >> 8) & 0xFF;
  outbuf[outptr++] = NICE_TYPE_HI;
  outbuf[outptr++] = len;
  memcpy((char *)&outbuf[outptr], value, len);
  outptr += len;
}

void NICEparamC1(
  uint16_t param,
  uint8_t value
)
{
  outbuf[outptr++] = param & 0xFF;
  outbuf[outptr++] = (param >> 8) & 0xFF;
  outbuf[outptr++] = NICE_TYPE_C1;
  outbuf[outptr++] = value;
}

void NICEparamCMn(
  uint16_t param,
  uint8_t len
)
{
  outbuf[outptr++] = param & 0xFF;
  outbuf[outptr++] = (param >> 8) & 0xFF;
  outbuf[outptr++] = NICE_TYPE_CM(len);
}

/*
 * Write node address optionally followed by a node name so that entire
 * parameter is encoded as CM-1/2
 */
void NICEparamNodeID(
  uint16_t param,
  uint16_t nodeaddress,
  char *nodename
)
{
  size_t len = nodename ? strlen(nodename) : 0;
  int i;

  outbuf[outptr++] = param & 0xFF;
  outbuf[outptr++] = (param >> 8) & 0xFF;
  outbuf[outptr++] = NICE_TYPE_CM((len != 0) ? 2 : 1);
  outbuf[outptr++] = NICE_TYPE_DU2;
  outbuf[outptr++] = nodeaddress & 0xFF;
  outbuf[outptr++] = (nodeaddress >> 8) & 0xFF;

  if (len) {
    outbuf[outptr++] = NICE_TYPE_AI;
    outbuf[outptr++] = len;
    for (i = 0; i < len; i++)
      outbuf[outptr++] = toupper(nodename[i]);
  }
}

/*
 * Write counter code, optionally followed by a bitmap, then followed by the
 * counter value.
 */
void NICEcounter8(
  uint16_t counter,
  uint8_t value
)
{
  counter = NICE_CTR_8(counter);

  outbuf[outptr++] = counter & 0xFF;
  outbuf[outptr++] = (counter >> 8) &0xFF;
  outbuf[outptr++] = value;
}

void NICEcounter16(
  uint16_t counter,
  uint16_t value
)
{
  counter = NICE_CTR_16(counter);

  outbuf[outptr++] = counter & 0xFF;
  outbuf[outptr++] = (counter >> 8) &0xFF;
  outbuf[outptr++] = value & 0xFF;
  outbuf[outptr++] = (value >> 8) & 0xFF;
}

void NICEcounter32(
  uint16_t counter,
  uint32_t value
)
{
  counter = NICE_CTR_32(counter);

  outbuf[outptr++] = counter & 0xFF;
  outbuf[outptr++] = (counter >> 8) &0xFF;
  outbuf[outptr++] = value & 0xFF;
  outbuf[outptr++] = (value >> 8) & 0xFF;
  outbuf[outptr++] = (value >> 16) & 0xFF;
  outbuf[outptr++] = (value >> 24) & 0xFF;
}

void NICEcounter8BM(
  uint16_t counter,
  uint16_t map,
  uint8_t value
)
{
  counter = NICE_CTR_8_BM(counter);

  outbuf[outptr++] = counter & 0xFF;
  outbuf[outptr++] = (counter >> 8) & 0xFF;
  outbuf[outptr++] = map & 0xFF;
  outbuf[outptr++] = (map >> 8) & 0xFF;
  outbuf[outptr++] = value;
}

void NICEcounter16BM(
  uint16_t counter,
  uint16_t map,
  uint16_t value
)
{
  counter = NICE_CTR_16_BM(counter);

  outbuf[outptr++] = counter & 0xFF;
  outbuf[outptr++] = (counter >> 8) & 0xFF;
  outbuf[outptr++] = map & 0xFF;
  outbuf[outptr++] = (map >> 8) & 0xFF;
  outbuf[outptr++] = value;
  outbuf[outptr++] = (value >> 8) & 0xFF;
}

void NICEcounter32BM(
  uint16_t counter,
  uint16_t map,
  uint32_t value
)
{
  counter = NICE_CTR_32_BM(counter);

  outbuf[outptr++] = counter & 0xFF;
  outbuf[outptr++] = (counter >> 8) & 0xFF;
  outbuf[outptr++] = map & 0xFF;
  outbuf[outptr++] = (map >> 8) & 0xFF;
  outbuf[outptr++] = value;
  outbuf[outptr++] = (value >> 8) & 0xFF;
  outbuf[outptr++] = (value >> 16) & 0xFF;
  outbuf[outptr++] = (value >> 24) & 0xFF;
}

/*
 * Write node address followed by a node name and flag an executor node by
 * setting bit 7 of the name length
 */
void NICEnodeEntity(
  uint16_t nodeaddress,
  char *nodename,
  int exec
)
{
  size_t len = nodename ? strlen(nodename) : 0;
  int i;

  outbuf[outptr++] = nodeaddress & 0xFF;
  outbuf[outptr++] = (nodeaddress >> 8) & 0xFF;

  outbuf[outptr++] = len | (exec ? 0x80 : 0);
  if (len) {
    for (i = 0; i < len; i++)
      outbuf[outptr++] = toupper(nodename[i]);
  }

  entptr = outptr;
}

/*
 * Write a circuit name as an Ascii Image field
 */
void NICEcircuitEntity(
  char *circuit
)
{
  outbuf[outptr++] = strlen(circuit);
  memcpy((char *)&outbuf[outptr], circuit, strlen(circuit));
  outptr += strlen(circuit);

  entptr = outptr;
}

/*
 * Write an area number
 */
void NICEareaEntity(
  uint8_t area
)
{
  outbuf[outptr++] = NICE_AFMT_ADDRESS;
  outbuf[outptr++] = area;

  entptr = outptr;
}

/*
 * Write an value without a preceeding parameter. These are used in building
 * coded multiple values.
 */
void NICEvalueDU1(
  uint8_t value
)
{
  outbuf[outptr++] = NICE_TYPE_DU1;
  outbuf[outptr++] = value;
}

void NICEvalueDU2(
  uint16_t value
)
{
  outbuf[outptr++] = NICE_TYPE_DU2;
  outbuf[outptr++] = value & 0xFF;
  outbuf[outptr++] = (value >> 8) & 0xFF;
}

/*
 * Generate an "Invalid Message Format" error response
 */
void NICEformatResponse(void)
{
  uint8_t imf[3] = { NICE_RET_INVALID, 0, 0 };

  write(sock, imf, sizeof(imf));
}

/*
 * Generate an "Unrecognized function or option" error response
 */
void NICEunsupportedResponse(void)
{
  uint8_t unsupp[3] = { NICE_RET_UNRECOG, 0, 0 };

  write(sock, unsupp, sizeof(unsupp));
}

/*
 * Generate a "Parameter too long" error response
 */
void NICEtoolongResponse(void)
{
  uint8_t toolong[3] = { NICE_RET_TOOLONG, 0, 0 };

  write(sock, toolong, sizeof(toolong));
}

/*
 * Generate an "Unrecognized component" error response
 */
void NICEunrecognizedComponentResponse(
  uint8_t component
)
{
  uint8_t unrecog[3] = { NICE_RET_BADCOMPONENT, 0, 0 };

  unrecog[1] = component;
  write(sock, unrecog, sizeof(unrecog));
}

/*
 * Generate an "Unrecognized parameter type" error response
 */
void NICEunrecognizedParameterTypeResponse(
  uint16_t param
)
{
  uint8_t unrecog[3] = { NICE_RET_BADPARAM, 0, 0 };

  unrecog[1] = param & 0xFF;
  unrecog[2] = (param >> 8) & 0xFF;
  write(sock, unrecog, sizeof(unrecog));
}

/*
 * Generate an "Invalid parameter value" error response
 */
void NICEinvalidParameterValueResponse(
  uint16_t param
)
{
  uint8_t invalid[3] = { NICE_RET_BADVALUE, 0, 0 };

  invalid[1] = param & 0xFF;
  invalid[2] = (param >> 8) & 0xFF;
  write(sock, invalid, sizeof(invalid));
}

/*
 * Generate a "Mirror link disconnected" error response
 */
void NICEmirrorLinkDisconnectedResponse(
  uint16_t detail
)
{
  uint8_t mirdisc[3] = { NICE_RET_DISCONNECT, 0, 0 };

  mirdisc[1] = detail & 0xFF;
  mirdisc[2] = (detail >> 8) & 0xFF;
  write(sock, mirdisc, sizeof(mirdisc));
}

/*
 * Generate a "Mirror connect failed" error response
 */
void NICEmirrorConnectFailedResponse(
  uint16_t detail
)
{
  uint8_t mirconn[3] = { NICE_RET_CONNECTERR, 0, 0 };

  mirconn[1] = detail & 0xFF;
  mirconn[2] = (detail >> 8) & 0xFF;
  write(sock, mirconn, sizeof(mirconn));
}

/*
 * Generate an "Operation failure" error response
 */
void NICEoperationFailureResponse(void)
{
  uint8_t opfail[3] = { NICE_RET_OPFAIL, 0, 0 };

  write(sock, opfail, sizeof(opfail));
}

/*
 * Generate a "Bad loopback response" error response
 */
void NICEbadLoopbackResponse(void)
{
  uint8_t badloop[3] = { NICE_RET_BADRESPONSE, 0, 0 };

  write(sock, badloop, sizeof(badloop));
}

/*
 * Generate an "Accepted" response
 */
void NICEacceptedResponse(void)
{
  uint8_t accepted = NICE_RET_ACCEPTED;

  write(sock, &accepted, sizeof(accepted));
}

/*
 * Generate a "Success" response in the outbound buffer
 */
void NICEsuccessResponse(void)
{
  outbuf[outptr++] = NICE_RET_SUCCESS;

  outbuf[outptr++] = 0;			/* Error detail */
  outbuf[outptr++] = 0;
  outbuf[outptr++] = 0;			/* Error message */
}

/*
 * Generate a "Done" response
 */
void NICEdoneResponse(void)
{
  uint8_t done = NICE_RET_DONE;

  write(sock, &done, sizeof(done));
}

/*
 * Read a NICE message from the socket
 */
int NICEread(void)
{
  inlen = read(sock, inbuf, sizeof(inbuf));
  inptr = 0;

  if ((verbosity > 1) && (inlen > 0)) {
    int i;
    char buf[2048];

    dnetlog(LOG_DEBUG, "Received NICE message %d bytes:\n", inlen);

    buf[0] = '\0';

    for (i = 0; i < inlen; i++)
      sprintf(&buf[strlen(buf)], "0x%02x ", inbuf[i]);
    dnetlog(LOG_DEBUG, "%s\n", buf);
  }

  return inlen;
}

/*
 * Check that there is some data available in the inbound buffer
 */
int NICEdataAvailable(void)
{
  return inlen != 0;
}

/*
 * Get a data field from the inbound buffer
 */
int NICEget1(
  uint8_t *result
)
{
  if (inlen >= sizeof(*result)) {
    *result = inbuf[inptr++];
    inlen -= sizeof(*result);
    return TRUE;
  }
  NICEformatResponse();
  return FALSE;
}

int NICEget2(
  uint16_t *result
)
{
  if (inlen >= sizeof(*result)) {
    *result = inbuf[inptr++];
    *result |= inbuf[inptr++] << 8;
    inlen -= sizeof(*result);
    return TRUE;
  }
  NICEformatResponse();
  return FALSE;
}

int NICEgetAI(
  uint8_t *len,
  uint8_t *buf,
  int maxlen
)
{
  int i;

  if (inlen >= sizeof(*len)) {
    *len = inbuf[inptr++];
    inlen -= sizeof(*len);
    if (*len <= inlen) {
      for (i = 0; i < *len; i++) {
        buf[i] = inbuf[inptr++];
        inlen -= sizeof(*buf);
      }
      return TRUE;
    }
    NICEtoolongResponse();
    return FALSE;
  }
  NICEformatResponse();
  return FALSE;
}
  
/*
 * Backup over some number of bytes in the inbound buffer. We don't allow
 * the backup operation to move before the start of the inbound buffer.
 */
void NICEbackup(
  int len
)
{
  if (len <= inptr) {
    inptr -= len;
    inlen += len;
  } else {
    inlen += inptr;
    inptr = 0;
  }
}
