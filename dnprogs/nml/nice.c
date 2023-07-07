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
static unsigned char outbuf[512], inbuf[512];
static int outptr, inptr;
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

  outbuf[outptr++] = 0;
  outbuf[outptr++] = nodeaddress & 0xFF;
  outbuf[outptr++] = (nodeaddress >> 8) & 0xFF;

  outbuf[outptr++] = len | (exec ? 0x80 : 0);
  if (len) {
    for (i = 0; i < len; i++)
      outbuf[outptr++] = toupper(nodename[i]);
  }
}

/*
 * Write a circuit name as an Ascii Image field
 */
void NICEcircuitEntity(
  char *circuit
)
{
  outbuf[outptr++] = 0;
  outbuf[outptr++] = strlen(circuit);
  memcpy((char *)&outbuf[outptr], circuit, strlen(circuit));
  outptr += strlen(circuit);
}

/*
 * Write an area number
 */
void NICEareaEntity(
  uint8_t area
)
{
  outbuf[outptr++] = 0;
  outbuf[outptr++] = 0;
  outbuf[outptr++] = area;
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
  char imf[3] = { NICE_RET_INVALID, 0, 0 };

  write(sock, imf, sizeof(imf));
}

/*
 * Generate an "Unrecognized function or option" error response
 */
void NICEunsupportedResponse(void)
{
  char unsupp[3] = { NICE_RET_UNRECOG, 0, 0 };

  write(sock, unsupp, sizeof(unsupp));
}

/*
 * Generate a "Parameter too long" error response
 */
void NICEtoolongResponse(void)
{
  char toolong[3] = { NICE_RET_TOOLONG, 0, 0 };

  write(sock, toolong, sizeof(toolong));
}

/*
 * Generate an "Unrecognized component" error response
 */
void NICEunrecognizedComponentResponse(
  char component
)
{
  char unrecog[3] = { NICE_RET_BADCOMPONENT, 0, 0 };

  unrecog[1] = component;
  write(sock, &unrecog, sizeof(unrecog));
}

/*
 * Generate an "Accepted" response
 */
void NICEacceptedResponse(void)
{
  char accepted = NICE_RET_ACCEPTED;

  write(sock, &accepted, sizeof(accepted));
}

/*
 * Generate a "Partial" response
 */
void NICEpartialResponse(void)
{
  char partial = NICE_RET_PARTIAL;

  write(sock, &partial, sizeof(partial));
}

/*
 * Generate a "Success" response in the outbound buffer
 */
void NICEsuccessResponse(void)
{
  outbuf[outptr++] = NICE_RET_SUCCESS;
  outbuf[outptr++] = 0;
  outbuf[outptr++] = 0;
}

/*
 * Generate a "Done" response
 */
void NICEdoneResponse(void)
{
  char done = NICE_RET_DONE;

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
  char *len,
  char *buf,
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
