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

/*
 * NICE support routines NCP => NML
 */

/*
 * All access to the outbound NICE response buffer MUST go through these
 * routines.
 */
static unsigned char outbuf[300], inbuf[300];
static int outptr, inptr;
static ssize_t inlen, savlen;
static int sock = -1;

void NICEinit(void)
{
  outptr = 0;
}

void NICEsock(
  int s
)
{
  sock = s;
}

void NICEclose(void)
{
  if (sock >= 0) {
    close(sock);
    sock = -1;
  }
}

/*
 * Flush any data in the outbound buffer
 */
void NICEflush(void)
{
  if (outptr) {
    /*** initiate connection first? ***/
    write(sock, outbuf, outptr);
  }
  outptr = 0;
}

/*
 * Write a single byte value to the outbound buffer
 */
void NICEput1(
  uint8_t value
)
{
  outbuf[outptr++] = value;
}

/*
 * Write a two byte value to the outbound buffer
 */
void NICEput2(
  uint16_t value
)
{
  outbuf[outptr++] = value & 0xFF;
  outbuf[outptr++] = (value >> 8) & 0xFF;
}

/*
 * Write a string preceeded by the length to the outbound buffer
 */
void NICEputString(
  char *value
)
{
  outbuf[outptr++] = strlen(value);
  memcpy((char *)&outbuf[outptr], value, strlen(value));
  outptr += strlen(value);
}

/*
 * Write a counted byte array to the outbound buffer
 */
void NICEputBytes(
  uint8_t count,
  uint8_t *bytes
)
{
  outbuf[outptr++] = count;
  if (count != 0) {
    memcpy((char *)&outbuf[outptr], bytes, count);
    outptr += count;
  }
}

/*
 * Write an arbitrary sized block to the output buffer (limited to a max of
 * 255 bytes
 */
void NICEputBlob(
  uint8_t count,
  uint8_t *bytes
)
{
  memcpy((char *)&outbuf[outptr], bytes, count);
  outptr += count;
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
}

/*
 * Write an area number
 */
void NICEareaEntity(
  uint8_t area
)
{
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
 * Generate an "Operation failure" error response
 */
void NICEoperationFailureResponse(void)
{
  char opfail[3] = { NICE_RET_OPFAIL, 0, 0 };

  write(sock, &opfail, sizeof(opfail));
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

  outbuf[outptr++] = 0;			/* Error detail */
  outbuf[outptr++] = 0;

  outbuf[outptr++] = 0;			/* Error message */
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
  inlen = savlen = read(sock, inbuf, sizeof(inbuf));
  inptr = 0;

  return inlen;
}

/*
 * Rewind the current NICE message to the beginning
 */
int NICErewind(void)
{
  inptr = 0;
  inlen = savlen;
  return savlen;
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
  return FALSE;
}

int NICEget4(
  uint32_t *result
)
{
  if (inlen >= sizeof(*result)) {
    *result = inbuf[inptr++];
    *result |= inbuf[inptr++] << 8;
    *result |= inbuf[inptr++] << 16;
    *result |= inbuf[inptr++] << 24;
    inlen -= sizeof(*result);
    return TRUE;
  }
  return FALSE;
}

int NICEgetAI(
  char *len,
  char mask,
  char *buf,
  int maxlen
)
{
  int i;
  char length;

  if (inlen >= sizeof(*len)) {
    *len = inbuf[inptr++];
    inlen -= sizeof(*len);

    length = *len & mask;

    if ((length <= inlen) && (length <= maxlen)) {
      for (i = 0; i < length; i++) {
        buf[i] = inbuf[inptr++];
        inlen -= sizeof(*buf);
      }
      return TRUE;
    }
  }
  return FALSE;
}

/*
 * Copy an ASCII image field into a supplied buffer. The resulting string
 * will be zero-terminated. The ASCII image field will always be passed over
 * in the input buffer even if there is insufficient space in the output
 * buffer.
 */
int NICEcopyAI(
  uint8_t *buf,
  int maxlen
)
{
  uint8_t len;
  int result = FALSE;

  if (inlen >= sizeof(uint8_t)) {
    len = inbuf[inptr++];
    inlen -= sizeof(uint8_t);

    if (len <= inlen) {
      if ((len + sizeof(uint8_t)) <= maxlen) {
	memcpy(buf, &inbuf[inptr], len);
	buf[len] = '\0';
	result = TRUE;
      }
      inptr += len;
      inlen -= len;
      return result;
    }
  }
  return FALSE;
}

/*
 * Skip over an ASCII image field in the input buffer.
 */
int NICEskipAI(void)
{
  uint8_t len;

  if (inlen >= sizeof(uint8_t)) {
    len = inbuf[inptr++];
    inlen -= sizeof(uint8_t);

    if (len <= inlen) {
      inptr += len;
      inlen -= len;
      return TRUE;
    }
  }
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

/*
 * Check if the current input buffer has been exhausted
 */
int NICEisEmpty(void)
{
  return inlen == 0;
}

