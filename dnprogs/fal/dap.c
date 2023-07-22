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
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>
#include "dap.h"

extern int verbosity;

extern void DetailedDump(uint8_t, uint8_t *, int);

char *messages[] = {
  "Unknown",
  "Configuration",
  "Attributes",
  "Access",
  "Control",
  "Continue Transfer",
  "Acknowledge",
  "Access Complete",
  "Data",
  "Status",
  "Key Definition",
  "allocation Attributes",
  "Summary Attributes",
  "Date and Time Attributes",
  "Protection Attributes",
  "Name",
  "Access Control List Attributes"
};

char *ascii[] = {
  "nul", "soh", "stx", "etx", "eot", "enq", "ack", "bel",
  "bs", "ht", "nl", "vt", "np", "cr", "so", "si",
  "dle", "dc1", "dc2", "dc3", "dc4", "nak", "syn", "etb",
  "can", "em", "sub", "esc", "fs", "gs", "rs", "us",
  " ", "!", "\"", "#", "$", "%", "&", "'",
  "(", ")", "*", "+", ",", "-", ".", "/",
  "0", "1", "2", "3", "4", "5", "6", "7",
  "8", "9", ":", ";", "<", "=", ">", "?",
  "@", "A", "B", "C", "D", "E", "F", "G",
  "H", "I", "J", "K", "L", "M", "N", "O",
  "P", "Q", "R", "S", "T", "U", "V", "W",
  "X", "Y", "Z", "[", "\\", "]", "^", "_",
  "`", "a", "b", "c", "d", "e", "f", "g",
  "h", "i", "j", "k", "l", "m", "n", "o",
  "p", "q", "r", "s", "t", "u", "v", "w",
  "x", "y", "z", "{", "|", "}", "~", "del"
};

/*
 * All access to DAP message MUST go through these routines.
 */
static uint8_t *inbuf;
static int bufsiz, inptr;
static ssize_t inlen;
static int sock;

/*
 * Current message variables
 */
static uint8_t msgtype, msgflags, msgstreamid, msgbitcnt, *msgsysspec;
static uint16_t msglength, hdrlength;
static int msgstart, msgend, datalength;

extern uint8_t remLen;
extern uint16_t bufferSize;

extern int ProcessAccessCompleteMessage(void);

void DumpMessageMetadata(void)
{
  dnetlog(LOG_DEBUG, "msgend: %d, inptr: %d\n", msgend, inptr);
}

static char *class[] = {
  "Sent", "Received", "Unexpected"
};

static void logMessage(
  uint8_t *data,
  int sndrcv,
  int hdrlen,
  int datalen
)
{
  char buf1[64], buf2[64];
  int i;

  dnetlog(LOG_DEBUG, "%s DAP %s message (hdr: %d, data %d)\n",
          class[sndrcv],
          messages[data[0] <= DAP_MSG_MAX ? data[0] : 0],
          hdrlen, datalen);

  buf1[0] = '\0';
  for (i = 0; i < hdrlen; i++)
    sprintf(&buf1[strlen(buf1)], "0x%02x ", data[i]);

  dnetlog(LOG_DEBUG, " DAP hdr: %s\n", buf1);

  if (datalen != 0) {
    dnetlog(LOG_DEBUG, " DAP data:\n");

    buf1[0] = buf2[0] = '\0';
    for (i = 0; i < datalen; i++) {
      sprintf(&buf1[strlen(buf1)], "0x%02x ", data[hdrlen + i]);
      sprintf(&buf2[strlen(buf2)], "%-5s", ascii[data[hdrlen + i] & 0x7F]);
      if ((i % 12) == 11) {
        dnetlog(LOG_DEBUG, "  %s\n", buf1);
        dnetlog(LOG_DEBUG, "   %s\n", buf2);
        buf1[0] = buf2[0] = '\0';
      }
    }

    if (buf1[0] != '\0') {
      dnetlog(LOG_DEBUG, "  %s\n", buf1);
      dnetlog(LOG_DEBUG, "   %s\n", buf2);
    }
  }

  if (verbosity > 2)
    DetailedDump(data[0], &data[hdrlen], datalen);
}

/*
 * Message reception support routines.
 */

/*
 * Check if we are currently at the end of message and all remaining fields
 * are defaulted.
 */
int DAPeom(void)
{
  return inptr == msgend;
}

/*
 * Single byte field.
 */
int DAPbGet(
  uint8_t *value
)
{
  if ((msgend - inptr) >= sizeof(uint8_t)) {
    *value = inbuf[inptr++];
    return 1;
  }
  return 0;
}

/*
 * 2 byte field.
 */
int DAP2bGet(
  uint16_t *value
)
{
  if ((msgend - inptr) >= sizeof(uint16_t)) {
    *value = inbuf[inptr++];
    *value |= (inbuf[inptr++] << 8);
    return 1;
  }
  return 0;
}

/*
 * Fixed-length field.
 */
int DAPfGet(
  uint8_t **value,
  uint16_t len
)
{
  if ((msgend - inptr) >= len) {
    *value = &inbuf[inptr];
    inptr += len;
    return 1;
  }
  return 0;
}

/*
 * Image field.
 */
int DAPiGet(
  uint8_t **value,
  uint8_t maxlen
)
{
  if ((msgend - inptr) >= 1) {
    uint8_t len = inbuf[inptr];

    if (len <= maxlen) {
      if ((len == 0) || (msgend - inptr) >= (len + 1)) {
        *value = &inbuf[inptr];
        inptr += len + 1;
        return 1;
      }
    }
  }
  return 0;
}

/*
 * Extensible field (EX-n) routines.
 */

int DAPexValid(
  uint8_t **value,
  uint8_t maxlen
)
{
  int start = inptr;
  
  *value = &inbuf[inptr];
  
  do {
    if (((msgend - inptr) < 1) || (inptr - start) >= maxlen)
      return 0;
  } while ((inbuf[inptr++] & DAP_EXTEND) != 0);

  if ((msgend - inptr) >= 0)
    return 1;

  return 0;
}

int DAPexGetBit(
  uint8_t *ptr,
  int bit
)
{
  int offset = bit / 7;

  while ((offset != 0) && ((*ptr & DAP_EXTEND) != 0)) {
    ptr++;
    offset--;
  }

  /*
   * If the bit is off the end of the extensible field, return 0
   */
  if (offset != 0)
    return 0;

  return (((*ptr & (1 << (bit % 7))) == 0) ? 0 : 1);
}

void DAPexCopy(
  uint8_t *ptr,
  uint8_t *dst,
  size_t len
)
{
  do {
    *dst = *ptr;
    if (--len == 0) {
      *dst &= ~DAP_EXTEND;
      return;
    }
    dst++;
  } while ((*ptr++ & DAP_EXTEND) != 0);
}

/*
 * Get a pointer to the data in a DAP Data message and it's length. Any
 * preceeding protocol elements must be processed before calling this
 * routine.
 */
void DAPgetFiledata(
  uint8_t **ptr,
  uint16_t *len
)
{
  *ptr = &inbuf[inptr];
  *len = msgend - inptr;
}

/*
 * Image field conversion routines. Note that the image field must first
 * be validated using DAPiGet().
 */
uint64_t DAPi2int(
  uint8_t *ptr
)
{
  uint64_t result = 0;
  unsigned int i;

  for (i = 0; i < *ptr; i++)
    result |= (ptr[i + 1] << (i << 3));

  return result;
}

char *DAPi2string(
  uint8_t *ptr,
  char *dst
)
{
  uint8_t len = *ptr++;

  if (len != 0)
    memcpy(dst, ptr, len);
  dst[len] = '\0';

  return dst;
}

/*
 * Extensible field conversion routines.
 */
uint64_t DAPex2int(
  uint8_t *ptr
)
{
  uint64_t result = 0;
  int shift = 0;

  /*
   * Note that the largest extensible field in the DAP 5.6.0 spec is the
   * SYSCAP field in the Configuration message which has a maximum length
   * of 12 bytes which maps to 84 bits of data, however, only 42 bits are
   * currently defined. The second largest field is 6 bytes which maps to
   * 42 bits which easily fits in a uint64_t. This routine and it's uses
   * should be re-examined if a newer DAP spec is used.
   */
  do {
    result |= (*ptr & 0x7F) << shift;
    shift += 7;
  } while ((*ptr++ & DAP_EXTEND) != 0);

  return result;
}

/*
 * Fixed length field conversion routines.
 */
char *DAPf2string(
  uint8_t *ptr,
  uint16_t len,
  char *dst
)
{
  memcpy(dst, ptr, len);
  dst[len] = '\0';
  return dst;
}

/*
 * Read a message from the socket. One or more DAP messages may be embedded
 * in the buffer - segmented messages are not supported.
 */
int DAPread(void)
{
  inlen = read(sock, inbuf, bufsiz);
  inptr = msgstart = msglength = hdrlength = 0;

  if ((verbosity > 1) && (inlen > 0))
    dnetlog(LOG_DEBUG, "DAPread %d bytes\n", inlen);

  return inlen;
}

/*
 * Move on to the next DAP message in the buffer or read a new message from
 * the socket. Parse the message header and return the message type.
 */
int DAPnextMessage(
  uint8_t *func
)
{
  if ((inptr != 0) &&
      ((msglength == 0) ||
       ((msgstart + hdrlength + msglength) == inlen))) {
    inlen = DAPread();

    if (inlen <= 0)
      return inlen;
  }

  inptr = msgstart = msgstart + hdrlength + msglength;

  /*
   * Parse the message header
   */
  if ((inlen - inptr) < 1)
    return -1;

  msgtype = inbuf[inptr++];
  msgflags = 0;
  msgstreamid = msgbitcnt = msglength = 0;
  msgsysspec = NULL;

  if ((inlen - inptr) != 0) {
    msgflags = inbuf[inptr++];
    
    if ((msgflags & DAP_FLAGS_STREAMID) != 0) {
      if ((inlen - inptr) < 1)
        return -1;
      msgstreamid = inbuf[inptr++];
    }

    if ((msgflags & DAP_FLAGS_LENGTH) != 0) {
      if ((inlen - inptr) < 1)
        return -1;
      msglength = inbuf[inptr++];
    }

    if ((msgflags & DAP_FLAGS_LEN256) != 0) {
      if (((msgflags & DAP_FLAGS_LENGTH) == 0) || ((inlen - inptr) < 1))
        return -1;
      msglength |= (inbuf[inptr++] << 8);
    }

    if ((msgflags & DAP_FLAGS_BITCNT) != 0) {
      if ((inlen - inptr) < 1)
        return -1;
      msgbitcnt = inbuf[inptr++];
    }

    if ((msgflags & DAP_FLAGS_SYSSPEC) != 0) {
      uint8_t len = inbuf[inptr];
      
      if (((inlen - inptr) < 1) || ((inlen - inptr) < (len + 1)))
        return -1;
      msgsysspec = &inbuf[inptr];
      inptr += len + 1;
    }
  }
  
  hdrlength = inptr - msgstart;
  datalength =  msglength != 0 ? msglength : inlen - (msgstart + hdrlength);
  msgend = msgstart + hdrlength + datalength;
  *func = msgtype;
  return datalength;
}

/*
 * Check if a blocked DAP message is available on the network socket. If
 * so, read it and process all DAP protocol messages present. This routine
 * only handles Access Complete messages
 * (by calling ProcessAccessCompleteMessage()). Note that this routine will
 * overwrite the (single) receive buffer so it should only be called when the
 * buffer is known to be empty.
 */
int DAPcheckRead(void)
{
  ssize_t rcvlen = recv(sock, inbuf, bufsiz, MSG_DONTWAIT);

  if (rcvlen > 0) {
    inlen = rcvlen;
    inptr = msgstart = msglength = hdrlength = 0;

    if (verbosity > 1)
      dnetlog(LOG_DEBUG, "DAPcheckRead %d bytes\n", inlen);

    do {
      uint8_t func;

      if (DAPnextMessage(&func) == -1)
        return 0;

      if (func == DAP_MSG_COMPLETE) {
        if (ProcessAccessCompleteMessage() == 0)
          return 0;
      } else {
        ReportError(DAP_MAC_SYNC | func);
        return 0;
      }
    } while ((msglength != 0) &&
             ((msgstart + hdrlength + msglength) < inlen));
  }
  return 1;
}

void DAPlogRcvMessage(void)
{
  logMessage(&inbuf[msgstart], 1, hdrlength, datalength);
}

void DAPlogUnexpectedMessage(void)
{
  logMessage(&inbuf[msgstart], 2, hdrlength, datalength);
}

/*
 * Message transmission support routines.
 */
#define BUFCNT          8                       /* Pre-allocated buffers */

/*
 * Buffer descriptor for message transmission
 */
struct bufDescr {
  struct bufDescr       *next;
  uint8_t               *data;
  int                   hdrlength;
  int                   datalength;
  int                   offset;
} descr[BUFCNT], *buffers = NULL, *pending = NULL;

uint8_t bufspace[BUFSIZ * BUFCNT];

/*
 * Single byte field routines.
 */
void DAPbPut(
  void *buf,
  uint8_t value
)
{
  struct bufDescr *desc = (struct bufDescr *)buf;

  desc->data[desc->offset++] = value;
}

/*
 * 2 byte field routines.
 */
void DAP2bPut(
  void *buf,
  uint16_t value
)
{
  struct bufDescr *desc = (struct bufDescr *)buf;

  desc->data[desc->offset++] = value & 0xFF;
  desc->data[desc->offset++] = (value >> 8) & 0xFF;
}

/*
 * Image field routines.
 */
void DAPiPut(
  void *buf,
  uint8_t len,
  uint8_t *value
)
{
  struct bufDescr *desc = (struct bufDescr *)buf;

  desc->data[desc->offset++] = len;
  if (len != 0)
    memcpy(&desc->data[desc->offset], value, len);
  desc->offset += len;
}

/*
 * Extensible field (EX-n) routines.
 */
void DAPexInit(
  void *buf,
  int maxlen
)
{
  struct bufDescr *desc = (struct bufDescr *)buf;

  memset(&desc->data[desc->offset], 0, maxlen);
}
void DAPexDone(
  void *buf
)
{
  struct bufDescr *desc = (struct bufDescr *)buf;

  while ((desc->data[desc->offset] & DAP_EXTEND) != 0)
    desc->offset++;

  desc->offset++;
}

void DAPexSetBit(
  void *buf,
  int bit
)
{
  struct bufDescr *desc = (struct bufDescr *)buf;
  int offset = desc->offset;
  int bytes = bit / 7;

  while ((bytes != 0) && ((desc->data[offset] & DAP_EXTEND) != 0)) {
    offset++;
    bytes--;
  }

  while (bytes != 0) {
    desc->data[offset++] |= DAP_EXTEND;
    bytes--;
  }

  desc->data[offset] |= (1 << (bit % 7));
}

/*
 * Indicate that the DAP header is complete
 */
void DAPhdrDone(
  void *buf
)
{
  struct bufDescr *desc = (struct bufDescr *)buf;

  desc->hdrlength = desc->offset;
}

/*
 * Image field conversion routines.
 */

/*
 * Convert an unsigned integer into an image field. If the value will not
 * fit into the image field a single byte image field of zero will be used.
 */
void DAPint2i(
  void *buf,
  uint8_t maxlen,
  uint64_t value
)
{
  struct bufDescr *desc = (struct bufDescr *)buf;
  int offset = desc->offset;
  uint8_t count = 0;

  desc->offset++;
  do {
    if (count == maxlen) {
      desc->offset = offset;
      desc->data[desc->offset++] = 1;
      desc->data[desc->offset++] = 0;
      return;
    }
    desc->data[desc->offset++] = value & 0xFF;
    value >>= 8;
    count++;
  } while (value != 0);
  desc->data[offset] = count;
}

/*
 * Convert a string into an image field. If string is too long for the field,
 * it will be truncated.
 */
void DAPstring2i(
  void *buf,
  uint8_t maxlen,
  char *str
)
{
  struct bufDescr *desc = (struct bufDescr *)buf;
  size_t len = strlen(str);

  if (len > maxlen)
    len = maxlen;

  desc->data[desc->offset++] = len;
  if (len != 0)
    memcpy(&desc->data[desc->offset], str, len);
  desc->offset += len;
}

/*
 * Allocate a buffer for transmission and return an opaque handle
 */
void *DAPallocBuf(void)
{
  struct bufDescr *result;

  /*
   * If all buffers are in use, flush buffers to the remote system
   */
  if (buffers == NULL)
    DAPflushBuffers();

  result = buffers;
  buffers = result->next;
  result->hdrlength = 0;
  result->datalength = 0;
  result->offset = 0;
  return result;
}

/*
 * Release a buffer which we no longer need
 */
void DAPreleaseBuf(
  void *buf
)
{
  struct bufDescr *desc = (struct bufDescr *)buf;

  desc->next = buffers;
  buffers = desc;
}

ssize_t DAPflushBuffers(void)
{
  struct bufDescr *bufs[BUFCNT], *desc;
  struct iovec iov[BUFCNT];
  int i, iovcnt = 0;
  ssize_t status;

  while ((desc = pending) != NULL) {
    pending = desc->next;

    iov[iovcnt].iov_base = (char *)desc->data;
    iov[iovcnt].iov_len = (size_t)(desc->hdrlength + desc->datalength);
    bufs[iovcnt++] = desc;
  }
  status = writev(sock, iov, iovcnt);

  if ((verbosity > 1) && (status > 0))
    dnetlog(LOG_DEBUG, "DAPwrite %lld bytes\n", status);
  
  /*
   * Return the buffers to the pool.
   */
  for (i = 0; i < iovcnt; i++) {
    bufs[i]->next = buffers;
    buffers = bufs[i];
  }
  return status;
}

int DAPwrite(
  void *buf
)
{
  struct bufDescr *ptr, *desc = (struct bufDescr *)buf;
  struct bufDescr **chain = &pending;
  
  desc->datalength = desc->offset - desc->hdrlength;
  desc->next = NULL;
  
  /*
   * Update the message header if necessary
   */
  if ((desc->data[1] & DAP_FLAGS_LENGTH) != 0) {
    int idx = ((desc->data[1] & DAP_FLAGS_STREAMID) != 0) ? 3 : 2;
    
    desc->data[idx] = desc->datalength & 0xFF;
    if ((desc->data[1] & DAP_FLAGS_LEN256) != 0)
      desc->data[idx + 1] = (desc->datalength >> 8) & 0xFF;
  }

  if (verbosity > 1)
    logMessage(desc->data, 0, desc->hdrlength, desc->datalength);
  
  /*
   * Check if this message will take us over negotiated buffer size.
   */
  if ((ptr = pending) != NULL) {
    uint16_t len = 0;

    do {
      len += ptr->hdrlength + ptr->datalength;
    } while ((ptr = ptr->next) != NULL);

    if ((len + desc->hdrlength + desc->datalength) > bufferSize)
      DAPflushBuffers();
  }
  
  /*
   * Append this message to the end of the pending chain.
   */
  while (*chain != NULL)
    chain = &((*chain)->next);

  *chain = desc;

  /*
   * If this message does not have a length field present or there are no
   * available buffers, flush all pending messages.
   */
  if (((desc->data[1] & DAP_FLAGS_LENGTH) == 0) || (buffers == NULL))
    return DAPflushBuffers();
  return 1;
}

/*
 * Allocate a buffer and build a simple DAP header with no length field
 * present.
 */
void *DAPbuildHeader(
  uint8_t msgtype
)
{
  void *buf = DAPallocBuf();
  
  DAPbPut(buf, msgtype);
  DAPbPut(buf, 0);
  DAPhdrDone(buf);

  return buf;
}

/*
 * Allocate a buffer and build a DAP header with a single byte length field
 * if the remote system supports it.
 */
void *DAPbuildHeader1Len(
  uint8_t msgtype
)
{
  void *buf = DAPallocBuf();
  
  DAPbPut(buf, msgtype);
  if (remLen != 0) {
    DAPbPut(buf, DAP_FLAGS_LENGTH);
    DAPbPut(buf, 0);
  } else DAPbPut(buf, 0);
  DAPhdrDone(buf);

  return buf;
}

/*
 * Allocate a buffer and build a DAP header with a two byte length field if
 * the remote system supports it.
 */
void *DAPbuildHeader2Len(
  uint8_t msgtype
)
{
  void *buf = DAPallocBuf();
  
  DAPbPut(buf, msgtype);
  if (remLen == 2) {
    DAPbPut(buf, DAP_FLAGS_LENGTH | DAP_FLAGS_LEN256);
    DAP2bPut(buf, 0);
  } else DAPbPut(buf, 0);
  DAPhdrDone(buf);

  return buf;
}

/*
 * Allocate space in a DAP message buffer, returing a pointer to the start
 * of the allocated space.
 */
void DAPallocateSpace(
  void *buf,
  size_t len
)
{
  struct bufDescr *desc = (struct bufDescr *)buf;

  desc->offset += len;
}

/*
 * Get pointer to current end of a DAP message buffer.
 */
uint8_t *DAPgetEnd(
  void *buf
)
{
  struct bufDescr *desc = (struct bufDescr *)buf;

  return &desc->data[desc->offset];
}

/*
 * Add a timestamp value to a DAP message as an 18-character string in the
 * format "dd-mmm-yy hh:mm:ss".
 */
int DAPaddDateTime(
  void *buf,
  struct timespec *ts
)
{
  struct tm t;
  char tmp[32];
  int i;

  if (gmtime_r(&(ts->tv_sec), &t) != NULL) {
    if (strftime(tmp, sizeof(tmp), "%d-%b-%y %T", &t) == 18) {
      /*
       * Force the month to uppercase
       */
      tmp[3] = toupper(tmp[3]);
      tmp[4] = toupper(tmp[4]);
      tmp[5] = toupper(tmp[5]);

      for (i = 0; i < 18; i++)
        DAPbPut(buf, tmp[i]);
      return 1;
    }
  }
  return 0;
}

/*
 * Send an Acknowledge message.
 */
void DAPsendAcknowledge(void)
{
  void *buf = DAPbuildHeader(DAP_MSG_ACKNOWLEDGE);
  
  DAPwrite(buf);
}

/*
 * Create a NAME message in a new buffer with the specified name and type.
 * If the string is too long, it will be truncated to the first 5 characters
 * followed by "...".
 */
void DAPsendName(
  uint8_t nametype,
  char *name
)
{
  void *buf;
  char temp[16];

  if (strlen(name) > DAP_NAME_MAX_NAMESPEC) {
    strncpy(temp, name, 5);
    temp[5] = '\0';
    strcat(temp, "...");
    name = temp;
  }

  buf = DAPbuildHeader1Len(DAP_MSG_NAME);

  DAPexInit(buf, 3);
  DAPexSetBit(buf, nametype);
  DAPexDone(buf);
  DAPiPut(buf, strlen(name), (uint8_t *)name);
  DAPwrite(buf);
}

/*
 * Initialize buffer usage.
 */
void DAPinit(
  int insock,
  uint8_t *bufin,
  int buflen
)
{
  uint8_t *data = bufspace;
  int i;
  
  sock = insock;
  inbuf = bufin;
  bufsiz = buflen;

  for (i = 0; i < BUFCNT; i++, data += BUFSIZ) {
    descr[i].data = data;
    descr[i].next = buffers;
    buffers = &descr[i];
  }
}
