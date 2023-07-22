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

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <glob.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>
#include "dap.h"

extern int verbosity;

extern uint8_t remOS, remFS, remLen, remDATATYPE[], remFOP[], remRFM, remRAT[];
extern uint16_t bufferSize;

extern int ProcessAccessCompleteMessage(void);

/*
 * Each instance of FAL can handle a single open file.
 */
enum {
  FileOpenNone,
  FileOpenRead,
  FileOpenWrite,
  FileOpenReadConnected,
  FileOpenWriteConnected
} fileStatus = FileOpenNone;

FILE *fp = NULL;

/*
 * This function provides the equivalent of realpath() where the final
 * component may not exist.
 */
static char *localRealpath(
  const char *path,
  char *resolved_path
)
{
  char *cp, tmppath[PATH_MAX];
  char *ptr = ".";
  
  if (strlen(path) < PATH_MAX) {
    strcpy(tmppath, path);
    if ((cp = rindex(tmppath, '/')) != NULL) {
      *cp++ = '\0';
      if (cp != tmppath)
        ptr = tmppath;
      else ptr = "/";
    } else cp = (char *)path;

    if ((ptr = realpath(ptr, resolved_path)) != NULL) {
      size_t len;

      while (((len = strlen(ptr)) != 0) && (ptr[len - 1] == '/'))
        ptr[len - 1] = '\0';

      strcat(ptr, "/");
      strcat(ptr, cp);
      return ptr;
    }
  }
  return NULL;
}

/*
 * Open an existing file
 */
void OpenFile(
  char *name,
  uint8_t *display
)
{
  struct stat statbuf;

  if (fp != NULL) {
    fclose(fp);
    fp = NULL;
  }

  if (stat(name, &statbuf) == 0) {
    if ((fp = fopen(name, "r")) != NULL) {
      if ((display == NULL) || DAPexGetBit(display, DAP_DSP_MAIN)) {
        void *buf = DAPbuildHeader1Len(DAP_MSG_ATTRIBUTES);

        DAPexInit(buf, 6);
        DAPexSetBit(buf, DAP_ATTR_DATATYPE);
        if (DAPexGetBit(remDATATYPE, DAP_DATATYPE_ASCII))
          DAPexSetBit(buf, DAP_ATTR_RFM);
        if (DAPexGetBit(remDATATYPE, DAP_DATATYPE_IMAGE))
          DAPexSetBit(buf, DAP_ATTR_MRS);
        DAPexSetBit(buf, DAP_ATTR_ALQ);
        DAPexSetBit(buf, DAP_ATTR_EBK);
        DAPexSetBit(buf, DAP_ATTR_FFB);
        DAPexDone(buf);

        DAPexInit(buf, 2);
        if (DAPexGetBit(remDATATYPE, DAP_DATATYPE_ASCII))
          DAPexSetBit(buf, DAP_DATATYPE_ASCII);
        if (DAPexGetBit(remDATATYPE, DAP_DATATYPE_IMAGE))
          DAPexSetBit(buf, DAP_DATATYPE_IMAGE);
        DAPexDone(buf);

        /*
         * If the remote system expects the file in ASCII, we'll send it
         * as an ASCII stream.
         */
        if (DAPexGetBit(remDATATYPE, DAP_DATATYPE_ASCII)) {
          DAPbPut(buf, DAP_RFM_STM);
          remRFM = DAP_RFM_STM;
        }

        /*
         * Return the maximum possible record size based on the available
         * buffer size.
         */
        if (DAPexGetBit(remDATATYPE, DAP_DATATYPE_IMAGE))
          DAP2bPut(buf, 512);

        /*
         * Fill in infomation about the file size, allocation etc
         */
        DAPint2i(buf, 5, statbuf.st_blocks);
        DAPint2i(buf, 5, (statbuf.st_size + 511) / 512);
        DAP2bPut(buf, statbuf.st_size % 512);
        DAPwrite(buf);
      }

      if (display != NULL) {
        if (DAPexGetBit(display, DAP_DSP_DATETIME)) {
          void *buf = DAPbuildHeader1Len(DAP_MSG_DATETIME);

          DAPexInit(buf, 6);
          DAPexSetBit(buf, DAP_DMNU_CDT);
          DAPexSetBit(buf, DAP_DMNU_RDT);
          DAPexDone(buf);
          DAPaddDateTime(buf, &statbuf.st_ctim);
          DAPaddDateTime(buf, &statbuf.st_mtim);
          DAPwrite(buf);
        }

        if (DAPexGetBit(display, DAP_DSP_NAME)) {
          char *cp;

          if ((cp = rindex(name, '/')) != NULL)
            cp++;
          else cp = name;
          DAPsendName(DAP_NAME_TYPE_FILESPEC, cp);
        }
      }
      
      DAPsendAcknowledge();

      fileStatus = FileOpenRead;
      return;
    }
  }
  ReportError(DAP_MAC_OPEN | DAP_MIC_IO_ER_FNF);
}

void CreateFile(
  char *name,
  uint8_t *display
)
{
  char fullpath[PATH_MAX];
  
  if ((display != NULL) && DAPexGetBit(display, DAP_DSP_NAME)) {
    if (localRealpath(name, fullpath) != NULL) {
      if (strlen(fullpath) > DAP_NAME_MAX_NAMESPEC) {
        ReportError(DAP_MAC_OPEN | DAP_MIC_IO_ER_FNM);
        return;
      }
    } else {
      ReportError(DAP_MAC_OPEN | DAP_MIC_IO_ER_DME);
      return;
    }
  }

  if ((access(name, F_OK) == 0) && ((DAPexGetBit, remFOP, DAP_FOP_SUP) == 0)) {
    ReportError( DAP_MAC_OPEN | DAP_MIC_IO_ER_FEX);
    return;
  }
    
  if ((fp = fopen(name, "w")) != NULL) {
    if ((display == NULL) || DAPexGetBit(display, DAP_DSP_MAIN)) {
      void *buf = DAPbuildHeader1Len(DAP_MSG_ATTRIBUTES);

      DAPexInit(buf, 6);
      DAPexSetBit(buf, DAP_ATTR_DATATYPE);
      DAPexSetBit(buf, DAP_ATTR_ORG);
      DAPexDone(buf);
      
      DAPexInit(buf, 2);
      if (DAPexGetBit(remDATATYPE, DAP_DATATYPE_ASCII))
        DAPexSetBit(buf, DAP_DATATYPE_ASCII);
      if (DAPexGetBit(remDATATYPE, DAP_DATATYPE_IMAGE))
        DAPexSetBit(buf, DAP_DATATYPE_IMAGE);
      DAPexDone(buf);

      DAPbPut(buf, DAP_ORG_SEQ);
      DAPwrite(buf);
    }

    if ((display != NULL) && DAPexGetBit(display, DAP_DSP_NAME))
      DAPsendName(DAP_NAME_TYPE_FILESPEC, fullpath);
    
    DAPsendAcknowledge();

    fileStatus = FileOpenWrite;
    return;
  }
  ReportError(DAP_MAC_OPEN | DAP_MIC_IO_ER_COF);
}

int  ConnectToFile(void)
{
  switch (fileStatus) {
    case FileOpenRead:
      fileStatus = FileOpenReadConnected;
      DAPsendAcknowledge();
      return 1;
      
    case FileOpenWrite:
      fileStatus = FileOpenWriteConnected;
      DAPsendAcknowledge();
      return 1;
      
    case FileOpenNone:
    case FileOpenReadConnected:
    case FileOpenWriteConnected:
      break;
  }
  ReportError(DAP_MAC_SYNC | DAP_MIC_SYNC_CONTROL);
  return 0;
}

int GetFileData(void)
{
  uint16_t dataSize = bufferSize - DAP_HDR_LEN_LENGTH - 9;
  size_t readlen;
  
  if (fileStatus == FileOpenReadConnected) {
    do {
      void *buf = DAPbuildHeader2Len(DAP_MSG_DATA);
      uint8_t *dbuf;
      size_t len;
      int eof = 0;
      
      DAPbPut(buf, 0);

      dbuf = DAPgetEnd(buf);
      
      switch (remRFM) {
        case DAP_RFM_VAR:
          /*
           * For variable length record, we'll send one line in each Data
           * message.
           */
          if (fgets((char *)dbuf, dataSize, fp) != NULL) {
            /*
             * For implied LF/CR record attributes, strip any trailing newline
             */
            if (DAPexGetBit(remRAT, DAP_RAT_CR))
              if (((len = strlen((char *)dbuf)) > 0) && (dbuf[len - 1] == '\n'))
                dbuf[len - 1] ='\0';
            readlen = strlen((char *)dbuf);
          } else eof = 1;
          break;

        case DAP_RFM_STM:
          /*
           * For ASCII stream format, we'll translate any terminating <LF>
           * character into <CR><LF>.
           */
          if (fgets((char *)dbuf, dataSize - 2, fp) != NULL) {
            if (((len = strlen((char *)dbuf)) > 0) && (dbuf[len - 1] == '\n')) {
              dbuf[len - 1] = '\r';
              dbuf[len] = '\n';
              dbuf[len + 1] = '\0';
            }
            readlen = strlen((char *)dbuf);
          } else eof = 1;
          break;

        case DAP_RFM_FIX:
          /*
           * For fixed length records, we'll send one disk block (512 bytes)
           * in each Data message, padded if necessary with NULLs.
           */
          if ((readlen = fread(dbuf, sizeof(uint8_t), 512, fp)) != 0) {
            if (readlen != 512)
              memset(&dbuf[readlen], 0, 512 - readlen);
            readlen = 512;
          } else eof = 1;
          break;
          
        default:
          /*
           * For all other formats, we'll send as much data as will fit in
           * each Data message.
           */
          if ((readlen = fread(dbuf, sizeof(uint8_t), dataSize, fp)) == 0)
            eof = 1;
          break;
      }

      if (eof) {
        DAPreleaseBuf(buf);
        break;
      }

      DAPallocateSpace(buf, readlen);
      DAPwrite(buf);

      if (DAPcheckRead() == 0)
        return 0;
    } while (fileStatus == FileOpenReadConnected);

    if (fileStatus == FileOpenReadConnected)
      ReportError(DAP_MAC_XFER | DAP_MIC_IO_ER_EOF);
    return 1;
  }
  ReportError(DAP_MAC_SYNC | DAP_MIC_SYNC_CONTROL);
  return 0;
}

int PutFileData(void)
{
  if (fileStatus == FileOpenWriteConnected) {
    uint8_t type;

    while (DAPnextMessage(&type) >= 0) {
      uint8_t *ptr;
      uint16_t len;
      size_t writelen;
      uint8_t extra = 0;
      
      switch (type) {
        case DAP_MSG_DATA:
          if (DAPiGet(&ptr, 8)) {
            DAPgetFiledata(&ptr, &len);

            if (verbosity > 1)
              DAPlogRcvMessage();

            switch (remRFM) {
              case DAP_RFM_VAR:
                /*
                 * For variable length records, we'll expect to receive one
                 * line in each Data message. For implied LF/CR attributes,
                 * we need to append a newline to each record.
                 */
                if (DAPexGetBit(remRAT, DAP_RAT_CR))
                  extra = '\n';
                break;
                
              case DAP_RFM_STM:
                /*
                 * For ASCII stream format, we'll translate any trailing
                 * <CR><LF> or <LF><CR> pairs into a single <LF>.
                 */
                if (len >= 2) {
                  if (((ptr[len - 2] == '\r') && (ptr[len - 1] == '\n')) ||
                      ((ptr[len - 2] == '\n') && (ptr[len - 1] == '\r'))) {
                    ptr[len - 2] = '\n';
                    len--;
                  }
                }
            }
            
            writelen = fwrite(ptr, sizeof(uint8_t), len, fp);
            if (writelen != len) {
              ReportError(DAP_MAC_XFER | DAP_MIC_IO_ER_WER);
              return 0;
            }
            if (extra != 0)
              if (fwrite(&extra, sizeof(uint8_t), 1, fp) != 1){
                ReportError(DAP_MAC_XFER | DAP_MIC_IO_ER_WER);
                return 0;
              }
            break;
          }
          ReportError(DAP_MAC_FORMAT | DAP_MIC_DATA_RECNUM);
          return 0;
          
        case DAP_MSG_COMPLETE:
          if (ProcessAccessCompleteMessage() == 0)
            return 0;
          if (fileStatus == FileOpenNone)
            return 1;
          break;
          
        default:
          ReportError(DAP_MAC_SYNC | type);
      }
    }
  }
  return 0;
}

int CloseFile(void)
{
  void *buf;
  
  if (fileStatus != FileOpenNone) {
    fclose(fp);
    fp = NULL;
    fileStatus = FileOpenNone;

    buf = DAPbuildHeader(DAP_MSG_COMPLETE);
    DAPbPut(buf, DAP_AFNC_RESPONSE);
    DAPwrite(buf);
  }
  return 0;
}

void DeleteFile(
  char *name,
  uint8_t *display
)
{
  void *buf;
  uint16_t status;
  
  if (unlink(name) == 0) {
    if ((display != NULL) && DAPexGetBit(display, DAP_DSP_NAME))
      DAPsendName(DAP_NAME_TYPE_FILESPEC, name);

    buf = DAPbuildHeader(DAP_MSG_COMPLETE);
    DAPbPut(buf, DAP_AFNC_RESPONSE);
    DAPwrite(buf);
    return;
  }

  /*
   * Delete failed, find a suitable error code
   */
  switch (errno) {
    case ENOENT:
      status = DAP_MAC_OPEN | DAP_MIC_IO_ER_FNF;
      break;

    case ENOTDIR:
      status = DAP_MAC_OPEN | DAP_MIC_IO_ER_DNF;
      break;

    case EACCES:
    case EPERM:
      status = DAP_MAC_OPEN | DAP_MIC_IO_ER_PRV;
      break;

    case EROFS:
      status = DAP_MAC_OPEN | DAP_MIC_IO_ER_WLK;
      break;
      
    default:
      status = DAP_MAC_OPEN | DAP_MIC_IO_UNSPEC;
      break;
  }
  ReportError(status);
}

void RenameFile(
  char *oldname,
  uint8_t *display
)
{
  struct stat statbuf;

  if (stat(oldname, &statbuf) == 0) {
    uint8_t type;
    
    if ((DAPnextMessage(&type) >= 0) && (type == DAP_MSG_NAME)) {
      uint8_t *nametype = NULL, *filespec = NULL;

      if (DAPexValid(&nametype, 3)) {
        char newname[256];
        uint16_t status;
        
        if (DAPiGet(&filespec, 200)) {
          if (verbosity > 1)
            DAPlogRcvMessage();

          DAPi2string(filespec, newname);

          if (rename(oldname, newname) == 0) {
            void *buf = DAPbuildHeader(DAP_MSG_COMPLETE);
            
            DAPbPut(buf, DAP_AFNC_RESPONSE);
            DAPwrite(buf);
            return;
          }

          /*
           * Rename failed, find a suitable error code
           */
          switch (errno) {
            case ENOTDIR:
              status = DAP_MAC_OPEN | DAP_MIC_IO_ER_DNF;
              break;
            
            case EACCES:
            case EPERM:
              status = DAP_MAC_OPEN | DAP_MIC_IO_ER_PRV;
              break;
              
            case EROFS:
              status = DAP_MAC_OPEN | DAP_MIC_IO_ER_WLK;
              break;

            case EXDEV:
              status = DAP_MAC_OPEN | DAP_MIC_IO_RENOVERDEVS;
              break;

            case ENOSPC:
              status = DAP_MAC_OPEN | DAP_MIC_IO_DIRFULL;
              break;
      
            default:
              status = DAP_MAC_OPEN | DAP_MIC_IO_UNSPEC;
              break;
          }
          ReportError(status);
        } else ReportError(DAP_MAC_FORMAT | DAP_MIC_NAME_NAMESPEC);
      } else ReportError(DAP_MAC_FORMAT | DAP_MIC_NAME_NAMETYPE);
    } else ReportError(DAP_MAC_SYNC | type);
  } else ReportError(DAP_MAC_OPEN | DAP_MIC_IO_ER_FNF);
}
