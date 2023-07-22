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
#include "dap.h"

#define BUFSIZ          8192
#define MIN(a,b)        (((a) < (b)) ? (a) : (b))

extern int verbosity;

uint8_t sndbuf[BUFSIZ], rcvbuf[BUFSIZ];

/*
 * Parameters extracted from received DAP messages.
 */
uint8_t remOS = 0, remFS = 0, remVersion[5], remSYSCAP[12], remLen = 0;
uint16_t bufferSize = BUFSIZ;

uint8_t remDATATYPE[2] = { (1 << DAP_DATATYPE_IMAGE) }, remORG = DAP_ORG_SEQ,
  remRFM = DAP_RFM_FIX, remRAT[3] = { 0 }, remMRS = DAP_MRS_DEFAULT,
  remBKS = DAP_BKS_DEFAULT, remFSZ = DAP_FSZ_DEFAULT, remFOP[6] = { 0 },
  remBSZ = DAP_BSZ_DEFAULT, remDEV[6] = { 0 }, remSDC[6] = { 0 };
uint16_t  remBLS = DAP_BLS_DEFAULT, remDEQ = DAP_DEQ_DEFAULT, remLRL, remFFB;
uint64_t remALQ = DAP_ALQ_DEFAULT, remMRN = DAP_MRN_DEFAULT, remHBK, remEBK,
  remSBN;
  
uint8_t config_seen = 0;

extern void ListDirectory(char *, uint8_t *), OpenFile(char *, uint8_t *),
  CreateFile(char *, uint8_t *), DeleteFile(char *, uint8_t *),
  RenameFile(char *, uint8_t *);
extern int ConnectToFile(void), GetFileData(void), PutFileData(void),
  CloseFile(void);

/*
 * Report an error to the remote system via a Status message
 */
void ReportError(
  uint16_t error
)
{
  void *buf = DAPbuildHeader(DAP_MSG_STATUS);
  
  DAP2bPut(buf, error);
  DAPbPut(buf, 0);
  DAPbPut(buf, 0);
  DAPbPut(buf, 0);

  DAPwrite(buf);
}

/*
 * Process a received Configuration message.
 */
int ProcessConfigurationMessage(void)
{
  void *buf;
  uint16_t bufsz;
  uint8_t *syscap;
  int i;
  
  if (config_seen++ == 0) {
    if (DAP2bGet(&bufsz)) {
      if (bufsz != 0)
        bufferSize = MIN(bufsz, BUFSIZ);

      if (DAPbGet(&remOS) && DAPbGet(&remFS)) {
        for (i = 0; i < sizeof(remVersion); i++)
          if (!DAPbGet(&remVersion[i]))
            return 0;

        if (DAPexValid(&syscap, 12)) {
          if (verbosity > 1)
            DAPlogRcvMessage();
          
          DAPexCopy(syscap, remSYSCAP, sizeof(remSYSCAP));

          if (DAPexGetBit(syscap, DAP_SYSCP_BLOCKING)) {
            remLen = 1;
            if (DAPexGetBit(syscap, DAP_SYSCP_2BYTELEN))
              remLen = 2;
          }
          
          /*
           * Create and send our configuration message.
           *
           * Note that TOPS-10 (and maybe TOPS-20) actually make use of
           * the OS and FS codes to decide how to format directory output.
           * Of course, they have no knowledge of the Linux codes I'm using
           * (I used some reserved for user codes) and default to an
           * unknown O/S and RMS-11 as the file system. If we see the remote
           * system is TOPS-10, we pretend to be Ultrix-32 which the TOPS-10
           * code understands and is able to format directory output
           * correctly.
           */
          buf = DAPbuildHeader(DAP_MSG_CONFIG);
          DAP2bPut(buf, BUFSIZ);
          if (remOS != DAP_OS_TOPS10) {
            DAPbPut(buf, DAP_OS_LINUX);
            DAPbPut(buf, DAP_FS_LINUX);
          } else {
            DAPbPut(buf, DAP_OS_ULTRIX);
            DAPbPut(buf, DAP_FS_ULTRIX);
          }
          DAPbPut(buf, DAP_VER_VERNUM);
          DAPbPut(buf, DAP_VER_ECONUM);
          DAPbPut(buf, DAP_VER_USRNUM);
          DAPbPut(buf, DAP_VER_SOFTVER);
          DAPbPut(buf, DAP_VER_USRSOFT);
          DAPexInit(buf, 12);
          DAPexSetBit(buf, DAP_SYSCP_SEQ);
          DAPexSetBit(buf, DAP_SYSCP_SEQXFER);
          DAPexSetBit(buf, DAP_SYSCP_APPEND);
          DAPexSetBit(buf, DAP_SYSCP_BLOCKING);
          DAPexSetBit(buf, DAP_SYSCP_2BYTELEN);
          DAPexSetBit(buf, DAP_SYSCP_DIRLIST);
          DAPexSetBit(buf, DAP_SYSCP_DATETIME);
          DAPexSetBit(buf, DAP_SYSCP_PROTECT);
//          DAPexSetBit(buf, DAP_SYSCP_SEQREC);
          DAPexSetBit(buf, DAP_SYSCP_RENAME);
          DAPexSetBit(buf, DAP_SYSCP_NAME);
          DAPexDone(buf);

          if (DAPwrite(buf) > 0)
            return 1;
        }
      }
    }
  } else ReportError(DAP_MAC_SYNC | DAP_MIC_SYNC_CONFIG);
  return 0;
}

/*
 * Process a received Access message
 */
int ProcessAccessMessage(void)
{
  uint8_t func, *opt = NULL, *filespec = NULL, *fac = NULL, *shr = NULL;
  uint8_t *display = NULL, *password = NULL;
  char name[256];
  uint8_t len;
  
  if (DAPbGet(&func)) {
    if (DAPexValid(&opt, 5)) {
      if (DAPiGet(&filespec, 255)) {
        if (DAPeom() || DAPexValid(&fac, 3)) {
          if (DAPeom() || DAPexValid(&shr, 3)) {
            if (DAPeom() || DAPexValid(&display, 4)) {
              if (DAPeom() || DAPiGet(&password, 40)) {
                if (verbosity > 1)
                  DAPlogRcvMessage();

                /*
                 * Convert the image format string into a NULL-terminated
                 * string
                 */
                DAPi2string(filespec, name);

                switch (func) {
                  case DAP_AFNC_OPEN:
                    /*
                     * TOPS-10 in some cases will open "*.*" and expect to get
                     * back a list of filenames.
                     */
                    if (remOS == DAP_OS_TOPS10) {
                      if (strchr(name, '*') != NULL) {
                        ListDirectory(name, display);
                        break;
                      }
                    }
                    OpenFile(name, display);
                    break;
                    
                  case DAP_AFNC_CREATE:
                    CreateFile(name, display);
                    break;
                    
                  case DAP_AFNC_RENAME:
                    RenameFile(name, display);
                    break;
                    
                  case DAP_AFNC_ERASE:
                    DeleteFile(name, display);
                    break;
                    
                  case DAP_AFNC_DIRLIST:
                    ListDirectory(name, display);
                    break;
                    
                  case DAP_AFNC_SUBMIT:
                  case DAP_AFNC_EXEC:
                    ReportError(DAP_MAC_UNSUPP | DAP_MIC_ACC_ACCFUNC);
                    return 0;
                }
                return 1;
              }
            }
          }
        }
      }
    }
  }
  return 0;
}

/*
 * Process a received Attributes message
 */
int ProcessAttributesMessage(void)
{
  uint8_t *attmenu = NULL, *datatype = NULL, org, rfm, *rat = NULL,
    *alq = NULL, *mrn = NULL, *runsys = NULL, *fop = NULL, *dev = NULL,
    *sdc = NULL, *hbk = NULL, *ebk = NULL, *sbn = NULL, bks, fsz, bsz;
  uint16_t bls, mrs, deq;
  uint16_t lrl, ffb;
  
  if (DAPexValid(&attmenu, 6)) {
    /*
     * Parse out the fields that are present
     */
    if (DAPexGetBit(attmenu, DAP_ATTR_DATATYPE))
      if (!DAPexValid(&datatype, 2))
        return 0;

    if (DAPexGetBit(attmenu, DAP_ATTR_ORG))
      if (!DAPbGet(&org))
        return 0;

    if (DAPexGetBit(attmenu, DAP_ATTR_RFM))
      if (!DAPbGet(&rfm))
        return 0;

    if (DAPexGetBit(attmenu, DAP_ATTR_RAT))
      if (!DAPexValid(&rat, 3))
        return 0;

    if (DAPexGetBit(attmenu, DAP_ATTR_BLS))
      if (!DAP2bGet(&bls))
        return 0;

    if (DAPexGetBit(attmenu, DAP_ATTR_MRS))
      if (!DAP2bGet(&mrs))
        return 0;

    if (DAPexGetBit(attmenu, DAP_ATTR_ALQ))
      if (!DAPiGet(&alq, 5))
        return 0;

    if (DAPexGetBit(attmenu, DAP_ATTR_BKS))
      if (!DAPbGet(&bks))
        return 0;

    if (DAPexGetBit(attmenu, DAP_ATTR_FSZ))
      if (!DAPbGet(&fsz))
        return 0;

    if (DAPexGetBit(attmenu, DAP_ATTR_MRN))
      if (!DAPiGet(&mrn, 5))
        return 0;

    if (DAPexGetBit(attmenu, DAP_ATTR_RUNSYS))
      if (!DAPiGet(&runsys, 40))
        return 0;

    if (DAPexGetBit(attmenu, DAP_ATTR_DEQ))
      if (!DAP2bGet(&deq))
        return 0;

    if (DAPexGetBit(attmenu, DAP_ATTR_FOP))
      if (!DAPexValid(&fop, 6))
        return 0;

    if (DAPexGetBit(attmenu, DAP_ATTR_BSZ))
      if (!DAPbGet(&bsz))
        return 0;

    if (DAPexGetBit(attmenu, DAP_ATTR_DEV))
      if (!DAPexValid(&dev, 6))
        return 0;

    if (DAPexGetBit(attmenu, DAP_ATTR_SDC))
      if (!DAPexValid(&sdc, 6))
        return 0;

    if (DAPexGetBit(attmenu, DAP_ATTR_LRL))
      if (!DAP2bGet(&lrl))
        return 0;

    if (DAPexGetBit(attmenu, DAP_ATTR_HBK))
      if (!DAPiGet(&hbk, 5))
        return 0;

    if (DAPexGetBit(attmenu, DAP_ATTR_EBK))
      if (!DAPiGet(&ebk, 5))
        return 0;

    if (DAPexGetBit(attmenu, DAP_ATTR_FFB))
      if (!DAP2bGet(&ffb))
        return 0;

    if (DAPexGetBit(attmenu, DAP_ATTR_SBN))
      if (!DAPiGet(&sbn, 5))
        return 0;

    if (verbosity > 1)
      DAPlogRcvMessage();

    /*
     * Update the attributes that will be used later.
     */
    if (datatype != NULL) {
      uint64_t tmpDatatype = DAPex2int(datatype);

      /*
       * Validate that only supported datatypes are present and only one
       * data type in selected.
       */
      if (tmpDatatype != 0) {
        uint64_t valid = (1 << DAP_DATATYPE_ASCII) | (1 << DAP_DATATYPE_IMAGE);

        if (((tmpDatatype & ~valid) != 0) || ((tmpDatatype & valid) == valid)) {
          ReportError(DAP_MAC_UNSUPP | DAP_MIC_ATTR_DATATYPE);
          return 1;
        }
      }
      DAPexCopy(datatype, remDATATYPE, sizeof(remDATATYPE));
    }

    if (DAPexGetBit(attmenu, DAP_ATTR_ORG))
      remORG = org;

    if (DAPexGetBit(attmenu, DAP_ATTR_RFM))
      remRFM = rfm;

    if (rat != NULL)
      DAPexCopy(rat, remRAT, sizeof(remRAT));

    if (DAPexGetBit(attmenu, DAP_ATTR_BLS))
      remBLS = bls;

    if (DAPexGetBit(attmenu, DAP_ATTR_MRS))
      remMRS = mrs;

    if (alq != NULL)
      remALQ = DAPi2int(alq);

    if (DAPexGetBit(attmenu, DAP_ATTR_BKS))
      remBKS = bks;

    if (DAPexGetBit(attmenu, DAP_ATTR_FSZ))
      remFSZ = fsz;

    if (mrn != NULL)
      remMRN = DAPi2int(mrn);

    if (DAPexGetBit(attmenu, DAP_ATTR_DEQ))
      remDEQ = deq;

    if (fop != NULL)
      DAPexCopy(fop, remFOP, sizeof(remFOP));

    if (DAPexGetBit(attmenu, DAP_ATTR_BSZ))
      remBSZ = bsz;

    if (dev != NULL)
      DAPexCopy(dev, remDEV, sizeof(remDEV));

    if (sdc != NULL)
      DAPexCopy(sdc, remSDC, sizeof(remSDC));

    if (DAPexGetBit(attmenu, DAP_ATTR_LRL))
      remLRL = lrl;

    if (hbk != NULL)
      remHBK = DAPi2int(hbk);

    if (ebk != NULL)
      remEBK = DAPi2int(ebk);

    if (DAPexGetBit(attmenu, DAP_ATTR_FFB))
      remFFB = ffb;

    if (sbn != NULL)
      remSBN = DAPi2int(sbn);

    return 1;
  }
  return 0;
}

/*
 * Process a received Control message.
 */
int ProcessControlMessage(void)
{
  uint8_t func = DAP_CFNC_GET, *ctlmenu = NULL, rac = 0, *key = NULL,
    krf = DAP_KRF_PRIMARY, *rop = NULL, *hsh = NULL, *display = NULL;

  if (DAPbGet(&func)) {
    if (DAPexValid(&ctlmenu, 4)) {
      /*
       * Parse out the fields that are present
       */
      if (DAPexGetBit(ctlmenu, DAP_CMNU_RAC))
        if (!DAPbGet(&rac))
          return 0;

      if (DAPexGetBit(ctlmenu, DAP_CMNU_KEY))
        if (!DAPiGet(&key, 255))
          return 0;

      if (DAPexGetBit(ctlmenu, DAP_CMNU_KRF))
        if (!DAPbGet(&krf))
          return 0;

      if (DAPexGetBit(ctlmenu, DAP_CMNU_ROP))
        if (!DAPexValid(&rop, 6))
          return 0;

      if (DAPexGetBit(ctlmenu, DAP_CMNU_HSH))
        if (!DAPiGet(&hsh, 5))
          return 0;

      if (DAPexGetBit(ctlmenu, DAP_CMNU_DISPLAY))
        if (!DAPexValid(&display, 4))
          return 0;
    }
  }

  if (verbosity > 1)
    DAPlogRcvMessage();

  switch (func) {
    case DAP_CFNC_GET:
      return GetFileData();
      
    case DAP_CFNC_CONNECT:
      return ConnectToFile();
      
    case DAP_CFNC_PUT:
      return PutFileData();
      
    case DAP_CFNC_UPDATE:
    case DAP_CFNC_DELETE:
    case DAP_CFNC_REWIND:
    case DAP_CFNC_TRUNCATE:
    case DAP_CFNC_MODIFY:
    case DAP_CFNC_RELEASE:
    case DAP_CFNC_FREE:
    case DAP_CFNC_FLUSH:
    case DAP_CFNC_NXTVOL:
    case DAP_CFNC_FIND:
    case DAP_CFNC_EXTEND:
    case DAP_CFNC_DISPLAY:
    case DAP_CFNC_FORWARD:
    case DAP_CFNC_BACKWARD:
      ReportError(DAP_MAC_UNSUPP | DAP_MIC_CTL_CTLFUNC);
  }
  return 0;
}

/*
 * Process a received Access Complete message.
 */
int ProcessAccessCompleteMessage(void)
{
  uint8_t func, *fop = NULL;
  uint16_t check;
  void *buf;
  
  if (DAPbGet(&func)) {
    if (DAPeom() || DAPexValid(&fop, 6)) {
      if (DAPeom() || DAP2bGet(&check)) {

        if (verbosity > 1)
          DAPlogRcvMessage();

        switch (func) {
          case DAP_AFNC_CLOSE:
            return CloseFile();
            
          case DAP_AFNC_ENDSTREAM:
            buf = DAPbuildHeader(DAP_MSG_COMPLETE);
            DAPbPut(buf, DAP_AFNC_RESPONSE);
            DAPwrite(buf);
            return 1;
            
          case DAP_AFNC_RESPONSE:
          case DAP_AFNC_PURGE:
          case DAP_AFNC_SKIP:
            ReportError(DAP_MAC_UNSUPP | DAP_MIC_COMP_CMPFUNC);
        }
      }
    }
  }
  return 0;
}

/*
 * Process a received Protection attributes extension message
 */
int ProcessProtectionAttributesMessage(void)
{
  uint8_t *protmenu = NULL, *owner = NULL, *protsys = NULL, *protown = NULL,
    *protgrp = NULL, *protwld = NULL;

  if (DAPexValid(&protmenu, 6)) {
    /*
     * Parse out the fields that are present
     */
    if (DAPexGetBit(protmenu, DAP_PMNU_OWNER))
      if (!DAPiGet(&owner, 40))
        return 0;

    if (DAPexGetBit(protmenu, DAP_PMNU_PROTSYS))
      if (!DAPexValid(&protsys, 3))
        return 0;

    if (DAPexGetBit(protmenu, DAP_PMNU_PROTOWN))
      if (!DAPexValid(&protown, 3))
        return 0;

    if (DAPexGetBit(protmenu, DAP_PMNU_PROTGRP))
      if (!DAPexValid(&protgrp, 3))
        return 0;

    if (DAPexGetBit(protmenu, DAP_PMNU_PROTWLD))
      if (!DAPexValid(&protwld, 3))
        return 0;

    if (verbosity > 1)
      DAPlogRcvMessage();
    
    /*
     * Update the protection codes that will be used later
     */
    /*** TODO ***/
    return 1;
  }
  return 0;
}

/*
 * Process a received Date and Time attributes extension message
 */
int ProcessDateTimeAttributesMessage(void)
{
  char cdtString[20] = { 0 }, rdtString[20] = { 0 }, edtString[20] = { 0 };
  uint8_t *datmenu = NULL, *cdt = NULL, *rdt = NULL, *edt = NULL;
  uint16_t rvn;
  
  if (DAPexValid(&datmenu, 6)) {
    if (DAPexGetBit(datmenu, DAP_DMNU_CDT))
      if (!DAPfGet(&cdt, 18))
        return 0;

    if (DAPexGetBit(datmenu, DAP_DMNU_RDT))
      if (!DAPfGet(&rdt, 18))
        return 0;

    if (DAPexGetBit(datmenu, DAP_DMNU_EDT))
      if (!DAPfGet(&edt, 18))
        return 0;

    if (DAPexGetBit(datmenu, DAP_DMNU_RVN))
      if (!DAP2bGet(&rvn))
        return 0;

    if (cdt != NULL)
      DAPf2string(cdt, 18, cdtString);
    if (rdt != NULL)
      DAPf2string(rdt, 18, rdtString);
    if (edt != NULL)
      DAPf2string(edt, 18, edtString);

    if (verbosity > 1)
      DAPlogRcvMessage();
    
    return 1;
  }
  return 0;
}

/*
 * Process requests from a socket until we get an error, the socket is closed
 * by the other end or we have completed processing. This routine handles the
 * first-level message processing which can initiate an operation.
 */
void process_request(
  int sock
)
{
  int status;
  
  DAPinit(sock, rcvbuf, BUFSIZ);
  
  /*
   * Wait until the first message is available from the client
   */
  status = DAPread();

  if ((status != -1) && (status != 0)) {
    for (;;) {
      uint8_t type;

      status = DAPnextMessage(&type);
      if ((status == -1) || (status == 0))
        break;

      switch (type) {
        case DAP_MSG_CONFIG:
          if (ProcessConfigurationMessage() <= 0)
            goto fail;
          break;
          
        case DAP_MSG_ACCESS:
          if (ProcessAccessMessage() <= 0)
            goto fail;
          break;
          
        case DAP_MSG_ATTRIBUTES:
          if (ProcessAttributesMessage() <= 0)
            goto fail;
          break;
          
        case DAP_MSG_CONTROL:
          if (ProcessControlMessage() <= 0)
            goto fail;
          break;
          
        case DAP_MSG_COMPLETE:
          if (ProcessAccessCompleteMessage() <= 0)
            goto fail;
          break;
          
        case DAP_MSG_PROTECT:
          if (ProcessProtectionAttributesMessage() <= 0)
            goto fail;
          break;
          
        case DAP_MSG_DATETIME:
          if (ProcessDateTimeAttributesMessage() <= 0)
            goto fail;
          break;
          
        case DAP_MSG_CONTINUE:
        case DAP_MSG_ACKNOWLEDGE:
        case DAP_MSG_DATA:
        case DAP_MSG_STATUS:
        case DAP_MSG_KEYDEF:
        case DAP_MSG_ALLOC:
        case DAP_MSG_SUMMARY:
        case DAP_MSG_NAME:
        case DAP_MSG_ACL:
          if (verbosity > 1)
            DAPlogUnexpectedMessage();
          
          ReportError(DAP_MAC_SYNC | type);
          break;
          
        default:
          ReportError(DAP_MAC_SYNC | DAP_MIC_SYNC_UNKNOWN);
          break;
      }
    }
  }
 fail:
  close(sock);
}
