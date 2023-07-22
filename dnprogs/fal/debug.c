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

static uint8_t *msgptr;
static int msglen;

/*
 * Structure to describe a bit or enumerated field.
 */
struct name {
  char                  *text;
  uint16_t              value;
};

/*
 * Configuration message:
 */
static struct name ostype[] = {
  { "Illegal", DAP_OS_ILLEGAL },
  { "RT11",  DAP_OS_RT11 },
  { "RSTS",  DAP_OS_RSTS },
  { "RSX-11S", DAP_OS_RSX11S },
  { "RSX-11M", DAP_OS_RSX11M },
  { "RSX-11D", DAP_OS_RSX11D },
  { "IAS",  DAP_OS_IAS },
  { "VAX/VMS", DAP_OS_VAXVMS },
  { "Tops-20", DAP_OS_TOPS20 },
  { "Tops-10", DAP_OS_TOPS10 },
  { "RTS-8", DAP_OS_RTS8 },
  { "OS/8", DAP_OS_OS8 },
  { "RSX-11M+", DAP_OS_RSX11MP },
  { "COPOS/11", DAP_OS_COPOS11 },
  { "P/OS", DAP_OS_POS },
  { "VAXELN", DAP_OS_VAXELN },
  { "CP/M", DAP_OS_CPM },
  { "MS/DOS", DAP_OS_MSDOS },
  { "Ultrix-32", DAP_OS_ULTRIX },
  { "Ultrix-11", DAP_OS_ULTRIX11 },
  { "Classic Mac/OS", DAP_OS_MACOS },
  { "OS/2", DAP_OS_OS2 },
  { "OSF/1", DAP_OS_OSF1 },
  { "Windows NT", DAP_OS_WIN_NT },
  { "Windows 95", DAP_OS_WIN_95 },
  { "Linux", DAP_OS_LINUX },
  { NULL }
},
filesys[] = {
  { "Illegal",  DAP_FS_ILLEGAL },
  { "RMS-11", DAP_FS_RMS_11 },
  { "RMS-20", DAP_FS_RMS_20 },
  { "RMS-32", DAP_FS_RMS_32 },
  { "FCS-11", DAP_FS_FCS_11 },
  { "RT-11", DAP_FS_RT11 },
  { "None", DAP_FS_NONE },
  { "Tops-20", DAP_FS_TOPS_20 },
  { "Tops-10", DAP_FS_TOPS_10 },
  { "OS/8", DAP_FS_OS8 },
  { "Ultrix-32", DAP_FS_ULTRIX },
  { "Linux", DAP_FS_LINUX },
  { NULL }
},
syscap[] = {
  { "File Preallocation", DAP_SYSCP_PREALLOC },
  { "Sequential files", DAP_SYSCP_SEQ },
  { "Relative files", DAP_SYSCP_REL },
  { "Direct files", DAP_SYSCP_DIRECT },
  { "Indexed files (1 key)", DAP_SYSCP_SINGLE },
  { "Sequential transfer", DAP_SYSCP_SEQXFER },
  { "Random access by record", DAP_SYSCP_RANRECNUM },
  { "Random access by VBN", DAP_SYSCP_RANVBN },
  { "Random access by key", DAP_SYSCP_RANKEY },
  { "Random access by hash", DAP_SYSCP_RANHASH },
  { "Random access by RFA", DAP_SYSCP_RANRFA },
  { "Indexed files (multiple keys)", DAP_SYSCP_MULTI },
  { "Switch access modes", DAP_SYSCP_SWITCH },
  { "Append to file", DAP_SYSCP_APPEND },
  { "Command file submission", DAP_SYSCP_CMDFILE_ACC },
  { "Data compression", DAP_SYSCP_COMPRESSION },
  { "Multiple data streams", DAP_SYSCP_MULTIPLE },
  { "Status return", DAP_SYSCP_STATUS },
  { "Message blocking", DAP_SYSCP_BLOCKING },
  { "Unrestricted blocking", DAP_SYSCP_UNRESTRICTED },
  { "2 byte length field", DAP_SYSCP_2BYTELEN },
  { "File checksum", DAP_SYSCP_CHECKSUM },
  { "Key definition attributes", DAP_SYSCP_KEYDEF },
  { "Allocation attributes", DAP_SYSCP_ALLOC },
  { "Summary attributes", DAP_SYSCP_SUMMARY },
  { "Directory list", DAP_SYSCP_DIRLIST },
  { "Date and Time attributes", DAP_SYSCP_DATETIME },
  { "File protection attributes", DAP_SYSCP_PROTECT },
  { "ACL attributes", DAP_SYSCP_ACL },
  { "Spooling (by FOP)", DAP_SYSCP_SPOOLING },
  { "Command file submission (by FOP)", DAP_SYSCP_CMDFILE },
  { "File deletion", DAP_SYSCP_FILE_DELETE },
  { "Default file specification", DAP_SYSCP_DEFAULT },
  { "Sequential record access", DAP_SYSCP_SEQREC },
  { "Transfer recovery", DAP_SYSCP_RECOVERY },
  { "BITCNT field", DAP_SYSCP_BITCNT },
  { "Warning status message", DAP_SYSCP_WARNING },
  { "File rename", DAP_SYSCP_RENAME },
  { "Wild card operations", DAP_SYSCP_WILDCARD },
  { "Go/No-Go option", DAP_SYSCP_GO_NOGO },
  { "Name message", DAP_SYSCP_NAME },
  { "Segmented messages", DAP_SYSCP_SEGMENTED },
  { NULL }
};

/*
 * Attributes message:
 */
static struct name attmenu[] = {
  { "DATATYPE", DAP_ATTR_DATATYPE },
  { "ORG", DAP_ATTR_ORG },
  { "RFM", DAP_ATTR_RFM },
  { "RAT", DAP_ATTR_RAT },
  { "BLS", DAP_ATTR_BLS },
  { "MRS", DAP_ATTR_MRS },
  { "ALQ", DAP_ATTR_ALQ },
  { "BKS", DAP_ATTR_BKS },
  { "FSZ", DAP_ATTR_FSZ },
  { "MRN", DAP_ATTR_MRN },
  { "RUNSYS", DAP_ATTR_RUNSYS },
  { "DEQ", DAP_ATTR_DEQ },
  { "FOP", DAP_ATTR_FOP },
  { "BSZ", DAP_ATTR_BSZ },
  { "DEV", DAP_ATTR_DEV },
  { "SDC", DAP_ATTR_SDC },
  { "LRL", DAP_ATTR_LRL },
  { "HBK", DAP_ATTR_HBK },
  { "EBK", DAP_ATTR_EBK },
  { "FFB", DAP_ATTR_FFB },
  { "SBN", DAP_ATTR_SBN },
  { NULL }
},
datatype[] = {
  { "ASCII", DAP_DATATYPE_ASCII },
  { "Image", DAP_DATATYPE_IMAGE },
  { "EBCDIC", DAP_DATATYPE_EBCDIC },
  { "Compressed", DAP_DATATYPE_COMPRESSED },
  { "Executable code", DAP_DATATYPE_EXEC },
  { "Privileged code", DAP_DATATYPE_PRIV },
  { "sensitive data", DAP_DATATYPE_SENSITIVE },
  { NULL }
},
org[] = {
  { "Sequential", DAP_ORG_SEQ },
  { "Relative", DAP_ORG_REL },
  { "Indexed", DAP_ORG_INDEXED },
  { "Hashed", DAP_ORG_HASHED },
  { NULL }
},
rfm[] = {
  { "Undefined", DAP_RFM_UDF },
  { "Fixed length", DAP_RFM_FIX },
  { "Variable length", DAP_RFM_VAR },
  { "Variable with fixed control", DAP_RFM_VFC },
  { "ASCII stream", DAP_RFM_STM },
  { NULL }
},
rat[] = {
  { "FORTRAN carriage control", DAP_RAT_FTN },
  { "Implied LF/CR envelope", DAP_RAT_CR },
  { "Print file carriage control", DAP_RAT_PRN },
  { "Records do not span blocks", DAP_RAT_BLK },
  { "Embedded carriage control", DAP_RAT_EMBED },
  { "COBOL carriage control", DAP_RAT_COBOL },
  { "Line sequenced ASCII", DAP_RAT_LSA },
  { "MACY11", DAP_RAT_MACY11 },
  { NULL }
},
fop[] = {
  { "Rewind on open", DAP_FOP_RWO },
  { "Rewind on close", DAP_FOP_RWC },
  { "Position MT after last file", DAP_FOP_POS },
  { "Don't lock file if improperly closed", DAP_FOP_DLK },
  { "File locked", DAP_FOP_LOCKED },
  { "Contiguous create", DAP_FOP_CTG },
  { "Supercede on create", DAP_FOP_SUP },
  { "Do not position MT to EOT", DAP_FOP_NEF },
  { "Create temporary file", DAP_FOP_TMP },
  { "Create temporary file and mark for delete", DAP_FOP_MKD },
  { "Rewind and dismount on close", DAP_FOP_DMO },
  { "Enable write checking", DAP_FOP_WCK },
  { "Enable read checking", DAP_FOP_RCK },
  { "Create if not present", DAP_FOP_CIF },
  { "Override file lock", DAP_FOP_LKO },
  { "Sequential access only", DAP_FOP_SQO },
  { "Max Version #", DAP_FOP_MXV },
  { "Spool file on close", DAP_FOP_SPL },
  { "Submit as command file", DAP_FOP_SCF },
  { "Delete on close", DAP_FOP_DLT },
  { "Contiguous best try", DAP_FOP_CBT },
  { "Wait if file locked", DAP_FOP_WAT },
  { "Deferred write", DAP_FOP_DFW },
  { "Truncate on close", DAP_FOP_TEF },
  { "Output file parse", DAP_FOP_OFP },
  { NULL }
},
dev[] = {
  { "Record oriented", DAP_DEV_REC },
  { "Carriage control device", DAP_DEV_CCL },
  { "Terminal", DAP_DEV_TRM },
  { "Directory structured", DAP_DEV_MDI },
  { "Single directory only", DAP_DEV_SDI },
  { "Sequential block device", DAP_DEV_SQD },
  { "Null device", DAP_DEV_NUL },
  { "File oriented device", DAP_DEV_FOD },
  { "Device can be shared", DAP_DEV_SHR },
  { "Device is being spooled", DAP_DEV_SPL },
  { "Device is mounted", DAP_DEV_MNT },
  { "Device marked for dismount", DAP_DEV_DMT },
  { "Device is allocated", DAP_DEV_ALL },
  { "Input device", DAP_DEV_IDV },
  { "Output device", DAP_DEV_ODV },
  { "Software write locked", DAP_DEV_SWL },
  { "Device available for use", DAP_DEV_AVL },
  { "Device has error logging", DAP_DEV_ELG },
  { "Device is a mailbox", DAP_DEV_MBX },
  { "Real-time device", DAP_DEV_RTM },
  { "Random access device", DAP_DEV_RAD },
  { "Read checking enabled", DAP_DEV_RCK },
  { "Write checking enabled", DAP_DEV_WCK },
  { "Foreign device", DAP_DEV_FOR },
  { "Network device", DAP_DEV_NET },
  { "Generic device", DAP_DEV_GEN },
  { NULL }
};

/*
 * Access message:
 */
static struct name accfunc[] = {
  { "Open existing file", DAP_AFNC_OPEN },
  { "Open new file", DAP_AFNC_CREATE },
  { "Rename a file", DAP_AFNC_RENAME },
  { "Delete a file", DAP_AFNC_ERASE },
  { "Directory list", DAP_AFNC_DIRLIST },
  { "Submit as a command (batch) file", DAP_AFNC_SUBMIT },
  { "Execute command (batch) file", DAP_AFNC_EXEC },
  { NULL }
},
accopt[] = {
  { "I/O errors non-fatal", DAP_OPT_NONFATAL },
  { "Status message on write record", DAP_OPT_WSTATUS },
  { "Status message on read record", DAP_OPT_RSTATUS },
  { "Compute/check checksums", DAP_OPT_CHECKSUM },
  { "Go/No-Go option", DAP_OPT_GO_NOGO },
  { NULL }
},
fac[] = {
  { "Put access", DAP_FAC_PUT },
  { "Get access", DAP_FAC_GET },
  { "Delete access", DAP_FAC_DEL },
  { "Update access", DAP_FAC_UPD },
  { "Truncate access", DAP_FAC_TRN },
  { "Block I/O access", DAP_FAC_BIO },
  { "Switch between block and record I/O", DAP_FAC_BRO },
  { NULL }
},
shr[] = {
  { "Put access", DAP_SHR_PUT },
  { "Get access", DAP_SHR_GET },
  { "Delete access", DAP_SHR_DEL },
  { "Update access", DAP_SHR_UPD },
  { "Enable multi-stream access", DAP_SHR_MSE },
  { "User provided locking", DAP_SHR_UPI },
  { "No shared access", DAP_SHR_NIL },
  { NULL }
},
display[] = {
  { "Main sttributes", DAP_DSP_MAIN },
  { "Key definition attributes", DAP_DSP_KEYDEF },
  { "Allocation attributes", DAP_DSP_ALLOC },
  { "Summary attributes", DAP_DSP_SUMMARY },
  { "Date and Time attributes", DAP_DSP_DATETIME },
  { "File protection attributes", DAP_DSP_PROTECT },
  { "ACL attributes", DAP_DSP_ACL },
  { "Resultant filespec name", DAP_DSP_NAME },
  { NULL }
};

/*
 * Control message:
 */
static struct name ctlfunc[] = {
  { "Get record or block", DAP_CFNC_GET },
  { "Initiate data stream", DAP_CFNC_CONNECT },
  { "Update current record", DAP_CFNC_UPDATE },
  { "Put record or block", DAP_CFNC_PUT },
  { "Delete current record", DAP_CFNC_DELETE },
  { "Rewind file", DAP_CFNC_REWIND },
  { "Truncate file", DAP_CFNC_TRUNCATE },
  { "Change attributes", DAP_CFNC_MODIFY },
  { "Unlock record", DAP_CFNC_RELEASE },
  { "Unlock all records", DAP_CFNC_FREE },
  { "Write modified buffers", DAP_CFNC_FLUSH },
  { "Volume processing", DAP_CFNC_NXTVOL },
  { "Find record", DAP_CFNC_FIND },
  { "Extend file", DAP_CFNC_EXTEND },
  { "Retrieve attributes", DAP_CFNC_DISPLAY },
  { "Forward space records", DAP_CFNC_FORWARD },
  { "Backward space records", DAP_CFNC_BACKWARD },
  { NULL }
},
ctlmenu[] = {
  { "Access mode", DAP_CMNU_RAC },
  { "Key value", DAP_CMNU_KEY  },
  { "Key of reference", DAP_CMNU_KRF },
  { "Optional processing features", DAP_CMNU_ROP },
  { "Hash code", DAP_CMNU_HSH },
  { "Attributes message(s)", DAP_CMNU_DISPLAY },
  { NULL }
},
rac[] = {
  { "Sequential record access", DAP_RAC_SEQ },
  { "Keyed access", DAP_RAC_KEY },
  { "Access by RFA", DAP_RAC_RFA },
  { "Sequential transfer for rest of file", DAP_RAC_SEQREST },
  { "Block mode via VBN", DAP_RAC_BMODEVBN },
  { "Block mode file transfer", DAP_RAC_BMODEXFER },
  { NULL }
},
rop[] = {
  { "Position to EOF", DAP_ROP_EOF },
  { "Fast record delete", DAP_ROP_FDL },
  { "Update existing records", DAP_ROP_UIF },
  { "Use hash code", DAP_ROP_HSH },
  { "Follow fill quantities", DAP_ROP_LOA },
  { "Manual locking", DAP_ROP_ULK },
  { "Truncate put", DAP_ROP_TPT },
  { "Read ahead", DAP_ROP_RAH },
  { "Write behind", DAP_ROP_WBH },
  { "Key is >=", DAP_ROP_KGE },
  { "Key is >", DAP_ROP_KGT },
  { "Do not lock record", DAP_ROP_NLK },
  { "Read locked record", DAP_ROP_RLK },
  { "Block I/O", DAP_ROP_BIO },
  { "Compare for key limit reached", DAP_ROP_LIM },
  { "Non-existant record processing", DAP_ROP_NXR },
  { NULL }
};

/*
 * Continue Transfer message:
 */
static struct name confunc[] = {
  { "Try again", DAP_CFNC_AGAIN },
  { "Skip and continue", DAP_CFNC_SKIP },
  { "Abort transfer", DAP_CFNC_ABORT },
  { "Resume processing", DAP_CFNC_RESUME },
  { NULL }
};

/*
 * Access Complete message:
 */
static struct name cmpfunc[] = {
  { "Close", DAP_AFNC_CLOSE },
  { "Response", DAP_AFNC_RESPONSE },
  { "Close and delete file", DAP_AFNC_PURGE },
  { "Terminate data stream", DAP_AFNC_ENDSTREAM },
  { "Close current, process next", DAP_AFNC_SKIP },
  { NULL }
};

/*
 * Status message:
 */
static struct name maccode[] = {
  { "Operation in progress",  DAP_MAC_PENDING >> 12 },
  { "Operation successful", DAP_MAC_SUCCESS >> 12 },
  { "Unsupported operation", DAP_MAC_UNSUPP >> 12 },
  { "File open error", DAP_MAC_OPEN >> 12 },
  { "File transfer error", DAP_MAC_XFER >> 12 },
  { "File transfer warning", DAP_MAC_WARN >> 12 },
  { "Access termination error", DAP_MAC_TERMIN >> 12 },
  { "Message format error", DAP_MAC_FORMAT >> 12 },
  { "Invalid message", DAP_MAC_INVALID >> 12 },
  { "Synchronization error", DAP_MAC_SYNC >>12 },
  { NULL }
},
miccodeA[] = {
  { "Unspecified error", DAP_MIC_MISC_USPEC },
  { "TYPE field error", DAP_MIC_MISC_TYPE },
  { "Configuration: Unknown field", DAP_MIC_CONF_UNKNOWN },
  { "Configuration: FLAGS field error", DAP_MIC_CONF_FLAGS },
  { "Configuration: STREAMID field error", DAP_MIC_CONF_STREAMID },
  { "Configuration: LENGTH field error", DAP_MIC_CONF_LENGTH },
  { "Configuration: LEN256 field error", DAP_MIC_CONF_LEN256 },
  { "Configuration: BITCNT field error", DAP_MIC_CONF_BITCNT },
  { "Configuration: BUFSIZ field error", DAP_MIC_CONF_BUFSIZ },
  { "Configuration: OSTYPE field error", DAP_MIC_CONF_OSTYPE },
  { "Configuration: FILESYS field error", DAP_MIC_CONF_FILESYS },
  { "Configuration: VERNUM field error", DAP_MIC_CONF_VERNUM },
  { "Configuration: ECONUM field error", DAP_MIC_CONF_ECONUM },
  { "Configuration: USRNUM field error", DAP_MIC_CONF_USRNUM },
  { "Configuration: SOFTVER field error", DAP_MIC_CONF_SOFTVER },
  { "Configuration: USRSOFT field error", DAP_MIC_CONF_USRSOFT },
  { "Configuration: SYSCAP field error", DAP_MIC_CONF_SYSCAP },
  
  { "Attributes: Unknown field", DAP_MIC_ATTR_UNKNOWN },
  { "Attributes: FLAGS field error", DAP_MIC_ATTR_FLAGS },
  { "Attributes: STREAMID field error", DAP_MIC_ATTR_STREAMID },
  { "Attributes: LENGTH field error", DAP_MIC_ATTR_LENGTH },
  { "Attributes: LEN256 field error", DAP_MIC_ATTR_LEN256 },
  { "Attributes: BITCNT field error", DAP_MIC_ATTR_BITCNT },
  { "Attributes: SYSPEC field error", DAP_MIC_ATTR_SYSPEC },
  { "Attributes: ATTMENU field error", DAP_MIC_ATTR_ATTMENU },
  { "Attributes: DATATYPE field error", DAP_MIC_ATTR_DATATYPE },
  { "Attributes: ORG field error", DAP_MIC_ATTR_ORG },
  { "Attributes: RFM field error", DAP_MIC_ATTR_RFM },
  { "Attributes: RAT field error", DAP_MIC_ATTR_RAT },
  { "Attributes: BLS field error", DAP_MIC_ATTR_BLS },
  { "Attributes: MRS field error", DAP_MIC_ATTR_MRS },
  { "Attributes: ALQ field error", DAP_MIC_ATTR_ALQ },
  { "Attributes: BKS field error", DAP_MIC_ATTR_BKS },
  { "Attributes: FSZ field error", DAP_MIC_ATTR_FSZ },
  { "Attributes: MRN field error", DAP_MIC_ATTR_MRN },
  { "Attributes: RUNSYS field error", DAP_MIC_ATTR_RUNSYS },
  { "Attributes: DEQ field error", DAP_MIC_ATTR_DEQ },
  { "Attributes: FOP field error", DAP_MIC_ATTR_FOP },
  { "Attributes: BSZ field error", DAP_MIC_ATTR_BSZ },
  { "Attributes: DEV field error", DAP_MIC_ATTR_DEV },
  { "Attributes: SDC field error", DAP_MIC_ATTR_SDC },
  { "Attributes: LRL field error", DAP_MIC_ATTR_LRL },
  { "Attributes: HBK field error", DAP_MIC_ATTR_HBK },
  { "Attributes: EBK field error", DAP_MIC_ATTR_EBK },
  { "Attributes: FFB field error", DAP_MIC_ATTR_FFB },
  { "Attributes: SBN field error", DAP_MIC_ATTR_SBN },

  { "Access: Unknown field error", DAP_MIC_ACC_UNKNOWN },
  { "Access: FLAGS field error", DAP_MIC_ACC_FLAGS },
  { "Access: STREAMID field error", DAP_MIC_ACC_STREAMID },
  { "Access: LENGTH field error", DAP_MIC_ACC_LENGTH },
  { "Access: LEN256 field error", DAP_MIC_ACC_LEN256 },
  { "Access: BITCNT field error", DAP_MIC_ACC_BITCNT },
  { "Access: SYSPEC field error", DAP_MIC_ACC_SYSPEC },
  { "Access: ACCFUNC field error", DAP_MIC_ACC_ACCFUNC },
  { "Access: ACCOPT field error", DAP_MIC_ACC_ACCOPT },
  { "Access: FILESPEC field error", DAP_MIC_ACC_FILESPEC },
  { "Access: FAC field error", DAP_MIC_ACC_FAC },
  { "Access: SHR field error", DAP_MIC_ACC_SHR },
  { "Access: DISPLAY field error", DAP_MIC_ACC_DISPLAY },
  { "Access: PASSWORD field error", DAP_MIC_ACC_PASSWORD },
  
  { "Control: Unknown field", DAP_MIC_CTL_UNKNOWN },
  { "Control: FLAGS field error", DAP_MIC_CTL_FLAGS },
  { "Control: STREAMID field error", DAP_MIC_CTL_STREAMID },
  { "Control: LENGTH field error", DAP_MIC_CTL_LENGTH },
  { "Control: LEN256 field error", DAP_MIC_CTL_LEN256 },
  { "Control: BITCNT field error", DAP_MIC_CTL_BITCNT },
  { "Control: SYSPEC field error", DAP_MIC_CTL_SYSPEC },
  { "Control: CTLFUNC field error", DAP_MIC_CTL_CTLFUNC },
  { "Control: CTLMENU field error", DAP_MIC_CTL_CTLMENU },
  { "Control: RAC field error", DAP_MIC_CTL_RAC },
  { "Control: KEY field error", DAP_MIC_CTL_KEY },
  { "Control: KRF field error", DAP_MIC_CTL_KRF },
  { "Control: ROP field error", DAP_MIC_CTL_ROP },
  { "Control: HSH field error", DAP_MIC_CTL_HSH },
  { "Control: DISPLAY field error", DAP_MIC_CTL_DISPLAY },
  
  { "Continue: Unknown field", DAP_MIC_CONT_UNKNOWN },
  { "Continue: FLAGS field error", DAP_MIC_CONT_FLAGS },
  { "Continue: STREAMID field error", DAP_MIC_CONT_STREAMID },
  { "Continue: LENGTH field error", DAP_MIC_CONT_LENGTH },
  { "Continue: LEN256 field error", DAP_MIC_CONT_LEN256 },
  { "Continue: BITCNT field error", DAP_MIC_CONT_BITCNT },
  { "Continue: SYSPEC field error", DAP_MIC_CONT_SYSPEC },
  { "Continue: CONFUNC field error", DAP_MIC_CONT_CONFUNC },
  
  { "Acknowledge: Unknown field", DAP_MIC_ACK_UNKNOWN },
  { "Acknowledge: FLAGS field error", DAP_MIC_ACK_FLAGS },
  { "Acknowledge: STREAMID field error", DAP_MIC_ACK_STREAMID },
  { "Acknowledge: LENGTH field error", DAP_MIC_ACK_LENGTH },
  { "Acknowledge: LEN256 field error", DAP_MIC_ACK_LEN256 },
  { "Acknowledge: BITCNT field error", DAP_MIC_ACK_BITCNT },
  { "Acknowledge: SYSPEC field error", DAP_MIC_ACK_SYSPEC },
  
  { "AccessComplete: Unknown field", DAP_MIC_COMP_UNKNOWN },
  { "AccessComplete: FLAGS field error", DAP_MIC_COMP_FLAGS },
  { "AccessComplete: STREAMID field error", DAP_MIC_COMP_STREAMID },
  { "AccessComplete: LENGTH field error", DAP_MIC_COMP_LENGTH },
  { "AccessComplete: LEN256 field error", DAP_MIC_COMP_LEN256 },
  { "AccessComplete: BITCNT field error", DAP_MIC_COMP_BITCNT },
  { "AccessComplete: SYSPEC field error", DAP_MIC_COMP_SYSPEC },
  { "AccessComplete: CMDFUNC field error", DAP_MIC_COMP_CMPFUNC },
  { "AccessComplete: FOP field error", DAP_MIC_COMP_FOP },
  { "AccessComplete: CHECK field error", DAP_MIC_COMP_CHECK },
  
  { "Data: Unknown field", DAP_MIC_DATA_UNKNOWN },
  { "Data: FLAGS field error", DAP_MIC_DATA_FLAGS },
  { "Data: STREAMID field error", DAP_MIC_DATA_STREAMID },
  { "Data: LENGTH field error", DAP_MIC_DATA_LENGTH },
  { "Data: LEN256 field error", DAP_MIC_DATA_LEN256 },
  { "Data: BITCNT field error", DAP_MIC_DATA_BITCNT },
  { "Data: SYSPEC field error", DAP_MIC_DATA_SYSPEC },
  { "Data: RECNUM field error", DAP_MIC_DATA_RECNUM },
  { "Data: FILEDATA field error", DAP_MIC_DATA_FILEDATA },
  
  { "Status: Unknown field", DAP_MIC_STAT_UNKNOWN },
  { "Status: FLAGS field error", DAP_MIC_STAT_FLAGS },
  { "Status: STREAMID field error", DAP_MIC_STAT_STREAMID },
  { "Status: LENGTH field error", DAP_MIC_STAT_LENGTH },
  { "Status: LEN256 field error", DAP_MIC_STAT_LEN256 },
  { "Status: BITCNT field error", DAP_MIC_STAT_BITCNT },
  { "Status: SYSPEC field error", DAP_MIC_STAT_SYSPEC },
  { "Status: MACCODE field error", DAP_MIC_STAT_MACCODE },
  { "Status: MICCODE field error", DAP_MIC_STAT_MICCODE },
  { "Status: RFA field error", DAP_MIC_STAT_RFA },
  { "Status: RECNUM field error", DAP_MIC_STAT_RECNUM },
  { "Status: STV field error", DAP_MIC_STAT_STV },
  
  { "Keydef: Unknown field", DAP_MIC_KDEF_UNKNOWN },
  { "Keydef: FLAGS field error", DAP_MIC_KDEF_FLAGS },
  { "Keydef: STREAMID field error", DAP_MIC_KDEF_STREAMID },
  { "Keydef: LENGTH field error", DAP_MIC_KDEF_LENGTH },
  { "Keydef: LEN256 field error", DAP_MIC_KDEF_LEN256 },
  { "Keydef: BITCNT field error", DAP_MIC_KDEF_BITCNT },
  { "Keydef: SYSPEC field error", DAP_MIC_KDEF_SYSPEC },
  { "Keydef: KEYMENU field error", DAP_MIC_KDEF_KEYMENU },
  { "Keydef: FLG field error", DAP_MIC_KDEF_FLG },
  { "Keydef: DFL field error", DAP_MIC_KDEF_DFL },
  { "Keydef: IFL field error", DAP_MIC_KDEF_IFL },
  { "Keydef: SEGCNT field error", DAP_MIC_KDEF_SEGCNT },
  { "Keydef: POS field error", DAP_MIC_KDEF_POS },
  { "Keydef: SIZ field error", DAP_MIC_KDEF_SIZ },
  { "Keydef: REF field error", DAP_MIC_KDEF_REF },
  { "Keydef: KNM field error", DAP_MIC_KDEF_KNM },
  { "Keydef: NUL field error", DAP_MIC_KDEF_NUL },
  { "Keydef: IAN field error", DAP_MIC_KDEF_IAN },
  { "Keydef: LAN field error", DAP_MIC_KDEF_LAN },
  { "Keydef: DAN field error", DAP_MIC_KDEF_DAN },
  { "Keydef: DTP field error", DAP_MIC_KDEF_DTP },
  { "Keydef: RVB field error", DAP_MIC_KDEF_RVB },
  { "Keydef: HAL field error", DAP_MIC_KDEF_HAL },
  { "Keydef: DVB field error", DAP_MIC_KDEF_DVB },
  { "Keydef: DBS field error", DAP_MIC_KDEF_DBS },
  { "Keydef: IBS field error", DAP_MIC_KDEF_IBS },
  { "Keydef: LVL field error", DAP_MIC_KDEF_LVL },
  { "Keydef: TKS field error", DAP_MIC_KDEF_TKS },
  { "Keydef: MRL field error", DAP_MIC_KDEF_MRL },
  
  { "Allocation: Unknown field", DAP_MIC_ALLO_UNKNOWN },
  { "Allocation: FLAGS field error", DAP_MIC_ALLO_FLAGS },
  { "Allocation: STREAMID field error", DAP_MIC_ALLO_STREAMID },
  { "Allocation: LENGTH field error", DAP_MIC_ALLO_LENGTH },
  { "Allocation: LEN256 field error", DAP_MIC_ALLO_LEN256 },
  { "Allocation: BITCNT field error", DAP_MIC_ALLO_BITCNT },
  { "Allocation: SYSPEC field error", DAP_MIC_ALLO_SYSPEC },
  { "Allocation: ALLMENU field error", DAP_MIC_ALLO_ALLMENU },
  { "Allocation: VOL field error", DAP_MIC_ALLO_VOL },
  { "Allocation: ALN field error", DAP_MIC_ALLO_ALN },
  { "Allocation: AOP field error", DAP_MIC_ALLO_AOP },
  { "Allocation: LOC field error", DAP_MIC_ALLO_LOC },
  { "Allocation: RFI field error", DAP_MIC_ALLO_RFI },
  { "Allocation: ALQ field error", DAP_MIC_ALLO_ALQ },
  { "Allocation: AID field error", DAP_MIC_ALLO_AID },
  { "Allocation: BKZ field error", DAP_MIC_ALLO_BKZ },
  { "Allocation: DEQ field error", DAP_MIC_ALLO_DEQ },
  
  { "Summary: Unknown field", DAP_MIC_SUMM_UNKNOWN },
  { "Summary: FLAGS field error", DAP_MIC_SUMM_FLAGS },
  { "Summary: STREAMID field error", DAP_MIC_SUMM_STREAMID },
  { "Summary: LENGTH field error", DAP_MIC_SUMM_LENGTH },
  { "Summary: LEN256 field error", DAP_MIC_SUMM_LEN256 },
  { "Summary: BITCNT field error", DAP_MIC_SUMM_BITCNT },
  { "Summary: SYSPEC field error", DAP_MIC_SUMM_SYSPEC },
  { "Summary: SUMENU field error", DAP_MIC_SUMM_SUMENU },
  { "Summary: NOK field error", DAP_MIC_SUMM_NOK },
  { "Summary: NOA field error", DAP_MIC_SUMM_NOA },
  { "Summary: NOR field error", DAP_MIC_SUMM_NOR },
  { "Summary: PVN field error", DAP_MIC_SUMM_PVN },
  
  { "DateTime: Unknown field", DAP_MIC_DTIM_UNKNOWN },
  { "DateTime: FLAGS field error", DAP_MIC_DTIM_FLAGS },
  { "DateTime: STREAMID field error", DAP_MIC_DTIM_STREAMID },
  { "DateTime: LENGTH field error", DAP_MIC_DTIM_LENGTH },
  { "DateTime: LEN256 field error", DAP_MIC_DTIM_LEN256 },
  { "DateTime: BITCNT field error", DAP_MIC_DTIM_BITCNT },
  { "DateTime: SYSPEC field error", DAP_MIC_DTIM_SYSPEC },
  { "DateTime: DATMENU field error", DAP_MIC_DTIM_DATMENU },
  { "DateTime: CDT field error", DAP_MIC_DTIM_CDT },
  { "DateTime: RDT field error", DAP_MIC_DTIM_RDT },
  { "DateTime: EDT field error", DAP_MIC_DTIM_EDT },
  { "DateTime: RVN field error", DAP_MIC_DTIM_RVN },
  
  { "Protection: Unknow field", DAP_MIC_PROT_UNKNOWN },
  { "Protection: FLAGS field error", DAP_MIC_PROT_FLAGS },
  { "Protection: STREAMID field error", DAP_MIC_PROT_STREAMID },
  { "Protection: LENGTH field error", DAP_MIC_PROT_LENGTH },
  { "Protection: LEN256 field error", DAP_MIC_PROT_LEN256 },
  { "Protection: BITCNT field error", DAP_MIC_PROT_BITCNT },
  { "Protection: SYSPEC field error", DAP_MIC_PROT_SYSPEC },
  { "Protection: PROTMENU field error", DAP_MIC_PROT_PROTMENU },
  { "Protection: OWNER field error", DAP_MIC_PROT_OWNER },
  { "Protection: PROTSYS field error", DAP_MIC_PROT_PROTSYS },
  { "Protection: PROTOWN field error", DAP_MIC_PROT_PROTOWN },
  { "Protection: PROTGRP field error", DAP_MIC_PROT_PROTGRP },
  { "Protection: PROTWLD field error", DAP_MIC_PROT_PROTWLD },
  
  { "Name: Unknown field", DAP_MIC_NAME_UNKNOWN },
  { "Name: FLAGS field error", DAP_MIC_NAME_FLAGS },
  { "Name: STREAMID field error", DAP_MIC_NAME_STREAMID },
  { "Name: LENGTH field error", DAP_MIC_NAME_LENGTH },
  { "Name: LEN256 field error", DAP_MIC_NAME_LEN256 },
  { "Name: BITCNT field error", DAP_MIC_NAME_BITCNT },
  { "Name: SYSPEC field error", DAP_MIC_NAME_SYSPEC },
  { "Name: NAMETYPE field error", DAP_MIC_NAME_NAMETYPE },
  { "Name: NAMESPEC field error", DAP_MIC_NAME_NAMESPEC },
  
  { "ACL: Unknown field", DAP_MIC_ACL_UNKNOWN },
  { "ACL: FLAGS field error", DAP_MIC_ACL_FLAGS },
  { "ACL: STREAMID field error", DAP_MIC_ACL_STREAMID },
  { "ACL: LENGTH field error", DAP_MIC_ACL_LENGTH },
  { "ACL: LEN256 field error", DAP_MIC_ACL_LEN256 },
  { "ACL: BITCNT field error", DAP_MIC_ACL_BITCNT },
  { "ACL: SYSPEC field error", DAP_MIC_ACL_SYSPEC },
  { "ACL: ACLCNT field error", DAP_MIC_ACL_ACLCNT },
  { "ACL: ACL field error", DAP_MIC_ACL_ACL },

  {NULL}
},
miccodeB[] = {
  { "Unspecified error", DAP_MIC_IO_UNSPEC },
  { "Operation aborted", DAP_MIC_IO_ER_ABO },
  { "F11ACP could not access file", DAP_MIC_IO_ER_ACC },
  { "File activity precludes operation", DAP_MIC_IO_ER_ACT },
  { "Bad area ID", DAP_MIC_IO_ER_AID },
  { "Alignment options error", DAP_MIC_IO_ER_ALN },
  { "Allocation quantity too large or zero", DAP_MIC_IO_ER_ALQ },
  { "Not ANSI D format", DAP_MIC_IO_ER_ANI },
  { "Allocation options error", DAP_MIC_IO_ER_AOP },
  { "Invalid operation at AST level", DAP_MIC_IO_ER_AST },
  { "Attribute read error", DAP_MIC_IO_ER_ATR },
  { "Attribute write error", DAP_MIC_IO_ER_ATW },
  { "Bucket size too large", DAP_MIC_IO_ER_BKS },
  { "Bucket size too large", DAP_MIC_IO_ER_BKZ },
  { "BLN length error", DAP_MIC_IO_ER_BLN },
  { "Beginning of file detected", DAP_MIC_IO_ER_BOF },
  { "Private pool address", DAP_MIC_IO_ER_BPA },
  { "Private pool size", DAP_MIC_IO_ER_BPS },
  { "Internal RMS error condition detected", DAP_MIC_IO_ER_BUG },
  { "Cannot connect RAB", DAP_MIC_IO_ER_CCR },
  { "$UPDATE changed key without XB$CHG set", DAP_MIC_IO_ER_CHG },
  { "Bucket format check-byte failure", DAP_MIC_IO_ER_CHK },
  { "RSTS/E close function failed", DAP_MIC_IO_ER_CLS },
  { "Invalid or unsupported COD field", DAP_MIC_IO_ER_COD },
  { "F11ACP could not create file", DAP_MIC_IO_ER_CRE },
  { "No current record (no prior GET/FIND)", DAP_MIC_IO_ER_CUR },
  { "F11ACP deaccess error during close", DAP_MIC_IO_ER_DAC },
  { "Data AREA number invalid", DAP_MIC_IO_ER_DAN },
  { "RFA-accessed record was deleted", DAP_MIC_IO_ER_DEL },
  { "Bad device or inappropriate device type", DAP_MIC_IO_ER_DEV },
  { "Error in directory name", DAP_MIC_IO_ER_DIR },
  { "Dynamic memory exhausted", DAP_MIC_IO_ER_DME },
  { "Directory not found", DAP_MIC_IO_ER_DNF },
  { "Device not ready", DAP_MIC_IO_ER_DNR },
  { "Device positioning error", DAP_MIC_IO_ER_DPE },
  { "DTP field invalid", DAP_MIC_IO_ER_DTP },
  { "Duplicate key detected, XB$DUP not set", DAP_MIC_IO_ER_DUP },
  { "F11ACP enter function failed", DAP_MIC_IO_ER_ENT },
  { "Operation not selected in ORG$ macro", DAP_MIC_IO_ER_ENV },
  { "End-of-file", DAP_MIC_IO_ER_EOF },
  { "Expanded string area too short", DAP_MIC_IO_ER_ESS },
  { "File expiration date not yer reached", DAP_MIC_IO_ER_EXP },
  { "File extend failure", DAP_MIC_IO_ER_EXT },
  { "Not a valid FAB", DAP_MIC_IO_ER_FAB },
  { "Illegal FAC for REC-OP", DAP_MIC_IO_ER_FAC },
  { "File already exists", DAP_MIC_IO_ER_FEX },
  { "Invalid file I.D.", DAP_MIC_IO_ER_FID },
  { "Invalid flags-bits combination", DAP_MIC_IO_ER_FLG },
  { "File locked by other user", DAP_MIC_IO_ER_FLK },
  { "F11ACP find function failed", DAP_MIC_IO_ER_FND },
  { "File not found", DAP_MIC_IO_ER_FNF },
  { "Error in file name", DAP_MIC_IO_ER_FNM },
  { "Invalid file options", DAP_MIC_IO_ER_FOP },
  { "Device/file full", DAP_MIC_IO_ER_FUL },
  { "Index AREA number invalid", DAP_MIC_IO_ER_IAN },
  { "Invalid IFI number or unopened file", DAP_MIC_IO_ER_IFI },
  { "Maximum NUM (254) areas/key XABS exceeded", DAP_MIC_IO_ER_IMX },
  { "$INIT macro never issued", DAP_MIC_IO_ER_INI },
  { "Operation illegal of invalid for file organization", DAP_MIC_IO_ER_IOP },
  { "Illegal record encountered", DAP_MIC_IO_ER_IRC },
  { "Invalid ISI value or unconnected RAB", DAP_MIC_IO_ER_ISI },
  { "Bad KEY buffer address (KBF = 0)", DAP_MIC_IO_ER_KBF },
  { "Invalid KEY field (KEY <= 0)", DAP_MIC_IO_ER_KEY },
  { "Invalid key-of-reference ($GET/$FIND)", DAP_MIC_IO_ER_KRF },
  { "KEY size too large", DAP_MIC_IO_ER_KSZ },
  { "Lowest-level-index AREA number invalid", DAP_MIC_IO_ER_LAN },
  { "Not ASNI labeled tape", DAP_MIC_IO_ER_LBL },
  { "Logical channel busy", DAP_MIC_IO_ER_LBY },
  { "Logical channel number too large", DAP_MIC_IO_ER_LCH },
  { "Logical extend error", DAP_MIC_IO_ER_LEX },
  { "LOC field invalid", DAP_MIC_IO_ER_LOC },
  { "Buffer mapping error", DAP_MIC_IO_ER_MAP },
  { "F11ACP could not mark file for deletion", DAP_MIC_IO_ER_MKD },
  { "MRN value negative or relative key > MRN", DAP_MIC_IO_ER_MRN },
  { "MRS value == 0", DAP_MIC_IO_ER_MRS },
  { "NAM  block address invalid or inaccessible", DAP_MIC_IO_ER_NAM },
  { "Not positioned to EOF", DAP_MIC_IO_ER_NEF },
  { "Cannot allocate internal index descriptor", DAP_MIC_IO_ER_NID },
  { "Index file; no primary key defined", DAP_MIC_IO_ER_NPK },
  { "RSTS/E open function failed", DAP_MIC_IO_ER_OPN },
  { "XAB's not in correct order", DAP_MIC_IO_ER_ORD },
  { "Invalid file organization value", DAP_MIC_IO_ER_ORG },
  { "Error in file's prologue", DAP_MIC_IO_ER_PLG },
  { "POS field invalid", DAP_MIC_IO_ER_POS },
  { "Bad file date field retrieved", DAP_MIC_IO_ER_PRM },
  { "Privilege violation", DAP_MIC_IO_ER_PRV },
  { "Not a valid RAB", DAP_MIC_IO_ER_RAB },
  { "Illegal RAC value", DAP_MIC_IO_ER_RAC },
  { "Illegal record attributes", DAP_MIC_IO_ER_RAT },
  { "Invalid record buffer address", DAP_MIC_IO_ER_RBF },
  { "File read error", DAP_MIC_IO_ER_RER },
  { "Record already exists", DAP_MIC_IO_ER_REX },
  { "Bad RFA value (RFA == 0)", DAP_MIC_IO_ER_RFA },
  { "Invalid record format", DAP_MIC_IO_ER_RFM },
  { "Target bucket locked by another stream", DAP_MIC_IO_ER_RLK },
  { "F11ACP remove function failed", DAP_MIC_IO_ER_RMV },
  { "Record not found", DAP_MIC_IO_ER_RNF },
  { "Record not locked", DAP_MIC_IO_ER_RNL },
  { "Invalid record options", DAP_MIC_IO_ER_ROP },
  { "Error while reading prologue", DAP_MIC_IO_ER_RPL },
  { "Invalid RRV record encountered", DAP_MIC_IO_ER_RRV },
  { "RAB stream currently active", DAP_MIC_IO_ER_RSA },
  { "Bad record size", DAP_MIC_IO_ER_RSZ },
  { "Record too big for user's buffer", DAP_MIC_IO_ER_RTB },
  { "Primary key out of sequence", DAP_MIC_IO_ER_SEQ },
  { "SHR field invalid for file", DAP_MIC_IO_ER_SHR },
  { "SIZ field invalid", DAP_MIC_IO_ER_SIZ },
  { "Stack too big for save area", DAP_MIC_IO_ER_STK },
  { "System directive error", DAP_MIC_IO_ER_SYS },
  { "Index tree error", DAP_MIC_IO_ER_TRE },
  { "Error in file type extension or FNS too big", DAP_MIC_IO_ER_TYP },
  { "Invalid user buffer address", DAP_MIC_IO_ER_UBF },
  { "Invalid user buffer size", DAP_MIC_IO_ER_USZ },
  { "Error in version number", DAP_MIC_IO_ER_VER },
  { "Invalid volume number", DAP_MIC_IO_ER_VOL },
  { "File write error", DAP_MIC_IO_ER_WER },
  { "Device is write locked", DAP_MIC_IO_ER_WLK },
  { "Error while writong prologue", DAP_MIC_IO_ER_WPL },
  { "Not a valid XAB", DAP_MIC_IO_ER_XAB },
  { "Default directory invalid", DAP_MIC_IO_BUGDDI },
  { "Cannot access argument list", DAP_MIC_IO_CAA },
  { "Cannot close file", DAP_MIC_IO_CCF },
  { "Cannot deliver AST", DAP_MIC_IO_CDA },
  { "Channel assignment failure", DAP_MIC_IO_CHN },
  { "Terminal output ignored due to ^O", DAP_MIC_IO_CNTRLO },
  { "Terminal output aborted due to ^Y", DAP_MIC_IO_CNTRLY },
  { "Default filename string address error", DAP_MIC_IO_DNA },
  { "Invalid device I.D. field", DAP_MIC_IO_DVI },
  { "Expanded string address error", DAP_MIC_IO_ESA },
  { "Filename string address error", DAP_MIC_IO_FNA },
  { "FSZ field invalid", DAP_MIC_IO_FSZ },
  { "Invalid argument list", DAP_MIC_IO_IAL },
  { "Known file found", DAP_MIC_IO_KFF },
  { "Logical name error", DAP_MIC_IO_LNE },
  { "Node name error", DAP_MIC_IO_NOD },
  { "Operation successful", DAP_MIC_IO_NORMAL },
  { "Record inserted had duplicate key", DAP_MIC_IO_OK_DUP },
  { "Index update error - record inserted", DAP_MIC_IO_OK_IDX },
  { "Record locked but read anyway", DAP_MIC_IO_OK_RLK },
  { "Record inserted in  primary", DAP_MIC_IO_OK_RRV },
  { "File was created but not opened", DAP_MIC_IO_CREATE },
  { "Bad prompt buffer address", DAP_MIC_IO_PBF },
  { "Async. operation  pending completion", DAP_MIC_IO_PNDING },
  { "Quoted string error", DAP_MIC_IO_QUO },
  { "Record header buffer invalid", DAP_MIC_IO_RHB },
  { "Invalid related file", DAP_MIC_IO_RLF },
  { "Invalid resultant string size", DAP_MIC_IO_RSS },
  { "Invalid resultant string address", DAP_MIC_IO_RST },
  { "Operation not sequential", DAP_MIC_IO_SQO },
  { "Operation successful", DAP_MIC_IO_SUC },
  { "Created file superceded existing version", DAP_MIC_IO_SPRSED },
  { "Filename syntax error", DAP_MIC_IO_SYN },
  { "Time-out period expired", DAP_MIC_IO_TMO },
  { "FB$BLK record attribute not supported", DAP_MIC_IO_ER_BLK },
  { "Bad byte size", DAP_MIC_IO_ER_BSZ },
  { "Cannot disconnect RAB", DAP_MIC_IO_ER_CDR },
  { "Cannot get JFN for file", DAP_MIC_IO_ER_CGJ },
  { "Cannot open file", DAP_MIC_IO_ER_COF },
  { "Bad JFN value", DAP_MIC_IO_ER_JFN },
  { "Cannot position to EOF", DAP_MIC_IO_ER_PEF },
  { "Cannot truncate file", DAP_MIC_IO_ER_TRU },
  { "File in undefined state, access denied", DAP_MIC_IO_ER_UDF },
  { "File must be opened for exclusive access", DAP_MIC_IO_ER_XCL },
  { "Directory full", DAP_MIC_IO_DIRFULL },
  { "Handler not in system", DAP_MIC_IO_NOHANDLER },
  { "Fatal hardware error", DAP_MIC_IO_FATAL },
  { "Attempt to write beyond EOF", DAP_MIC_IO_BEYONDEOF },
  { "Hardware option not present", DAP_MIC_IO_NOTPRESENT },
  { "Device not attached", DAP_MIC_IO_NOTATTACHED },
  { "Device already attached", DAP_MIC_IO_ATTACHED },
  { "Device not attachable", DAP_MIC_IO_NOATTACH },
  { "Shareable resource in use", DAP_MIC_IO_SHRINUSE },
  { "Illegal overlay request", DAP_MIC_IO_ILLEGALOVR },
  { "Block check or CRC error", DAP_MIC_IO_CRCERROR },
  { "Caller's nodes exhausted", DAP_MIC_IO_NONODES },
  { "Index file full", DAP_MIC_IO_IDXFULL },
  { "File header full", DAP_MIC_IO_HDRFULL },
  { "Accessed for write", DAP_MIC_IO_WRACCESSED },
  { "File header checksum failure", DAP_MIC_IO_HDRCHECKSUM },
  { "Attribute control list error", DAP_MIC_IO_BADATTRIB },
  { "File already accessed on LUN", DAP_MIC_IO_LUNACCESS },
  { "Bad tape format", DAP_MIC_IO_BADTAPE },
  { "Illegal operation on file descriptor block", DAP_MIC_IO_BADOP },
  { "Rename; 2 different devices", DAP_MIC_IO_RENOVERDEVS },
  { "Rename; new filename already in use", DAP_MIC_IO_RENNAMEUSE },
  { "Cannot rename old file system", DAP_MIC_IO_RENOLDFS },
  { "File already open", DAP_MIC_IO_FILEOPEN },
  { "Parity error on device", DAP_MIC_IO_PARITY },
  { "End of volume detected", DAP_MIC_IO_EOV },
  { "Data over-run", DAP_MIC_IO_OVERRUN },
  { "Bad block on device", DAP_MIC_IO_BADBLOCK },
  { "End of tape detected", DAP_MIC_IO_ENDTAPE },
  { "No buffer space for file", DAP_MIC_IO_NOBUFFER },
  { "File exceeds allocated space - no blocks", DAP_MIC_IO_NOBLOCKS },
  { "Specified task not installed", DAP_MIC_IO_NOTINSTALLED },
  { "Unlock error", DAP_MIC_IO_UNLOCK },
  { "No file accessed on LUN", DAP_MIC_IO_NOFILE },
  { "Send/receive failure", DAP_MIC_IO_SRERROR },
  { "Spool or submit command file failure", DAP_MIC_IO_SPL },
  { "No more files", DAP_MIC_IO_NMF },
  { "DAP file transfer checksum error", DAP_MIC_IO_CRC },
  { "Quota exceeded", DAP_MIC_IO_QUOTA },
  { "Internal network error condition detected", DAP_MIC_IO_BUGDAP },
  { "Terminal input aborted due to ^C", DAP_MIC_IO_CNTRLC },
  { "Data bucket fill size > bucket size in XAB", DAP_MIC_IO_DFL },
  { "Invalid expanded string length", DAP_MIC_IO_ESL },
  { "Illegal bucket format", DAP_MIC_IO_IBF },
  { "Bucket size of LAN != IAN in XAB", DAP_MIC_IO_IBK },
  { "Index not initialized", DAP_MIC_IO_IDX },
  { "Illegal file attributes (corrupt file header)", DAP_MIC_IO_IFA },
  { "Index bucket fill size > bucket size in XAB", DAP_MIC_IO_IFL },
  { "Key name bucket not readable/writeable in XAB", DAP_MIC_IO_KNM },
  { "Index bucket will not hold 2 keys for key of reference", DAP_MIC_IO_KSI },
  { "Multi-buffer count invalid", DAP_MIC_IO_MBC },
  { "Network operation failed at remote node", DAP_MIC_IO_NET },
  { "Record is already locked", DAP_MIC_IO_OK_ALK },
  { "Deleted record successfully accessed", DAP_MIC_IO_OK_DEL },
  { "Retrieved record exceeds specified key value", DAP_MIC_IO_OK_LIM },
  { "Key XAB not filled in", DAP_MIC_IO_OK_NOP },
  { "Nonexistant record successfully accessed", DAP_MIC_IO_OK_RNF },
  { "Unsupported prologue version", DAP_MIC_IO_PLV },
  { "Illegal key-of-reference in XAB", DAP_MIC_IO_REF },
  { "Invalid resultant string length", DAP_MIC_IO_RSL },
  { "Error updating RRV's, some paths to data may be lost", DAP_MIC_IO_RVU },
  { "Data types other than string limited to one segmen in XAB", DAP_MIC_IO_SEG },
  { "Reserved", DAP_MIC_IO_RSVD1 },
  { "Operation not supported over network", DAP_MIC_IO_SUP },
  { "Error on write behind", DAP_MIC_IO_WBE },
  { "Invalid wildcard operation", DAP_MIC_IO_WLD },
  { "Working set full", DAP_MIC_IO_WSF },
  { "Directory list - error reading name(s)", DAP_MIC_IO_DIRLSTNAME },
  { "Directory list - error reading attributes", DAP_MIC_IO_DIRLSTATTR },
  { "Directory list - protection violation, name(s)", DAP_MIC_IO_DIRLSTPROT },
  { "Directory list - protection violation, attributes", DAP_MIC_IO_DIRLSTPROTA },
  { "Directory list - attributes do not exist", DAP_MIC_IO_DIRLSTNOATTR },
  { "Directory list - recovery failed after Continue Transfer", DAP_MIC_IO_DIRLSTXFER },
  { "Sharing not enabled", DAP_MIC_IO_SNE },
  { "Sharing page count exceeded", DAP_MIC_IO_SPE },
  { "UPI bit not set when sharing with BRO set", DAP_MIC_IO_UPI },
  { "Error in access control string (PMR error)", DAP_MIC_IO_ACS },
  { "Terminator not seen", DAP_MIC_IO_TNS },
  { "Bad escape sequence", DAP_MIC_IO_BES },
  { "Partial escape sequence", DAP_MIC_IO_PES },
  { "Invalid wildcard context value", DAP_MIC_IO_WCC },
  { "Invalid directory rename operation", DAP_MIC_IO_IDR },
  { "User structure FAB/RAB became invalid", DAP_MIC_IO_STR },
  { "Network file transfer mode precludes operation", DAP_MIC_IO_FTM },
  
  { NULL }
},
miccodeC[] = {
  { "Unknown message type", DAP_MIC_SYNC_UNKNOWN },
  { "Configuration message", DAP_MIC_SYNC_CONFIG },
  { "Attributes message", DAP_MIC_SYNC_ATTRIB },
  { "Access message", DAP_MIC_SYNC_ACCESS },
  { "Control message", DAP_MIC_SYNC_CONTROL },
  { "Continue Transfer message", DAP_MIC_SYNC_CONTINUE },
  { "Acknowledge message", DAP_MIC_SYNC_ACK },
  { "Access Complete message", DAP_MIC_SYNC_COMPLETE },
  { "Data message", DAP_MIC_SYNC_DATA },
  { "Status message", DAP_MIC_SYNC_STATUS },
  { "Key Definition Attributes message", DAP_MIC_SYNC_KEYDEF },
  { "Allocation Attributes message", DAP_MIC_SYNC_ALLOC },
  { "Summary Attributes message", DAP_MIC_SYNC_SUMMARY },
  { "Date and Time Attributes message", DAP_MIC_SYNC_DTIME },
  { "Protection Attributes message", DAP_MIC_SYNC_PROTECT },
  { "Name message", DAP_MIC_SYNC_NAME },
  { "Access Control List Attributes message", DAP_MIC_SYNC_ACL },

  { NULL }
};

/*
 * Key Definition Attributes message:
 */
static struct name keymenu[] = {
  { "FLG", DAP_KMNU_FLG },
  { "DFL", DAP_KMNU_DFL },
  { "IFL", DAP_KMNU_IFL },
  { "NSG, POS and SIZ", DAP_KMNU_NSG },
  { "REF", DAP_KMNU_REF },
  { "KNM", DAP_KMNU_KNM },
  { "NUL", DAP_KMNU_NUL },
  { "IAN", DAP_KMNU_IAN },
  { "LAN", DAP_KMNU_LAN },
  { "DAN", DAP_KMNU_DAN },
  { "DTP", DAP_KMNU_DTP },
  { "RVB", DAP_KMNU_RVB },
  { "HAL", DAP_KMNU_HAL },
  { "DVB", DAP_KMNU_DVB },
  { "DBS", DAP_KMNU_DBS },
  { "IBS", DAP_KMNU_IBS },
  { "LVL", DAP_KMNU_LVL },
  { "TKS", DAP_KMNU_TKS },
  { "MRL", DAP_KMNU_MRL },
  { NULL }
},
flg[] = {
  { "Duplicates allowed", DAP_KEY_OPT_DUP },
  { "Allow keys to change", DAP_KEY_OPT_CHG },
  { "Null key character defined", DAP_KEY_OPT_NUL },
  { NULL }
};

/*
 * Allocation Attributes message:
 */
static struct name allmenu[] = {
  { "VOL", DAP_AMNU_VOL },
  { "ALN", DAP_AMNU_ALN },
  { "AOP", DAP_AMNU_AOP },
  { "LOC", DAP_AMNU_LOC },
  { "RFI", DAP_AMNU_RFI },
  { "ALQ", DAP_AMNU_ALQ },
  { "AID", DAP_AMNU_AID },
  { "BKZ", DAP_AMNU_BKZ },
  { "DEQ", DAP_AMNU_DEQ },
  { NULL }
},
aln[] = {
  { "No specified allocation placement", DAP_ALLOC_ALN_ANY },
  { "Align on cylinder boundary", DAP_ALLOC_ALN_CYL },
  { "Align to specified logical block", DAP_ALLOC_ALN_LBN },
  { "Allocate as near as possible to specified virtual block", DAP_ALLOC_ALN_VBN },
  { "Allocate as near as possible to specified related file", DAP_ALLOC_ALN_RFI },
  { NULL }
},
aop[] = {
  { "Return error if requested alignment fails", DAP_ALLOC_AOP_HRD },
  { "Contiguous allocation request", DAP_ALLOC_AOP_CTG },
  { "Contiguous best try allocation request", DAP_ALLOC_AOP_CBT },
  { "Allocate space on any cylinder boundary", DAP_ALLOC_AOP_ONC },
  { NULL }
};

/*
 * Summary Attributes message:
 */
static struct name sumenu[] = {
  { "NOK", DAP_SMNU_NOK },
  { "NOA", DAP_SMNU_NOA },
  { "NOR", DAP_SMNU_NOR },
  { "PVN", DAP_SMNU_PVN },
  { NULL }
};

/*
 * Date and Time Attributes message:
 */
static struct name datmenu[] = {
  { "Creation date/time", DAP_DMNU_CDT },
  { "Last update date/time", DAP_DMNU_RDT },
  { "Deletion allowed after date/time", DAP_DMNU_EDT },
  { "File revision number", DAP_DMNU_RVN },
  { NULL }
};

/*
 * Protection Attributes message:
 */
static struct name protmenu[] = {
  { "OWNER", DAP_PMNU_OWNER },
  { "PROTSYS", DAP_PMNU_PROTSYS },
  { "PROTOWN", DAP_PMNU_PROTOWN },
  { "PROTGRP", DAP_PMNU_PROTGRP },
  { "PROTWLD", DAP_PMNU_PROTWLD },
  { NULL }
},
prot[] = {
  { "Deny read access", DAP_PROT_DENY_READ },
  { "Deny write access", DAP_PROT_DENY_WRITE },
  { "Deny execute access", DAP_PROT_DENY_EXEC },
  { "Deny delete access", DAP_PROT_DENY_DELETE },
  { "Deny append access", DAP_PROT_DENY_APPEND },
  { "Deny directory list access", DAP_PROT_DENY_DIRLIST },
  { "Deny update access", DAP_PROT_DENY_UPDATE },
  { "Deny protection change access", DAP_PROT_DENY_CHANGE },
  { "Deny extend access", DAP_PROT_DENY_EXTEND },
  { NULL }
};

/*
 * Name message:
 */
static struct name nametype[] = {
  { "File specification", DAP_NAME_TYPE_FILESPEC },
  { "File name", DAP_NAME_TYPE_FILENAME },
  { "Directory name", DAP_NAME_TYPE_DIRECTORY },
  { "Volume/structure name", DAP_NAME_TYPE_VOLUME },
  { "Default file specification", DAP_NAME_TYPE_DEFAULT },
  { "Related file specification", DAP_NAME_TYPE_RELATED },
  { NULL }
};

/*
 * Get a single byte value and skip over it.
 */
static uint8_t DBGbGet(void)
{
  uint8_t result = *msgptr++;

  msglen--;
  return result;
}

/*
 * Get a two byte value and skip over it.
 */
static uint16_t DBG2bGet(void)
{
  uint16_t result = *msgptr++;

  result |= (*msgptr++ << 8);
  msglen -= 2;
  return result;
}

/*
 * Display a single byte field. If "names" is NULL or the value is not found
 * in  the table, display the value (base == 0, octal; base != 0, decimal).
 */
static void DBGb(
  char *hdr,
  struct name *names,
  uint8_t value,
  uint8_t base
)
{
  if (names != NULL) {
    while (names->text != NULL) {
      if (names->value == value) {
        dnetlog(LOG_DEBUG, "%s:  %s\n", hdr, names->text);
        return;
      }
      names++;
    }
  }
  dnetlog(LOG_DEBUG, base ? "%s:  %3u\n" : "%s:  %04o\n", hdr, value);
}

/*
 * Display a two byte field. If "names" is NULL or the value is not found
 * in  the table, display the value (base == 0, octal; base != 0, decimal).
 */
static void DBG2b(
  char *hdr,
  struct name *names,
  uint16_t value,
  uint8_t base
)
{
  if (names != NULL) {
    while (names->text != NULL) {
      if (names->value == value) {
        dnetlog(LOG_DEBUG, "%s:  %s\n", hdr, names->text);
        return;
      }
      names++;
    }
  }
  dnetlog(LOG_DEBUG, base ? "%s:  %5u\n" : "%s:  %07o\n", hdr, value);
}

/*
 * Display a uint64_t field in decimal.
 */
static void DBG64(
  char *hdr,
  uint64_t value
)
{
  dnetlog(LOG_DEBUG, "%s:  %llu\n", hdr, value);
}

/*
 * Display a text string field.
 */
static void DBGstring(
  char *hdr,
  char *text
)
{
  dnetlog(LOG_DEBUG, "%s:  %s\n", hdr, text);
}

/*
 * Display extensible format values.
 */
static void DBGex(
  char *hdr,
  struct name *names,
  uint8_t *ex
)
{
  char buf[128];

  sprintf(buf, "%s:  ", hdr);

  while (names->text != NULL) {
    if (DAPexGetBit(ex, names->value)) {
      size_t len;
      
      sprintf(&buf[strlen(buf)], "%s, ", names->text);
      if ((len = strlen(buf)) > 50) {
        buf[len - 2] = '\n';
        buf[len - 1] = '\0';
        dnetlog(LOG_DEBUG, buf);
        buf[0] = '\0';
      }
    }
    names++;
  }
  if (buf[0] != '\0') {
    size_t len = strlen(buf);
    
    buf[len - 2] = '\n';
    buf[len - 1] = '\0';
    dnetlog(LOG_DEBUG, buf);
  }
}

/*
 * Get pointer to extensible field while skipping over it.
 */
static uint8_t *DBGexSkip(void)
{
  uint8_t *result = msgptr;

  while ((*msgptr++ & DAP_EXTEND) != 0)
    msglen--;

  msglen--;
  return result;
}

/*
 * Get pointer to an image field while skipping over it.
 */
static uint8_t *DBGiSkip(void)
{
  uint8_t *result = msgptr;
  uint8_t len = *msgptr;

  msgptr += len + 1;
  msglen -= len + 1;
  return result;
}

/*
 * Get pointer to a fixed length field while skipping over it.
 */
static uint8_t *DBGfSkip(
  uint16_t len
)
{
  uint8_t *result = msgptr;

  msgptr += len;
  msglen -= len;
  return result;
}

/*
 * Display Configuration message information.
 */
static void DBGconfiguration(void)
{
  uint8_t vernum, econum, usrnum, softver, usrsoft;
  
  DBG2b("BUFSIZ", NULL, DBG2bGet(), 1);
  DBGb("OSTYPE", ostype, DBGbGet(), 1);
  DBGb("FILESYS", filesys, DBGbGet(), 1);

  vernum = DBGbGet();
  econum = DBGbGet();
  usrnum = DBGbGet();
  softver = DBGbGet();
  usrsoft = DBGbGet();

  dnetlog(LOG_DEBUG, "VERSION:  %d.%d.%d (Softver: %d, Usrsoft: %d)\n",
          vernum, econum, usrnum, softver, usrsoft);

  DBGex("SYSCAP", syscap, msgptr);
}

/*
 * Display Attributes message information.
 */
static void DBGattributes(void)
{
  uint8_t *menu = DBGexSkip();

  DBGex("ATTMENU", attmenu, menu);
  if (DAPexGetBit(menu, DAP_ATTR_DATATYPE))
    DBGex("DATATYPE", datatype, DBGexSkip());
  if (DAPexGetBit(menu, DAP_ATTR_ORG))
    DBGb("ORG", org, DBGbGet(), 0);
  if (DAPexGetBit(menu, DAP_ATTR_RFM))
    DBGb("RFM", rfm, DBGbGet(), 0);
  if (DAPexGetBit(menu, DAP_ATTR_RAT))
    DBGex("RAT", rat, DBGexSkip());
  if (DAPexGetBit(menu, DAP_ATTR_BLS))
    DBG2b("BLS", NULL, DBG2bGet(), 1);
  if (DAPexGetBit(menu, DAP_ATTR_MRS))
    DBG2b("MRS", NULL, DBG2bGet(), 1);
  if (DAPexGetBit(menu, DAP_ATTR_ALQ))
    DBG64("ALQ", DAPi2int(DBGiSkip()));
  if (DAPexGetBit(menu, DAP_ATTR_BKS))
    DBGb("BKS", NULL, DBGbGet(), 1);
  if (DAPexGetBit(menu, DAP_ATTR_FSZ))
    DBGb("FSZ", NULL, DBGbGet(), 1);
  if (DAPexGetBit(menu, DAP_ATTR_MRN))
    DBG64("MRN", DAPi2int(DBGiSkip()));

  if (DAPexGetBit(menu, DAP_ATTR_RUNSYS)) {
    char runsys[64];

    DBGstring("RUNSYS", DAPi2string(DBGiSkip(), runsys));
  }

  if (DAPexGetBit(menu, DAP_ATTR_DEQ))
    DBG2b("DEQ", NULL, DBG2bGet(), 1);
  if (DAPexGetBit(menu, DAP_ATTR_FOP))
    DBGex("FOP", fop, DBGexSkip());
  if (DAPexGetBit(menu, DAP_ATTR_BSZ))
    DBGb("BSZ", NULL, DBGbGet(), 1);
  if (DAPexGetBit(menu, DAP_ATTR_DEV))
    DBGex("DEV", dev, DBGexSkip());
  if (DAPexGetBit(menu, DAP_ATTR_SDC)) {
    dnetlog(LOG_DEBUG, "SDC:  present\n");
    DBGexSkip();
  }
  if (DAPexGetBit(menu, DAP_ATTR_LRL))
    DBG2b("LRL", NULL, DBG2bGet(), 1);
  if (DAPexGetBit(menu, DAP_ATTR_HBK))
    DBG64("HBK", DAPi2int(DBGiSkip()));
  if (DAPexGetBit(menu, DAP_ATTR_EBK))
    DBG64("EBK", DAPi2int(DBGiSkip()));
  if (DAPexGetBit(menu, DAP_ATTR_FFB))
    DBG2b("FFB", NULL, DBG2bGet(), 1);
  if (DAPexGetBit(menu, DAP_ATTR_SBN))
    DBG64("SBN", DAPi2int(DBGiSkip()));
}

/*
 * Display Access message information.
 */
static void DBGaccess(void)
{
  char filespec[256], password[40];
  
  DBGb("ACCFUNC", accfunc, DBGbGet(), 1);
  DBGex("ACCOPT", accopt, DBGexSkip());
  DBGstring("FILESPEC", DAPi2string(DBGiSkip(), filespec));
  if (msglen >= 1) {
    DBGex("FAC", fac, DBGexSkip());
    if (msglen >= 1) {
      DBGex("SHR", shr, DBGexSkip());
      if (msglen >= 1) {
        DBGex("DISPLAY", display, DBGexSkip());
        if (msglen >= 1)
          DBGstring("PASSWORD", DAPi2string(DBGiSkip(), password));
      }
    }
  }
}

/*
 * Display Control message information.
 */
static void DBGcontrol(void)
{
  uint8_t *menu;

  DBGb("CTLFUNC", ctlfunc, DBGbGet(), 1);
  menu = DBGexSkip();
  DBGex("CTLMENU", ctlmenu, menu);
  if (DAPexGetBit(menu, DAP_CMNU_RAC))
    DBGb("RAC", rac, DBGbGet(), 1);

  if (DAPexGetBit(menu, DAP_CMNU_KEY)) {
    dnetlog(LOG_DEBUG, "KEY:  present\n");
    DBGexSkip();
  }

  if (DAPexGetBit(menu, DAP_CMNU_KRF))
    DBGb("KRF", NULL, DBGbGet(), 1);
  if (DAPexGetBit(menu, DAP_CMNU_ROP))
    DBGex("ROP", rop, DBGexSkip());

  if (DAPexGetBit(menu, DAP_CMNU_HSH)) {
    dnetlog(LOG_DEBUG, "HSH:  present\n");
    DBGiSkip();
  }

  if (DAPexGetBit(menu, DAP_CMNU_DISPLAY))
    DBGex("DISPLAY", display, DBGexSkip());
}

/*
 * Display Continue Transfer message information.
 */
static void DBGcontinueTransfer(void)
{
  DBGb("CONFUNC", confunc, DBGbGet(), 1);
}

/*
 * Display Access Complete message information.
 */
static void DBGaccessComplete(void)
{
  DBGb("CMPFUNC", cmpfunc, DBGbGet(), 1);
  if (msglen >= 1) {
    DBGex("FOP", fop, DBGexSkip());
    if (msglen >= 2)
      DBG2b("CHECK", NULL, DBG2bGet(), 0);
  }
}

/*
 * Display Data message infomration.
 */
static void DBGdata(void)
{
  DBG64("RECNUM", DAPi2int(DBGiSkip()));
}

/*
 * Display Status message information.
 */
static void DBGstatus(void)
{
  uint16_t stscode = DBG2bGet();

  DBG2b("SYSCODE", NULL, stscode, 0);
  DBGb(" MACCODE", maccode, (stscode >> 12) & 0xF, 0);

  switch (stscode & 0xF000) {
    case DAP_MAC_UNSUPP:
    case DAP_MAC_FORMAT:
    case DAP_MAC_INVALID:
      DBG2b(" MICCODE", miccodeA, stscode & 0xFFF, 0);
      break;
      
    case DAP_MAC_PENDING:
    case DAP_MAC_SUCCESS:
    case DAP_MAC_OPEN:
    case DAP_MAC_XFER:
    case DAP_MAC_WARN:
    case DAP_MAC_TERMIN:
      DBG2b(" MICCODE", miccodeB, stscode & 0xFFF, 0);
      break;
      
    case DAP_MAC_SYNC:
      DBG2b(" MICCODE", miccodeC, stscode & 0xFFF, 0);
      break;
      
    default:
      DBG2b(" MICCODE", NULL, stscode & 0xFFF, 0);
      break;
  }
  DBG64("RFA", DAPi2int(DBGiSkip()));
  DBG64("RECNUM", DAPi2int(DBGiSkip()));
  DBG64("STV", DAPi2int(DBGiSkip()));
}

/*
 * Display Key Definition Attributes message information.
 */
static void DBGkeydef(void)
{
  uint8_t *menu = DBGexSkip();
  
  DBGex("KEYMENU", keymenu, menu);
  if (DAPexGetBit(menu, DAP_KMNU_FLG))
    DBGex("FLG", flg, DBGexSkip());
  if (DAPexGetBit(menu, DAP_KMNU_DFL))
    DBG2b("DFL", NULL, DBG2bGet(), 1);
  if (DAPexGetBit(menu, DAP_KMNU_IFL))
    DBG2b("IFL", NULL, DBG2bGet(), 1);

  if (DAPexGetBit(menu, DAP_KMNU_NSG)) {
    uint8_t i, nsg = DBGbGet();
    char posname[8], sizname[8];

    DBGb("NSG", NULL, nsg, 1);
    for (i = 0; i < nsg; i++) {
      sprintf(posname, "POS%1u", i + 1);
      sprintf(sizname, "SIZ%1u", i + 1);
      DBG2b(posname, NULL, DBG2bGet(), 1);
      DBGb(sizname, NULL, DBGbGet(), 1);
    }
  }

  if (DAPexGetBit(menu, DAP_KMNU_REF))
    DBGb("REF", NULL, DBGbGet(), 1);

  if (DAPexGetBit(menu, DAP_KMNU_KNM)) {
    char keyname[64];

    DBGstring("KNM", DAPi2string(DBGiSkip(), keyname));
  }

  if (DAPexGetBit(menu, DAP_KMNU_NUL))
    DBGb("NUL", NULL, DBGbGet(), 0);
  if (DAPexGetBit(menu, DAP_KMNU_IAN))
    DBGb("IAN", NULL, DBGbGet(), 1);
  if (DAPexGetBit(menu, DAP_KMNU_LAN))
    DBGb("LAN", NULL, DBGbGet(), 1);
  if (DAPexGetBit(menu, DAP_KMNU_DAN))
    DBGb("DAN", NULL, DBGbGet(), 1);
  if (DAPexGetBit(menu, DAP_KMNU_DTP))
    DBGb("DTP", NULL, DBGbGet(), 1);
  if (DAPexGetBit(menu, DAP_KMNU_RVB))
    DBG64("RVB", DAPi2int(DBGiSkip()));
  if (DAPexGetBit(menu, DAP_KMNU_HAL))
    DBG64("HAL", DAPi2int(DBGiSkip()));
  if (DAPexGetBit(menu, DAP_KMNU_DVB))
    DBG64("DVB", DAPi2int(DBGiSkip()));
  if (DAPexGetBit(menu, DAP_KMNU_DBS))
    DBGb("DBS", NULL, DBGbGet(), 1);
  if (DAPexGetBit(menu, DAP_KMNU_IBS))
    DBGb("IBS", NULL, DBGbGet(), 1);
  if (DAPexGetBit(menu, DAP_KMNU_LVL))
    DBGb("LVL", NULL, DBGbGet(), 1);
  if (DAPexGetBit(menu, DAP_KMNU_TKS))
    DBGb("TKS", NULL, DBGbGet(), 1);
  if (DAPexGetBit(menu, DAP_KMNU_MRL))
    DBG2b("MRL", NULL, DBG2bGet(), 1);
}

/*
 * Display Allocation Attributes message information.
 */
static void DBGallocation(void)
{
  uint8_t *menu = DBGexSkip();

  DBGex("ALLMENU", allmenu, menu);
  if (DAPexGetBit(menu, DAP_AMNU_VOL))
    DBG2b("VOL", NULL, DBG2bGet(), 1);
  if (DAPexGetBit(menu, DAP_AMNU_ALN))
    DBGex("ALN", aln, DBGexSkip());
  if (DAPexGetBit(menu, DAP_AMNU_AOP))
    DBGex("AOP", aop, DBGexSkip());
  if (DAPexGetBit(menu, DAP_AMNU_LOC))
    DBG64("LOC", DAPi2int(DBGiSkip()));

  if (DAPexGetBit(menu, DAP_AMNU_RFI)) {
    dnetlog(LOG_DEBUG, "RFI:  present\n");
    DBGiSkip();
  }

  if (DAPexGetBit(menu, DAP_AMNU_ALQ))
    DBG64("ALQ", DAPi2int(DBGiSkip()));
  if (DAPexGetBit(menu, DAP_AMNU_AID))
    DBGb("AID", NULL, DBGbGet(), 1);
  if (DAPexGetBit(menu, DAP_AMNU_BKZ))
    DBGb("BKZ", NULL, DBGbGet(), 1);
  if (DAPexGetBit(menu, DAP_AMNU_DEQ))
    DBG2b("DEQ", NULL, DBG2bGet(), 1);
}

/*
 * Display Summary Attributes message information.
 */
static void DBGsummary(void)
{
  uint8_t *menu = DBGexSkip();

  DBGex("SUMENU", sumenu, menu);
  if (DAPexGetBit(menu, DAP_SMNU_NOK))
    DBGb("NOK", NULL, DBGbGet(), 1);
  if (DAPexGetBit(menu, DAP_SMNU_NOA))
    DBGb("NOA", NULL, DBGbGet(), 1);
  if (DAPexGetBit(menu, DAP_SMNU_NOR))
    DBGb("NOR", NULL, DBGbGet(), 1);
  if (DAPexGetBit(menu, DAP_SMNU_PVN))
    DBG2b("PVN", NULL, DBG2bGet(), 1);
}

/*
 * Display Date and Time Attributes message information.
 */
static void DBGdatetime(void)
{
  uint8_t *menu = DBGexSkip();
  char value[32];
  
  DBGex("DATMENU", datmenu, menu);
  if (DAPexGetBit(menu, DAP_DMNU_CDT))
    DBGstring("CDT", DAPf2string(DBGfSkip(18), 18, value));
  if (DAPexGetBit(menu, DAP_DMNU_RDT))
    DBGstring("RDT", DAPf2string(DBGfSkip(18), 18, value));
  if (DAPexGetBit(menu, DAP_DMNU_EDT))
    DBGstring("EDT", DAPf2string(DBGfSkip(18), 18, value));
  if (DAPexGetBit(menu, DAP_DMNU_RVN))
    DBG2b("RVN", NULL, DBG2bGet(), 1);
}

/*
 * Display Protection Attributes message information.
 */
static void DBGprotection(void)
{
  uint8_t *menu = DBGexSkip();
  char owner[64];
  
  DBGex("PROTMENU", protmenu, menu);
  if (DAPexGetBit(menu, DAP_PMNU_OWNER))
    DBGstring("OWNER", DAPi2string(DBGiSkip(), owner));
  if (DAPexGetBit(menu, DAP_PMNU_PROTSYS))
    DBGex("PROTSYS", prot, DBGexSkip());
  if (DAPexGetBit(menu, DAP_PMNU_PROTOWN))
    DBGex("PROTOWN", prot, DBGexSkip());
  if (DAPexGetBit(menu, DAP_PMNU_PROTGRP))
    DBGex("PROTGRP", prot, DBGexSkip());
  if (DAPexGetBit(menu, DAP_PMNU_PROTWLD))
    DBGex("PROTWLD", prot, DBGexSkip());
}

/*
 * Display Name message information.
 */
static void DBGname(void)
{
  uint8_t *type = DBGexSkip();
  char namespec[256];
  
  DBGex("NAMETYPE", nametype, type);
  DBGstring("NAMESPEC", DAPi2string(DBGiSkip(), namespec));
}

/*
 * Display Access Control List Attributes message information.
 */
static void DBGacl(void)
{
  uint8_t aclcnt = DBGbGet();
  uint16_t i;
  char acl[128];

  DBGb("ACLCNT", NULL, aclcnt, 1);
  for (i = 0; i < aclcnt; i++) {
    char aclname[8];
    
    sprintf(aclname, "ACL%u", i + 1);
    DBGstring(aclname, DAPi2string(DBGiSkip(), acl));
  }
}

/*
 * Dump a detailed description of a DAP message. This routine assumes that
 * the DAP message is syntactically correct and does not perform any checking.
 */
void DetailedDump(
  uint8_t msgtype,
  uint8_t *content,
  int datalen
)
{
  msgptr = content;
  msglen = datalen;
  
  switch(msgtype) {
    case DAP_MSG_CONFIG:
      DBGconfiguration();
      break;
      
    case DAP_MSG_ATTRIBUTES:
      DBGattributes();
      break;
      
    case DAP_MSG_ACCESS:
      DBGaccess();
      break;
      
    case DAP_MSG_CONTROL:
      DBGcontrol();
      break;
      
    case DAP_MSG_CONTINUE:
      DBGcontinueTransfer();
      break;
      
    case DAP_MSG_ACKNOWLEDGE:
      break;
      
    case DAP_MSG_COMPLETE:
      DBGaccessComplete();
      break;
      
    case DAP_MSG_DATA:
      DBGdata();
      break;
      
    case DAP_MSG_STATUS:
      DBGstatus();
      break;

    case DAP_MSG_KEYDEF:
      DBGkeydef();
      break;
      
    case DAP_MSG_ALLOC:
      DBGallocation();
      break;
      
    case DAP_MSG_SUMMARY:
      DBGsummary();
      break;
      
    case DAP_MSG_DATETIME:
      DBGdatetime();
      break;
      
    case DAP_MSG_PROTECT:
      DBGprotection();
      break;
      
    case DAP_MSG_NAME:
      DBGname();
      break;
      
    case DAP_MSG_ACL:
      DBGacl();
      break;
      
    default:
      return;
  }
  dnetlog(LOG_DEBUG, "\n");
}
