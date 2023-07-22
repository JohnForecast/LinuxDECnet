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

#ifndef __DAP_H__
#define __DAP_H__

/*
 * This file is based of DAP Version 5.6.0 with some extensions (extra O/S and
 * filesystem types.
 */

#define DAP_EXTEND              0x80            /* EX-n extension indicator */

/*
 * Message type codes
 */
#define DAP_MSG_CONFIG          1               /* Configuration msg. */
#define DAP_MSG_ATTRIBUTES      2               /* Attributes msg. */
#define DAP_MSG_ACCESS          3               /* Access msg. */
#define DAP_MSG_CONTROL         4               /* Control msg. */
#define DAP_MSG_CONTINUE        5               /* Continue transfer msg. */
#define DAP_MSG_ACKNOWLEDGE     6               /* Acknowledge msg. */
#define DAP_MSG_COMPLETE        7               /* Access complete msg. */
#define DAP_MSG_DATA            8               /* Data msg. */
#define DAP_MSG_STATUS          9               /* Status msg. */
#define DAP_MSG_KEYDEF          10              /* Key definition msg. */
#define DAP_MSG_ALLOC           11              /* Allocation attributes */
                                                /*   extension msg. */
#define DAP_MSG_SUMMARY         12              /* Summary attributes  */
                                                /*   extension msg. */
#define DAP_MSG_DATETIME        13              /* Date and time attributes */
                                                /*   extension msg. */
#define DAP_MSG_PROTECT         14              /* Protection attributes */
                                                /*   extension msg. */
#define DAP_MSG_NAME            15              /* Name msg. */
#define DAP_MSG_ACL             16              /* Access control list attributes */
                                                /*   extension msg. */
#define DAP_MSG_MAX             16

/*
 * Message flag values
 */
#define DAP_FLAGS_STREAMID      0x01            /* Stream ID is present */
#define DAP_FLAGS_LENGTH        0x02            /* Length field is present */
#define DAP_FLAGS_LEN256        0x04            /* Length field is 2 bytes */
#define DAP_FLAGS_BITCNT        0x08            /* Bitcnt field is present */
#define DAP_FLAGS_SYSSPEC       0x20            /* Syspec field is present */
#define DAP_FLAGS_SEGMENTED     0x40            /* Segmented msg. */

#define DAP_MIN_HDR_LEN         2               /* Message type + flags */
#define DAP_HDR_LEN_LENGTH      4               /* Type + flags + 16-bit len */

                                                /* Configuration message */
/*
 * O/S type codes
 */
#define DAP_OS_ILLEGAL          0               /* Illegal value */
#define DAP_OS_RT11             1               /* RT-11 */
#define DAP_OS_RSTS             2               /* RSTS/E */
#define DAP_OS_RSX11S           3               /* RSX-11S */
#define DAP_OS_RSX11M           4               /* RSX-11M */
#define DAP_OS_RSX11D           5               /* RSX-11D */
#define DAP_OS_IAS              6               /* IAS */
#define DAP_OS_VAXVMS           7               /* VAX/VMS (OpenVMS) */
#define DAP_OS_TOPS20           8               /* TOPS-20 */
#define DAP_OS_TOPS10           9               /* TOPS-10 */
#define DAP_OS_RTS8             10              /* RTS/8 */
#define DAP_OS_OS8              11              /* OS/8 */
#define DAP_OS_RSX11MP          12              /* RSX-11M+ */
#define DAP_OS_COPOS11          13              /* COPOS/11 (TOPS-20 FE) */
#define DAP_OS_POS              14              /* P/OS */
#define DAP_OS_VAXELN           15              /* VAXELN */
#define DAP_OS_CPM              16              /* CP/M */
#define DAP_OS_MSDOS            17              /* MSDOS */
#define DAP_OS_ULTRIX           18              /* Ultrix-32 */
#define DAP_OS_ULTRIX11         19              /* Ultrix-11 */
#define DAP_OS_DTF_MVS          21              /* ??? */
#define DAP_OS_MACOS            22              /* Classic MAC/OS */
#define DAP_OS_OS2              23              /* OS/2 */
#define DAP_OS_DTF_VM           24              /* ??? */
#define DAP_OS_OSF1             25              /* OSF/1 */
#define DAP_OS_WIN_NT           26              /* Windows NT */
#define DAP_OS_WIN_95           27              /* Windows 95 */

#define DAP_OS_LINUX            192             /* Linux */

/*
 * File system type codes
 */
#define DAP_FS_ILLEGAL          0               /* Illegal value */
#define DAP_FS_RMS_11           1               /* RMS-11 */
#define DAP_FS_RMS_20           2               /* RMS-20 */
#define DAP_FS_RMS_32           3               /* RMS-32 */
#define DAP_FS_FCS_11           4               /* FCS-11 */
#define DAP_FS_RT11             5               /* RT-11 */
#define DAP_FS_NONE             6               /* No file system supported */
#define DAP_FS_TOPS_20          7               /* TOPS-20 */
#define DAP_FS_TOPS_10          8               /* TOPS-10 */
#define DAP_FS_OS8              9               /* OS/8 */
#define DAP_FS_ULTRIX           13              /* Ultrix-32 */

#define DAP_FS_LINUX            192             /* Linux */

/*
 * Protocol version numbers
 */
#define DAP_VER_VERNUM          5               /* DAP version number */
#define DAP_VER_ECONUM          6               /* DAP ECO number */
#define DAP_VER_USRNUM          0               /* Customer modification */
#define DAP_VER_SOFTVER         0               /* DAP software version */
#define DAP_VER_USRSOFT         0               /* User software version */

/*
 * System capabilities
 */
                                                /* Supports: */
#define DAP_SYSCP_PREALLOC      0               /* File preallocation */
#define DAP_SYSCP_SEQ           1               /* Sequential file org. */
#define DAP_SYSCP_REL           2               /* Relative file org. */
#define DAP_SYSCP_DIRECT        3               /* Direct file org. (RSVD) */
#define DAP_SYSCP_SINGLE        4               /* Single key indexed file org. */
#define DAP_SYSCP_SEQXFER       5               /* Sequential file transfer */
#define DAP_SYSCP_RANRECNUM     6               /* Random access by record # */
#define DAP_SYSCP_RANVBN        7               /* Random access by VBN */
#define DAP_SYSCP_RANKEY        8               /* Random access by key */
#define DAP_SYSCP_RANHASH       9               /* Random access by hash (RSVD) */
#define DAP_SYSCP_RANRFA        10              /* Random access by RFA */
#define DAP_SYSCP_MULTI         11              /* Multi key indexed file org. */
#define DAP_SYSCP_SWITCH        12              /* Switching access mode */
#define DAP_SYSCP_APPEND        13              /* Append to file access */
#define DAP_SYSCP_CMDFILE_ACC   14              /* Command file submission */
#define DAP_SYSCP_COMPRESSION   15              /* Data compression (RSVD) */
#define DAP_SYSCP_MULTIPLE      16              /* Multiple data streams */
#define DAP_SYSCP_STATUS        17              /* Status return (RSVD) */
#define DAP_SYSCP_BLOCKING      18              /* Blocking of DAP messages */
#define DAP_SYSCP_UNRESTRICTED  19              /* Unrestricted blocking */
#define DAP_SYSCP_2BYTELEN      20              /* 2 byte length field */
#define DAP_SYSCP_CHECKSUM      21              /* File checksum */
#define DAP_SYSCP_KEYDEF        22              /* Key definition extended */
                                                /*   attributes msg. */
#define DAP_SYSCP_ALLOC 23                      /* Allocation extended */
                                                /*   attributes msg. */
#define DAP_SYSCP_SUMMARY       24              /* Summary extended */
                                                /*   attributes msg. */
#define DAP_SYSCP_DIRLIST       25              /* Directory list */
#define DAP_SYSCP_DATETIME      26              /* Date and time extended */
                                                /*   attributes msg. */
#define DAP_SYSCP_PROTECT       27              /* File protection extended */
                                                /*   attributes msg. */
#define DAP_SYSCP_ACL           28              /* Access control list extended */
                                                /*   attributes msg. */
#define DAP_SYSCP_SPOOLING      29              /* Spooling, FOP bit 20 */
#define DAP_SYSCP_CMDFILE       30              /* Command file submission */
#define DAP_SYSCP_FILE_DELETE   31              /* File deletion */
#define DAP_SYSCP_DEFAULT       32              /* Default file spec (RSVD) */
#define DAP_SYSCP_SEQREC        33              /* Seq. record access */
#define DAP_SYSCP_RECOVERY      34              /* Transfer recovery (RSVD) */
#define DAP_SYSCP_BITCNT        35              /* BITCNT field */
#define DAP_SYSCP_WARNING       36              /* Warning status msg. */
#define DAP_SYSCP_RENAME        37              /* File rename */
#define DAP_SYSCP_WILDCARD      38              /* Wild card operations */
#define DAP_SYSCP_GO_NOGO       39              /* GO/NO-GO option */
#define DAP_SYSCP_NAME          40              /* Name msg. */
#define DAP_SYSCP_SEGMENTED     61              /* Segmented messages */

/*
 * Attributes present
 */
#define DAP_ATTR_DATATYPE       0               /* Type of data present */
#define DAP_ATTR_ORG            1               /* File organization */
#define DAP_ATTR_RFM            2               /* Record format */
#define DAP_ATTR_RAT            3               /* Record attributes */
#define DAP_ATTR_BLS            4               /* Physical block size */
#define DAP_ATTR_MRS            5               /* Maximum record size */
#define DAP_ATTR_ALQ            6               /* Allocation quantity */
#define DAP_ATTR_BKS            7               /* Bucket block size */
#define DAP_ATTR_FSZ            8               /* Fixed size record part */
#define DAP_ATTR_MRN            9               /* Maximum record # */
#define DAP_ATTR_RUNSYS         10              /* Run-Time system name */
#define DAP_ATTR_DEQ            11              /* File extension quantum */
#define DAP_ATTR_FOP            12              /* File access options */
#define DAP_ATTR_BSZ            13              /* Byte size in bits */
#define DAP_ATTR_DEV            14              /* Device attributes */
#define DAP_ATTR_SDC            15              /* Spooling device chars (RSVD) */
#define DAP_ATTR_LRL            16              /* Longest record length */
#define DAP_ATTR_HBK            17              /* Highest VBN in file */
#define DAP_ATTR_EBK            18              /* EOF VBN */
#define DAP_ATTR_FFB            19              /* First free byte at EOF */
#define DAP_ATTR_SBN            20              /* Starting LBN if contiguous */

/*
 * Datatypes
 */
#define DAP_DATATYPE_ASCII      0               /* 7-bit ASCII */
#define DAP_DATATYPE_IMAGE      1               /* 8-bit raw data */
#define DAP_DATATYPE_EBCDIC     2               /* EBCDIC (RSVD) */
#define DAP_DATATYPE_COMPRESSED 3               /* Compressed */
#define DAP_DATATYPE_EXEC       4               /* Executable code */
#define DAP_DATATYPE_PRIV       5               /* Privileged code */
#define DAP_DATATYPE_RESERVED   6
#define DAP_DATATYPE_SENSITIVE  7               /* Sensitive data */

/*
 * File organization
 */
#define DAP_ORG_SEQ             0               /* Sequential */
#define DAP_ORG_REL             0x10            /* Relative */
#define DAP_ORG_INDEXED         0x20            /* Indexed */
#define DAP_ORG_HASHED          0x30            /* Hashed (RSVD) */

/*
 * Record format
 */
#define DAP_RFM_UDF             0               /* Undefined */
#define DAP_RFM_FIX             1               /* Fixed length */
#define DAP_RFM_VAR             2               /* Variable length */
#define DAP_RFM_VFC             3               /* Variable with fixed control */
#define DAP_RFM_STM             4               /* ASCII stream */

/*
 * Record attributes
 */
#define DAP_RAT_FTN             0               /* FORTRAN carriage control */
#define DAP_RAT_CR              1               /* Implied LF/CR envelope */
#define DAP_RAT_PRN             2               /* Print file carriage control */
#define DAP_RAT_BLK             3               /* Records do no span blocks */
#define DAP_RAT_EMBED           4               /* Embedded carriage control */
#define DAP_RAT_COBOL           5               /* COBOL (RSVD) */
#define DAP_RAT_LSA             6               /* Line sequenced ASCII */
#define DAP_RAT_MACY11          7               /* MACY11 */

#define DAP_BLS_DEFAULT         512
#define DAP_MRS_DEFAULT         0
#define DAP_ALQ_DEFAULT         0
#define DAP_BKS_DEFAULT         0
#define DAP_FSZ_DEFAULT         0
#define DAP_MRN_DEFAULT         0
#define DAP_DEQ_DEFAULT         0
#define DAP_BSZ_DEFAULT         8

/*
 * File access options
 */
#define DAP_FOP_RWO             0               /* Rewind on open */
#define DAP_FOP_RWC             1               /* Rewind on close */
#define DAP_FOP_POS             3               /* Position MT past last file */
#define DAP_FOP_DLK             4               /* Do not lock file if improperly closed */
#define DAP_FOP_LOCKED          6               /* File locked */
#define DAP_FOP_CTG             7               /* Contiguous create */
#define DAP_FOP_SUP             8               /* Supercede on create */
#define DAP_FOP_NEF             9               /* Do not position MT to EOT */
#define DAP_FOP_TMP             10              /* Create temp file */
#define DAP_FOP_MKD             11              /* Create temp file and mark for delete */
#define DAP_FOP_DMO             13              /* Rewind and dismount MT on close */
#define DAP_FOP_WCK             14              /* Enable write checking */
#define DAP_FOP_RCK             15              /* Enable read checking */
#define DAP_FOP_CIF             16              /* Create if not present */
#define DAP_FOP_LKO             17              /* Override file lock (RSVD) */
#define DAP_FOP_SQO             18              /* Seq. access only */
#define DAP_FOP_MXV             19              /* Max version number */
#define DAP_FOP_SPL             20              /* Spool file on close */
#define DAP_FOP_SCF             21              /* Submit as command file */
#define DAP_FOP_DLT             22              /* Delete on close */
#define DAP_FOP_CBT             23              /* Contiguous best try */
#define DAP_FOP_WAT             24              /* Wait if file locked */
#define DAP_FOP_DFW             25              /* Deferred write */
#define DAP_FOP_TEF             26              /* Truncate on close */
#define DAP_FOP_OFP             27              /* Output file parse */

/*
 * Device attributes
 */
#define DAP_DEV_REC             0               /* Record oriented */
#define DAP_DEV_CCL             1               /* Carriage control device */
#define DAP_DEV_TRM             2               /* Terminal */
#define DAP_DEV_MDI             3               /* Directory structured */
#define DAP_DEV_SDI             4               /* Single directory only */
#define DAP_DEV_SQD             5               /* Sequential block device */
#define DAP_DEV_NUL             6               /* Null device */
#define DAP_DEV_FOD             7               /* File oriented device */
#define DAP_DEV_SHR             8               /* Device can be shared */
#define DAP_DEV_SPL             9               /* Device is being spooled */
#define DAP_DEV_MNT             10              /* Device is mounted */
#define DAP_DEV_DMT             11              /* Device marked for dismount */
#define DAP_DEV_ALL             12              /* Device is allocated */
#define DAP_DEV_IDV             13              /* Input device */
#define DAP_DEV_ODV             14              /* Output device */
#define DAP_DEV_SWL             15              /* Software write locked */
#define DAP_DEV_AVL             16              /* Device available for use */
#define DAP_DEV_ELG             17              /* Device has error logging */
#define DAP_DEV_MBX             18              /* Device is a mailbox */
#define DAP_DEV_RTM             19              /* Realtime device (no RMS) */
#define DAP_DEV_RAD             20              /* Random access device */
#define DAP_DEV_RCK             21              /* Read checking enabled */
#define DAP_DEV_WCK             22              /* Write checking enabled */
#define DAP_DEV_FOR             23              /* Foreign device */
#define DAP_DEV_NET             24              /* Network device */
#define DAP_DEV_GEN             25              /* Generic device */

                                                /* Access message */
/*
 * Access function codes
 */
#define DAP_AFNC_OPEN           1               /* Open existing file */
#define DAP_AFNC_CREATE         2               /* Open a new file */
#define DAP_AFNC_RENAME         3               /* Rename a file */
#define DAP_AFNC_ERASE          4               /* Delete a file */
#define DAP_AFNC_DIRLIST        6               /* Directory list */
#define DAP_AFNC_SUBMIT         7               /* Submit a cmd (batch) file */
#define DAP_AFNC_EXEC           8               /* Execute a cmd (batch) file */

/*
 * Access options
 */
#define DAP_OPT_NONFATAL        0               /* Errors are non-fatal */
#define DAP_OPT_WSTATUS         1               /* Return status msg. on write (RSVD) */
#define DAP_OPT_RSTATUS         2               /* Return status msg. on read (RSVD) */
#define DAP_OPT_CHECKSUM        3               /* Compute/check checksums */
#define DAP_OPT_GO_NOGO         4               /* Go/No-Go control */

#define DAP_ACCESS_MAX_FILESPEC 255             /* Max file spec length */

/*
 * File access operations
 */
#define DAP_FAC_PUT             0               /* Put access */
#define DAP_FAC_GET             1               /* Get access */
#define DAP_FAC_DEL             2               /* Delete access */
#define DAP_FAC_UPD             3               /* Update access */
#define DAP_FAC_TRN             4               /* Truncate access */
#define DAP_FAC_BIO             5               /* Block I/O access */
#define DAP_FAC_BRO             6               /* Switch between block and record I/O */

/*
 * Operations shared with other users
 */
#define DAP_SHR_PUT             0               /* Put access */
#define DAP_SHR_GET             1               /* Get access */
#define DAP_SHR_DEL             2               /* Delete access */
#define DAP_SHR_UPD             3               /* Update access */
#define DAP_SHR_MSE             4               /* Enable multi-stream access */
#define DAP_SHR_UPI             5               /* User provided locking */
#define DAP_SHR_NIL             6               /* No access by other users */

/*
 * Messages to be returned to remote system
 */
#define DAP_DSP_MAIN            0               /* Main attributes msg. */
#define DAP_DSP_KEYDEF          1               /* Keydef attributes msg. */
#define DAP_DSP_ALLOC           2               /* Allocation attributes msg. */
#define DAP_DSP_SUMMARY         3               /* Summary attributes msg. */
#define DAP_DSP_DATETIME        4               /* Date/Time attributes msg. */
#define DAP_DSP_PROTECT         5               /* File protection attributes msg. */
#define DAP_DSP_ACL             7               /* ACL attributes msg. */
#define DAP_DSP_NAME            8               /* Name msg. */

                                                /* Control message */
/*
 * Control function codes
 */
#define DAP_CFNC_GET            1               /* Get record or block */
#define DAP_CFNC_CONNECT        2               /* Initiate data stream */
#define DAP_CFNC_UPDATE         3               /* Update current record */
#define DAP_CFNC_PUT            4               /* Put record or block */
#define DAP_CFNC_DELETE         5               /* Delete current record */
#define DAP_CFNC_REWIND         6               /* Rewind file */
#define DAP_CFNC_TRUNCATE       7               /* Truncate file */
#define DAP_CFNC_MODIFY         8               /* Change attributes (RSVD) */
#define DAP_CFNC_RELEASE        9               /* Unlock record */
#define DAP_CFNC_FREE           10              /* Unlock all records */
#define DAP_CFNC_FLUSH          12              /* Write modified buffers */
#define DAP_CFNC_NXTVOL         13              /* Volume processing (RSVD) */
#define DAP_CFNC_FIND           14              /* Find record (no xfer) */
#define DAP_CFNC_EXTEND         15              /* Extend file */
#define DAP_CFNC_DISPLAY        16              /* Retrieve attributes */
#define DAP_CFNC_FORWARD        17              /* Space forward records */
#define DAP_CFNC_BACKWARD       18              /* Space backward records */

/*
 * Control menu values
 */
#define DAP_CMNU_RAC            0               /* Access mode */
#define DAP_CMNU_KEY            1               /* Key value */
#define DAP_CMNU_KRF            2               /* Key of reference */
#define DAP_CMNU_ROP            3               /* Optional processing features */
#define DAP_CMNU_HSH            4               /* Hash code */
#define DAP_CMNU_DISPLAY        5               /* Attributes message */

/*
 * Access modes
 */
#define DAP_RAC_SEQ             0               /* Sequential record access */
#define DAP_RAC_KEY             1               /* Keyed access */
#define DAP_RAC_RFA             2               /* Access by RFA */
#define DAP_RAC_SEQREST         3               /* Rest of file is seq. xfer */
#define DAP_RAC_BMODEVBN        4               /* Block mode via VBN */
#define DAP_RAC_BMODEXFER       5               /* Block mode file xfer */

/*
 * Key of reference values
 */
#define DAP_KRF_PRIMARY         0               /* Primary key */
                                /* 1 - 254         Secondary key indicator */


/*
 * Optional record processing features
 */
#define DAP_ROP_EOF             0               /* Position to EOF */
#define DAP_ROP_FDL             1               /* Fast record delete */
#define DAP_ROP_UIF             2               /* Update existing records */
#define DAP_ROP_HSH             3               /* Use hash code (RSVD) */
#define DAP_ROP_LOA             4               /* Follow fill quantities */
#define DAP_ROP_ULK             5               /* Manual locking (RSVD) */
#define DAP_ROP_TPT             6               /* Truncate put */
#define DAP_ROP_RAH             7               /* Read ahead */
#define DAP_ROP_WBH             8               /* Write behind */
#define DAP_ROP_KGE             9               /* Key is >= */
#define DAP_ROP_KGT             10              /* Key is > */
#define DAP_ROP_NLK             11              /* Do not lock record */
#define DAP_ROP_RLK             12              /* Read locked record */
#define DAP_ROP_BIO             13              /* Block I/O */
#define DAP_ROP_LIM             14              /* Compare for key limit reached (RSVD) */
#define DAP_ROP_NXR             15              /* Non-existent record processing (RSVD) */

                                                /* Continue transfer message */
/*
 * Continue transfer function codes
 */
#define DAP_CFNC_AGAIN          1               /* Try again */
#define DAP_CFNC_SKIP           2               /* Skip and continue */
#define DAP_CFNC_ABORT          3               /* Abort transfer */
#define DAP_CFNC_RESUME         4               /* Resume processing */

                                                /* Access complete message */
/*
 * Access complete function codes
 */
#define DAP_AFNC_CLOSE          1               /* Terminate access */
#define DAP_AFNC_RESPONSE       2               /* Response msg. */
#define DAP_AFNC_PURGE          3               /* Close and delete file */
#define DAP_AFNC_ENDSTREAM      4               /* Terminate data stream */
#define DAP_AFNC_SKIP           5               /* Close current, process next */

                                                /* Status message */
/*
 * Status codes - MACCODE
 */
#define DAP_MAC_PENDING         0x0000          /* Operation in progress */
#define DAP_MAC_SUCCESS         0x1000          /* Operation was successful */
#define DAP_MAC_UNSUPP          0x2000          /* Unsupported operation */
#define DAP_MAC_OPEN            0x4000          /* File open error */
#define DAP_MAC_XFER            0x5000          /* File transfer error */
#define DAP_MAC_WARN            0x6000          /* File transfer warning */
#define DAP_MAC_TERMIN          0x7000          /* Access termination error */
#define DAP_MAC_FORMAT          0x8000          /* Message format error */
#define DAP_MAC_INVALID         0x9000          /* Message invalid error */
#define DAP_MAC_SYNC            0xA000          /* Synchronization error */

/*
 * Status codes - MICCODE
 */
#define DAP_MIC_MISC_USPEC      00000           /* Unspecified error */
#define DAP_MIC_MISC_TYPE       00010           /* TYPE field error */

                                                /* Configuration message */
#define DAP_MIC_CONF_UNKNOWN    00100           /* Unknown field */
#define DAP_MIC_CONF_FLAGS      00110           /* FLAGS field error */
#define DAP_MIC_CONF_STREAMID   00111           /* STREAMID field error */
#define DAP_MIC_CONF_LENGTH     00112           /* LENGTH field error */
#define DAP_MIC_CONF_LEN256     00113           /* LEN256 field error */
#define DAP_MIC_CONF_BITCNT     00114           /* BITCNT field error */
#define DAP_MIC_CONF_BUFSIZ     00120           /* BUFSIZ field error */
#define DAP_MIC_CONF_OSTYPE     00121           /* OSTYPE field error */
#define DAP_MIC_CONF_FILESYS    00122           /* FILESYS field error */
#define DAP_MIC_CONF_VERNUM     00123           /* VERNUM field error */
#define DAP_MIC_CONF_ECONUM     00124           /* ECONUM field error */
#define DAP_MIC_CONF_USRNUM     00125           /* USRNUM field error */
#define DAP_MIC_CONF_SOFTVER    00126           /* SOFTVER field error */
#define DAP_MIC_CONF_USRSOFT    00127           /* USRSOFT field error */
#define DAP_MIC_CONF_SYSCAP     00130           /* SYSCAP field error */

                                                /* Attributes message */
#define DAP_MIC_ATTR_UNKNOWN    00200           /* Unknown field */
#define DAP_MIC_ATTR_FLAGS      00210           /* FLAGS field error */
#define DAP_MIC_ATTR_STREAMID   00211           /* STREAMID field error */
#define DAP_MIC_ATTR_LENGTH     00212           /* LENGTH field error */
#define DAP_MIC_ATTR_LEN256     00213           /* LEN256 field error */
#define DAP_MIC_ATTR_BITCNT     00214           /* BITCNT field error */
#define DAP_MIC_ATTR_SYSPEC     00215           /* SYSPEC field error */
#define DAP_MIC_ATTR_ATTMENU    00220           /* ATTMENU field error */
#define DAP_MIC_ATTR_DATATYPE   00221           /* DATATYPE field error */
#define DAP_MIC_ATTR_ORG        00222           /* ORG field error */
#define DAP_MIC_ATTR_RFM        00223           /* RFM field error */
#define DAP_MIC_ATTR_RAT        00224           /* RAT field error */
#define DAP_MIC_ATTR_BLS        00225           /* BLS field error */
#define DAP_MIC_ATTR_MRS        00226           /* MRS field error */
#define DAP_MIC_ATTR_ALQ        00227           /* ALQ field error */
#define DAP_MIC_ATTR_BKS        00230           /* BKS field error */
#define DAP_MIC_ATTR_FSZ        00231           /* FSZ field error */
#define DAP_MIC_ATTR_MRN        00232           /* MRN field error */
#define DAP_MIC_ATTR_RUNSYS     00233           /* RUNSYS field error */
#define DAP_MIC_ATTR_DEQ        00234           /* DEQ field error */
#define DAP_MIC_ATTR_FOP        00235           /* FOP field error */
#define DAP_MIC_ATTR_BSZ        00236           /* BSZ field error */
#define DAP_MIC_ATTR_DEV        00237           /* DEV field error */
#define DAP_MIC_ATTR_SDC        00240           /* SDC field error */
#define DAP_MIC_ATTR_LRL        00241           /* LRL field error */
#define DAP_MIC_ATTR_HBK        00242           /* HBK field error */
#define DAP_MIC_ATTR_EBK        00243           /* EBK field error */
#define DAP_MIC_ATTR_FFB        00244           /* FFB field error */
#define DAP_MIC_ATTR_SBN        00245           /* SBN field error */

                                                /* Access message */
#define DAP_MIC_ACC_UNKNOWN     00300           /* Unknown field */
#define DAP_MIC_ACC_FLAGS       00310           /* FLAGS field error */
#define DAP_MIC_ACC_STREAMID    00311           /* STREAMID field error */
#define DAP_MIC_ACC_LENGTH      00312           /* LENGTH field error */
#define DAP_MIC_ACC_LEN256      00313           /* LEN256 field error */
#define DAP_MIC_ACC_BITCNT      00314           /* BITCNT field error */
#define DAP_MIC_ACC_SYSPEC      00315           /* SYSPEC field error */
#define DAP_MIC_ACC_ACCFUNC     00320           /* ACCFUNC field error */
#define DAP_MIC_ACC_ACCOPT      00321           /* ACCOPT field error */
#define DAP_MIC_ACC_FILESPEC    00322           /* FILESPEC field error */
#define DAP_MIC_ACC_FAC         00323           /* FAC field error */
#define DAP_MIC_ACC_SHR         00324           /* SHR field error */
#define DAP_MIC_ACC_DISPLAY     00325           /* DISPLAY field error */
#define DAP_MIC_ACC_PASSWORD    00326           /* PASSWORD field error */

                                                /* Control message */
#define DAP_MIC_CTL_UNKNOWN     00400           /* Unknown field */
#define DAP_MIC_CTL_FLAGS       00410           /* FLAGS field error */
#define DAP_MIC_CTL_STREAMID    00411           /* STREAMID field error */
#define DAP_MIC_CTL_LENGTH      00412           /* LENGTH field error */
#define DAP_MIC_CTL_LEN256      00413           /* LEN256 field error */
#define DAP_MIC_CTL_BITCNT      00414           /* BITCNT field error */
#define DAP_MIC_CTL_SYSPEC      00415           /* SYSPEC field error */
#define DAP_MIC_CTL_CTLFUNC     00420           /* CTLFUNC field error */
#define DAP_MIC_CTL_CTLMENU     00421           /* CTLMENU field error */
#define DAP_MIC_CTL_RAC         00422           /* RAC field error */
#define DAP_MIC_CTL_KEY         00423           /* KEY field error */
#define DAP_MIC_CTL_KRF         00424           /* KRF field error */
#define DAP_MIC_CTL_ROP         00425           /* ROP field error */
#define DAP_MIC_CTL_HSH         00426           /* HSH field error */
#define DAP_MIC_CTL_DISPLAY     00427           /* DISPLAY field error */

                                                /* Continue message */
#define DAP_MIC_CONT_UNKNOWN    00500           /* Unknown field */
#define DAP_MIC_CONT_FLAGS      00510           /* FLAGS field error */
#define DAP_MIC_CONT_STREAMID   00511           /* STREAMID field error */
#define DAP_MIC_CONT_LENGTH     00512           /* LENGTH field error */
#define DAP_MIC_CONT_LEN256     00513           /* LEN256 field error */
#define DAP_MIC_CONT_BITCNT     00514           /* BITCNT field error */
#define DAP_MIC_CONT_SYSPEC     00515           /* SYSPEC field error */
#define DAP_MIC_CONT_CONFUNC    00520           /* CONFUNC field error */

                                                /* Acknowledge message */
#define DAP_MIC_ACK_UNKNOWN     00600           /* Unknown field */
#define DAP_MIC_ACK_FLAGS       00610           /* FLAGS field error */
#define DAP_MIC_ACK_STREAMID    00611           /* STREAMID field error */
#define DAP_MIC_ACK_LENGTH      00612           /* LENGTH field error */
#define DAP_MIC_ACK_LEN256      00613           /* LEN256 field error */
#define DAP_MIC_ACK_BITCNT      00614           /* BITCNT field error */
#define DAP_MIC_ACK_SYSPEC      00615           /* SYSPEC field error */

                                                /* Access complete message */
#define DAP_MIC_COMP_UNKNOWN    00700           /* Unknown field */
#define DAP_MIC_COMP_FLAGS      00710           /* FLAGS field error */
#define DAP_MIC_COMP_STREAMID   00711           /* STREAMID field error */
#define DAP_MIC_COMP_LENGTH     00712           /* LENGTH field error */
#define DAP_MIC_COMP_LEN256     00713           /* LEN256 field error */
#define DAP_MIC_COMP_BITCNT     00714           /* BITCNT field error */
#define DAP_MIC_COMP_SYSPEC     00715           /* SYSPEC field error */
#define DAP_MIC_COMP_CMPFUNC    00720           /* CMPFUNC field error */
#define DAP_MIC_COMP_FOP        00721           /* FOP field error */
#define DAP_MIC_COMP_CHECK      00722           /* CHECK field error */

                                                /* Data message */
#define DAP_MIC_DATA_UNKNOWN    01000           /* Unknown field */
#define DAP_MIC_DATA_FLAGS      01010           /* FLAGS field error */
#define DAP_MIC_DATA_STREAMID   01011           /* STREAMID field error */
#define DAP_MIC_DATA_LENGTH     01012           /* LENGTH field error */
#define DAP_MIC_DATA_LEN256     01013           /* LEN256 field error */
#define DAP_MIC_DATA_BITCNT     01014           /* BITCNT field error */
#define DAP_MIC_DATA_SYSPEC     01015           /* SYSPEC field error */
#define DAP_MIC_DATA_RECNUM     01020           /* RECNUM field error */
#define DAP_MIC_DATA_FILEDATA   01021           /* FILEDATA field error */

                                                /* Status message */
#define DAP_MIC_STAT_UNKNOWN    01100           /* Unknown field */
#define DAP_MIC_STAT_FLAGS      01110           /* FLAGS field error */
#define DAP_MIC_STAT_STREAMID   01111           /* STREAMID field error */
#define DAP_MIC_STAT_LENGTH     01112           /* LENGTH field error */
#define DAP_MIC_STAT_LEN256     01113           /* LEN256 field error */
#define DAP_MIC_STAT_BITCNT     01114           /* BITCNT field error */
#define DAP_MIC_STAT_SYSPEC     01115           /* SYSPEC field error */
#define DAP_MIC_STAT_MACCODE    01120           /* MACCODE field error */
#define DAP_MIC_STAT_MICCODE    01121           /* MICCODE field error */
#define DAP_MIC_STAT_RFA        01122           /* RFA field error */
#define DAP_MIC_STAT_RECNUM     01123           /* RECNUM field error */
#define DAP_MIC_STAT_STV        01124           /* STV field error */

                                                /* Key definition message */
#define DAP_MIC_KDEF_UNKNOWN    01200           /* Unknown field */
#define DAP_MIC_KDEF_FLAGS      01210           /* FLAGS field error */
#define DAP_MIC_KDEF_STREAMID   01211           /* STREAMID field error */
#define DAP_MIC_KDEF_LENGTH     01212           /* LENGTH field error */
#define DAP_MIC_KDEF_LEN256     01213           /* LEN256 field error */
#define DAP_MIC_KDEF_BITCNT     01214           /* BITCNT field error */
#define DAP_MIC_KDEF_SYSPEC     01215           /* SYSPEC field error */
#define DAP_MIC_KDEF_KEYMENU    01220           /* KEYMENU field error */
#define DAP_MIC_KDEF_FLG        01221           /* FLG field error */
#define DAP_MIC_KDEF_DFL        01222           /* DFL field error */
#define DAP_MIC_KDEF_IFL        01223           /* IFL field error */
#define DAP_MIC_KDEF_SEGCNT     01224           /* SEGCNT field error */
#define DAP_MIC_KDEF_POS        01225           /* POS field error */
#define DAP_MIC_KDEF_SIZ        01226           /* SIZ field error */
#define DAP_MIC_KDEF_REF        01227           /* REF field error */
#define DAP_MIC_KDEF_KNM        01230           /* KNM field error */
#define DAP_MIC_KDEF_NUL        01231           /* NUL field error */
#define DAP_MIC_KDEF_IAN        01232           /* IAN field error */
#define DAP_MIC_KDEF_LAN        01233           /* LAN field error */
#define DAP_MIC_KDEF_DAN        01234           /* DAN field error */
#define DAP_MIC_KDEF_DTP        01235           /* DTP field error */
#define DAP_MIC_KDEF_RVB        01236           /* RVB field error */
#define DAP_MIC_KDEF_HAL        01237           /* HAL field error */
#define DAP_MIC_KDEF_DVB        01240           /* DVB field error */
#define DAP_MIC_KDEF_DBS        01241           /* DBS field error */
#define DAP_MIC_KDEF_IBS        01242           /* IBS field error */
#define DAP_MIC_KDEF_LVL        01243           /* LVL field error */
#define DAP_MIC_KDEF_TKS        01244           /* TKS field error */
#define DAP_MIC_KDEF_MRL        01245           /* MRL field error */

                                                /* Allocation message */
#define DAP_MIC_ALLO_UNKNOWN    01300           /* Unknown field */
#define DAP_MIC_ALLO_FLAGS      01310           /* FLAGS field error */
#define DAP_MIC_ALLO_STREAMID   01311           /* STREAMID field error */
#define DAP_MIC_ALLO_LENGTH     01312           /* LENGTH field error */
#define DAP_MIC_ALLO_LEN256     01313           /* LEN256 field error */
#define DAP_MIC_ALLO_BITCNT     01314           /* BITCNT field error */
#define DAP_MIC_ALLO_SYSPEC     01315           /* SYSPEC field error */
#define DAP_MIC_ALLO_ALLMENU    01320           /* ALLMENU field error */
#define DAP_MIC_ALLO_VOL        01321           /* VOL field error */
#define DAP_MIC_ALLO_ALN        01322           /* ALN field error */
#define DAP_MIC_ALLO_AOP        01323           /* AOP field error */
#define DAP_MIC_ALLO_LOC        01324           /* LOC field error */
#define DAP_MIC_ALLO_RFI        01325           /* RFI field error */
#define DAP_MIC_ALLO_ALQ        01326           /* ALQ field error */
#define DAP_MIC_ALLO_AID        01327           /* AID field error */
#define DAP_MIC_ALLO_BKZ        01330           /* BKZ field error */
#define DAP_MIC_ALLO_DEQ        01331           /* DEQ field error */

                                                /* Summary message */
#define DAP_MIC_SUMM_UNKNOWN    01400           /* Unknown field */
#define DAP_MIC_SUMM_FLAGS      01410           /* FLAGS field error */
#define DAP_MIC_SUMM_STREAMID   01411           /* STREAMID field error */
#define DAP_MIC_SUMM_LENGTH     01412           /* LENGTH field error */
#define DAP_MIC_SUMM_LEN256     01413           /* LEN256 field error */
#define DAP_MIC_SUMM_BITCNT     01414           /* BITCNT field error */
#define DAP_MIC_SUMM_SYSPEC     01415           /* SYSPEC field error */
#define DAP_MIC_SUMM_SUMENU     01420           /* SUMENU field error */
#define DAP_MIC_SUMM_NOK        01421           /* NOK field error */
#define DAP_MIC_SUMM_NOA        01422           /* NOA field error */
#define DAP_MIC_SUMM_NOR        01423           /* NOR field error */
#define DAP_MIC_SUMM_PVN        01424           /* PVN field error */

                                                /* Date and Time message */
#define DAP_MIC_DTIM_UNKNOWN    01500           /* Unknown field */
#define DAP_MIC_DTIM_FLAGS      01510           /* FLAGS field error */
#define DAP_MIC_DTIM_STREAMID   01511           /* STREAMID field error */
#define DAP_MIC_DTIM_LENGTH     01512           /* LENGTH field error */
#define DAP_MIC_DTIM_LEN256     01513           /* LEN256 field error */
#define DAP_MIC_DTIM_BITCNT     01514           /* BITCNT field error */
#define DAP_MIC_DTIM_SYSPEC     01515           /* SYSPEC field error */
#define DAP_MIC_DTIM_DATMENU    01520           /* DATMENU field error */
#define DAP_MIC_DTIM_CDT        01521           /* CDT field error */
#define DAP_MIC_DTIM_RDT        01522           /* RDT field error */
#define DAP_MIC_DTIM_EDT        01523           /* EDT field error */
#define DAP_MIC_DTIM_RVN        01524           /* RVN field error */

                                                /* Protection message */
#define DAP_MIC_PROT_UNKNOWN    01600           /* Unknown field */
#define DAP_MIC_PROT_FLAGS      01610           /* FLAGS field error */
#define DAP_MIC_PROT_STREAMID   01611           /* STREAMID field error */
#define DAP_MIC_PROT_LENGTH     01612           /* LENGTH field error */
#define DAP_MIC_PROT_LEN256     01613           /* LEN256 field error */
#define DAP_MIC_PROT_BITCNT     01614           /* BITCNT field error */
#define DAP_MIC_PROT_SYSPEC     01615           /* SYSPEC field error */
#define DAP_MIC_PROT_PROTMENU   01620           /* PROTMENU field error */
#define DAP_MIC_PROT_OWNER      01621           /* OWNER field error */
#define DAP_MIC_PROT_PROTSYS    01622           /* PROTSYS field error */
#define DAP_MIC_PROT_PROTOWN    01623           /* PROTOWN field error */
#define DAP_MIC_PROT_PROTGRP    01624           /* PROTGRP field error */
#define DAP_MIC_PROT_PROTWLD    01625           /* PROTWLD field error */

                                                /* Name message */
#define DAP_MIC_NAME_UNKNOWN    01700           /* Unknown field */
#define DAP_MIC_NAME_FLAGS      01710           /* FLAGS field error */
#define DAP_MIC_NAME_STREAMID   01711           /* STREAMID field error */
#define DAP_MIC_NAME_LENGTH     01712           /* LENGTH field error */
#define DAP_MIC_NAME_LEN256     01713           /* LEN256 field error */
#define DAP_MIC_NAME_BITCNT     01714           /* BITCNT field error */
#define DAP_MIC_NAME_SYSPEC     01715           /* SYSPEC field error */
#define DAP_MIC_NAME_NAMETYPE   01720           /* NAMETYPE field error */
#define DAP_MIC_NAME_NAMESPEC   01721           /* NAMESPEC field error */

                                                /* Access control list message */
#define DAP_MIC_ACL_UNKNOWN     02000           /* Unknown field */
#define DAP_MIC_ACL_FLAGS       02010           /* FLAGS field error */
#define DAP_MIC_ACL_STREAMID    02011           /* STREAMID field error */
#define DAP_MIC_ACL_LENGTH      02012           /* LENGTH field error */
#define DAP_MIC_ACL_LEN256      02013           /* LEN256 field error */
#define DAP_MIC_ACL_BITCNT      02014           /* BITCNT field error */
#define DAP_MIC_ACL_SYSPEC      02015           /* SYSPEC field error */
#define DAP_MIC_ACL_ACLCNT      02020           /* ACLCNT field error */
#define DAP_MIC_ACL_ACL         02021           /* ACL field error */

                                                /* I/O error codes */
#define DAP_MIC_IO_UNSPEC       0000            /* Unspecified error */
#define DAP_MIC_IO_ER_ABO       0001            /* Operation aborted */
#define DAP_MIC_IO_ER_ACC       0002            /* F11ACP could not access file */
#define DAP_MIC_IO_ER_ACT       0003            /* File activity precludes operation */
#define DAP_MIC_IO_ER_AID       0004            /* Bad area ID */
#define DAP_MIC_IO_ER_ALN       0005            /* Alignment options error */
#define DAP_MIC_IO_ER_ALQ       0006            /* Alloc. 0 or too large */
#define DAP_MIC_IO_ER_ANI       0007            /* Not ANSI D format */
#define DAP_MIC_IO_ER_AOP       0010            /* Allocation options error */
#define DAP_MIC_IO_ER_AST       0011            /* Invalid op. at AST level */
#define DAP_MIC_IO_ER_ATR       0012            /* Attribute read error */
#define DAP_MIC_IO_ER_ATW       0013            /* Attribute write error */
#define DAP_MIC_IO_ER_BKS       0014            /* Bucket size too large */
#define DAP_MIC_IO_ER_BKZ       0015            /* Bucket size too large */
#define DAP_MIC_IO_ER_BLN       0016            /* BLN length error */
#define DAP_MIC_IO_ER_BOF       0017            /* Beginning of file detected */
#define DAP_MIC_IO_ER_BPA       0020            /* Private pool address */
#define DAP_MIC_IO_ER_BPS       0021            /* Private pool size */
#define DAP_MIC_IO_ER_BUG       0022            /* Internal RMS error */
#define DAP_MIC_IO_ER_CCR       0023            /* Cannot connect RAB */
#define DAP_MIC_IO_ER_CHG       0024            /* $UPDATE changed key */
#define DAP_MIC_IO_ER_CHK       0025            /* Bucket format failure */
#define DAP_MIC_IO_ER_CLS       0026            /* RSTS/E close failed */
#define DAP_MIC_IO_ER_COD       0027            /* Invalid COD field */
#define DAP_MIC_IO_ER_CRE       0030            /* F11ACP create failed */
#define DAP_MIC_IO_ER_CUR       0031            /* No current record */
#define DAP_MIC_IO_ER_DAC       0032            /* F11ACP deaccess error */
#define DAP_MIC_IO_ER_DAN       0033            /* Data area number invalid */
#define DAP_MIC_IO_ER_DEL       0034            /* RFA-accessed record deleted */
#define DAP_MIC_IO_ER_DEV       0035            /* Bad device */
#define DAP_MIC_IO_ER_DIR       0036            /* Error in directory name */
#define DAP_MIC_IO_ER_DME       0037            /* Dynamic memory exhausted */
#define DAP_MIC_IO_ER_DNF       0040            /* Directory not found */
#define DAP_MIC_IO_ER_DNR       0041            /* Device not ready */
#define DAP_MIC_IO_ER_DPE       0042            /* Device positioning error */
#define DAP_MIC_IO_ER_DTP       0043            /* DTP field invalid */
#define DAP_MIC_IO_ER_DUP       0044            /* Duplicate key detected */
#define DAP_MIC_IO_ER_ENT       0045            /* F11ACP enter failed */
#define DAP_MIC_IO_ER_ENV       0046            /* No operation in ORG$ */
#define DAP_MIC_IO_ER_EOF       0047            /* End-of-file */
#define DAP_MIC_IO_ER_ESS       0050            /* String area too short */
#define DAP_MIC_IO_ER_EXP       0051            /* Not yet expiration date */
#define DAP_MIC_IO_ER_EXT       0052            /* File extend failure */
#define DAP_MIC_IO_ER_FAB       0053            /* Invalid FAB */
#define DAP_MIC_IO_ER_FAC       0054            /* Illegal FAC */
#define DAP_MIC_IO_ER_FEX       0055            /* File already exists */
#define DAP_MIC_IO_ER_FID       0056            /* Invalid file ID */
#define DAP_MIC_IO_ER_FLG       0057            /* Invalid flag bits */
#define DAP_MIC_IO_ER_FLK       0060            /* File locked by other user */
#define DAP_MIC_IO_ER_FND       0061            /* F11ACP find failed */
#define DAP_MIC_IO_ER_FNF       0062            /* File not found */
#define DAP_MIC_IO_ER_FNM       0063            /* Error in file name */
#define DAP_MIC_IO_ER_FOP       0064            /* Invalid file options */
#define DAP_MIC_IO_ER_FUL       0065            /* Device/file full */
#define DAP_MIC_IO_ER_IAN       0066            /* Index area number invalid */
#define DAP_MIC_IO_ER_IFI       0067            /* Invalid IFI */
#define DAP_MIC_IO_ER_IMX       0070            /* Max areas/keys exceeded */
#define DAP_MIC_IO_ER_INI       0071            /* No $INIT macro issued */
#define DAP_MIC_IO_ER_IOP       0072            /* Operation illegal */
#define DAP_MIC_IO_ER_IRC       0073            /* Illegal record */
#define DAP_MIC_IO_ER_ISI       0074            /* Invalid ISI value */
#define DAP_MIC_IO_ER_KBF       0075            /* Bad key buffer address */
#define DAP_MIC_IO_ER_KEY       0076            /* Invalid KEY field */
#define DAP_MIC_IO_ER_KRF       0077            /* Invalid key-of-reference */
#define DAP_MIC_IO_ER_KSZ       0100            /* KEY size too large */
#define DAP_MIC_IO_ER_LAN       0101            /* Area number invalid */
#define DAP_MIC_IO_ER_LBL       0102            /* Not ANSI labelled tape */
#define DAP_MIC_IO_ER_LBY       0103            /* Logical channel busy */
#define DAP_MIC_IO_ER_LCH       0104            /* Channel number too large */
#define DAP_MIC_IO_ER_LEX       0105            /* Logical extend error */
#define DAP_MIC_IO_ER_LOC       0106            /* LOC field invalid */
#define DAP_MIC_IO_ER_MAP       0107            /* Buffer mapping error */
#define DAP_MIC_IO_ER_MKD       0110            /* Mark for delete failed */
#define DAP_MIC_IO_ER_MRN       0111            /* Bad MRN value */
#define DAP_MIC_IO_ER_MRS       0112            /* Bad MRS value */
#define DAP_MIC_IO_ER_NAM       0113            /* Invalid NAM block address */
#define DAP_MIC_IO_ER_NEF       0114            /* Not positioned at EOF */
#define DAP_MIC_IO_ER_NID       0115            /* Index descr. alloc failed */
#define DAP_MIC_IO_ER_NPK       0116            /* No primary key defined */
#define DAP_MIC_IO_ER_OPN       0117            /* RSTS/E open failed */
#define DAP_MIC_IO_ER_ORD       0120            /* XABs in incorrect order */
#define DAP_MIC_IO_ER_ORG       0121            /* Invalid file organization */
#define DAP_MIC_IO_ER_PLG       0122            /* File prologue error */
#define DAP_MIC_IO_ER_POS       0123            /* Invalid POS field */
#define DAP_MIC_IO_ER_PRM       0124            /* Bad file date field */
#define DAP_MIC_IO_ER_PRV       0125            /* Privilege violation */
#define DAP_MIC_IO_ER_RAB       0126            /* Not a valid RAB */
#define DAP_MIC_IO_ER_RAC       0127            /* Illegal RAC value */
#define DAP_MIC_IO_ER_RAT       0130            /* Illegal record attributes */
#define DAP_MIC_IO_ER_RBF       0131            /* Invalid buffer address */
#define DAP_MIC_IO_ER_RER       0132            /* File read error */
#define DAP_MIC_IO_ER_REX       0133            /* Record already exists */
#define DAP_MIC_IO_ER_RFA       0134            /* Bad RFA value */
#define DAP_MIC_IO_ER_RFM       0135            /* Invalid record format */
#define DAP_MIC_IO_ER_RLK       0136            /* Target bucked locked */
#define DAP_MIC_IO_ER_RMV       0137            /* Remove function failed */
#define DAP_MIC_IO_ER_RNF       0140            /* Record not found */
#define DAP_MIC_IO_ER_RNL       0141            /* Record not locked */
#define DAP_MIC_IO_ER_ROP       0142            /* Invalid record options */
#define DAP_MIC_IO_ER_RPL       0143            /* Error reading prologue */
#define DAP_MIC_IO_ER_RRV       0144            /* Invalid RRV record */
#define DAP_MIC_IO_ER_RSA       0145            /* RAB stream active */
#define DAP_MIC_IO_ER_RSZ       0146            /* Bad record size */
#define DAP_MIC_IO_ER_RTB       0147            /* Record too big */
#define DAP_MIC_IO_ER_SEQ       0150            /* Primary key out of sequence */
#define DAP_MIC_IO_ER_SHR       0151            /* Invalid SHR field */
#define DAP_MIC_IO_ER_SIZ       0152            /* SIZ field invalid */
#define DAP_MIC_IO_ER_STK       0153            /* Stack too big */
#define DAP_MIC_IO_ER_SYS       0154            /* System directive error */
#define DAP_MIC_IO_ER_TRE       0155            /* Index tree error */
#define DAP_MIC_IO_ER_TYP       0156            /* File type extension error */
#define DAP_MIC_IO_ER_UBF       0157            /* Invalid user buffer address */
#define DAP_MIC_IO_ER_USZ       0160            /* Invalid user buffer size */
#define DAP_MIC_IO_ER_VER       0161            /* Error in version number */
#define DAP_MIC_IO_ER_VOL       0162            /* Invalid volume number */
#define DAP_MIC_IO_ER_WER       0163            /* File write error */
#define DAP_MIC_IO_ER_WLK       0164            /* Device is write locked */
#define DAP_MIC_IO_ER_WPL       0165            /* Error writing prologue */
#define DAP_MIC_IO_ER_XAB       0166            /* Not a valid XAB */
#define DAP_MIC_IO_BUGDDI       0167            /* Default directory invalid */
#define DAP_MIC_IO_CAA          0170            /* Cannot access arg list */
#define DAP_MIC_IO_CCF          0171            /* Cannot close file */
#define DAP_MIC_IO_CDA          0172            /* Cannot deliver AST */
#define DAP_MIC_IO_CHN          0173            /* Channel assignment failed */
#define DAP_MIC_IO_CNTRLO       0174            /* Terminal output ignored */
#define DAP_MIC_IO_CNTRLY       0175            /* Terminal output aborted */
#define DAP_MIC_IO_DNA          0176            /* Default filename error */
#define DAP_MIC_IO_DVI          0177            /* Invalid device ID field */
#define DAP_MIC_IO_ESA          0200            /* Expanded string addr error */
#define DAP_MIC_IO_FNA          0201            /* Filename string addr error */
#define DAP_MIC_IO_FSZ          0202            /* FSZ field invalid */
#define DAP_MIC_IO_IAL          0203            /* Invalid argument list */
#define DAP_MIC_IO_KFF          0204            /* Known file found */
#define DAP_MIC_IO_LNE          0205            /* Logical name error */
#define DAP_MIC_IO_NOD          0206            /* Node name error */
#define DAP_MIC_IO_NORMAL       0207            /* Operation successful */
#define DAP_MIC_IO_OK_DUP       0210            /* Inserted record had duplicate key */
#define DAP_MIC_IO_OK_IDX       0211            /* Index update error */
#define DAP_MIC_IO_OK_RLK       0212            /* Read while record locked */
#define DAP_MIC_IO_OK_RRV       0213            /* Record inserted */
#define DAP_MIC_IO_CREATE       0214            /* File created, not opened */
#define DAP_MIC_IO_PBF          0215            /* Bad prompt buffer address */
#define DAP_MIC_IO_PNDING       0216            /* Async op pending */
#define DAP_MIC_IO_QUO          0217            /* Quoted string error */
#define DAP_MIC_IO_RHB          0220            /* Record hdr buffer invalid */
#define DAP_MIC_IO_RLF          0221            /* Invalid related file */
#define DAP_MIC_IO_RSS          0222            /* Invalid resultant string size */
#define DAP_MIC_IO_RST          0223            /* Invalid resultant string addres */
#define DAP_MIC_IO_SQO          0224            /* Operation not sequential */
#define DAP_MIC_IO_SUC          0225            /* Operation successful */
#define DAP_MIC_IO_SPRSED       0226            /* Create superseded file */
#define DAP_MIC_IO_SYN          0227            /* Filename syntax error */
#define DAP_MIC_IO_TMO          0230            /* Time-out period expired */
#define DAP_MIC_IO_ER_BLK       0231            /* FB$BLK not supported */
#define DAP_MIC_IO_ER_BSZ       0232            /* Bad byte size */
#define DAP_MIC_IO_ER_CDR       0233            /* Cannot disconnect RAB */
#define DAP_MIC_IO_ER_CGJ       0234            /* Cannot get file JFN */
#define DAP_MIC_IO_ER_COF       0235            /* Cannot open file */
#define DAP_MIC_IO_ER_JFN       0236            /* Bad JFN value */
#define DAP_MIC_IO_ER_PEF       0237            /* Cannot position to EOF */
#define DAP_MIC_IO_ER_TRU       0240            /* Cannot truncate file */
#define DAP_MIC_IO_ER_UDF       0241            /* File in undefined state */
#define DAP_MIC_IO_ER_XCL       0242            /* Exclusive access */
#define DAP_MIC_IO_DIRFULL      0243            /* Directory full */
#define DAP_MIC_IO_NOHANDLER    0244            /* Handler not in system */
#define DAP_MIC_IO_FATAL        0245            /* Fatal hardware error */
#define DAP_MIC_IO_BEYONDEOF    0246            /* Write beyond EOF */
#define DAP_MIC_IO_NOTPRESENT   0247            /* Hardware option not present */
#define DAP_MIC_IO_NOTATTACHED  0250            /* Device not attached */
#define DAP_MIC_IO_ATTACHED     0251            /* Device already attached */
#define DAP_MIC_IO_NOATTACH     0252            /* Device not attachable */
#define DAP_MIC_IO_SHRINUSE     0253            /* Shareable resource in use */
#define DAP_MIC_IO_ILLEGALOVR   0254            /* Illegal overlay request */
#define DAP_MIC_IO_CRCERROR     0255            /* Block check/CRC error */
#define DAP_MIC_IO_NONODES      0256            /* Caller's nodes exhausted */
#define DAP_MIC_IO_IDXFULL      0257            /* Index file full */
#define DAP_MIC_IO_HDRFULL      0260            /* File header full */
#define DAP_MIC_IO_WRACCESSED   0261            /* Accessed for write */
#define DAP_MIC_IO_HDRCHECKSUM  0262            /* File hdr checsum failure */
#define DAP_MIC_IO_BADATTRIB    0263            /* Attribute control list fail */
#define DAP_MIC_IO_LUNACCESS    0264            /* File already accessed on LUN */
#define DAP_MIC_IO_BADTAPE      0265            /* Bad tape format */
#define DAP_MIC_IO_BADOP        0266            /* Bad op on file descriptor */
#define DAP_MIC_IO_RENOVERDEVS  0267            /* Rename across devices */
#define DAP_MIC_IO_RENNAMEUSE   0270            /* Rename name already in use */
#define DAP_MIC_IO_RENOLDFS     0271            /* Cannot rename old FS */
#define DAP_MIC_IO_FILEOPEN     0272            /* File already open */
#define DAP_MIC_IO_PARITY       0273            /* Parity error on device */
#define DAP_MIC_IO_EOV          0274            /* End of volume detected */
#define DAP_MIC_IO_OVERRUN      0275            /* Data over-run */
#define DAP_MIC_IO_BADBLOCK     0276            /* Bad block on device */
#define DAP_MIC_IO_ENDTAPE      0277            /* End of tape detected */
#define DAP_MIC_IO_NOBUFFER     0300            /* No buffer space for file */
#define DAP_MIC_IO_NOBLOCKS     0301            /* File exceeds allocation */
#define DAP_MIC_IO_NOTINSTALLED 0302            /* Task not installed */
#define DAP_MIC_IO_UNLOCK       0303            /* Unlock error */
#define DAP_MIC_IO_NOFILE       0304            /* No file accessed on LUN */
#define DAP_MIC_IO_SRERROR      0305            /* Send/Receive error */
#define DAP_MIC_IO_SPL          0306            /* Spool/submit failure */
#define DAP_MIC_IO_NMF          0307            /* No more files */
#define DAP_MIC_IO_CRC          0310            /* Xfer checksum error */
#define DAP_MIC_IO_QUOTA        0311            /* Quota exceeded */
#define DAP_MIC_IO_BUGDAP       0312            /* Internal network error */
#define DAP_MIC_IO_CNTRLC       0313            /* Terminal input aborted */
#define DAP_MIC_IO_DFL          0314            /* Bad data bucket file size */
#define DAP_MIC_IO_ESL          0315            /* Invalid expanded string size */
#define DAP_MIC_IO_IBF          0316            /* Illegal bucket format */
#define DAP_MIC_IO_IBK          0317            /* Bad bucket size */
#define DAP_MIC_IO_IDX          0320            /* Index not initialized */
#define DAP_MIC_IO_IFA          0321            /* Illegal file attributes */
#define DAP_MIC_IO_IFL          0322            /* Bad index bucket fill size */
#define DAP_MIC_IO_KNM          0323            /* No access to key name buffer */
#define DAP_MIC_IO_KSI          0324            /* No key space */
#define DAP_MIC_IO_MBC          0325            /* Invalid multi-buffer count */
#define DAP_MIC_IO_NET          0326            /* Network op failed */
#define DAP_MIC_IO_OK_ALK       0327            /* Record already locked */
#define DAP_MIC_IO_OK_DEL       0330            /* Accessed deleted record */
#define DAP_MIC_IO_OK_LIM       0331            /* Key value exceeded */
#define DAP_MIC_IO_OK_NOP       0332            /* Key XAB not filled in */
#define DAP_MIC_IO_OK_RNF       0333            /* Non-existent record accessed */
#define DAP_MIC_IO_PLV          0334            /* Unsupported prologue version */
#define DAP_MIC_IO_REF          0335            /* Illegal key-of-reference */
#define DAP_MIC_IO_RSL          0336            /* Invalid resultant string length */
#define DAP_MIC_IO_RVU          0337            /* Error updating RRVs */
#define DAP_MIC_IO_SEG          0340            /* Bad data types */
#define DAP_MIC_IO_RSVD1        0341            /* Reserved */
#define DAP_MIC_IO_SUP          0342            /* Op not supported over net */
#define DAP_MIC_IO_WBE          0343            /* Error on write behind */
#define DAP_MIC_IO_WLD          0344            /* Invalid wildcard operation */
#define DAP_MIC_IO_WSF          0345            /* Working set full */
#define DAP_MIC_IO_DIRLSTNAME   0346            /* Directory list - name */
#define DAP_MIC_IO_DIRLSTATTR   0347            /* Directory list - attributes */
#define DAP_MIC_IO_DIRLSTPROT   0350            /* Directory list - protection */
#define DAP_MIC_IO_DIRLSTPROTA  0351            /* Directory list - attributes protection */
#define DAP_MIC_IO_DIRLSTNOATTR 0352            /* Directory list - no attributes */
#define DAP_MIC_IO_DIRLSTXFER   0353            /* Directory list - xfer */
#define DAP_MIC_IO_SNE          0354            /* Sharing not enabled */
#define DAP_MIC_IO_SPE          0355            /* Sharing page count exceeded */
#define DAP_MIC_IO_UPI          0356            /* UPI bit not set */
#define DAP_MIC_IO_ACS          0357            /* Access control error */
#define DAP_MIC_IO_TNS          0360            /* Terminator not seen */
#define DAP_MIC_IO_BES          0361            /* Bad escape sequence */
#define DAP_MIC_IO_PES          0362            /* Partial escape sequence */
#define DAP_MIC_IO_WCC          0363            /* Invalid wildcard context */
#define DAP_MIC_IO_IDR          0364            /* Invalid directory rename */
#define DAP_MIC_IO_STR          0365            /* FAB/RAB became invalid */
#define DAP_MIC_IO_FTM          0366            /* Transfer mode not allowed */

                                                /* Synchronization msg. type codes */
#define DAP_MIC_SYNC_UNKNOWN    0               /* Unknown msg. type */
#define DAP_MIC_SYNC_CONFIG     1               /* Configuration msg. */
#define DAP_MIC_SYNC_ATTRIB     2               /* Attributes msg. */
#define DAP_MIC_SYNC_ACCESS     3               /* Access msg. */
#define DAP_MIC_SYNC_CONTROL    4               /* Control msg. */
#define DAP_MIC_SYNC_CONTINUE   5               /* Continus transfer msg. */
#define DAP_MIC_SYNC_ACK        6               /* Acknowledge msg. */
#define DAP_MIC_SYNC_COMPLETE   7               /* Access complete msg. */
#define DAP_MIC_SYNC_DATA       8               /* Data msg. */
#define DAP_MIC_SYNC_STATUS     9               /* Status msg. */
#define DAP_MIC_SYNC_KEYDEF     10              /* Key definition msg. */
#define DAP_MIC_SYNC_ALLOC      11              /* Allocation attributes msg. */
#define DAP_MIC_SYNC_SUMMARY    12              /* Summary attributes msg. */
#define DAP_MIC_SYNC_DTIME      13              /* Date and Time attributes msg. */
#define DAP_MIC_SYNC_PROTECT    14              /* Protection attributes msg. */
#define DAP_MIC_SYNC_NAME       15              /* Name msg. */
#define DAP_MIC_SYNC_ACL        16              /* Access control list msg. */

                                                /* Key definition attributes extension message */
/*
 * Key menu values
 */
#define DAP_KMNU_FLG            0               /* Key option flags */
#define DAP_KMNU_DFL            1               /* Data bucket fill */
#define DAP_KMNU_IFL            2               /* Index bucket fill */
#define DAP_KMNU_NSG            3               /* Number of key segments */
#define DAP_KMNU_REF            4               /* Key-of-reference ind. */
#define DAP_KMNU_KNM            5               /* Key name for REF */
#define DAP_KMNU_NUL            6               /* Null key character */
#define DAP_KMNU_IAN            7               /* Index area number */
#define DAP_KMNU_LAN            8               /* Lowest index area number */
#define DAP_KMNU_DAN            9               /* Data level area number */
#define DAP_KMNU_DTP            10              /* Data type */
#define DAP_KMNU_RVB            11              /* Root VBN for key */
#define DAP_KMNU_HAL            12              /* Hash algorithm (RSVD) */
#define DAP_KMNU_DVB            13              /* 1st data bucket VBN */
#define DAP_KMNU_DBS            14              /* Data bucket size */
#define DAP_KMNU_IBS            15              /* Index bucket size */
#define DAP_KMNU_LVL            16              /* Root bucket level */
#define DAP_KMNU_TKS            17              /* Total key size */
#define DAP_KMNU_MRL            18              /* Minimum record length */

/*
 * Key option values
 */
#define DAP_KEY_OPT_DUP         0               /* Duplicates allowed */
#define DAP_KEY_OPT_CHG         1               /* Allow keys to change */
#define DAP_KEY_OPT_NUL         2               /* Null key char defined */

                                                /* Allocation attributes extension message */
/*
 * Allocation menu values
 */
#define DAP_AMNU_VOL            0               /* Relative volume number */
#define DAP_AMNU_ALN            1               /* Alignment options */
#define DAP_AMNU_AOP            2               /* Allocation options */
#define DAP_AMNU_LOC            3               /* Allocation starting point */
#define DAP_AMNU_RFI            4               /* Related file ID (RSVD) */
#define DAP_AMNU_ALQ            5               /* Allocation size */
#define DAP_AMNU_AID            6               /* Area ID */
#define DAP_AMNU_BKZ            7               /* Bucket size for area */
#define DAP_AMNU_DEQ            8               /* Default extension size */

/*
 * Alignment options
 */
#define DAP_ALLOC_ALN_ANY       0               /* No specified alignment */
#define DAP_ALLOC_ALN_CYL       1               /* Cylinder boundary */
#define DAP_ALLOC_ALN_LBN       2               /* Specified LBN */
#define DAP_ALLOC_ALN_VBN       3               /* Near to VBN */
#define DAP_ALLOC_ALN_RFI       4               /* Near to related file */

/*
 * Allocation options
 */
#define DAP_ALLOC_AOP_HRD       0               /* Error on alignment fail */
#define DAP_ALLOC_AOP_CTG       1               /* Contiguous allocation */
#define DAP_ALLOC_AOP_CBT       2               /* Contiguous best try */
#define DAP_ALLOC_AOP_ONC       3               /* Any cylinder boundary */

                                                /* Summary attributes extension message */
/*
 * Summary menu values
 */
#define DAP_SMNU_NOK            0               /* # of keys in file */
#define DAP_SMNU_NOA            1               /* # of areas in file */
#define DAP_SMNU_NOR            2               /* # of records in file */
#define DAP_SMNU_PVN            3               /* Prologue version number */

                                                /* Date and Time attributes extension message */
/*
 * Date and Time menu values
 */
#define DAP_DMNU_CDT            0               /* Creation date/time */
#define DAP_DMNU_RDT            1               /* Last update date/time */
#define DAP_DMNU_EDT            2               /* Deletion allowed date/time */
#define DAP_DMNU_RVN            3               /* File revision number */

                                                /* Protection attributes extension message */
/*
 * Protection menu values
 */
#define DAP_PMNU_OWNER          0               /* Name/ID of owner */
#define DAP_PMNU_PROTSYS        1               /* Protection for system access */
#define DAP_PMNU_PROTOWN        2               /* Protection for owner access */
#define DAP_PMNU_PROTGRP        3               /* Protection for group access */
#define DAP_PMNU_PROTWLD        4               /* Protection for world access */

/*
 * Protection values
 */
#define DAP_PROT_DENY_READ      0               /* Deny read access */
#define DAP_PROT_DENY_WRITE     1               /* Deny write access */
#define DAP_PROT_DENY_EXEC      2               /* Deny execute access */
#define DAP_PROT_DENY_DELETE    3               /* Deny delete access */
#define DAP_PROT_DENY_APPEND    4               /* Deny append access */
#define DAP_PROT_DENY_DIRLIST   5               /* Deny directory list access */
#define DAP_PROT_DENY_UPDATE    6               /* Deny update access */
#define DAP_PROT_DENY_CHANGE    7               /* Deny protection change access */
#define DAP_PROT_DENY_EXTEND    8               /* Deny extend access */

                                                /* Name message */
#define DAP_NAME_TYPE_FILESPEC  0               /* File specification */
#define DAP_NAME_TYPE_FILENAME  1               /* File name */
#define DAP_NAME_TYPE_DIRECTORY 2               /* Directory name */
#define DAP_NAME_TYPE_VOLUME    3               /* Volume/structure name */
#define DAP_NAME_TYPE_DEFAULT   4               /* Default filespec (RSVD) */
#define DAP_NAME_TYPE_RELATED   5               /* Related filespec (RSVD) */

#define DAP_NAME_MAX_NAMESPEC   200             /* Max length of namespec */

extern void ReportError(uint16_t);

extern void DumpMessageMetadata(void);
extern int DAPeom(void);
extern int DAPbGet(uint8_t *);
extern int DAP2bGet(uint16_t *);
extern int DAPfGet(uint8_t**, uint16_t);
extern int DAPiGet(uint8_t **, uint8_t);
extern int DAPexValid(uint8_t **, uint8_t);
extern int DAPexGetBit(uint8_t *, int);
extern void DAPexCopy(uint8_t *, uint8_t *, size_t);
extern void DAPgetFiledata(uint8_t **, uint16_t *);
extern uint64_t DAPi2int(uint8_t *);
extern char *DAPi2string(uint8_t *, char *);
extern uint64_t DAPex2int(uint8_t *);
extern char *DAPf2string(uint8_t *, uint16_t, char *);
extern int DAPread(void);
extern int DAPnextMessage(uint8_t *);
extern int DAPcheckRead(void);
extern void DAPlogRcvMessage(void);
extern void DAPlogUnexpectedMessage(void);
extern void DAPbPut(void *, uint8_t);
extern void DAP2bPut(void *, uint16_t);
extern void DAPiPut(void *, uint8_t, uint8_t *);
extern void DAPexInit(void *, int);
extern void DAPexDone(void *);
extern void DAPexSetBit(void *, int);
extern void DAPhdrDone(void *);
extern void DAPint2i(void *, uint8_t, uint64_t);
extern void DAPstring2i(void *, uint8_t, char *);
extern void *DAPallocBuf(void);
extern void DAPreleaseBuf(void *);
extern ssize_t DAPflushBuffers(void);
extern int DAPwrite(void *);
extern void *DAPbuildHeader(uint8_t);
extern void *DAPbuildHeader1Len(uint8_t);
extern void *DAPbuildHeader2Len(uint8_t);
extern void DAPallocateSpace(void *, size_t);
extern uint8_t *DAPgetEnd(void *);
extern int DAPaddDateTime(void *, struct timespec *);
extern void DAPsendAcknowledge(void);
extern void DAPsendName(uint8_t, char *);
extern void DAPinit(int, uint8_t *, int);

/*
 * Access a bit in an extensible field which has been converted to a uint64_t
 * via DAPex2int().
 */
#define EXBIT(v, b)     (v & (1 << b))

#endif
