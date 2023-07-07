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

#ifndef __NICE_H__
#define __NICE_H__

/*
 * Maximum string lengths for various parameters/entities
 */
#define NICE_MAXNODEL           6
#define NICE_MAXCIRCUITL        16

/*
 * Function codes
 */
#define NICE_FC_DLL             15              /* Request down-line load */
#define NICE_FC_ULD             16              /* Request up-line dump */
#define NICE_FC_BOOT            17              /* Trigger bootstrap */
#define NICE_FC_TEST            18              /* Test */
#define NICE_FC_CHANGE          19              /* Change parameter */
#define NICE_FC_READ            20              /* Read information */
#define NICE_FC_ZERO            21              /* Zero counters */
#define NICE_FC_SYS             22              /* System specific function */

/*
 * Option values
 */
                                                /* Read information */
#define NICE_READ_OPT_PERM      0x80            /* Permanent vs. volatile */
#define NICE_READ_OPT_TYPE      0x70            /* Information type field */
#define NICE_READ_OPT_SUM       0x00            /* Summary */
#define NICE_READ_OPT_STATUS    0x10            /* Status */
#define NICE_READ_OPT_CHAR      0x20            /* Characteristics */
#define NICE_READ_OPT_CTRS      0x30            /* Counters */
#define NICE_READ_OPT_EVENTS    0x40            /* Events */
#define NICE_READ_OPT_ENTITY    0x07            /* Entity field */

/*
 * Entity type numbers
 */
#define NICE_ENT_NODE           0               /* Node entity */
#define NICE_ENT_LINE           1               /* Line entity */
#define NICE_ENT_LOGGING        2               /* Logging entity */
#define NICE_ENT_CIRCUIT        3               /* Circuit entity */
#define NICE_ENT_MODULE         4               /* Module entity */
#define NICE_ENT_AREA           5               /* Area entity */

/*
 * String identifier format
 */
#define NICE_SFMT_SIGNIFICANT  251              /* Significant */
#define NICE_SFMT_ACTIVE       254              /* Active */
#define NICE_SFMT_KNOWN        255              /* Known */

/*
 * Node identifier format
 */
#define NICE_NFMT_SIGNIFICANT  251              /* Significant nodes */
#define NICE_NFMT_ADJACENT     252              /* Adjacent nodes */
#define NICE_NFMT_LOOP         253              /* Loop nodes */
#define NICE_NFMT_ACTIVE       254              /* Active nodes */
#define NICE_NFMT_KNOWN        255              /* Known nodes */
#define NICE_NFMT_ADDRESS        0              /* Specific node address */

/*
 * Area identifier format
 */
#define NICE_AFMT_ACTIVE       254              /* Active areas */
#define NICE_AFMT_KNOWN        255              /* Known areas */
#define NICE_AFMT_ADDRESS        0              /* Specific area */

/*
 * Object identifier format
 */
#define NICE_OFMT_NUMERIC        0              /* Numeric object number */

/*
 * Data ID
 */
#define NICE_ID_PARAM           0x0000          /* Parameter */
#define NICE_ID_PARAM_TYPE      0x0FFF          /* Parameter type */
#define NICE_ID_PARAM_RSVD      0xF000          /* Reserved */

#define NICE_ID_CTR             0x8000          /* Counter */
#define NICE_ID_CTR_TYPE        0x0FFF          /* Counter type */
#define NICE_ID_CTR_BITMAP      0x1000          /* Bitmap counter */
#define NICE_ID_CTR_LENGTH      0x6000          /* Counter length encoding */
#define NICE_ID_CTR_LEN_RSVD    0x0000          /* Reserved length encoding */
#define NICE_ID_CTR_LEN_8BIT    0x2000          /* 8-bit counter */
#define NICE_ID_CTR_LEN_16BIT   0x4000          /* 16-bit counter */
#define NICE_ID_CTR_LEN_32BIT   0x6000          /* 32-bit counter */

/*
 * Data type
 */
#define NICE_TYPE_NC            0x00            /* Not coded */
#define NICE_TYPE_NC_BIN        0x00            /* Binary number */
#define NICE_TYPE_NC_BIN_IMAGE  0x00            /* Image field */
#define NICE_TYPE_NC_BIN_LEN    0x0F            /* Data length */
#define NICE_TYPE_NC_BIN_UNS    0x00            /* Unsigned decimal */
#define NICE_TYPE_NC_BIN_SIGN   0x10            /* Signed decimal */
#define NICE_TYPE_NC_BIN_HEX    0x20            /* Hexadecimal */
#define NICE_TYPE_NC_BIN_OCT    0x30            /* Octal */
#define NICE_TYPE_NC_ASCII      0x40            /* ASCII image field */

#define NICE_TYPE_C             0x80            /* Coded */
#define NICE_TYPE_C_SING        0x00            /* Single field */
#define NICE_TYPE_C_SING_BYTES  0x3F            /* Single field length */
#define NICE_TYPE_C_MULTI       0x40            /* Multiple fields */
#define NICE_TYPE_C_MULTI_CNT   0x3F            /* Multiple field count */

/*
 * Common data type encodings.
 */
#define NICE_TYPE_DU1 \
  (NICE_TYPE_NC | NICE_TYPE_NC_BIN | NICE_TYPE_NC_BIN_UNS | 1)
#define NICE_TYPE_DU2 \
  (NICE_TYPE_NC | NICE_TYPE_NC_BIN | NICE_TYPE_NC_BIN_UNS | 2)
#define NICE_TYPE_AI \
  (NICE_TYPE_NC | NICE_TYPE_NC_ASCII)
#define NICE_TYPE_HI \
  (NICE_TYPE_NC | NICE_TYPE_NC_BIN | NICE_TYPE_NC_BIN_IMAGE | NICE_TYPE_NC_BIN_HEX)
#define NICE_TYPE_C1 \
  (NICE_TYPE_C | NICE_TYPE_C_SING | 1)
#define NICE_TYPE_CM(n) \
  (NICE_TYPE_C | NICE_TYPE_C_MULTI | (n))

/*
 * Circuit parameters
 */
#define NICE_P_C_STATE          0               /* STATE (C-1) */
#define NICE_P_C_STATE_ON       0               /*   - ON */
#define NICE_P_C_STATE_OFF      1               /*   - OFF */
#define NICE_P_C_STATE_SERVICE  2               /*   - SERVICE */
#define NICE_P_C_STATE_CLEARED  3               /*   - CLEARED */

#define NICE_P_C_SSTATE         1               /* SUBSTATE (C-1) */
#define NICE_P_C_SSTATE_START    0              /*   - STARTING */
#define NICE_P_C_SSTATE_REFLECT  1              /*   - REFLECTING */
#define NICE_P_C_SSTATE_LOOP     2              /*   - LOOPING */
#define NICE_P_C_SSTATE_LOAD     3              /*   - LOADING */
#define NICE_P_C_SSTATE_DUMP     4              /*   - DUMPING */
#define NICE_P_C_SSTATE_TRIG     5              /*   - TRIGGERING */
#define NICE_P_C_SSTATE_AUTOS    6              /*   - AUTOSERVICE */
#define NICE_P_C_SSTATE_AUTOL    7              /*   - AUTOLOADING */
#define NICE_P_C_SSTATE_AUTOD    8              /*   - AUTODUMPING */
#define NICE_P_C_SSTATE_AUTOT    9              /*   - AUTOTRIGGERING */
#define NICE_P_C_SSTATE_SYNCH   10              /*   - SYNCHRONIZING */
#define NICE_P_C_SSTATE_FAILED  11              /*   - FAILED */

#define NICE_P_C_SERVICE        100             /* SERVICE (C-1) */
#define NICE_P_C_SERVICE_ENA    0               /*   - ENABLED */
#define NICE_P_C_SERVICE_DIS    1               /*   - DISABLED */

#define NICE_P_C_CTR_TIMER      110             /* COUNTER TIMER (DU-2) */
#define NICE_P_C_SERVICE_PA     120             /* SERVICE PHYS ADDR (HI-6) */
#define NICE_P_C_SSSTATE        121             /* SERVICE SUBSTATE */
#define NICE_P_C_SSSTATE_START    0             /*   - STARTING */
#define NICE_P_C_SSSTATE_REFLECT  1             /*   - REFLECTING */
#define NICE_P_C_SSSSTATE_LOOP    2             /*   - LOOPING */
#define NICE_P_C_SSSTATE_LOAD     3             /*   - LOADING */
#define NICE_P_C_SSSTATE_DUMP     4             /*   - DUMPING */
#define NICE_P_C_SSSTATE_TRIG     5             /*   - TRIGGERING */
#define NICE_P_C_SSSTATE_AUTOS    6             /*   - AUTOSERVICE */
#define NICE_P_C_SSSTATE_AUTOL    7             /*   - AUTOLOADING */
#define NICE_P_C_SSSTATE_AUTOD    8             /*   - AUTODUMPING */
#define NICE_P_C_SSSTATE_AUTOT    9             /*   - AUTOTRIGGERING */
#define NICE_P_C_SSSTATE_SYNCH   10             /*   - SYNCHRONIZING */
#define NICE_P_C_SSSTATE_FAILED  11             /*   - FAILED */

#define NICE_P_C_CONNNODE       200             /* CONNECTED NODE (CM-1/2) */
#define NICE_P_C_CONNOBJ        201             /* CONNECTED OBJECT (CM-1/2) */
#define NICE_P_C_LOOPNAME       400             /* LOOPBACK NAME (AI-6) */
#define NICE_P_C_ADJNODE        800             /* ADJACDENT NODE (CM-1/2) */
#define NICE_P_C_DR             801             /* DESIGNATED ROUTER (CM_1/2) */
#define NICE_P_C_BLOCKSIZE      810             /* BLOCK SIZE (DU-2) */
#define NICE_P_C_OQLIMIT        811             /* ORIGIATING QUEUE LIMIT (DU-2) */
#define NICE_P_C_COST           900             /* COST (DU-1) */
#define NICE_P_C_MAXROUTERS     901             /* MAXIMUM ROUTERS (DU-1) */
#define NICE_P_C_RPRIORITY      902             /* ROUTER PRIORITY (DU-1) */
#define NICE_P_C_HELLO          906             /* HELLO TIMER (DU-2) */
#define NICE_P_C_LISTEN         907             /* LISTEN TIMER (DU-2) */
#define NICE_P_C_BLOCKING       910             /* BLOCKING (C-1) */
#define NICE_P_C_BLOCKING_ENA   0               /*   - ENABLED */
#define NICE_P_C_BLOCKING_DIS   1               /*   - DISABLE */

#define NICE_P_C_MAXRECALLS     920             /* MAXIMUM RECALLS (DU-1) */
#define NICE_P_C_RECALL         921             /* RECALL TIMER (DU-2) */
#define NICE_P_C_NUMBER         930             /* NUMBER (AI-16) */
#define NICE_P_C_USER           1000            /* USER (CM-2/3) */
#define NICE_P_C_PSTATE         1010            /* POLLING STATE (C-1) */
#define NICE_P_C_PSTATE_AUTO    0               /*   - AUTOMATIC */
#define NICE_P_C_PSTATE_ACT     1               /*   - ACTIVE */
#define NICE_P_C_PSTATE_INACT   2               /*   - INACTIVE */
#define NICE_P_C_PSTATE_DYING   3               /*   - DYING */
#define NICE_P_C_PSTATE_DEAD    4               /*   - DEAD */

#define NICE_P_C_PSSTATE        1011            /* POLLING SUNSTATE (C-1) */
#define NICE_P_C_PSSTATE_ACT    0               /*   - ACTIVE */
#define NICE_P_C_PSSTATE_INACT  1               /*   - INACTIVE */
#define NICE_P_C_PSSTATE_DYING  2               /*   - DYING */
#define NICE_P_C_PSSTATE_DEAD   3               /*   - DEAD */

#define NICE_P_C_OWNER          1100            /* OWNER (CM-2/3) */
#define NICE_P_C_LINE           1110            /* LINE (AI-16) */
#define NICE_P_C_USAGE          1111            /* USAGE (C-1) */
#define NICE_P_C_USAGE_PERM     0               /*   - PERMANENT */
#define NICE_P_C_USAGE_INC      1               /*   - INCOMING */
#define NICE_P_C_USAGE_OUT      2               /*   - OUTGOING */

#define NICE_P_C_TYPE           1112            /* TYPE (C-1) */
#define NICE_P_C_TYPE_D_POINT   0               /*   - DDCMP POINT */
#define NICE_P_C_TYPE_D_CTRL    1               /*   - DDCMP CONTROL */
#define NICE_P_C_TYPE_D_TRIB    2               /*   - DDCMP TRIBUTARY */
#define NICE_P_C_TYPE_X25       3               /*   - X25 */
#define NICE_P_C_TYPE_D_DMC     4               /*   - DDCMP DMC */
#define NICE_P_C_TYPE_ETHER     6               /*   - ETHERNET */
#define NICE_P_C_TYPE_CI        7               /*   - CI */
#define NICE_P_C_TYPE_QP2       8               /*   - QP2 (DTE20) */
#define NICE_P_C_TYPE_BISYNC    9               /*   - BISYNC */

#define NICE_P_C_DTE            1120            /* DTE (AI-16) */
#define NICE_P_C_CHANNEL        1121            /* CHANNEL (DU-2) */
#define NICE_P_C_MAXDATA        1122            /* MAXIMUM DATA (DU-2) */
#define NICE_P_C_MAXWINDOW      1123            /* MAXIMUM WINDOW (DU-2) */
#define NICE_P_C_TRIB           1140            /* TRIBUTARY (DU-1) */
#define NICE_P_C_BABBLE         1141            /* BABBLE TIMER (DU-2) */
#define NICE_P_C_TRANSMIT       1142            /* TRANSMIT TIMER (DU-2) */
#define NICE_P_C_MAXBUFFERS     1145            /* MAXIMUM BUFFERS (C-1) */
                                                /* 1-254 - # of buffers */
#define NICE_P_C_MAXBUFFERS_UNL 255             /*   - UNLIMITED */

#define NICE_P_C_MAXTRANSMITS   1146            /* MAXIMUM TRANSMITS (DU-1) */
#define NICE_P_C_ACTIVEBASE     1150            /* ACTIVE BASE (DU-1) */
#define NICE_P_C_ACTIVEINCR     1151            /* ACTIVE INCREMENT (DU-1) */
#define NICE_P_C_INACTIVEBASE   1152            /* INACTIVE BASE (DU-1) */
#define NICE_P_C_INACTIVEINCR   1153            /* INACTIVE INCREMENT (DU-1) */
#define NICE_P_C_INACTIVETHRESH 1154            /* INACTIVE THRESHOLD (DU-1) */
#define NICE_P_C_DYINGBASE      1155            /* DYING BASE (DU-1) */
#define NICE_P_C_DYINGINCR      1156            /* DYING INCREMENT (DU-1) */
#define NICE_P_C_DYINGTHRESH    1157            /* DYING THRESHOLD (DU-1) */
#define NICE_P_C_DEADTHRESH     1158            /* DEAD THRESHOLD (DU-1) */

/*
 * Circuit counters
 */
#define NICE_C_C_SECONDS        0               /* Seconds since zeerod (16) */
#define NICE_C_C_PKTSRCVD       800             /* Terminating packets rcvd (32) */
#define NICE_C_C_PKTSSENT       801             /* Terminating packets sent (32) */
#define NICE_C_C_CONGLOSS       802             /* Congestion loss (16) */
#define NICE_C_C_CORRLOSS       805             /* Corruption loss (8) */
#define NICE_C_C_TRANS_PKTSRCVD 810             /* Transit packets rcvd (32) */
#define NICE_C_C_TRANS_PKTSSENT 811             /* Transit packets sent (32) */
#define NICE_C_C_TRANS_CONGLOSS 812             /* Transit congestion loss (16) */
#define NICE_C_C_CIRC_DOWN      820             /* Circuit down (8) */
#define NICE_C_C_INIT_FAIL      821             /* Initialization failure (8) */

                                                /* DDCMP Circuits */
#define NICE_C_C_D_BYTESRCVD    1000            /* Bytes received (32) */
#define NICE_C_C_D_BYTESSENT    1001            /* Bytes sent (32) */
#define NICE_C_C_D_DBRCVD       1010            /* Data blocks received (32) */
#define NICE_C_C_D_DBSENT       1011            /* Data blocks sent (32) */
#define NICE_C_C_D_DE_IN        1020            /* Data errors inbound (8) */
#define NICE_C_C_D_DE_IN_DATA   0x01            /*   - data block check */
#define NICE_C_C_D_DE_IN_REP    0x02            /*   - REP response */

#define NICE_C_C_D_DE_OUT       1021            /* Data errors outbound (8) */
#define NICE_C_C_D_DE_OUT_HDR   0x01            /*   - header block check */
#define NICE_C_C_D_DE_OUT_DATA  0x02            /*   - data block check */
#define NICE_C_C_D_DE_OUT_REP   0x04            /*   - REP response */

#define NICE_C_C_D_RREP_TMO     1030            /* Remote reply timouts (8) */
#define NICE_C_C_D_LREP_TMO     1031            /* Local reply timeouts (8) */
#define NICE_C_C_D_RBUF         1040            /* Remote buffer errors (8) */
#define NICE_C_C_D_RBUF_UNAVAIL 0x01            /*   - buffer unavailable */
#define NICE_C_C_D_RBUF_SMALL   0x02            /*   - buffer too small */

#define NICE_C_C_D_LBUF         1041            /* Local buffer errors (8) */
#define NICE_C_C_D_LBUF_UNAVAIL 0x01            /*   - buffer unavailable */
#define NICE_C_C_D_LBUF_SMALL   0x02            /*   - buffer too small */

#define NICE_C_C_D_SEL_INT      1050            /* Selection intervals (16) */
#define NICE_C_C_D_SEL_TMO      1051            /* Selection timeouts (8) */
#define NICE_C_C_D_SEL_TMO_NO   0x01            /*   - No reply to select */
#define NICE_C_C_D_SEL_TMO_INC  0x02            /*   - Incomplete reply to select */

                                                /* Permanent X.25 Circuits */
#define NICE_C_C_X_BYTESRCVD    1000            /* Bytes received (32) */
#define NICE_C_C_X_BYTESSENT    1001            /* Bytes sent (32) */
#define NICE_C_C_X_DBRCVD       1010            /* Data blocks received (32) */
#define NICE_C_C_X_DBSENT       1011            /* Data blocks sent (32) */
#define NICE_C_C_X_LOCAL_RESET  1240            /* Local resets (8) */
#define NICE_C_C_X_REMOTE_RESET 1241            /* Remote resets (8) */
#define NICE_C_C_X_NET_RESET    1242            /* Network resets (8) */

                                                /* Ethernet Circuits */
#define NICE_C_C_E_BYTESRCVD    1000            /* Bytes received (32) */
#define NICE_C_C_E_BYTESSENT    1001            /* Bytes sent (32) */
#define NICE_C_C_E_DBRCVD       1010            /* Data blocks received (32) */
#define NICE_C_C_E_DBSENT       1011            /* Data blocks sent (32) */
#define NICE_C_C_E_NOBUF        1065            /* User buffer unavailable (16) */

/*
 * Line parameters
 */
#define NICE_P_L_STATE          0               /* STATE (C-1) */
#define NICE_P_L_STATE_ON       0               /*   - ON */
#define NICE_P_L_STATE_OFF      1               /*   - OFF */
#define NICE_P_L_STATE_SERVICE  2               /*   - SERVICE */
#define NICE_P_L_STATE_CLEARED  3               /*   - CLEARED */

#define NICE_P_L_SSTATE         1               /* SUBSTATE (C-1) */
#define NICE_P_L_SSTATE_START    0              /*   - STARTING */
#define NICE_P_L_SSTATE_REFLECT  1              /*   - REFLECTING */
#define NICE_P_L_SSTATE_LOOP     2              /*   - LOOPING */
#define NICE_P_L_SSTATE_LOAD     3              /*   - LOADING */
#define NICE_P_L_SSTATE_DUMP     4              /*   - DUMPING */
#define NICE_P_L_SSTATE_TRIG     5              /*   - TRIGGERING */
#define NICE_P_L_SSTATE_AUTOS    6              /*   - AUTOSERVICE */
#define NICE_P_L_SSTATE_AUTOL    7              /*   - AUTOLOADING */
#define NICE_P_L_SSTATE_AUTOD    8              /*   - AUTODUMPING */
#define NICE_P_L_SSTATE_AUTOT    9              /*   - AUTOTRIGGERING */
#define NICE_P_L_SSTATE_SYNCH   10              /*   - SYNCHRONIZING */
#define NICE_P_L_SSTATE_FAILED  11              /*   - FAILED */

#define NICE_P_L_SERVICE        100             /* SERVICE (C-1) */
#define NICE_P_L_SERVICE_ENA    0               /*   - ENABLED */
#define NICE_P_L_SERVICE_DIS    1               /*   - DISABLED */

#define NICE_P_L_CTR_TIMER      110             /* COUNTER TIMER (DU-2) */
#define NICE_P_L_DEVICE         1100            /* DEVICE (AI-16) */
#define NICE_P_L_RCVBUF         1105            /* RECEIVE BUFFERS (DU-2) */
#define NICE_P_L_CTLR           1110            /* CONTROLLER (C-1) */
#define NICE_P_L_CTLR_DP         0              /*   - DP11-DA (obsolete) */
#define NICE_P_L_CTLR_UNA        1              /*   - DEUNA */
#define NICE_P_L_CTLR_DU         2              /*   - DU11-DA */
#define NICE_P_L_CTLR_CNA        3              /*   - DECNA */
#define NICE_P_L_CTLR_DL         4              /*   - DL11-C, -E, -WA */
#define NICE_P_L_CTLR_QNA        5              /*   - DEQNA */
#define NICE_P_L_CTLR_DQ         6              /*   - DQ11-DA (obsolete) */
#define NICE_P_L_CTLR_CI         7              /*   - Computer interconnect */
#define NICE_P_L_CTLR_DA         8              /*   - DA11-B, -AL */
#define NICE_P_L_CTLR_PCL        9              /*   - PCL11-B */
#define NICE_P_L_CTLR_DUP       10              /*   - DUP11-DA */
#define NICE_P_L_CTLR_DMC       12              /*   - DMC11-DA/AR, -FA/AR, */
                                                /*        -MA/AL, -MD/AL */
#define NICE_P_L_CTLR_DN        14              /*   - DN11-BA, -AA */
#define NICE_P_L_CTLR_DLV       16              /*   - DLV11-R, -F, -J */
                                                /*     MXV11-A, -B */
#define NICE_P_L_CTLR_DMP       18              /*   - DMP11 */
#define NICE_P_L_CTLR_DTE       20              /*   - DTE20 */
#define NICE_P_L_CTLR_DV        22              /*   - DV11-AA/BA */
#define NICE_P_L_CTLR_DZ        24              /*   - DZ11-A, -B, -C, -D */
#define NICE_P_L_CTLR_KDP       28              /*   - KMC11/DUP11-DA */
#define NICE_P_L_CTLR_KDZ       30              /*   - KMC11/DZ11-A, -B, -C, -D */
#define NICE_P_L_CTLR_KL        32              /*   - KL8-J (obsolete) */
#define NICE_P_L_CTLR_DMV       34              /*   - DMV11 */
#define NICE_P_L_CTLR_DPV       36              /*   - DPV11 */
#define NICE_P_L_CTLR_DMF       38              /*   - DMF-32 */
#define NICE_P_L_CTLR_DMR       40              /*   - DMR11-AA, -AB, -AC, -AE */
#define NICE_P_L_CTLR_KMY       42              /*   - KMS11-PX */
#define NICE_P_L_CTLR_KMX       44              /*   - KMS11-BD/BE */

#define NICE_P_L_DUPLEX         1111            /* DUPLEX (C-1) */
#define NICE_P_L_DUPLEX_FULL    0               /*   - FULL */
#define NICE_P_L_DUPLEX_HALF    1               /*   - HALF */

#define NICE_P_L_PROTO          1112            /* PROTOCOL (C-1) */
#define NICE_P_L_PROTO_D_POINT  0               /*   - DDCMP POINT */
#define NICE_P_L_PROTO_D_CTRL   1               /*   - DDCMP CONTROL */
#define NICE_P_L_PROTO_D_TRIB   2               /*   - DDCMP TRIBUTARY */
#define NICE_P_L_PROTO_D_DMC    4               /*   - DDCMP DMC */
#define NICE_P_L_PROTO_LAPB     5               /*   - LAPB */
#define NICE_P_L_PROTO_ETHER    6               /*   - ETHERNET */
#define NICE_P_L_PROTO_CI       7               /*   - CI */
#define NICE_P_L_PROTO_QP2      8               /*   - QP2 (DTE20) */

#define NICE_P_L_CLOCK          1113            /* CLOCK (C-1) */
#define NICE_P_L_CLOCK_EXT      0               /*   - EXTERNAL */
#define NICE_P_L_CLOCK_INT      1               /*   - INTERNAL */

#define NICE_P_L_SERV_TIMER     1120            /* SERVICE TIMER (DU-2) */
#define NICE_P_L_RETRANS_TIMER  1121            /* RETRANSMIT TIMER (DU-2) */
#define NICE_P_L_HOLDBACK_TIMER 1122            /* HOLDBACK TIMER (DU-2) */
#define NICE_P_L_MAXBLOCK       1130            /* MAXIMUM BLOCK (DU-2) */
#define NICE_P_L_MAXRETRANS     1131            /* MAXIMUM RETRANSMITS (DU-2) */
#define NICE_P_L_MAXWINDOW      1132            /* MAXIMUM WINDOW (DU-2) */
#define NICE_P_L_SCHED_TIMER    1150            /* SCHEDULING TIMER (DU-2) */
#define NICE_P_L_DEAD_TIMER     1151            /* DEAD TIMER (DU-2) */
#define NICE_P_L_DELAY_TIMER    1152            /* DELAY TIMER (DU-2) */
#define NICE_P_L_STREAM_TIMER   1153            /* STREAM TIMER (DU-2) */
#define NICE_P_L_HA             1160            /* HARDWARE ADDRESS (HI-6) */

/*
 * Line counters
 */
                                                /* LAPB Lines */
#define NICE_C_L_L_SECONDS      0               /* Seconds since zeroed (16) */
#define NICE_C_L_L_BYTESRCVD    1000            /* Bytes received (32) */
#define NICE_C_L_L_BYTESSENT    1001            /* Bytes sent (32) */
#define NICE_C_L_L_DBRCVD       1010            /* Data blocks received (32) */
#define NICE_C_L_L_DBSENT       1011            /* Data blocks sent (32) */
#define NICE_C_L_L_DE_IN        1020            /* Data errors inbound (8) */
#define NICE_C_L_L_DE_IN_LONG   0x08            /*   - block too long */
#define NICE_C_L_L_DE_IN_BCE    0x10            /*   - block check error */
#define NICE_C_L_L_DE_IN_REJ    0x20            /*   - REJ sent */

#define NICE_C_L_L_DE_OUT       1021            /* Data errors outbound (8) */
#define NICE_C_L_L_DE_OUT_REJ   0x08            /*   - REJ received */

#define NICE_C_L_L_RREP_TMO     1030            /* Remote reply timeouts (8) */
#define NICE_C_L_L_LREP_TMO     1031            /* Local reply timeouts (8) */
#define NICE_C_L_L_RBUF         1040            /* Remote buffer errors (8) */
#define NICE_C_L_L_RBUF_UNAVAIL 0x04            /*   - RNR rcvd, no buffer */

#define NICE_C_L_L_LBUF         1041            /* Local buffer errors (8) */
#define NICE_C_L_L_LBUF_UNAVIL  0x04            /*   - RNR sent, no buffer */

#define NICE_C_L_L_RSTAT        1100            /* Remote station errors (8) */
#define NICE_C_L_L_RSTAT_INV    0x10            /*   - invalid N(S) rcvd */
#define NICE_C_L_L_RSTAT_FMT    0x20            /*   - hdr format error */

#define NICE_C_L_L_LSTAT        1101            /* Local station errors (8) */
#define NICE_C_L_L_LSTAT_XUND   0x04            /*   - transmit underrun */
#define NICE_C_L_L_LSTAT_ROVR   0x10            /*   - receive overrun */
#define NICE_C_L_L_LSTAT_FMT    0X20            /*   - hdr format error */

                                                /* DDCMP Circuits */
#define NICE_C_L_D_DE_IN        1020            /* Data errors inbound (8) */
#define NICE_C_L_D_DE_IN_HDR    0x01            /*   - header block check */
#define NICE_C_L_D_RSTAT        1100            /* Remote station errors (8) */
#define NICE_C_L_D_RSTAT_ROVR   0x01            /*   - receive overrun */
#define NICE_C_L_D_RSTAT_HFMT   0x02            /*   - header format error */
#define NICE_C_L_D_RSTAT_SEL    0x04            /*   - selection addr errors */
#define NICE_C_L_D_RSTAT_STREAM 0x08            /*   - streaming tributaries */

#define NICE_C_L_D_LSTAT        1101            /* Local station errors (8) */
#define NICE_C_L_D_LSTAT_ROVR   0x01            /*   - receive overrun, NAK */
#define NICE_C_L_D_LSTAT_ROVR2  0x02            /*   - receive overrun, no NAK */
#define NICE_C_L_D_LSTAT_XUND   0x04            /*   - transmit underrun */
#define NICE_C_L_D_LSTAT_HFMT   0x08            /*   - header format error */

                                                /* Ethernet Circuits */
#define NICE_C_L_E_SECONDS      0               /* Seconds since zeroed (16) */
#define NICE_C_L_E_BYTESRCVD    1000            /* Bytes received (32) */
#define NICE_C_L_E_BYTESSENT    1001            /* Bytes sent (32) */
#define NICE_C_L_E_MBYTESRCVD   1002            /* Multicast bytes received (32) */
#define NICE_C_L_E_DBRCVD       1010            /* Data blocks received (32) */
#define NICE_C_L_E_DBSENT       1011            /* Data blocks sent (32) */
#define NICE_C_L_E_MBLOCKRCVD   1012            /* Multicast blocks received (32) */
#define NICE_C_L_E_1DEFER       1013            /* Blocks sent, initially deferred (32) */
#define NICE_C_L_E_1COLL        1014            /* Blocks sent, 1 collision (32) */
#define NICE_C_L_E_COLLISIONS   1015            /* Blocks sent, multiple collisions (32) */
#define NICE_C_L_E_SFAIL        1060            /* Send failure (16) */
#define NICE_C_L_E_SFAIL_COLL   0x0001          /*   - excessive collisions */
#define NICE_C_L_E_SFAIL_CC     0x0002          /*   - carrier check failed */
#define NICE_C_L_E_SFAIL_SC     0x0004          /*   - short circuit */
#define NICE_C_L_E_SFAIL_OC     0x0008          /*   - open circuit */
#define NICE_C_L_E_SFAIL_LONG   0x0010          /*   - frame too long */
#define NICE_C_L_E_SFAIL_DEFER  0x0020          /*   - remote failed to defer */

#define NICE_C_L_E_CDETECT      1061            /* Collision check failure (16) */
#define NICE_C_L_E_RFAIL        1062            /* Receive failure (16) */
#define NICE_C_L_E_RFAIL_BCE    0x0001          /*   - block check error */
#define NICE_C_L_E_RFAIL_FRAME  0x0002          /*   - framing error */
#define NICE_C_L_E_RFAIL_LONG   0x0004          /*   - frame too long */

#define NICE_C_L_E_NODEST       1063            /* Unknown frame destination (16) */
#define NICE_C_L_E_OVERRUN      1064            /* Data overrun (16) */
#define NICE_C_L_E_NOSYSBUF     1065            /* System buffer unavail (16) */
#define NICE_C_L_E_NOUSERBUF    1066            /* User buffer unavail (16) */

/*
 * Logging parameters
 */
#define NICE_P_G_SINK_ACTIVE    254             /* Active sink types */
#define NICE_P_G_SINK_KNOWN     255             /* Known sink types */
#define NICE_P_G_SINK_CONSOLE   1               /* Console */
#define NICE_P_G_SINK_FILE      2               /* File */
#define NICE_P_G_SINK_MONITOR   3               /* Monitor */

#define NICE_P_G_STATE          0               /* STATE (C-1) */
#define NICE_P_G_STATE_ON       0               /*   - ON */
#define NICE_P_G_STATE_OFF      1               /*   - OFF */
#define NICE_P_G_STATE_HOLD     2               /*   - HOLD */

#define NICE_P_G_NAME           100             /* NAME (AI-255) */
#define NICE_P_G_SINKNODE       200             /* SINK NODE (CM-1/2) */
#define NICE_P_G_EVENTS         201             /* EVENTS (CM-2/3/4/5) */

#define NICE_P_G_ENTITY_NONE    255             /* No entity */
#define NICE_P_G_ENTITY_NODE    0               /* NODE */
#define NICE_P_G_ENTITY_LINE    1               /* LINE */
#define NICE_P_G_ENTITY_CIRCUIT 3               /* CIRCUIT */
#define NICE_P_G_ENTITY_MODULE  4               /* MODULE */
#define NICE_P_G_ENTITY_AREA    5               /* AREA */

#define NICE_P_G_CLASS_SINGLE   0x0000          /* Single class */
#define NICE_P_G_CLASS_ALL      0x8000          /* All events for class */
#define NICE_P_G_CLASS_KNOWN    0xC000          /* KNOWN EVENTS */
#define NICE_P_G_CLASS_VALUE    0x01FF          /* Event class */

/*
 * Node parameters
 */
#define NICE_P_N_STATE          0               /* STATE (C-1) */
#define NICE_P_N_STATE_ON       0               /*   - ON */
#define NICE_P_N_STATE_OFF      1               /*   - OFF */
#define NICE_P_N_STATE_SHUT     2               /*   - SHUT */
#define NICE_P_N_STATE_RESTRICT 3               /*   - RESTRICTED */
#define NICE_P_N_STATE_REACH    4               /*   - REACHABLE */
#define NICE_P_N_STATE_UNREACH  5               /*   - UNREACHABLE */

#define NICE_P_N_PA             10              /* PHYSICAL ADDRESS (HI-6) */
#define NICE_P_N_IDENTIFICATION 100             /* IDENTIFICATION (AI-32) */
#define NICE_P_N_MGMTVERS       101             /* MANAGEMENT VERSION (CM-3) */
#define NICE_P_N_SERV_CIRC      110             /* SERVICE CIRCUIT (AI-16) */
#define NICE_P_N_SERV_PWD       111             /* SERVICE PASSWORD (H-8) */
#define NICE_P_N_SERV_DEV       112             /* SERVICE DEVICE (C-1) */
#define NICE_P_N_DEV_DP          0              /*   - DP11-DA (obsolete) */
#define NICE_P_N_DEV_UNA         1              /*   - DEUNA */
#define NICE_P_N_DEV_DU          2              /*   - DU11-DA */
#define NICE_P_N_DEV_CNA         3              /*   - DECNA */
#define NICE_P_N_DEV_DL          4              /*   - DL11-C, -E, -WA */
#define NICE_P_N_DEV_QNA         5              /*   - DEQNA */
#define NICE_P_N_DEV_DQ          6              /*   - DQ11-DA (obsolete) */
#define NICE_P_N_DEV_CI          7              /*   - Computer interconnect */
#define NICE_P_N_DEV_DA          8              /*   - DA11-B, -AL */
#define NICE_P_N_DEV_PCL         9              /*   - PCL11-B */
#define NICE_P_N_DEV_DUP        10              /*   - DUP11-DA */
#define NICE_P_N_DEV_DMC        12              /*   - DMC11-DA/AR, -FA/AR, */
                                                /*       -MA/AL, -MD/AL */
#define NICE_P_N_DEV_DN         14              /*   - DN11-BA, -AA */
#define NICE_P_N_DEV_DLV        16              /*   - DLV11-R, -F, -J */
                                                /*     MXV11-A, -B */
#define NICE_P_N_DEV_DMP        18              /*   - DMP11 */
#define NICE_P_N_DEV_DTE        20              /*   - DTE20 */
#define NICE_P_N_DEV_DV         22              /*   - DV11-AA/BA */
#define NICE_P_N_DEV_DZ         24              /*   - DZ11-A, -B, -C, -D */
#define NICE_P_N_DEV_KDP        28              /*   - KMC11/DUP11-DA */
#define NICE_P_N_DEV_KDZ        30              /*   - KMC11/DZ11-A, -B, -C, -D */
#define NICE_P_N_DEV_KL         32              /*   - KL8-J (obsolete) */
#define NICE_P_N_DEV_DMV        34              /*   - DMV11 */
#define NICE_P_N_DEV_DPV        36              /*   - DPV11 */
#define NICE_P_N_DEV_DMF        38              /*   - DMF-32 */
#define NICE_P_N_DEV_DMR        40              /*   - DMR11-AA, -AB, -AC, -AE */
#define NICE_P_N_DEV_KMY        42              /*   - KMS11-PX */
#define NICE_P_N_DEV_KMX        44              /*   - KMS11-BD/BE */

#define NICE_P_N_CPU            113             /* CPU (C-1) */
#define NICE_P_N_CPU_PDP8       0               /*   - PDP8 */
#define NICE_P_N_CPU_PDP11      1               /*   - PDP11 */
#define NICE_P_N_CPU_1020       2               /*   - DECsystem-10/20 */
#define NICE_P_N_CPU_VAX        3               /*   - VAX */

#define NICE_P_N_HA             114             /* HARDWARE ADDRESS (HI-6) */
#define NICE_P_N_SNV            115             /* SERVICE NODE VERSION (C1) */
#define NICE_P_N_SNV_III        0               /*   - PHASE III */
#define NICE_P_N_SNV_IV         1               /*   - PHASE IV */

#define NICE_P_N_LOADFILE       120             /* LOAD FILE (AI-255) */
#define NICE_P_N_SECLDR         121             /* SECONDARY LOADER (AI-255) */
#define NICE_P_N_TERLDR         122             /* TERTIARY LOADER (AI-255) */
#define NICE_P_N_DIAGNOSTIC     123             /* DIAGNOSTIC FILE (AI-255) */
#define NICE_P_N_SWTYPE         125             /* SOFTWARE TYPE (C-1) */
#define NICE_P_N_SWTYPE_SECLDR  0               /*   - SECONDARY LOADER */
#define NICE_P_N_SWTYPE_TERLDR  1               /*   - TERTIARY LOADER */
#define NICE_P_N_SWTYPE_SYSTEM  2               /*   - SYSTEM */

#define NICE_P_N_SWID           126             /* SOFTWARE IDENTIFICATIION (AI-16) */
#define NICE_P_N_DUMPFILE       130             /* DUMP FILE (AI-255) */
#define NICE_P_N_SECDUMPER      131             /* SECONDARY DUMPER (AI-255) */
#define NICE_P_N_DUMPADDRESS    135             /* DUMP ADDRESS (O-4) */
#define NICE_P_N_DUMPCOUNT      136             /* DUMP COUNT (DU-4) */
#define NICE_P_N_HOST_RO        140             /* HOST (CM-1/2) */
#define NICE_P_N_HOST_WO        141             /* HOST */
#define NICE_P_N_LC             150             /* LOOP COUNT (DU-2) */
#define NICE_P_N_LL             151             /* LOOP LENGTH (DU-2) */
#define NICE_P_N_LW             152             /* LOOP WITH (C-1) */
#define NICE_P_N_LW_ZEROES      0               /*   - ZEROES */
#define NICE_P_N_LW_ONES        1               /*   - ONES */
#define NICE_P_N_LW_MIXED       2               /*   - MIXED */

#define NICE_P_N_LAPA           153             /* LOOP ASSISTANT PHYSICAL ADDRESS (HI-6) */
#define NICE_P_N_LH             154             /* LOOP HELP (C-1) */
#define NICE_P_N_LH_TRANSMIT    0               /*   - TRANSMIT */
#define NICE_P_N_LH_RECEIVE     1               /*   - RECEIVE */
#define NICE_P_N_LH_FULL        2               /*   - FULL */

#define NICE_P_N_LN             155             /* LOOP NODE */
#define NICE_P_N_LAN            156             /* LOOP ASSISTANT NODE */
#define NICE_P_N_CTR_TIMER      160             /* COUNTER TIMER (DU-2) */
#define NICE_P_N_NAME           500             /* NAME */
#define NICE_P_N_CIRC           501             /* CIRCUIT (AI-16) */
#define NICE_P_N_ADDRESS        502             /* ADDRESS (DU-2) */
#define NICE_P_N_INC_TIMER      510             /* INCOMING TIMER (DU-2) */
#define NICE_P_N_OUT_TIMER      511             /* OUTGOING TIMER (DU-2) */
#define NICE_P_N_ACTIVELINKS    600             /* ACTIVE LINKS (DU-2) */
#define NICE_P_N_DELAY          601             /* DELAY (DU-2) */
#define NICE_P_N_NSPVERSION     700             /* NSP VERSION */
#define NICE_P_N_MAXLINKS       710             /* MAXIMUM LINKS (DU-2) */
#define NICE_P_N_DELAYFACTOR    720             /* DELAY FACTOR (DU-1) */
#define NICE_P_N_DELAYWEIGHT    721             /* DELAY WEIGHT (DU-1) */
#define NICE_P_N_INACT_TIMER    722             /* INACTIVE TIMER (DU-2) */
#define NICE_P_N_RETRANS_FACTOR 723             /* RETRANSMIT FACTOR (DU-2) */
#define NICE_P_N_TYPE           810             /* TYPE (C-1) */
#define NICE_P_N_TYPE_RTR_III   0               /*   - ROUTING III */
#define NICE_P_N_TYPE_NRTR_III  1               /*   - NONROUTING III */
#define NICE_P_N_TYPE_AREA      3               /*   - AREA */
#define NICE_P_N_TYPE_RTR_IV    4               /*   - ROUTING IV */
#define NICE_P_N_TYPE_NRTR_IV   5               /*   - NONROUTING IV */

#define NICE_P_N_COST           820             /* COST (DU-2) */
#define NICE_P_N_HOPS           821             /* HOPS (DU-1) */
#define NICE_P_N_CIRCUIT        822             /* CIRCUIT (AI-16) */
#define NICE_P_N_NEXTNODE       830             /* NEXT NODE (CM-1/2) */
#define NICE_P_N_RTRVERSION     900             /* ROUTING VERSION (CM-3) */
#define NICE_P_N_RTYPE          901             /* TYPE (C-1) */
#define NICE_P_N_RTYPE_RTR_III  0               /*   - ROUTING III */
#define NICE_P_N_RTYPE_NRTR_III 1               /*   - NONROUTING III */
#define NICE_P_N_RTYPE_AREA     3               /*   - AREA */
#define NICE_P_N_RTYPE_RTR_IV   4               /*   - ROUTING IV */
#define NICE_P_N_RTYPE_NRTR_IV  5               /*   - NONROUTING IV */

#define NICE_P_N_RTR_TIMER      910             /* ROUTING TIMER (DU-2) */
#define NICE_P_N_SUBADDRESSES   911             /* SUBADDRESSES (CM-1/2) */
#define NICE_P_N_BRT            912             /* BROADCAST ROUTING TIMER (DU-2) */
#define NICE_P_N_MAXADDRESS     920             /* MAXIMUM ADDRESS (DU-2) */
#define NICE_P_N_MAXCIRCUITS    921             /* MAXIMUM CIRCUITS (DU-2) */
#define NICE_P_N_MAXCOST        922             /* MAXIMUM COST (DU-2) */
#define NICE_P_N_MAXHOPS        923             /* MAXIMUM HOPS (DU-2) */
#define NICE_P_N_MAXVISITS      924             /* MAXIMUM VISITS (DU-1) */
#define NICE_P_N_MAXAREA        925             /* MAXIMUM AREA (DU-1) */
#define NICE_P_N_MAXBNRTR       926             /* MAXIMUM BROADCAST NONROUTERS (DU-2) */
#define NICE_P_N_MAXBRTR        927             /* MAXIMUM BROADCAST ROUTERS (DU-2) */
#define NICE_P_N_AMAXCOST       928             /* AREA MAXIMUM COST (DU-2) */
#define NICE_P_N_AMAXHOPS       929     `       /* AREA MAXIMUM HOPS (DU-1) */
#define NICE_P_N_MAXBUFFERS     930             /* MAXIMUM BUFFERS (DU-2) */
#define NICE_P_N_BUFFERSIZE     931             /* BUFFER SIZE (DU-2) */
#define NICE_P_N_SEGBUFFERSIZE  932             /* SEGMENT BUFFER SIZE (DU-2) */

/*
 * Node counters
 */
#define NICE_C_N_SECONDS        0               /* Seconds since zeroed (16) */
#define NICE_C_N_USERBYTESRCVD  600             /* User bytes received (32) */
#define NICE_C_N_USERBYTESSENT  601             /* User bytes sent (32) */
#define NICE_C_N_USERMSGSRCVD   602             /* User messages received (32) */
#define NICE_C_N_USERMSGSSENT   603             /* User messages sent (32) */
#define NICE_C_N_TOTBYTESRCVD   608             /* Total bytes received (32) */
#define NICE_C_N_TOTBYTESSENT   609             /* Total bytes sent (32) */
#define NICE_C_N_TOTMSGSRCVD    610             /* Total messages received (32) */
#define NICE_C_N_TOTMSGSSENT    611             /* Total messages sent (32) */
#define NICE_C_N_CONNRCVD       620             /* Connects received (16) */
#define NICE_C_N_CONNSENT       621             /* Connects sent (16) */
#define NICE_C_N_RESP_TMO       630             /* Response timeouts (16) */
#define NICE_C_N_CONNRESERR     640             /* Received connect resource errors (16) */
#define NICE_C_N_MAXLINKSACTIVE 700             /* Maximum logical links active (16) */
#define NICE_C_N_AGEDLOSS       900             /* Aged packet loss (8) */
#define NICE_C_N_UNREACHLOSS    901             /* Node unreachable packet loss (16) */
#define NICE_C_N_RANGELOSS      902             /* Node out-of-range packet loss (8) */
#define NICE_C_N_OVERSIZELOSS   903             /* Oversized packet loss (8) */
#define NICE_C_N_FORMATERR      910             /* Packet format error (8) */
#define NICE_C_N_PARTIALLOSS    920             /* Partial routing update loss (8) */
#define NICE_C_N_VERIFREJECT    930             /* Verification reject (8) */

/*
 * Area parameters
 */
#define NICE_P_A_STATE          0               /* STATE (C-1) */
#define NICE_P_A_STATE_REACH    4               /*   - REACHABLE */
#define NICE_P_A_STATE_UNREACH  5               /*   - UNREACHABLE */

#define NICE_P_A_COST           820             /* COST (DU-2) */
#define NICE_P_A_HOPS           821             /* HOPS (DU-1) */
#define NICE_P_A_CIRCUIT        822             /* CIRCUIT (AI-16) */
#define NICE_P_A_NEXTNODE       830             /* NEXT NODE (CM-1/2) */

/*
 * NICE return codes
 */
#define NICE_RET_SUCCESS        1               /* Success */
#define NICE_RET_ACCEPTED       2               /* Request accepted */
#define NICE_RET_PARTIAL        3               /* Partial reply, more to come */
#define NICE_RET_UNRECOG         -1             /* Unrecognized function or option */
#define NICE_RET_INVALID         -2             /* Invalid message format */
#define NICE_RET_PRIV            -3             /* Privilege violation */
#define NICE_RET_OVERSIZE        -4             /* Message too long */
#define NICE_RET_PROGERR         -5             /* Software error */
#define NICE_RET_BADPARAM        -6             /* Unrecognized parameter type */
#define NICE_RET_BADVERSION      -7             /* Incompatibe version # */
#define NICE_RET_BADCOMPONENT    -8             /* Unrecognized component */
#define NICE_RET_BADID           -9             /* Invalid identification */
#define NICE_RET_COMMFAIL       -10             /* Line communication failure */
#define NICE_RET_BADSTATE       -11             /* Component in wrong state */
#define NICE_RET_OPENERR        -13             /* File open error */
#define NICE_RET_BADDATA        -14             /* Invalid file contents */
#define NICE_RET_RESERR         -15             /* Resource error */
#define NICE_RET_BADVALUE       -16             /* Invalid parameter value */
#define NICE_RET_PROTOERR       -17             /* Line protocol error */
#define NICE_RET_IOERROR        -18             /* File I/O error */
#define NICE_RET_DISCONNECT     -19             /* Mirror link disconnected */
#define NICE_RET_NOROOM         -20             /* No room for new entry */
#define NICE_RET_CONNECTERR     -21             /* Mirror connect failed */
#define NICE_RET_NOTAPPLIC      -22             /* Parameter not applicable */
#define NICE_RET_TOOLONG        -23             /* Parameter value too long */
#define NICE_RET_HWFAIL         -24             /* Hardware failure */
#define NICE_RET_OPFAIL         -25             /* Operation failure */
#define NICE_RET_SYSUNSUPP      -26             /* Function not supported */
#define NICE_RET_INVGROUP       -27             /* Invalid parameter grouping */
#define NICE_RET_BADRESPONSE    -28             /* Bad loopback response */
#define NICE_RET_MISSING        -29             /* Parameter missing */
#define NICE_RET_DONE           -128            /* Multiple responses done */

extern void NICEinit(int);
extern void NICEflush(void);
extern void NICEparamDU1(uint16_t, uint8_t);
extern void NICEparamDU2(uint16_t, uint16_t);
extern void NICEparamAIn(uint16_t, char *);
extern void NICEparamHIn(uint16_t, char, char *);
extern void NICEparamC1(uint16_t, uint8_t);
extern void NICEparamCMn(uint16_t, uint8_t);
extern void NICEparamNodeID(uint16_t, uint16_t, char *);
extern void NICEnodeEntity(uint16_t, char *, int);
extern void NICEcircuitEntity(char *);
extern void NICEareaEntity(uint8_t);
extern void NICEvalueDU1(uint8_t);
extern void NICEvalueDU2(uint16_t);

extern void NICEformatResponse(void);
extern void NICEunsupportedResponse(void);
extern void NICEtoolongResponse(void);
extern void NICEunrecognizedComponentResponse(char);
extern void NICEacceptedResponse(void);
extern void NICEpartialResponse(void);
extern void NICEsuccessResponse(void);
extern void NICEdoneResponse(void);
extern int NICEread(void);
extern int NICEget1(uint8_t *);
extern int NICEget2(uint16_t *);
extern int NICEgetAI(char *, char *, int);
extern void NICEbackup(int);

#ifndef TRUE
#define TRUE                    1
#define FALSE                   0
#endif

#endif
