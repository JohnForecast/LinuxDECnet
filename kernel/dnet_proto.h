/* SPDX-License-Identifier: GPL-2.0 */

/*
 *      John Forecast (C) 2023
 *
 * Re-implementation of the kernel code from DECnet for Linux with the
 * following changes/restrictions:
 *
 *      Ethernet (or WLAN) endnode only
 *      Latent support for Phase IV Prime
 *      Designed to be built as an external module
 */
#ifndef __DN_PROTO_H__
#define __DN_PROTO_H__

/*
 * Message layouts
 */

/*
 * Transport layer messages
 */
typedef struct __attribute__((__packed__)) rt_long_hdr {
        uint8_t         flags;
#define RT_FLG_PAD      0x80
#define RT_FLG_PADM     0x7F
#define RT_FLG_VER      0x40
#define RT_FLG_IE       0x20
#define RT_FLG_RTS      0x10
#define RT_FLG_RQR      0x08
#define RT_FLG_LFDP     0x07
#define RT_FLG_LONG     0x06
        uint8_t         d_area;
        uint8_t         d_subarea;
        uint8_t         d_id[6];
        uint8_t         s_area;
        uint8_t         s_subarea;
        uint8_t         s_id[6];
        uint8_t         nl2;
        uint8_t         visit_ct;
#define RT_VISIT_CT     0x3F
        uint8_t         s_class;
        uint8_t         pt;
} rt_long_hdr;

typedef struct __attribute__((__packed__)) rt_eth_rtr_hello {
        uint8_t         flags;
#define RT_FLG_CNTL_MSK 0x0E
#define RT_FLG_RHELLO   0x0A
#define RT_FLG_CONTROL  0x01
#define RT_FLG_RSVD     0x70
#define RT_FLG_FP       0x10
        uint8_t         tiver[3];
        uint8_t         id[6];
        uint8_t         iinfo;
#define RT_II_RTR_MASK  0x03
#define RT_II_LEVEL_1   0x02
#define RT_II_LEVEL_2   0x01
        uint16_t        blksize;
        uint8_t         priority;
        uint8_t         area;
        uint16_t        timer;
        uint8_t         mpd;
        uint8_t         elist;
} rt_eth_rtr_hello;

struct __attribute__((__packed__)) rt_elist {
        uint8_t         name[7];
        uint8_t         rslist;
};

struct __attribute__((__packed__)) rt_rslist {
        uint8_t         router[6];
        uint8_t         pristate;
#define RT_PS_2WAY      0x80
#define RT_PS_PRIMASK   0x7F
};

typedef struct __attribute__((__packed__)) rt_eth_end_hello {
        uint8_t         flags;
#define RT_FLG_EHELLO   0x0C
#define RT_FLG_EHELLOP  0x0E
        uint8_t         tiver[3];
        uint8_t         id[6];
        uint8_t         iinfo;
#define RT_II_ENDNODE   0x03
        uint16_t        blksize;
        uint8_t         area;
        uint8_t         seed[8];
        uint8_t         neighbor[6];
        uint16_t        timer;
        uint8_t         mpd;
        uint8_t         datalen;
        uint8_t         data[0];
} rt_eth_end_hello;

/*
 * Multipliers to be applied to the hello timer interval to generate
 * the listen timer.
 *
 * Note: Wireless networking did not exist when DECnet was architected.
 * In a location with a large number of wireless networks (e.g. an
 * apartment complex), packet loss can be higher than an equivalent
 * wired network. The DN_WT3MULT allows some additional leeway for
 * such networks.
 */
#define DN_BCT3MULT     3       /* Broadcast links */
#define DN_WT3MULT      5       /* Wireless links */

#define DN_DEFAULT_HELLO 10     /* Default Hello timer */

/*
 * NSP level messages
 */
#define NSP_MBZ         0x83

#define NSP_TYP_MASK    0x0C
#define NSP_TYP_DATA    0x00
#define NSP_TYP_ACK     0x04
#define NSP_TYP_CONTROL 0x08

#define NSP_MSG_DATA    0x00
#define NSP_MSG_BOM     0x20
#define NSP_MSG_EOM     0x40

#define NSP_SUBTYP_MASK 0x70

#define NSP_MSG_ILS     0x10

#define NSP_MSG_LS      (NSP_TYP_DATA | NSP_MSG_ILS)
#define NSP_MSG_INTR    (NSP_TYP_DATA | NSP_MSG_ILS | 0x20)

#define NSP_MSG_DATACK  NSP_TYP_ACK
#define NSP_MSG_OTHACK  (NSP_TYP_ACK | 0x10)
#define NSP_MSG_CIACK   (NSP_TYP_ACK | 0x20)

#define NSP_MSG_NOP     NSP_TYP_CONTROL
#define NSP_MSG_CI      (NSP_TYP_CONTROL | 0x10)
#define NSP_MSG_CC      (NSP_TYP_CONTROL | 0x20)
#define NSP_MSG_DI      (NSP_TYP_CONTROL | 0x30)
#define NSP_MSG_DC      (NSP_TYP_CONTROL | 0x40)
#define NSP_MSG_P2INIT  (NSP_TYP_CONTROL | 0x50)
#define NSP_MSG_RCI     (NSP_TYP_CONTROL | 0x60)
#define NSP_MSG_RSVD    (NSP_TYP_CONTROL | 0x70)

#define NSP_ACK_PRESENT 0x8000
#define NSP_ACK_CROSS   0x2000
#define NSP_ACK_NAK     0x1000
#define NSP_ACK_DELAY   0x1000
#define NSP_SEG_MASK    0x0FFF

#define NSP_FCVAL_MASK  0x0C
#define NSP_FCVAL_DATA  0x00
#define NSP_FCVAL_INTR  0x04
#define NSP_FCMOD_MASK  0x03
#define NSP_FCMOD_NOC   0x00
#define NSP_FCMOD_NOSND 0x01
#define NSP_FCMOD_SND   0x02

typedef struct __attribute__((__packed__)) nsp_data {
        uint8_t         msgflg;
        uint16_t        dstaddr;
        uint16_t        srcaddr;
        uint16_t        acknum;
        uint16_t        ackoth;
        uint16_t        segnum;
} nsp_data;
#define NSP_MAX_DATAHDR (sizeof(nsp_data))

typedef struct __attribute__((__packed__)) nsp_ack {
        uint8_t         msgflg;
        uint16_t        dstaddr;
        uint16_t        srcaddr;
        uint16_t        acknum;
        uint16_t        ackoth;
} nsp_ack;
#define NSP_MAX_ACK     (sizeof(nsp_ack))

typedef struct __attribute__((__packed__)) nsp_header {
        uint8_t         msgflg;
        uint16_t        dstaddr;
        uint16_t        srcaddr;
} nsp_header;

typedef struct __attribute__((__packed__)) nsp_ciack {
        uint8_t         msgflg;
        uint16_t        dstaddr;
} nsp_ciack;

typedef struct __attribute__((__packed__)) nsp_ci {
        uint8_t         msgflg;
        uint16_t        dstaddr;
        uint16_t        srcaddr;
        uint8_t         services;
#define NSP_FCOPT_MASK  0x0D
#define NSP_FCOPT_NONE  0x01
#define NSP_FCOPT_SEG   0x05
#define NSP_FCOPT_MSG   0x09
        uint8_t         info;
#define NSP_INFO_3_2    0x00
#define NSP_INFO_3_1    0x01
#define NSP_INFO_4_0    0x02
#define NSP_INFO_4_1    0x03
        uint16_t        segsize;
        uint8_t         data_ctl[0];
} nsp_ci;
#define NSP_MENU_ACC    0x01
#define NSP_MENU_USR    0x02
#define NSP_MENU_PROXY  0x04
#define NSP_MENU_UIC    0x08

typedef struct __attribute__((__packed__)) nsp_cc {
        uint8_t         msgflg;
        uint16_t        dstaddr;
        uint16_t        srcaddr;
        uint8_t         services;
        uint8_t         info;
        uint16_t        segsize;
        uint8_t         data_ctl[1];
} nsp_cc;

typedef struct __attribute__((__packed__)) nsp_di {
        uint8_t         msgflg;
        uint16_t        dstaddr;
        uint16_t        srcaddr;
        uint16_t        reason;
#define NSP_REASON_OK   0               /* No error */
#define NSP_REASON_NR   1               /* No resources */
#define NSP_REASON_UN   2               /* Unrecognised node name */
#define NSP_REASON_SD   3               /* Node shutting down */
#define NSP_REASON_ID   4               /* Invalid destination end user */
#define NSP_REASON_ER   5               /* End user lacks resources */
#define NSP_REASON_OB   6               /* Object too busy */
#define NSP_REASON_US   7               /* Unspecified error */
#define NSP_REASON_TP   8               /* Third party abort */
#define NSP_REASON_EA   9               /* End user has aborted the link */
#define NSP_REASON_IF   10              /* Invalid node name format */
#define NSP_REASON_LS   11              /* Local node shutdown */
#define NSP_REASON_LL   32              /* Node lacks LL resources */
#define NSP_REASON_LE   33              /* End user lacks LL resources */
#define NSP_REASON_UR   34              /* Unacceptable RQSTRID or PASSWD */
#define NSP_REASON_UA   36              /* Unacceptable ACCOUNT */
#define NSP_REASON_TM   38              /* End user timed out LL */
#define NSP_REASON_NU   39              /* Node unreachable */
#define NSP_REASON_NL   41              /* No-link message */
#define NSP_REASON_DC   42              /* Disconnect confirm */
#define NSP_REASON_IO   43              /* Image data field overflow */
        uint8_t         data_ctl[1];
} nsp_di;

typedef struct __attribute__((__packed__)) nsp_dc {
        uint8_t         msgflg;
        uint16_t        dstaddr;
        uint16_t        srcaddr;
        uint16_t        reason;
} nsp_dc;

#define NSP_MAX_NSP_HDR (11)

/*
 * Flow control values
 */
#define NSP_FC_MIN      1
#define NSP_FC_MAX      0x07FE

/*
 * Functions for manipulating DECnet sequence numbers.
 */
static __inline__ int dn_before(uint16_t seq1, uint16_t seq2)
{
        seq1 &= NSP_SEG_MASK;
        seq2 &= NSP_SEG_MASK;
        return (int)((seq1 - seq2) & NSP_SEG_MASK) > 2048;
}

static __inline__ int dn_after(uint16_t seq1, uint16_t seq2)
{
        seq1 &= NSP_SEG_MASK;
        seq2 &= NSP_SEG_MASK;
        return (int)((seq2 - seq1) & NSP_SEG_MASK) > 2048;
}

static __inline__ int dn_equal(uint16_t seq1, uint16_t seq2)
{
        return ((seq1 ^ seq2) & NSP_SEG_MASK) == 0;
}

static __inline__ int dn_before_or_equal(uint16_t seq1, uint16_t seq2)
{
        return (dn_before(seq1, seq2) || dn_equal(seq1, seq2));
}

static __inline__ int seq_next(uint16_t seq1, uint16_t seq2)
{
        return dn_equal(seq1 + 1, seq2);
}

static __inline__ void seq_add(uint16_t *seq, uint16_t off)
{
        (*seq) += off;
        (*seq) &= NSP_SEG_MASK;
}

/*
 * Can we delay the ACK?
 */
static __inline__ int delayack(uint16_t seq)
{
        return (int)((seq & NSP_ACK_DELAY) ? 1 : 0);
}
#endif
