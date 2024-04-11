/******************************************************************************
    (c) 2002-2006      Christine Caulfield          christine.caulfield@googlemail.com

    Portions based on code (c) 2000 Eduardo M Serrat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
*******************************************************************************/

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <ctype.h>
#include <termios.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/fcntl.h>
#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>
#include "dn_endian.h"
#include "dnlogin.h"
#include "tty.h"

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

/* CTERM message numbers */
#define CTERM_MSG_INITIATE               1
#define CTERM_MSG_START_READ             2
#define CTERM_MSG_READ_DATA              3
#define CTERM_MSG_OOB                    4
#define CTERM_MSG_UNREAD                 5
#define CTERM_MSG_CLEAR_INPUT            6
#define CTERM_MSG_WRITE                  7
#define CTERM_MSG_WRITE_COMPLETE         8
#define CTERM_MSG_DISCARD_STATE          9
#define CTERM_MSG_READ_CHARACTERISTICS  10
#define CTERM_MSG_CHARACTERISTICS       11
#define CTERM_MSG_CHECK_INPUT           12
#define CTERM_MSG_INPUT_COUNT           13
#define CTERM_MSG_INPUT_STATE           14

extern int timeout_valid;
extern int read_pending;

struct  logical_terminal_characteristics
{
        short                   mode_writing_allowed;
        int                     terminal_attributes;
        char                    terminal_type[6];
        short                   output_flow_control;
        short                   output_page_stop;
        short                   flow_character_pass_through;
        short                   input_flow_control;
        short                   loss_notification;
        int                     line_width;
        int                     page_length;
        int                     stop_length;
        int                     cr_fill;
        int                     lf_fill;
        int                     wrap;
        int                     horizontal_tab;
        int                     vertical_tab;
        int                     form_feed;
};

struct  physical_terminal_characteristics
{
        int                     input_speed;
        int                     output_speed;
        int                     character_size;
        short                   parity_enable;
        int                     parity_type;
        short                   modem_present;
        short                   auto_baud_detect;
        short                   management_guaranteed;
        char                    switch_char_1;
        char                    switch_char_2;
        short                   eigth_bit;
        short                   terminal_management_enabled;
};

struct  handler_maintained_characteristics
{
        short                   ignore_input;
        short                   control_o_pass_through;
        short                   raise_input;
        short                   normal_echo;
        short                   input_escseq_recognition;
        short                   output_escseq_recognition;
        int                     input_count_state;
        short                   auto_prompt;
        short                   error_processing;
};


static struct logical_terminal_characteristics
log_char = {FALSE,3,{5,'V','T','2','0','0'}
            ,TRUE,
            TRUE,TRUE,TRUE,TRUE,80,24,0,0,
            0,1,1,1,1};

static struct physical_terminal_characteristics
phy_char = {9600,9600,8,FALSE,1,FALSE,FALSE,
            FALSE,0,0,FALSE,FALSE};

static struct handler_maintained_characteristics
han_char = {FALSE,FALSE,FALSE,TRUE,TRUE,TRUE,
            1,FALSE,FALSE};

char char_attr[256];
static int skip_next_lf;

static void skip_first_lf(char *buf, int len)
{
        int i;
        int skipped = 0;

        for (i=0; i<len; i++)
        {
                if (buf[i] == '\n')
                {
                        buf[i] = '\0';
                        skipped = 1;
                        DEBUG_CTERM("skipping this LF\n");
                        break;
                }
        }
        if (skipped)
                skip_next_lf = 0;
}

/* Process incoming CTERM messages */
static int cterm_process_initiate(char *buf, int len)
{
        char initsq[] =
                { 0x01, 0x00, 0x01, 0x04, 0x00,
                  'd', 'n', 'l', 'o', 'g', 'i', 'n', ' ',
                  0x01, 0x02, 0x00, 0x02,       /* Max msg size */
                  0x02, 0x02, 0xF4, 0x03,       /* Max input buf */
                  0x03, 0x04, 0xFE, 0x7F, 0x00, /* Supp. Msgs */
                  0x00
                };

        found_common_write(initsq, sizeof(initsq));
        return len;
}

static int cterm_process_start_read(char *buf, int len)
{
        unsigned int   flags;
        unsigned short maxlength;
        unsigned short eodata;
        unsigned short timeout;
        unsigned short eoprompt;
        unsigned short sodisplay;
        unsigned short lowwater;
        char term_len;
        int  ptr = 0;
        unsigned char ZZ, EE, DDD, Q, II;

        flags = buf[1] | (buf[2] << 8) | (buf[3] << 16);
        ptr = 4;

        maxlength = buf[ptr] | (buf[ptr+1]<<8); ptr += 2;
        eodata    = buf[ptr] | (buf[ptr+1]<<8); ptr += 2;
        timeout   = buf[ptr] | (buf[ptr+1]<<8); ptr += 2;
        eoprompt  = buf[ptr] | (buf[ptr+1]<<8); ptr += 2;
        sodisplay = buf[ptr] | (buf[ptr+1]<<8); ptr += 2;
        lowwater  = buf[ptr] | (buf[ptr+1]<<8); ptr += 2;
        term_len  = buf[ptr++];

        ZZ  = (flags>>14)&3;
        EE  = (flags>>16)&3;
        DDD = (flags>>8)&7;
        Q   = (flags>>13)&1;
        II  = (flags>>6)&3;

// INFO: flags (Page 59)
//           EE ZZQT NDDD IIKV FCUU
//           UU 1=write BEL on underflow, 2=terminate on underflow
//           C  1=clear typeahead
//           F  1=if last char was CR, end LF, discard LF if first char of
//                preloaded input
//           V  1=Terminate if vertical pos changes while echoing input char.
//           K  1=This is a continuation of previous read - see doc
//           II 2=Convert lower to uppercase
//           DDD 1=Disable  ^U & ^R only, 2=Disable all editing control chars
//               3=Disable all editting chars EXCEPT XON/XOFF
//           N   1=Do not echo chars from this read
//           T   1=echo terminator, 0=no not echo terminator
//           Q   1=Timeout field is present
//           ZZ  1=Use this terminator set, 2=use universal terminator set.
//           EE  1=Do NOT perform esc-seq recognition (this read only)
//               2=DO perform esc-seq recognition (this read only)
//

        if (debug & 2) DEBUG_CTERM("process_start_read. flags = %x\n",flags);
        if (debug & 2) DEBUG_CTERM("len=%d, term_len=%d, ptr=%d\n",
                                   len, term_len, ptr);
        if (debug & 2) DEBUG_CTERM("Q=%d timeout = %d, EE=%d, ZZ=%d\n", Q, timeout, EE, ZZ);

        if (flags & 4) tty_clear_typeahead();
        if ((flags & 0x800) || (han_char.normal_echo == FALSE))
                tty_set_noecho();

	if (flags & 0x8)
		if (tty_format_cr())
			skip_next_lf = 1;

        if (ZZ==1) tty_set_terminators(buf+ptr, term_len);
        if (ZZ==2) tty_set_default_terminators();
        if (EE)    tty_set_escape_proc(EE-1);
        else       tty_set_escape_proc(han_char.input_escseq_recognition);
        tty_allow_edit(!(DDD==2));
        tty_set_uppercase(II==2);
        tty_set_maxlen(maxlength);
        if (Q) tty_set_timeout(timeout);
        else timeout_valid = 0;
        tty_echo_terminator((flags>>12)&1);

        if (skip_next_lf)
        {
                skip_first_lf(buf+ptr+term_len, eoprompt);
        }

        /* do the biz */
        tty_start_read(buf+ptr+term_len, len-term_len-ptr, eoprompt);

        return len;
}

static int cterm_process_read_data(char *buf, int len)
{return len;}

static int cterm_process_oob(char *buf, int len)
{return len;}

static int cterm_process_unread(char *buf, int len)
{
        tty_send_unread();
        return len;
}

static int cterm_process_clear_input(char *buf, int len)
{return len;}

static void send_write_complete(void)
{
        char newbuf[6];

        DEBUG_CTERM("Sending write complete\n");
        newbuf[0] = CTERM_MSG_WRITE_COMPLETE;
        newbuf[1] = 0;
        newbuf[2] = 0 & 0xFF;    // Horiz pos
        newbuf[3] = (0 >> 8) & 0xFF;
        newbuf[4] = 0 & 0xFF;    // Vert pos
        newbuf[5] = (0 >> 8) & 0xFF;

        found_common_write(newbuf, 6);
}

static void send_prepostfix(int flag, char data)
{
        char feed;

        DEBUG_CTERM("send_prepostfix: flag =%d, data=%d\n", flag, data);
        if (flag == 0)
                return;

        if (flag == 1 && data)
        {
                int i;

                feed = '\r';
                tty_write(&feed, 1);
                feed = '\n';
                for (i=0; i<data - skip_next_lf; i++)
                        tty_write(&feed, 1);
                skip_next_lf = 0;
        }
        if (flag == 2)
                tty_write(&data, 1);
}

static int cterm_process_write(char *buf, int len)
{
        unsigned short flags = buf[1] | buf[2]<<8;
        char  prefixdata  = buf[3];
        char  postfixdata = buf[4];
        char  feed = '\n';

        // INFO: flags...
        //       TSQQ PPEB DLUU
        //       UU  lock handling "Page 65"
        //       L   1=Output LF at end and set a flag to skip next LF in next write
        //       D   1=Set output discard state to "do not discard"
        //       B   1=This is the beginning of a host data message
        //       E   1=This is the end of a host data message
        //       PP  1=prefixdata is a newline count, 2=prefixdata=character
        //       QQ  1=postfix is a newline count, 2=postfix=character
        //       S   1=Send write completion when this write completes
        //       T   1=This data is written to foundation services transparently

        DEBUG_CTERM("process_write flags = %x (prefix=%d, postfix=%d)\n",flags, prefixdata, postfixdata);

        tty_set_discard(!(flags >> 3)); // D

        send_prepostfix(((flags >> 6) & 3), prefixdata); // PP

        if (skip_next_lf)
        {
                skip_first_lf(buf+4, len-4);
        }

        tty_write(buf+4, len-4);

        if ((flags >> 2)&1) // L
        {
                if (!skip_next_lf)
                {
                        DEBUG_CTERM("sending feed, skipping next LF\n");
                        tty_write(&feed, 1);
                        skip_next_lf = 1;
                }
                else
                {
                        DEBUG_CTERM("NOT sending feed, skip_next_lf set\n");
                        skip_next_lf = 0;
                }
        }

        send_prepostfix(((flags >> 8) & 3), postfixdata); // QQ

        // CC: This broke to RSX, but was wrong -- TODO: Retest
        if ((flags >> 10) & 1) // S
                send_write_complete();

        return len;
}

static int cterm_process_write_complete(char *buf, int len)
{return len;}

static int cterm_process_discard_state(char *buf, int len)
{return len;}

static int cterm_process_read_characteristics(char *buf, int len)
{
        int  bufptr = 2;/* skip past flags */
        char outbuf[256];
        int  outptr = 0;

        outbuf[outptr++] = CTERM_MSG_CHARACTERISTICS;
        outbuf[outptr++] = 0;

        while (bufptr < len)
        {
                unsigned short selector = buf[bufptr] | buf[bufptr+1]<<8;

                bufptr += 2;

                DEBUG_CTERM("selector = 0x%x\n", selector);

                if ((selector & 0x300) == 0) /* Physical characteristics */
                {
                        outbuf[outptr++] = selector & 0xFF;
                        outbuf[outptr++] = 0;

                        switch (selector & 0xFF)
                        {
                        case 0x01:      /* Input speed                  */
                                outbuf[outptr++] = phy_char.input_speed;
                                outbuf[outptr++] = phy_char.input_speed >> 8;
                                break;

                        case 0x02:      /* Output speed                 */
                                outbuf[outptr++] = phy_char.output_speed;
                                outbuf[outptr++] = phy_char.output_speed >> 8;
                                break;

                        case 0x03:      /* Character size               */
                                outbuf[outptr++] = phy_char.character_size;
                                outbuf[outptr++] = phy_char.character_size >> 8;
                                break;

                        case 0x04:      /* Parity enable                */
                                outbuf[outptr++] = phy_char.parity_enable;
                                break;

                        case 0x05:      /* Parity type                  */
                                outbuf[outptr++] = phy_char.parity_type;
                                outbuf[outptr++] = phy_char.parity_type >> 8;
                                break;

                        case 0x06:      /* Modem Present                */
                                outbuf[outptr++] = phy_char.modem_present;
                                break;

                        case 0x07:      /* Auto baud detect             */
                                outbuf[outptr++] = phy_char.auto_baud_detect;
                                break;

                        case 0x08:      /* Management guaranteed        */
                                outbuf[outptr++] = phy_char.management_guaranteed;
                                break;

                        case 0x09:      /* SW 1                         */
                                break;

                        case 0x0A:      /* SW 2                         */
                                break;

                        case 0x0B:      /* Eight bit                    */
                                outbuf[outptr++] = phy_char.eigth_bit;
                                break;

                        case 0x0C:      /* Terminal Management          */
                                outbuf[outptr++] = phy_char.terminal_management_enabled;
                                break;
                        }
                }
                if ((selector & 0x300) == 0x100) /* Logical Characteristics*/
                {
                        outbuf[outptr++] = selector & 0xFF;
                        outbuf[outptr++] = 1;

                        switch(selector & 0xFF)
                        {
                        case 0x01:      /* Mode writing allowed         */
                                outbuf[outptr++] = log_char.mode_writing_allowed;
                                break;

                        case 0x02:      /* Terminal attributes          */
                                outbuf[outptr++] = log_char.terminal_attributes;
                                outbuf[outptr++] = log_char.terminal_attributes >> 8;
                                break;

                        case 0x03:      /* Terminal Type                */
                                memcpy(&outbuf[outptr],log_char.terminal_type, 6);
                                outptr += 6;
                                break;

                        case 0x04:      /* Output flow control          */
                                outbuf[outptr++] = log_char.output_flow_control;
                                break;

                        case 0x05:      /* Output page stop             */
                                outbuf[outptr++] = log_char.output_page_stop;
                                break;

                        case 0x06:      /* Flow char pass through       */
                                outbuf[outptr] = log_char.flow_character_pass_through;
                                break;

                        case 0x07:      /* Input flow control           */
                                outbuf[outptr++] = log_char.input_flow_control;
                                break;

                        case 0x08:      /* Loss notification            */
                                outbuf[outptr++] = log_char.loss_notification;
                                break;

                        case 0x09:      /* Line width                   */
                                outbuf[outptr++] = log_char.line_width;
                                outbuf[outptr++] = log_char.line_width >> 8;
                                break;

                        case 0x0A:      /* Page length                  */
                                outbuf[outptr++] = log_char.page_length;
                                outbuf[outptr++] = log_char.page_length >> 8;
                                break;

                        case 0x0B:      /* Stop length                  */
                                outbuf[outptr++] = log_char.stop_length;
                                outbuf[outptr++] = log_char.stop_length >> 8;
                                break;

                        case 0x0C:      /* CR-FILL                      */
                                outbuf[outptr++] = log_char.cr_fill;
                                outbuf[outptr++] = log_char.cr_fill >> 8;
                                break;

                        case 0x0D:      /* LF-FILL                      */
                                outbuf[outptr++] = log_char.lf_fill;
                                outbuf[outptr++] = log_char.lf_fill >> 8;
                                break;

                        case 0x0E:      /* wrap                         */
                                outbuf[outptr++] = log_char.wrap;
                                outbuf[outptr++] = log_char.wrap >> 8;
                                break;

                        case 0x0F:      /* Horizontal tab               */
                                outbuf[outptr++] = log_char.horizontal_tab;
                                outbuf[outptr++] = log_char.horizontal_tab >> 8;
                                break;

                        case 0x10:      /* Vertical tab                 */
                                outbuf[outptr++] = log_char.vertical_tab;
                                outbuf[outptr++] = log_char.vertical_tab >> 8;
                                break;

                        case 0x11:      /* Form feed                    */
                                outbuf[outptr++] = log_char.form_feed;
                                outbuf[outptr++] = log_char.form_feed >> 8;
                                break;
                        }
                }
                if ((selector & 0x300) == 0x200) /* Handler Characteristics */
                {
                        char c;

                        outbuf[outptr++] = selector & 0xFF;
                        outbuf[outptr++] = 2;

                        switch (selector & 0xFF)
                        {
                        case 0x01:      /* IGNORE INPUT                 */
                                outbuf[outptr++] = han_char.ignore_input;
                                break;

                        case 0x02:      /* Character Attributes         */
                                c = buf[bufptr++];
                                outbuf[outptr++] = c;
                                outbuf[outptr++] = 0xFF;
                                outbuf[outptr++] = char_attr[(int)c];
                                break;

                        case 0x03:      /* Control-o pass through       */
                                outbuf[outptr++] = han_char.control_o_pass_through;
                                break;

                        case 0x04:      /* Raise Input                  */
                                outbuf[outptr++] = han_char.raise_input;
                                break;

                        case 0x05:      /* Normal Echo                  */
                                outbuf[outptr++] = han_char.normal_echo;
                                break;

                        case 0x06:      /* Input Escape Seq Recognition */
                                outbuf[outptr++]= han_char.input_escseq_recognition;
                                break;

                        case 0x07:      /* Output Esc Seq Recognition   */
                                outbuf[outptr++] = han_char.output_escseq_recognition;
                                break;

                        case 0x08:      /* Input count state            */
                                outbuf[outptr++] = han_char.input_count_state;
                                outbuf[outptr++] = han_char.input_count_state >> 8;
                                break;

                        case 0x09:      /* Auto Prompt                  */
                                outbuf[outptr++] = han_char.auto_prompt;
                                break;

                        case 0x0A:      /* Error processing option      */
                                outbuf[outptr++] = han_char.error_processing;
                                break;

                        case 0x0B:      /* Error processing option rsxm+ ed*/
                                outbuf[outptr++] = han_char.error_processing;
                                break;
                        }
                }
        }

        found_common_write(outbuf, outptr);
        return len;
}

static int cterm_process_characteristics(char *buf, int len)
{
        int bufptr = 2; /* skip past flags */
        int selector;
        char c;
        char mask, val;

        while (bufptr < len)
        {
                selector = buf[bufptr] | (buf[bufptr+1]<<8);
                bufptr += 2;            /* Skip over selector */
                if ((selector & 0x300) != 0x200)
                {
                        /*
                         * Characteristics may not be sorted in numerical order
                         * so we will need to skip over characteristics which
                         * are not settable (Foundation terminal
                         * characteristics at the moment).
                         */
                        if ((selector & 0x300) == 0)
                        {
                                switch (selector & 0xFF)
                                {
                                case 0x01:
                                case 0x02:
                                case 0x03:
                                case 0x05:
                                        bufptr += 2;
                                        break;

                                case 0x04:
                                case 0x06:
                                case 0x07:
                                case 0x08:
                                case 0x0B:
                                case 0x0C:
                                        bufptr += 1;
                                        break;
                                }
                        }
                        if ((selector & 0x300) == 0x100)
                        {
                                switch (selector & 0xFF)
                                {
                                case 0x01:
                                case 0x04:
                                case 0x05:
                                case 0x06:
                                case 0x07:
                                case 0x08:
                                        bufptr += 1;
                                        break;

                                case 0x02:
                                case 0x09:
                                case 0x0A:
                                case 0x0B:
                                case 0x0C:
                                case 0x0D:
                                case 0x0E:
                                case 0x0F:
                                case 0x10:
                                case 0x11:
                                        bufptr += 2;
                                        break;

                                case 0x03:
                                        bufptr += buf[0] + 1;
                                        break;
                                }
                        }
                        continue;
                }
                selector &= 0xFF;
                switch(selector)
                {
                case 0x01:
                        han_char.ignore_input = buf[bufptr];
                        bufptr += 1;
                        break;
                case 0x02: /* Character attributes */
                        c = buf[bufptr];
                        mask = buf[bufptr+1];
                        val = buf[bufptr+2];
                        char_attr[(int)c] &= ~mask; // clear those in the mask
                        char_attr[(int)c] |= (val & mask); // set the new ones.
                        bufptr += 3;
                        DEBUG_CTERM("Setting characteristics for char %d to 0x%x\n",
                                 c, char_attr[(int)c]);
                        break;

                case 0x03:      /* Control-o pass through       */
                        han_char.control_o_pass_through = buf[bufptr];
                        bufptr += 1;
                        break;
                case 0x04:      /* Raise Input                  */
                        han_char.raise_input = buf[bufptr];
                        bufptr += 1;
                        break;
                case 0x05:      /* Normal Echo                  */
                        han_char.normal_echo = buf[bufptr];
                        bufptr += 1;
                        break;

                case 0x06:      /* Input Escape Seq Recognition */
                        han_char.input_escseq_recognition = buf[bufptr];
                        bufptr += 1;
                        tty_set_escape_proc(han_char.input_escseq_recognition);
                        break;

                case 0x07:      /* Output Esc Seq Recognition   */
                        han_char.output_escseq_recognition=buf[bufptr];
                        bufptr += 1;
                        break;

                case 0x08:      /* Input count state            */
                        han_char.input_count_state = buf[bufptr] |  buf[bufptr+1]<<8;
                        bufptr += 2;
                        break;

                case 0x09:      /* Auto Prompt                  */
                        han_char.auto_prompt = buf[bufptr];
                        bufptr += 1;
                        break;

                case 0x0A:      /* Error processing option      */
                        han_char.error_processing = buf[bufptr];
                        bufptr += 1;
                        break;
                }
        }

        return len;
}

static int cterm_process_check_input(char *buf, int len)
{
        unsigned short count = tty_get_input_count();
        char newbuf[4];

        newbuf[0] = CTERM_MSG_INPUT_COUNT;
        newbuf[1] = 0;
        newbuf[2] = count & 0xFF;
        newbuf[3] = (count >> 8) & 0xFF;

        found_common_write(newbuf, 4);

        return len;
}

static int cterm_process_input_count(char *buf, int len)
{return len;}

static int cterm_process_input_state(char *buf, int len)
{return len;}

/* Process buffer from cterm host */
int cterm_process_network(char *buf, int len)
{
        int offset = 0;

        while (offset < len)
        {
                DEBUG_CTERM("got msg: %d, len=%d\n",
                         buf[offset], len);

                switch (buf[offset])
                {
                case CTERM_MSG_INITIATE:
                        offset += cterm_process_initiate(buf+offset, len-offset);
                        break;
                case CTERM_MSG_START_READ:
                        offset += cterm_process_start_read(buf+offset, len-offset);
                        break;
                case CTERM_MSG_READ_DATA:
                        offset += cterm_process_read_data(buf+offset, len-offset);
                        break;
                case CTERM_MSG_OOB:
                        offset += cterm_process_oob(buf+offset, len-offset);
                        break;
                case CTERM_MSG_UNREAD:
                        offset += cterm_process_unread(buf+offset, len-offset);
                        break;
                case CTERM_MSG_CLEAR_INPUT:
                        offset += cterm_process_clear_input(buf+offset, len-offset);
                        break;
                case CTERM_MSG_WRITE:
                        offset += cterm_process_write(buf+offset, len-offset);
                        break;
                case CTERM_MSG_WRITE_COMPLETE:
                        offset += cterm_process_write_complete(buf+offset, len-offset);
                        break;
                case CTERM_MSG_DISCARD_STATE:
                        offset += cterm_process_discard_state(buf+offset, len-offset);
                        break;
                case CTERM_MSG_READ_CHARACTERISTICS:
                        offset += cterm_process_read_characteristics(buf+offset, len-offset);
                        break;
                case CTERM_MSG_CHARACTERISTICS:
                        offset += cterm_process_characteristics(buf+offset, len-offset);
                        break;
                case CTERM_MSG_CHECK_INPUT:
                        offset += cterm_process_check_input(buf+offset, len-offset);
                        break;
                case CTERM_MSG_INPUT_COUNT:
                        offset += cterm_process_input_count(buf+offset, len-offset);
                        break;
                case CTERM_MSG_INPUT_STATE:
                        offset += cterm_process_input_state(buf+offset, len-offset);
                        break;

                default:
                        fprintf(stderr, "Unknown cterm message %d received, offset=%d\n",
                                (char)buf[offset], offset);
                        return -1;
                }
        }
        return 0;
}


int cterm_send_oob(char oobchar, int discard)
{
        char newbuf[3];
        int ret;

        DEBUG_CTERM("sending OOB char %d\n", oobchar);

        newbuf[0] = CTERM_MSG_OOB;
        newbuf[1] = discard;
        newbuf[2] = oobchar;

        ret = found_common_write(newbuf, 3);

        /* Echo needed ? */
        if (char_attr[(int)oobchar] & 0x30) //TODO NAME!
        {
                if (oobchar == CTRL_C)
                        tty_write("\033[7m Cancel \033[0m\n", 17);
                if (oobchar == CTRL_Y)
                        tty_write("\033[7m Interrupt \033[0m\n", 20);
                if (oobchar == CTRL_O)
                {
                        if (tty_discard())
                                tty_write("\n\033[7mOutput Off\033[0m\n", 20);
                        else
                                tty_write("\n\033[7mOutput On\033[0m\n", 19);
                }
        }
        return ret;

}

int cterm_send_input(char *buf, int len, int term_pos, int flags)
{
        char newbuf[len+9];
        DEBUG_CTERM("sending input data: len=%d\n", len);

        read_pending = 0;

        newbuf[0] = CTERM_MSG_READ_DATA;
        newbuf[1] = flags;
        newbuf[2] = 0; // low-water 1
        newbuf[3] = 0; // low-water 2
        newbuf[4] = 0; // vert pos
        newbuf[5] = 0; // horiz pos
        newbuf[6] = term_pos;
        newbuf[7] = term_pos << 8;
        newbuf[8] = 0; // in case there is no data

        memcpy(newbuf+8, buf, len);

        return found_common_write(newbuf, len == 0 ? 9 : len+8);
}

void cterm_rahead_change(int count)
{
        char newbuf[2];

        if (han_char.input_count_state)
        {
                newbuf[0] = CTERM_MSG_INPUT_STATE;
                newbuf[1] = count;

                found_common_write(newbuf, 2);
        }
}
