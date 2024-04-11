/******************************************************************************
    (c) 2002-2008      Christine Caulfield          christine.caulfield@googlemail.com

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 ******************************************************************************
 */


/* Foundation services routines */
extern char *found_connerror(void);
extern int found_getsockfd(void);
extern int found_write(char *buf, int len);
extern int found_read(void);
extern int found_setup_link(char *node, int object, int (*processor)(char *, int), int connect_timeout);
extern int found_common_write(char *buf, int len);

/* cterm/dterm routines */
extern int cterm_send_input(char *buf, int len, int term_pos, int flags);
extern int cterm_send_oob(char, int);
extern int cterm_process_network(char *buf, int len);
extern void cterm_rahead_change(int count);

/* TTY routines */
extern int  tty_write(char *buf, int len);
extern void tty_set_terminators(char *buf, int len);
extern void tty_timeout(void);
extern void tty_set_default_terminators(void);
extern void tty_start_read(char *prompt, int len, int promptlen);
extern void tty_set_timeout(unsigned short to);
extern void tty_set_maxlen(unsigned short len);
extern void tty_send_unread(void);
extern int  tty_process_terminal(char *inbuf, int len);
extern int  tty_setup(char *name, int setup);
extern void tty_clear_typeahead(void);
extern void tty_set_noecho(void);
extern void tty_echo_terminator(int a);
extern void tty_set_discard(int onoff);
extern int  tty_set_escape_proc(int onoff);
extern void tty_set_uppercase(int onoff);
extern void tty_allow_edit(int onoff);
extern int  tty_format_cr(void);
extern int  tty_get_input_count(void);
extern int  tty_discard(void);

extern int (*send_input)(char *buf, int len, int term_pos, int flags);
extern int (*send_oob)(char, int);
extern void (*rahead_change)(int count);

/* Global variables */
extern int debug;


/* Send flags:
 * These are actuall CTERM Read-Data flags (p62)
 */
#define SEND_FLAG_TERMINATOR     0
#define SEND_FLAG_VALID_ESCAPE   1
#define SEND_FLAG_INVALID_ESCAPE 2
#define SEND_FLAG_OUT_OF_BAND    3
#define SEND_FLAG_BUFFER_FULL    4
#define SEND_FLAG_TIMEOUT        5
#define SEND_FLAG_UNREAD         6
#define SEND_FLAG_UNDERFLOW      7
#define SEND_FLAG_ABSENTEE_TOKEN 8
#define SEND_FLAG_VPOS_CHANGE    9
#define SEND_FLAG_LINE_BREAK    10
#define SEND_FLAG_FRAMING_ERROR 11
#define SEND_FLAG_PARITY_ERROR  12
#define SEND_FLAG_OVERRUN       13

/* DEBUG flags */
#define DEBUG_FLAG_FOUND   1
#define DEBUG_FLAG_CTERM   2
#define DEBUG_FLAG_TTY     4
#define DEBUG_FLAG_FOUND2  8
#define DEBUG_FLAG_TTY2   16

#define DEBUGLOG(subsys, args...) if (debug & subsys) fprintf(stderr, args)

#define DEBUG_FOUND(args...) DEBUGLOG(DEBUG_FLAG_FOUND, "FOUND: " args)
#define DEBUG_FOUND2(args...) DEBUGLOG(DEBUG_FLAG_FOUND2, "FOUND2: " args)
#define DEBUG_CTERM(args...) DEBUGLOG(DEBUG_FLAG_CTERM, "CTERM: " args)
#define DEBUG_TTY(args...) DEBUGLOG(DEBUG_FLAG_TTY, "TTY: " args)
#define DEBUG_TTY2(args...) DEBUGLOG(DEBUG_FLAG_TTY2, "TTY2: " args)
