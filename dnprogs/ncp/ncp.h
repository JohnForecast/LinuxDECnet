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

#ifndef __NCP_H__
#define __NCP_H__

/*
 * Node name parse return types
 */
#define PARSE_UNKNOWN	-1		/* Unknown */
#define PARSE_ADDRESS	 0		/* Address in aa.nnnn format */
#define PARSE_NAME	 1		/* Node name with address mapping */
#define PARSE_NONAME	 2		/* Node name with no address mapping */

/*
 * Command parse table structures
 */
struct element {
  char			*words;
  int			value;
};

struct table {
  struct element	*entries;
  uint32_t		count;
};

/*
 * Table entries can return up to a 32-bit unsigned integer value which may
 * be zero. Often we need to return multiple smaller values. In order to
 * make sure the result is non-zero, we reserve the high bit to indicate a
 * valid value. The following macros may be used to pack up multiple small
 * fields.
 */
#define PACK4(a7, b8, c8, d8) \
	(0x80000000 | ((a7) << 24) | ((b8) << 16) | ((c8) << 8) | (d8))
#define PACK3(a7, b8, c16) \
	(0x80000000 | ((a7) << 24) | ((b8) << 16) | (c16))
#define UNPACK4(v, a, b, c, d) \
	*(a) = ((v) >> 24) & 0x3F; \
	*(b) = ((v) >> 16) & 0xFF; \
	*(c) = ((v) >> 8) & 0xFF; \
	*(d) = ((v) & 0xFF)
#define UNPACK3(v, a, b, c) \
	*(a) = ((v) >> 24) & 0x3F; \
	*(b) = ((v) >> 16) & 0xFF; \
	*(c) = ((v) & 0xFFFF)

/*
 * Commands
 */
#define CMD_CLEAR	1
#define CMD_COPY	2
#define CMD_DEFINE	3
#define CMD_EXIT	4
#define CMD_LIST	5
#define CMD_LOAD	6
#define CMD_LOOP	7
#define CMD_PURGE	8
#define CMD_SET		9
#define CMD_SHOW	10
#define CMD_TRIGGER	11
#define CMD_ZERO	12

/*
 * Table structures to map parameter/counter IDs to text strings and,
 * optionally, auxilliary information (e.g. bitmap names).
 */
struct nameTable {
  uint16_t		number;
  char			*name;
  void			*aux;
};

struct valueTable {
  uint16_t		value;
  char			*name;
};

/*
 * Parameter parse table structures
 */
struct paramElement {
  char			*words;
  uint16_t		id;
  char			*(*parser)(void *);
  void			*arg;
};

struct paramTable {
  struct paramElement	*entries;
  uint32_t		count;
};

struct minmaxU {
  unsigned long		min;
  unsigned long		max;
};

struct minmax {
  long			min;
  long			max;
};

extern int idx, args;
extern char *wds[];

extern struct table commandTable;
extern struct table showEntitiesTable;
extern struct table listEntitiesTable;
extern struct table infoTypeTable;

extern struct nameTable nodeCtrTable[];
extern struct nameTable nodeParamTable[];

extern struct nameTable areaParamTable[];

extern struct nameTable circuitCtrTable[];
extern struct nameTable circuitParamTable[];

extern struct table zeroEntitiesTable;

extern struct table loopEntitiesTable;

extern struct table copyEntitiesTable;

extern struct paramTable loopCircuitParamTable;
extern struct paramTable loopLineParamTable;
extern struct paramTable loopNodeParamTable;

extern int vmatch(char *, char *);
extern uint32_t tablefind(struct table *);

extern int netConnect(void);
extern uint8_t tellvalid;
extern char *parseForTell(void);
extern char *parseForSetexec(void);
extern char *parseRemote(uint16_t *, char **, int *, struct accessdata_dn *);
extern char *parseAccessCtrl(struct accessdata_dn *);

extern int parseTablefind(struct paramTable *);
extern char *parseC1(void *);
extern char *parseDU1(void *);
extern char *parseDU2(void *);
extern char *parseMAC(void *);
extern char *parseNodename(void *);

extern void displayCtr(struct nameTable *);
extern void param2Text(void *, char *, uint16_t);
extern void displayParam(struct nameTable *);

extern void cmdError(char *, int8_t, struct paramTable *);

#endif

