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
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>

#include "ncp.h"
#include "nice.h"
#include "node.h"

struct minmaxU minmaxDU1 = { 0, 0xFF };
struct minmaxU minmaxDU2 = { 0, 0xFFFF };

/*
 * Lookup the next parameter keyword and parse it's following value if any
 */
int parseTablefind(
  struct paramTable *table
)
{
  int i;

  for (i = 0; i < table->count; i++) {
    int offset = 0;
    char *match = table->entries[i].words;
    char *result;

    do {
      /*
       * Make sure we don't match past the end of line
       */
      if ((idx + offset) >= args)
	goto nomatch;

      if (match[0] == ' ')
	match++;

      if (vmatch(wds[idx + offset], match) != 0)
	goto nomatch;

      offset++;
    } while ((match = strchr(match, ' ')) != NULL);

    /*
     * Skip over the words we just matched
     */
    idx += offset;

    NICEput2(table->entries[i].id);

    if (table->entries[i].parser != NULL) {
      if (idx >= args) {
	fprintf(stderr, "argument not present for \"%s\"\n",
		 table->entries[i].words);
	return 0;
      }

      result = (*table->entries[i].parser)(table->entries[i].arg);
      if (result != NULL) {
	fprintf(stderr, "error parsing \"%s\" argument - %s\n",
		 table->entries[i].words, result);
	return 0;
      }
    }
    return 1;

nomatch:
    continue;
  }
  return 0;
}

/*
 * Parse an argument (in wds[idx]) which will fit in a C-1 data type and
 * place the data in the NICE message. The argument is a pointer to a table
 * descriptor providing the mapping between text strings and the coded values.
 */
char *parseC1(
  void *arg
)
{
  struct table *table = arg;
  int i;

  for (i = 0; i < table->count; i++) {
    if (vmatch(wds[idx], table->entries[i].words) == 0) {
      NICEput1(table->entries[i].value);
      idx++;
      return NULL;
    }
  }
  return "unknown value";
}

/*
 * Parse an argument (in wds[idx]) which will fit in a DU-1 data type and
 * place the data in the NICE message.
 */
char *parseDU1(
  void *arg
)
{
  struct minmax *minmax = arg == NULL ? &minmaxDU1 : arg;
  unsigned long val;
  char *endptr;

  val = strtoul(wds[idx++], &endptr, 10);
  if (*endptr != '\0')
    return "extra characters";

  if ((val < minmax->min) || (val > minmax->max))
    return "value out of range";

  NICEput1(val & 0xFF);
  return NULL;
}

/*
 * Parse an argument (in wds[idx]) which will fit in a DU-2 data type and
 * place the data in the NICE message.
 */
char *parseDU2(
  void *arg
)
{
  struct minmax *minmax = arg == NULL ? &minmaxDU2 : arg;
  unsigned long val;
  char *endptr;

  val = strtoul(wds[idx++], &endptr, 10);
  if (*endptr != '\0')
    return "extra characters";

  if ((val < minmax->min) || (val > minmax->max))
    return "value out of range";

  NICEput2(val & 0xFFFF);
  return NULL;
}

/*
 * Parse a MAC address in the format "aa-bb-cc-dd-ee-ff" (in wds[idx]) and
 * place the 6 bytes of the address in the NICE message.
 */
char *parseMAC(
  void *arg
)
{
  char *ptr = wds[idx++];
  uint8_t addr[6];
  int i;

  for (i = 0; i < 6; i++) {
    char ch1 = *ptr++;
    char ch2 = *ptr++;

    if (!isxdigit(ch1) || !isxdigit(ch2))
      return "invalid character in MAC address";

    if (isdigit(ch1)) {
      ch1 -= '0';
    } else {
      if (islower(ch1))
	ch1 += 10 - 'a';
      else ch1 += 10 -'A';
    }

    if (isdigit(ch2)) {
      ch2 -= '0';
    } else {
      if (islower(ch2))
	ch2 += 10 - 'a';
      else ch2 += 10 -'A';
    }

    addr[i] = (ch1 << 4) | ch2;

    if (i != 5)
      if (*ptr++ != '-')
	return "invalid separator in MAC address";
  }

  if (*ptr != '\0')
    return "extra character(s) after MAC address";

  NICEputBytes(sizeof(addr), addr);
  return NULL;
}


/*
 * Parse a node name with no access control information (in wdx[idx]) and
 * place the character string in the NICE message. The nodename may, optionally,
 * be trerminated by "::".
 */
char *parseNodename(
  void *arg
)
{
  char *name = wds[idx++];
  char node[8];
  int i, len;

  memset(node, 0, sizeof(node));

  if ((len = strlen(name)) > 2) {
    if (name[len - 1] == ':') {
      if (name[len - 2] == ':')
	name[len - 2] = '\0';
      else return "invalid node name syntax";
    }
  }

  for (i = 0; i < 6; i++) {
   if (name[i] == '\0')
     break;

   if (!isalnum(name[i]))
     return "non-alphanumeric character";
   if (islower(name[i]))
     name[i] = toupper(name[i]);

   node[i] = name[i];
  }

  /*
   * A node name must contain at least 1 alphabetic character.
   */
  for (i = 0; (i < 6) && (node[i] != '\0'); i++) {
    if (isalpha(node[i])) {
      NICEputString(node);
      return NULL;
    }
  }
  return "node name must contain 1 alphabetic character";
}

