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
#include <readline/readline.h>
#include <readline/history.h>
#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>

#include "ncp.h"
#include "nice.h"

/*
 * Table of expected parameters for "Summary" and "Status" responses along with
 * the field widths for display.
 */
static struct fields {
  uint16_t		id;
  int16_t		width;
} summaryFields[] = {
  { NICE_P_N_STATE, -13 },
  { NICE_P_N_ACTIVELINKS, -8 },
  { NICE_P_N_DELAY, -8 },
  { NICE_P_N_CIRCUIT, -11 },
  { NICE_P_N_NEXTNODE, -16 },
  { 0xFFFF, 0 }
}, statusFields[] = {
  { NICE_P_N_STATE, -13 },
  { NICE_P_N_ACTIVELINKS, -8 },
  { NICE_P_N_DELAY, -7 },
  { NICE_P_N_TYPE, -16 },
  { NICE_P_N_COST, -6 },
  { NICE_P_N_HOPS, -6 },
  { NICE_P_N_CIRCUIT, -8 },
  { 0xFFFF, 0 }
};

void showNode(
  uint8_t code,
  uint8_t option,
  uint8_t infotype,
  uint8_t format,
  uint8_t display,
  uint8_t first,
  uint8_t *oneshot
)
{
  uint16_t nodeaddress;
  char length, nodename[NICE_MAXNODEL+1], entity[32];
  uint8_t executor = FALSE;

  /*
   * Get the node address and possible node name from the input buffer
   */
  memset(nodename, 0, sizeof(nodename));
  if (NICEget2(&nodeaddress)) {
    if (NICEgetAI(&length, 0x7F, nodename, NICE_MAXNODEL)) {
      if ((length & 0x80) != 0) {
	executor = TRUE;
	length &= ~0x80;
      }

      /*
       * Construct the entity (node address + optional name).
       */
      sprintf(entity, "%hu.%hu%s%s%s",
	       (nodeaddress >> 10) & 0x3F, nodeaddress & 0x3FF,
	       length ? " (" : "", length ? nodename : "", length ? ")" : "");

      if (display)
	if ((((infotype & NICE_READ_OPT_TYPE) != NICE_READ_OPT_SUM) &&
	     ((infotype & NICE_READ_OPT_TYPE) != NICE_READ_OPT_STATUS)) ||
	      executor)
	  printf("%s node = %s\n\n", executor ? "Executor" : "Remote", entity);

      switch (infotype & NICE_READ_OPT_TYPE) {
	case NICE_READ_OPT_SUM:
	  if (executor) {
	    if (!NICEisEmpty()) {
	      do {
		displayParam(nodeParamTable);
	      } while (!NICEisEmpty());
	    }
	    printf("\n\n");

	  } else {
	    uint16_t entry;
	    struct fields *fields = summaryFields;
	    struct valueTable *vtable = NULL;

	    if (NICEisEmpty()) {
	      if ((code == NICE_RET_SUCCESS) && first)
		printf("No infomation available\n\n");
	      return;
	    }

	    if (*oneshot) {
	      printf("    Node         State        Active  Delay   Circuit    Next Node\n");
	      printf("                              Links\n\n");
	      *oneshot = 0;
	    }

	    printf("%-17s", entity);

	    while (!NICEisEmpty()) {
	      struct nameTable *table = nodeParamTable;
	      char buf[64] = "";

	      if (!NICEget2(&entry))
		break;

	      if ((entry & NICE_ID_CTR) != 0) {
		fprintf(stderr, "Unexpected counter data ID seen\n");
		return;
	      }

	      while (fields->id != (entry & NICE_ID_PARAM_TYPE)) {
		if (fields->id == 0xFFFF)
		  goto done;

		printf("%*s", fields->width, "");
		fields++;
	      }

	      while (table->name != NULL) {
		if (table->number == (entry & NICE_ID_PARAM_TYPE)) {
		  vtable = table->aux;
		  break;
		}
		table++;
	      }

	      if (table->name == NULL)
		goto done;

	      param2Text(vtable, buf, entry);
	      printf("%*s", fields->width, buf);
	      fields++;
	    }
  done:
	    printf("\n");
	  }
	  break;

	case NICE_READ_OPT_STATUS:
	  if (executor) {
	    if (!NICEisEmpty()) {
	      do {
		displayParam(nodeParamTable);
	      } while (!NICEisEmpty());
	    }
	    printf("\n\n");

	  } else {
            uint16_t entry;
            struct fields *fields = statusFields;
            struct valueTable *vtable = NULL;

	    if (*oneshot) {
	      printf("    Node          State      Active  Delay  Type            Cost  Hops  Circuit\n");
	      printf("                             Links\n\n");
	      *oneshot = 0;
	    }

            printf("%-16s", entity);

            while (!NICEisEmpty()) {
              struct nameTable *table = nodeParamTable;
              char buf[64] = "";

              if (!NICEget2(&entry))
                break;

              if ((entry & NICE_ID_CTR) != 0) {
                fprintf(stderr, "Unexpected counter data ID seen\n");
                return;
              }

              while (table->name != NULL) {
                if (table->number == (entry & NICE_ID_PARAM_TYPE)) {
                  vtable = table->aux;
                  break;
                }
                table++;
              }

              while (fields->id != (entry & NICE_ID_PARAM_TYPE)) {
                if (fields->id == 0xFFFF)
		  break;

                printf("%*s", fields->width, "");
                fields++;
              }

	      if (fields->id == 0xFFFF) {
		if (table->name != NULL)
		  printf("\n%s = ", table->name);
		else printf("\nParameter #%u = ", entry & NICE_ID_PARAM_TYPE);
		param2Text(vtable, buf, entry);
		printf("%s", buf);
	      } else {
                param2Text(vtable, buf, entry);
                printf("%*s", fields->width, buf);
                fields++;
	      }
            }
            printf("\n");
	  }
	  break;

	case NICE_READ_OPT_CHAR:
	  if (NICEisEmpty()) {
	    if ((code == NICE_RET_SUCCESS) && first)
	      printf("No information available\n\n");
	    return;
	  }

	  do {
	    displayParam(nodeParamTable);
	  } while (!NICEisEmpty());
	  printf("\n");
	  break;

	case NICE_READ_OPT_CTRS:
	  if (NICEisEmpty()) {
	    if ((code == NICE_RET_SUCCESS) && first)
	      printf("No information available\n\n");
	    return;
	  }

	  do {
	    displayCtr(nodeCtrTable);
	  } while (!NICEisEmpty());
	  printf("\n");
	  break;
      }
    }
  }
}

/*
 * Parse a node name or node address and place it in the Read Information
 * request message.
 */
int parseNode(
  char *ident
)
{
  uint16_t addr, area = 0, node;
  uint8_t name[8];
  char *str = ident;
  int valid = 0;

  /*
   * First we'll try to parse the input as a node address.
   */
  if (*str != 0) {
    if (strchr(ident, '.') != NULL) {
      if (!isdigit(*str))
	goto notaddr;

      area = *str++ -'0';
      if (isdigit(*str)) {
	area *= 10;
	area += *str++ - '0';
      }
      if (*str++ != '.')
	goto notaddr;
    }

    if (isdigit(*str)) {
      node = *str++ - '0';
      if (isdigit(*str)) {
	node *= 10;
	node += *str++ - '0';
      }
      if (isdigit(*str)) {
	node *= 10;
	node += *str++ - '0';
      }
      if (isdigit(*str)) {
	node *= 10;
	node += *str++ - '0';
      }

      if (*str == 0) {
	if ((node <= 1023) && (area <= 63)) {
	  /*
	   * Valid node address found
	   */
	  addr = (area << 10) | node;
	  NICEput1(NICE_NFMT_ADDRESS);
	  NICEput2(addr);
	  return 0;
	}
      }
    }

notaddr:
    /*
     * Now try to parse the input as a node name
     */
    if (strlen(ident) <= 6) {
      str = ident;

      while (*str != 0) {
	if (!isalnum(*str))
	  return -1;
	if (isalpha(*str)) {
	  valid = 1;
	  *str = toupper(*str);
	}
	str++;
      }

      if (valid) {
	NICEputString(ident);
	return 0;
      }
    }
  }
  return -1;
}
