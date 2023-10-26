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
  { NICE_P_C_STATE, -25 },
  { NICE_P_C_LOOPNAME, -11 },
  { NICE_P_C_ADJNODE, -16 },
  { 0xFFFF, 0 }
}, statusFields[] = {
  { NICE_P_C_STATE, -24 },
  { NICE_P_C_LOOPNAME, -13 },
  { NICE_P_C_ADJNODE, -15 },
  { NICE_P_C_BLOCKSIZE, -6 },
  { 0xFFFF, 0 }
};

void showCircuit(
  uint8_t code,
  uint8_t option,
  uint8_t infotype,
  uint8_t format,
  uint8_t display,
  uint8_t first,
  uint8_t *oneshot
)
{
  char length, entity[32];
  uint16_t entry;
  struct fields *fields;
  struct valueTable *vtable;
  uint8_t id, idfmt;

  /*
   * Skip over the returned entity id and format.
   */
  if (!NICEget1(&id) || !NICEget1(&idfmt))
    return;

  /*
   * Get the circuit name from the input buffer
   */
  memset(entity, 0, sizeof(entity));

  if (NICEgetAI(&length, 0xFF, entity, NICE_MAXCIRCUITL)) {
    if (((infotype & NICE_READ_OPT_TYPE) != NICE_READ_OPT_SUM) &&
	((infotype & NICE_READ_OPT_TYPE) != NICE_READ_OPT_STATUS))
      printf("Circuit = %s\n\n", entity);

    switch (infotype & NICE_READ_OPT_TYPE) {
      case NICE_READ_OPT_SUM:
	fields = summaryFields;

	if (*oneshot) {
	  printf("   Circuit          State                   Loopback     Adjacent\n");
	  printf("                                              Name      Routing Node\n\n");
	  *oneshot = 0;
	}

	printf("  %-18s", entity);

	while (!NICEisEmpty()) {
	  struct nameTable *table = circuitParamTable;
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
	break;

      case NICE_READ_OPT_STATUS:
	fields = statusFields;

	if (*oneshot) {
	  printf("   Circuit          State                   Loopback     Adjacent       Block\n");
	  printf("                                              Name         Node         Size\n\n");
	  *oneshot = 0;
	}

	printf("  %-18s", entity);

	while (!NICEisEmpty()) {
	  struct nameTable *table = circuitParamTable;
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
	    printf(buf);
	  } else {
	    param2Text(vtable, buf, entry);
	    printf("%*s", fields->width, buf);
	    fields++;
	  }
	}
	printf("\n");
	break;

      case NICE_READ_OPT_CHAR:
	if (NICEisEmpty()) {
	  if ((code == NICE_RET_SUCCESS) && first)
	    printf("No information available\n\n");
	  return;
	}

	do {
	  displayParam(circuitParamTable);
	} while (!NICEisEmpty());
	printf("\n");
	break;

      case NICE_READ_OPT_CTRS:
	if (NICEisEmpty()) {
	  if ((code == NICE_RET_SUCCESS) && first)
	    printf("No information available\n");
	  return;
	}

	do {
	  displayCtr(circuitCtrTable);
	} while (!NICEisEmpty());
	printf("\n");
	break;
    }
  }
}

