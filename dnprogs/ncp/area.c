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
 * Table of epected parameters for "Summary" and "Status" responses along with
 * the field widths for display.
 */
static struct fields {
  uint16_t		id;
  int16_t		width;
} summaryFields[] = {
  { NICE_P_A_STATE, -15 },
  { NICE_P_A_CIRCUIT, -18 },
  { NICE_P_A_NEXTNODE, -18 },
  { 0xFFFF, 0 }
}, statusFields[] = {
  { NICE_P_A_STATE, -13 },
  { NICE_P_A_COST, -7 },
  { NICE_P_A_HOPS, -7 },
  { NICE_P_A_CIRCUIT, -18 },
  { NICE_P_A_NEXTNODE, -18 },
  { 0xFFFF, 0 }
};

void showArea(
  uint8_t code,
  uint8_t option,
  uint8_t infotype,
  uint8_t format,
  uint8_t display,
  uint8_t first,
  uint8_t *oneshot
)
{
  uint8_t id, idfmt, fmt, area;
  char entity[32];
  uint16_t entry;
  struct fields *fields;
  struct valueTable *vtable = NULL;

  /*
   * Skip over the returned entity id and check the entity specifies an
   * area address.
   */
  if (!NICEget1(&id) || !NICEget1(&idfmt))
    return;

  if (idfmt != NICE_AFMT_ADDRESS) {
    fprintf(stderr, "Area format is not 0 (area)\n");
    return;
  }

  /*
   * Get the area address from the input buffer
   */
  if (NICEget1(&fmt)) {
    if ((fmt == 0) && NICEget1(&area)) {
      /*
       * Construct the entity (area address)
       */
      sprintf(entity, "%hhu", area);

      if (display)
        if (((infotype & NICE_READ_OPT_TYPE) != NICE_READ_OPT_SUM) &&
	    ((infotype & NICE_READ_OPT_TYPE) != NICE_READ_OPT_STATUS))
	  printf("Area = %s\n\n", entity);

      switch (infotype & NICE_READ_OPT_TYPE) {
        case NICE_READ_OPT_SUM:
	  fields = summaryFields;

	  if (*oneshot) {
	    printf("  Area    State          Circuit           Next node to area\n\n");
	    *oneshot = 0;
	  }

common:
	  printf("  %-8s", entity);

	  while (!NICEisEmpty()) {
	    struct nameTable *table = areaParamTable;
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
	    printf("  Area    State       Cost   Hops    Circuit           Next node to area\n\n");
	    *oneshot = 0;
	  }
	  goto common;
      }
    }
  }
}


/*
 * Parse an area address and place it in the Read Information request message
 */
int parseArea(
  char *ident
)
{
  uint8_t area;

  if (isdigit(*ident)) {
    area = *ident++ - '0';
    if (isdigit(*ident)) {
      area *= 10;
      area += *ident++ - '0';
    }
    if (*ident == 0) {
      if (area <= 63) {
	NICEput1(NICE_AFMT_ADDRESS);
	NICEput1(area);
	return 0;
      }
    }
  }
  return -1;
}
