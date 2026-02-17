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
 * Find a sequence of bits set on an event bitmap
 */
static int findSetBits(
  uint8_t *bitmap,
  int start
)
{
  int i;

  for (i = start; i < 64; i++)
    if ((bitmap[i / 8] & (1 << (i % 8))) == 0)
      break;

  return i - 1;
}

/*
 * Process an events parameter, breaking out individual subfields.
 */
static int processEvents(
  char *source,
  uint16_t *class,
  uint8_t *events,
  char *evstring
)
{
  uint8_t encoding, count, entity;
  uint16_t addr, param;
  char nodename[8], temp[8];
  int i, first = TRUE;

  *source = '\0';
  *evstring = '\0';
  memset(events, 0, 8);

  nodename[0]= '\0';

  if (NICEget1(&encoding)) {
    if ((encoding & NICE_TYPE_CMULTI) == NICE_TYPE_CMULTI) {
      count = encoding & NICE_TYPE_C_MULTI_CNT;

      if ((count >= 2) && (count <= 5)) {
	if (NICEgetType(NICE_TYPE_C1, &entity, 0)) {
	  if (entity != NICE_P_G_ENTITY_NONE) {
	    if (entity == NICE_P_G_ENTITY_NODE) {
	      if (!NICEgetType(NICE_TYPE_DU2, &addr, 0))
		return FALSE;

	      NICEgetType(NICE_TYPE_AI, nodename, 0);

	      sprintf(source, "%hu.%hu", (addr >> 10) & 0x3F, addr & 0x3FF);
	      if (nodename[0]) {
		strcat(source, "(");
		strcat(source, nodename);
		strcat(source, ")");
	      }
	    } else {
	      if (!NICEgetType(NICE_TYPE_AI, source, 17))
		return FALSE;
	    }
	  }
	  if (NICEgetType(NICE_TYPE_DU2, class, 0)) {
	    if ((*class & NICE_P_G_CLASS_TYPE) == NICE_P_G_CLASS_SINGLE) {
	      NICEgetType(NICE_TYPE_HI, events, 8);

	      if (entity != NICE_P_G_ENTITY_NONE) {
		switch (entity) {
		  case NICE_P_G_ENTITY_LINE:
		    strcat(evstring, "Line ");
		    break;

		  case NICE_P_G_ENTITY_CIRCUIT:
		    strcat(evstring, "Circuit ");
		    break;

		  case NICE_P_G_ENTITY_MODULE:
		    strcat(evstring, "Module ");
		    break;

		  case NICE_P_G_ENTITY_AREA:
		    strcat(evstring, "Area ");
		    break;

		}

		strcat(evstring, source);
		strcat(evstring, ", ");
	      }

	      switch(*class & NICE_P_G_CLASS_TYPE) {
		case NICE_P_G_CLASS_SINGLE:
		  sprintf(temp, "%u.", *class & NICE_P_G_CLASS_VALUE);
		  strcat(evstring, temp);

		  /*
		   * Build descriptors for all the bits set in the event
		   * bitmap.
		   */
		  for (i = 0; i < 64; i++)
		    if ((events[i / 8] & (1 << (i % 8))) != 0) {
		      int endbit = findSetBits(events, i + 1);

		      if (i == endbit)
			sprintf(temp, "%u", i);
		      else sprintf(temp, "%u-%u", i, endbit);

		      if (!first)
			strcat(evstring, ",");
		      first = FALSE;

		      strcat(evstring, temp);

		      i = endbit + 1;
		    }
		  break;

		case NICE_P_G_CLASS_ALL:
		  sprintf(temp, "%u.*", *class & NICE_P_G_CLASS_VALUE);
		  strcat(evstring, temp);
		  break;

		case NICE_P_G_CLASS_KNOWN:
		  strcat(evstring, "*.*");
		  break;
	      }  
	      return TRUE;
	    }
	  }
	}
      }
    }
  }
done:
  return FALSE;
}

void showLogging(
  uint8_t code,
  uint8_t option,
  uint8_t infotype,
  uint8_t format,
  uint8_t display,
  uint8_t first,
  uint8_t *oneshot
)
{
  uint8_t sinktype, events[8];
  uint16_t class;
  char *entity, source[32], evstring[256];

  if (NICEget1(&sinktype)) {
    /*
     * Construct the entity (logging sink type)
     */
    switch (sinktype) {
      case NICE_P_G_SINK_CONSOLE:
	entity = "console";
	break;

      case NICE_P_G_SINK_FILE:
	entity = "file";
	break;

      case NICE_P_G_SINK_MONITOR:
	entity = "monitor";
	break;

      default:
	fprintf(stderr, "Unexpected sink type seen\n");
	return;
    }

    if (display)
      printf("Logging sink type = %s\n\n", entity);

    switch (infotype & NICE_READ_OPT_TYPE) {
      case NICE_READ_OPT_SUM:
      case NICE_READ_OPT_STATUS:
      case NICE_READ_OPT_CHAR:
      case NICE_READ_OPT_EVENTS:
	if (NICEisEmpty()) {
	  if ((code == NICE_RET_SUCCESS) && first)
	    printf("No information available\n\n");
	  return;
	}

	do {
	  uint16_t param;

	  if (!NICEpeek2(&param))
	    break;

	  if (param == NICE_P_G_EVENTS) {
	    NICEget2(&param);

	    if (!processEvents(source, &class, events, evstring))
	      break;

	    printf("%-25s= %s\n", "Events", evstring);
	  } else displayParam(loggingParamTable);
 	} while (!NICEisEmpty());
	break; 
    }
done:
    printf("\n");
  }
}

