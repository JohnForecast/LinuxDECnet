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

void zeroCommand(void)
{
  uint32_t result;
  int junk;

  NICEput1(NICE_FC_ZERO);

  if ((result = tablefind(&zeroEntitiesTable)) != 0) {
    uint8_t entity, format;
    uint16_t mode;
    char *ident;

    UNPACK4(result, &junk, &junk, &format, &entity);

    mode = (entity << 8) | format;

    if ((mode == ((NICE_ENT_LINE << 8) | NICE_SFMT_STRING)) ||
        (mode == ((NICE_ENT_CIRCUIT << 8) | NICE_SFMT_STRING)) ||
	(mode == ((NICE_ENT_NODE << 8) | NICE_NFMT_ADDRESS))) {
      if (idx >= args) {
	fprintf(stderr, "zero - missing entity identification\n");
	return;
      }
      ident = wds[idx++];

      if (strlen(ident) > 127) {
	fprintf(stderr, "zero - entity identification too long\n");
	return;
      }
    }

    /*** Check for entity-specific parameters ***/

    if (idx < args) {
      char *extra = wds[idx++];

      if ((vmatch(extra, "counters") != 0) || (idx < args)) {
	fprintf(stderr, "zero - extra characters at end of command\n");
	return;
      }
    }

    /*
     * Construct the zero counters message
     */
    NICEput1(entity & NICE_ZERO_OPT_ENTITY);

    switch (mode) {
      case (NICE_ENT_LINE << 8) | NICE_SFMT_STRING:
      case (NICE_ENT_CIRCUIT << 8) | NICE_SFMT_STRING:
	NICEputString(ident);
	break;

      case (NICE_ENT_NODE << 8) | NICE_NFMT_EXECUTOR:
	NICEput1(0);
	NICEput2(0);
	break;

      case (NICE_ENT_NODE << 8) | NICE_NFMT_ADDRESS:
	if (parseNode(ident)) {
	  fprintf(stderr, "Invalid node address or node name\n");
	  return;
	}
	break;

      default:
	NICEput1(format);
	break;
    }

    if (netConnect() >= 0) {
      int len;

      NICEflush();

      if ((len = NICEread()) > 0) {
	int8_t code;

	NICEget1((uint8_t *)&code);
	if (code < 0) {
	  cmdError("zero", code, NULL);
	  return;
	}
      } else fprintf(stderr, "NICEread() error return (%d)\n", len);
    }
  } else fprintf(stderr, "zero - unknown entity\n");
}

