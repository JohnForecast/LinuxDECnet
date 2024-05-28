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
#include "circuit.h"

void loopCommand(void)
{
  uint32_t result;
  int junk;

  NICEput1(NICE_FC_TEST);

  if ((result = tablefind(&loopEntitiesTable)) != 0) {
    uint8_t option, entity, format;
    uint16_t mode;
    char *status, *ident = NULL;
    uint16_t addr = 0;
    struct accessdata_dn access;
    struct paramTable *params = &loopNodeParamTable;

    memset(&access, 0, sizeof(access));

    UNPACK4(result, &junk, &option, &format, &entity);

    mode = (entity << 8) | format;

    /*
     * Handle entity specific identification
     */
    switch (mode) {
      case (NICE_ENT_CIRCUIT << 8) | NICE_SFMT_STRING:
      case (NICE_ENT_LINE << 8) | NICE_SFMT_STRING:
	if (idx >= args) {
	  fprintf(stderr, "loop - missing entity identification\n");
	  return;
	}
	ident = wds[idx++];

	if (strlen(ident) > 127) {
	  fprintf(stderr, "loop - entity identification too long\n");
	  return;
	}
	params = (mode == ((NICE_ENT_CIRCUIT << 8) | NICE_SFMT_STRING)) ?
		&loopCircuitParamTable : &loopLineParamTable;
	break;

      case (NICE_ENT_NODE << 8) | NICE_NFMT_EXECUTOR:
	if ((status = parseAccessCtrl(&access)) != NULL) {
	  fprintf(stderr, "loop - %s\n", status);
	  return;
	}
	goto common;

      case (NICE_ENT_NODE << 8) | NICE_NFMT_ADDRESS:
	if ((status = parseRemote(&addr, &access)) != NULL) {
	  fprintf(stderr, "loop - %s\n", status);
	  return;
	}

  common:
	if ((access.acc_userl != 0) ||
	    (access.acc_passl != 0) ||
	    (access.acc_accl != 0))
	  option |= NICE_LOOP_OPT_ACCESS;
	break;
    }

    NICEput1(option);

    if (entity == NICE_ENT_NODE) {
      /*
       * NODE entity (includes EXECUTOR)
       */
      NICEput1(NICE_NFMT_ADDRESS);
      NICEput2(addr);

      if ((option & NICE_LOOP_OPT_ACCESS) != 0) {
	NICEputBytes(access.acc_userl, access.acc_user);
	NICEputBytes(access.acc_passl, access.acc_pass);
	NICEputBytes(access.acc_accl, access.acc_acc);
      }
    } else {
      /*
       * CIRCUIT or LINE entity
       */
      NICEputString(ident);
    }

    /*
     * Process following parameters
     */
    while (idx < args) {
      if (parseTablefind(params) == 0)
	return;
    }

    if (netConnect() >= 0) {
      int len;

      NICEflush();

      if ((len = NICEread()) > 0) {
	int8_t code;

	NICEget1((uint8_t *)&code);
	if (code < 0) {
	  cmdError("loop", code, params);
	  return;
	}
      } else fprintf(stderr, "NICEread() error return (%d)\n", len);
    }
  } else fprintf(stderr, "loop - unknown entity\n");
}

