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
#include "line.h"
#include "logging.h"
#include "circuit.h"
#include "module.h"
#include "area.h"

typedef void (*entityDisp_t)(uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t *);

static entityDisp_t showDispatch[] = {
  showNode,
  showLine,
  showLogging,
  showCircuit,
  showModule,
  showArea
};

static char *entityName[] = {
  "Node", "Line", "Logging", "Circuit", "Module", "Area"
};

static char *optionName[] = {
  "Summary", "Status", "Characteristics", "Counters", "Events"
};

void displayCtr(
  struct nameTable *table
)
{
  uint16_t entry, bitmap;
  uint8_t counter8;
  uint16_t counter16;
  uint32_t counter32;
  struct valueTable *vtable = NULL;

  if (NICEget2(&entry)) {
    if ((entry & NICE_ID_CTR) == 0) {
      fprintf(stderr, "Non-counter data ID seen\n");
      return;
    }

    if ((entry & NICE_ID_CTR_BITMAP) != 0) {
      if (!NICEget2(&bitmap)) {
	fprintf(stderr, "Bitmap data not present\n");
	return;
      }
    }

    switch (entry & NICE_ID_CTR_LENGTH) {
      case NICE_ID_CTR_LEN_RSVD:
	fprintf(stderr, "Reserved field in counter data ID\n");
	return;

      case NICE_ID_CTR_LEN_8BIT:
	if (!NICEget1(&counter8)) {
	  fprintf(stderr, "8-bit counter data not present\n");
	  return;
	}
	break;

      case NICE_ID_CTR_LEN_16BIT:
	if (!NICEget2(&counter16)) {
	  fprintf(stderr, "16-bit counter data not present\n");
	  return;
	}
	break;

      case NICE_ID_CTR_LEN_32BIT:
	if (!NICEget4(&counter32)) {
	  fprintf(stderr, "32-bit counter data not present\n");
	  return;
	}
	break;
    }

    switch (entry & NICE_ID_CTR_LENGTH) {
      case NICE_ID_CTR_LEN_8BIT:
	if (counter8 == 0xFF)
	  printf("%12s  ", "> 254");
	else printf("%12hhu  ", counter8);
	counter32 = counter8;
	break;

      case NICE_ID_CTR_LEN_16BIT:
	if (counter16 == 0xFFFF)
	  printf("%12s  ", "> 65534");
	else printf("%12hu  ", counter16);
	counter32 = counter16;
	break;

      case NICE_ID_CTR_LEN_32BIT:
	if (counter32 == 0xFFFFFFFF)
	  printf("%12s  ", "> 4294967294");
	else printf("%12u  ", counter32);
	break;
    }

    /*
     * Try to find the text associated with the counter
     */
    while (table->name != NULL) {
      if (table->number == (entry & (NICE_ID_CTR | NICE_ID_CTR_TYPE))) {
	vtable = table->aux;
	break;
      }
      table++;
    }

    if (table->name != NULL)
      printf(table->name);
    else printf("Counter #%u", entry & NICE_ID_CTR_TYPE);

    if (((entry & NICE_ID_CTR_BITMAP) != 0) && (counter32 != 0)) {
      printf(", including:\n");

      if (vtable != NULL) {
	while (vtable->name != NULL) {
	  if ((bitmap & vtable->value) != 0)
	    printf("                %s\n", vtable->name);
	  vtable++;
	}
      } else {
	int i;

	for (i = 0; i < 16; i++)
	  if ((bitmap & (1 << i)) != 0)
	    printf("                Qualifier #%u\n", i);
      }
    }
    printf("\n");
  }
}

static void name_address2Text(
  char *buf
)
{
  uint8_t type, type2;
  uint16_t addr;

  if (NICEget1(&type)) {
    switch (type) {
      case NICE_TYPE_CM(1):
      case NICE_TYPE_CM(2):
	if (NICEget1(&type2)) {
	  if (type2 == NICE_TYPE_DU2) {
	    if (NICEget2(&addr)) {
	      sprintf(buf, "%hu.%hu", (addr >> 10) & 0x3F, addr & 0x3FF);

	      if (type == NICE_TYPE_CM(2)) {
		if (NICEget1(&type2)) {
		  if (type2 == NICE_TYPE_AI) {
		    char length, nodename[NICE_MAXNODEL+1];

		    memset(nodename, 0, sizeof(nodename));
		    if (NICEgetAI(&length, 0xFF, nodename, NICE_MAXNODEL)) {
		      strcat(buf, " (");
		      strcat(buf, nodename);
		      strcat(buf, ")");
		      return;
		    }
		  }
		}
	      }
	    }
	  }
	}
	break;
    }
  }
}

/*
 * The "codedInfo" parameter provided to param2Text() is only used by coded
 *  parameters:
 *
 * 1. Single coded value
 *
 *    In this case, codedInfo is a pointer to a valueTable structure which
 *    is searched for a matching coded value to provide an associated test
 *    string.
 *
 * 2. Multi coded value
 *
 *    In this case, codedInfo points to an array of pointers to strings. The
 *    first string is output after all the component fields have been output.
 *    Subsequent strings are output before each component coded value. If
 *    codedInfo is a NULL pointer a default array of strings is used:
 *	"", "", " ", " ", " " ...
 */
void param2Text(
  void *codedInfo,
  char *buf,
  uint16_t entry
)
{
  uint8_t type;
  uint32_t data = 0;
  uint8_t datalen, value, image[256];
  int i;

  /*
   * Check for parameters which need special formatting.
   */
  switch (entry) {
    case NICE_P_C_CONNNODE:
    case NICE_P_C_ADJNODE:
    case NICE_P_C_DR:
    case NICE_P_N_HOST_RO:
    case NICE_P_N_HOST_WO:
    case NICE_P_N_NEXTNODE:
      /*
       * Format as a node address + optional name
       */
      name_address2Text(buf);
      return;
  }

  if (NICEget1(&type)) {
    if ((type & NICE_TYPE_C) == 0) {
      if ((type & NICE_TYPE_NC_ASCII) == 0) {
	/*
	 * Binary number
	 */
	if (type == NICE_TYPE_NC_BIN_HEX) {
	  /*
	   * Handle hexadecimal image fields specially
	   */
	  if (!NICEget1(&datalen)) {
	    fprintf(stderr, "Missing HI data length\n");
	    return;
	  }
	  for (i = 0; i < datalen; i++) {
	    if (!NICEget1(&value)) {
	      fprintf(stderr, "Missing HI data byte\n");
	      return;
	    }
	    sprintf(&buf[strlen(buf)],
		     "%02X%s", value, i == (datalen - 1) ? "" : "-");
	  }
	} else {
	  if ((datalen = (type & NICE_TYPE_NC_BIN_LEN)) == 0)
	    if (!NICEget1(&datalen)) {
	      fprintf(stderr, "Missing binary number image length\n");
	      return;
	    }
	  if (datalen > 4) {
	    fprintf(stderr, "Binary number size > 4\n");
	    return;
	  }

	  for (i = 0; i < datalen; i++) {
	    if (!NICEget1(&value)) {
	      fprintf(stderr, "Missing binary number data\n");
	      return;
	    }
	    data |= value << (i * 8);
	  }
	  switch (type & NICE_TYPE_NC_BIN_FORMAT) {
	    case NICE_TYPE_NC_BIN_UNS:
	      sprintf(buf, "%u", data);
	      break;

	    case NICE_TYPE_NC_BIN_SIGN:
	      sprintf(buf, "%d", data);
	      break;

	    case NICE_TYPE_NC_BIN_HEX:
	      sprintf(buf, "0x%X", data);
	      break;

	    case NICE_TYPE_NC_BIN_OCT:
	      sprintf(buf, "%o", data);
	      break;
	  }
	}
      } else {
	/*
	 * ASCII image field
	 */
	if (!NICEcopyAI(image, sizeof(image))) {
	  fprintf(stderr, "Malformed ASCII image field\n");
	  return;
	}
	strcat(buf, (char *)image);
      }
    } else {
      if ((type & NICE_TYPE_C_MULTI) == 0) {
        struct valueTable *vtable = codedInfo;

	if ((type & NICE_TYPE_C_SING_BYTES) > 1) {
	  fprintf(stderr, "Single encoded field > 1 byte\n");
	  return;
	}
	if (!NICEget1(&value)) {
	  fprintf(stderr, "Missing single encoded value\n");
	  return;
	}

	if (vtable != NULL) {
	  while (vtable->name != NULL) {
	    if (vtable->value == value)
	      break;
	    vtable++;
	  }
	}

	if ((vtable != NULL) && (vtable->name != NULL))
	  strcat(buf, vtable->name);
	else sprintf(buf, "0x%X", value);
      } else {
	static char *defaultTable[] = {
	  "", "",
	  " ", " ", " ", " ", " ", " ", " ", " ",
	  " ", " ", " ", " ", " ", " ", " ", " ",
	  " ", " ", " ", " ", " ", " ", " ", " ",
	  " ", " ", " ", " ", " ", " ", " "
	};
	char *termin, **table = codedInfo;

	if (table == NULL)
	  table = defaultTable;
	termin = *table++;

	for (i = 0; i < (type & NICE_TYPE_C_MULTI_CNT); i++) {
	  strcat(buf, *table++);
	  param2Text(NULL, &buf[strlen(buf)], entry);
	}
	strcat(buf, termin);
      }
    }
  }
}

void displayParam(
  struct nameTable *table
)
{
  uint16_t entry;
  char buf[128] = "";
  struct valueTable *vtable = NULL;

  if (NICEget2(&entry)) {
    if ((entry & NICE_ID_CTR) != 0) {
      fprintf(stderr, "Counter data ID seen\n");
      return;
    }

    while (table->name != NULL) {
      if (table->number == (entry & NICE_ID_PARAM_TYPE)) {
	vtable = table->aux;
	break;
      }
      table++;
    }

    if (table->name != NULL)
      sprintf(buf, "%-25s= ", table->name);
    else {
      char temp[64];

      sprintf(temp, "Parameter #%hu", entry & NICE_ID_PARAM_TYPE);
      sprintf(buf, "%-25s= ", temp);
    }

    param2Text(vtable, &buf[strlen(buf)], entry);
    printf("%s\n", buf);
  }
}

void showCommand(
  int perm
)
{
  uint8_t option = perm ? NICE_READ_OPT_PERM : 0;
  uint8_t infoType = NICE_READ_OPT_SUM;
  uint32_t result;
  int junk;

  NICEput1(NICE_FC_READ);

  if ((result = tablefind(perm ? &listEntitiesTable : &showEntitiesTable)) != 0) {
    uint8_t entity, format, allowed;
    uint16_t mode;
    char *ident;

    UNPACK4(result, &junk, &allowed, &format, &entity);

    mode = (entity << 8) | format;

    if ((mode == ((NICE_ENT_AREA << 8) | NICE_AFMT_ADDRESS)) ||
        (mode == ((NICE_ENT_LINE << 8) | NICE_SFMT_STRING)) ||
	(mode == ((NICE_ENT_CIRCUIT << 8) | NICE_SFMT_STRING)) ||
	(mode == ((NICE_ENT_NODE << 8) | NICE_NFMT_ADDRESS))) {
      if (idx >= args) {
	fprintf(stderr, "show - missing entity identification\n");
	return;
      }
      ident = wds[idx++];

      if (strlen(ident) > 127) {
	fprintf(stderr, "show - entity identification too long\n");
	return;
      }
    }

    if (idx < args) {
      if ((result = tablefind(&infoTypeTable)) != 0) {
        UNPACK4(result, &junk, &junk, &junk, &infoType);
	if (((1 << ((infoType >> 4) & 0xF)) & allowed) == 0) {
	  fprintf(stderr, "show - invalid information type\n");
	  return;
	}
      } else {
	fprintf(stderr, "show - unknown information type\n");
	return;
      }
    }

    /*
     * Construct the read information message
     */
    NICEput1(option | (infoType & NICE_READ_OPT_TYPE) | (entity & NICE_READ_OPT_ENTITY));

    switch (mode) {
      case (NICE_ENT_AREA << 8) | NICE_AFMT_ADDRESS:
	if (parseArea(ident)) {
	  fprintf(stderr, "Invalid area address\n");
	  return;
	}
	break;

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
      char *prefix, *entype, *optype, daytime[32];
      time_t now = time(NULL);
      struct tm tm;
      uint8_t displayEntity = TRUE;
      uint8_t oneshot = 1;

      localtime_r(&now, &tm);
      strftime(daytime, sizeof(daytime), "%d-%b-%Y %T", &tm);

      NICEflush();

      if ((len = NICEread()) > 0) {
	int8_t code;

	NICEget1((uint8_t *)&code);
	if (code < 0) {
	  cmdError("show/list", code);
	  return;
	}

	/*
	 * Print the header line. We use node identifier formats here but
	 * other entities use similar values.
	 */
	switch (format) {
	  case NICE_NFMT_SIGNIFICANT:
	    prefix = "Known ";
	    break;

	  case NICE_NFMT_ADJACENT:
	    prefix = "Adjacent ";
	    break;

	  case NICE_NFMT_LOOP:
	    prefix = "Loop ";
	    break;

	  case NICE_NFMT_ACTIVE:
	    prefix = "Active ";
	    break;

	  case NICE_NFMT_KNOWN:
	    prefix = "Known ";
	    break;

	  default:
	    prefix = "";
	    break;
	}

	printf("%s%s %s %s as of %s\n\n", prefix, entityName[entity],
		perm ? "Permanent" : "Volatile",
	        optionName[(infoType >> 4) & 0xF], daytime);

	/*
	 * Process a successful response
	 */
	if (code == NICE_RET_ACCEPTED) {
	  uint16_t detail;
	  uint16_t blkno = 0;

	  while (code != NICE_RET_DONE) {
	    if ((len = NICEread()) < 0) {
	      fprintf(stderr, "NICEread() error return (%d)\n", len);
	      return;
	    }

	    NICEget1((uint8_t *)&code);
	    if (code < 0) {
	      cmdError("show/list", code);
	      return;
	    }

	    /*
	     * Skip over the "error detail" and "error message" fields
	     */
	    if (!NICEget2(&detail) || !NICEskipAI())
	      return;

	    (showDispatch[entity])(code, option, infoType, format, displayEntity, blkno == 0, &oneshot);
	    displayEntity = FALSE;
	    blkno++;

	    if (code == NICE_RET_SUCCESS) {
	      displayEntity = TRUE;
	      blkno = 0;
	    }
	  }
	} else (showDispatch[entity])(code, option, infoType, format, displayEntity, 1, &oneshot);
      } else fprintf(stderr, "NICEread() error return (%d)\n", len);
    }
  } else fprintf(stderr, "show - unknown entity\n");
}

