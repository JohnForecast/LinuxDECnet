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
#include <sys/stat.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>

#include "ncp.h"
#include "nice.h"
#include "node.h"

#define DECNET_CONF	"/etc/decnet.conf"
#define DECNET_TEMP	"/etc/decnet_XXXXXX"

void copyCommand(void)
{
  uint32_t result;
  char *status;
  uint8_t option = 0;
  uint16_t addr;
  char executor[100], tempname[sizeof(DECNET_TEMP) + 1];
  FILE *fp;

  if (tellvalid) {
    fprintf(stderr, "copy cannot be used with a \"tell\" prefix\n");
    return;
  }

  /*
   * Extract the "executor" line form the current configuration - we will
   * keep it the same.
   */
  if ((fp = fopen(DECNET_CONF, "r")) != NULL) {
    int found = 0;

    while (fgets(executor, sizeof(executor), fp) != NULL) {
      if (executor[0] != '#') {
        char nodetag[16], nodeadr[16], nametag[16], nodename[16];
        char linetag[16], devicename[16];

	sscanf(executor, "%s%s%s%s%s%s\n",
	        nodetag, nodeadr, nametag, nodename, linetag, devicename);

	if (strcmp(nodetag, "executor") == 0) {
	  uint16_t area, node;

	  found = 1;
	  sscanf(nodeadr, "%hu.%hu", &area, &node);
	  addr = (area << 10) | node;
	  break;
        }
      }
    }
    fclose(fp);

    if (!found) {
      fprintf(stderr, "Unable to find \"executor\" line in " DECNET_CONF "\n");
      return;
    }
  } else {
    fprintf(stderr, "Unable to open \"" DECNET_CONF "\"\n");
    return;
  }
  
  if ((result = tablefind(&copyEntitiesTable)) != 0) {
    /*
     * Parse the node name or address.
     */
    if (idx < args) {
      if ((status = parseForTell()) != NULL) {
	fprintf(stderr, "copy - %s\n", status);
	return;
      }
    } else {
      fprintf(stderr, "Missing node name or address\n");
      return;
    }

    /*
     * Are there at least 2 more words on the command line?
     */
    if ((idx + 1) < args) {
      if (vmatch(wds[idx], "using")) {
	idx++;
	if (vmatch(wds[idx], "volatile")) {
	  idx++;
	} else {
	  if (vmatch(wds[idx], "permanent")) {
	    option = NICE_READ_OPT_PERM;
	    idx++;
	  }
	}
      }
    }

    if (idx < args) {
      fprintf(stderr, "copy - extra characaters at end of command\n");
      return;
    }

    /*
     * Build a "show/list known nodes summary" message to send to the
     * remote node.
     */
    NICEput1(NICE_FC_READ);
    NICEput1(option | NICE_READ_OPT_SUM | NICE_ENT_NODE);
    NICEput1(NICE_NFMT_KNOWN);

    if (netConnect() >= 0) {
      int len, status;
      int8_t code;

      NICEflush();

      if ((len = NICEread()) > 0) {
	NICEget1((uint8_t *)&code);
	if (code < 0) {
	  cmdError("copy", code, NULL);
	  return;
	}
      }

      /*
       * Process a successful response
       */
      if (code == NICE_RET_ACCEPTED) {
	int fd;
        uint16_t detail;

	strcpy(tempname, DECNET_TEMP);

	if ((fd = mkstemp(tempname)) == -1) {
	  fprintf(stderr, "Unable to create temporary file\n");
	  return;
	}

	if ((fp = fdopen(fd, "w")) == NULL) {
	  fprintf(stderr, "Error opening temporary file\n");
	  unlink(tempname);
	  close(fd);
	  return;
	}

	fputs("#V001.0\n", fp);
	fputs("#               DECnet hosts file\n", fp);
	fputs("#\n", fp);
	fputs("#Node           Node            Name            Node    Line    Line\n", fp);
	fputs("#Type           Address         Tag             Name    Tag     Device\n", fp);
	fputs("#-----          -------         -----           -----   -----   ------\n", fp);
	fputs(executor, fp);

	while (code != NICE_RET_DONE) {
	  uint16_t nodeaddress;
	  char length, nodename[NICE_MAXNODEL+1];

	  if ((len = NICEread()) < 0) {
	    fprintf(stderr, "NICEread error return (%d)\n", len);
	    fclose(fp);
	    return;
	  }

	  NICEget1((uint8_t *)&code);

	  if (code == NICE_RET_DONE)
	    break;

	  if (code < 0) {
	    cmdError("copy", code, NULL);
	    fclose(fp);
	    return;
	  }

	  /*
	   * Skip over the "error detail" and "error message" fields
	   */
	  if (!NICEget2(&detail) || !NICEskipAI()) {
	    fclose(fp);
	    return;
	  }

	  memset(nodename, 0, sizeof(nodename));

	  if (NICEget2(&nodeaddress)) {
	    if (NICEgetAI(&length, 0x7F, nodename, NICE_MAXNODEL)) {
	      length &= ~0x80;

	      if ((length != 0) && (addr != nodeaddress)) {
		char naddr[16];

		sprintf(naddr, "%u.%u",
			(nodeaddress >> 10) & 0x3F, nodeaddress & 0x3FF);
		fprintf(fp, "node             %-15sname            %s\n",
			 naddr, nodename);
	      }
	    }
	  }
	}
	fchmod(fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	fclose(fp);

	/*
	 * Move the new file into the correct location
	 */
	if (rename(tempname, DECNET_CONF) == -1) {
	  perror("Failed to update " DECNET_CONF);
	  fprintf(stderr, "Temporary file left as %s\n", tempname);
	}
      } else fprintf(stderr, "Unexpected command status (%d)\n", code);
    } 
  } else fprintf(stderr, "copy - invalid command format\n");
}


