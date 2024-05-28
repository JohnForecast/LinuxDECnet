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

#define MIN(a, b)	((a) < (b) ? (a) : (b))
#define MAX(a, b)	((a) > (b) ? (a) : (b))

#define MATCH_MINLEN	3
#define MAX_WDS		512
char *wds[MAX_WDS + 1];
int idx, args;

int done = 0;

extern void showCommand(int), zeroCommand(void), copyCommand(void),
	     loopCommand(void);

static char *fileerror[] = {
  "Permanent database",
  "Load file",
  "Dump file",
  "Secondary loader",
  "Tertiary loader",
  "Secondary dumper",
  "Volatile database",
  "Diagnostic file"
};

static char *mirrorerror[] = {
  "No node name set",
  "Invalid node name format",
  "Unrecognized node name",
  "Node unreachable",
  "Network resources",
  "Rejected by object",
  "Invalid object name format",
  "Unrecognized object",
  "Access control reject",
  "Object too busy",
  "No response from object",
  "Remote node shut down",
  "Node or object failed",
  "Disconnect by object",
  "Abort by object",
  "Abort by management",
  "Local node shut down"
};

void cmdError(
  char *cmd,
  int8_t code,
  struct paramTable *params
)
{
  char *error = NULL, *error2 = NULL, errorText[64];
  int16_t detail = 0;
  uint8_t msg[256];

  msg[0] = '\0';

  /*
   * Retrieve optional error arguments
   */
  if (NICEget2((uint16_t *)&detail))
    NICEcopyAI(msg, sizeof(msg));

  switch (code) {
    case NICE_RET_UNRECOG:
      error = "Unrecognized function or option";
      break;

    case NICE_RET_INVALID:
      error = "Invalid message format";
      break;

    case NICE_RET_PRIV:
      error = "Privilege violation";
      break;

    case NICE_RET_OVERSIZE:
      error = "Oversized management command message";
      break;

    case NICE_RET_PROGERR:
      error = "Management program error";
      break;

    case NICE_RET_BADPARAM:
      error = "Unrecognized parameter type";

param_error:
      if ((detail != 0) && (detail != 65535)) {
	if (params != NULL) {
	  uint32_t i;

	  for (i = 0; i < params->count; i++)
	    if (params->entries[i].id == detail) {
	      error2 = params->entries[i].words;
	      goto param_done;
	    }
	}
	error2 = errorText;
	sprintf(errorText, "Parameter #%u", detail);
      }
param_done:
      break;

    case NICE_RET_BADVERSION:
      error = "Incompatible management version";
      break;

    case NICE_RET_BADCOMPONENT:
      error = "Unrecognized component";
      break;

    case NICE_RET_BADID:
      error = "Invalid identification";
      break;

    case NICE_RET_COMMFAIL:
      error = "Line communication error";
      break;

    case NICE_RET_BADSTATE:
      error = "Component in wrong state";
      break;

    case NICE_RET_OPENERR:
      error = "File open error";

  file_error:
      if (detail != 0xFFFF) {
	if ((detail >= NICE_DETAIL_PERMDB) && (detail <= NICE_DETAIL_DIAG))
	  error2 = fileerror[detail];
	else {
	  error2 = errorText;
	  sprintf(errorText, "Detail code = %d)", detail);
	}
      }
      break;

    case NICE_RET_BADDATA:
      error = "Invalid file contents";
      goto file_error;

    case NICE_RET_RESERR:
      error = "Resource error";
      break;

    case NICE_RET_BADVALUE:
      error = "Invalid parameter value";
      goto param_error;

    case NICE_RET_PROTOERR:
      error = "Line protocol error";
      break;

    case NICE_RET_IOERROR:
      error = "File I/O error";
      break;

    case NICE_RET_DISCONNECT:
      error = "Mirror link disconnected";

  mirror_error:
      if (detail != 0xFFFF) {
	if ((detail >= NICE_DETAIL_NONAME) && (detail <= NICE_DETAIL_LOC_SHUTDN))
	  error2 = mirrorerror[detail];
	else {
	  error2 = errorText;
	  sprintf(errorText, "Detail code = %d)", detail);
	}
      }
      break;

    case NICE_RET_NOROOM:
      error = "No room for new entry";
      break;

    case NICE_RET_CONNECTERR:
      error = "Mirror connect failed";
      goto mirror_error;

    case NICE_RET_NOTAPPLIC:
      error = "Parameter not applicable";
      goto param_error;

    case NICE_RET_TOOLONG:
      error = "Parameter value too long";
      goto param_error;

    case NICE_RET_HWFAIL:
      error = "Hardware failure";
      break;

    case NICE_RET_OPFAIL:
      error = "Operation failure";
      break;

    case NICE_RET_SYSUNSUPP:
      error = "System-specific management function not supported";
      break;

    case NICE_RET_INVGROUP:
      error = "Invalid parameter grouping";
      break;

    case NICE_RET_BADRESPONSE:
      error = "Bad loopback response";
      break;

    case NICE_RET_MISSING:
      error = "Parameter missing";
      goto param_error;

    case NICE_RET_DONE:
      return;
  }

  if (error) {
    if (error2)
      fprintf(stderr, "%s - %s (%s)\n", cmd, error, error2);
    else fprintf(stderr, "%s - %s\n", cmd, error);
  } else fprintf(stderr, "%s - Unknown error code \"%d\"\n", cmd, code);

  if (*msg)
    fprintf(stderr, "%s\n", (char *)msg);
}

int vmatch(
  char *word,
  char *cmd
)
{
  int wordlen = strlen(word), cmdlen = strlen(cmd);

  if ((wordlen <= cmdlen) && (wordlen >= MATCH_MINLEN)) {
    if (strncmp(word, cmd, MIN(wordlen, cmdlen)) == 0)
      return 0;
  }
  return -1;
}

uint32_t tablefind(
  struct table *table
)
{
  int i;

  for (i = 0; i < table->count; i++) {
    int offset = 0;
    char *match = table->entries[i].words;

    do {
      /*
       * Make sure we don't match past the end of line.
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
    return table->entries[i].value;

nomatch:
    continue;
  }
  return 0;
}


static void process(void)
{
  uint32_t cmd;
  char *status;

  NICEinit();

  idx = 0;

  if (vmatch(wds[idx], "tell") == 0) {
    idx++;

    if (idx < args) {
      if ((status = parseForTell()) != NULL) {
	fprintf(stderr, "tell - %s\n", status);
        return;
      }
    } else {
      fprintf(stderr, "Missing node name or address\n");
      return;
    }
  }

  if (idx < args) {
    if ((cmd = tablefind(&commandTable)) != 0) {

      /*
       * Dispatch to command processing routine
       */
      switch (cmd) {
	case CMD_COPY:
	  copyCommand();
	  break;

	case CMD_EXIT:
	  done = 1;
	  return;

	case CMD_LIST:
	  showCommand(1);
	  break;

	case CMD_SHOW:
	  showCommand(0);
	  break;

	case CMD_ZERO:
	  zeroCommand();
	  break;

	case CMD_LOOP:
	  loopCommand();
	  break;

	default:
	  break;
      }

      /*
       * Clean up any socket used
       */
      NICEclose();
    } else fprintf(stderr, "Unknown command \'%s\'\n", wds[idx]);
  } else fprintf(stderr, "No command provided\n");
}

static int parse(
  char *in
)
{
  char quote, **words;

  words = wds;
  args = 0;

  /*
   * Split the command line into individual words
   */
  while (*in != '\0') {
    if (args >= MAX_WDS) {
      fprintf(stderr, "Too many command words\n");
      return -1;
    }

    switch (*in) {
      case ' ':
      case '\t':
	in++;
	continue;

      case '\'':
      case '\"':
	quote = *in++;
	words[args++] = in;
	while (*in != quote) {
	  if (*in == '\0') {
	    fprintf(stderr, "Missing terminating string quote - %c%s\n",
		     quote, words[args - 1]);
	    return -1;
	  }
	  in++;
	}
	*in++ = '\0';
	break;

      default:
	words[args++] = in++;
	while ((*in != ' ') && (*in != '\t') && (*in != '\0'))
	  in++;

	if (*in != '\0')
	  *in++ = '\0';
	break;
    }
  }
  return 0;
}

int main(
  int argc,
  char **argv
)
{
  char *buf;

  optind = 1;

  if (argc > 1) {
    int i;

    for (i = 1, args = 0; i < argc; i++)
      wds[args++] = argv[i];

    process();
    return 0;
  }

  while (!done) {
    if ((buf = readline("NCP> ")) == NULL)
      break;

    /*
     * Don't add empty lines to history
     */
    if (*buf)
      add_history(buf);

    if (parse(buf) == 0) {
      process();
    }
    free(buf);
  }
  return 0;
}

