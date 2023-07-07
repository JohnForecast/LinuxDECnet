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
#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>

int verbosity = 0;

extern void process_request(int);

void usage(
  char *prog,
  FILE *f
)
{
  fprintf(f, "\n%s options:\n", prog);
  fprintf(f, " -v        Verbose messages\n");
  fprintf(f, " -h        Display this message\n");
  fprintf(f, " -d        Show debug logging\n");
  fprintf(f, " -V        Show version number\n\n");
}

int main(
  int argc,
  char **argv
)
{
  int debug = 0;
  int insock;
  char opt;

  while ((opt = getopt(argc, argv, "?vVdh")) != EOF) {
    switch (opt) {
      case '?':
      case 'h':
        usage(argv[0], stdout);
        exit(0);

      case 'v':
        verbosity++;
        break;

      case 'd':
        debug++;
        break;

      case 'V':
        printf("\nnml from dnprogs version %s\n\n", VERSION);
        exit(1);
    }
  }

  init_daemon_logging("nml", debug ? 'e' : 's');

  insock = dnet_daemon(DNOBJECT_NICE, NULL, verbosity, !debug);

  if (insock > -1) {
    /*
     * Indicate we are running version 4.0.0 of the NICE protocol
     */
    char ver[] = {4, 0, 0};

    dnet_accept(insock, 0, ver, sizeof(ver));
    process_request(insock);
  }
  return 0;
}
