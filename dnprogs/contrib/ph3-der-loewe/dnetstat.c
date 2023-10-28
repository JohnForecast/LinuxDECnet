//dnetstat.c:

/*
    copyright 2008 Philipp 'ph3-der-loewe' Schafft <lion@lion.leolix.org>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    version 3.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
*/

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>

#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>

#include <netdb.h>

#define DNNS_FILE "/proc/net/decnet"

struct dn_nse {
 char node[8];
 char object[32];
};

char * progname = NULL;
int numeric = 0;

void usage (void) {
 fprintf(stderr, "Usage: %s [OPTIONS]\n", progname);
 fprintf(stderr, "\n");
 fprintf(stderr, "Options:\n");
 fprintf(stderr, " -h   --help        this help\n"
                 " -n                 numerical mode (do not show node names but addresses)\n"
        );
}

char * object_name(char *number) {
 int objnum = atoi(number);
 static char name[16];

 if (numeric)
  return number;

 if ( objnum )
  if ( getobjectbynumber(objnum, name, 16) != -1 )
   return name;

 return number;
}

int prep_addr (char * buf, char * object) {
 struct nodeent * ne;

 *index(buf, '/') = 0;

  if ( strcmp(buf, "0.0") == 0 && ! numeric ) {
   strcpy(buf, "*");
  } else if ( !numeric ) {
   if ( (ne = getnodebyname(buf)) != NULL ) {
    if ( (ne = getnodebyaddr((const char *)ne->n_addr, ne->n_length, ne->n_addrtype)) != NULL ) {
     strcpy(buf, ne->n_name);
    }
   }
  }

 strcat(buf, "::");

 if ( strcmp(object, "0") == 0 && ! numeric ) {
  strcat(buf, "*");
 } else {
  strcat(buf, object_name(object));
 }
 return 0;
}

char * state_ktou (char * state, char ** dir) {

 if ( strcmp(state, "OPEN") == 0 ) {
  *dir = "IN";
  return "LISTEN";
 } else if ( strcmp(state, "RUN") == 0 ) {
  return "ESTABLISHED";
 } else if ( strcmp(state, "RJ") == 0 ) {
  *dir = "OUT";
  return "REJECTED";
 } else if ( strcmp(state, "DN") == 0 ) {
  return "DISCNOTIFY";
 } else if ( strcmp(state, "DIC") == 0 ) {
  return "DISCONNECTED";
 } else if ( strcmp(state, "DI") == 0 ) {
  return "DISCONNECTING";
 } else if ( strcmp(state, "DR") == 0 ) {
  return "DISCONREJECT";
 } else if ( strcmp(state, "DRC") == 0 ) {
  return "DISCONREJCOMP";
 } else if ( strcmp(state, "CL") == 0 ) {
  return "CLOSED";
 } else if ( strcmp(state, "CN") == 0 ) {
  return "CLOSEDNOTIFY";
 } else if ( strcmp(state, "CI") == 0 ) {
  *dir = "OUT";
  return "CONNECTING";
 } else if ( strcmp(state, "NR") == 0 ) {
  return "NORES";
 } else if ( strcmp(state, "NC") == 0 ) {
  return "NOCOM";
 } else if ( strcmp(state, "CC") == 0 ) {
  return "CONCONFIRM";
 } else if ( strcmp(state, "CD") == 0 ) {
  return "CONDELIVERY";
 } else if ( strcmp(state, "CR") == 0 ) {
  return "CONNECTRECV";
 }

 return state;
}

int proc_file (FILE * fh) {
 struct dn_nse local, remote;
 char state[32], immed[32];
 char buf[1024];
 char out[2048] = {0}, * outdir = out+57;
 char conid[8] = {0,0,0,0,0,0,0,0}, *lid, *rid;
 char * lbuf = buf, * rbuf = buf + 512;
 char * dir = ""; // max be "UNI" or "BI", "IN", "OUT"
 char * sta;
 int unused;

 if ( fgets(buf, 1024, fh) == NULL ) {
  fprintf(stderr, "Error: can not read banner from file\n");
  return -1;
 }

 if ( strcmp(buf, "Local                                              Remote\n") != 0 ) {
  fprintf(stderr, "Error: invalid file format\n");
  return -1;
 }

 while (fscanf(fh, "%s %04d:%04d %04d:%04d %01d %16s"
                   "%s %04d:%04d %04d:%04d %01d %16s"
                   "%4s %s\n",
                   lbuf, &unused, &unused, &unused, &unused, &unused, local.object,
                   rbuf, &unused, &unused, &unused, &unused, &unused, remote.object,
                   state, immed
                   ) == 16) {
  lid = index(lbuf, '/') + 1;
  rid = index(rbuf, '/') + 1;

  if ( memcmp(lid, conid+4, 4) == 0 && memcmp(rid, conid, 4) == 0 && strcmp(state, "OPEN") != 0 ) {
   if ( *out ) {
    memcpy(outdir, "LOC", 3);
    puts(out);
    *out = 0;
    continue;
   }
  }

  if ( *out )
   puts(out);

  memcpy(conid,   lid, 4);
  memcpy(conid+4, rid, 4);


  prep_addr(lbuf, local.object);
  prep_addr(rbuf, remote.object);

  dir = "";

  if ( strcmp(state, "OPEN") != 0 ) {
   immed[0] = 0;
  }

  sta = state_ktou(state, &dir);
  sprintf(out, "decnet local:  %-24s %-3s %-13s %s", lbuf, dir, sta, immed);
  puts(out);
  sprintf(out, "       remote: %-24s", rbuf);
 }
 puts(out);

 return 0;
}

int main (int argc, char * argv[]) {
 FILE * fh = NULL;
 int i;
 char * k;
 char * file = DNNS_FILE;

 progname = argv[0];

 for (i = 1; i < argc; i++) {
  k = argv[i];
  if ( strcmp(k, "-n") == 0 ) {
   numeric = 1;
  } else if ( strcmp(k, "-h") == 0 || strcmp(k, "--help") == 0 ) {
   usage();
   return 0;
  } else {
   fprintf(stderr, "Error: unknown parameter %s\n", k);
   usage();
   return 1;
  }
 }

 if ( (fh = fopen(file, "r")) == NULL ) {
  fprintf(stderr, "Error: can not open DECnet netstat file: %s: %s\n", file, strerror(errno));
  return 2;
 }

//      |Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
//      |decnet *::29                    *::0                         LISTEN       IMMED
 printf("Active DECnet sockets (servers and established)\n");
 printf("Proto  Local/Remote Addresses           Dir State         Accept mode\n");
 proc_file(fh);

 fclose(fh);

 return 0;
}

//ll
