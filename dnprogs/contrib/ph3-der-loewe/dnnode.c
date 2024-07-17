//dnnode.c:

/*
    copyright 2008-2010 Philipp 'ph3-der-loewe' Schafft <lion@lion.leolix.org>

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
#include <sys/socket.h>
#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>

char * progname = NULL;

void usage (void) {
 fprintf(stderr, "Usage:\n");
 fprintf(stderr, "%s [OPTIONS] nodename\n", progname);
 fprintf(stderr, "or\n");
 fprintf(stderr, "%s [OPTIONS] nodeaddress\n", progname);
 fprintf(stderr, "\n");
 fprintf(stderr, "Options:\n");
 fprintf(stderr, " -h   --help        this help\n"
                 " -v                 be verbose\n"
                 " -m                 display addresses as MAC address\n"
        );
}

int main (int argc, char * argv[]) {
 int i;
 int verbose   = 0;
 int show_mac  = 0;
 char * k      = NULL;
 char * node   = NULL;
 struct nodeent   * ne;
 int areaa, nodea = -1;
 char addr[2];
 unsigned int mac[6];

 progname = argv[0];

 for (i = 1; i < argc; i++) {
  k = argv[i];
  if ( strcmp(k, "-h") == 0 || strcmp(k, "--help") == 0 ) {
   usage();
   return 0;
  } else if ( strcmp(k, "-v") == 0 ) {
   verbose++;
  } else if ( strcmp(k, "-m") == 0 ) {
   show_mac = 1;
  } else if ( node == NULL ) {
   node = k;
  } else {
   usage();
   return 1;
  }
 }

 if ( node == NULL ) {
  usage();
  return 1;
 }


 if ( sscanf(node, "%i.%i", &areaa, &nodea) != 2 ) {
  if ( sscanf(node, "%X:%X:%X:%X:%X:%X", mac+0, mac+1, mac+2, mac+3, mac+4, mac+5) == 6 ) {
   addr[0] = mac[4];
   addr[1] = mac[5];
   nodea = 0;
  }
 } else {
  addr[1] = (areaa << 2) + ((nodea >> 8) & 0x03);
  addr[0] = nodea & 0xFF;
 }

 if ( nodea != -1 ) {
  if ( (ne = getnodebyaddr(addr, 2, AF_DECnet)) == NULL ) {
   printf("Node %s not found\n", node);
   return 1;
  } else {
   printf("%s has name %s\n", node, ne->n_name);
  }
 } else {
  if ( (ne = getnodebyname(node)) == NULL ) {
   printf("Node %s not found\n", node);
   return 1;
  } else {
   if ( show_mac ) {
    printf("%s has address AA:00:04:00:%.2X:%.2X\n", node, ne->n_addr[0], ne->n_addr[1]);
   } else {
    printf("%s has address %i.%i\n", node, ne->n_addr[1] >> 2, ne->n_addr[0] + ((ne->n_addr[1] & 0x3) << 8));
   }
  }
 }

 return 0;
}

//ll
