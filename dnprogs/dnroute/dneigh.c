//dneigh.c:

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

#include <sys/un.h>

#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>
#include <netinet/ether.h>

#include <net/if.h>
#include <sys/ioctl.h>

#include <signal.h>

#define DNN_FILE  "/proc/net/decnet_neigh"
#define DNRP_FILE "/var/run/dnroute.pid"
#define DNRS_FILE "/var/run/dnroute.status"

char * progname = NULL;
int numeric = 0;

void usage (void) {
 fprintf(stderr, "Usage: %s [OPTIONS]\n", progname);
 fprintf(stderr, "\n");
 fprintf(stderr, "Options:\n");
 fprintf(stderr, " -h   --help        this help\n"
                 "      --dneigh      force dneigh behavor\n"
                 "      --dnetinfo    force dnetinfo behavor\n"
                 " -n                 numerical mode (do not show node names but addresses)\n"
        );
}

char * get_node_name (char * address) {
 struct nodeent * ne;

 if ( numeric )
  return address;

 if ( (ne = getnodebyname(address)) != NULL )
  if ( (ne = getnodebyaddr((const char *)ne->n_addr, ne->n_length, ne->n_addrtype)) != NULL )
   return ne->n_name;

 return address;
}

char * get_hwtype (char * dev) {
 int sock;
 struct ifreq ifr;
 int type = -1;

 if ( (sock = socket(AF_UNIX, SOCK_STREAM, 0)) != -1 ) {
  strcpy(ifr.ifr_name, dev);

  if ( ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
   type = ifr.ifr_hwaddr.sa_family;

  close(sock);
 }

 switch (type) {
  // supported by current kernel:
  case ARPHRD_ETHER:    return "ether";
  case ARPHRD_LOOPBACK: return "loop";
  case ARPHRD_IPGRE:    return "ipgre";
  case ARPHRD_DDCMP:    return "ddcmp";

  // support is commented out in the kernel (why?):
  case ARPHRD_X25:      return "x25";
  case ARPHRD_PPP:      return "ppp";
 }

 return "?";
}

int proc_file (FILE * fh) {
 char buf[128];
 char flags[8];
 char dev[32];
 char hwa[32];
 int state;
 int use;
 int blocksize;
 int area, node;

 if ( fgets(buf, sizeof(buf), fh) == NULL ) {
  fprintf(stderr, "Error: can not read banner from file\n");
  return -1;
 }

 if ( strcmp(buf, "Addr    Flags State Use Blksize Dev\n") != 0 ) {
  fprintf(stderr, "Error: invalid file format\n");
  return -1;
 }

 while (fscanf(fh, "%s %s %02d    %02d  %07d %s %s\n",
                   buf, flags, &state, &use, &blocksize, dev, hwa
                   ) == 7) {
  if ( sscanf(buf, "%d.%d", &area, &node) == 2 ) {
    printf("%-24s %-7s %-19s %-6s %-10i %s\n", get_node_name(buf), get_hwtype(dev), hwa, flags, blocksize, dev);
  }
 }

 return 0;
}

int cat (FILE * fh) {
 char buf[1024];
 int len;

 while ((len = fread(buf, 1, sizeof(buf), fh))) {
  fwrite(buf, 1, len, stdout);
 }

 return 0;
}

FILE * connect_unix (char * file) {
 int fh;
 struct sockaddr_un  un = {AF_UNIX};

 errno = 0;

 if ( (fh = socket(AF_UNIX, SOCK_STREAM, 0)) == -1 ) {
  return NULL;
 }

 strncpy(un.sun_path, file, sizeof(un.sun_path) - 1);

 if ( connect(fh, (struct sockaddr *)&un, sizeof(struct sockaddr_un)) == -1 ) {
  close(fh);
  return NULL;
 }

 return fdopen(fh, "rw");
}

int main (int argc, char * argv[]) {
 FILE * fh = NULL;
 int i;
 char * k;
 char * file = DNN_FILE;
 int dnetinfo = 0; // 1 = forced dnetinfo, -1 = forced dneigh
 char pid[8];
 struct stat st;

 progname = argv[0];

 for (i = 1; i < argc; i++) {
  k = argv[i];
  if ( strcmp(k, "-n") == 0 ) {
   numeric  = 1;
  } else if ( strcmp(k, "--dneigh") == 0 || strcmp(k, "-l") == 0 ) {
   dnetinfo = -1;
  } else if ( strcmp(k, "--dnetinfo") == 0 ) {
   dnetinfo =  1;
  } else if ( strcmp(k, "-h") == 0 || strcmp(k, "--help") == 0 ) {
   usage();
   return 0;
  } else {
   fprintf(stderr, "Error: unknown parameter %s\n", k);
   usage();
   return 1;
  }
 }

 // are we dnetinfo?
 if ( dnetinfo != -1 ) {
  i = strlen(progname);
  if ( i >= 8 ) {
   if ( strcmp(progname+i-8, "dnetinfo") == 0 ) {
    dnetinfo = 1;
   }
  }
 }

 // is dnroute running?
 if ( dnetinfo == 1 ) {
  if ( (fh = fopen(DNRP_FILE, "r")) != NULL ) {
   *pid = 0;
   fgets(pid, 8, fh);
   dnetinfo = atoi(pid);
   fclose(fh);
  } else {
   dnetinfo = 0;
  }
 }

 // if this is true, than we just should dump the dnroute's data
 if ( dnetinfo > 0 ) {
  if ( stat(DNRS_FILE, &st) == -1 ) { // socket for fifo?
   fprintf(stderr, "Error: can not stat dnroute info file: %s: %s\n", DNRS_FILE, strerror(errno));
   return 1;
  }

  if ( S_ISFIFO(st.st_mode) ) {        // fifo: old interface
   if ( kill(dnetinfo, SIGUSR1) ) {
    if ( errno != ESRCH ) {
     fprintf(stderr, "Error: can not send signal to dnroute: %s\n", strerror(errno));
     return 1;
    } // else we continue in dneigh mode
   } else fh = fopen(DNRS_FILE, "r");
  } else {                            // socket: new interface
   fh = connect_unix(DNRS_FILE);
//  fprintf(stderr, "Error: can not create new UNIX Domain Socket: %s\n", strerror(errno));
  }
  if ( fh != NULL ) {
   cat(fh);
   fclose(fh);
   return 0;
  }
 }

 if ( (fh = fopen(file, "r")) == NULL ) {
  fprintf(stderr, "Error: can not open DECnet neigh file: %s: %s\n", file, strerror(errno));
  return 2;
 }

 printf("Node                     HWtype  Next-Hop            Flags  MTU        Iface\n");
 proc_file(fh);

 fclose(fh);
 return 0;
}

//ll
