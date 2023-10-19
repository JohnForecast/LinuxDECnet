/******************************************************************************
    (c) 1995-1998 E.M. Serrat          emserrat@geocities.com
    (c) 1999      Christine Caulfield       christine.caulfield@googlemail.com

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>

#ifdef __NetBSD__
#include <net/if.h>
#include <net/if_ether.h>
#elif defined(__FreeBSD__)
#include <net/ethernet.h>
#define ether_addr_octet octet
#else
#include <netinet/ether.h>
#endif

static char             nodetag[80],nametag[80],nodeadr[80],nodename[80];
static struct nodeent	dp;
static struct dn_naddr	*naddr;

#define RESOLV_CONF "/etc/resolv.conf"

struct nodeent *getnodebyname_ether(const char *name) {
	static char search[3][32] = {{0}, {0}, {0}};
	static int  search_len    =   0;
	FILE * conf;
	int i;
	static struct ether_addr ea;
	u_int8_t decnet_prefix[4] = {0xAA, 0x00, 0x04, 0x00};

	memset((void*)&ea, 0, sizeof(ea));

	if ( !search_len ) {
	    if ( (conf = fopen(RESOLV_CONF, "r")) != NULL ) {
	        while (fgets(nodetag, 80, conf) != NULL) {
	            if ( strncmp(nodetag, "search ", 7) == 0 ) {
	                if ( (search_len = sscanf(nodetag, "search %s%s%s\n", search[0], search[0], search[3])) )
	                    break;
	            }
	        }
	        fclose(conf);
	    }
	}

	dp.n_addrtype = AF_DECnet;
	dp.n_length   = 2;
	dp.n_name     = (char*)name;

	if ( ether_hostton(name, &ea) == 0 ) {
	    if ( memcmp(ea.ether_addr_octet, decnet_prefix, 4) == 0 ) {
	        dp.n_addr=(unsigned char *)&ea.ether_addr_octet[4];
	        return &dp;
	    }
	}

	for(i = 0; i < search_len; i++) {
	    sprintf(nodename, "%s.%s", name, search[i]);


	    if ( ether_hostton(nodename, &ea) == 0 ) {
	        if ( memcmp(ea.ether_addr_octet, decnet_prefix, 4) == 0 ) {
	            dp.n_addr=(unsigned char *)&ea.ether_addr_octet[4];
	            return &dp;
	        }
	    }
	}

	return NULL;
}

struct nodeent *getnodebyname(const char *name)
{
	FILE		*dnhosts;
	char		nodeln[80];
	int             i,a,n,ae,ne,na;

	/* See if it is an address really */

	n = strlen(name);
	na = 1;
	for (i=0; i<n; i++)
	{
		if (isalpha(name[i]))
		{
		    na = 0;
		    break;
		} else if (na && name[i]=='.') na = 2;
	}

	if (na==1)
	{
		a = 0;
		na = sscanf(name, "%d", &n) + 1;
	} else if (na==2) {
		na = sscanf(name, "%d.%d", &a, &n);
	}

	if ((dnhosts = fopen(SYSCONF_PREFIX "/etc/decnet.conf","r")) == NULL)
	{
		printf("getnodebyname: Can not open " SYSCONF_PREFIX "/etc/decnet.conf\n");
		return 0;
	}
	while (fgets(nodeln,80,dnhosts) != NULL)
	{
		sscanf(nodeln,"%s%s%s%s\n",nodetag,nodeadr,nametag,nodename);
		if (strncmp(nodetag,"#",1) != 0)	
		{
		   if (((strcmp(nodetag,"executor") != 0) &&
	    	       (strcmp(nodetag,"node")     != 0)) ||
		       (strcmp(nametag,"name")     != 0))
		   {
		       printf("getnodebyname: Invalid decnet.conf syntax\n");
			 fclose(dnhosts);
		       return 0;
		   }

		   if (na==2) {
		       static struct dn_naddr addr;
		       na = sscanf(nodeadr, "%d.%d", &ae, &ne);
		       if (a==0) a = ae;
		       if (n==0) n = ne;
		       addr.a_addr[0] = n & 0xFF;
		       addr.a_addr[1] = (a << 2) | ((n & 0x300) >> 8);
		       dp.n_addr = (unsigned char *)&addr.a_addr;
		       dp.n_length=2;
		       dp.n_name=(char *)name;  /* No point looking this up for a real name */
		       dp.n_addrtype=AF_DECnet;

		       return &dp;
		   }

		   if (strcasecmp(nodename,name) == 0) 
		   {
			int i;

			fclose(dnhosts);
			if ( (naddr=dnet_addr(nodename)) == 0)
					return 0;

			/*
			 * Convert nodename to upper case
			 */
			for (i = 0; i < sizeof(nodename); i++) {
				if (islower(nodename[i]))
					nodename[i] = toupper(nodename[i]);
				if (nodename[i] == '\0')
					break;
			}

			dp.n_addr=(unsigned char *)&naddr->a_addr; 
			dp.n_length=2;
			dp.n_name=nodename;		
			dp.n_addrtype=AF_DECnet;
			return &dp;
		   }
		}
	}
	fclose(dnhosts);
	return getnodebyname_ether(name);
}
/*--------------------------------------------------------------------------*/
