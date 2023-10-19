/******************************************************************************
    (c) 1995-1998 E.M. Serrat          emserrat@geocities.com

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
static char             asc_addr[8];
static struct nodeent	dp;
static char   		laddr[2];

struct nodeent *getnodebyaddr_ether(const char *inaddr, int len, int family) {
	struct ether_addr ea = {.ether_addr_octet = {0xAA, 0x00, 0x04, 0x00}};
	int i;

	memcpy((void*)laddr, (void*)inaddr, 2);

	dp.n_addr     = (unsigned char *)&laddr;
	dp.n_length   = 2;
	dp.n_addrtype = AF_DECnet;

	memcpy((void*)&ea.ether_addr_octet[4], (void*)laddr, 2);

	if ( ether_ntohost(nodename, &ea) != 0 )
	    return NULL;

	for (i = 0; nodename[i] != 0; i++) {
	    if ( nodename[i] == '.' ) {
	        nodename[i] = 0;
	        break;
	    }
	}

	dp.n_name = nodename;
	return &dp;
}

struct nodeent *getnodebyaddr(const char *inaddr, int len, int family)
{
	FILE	*dnhosts;
	char	nodeln[80];
	const unsigned char *addr = (const unsigned char *)inaddr;

	sprintf (asc_addr,"%d.%d",((unsigned char)*(addr+1) >> 2),
		 (((unsigned char)*(addr+1) & 0x03) << 8) | ((unsigned char)*(addr))
		);
	
	if ((dnhosts = fopen(SYSCONF_PREFIX "/etc/decnet.conf","r")) == NULL)
	{
		printf("getnodebyaddr: Can not open " SYSCONF_PREFIX "/etc/decnet.conf\n");
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
		       printf("getnodebyaddr: Invalid decnet.conf syntax\n");
			 fclose(dnhosts);
		       return 0;
		   }
		   if (strcmp(nodeadr,asc_addr) == 0) 
		   {
			int i;

			fclose(dnhosts);

                        /*
                         * Convert nodename to upper case
                         */
                        for (i = 0; i < sizeof(nodename); i++) {
                                if (islower(nodename[i]))
                                        nodename[i] = toupper(nodename[i]);
                                if (nodename[i] == '\0')
                                        break;
                        }

			memcpy(laddr,addr,len);
			dp.n_addr=(unsigned char *)&laddr;
			dp.n_length=2;		
			dp.n_name=nodename;		
			dp.n_addrtype=AF_DECnet;
			return &dp;
		   }
		}
	}
	fclose(dnhosts);
	return getnodebyaddr_ether(inaddr, len, family);
}

