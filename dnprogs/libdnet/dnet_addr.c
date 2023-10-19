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
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>

static char             nodetag[80],nametag[80],nodeadr[80],nodename[80];
static struct dn_naddr	binadr = {0x0002,{0x00,0x00}};


struct	dn_naddr	*dnet_addr(char *name)
{

	FILE		*dnhosts;
	char		nodeln[80];
        char            **endptr;
	char		*aux;
	long		area,node;


	if ((dnhosts = fopen(SYSCONF_PREFIX "/etc/decnet.conf","r")) == NULL)
	{
		printf("dnet_addr: Can not open " SYSCONF_PREFIX "/etc/decnet.conf\n");
		errno = ENOENT;
		return NULL;
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
		       printf("dnet_addr: Invalid decnet.conf syntax\n");
		       errno = ENOENT;
		       return 0;
		   }
		   if (strcasecmp(nodename,name) == 0)
		   {
			aux=nodeadr;
			endptr=&aux;
			area=strtol(nodeadr,endptr,0);
			node=strtol(*endptr+1,endptr,0);
			if ((area < 0) || (area > 63) ||
			    (node < 0) || (node > 1023))
			{
				printf("dnet_addr: Invalid address %d.%d\n",
							(int)area,(int)node);
				fclose(dnhosts);
				return 0;
			}
			binadr.a_addr[0] = node & 0xFF;
			binadr.a_addr[1] = (area << 2) | ((node & 0x300) >> 8);
			fclose(dnhosts);
			return &binadr;
		   }
		}
	}
	fclose(dnhosts);
	errno = ENOENT;
	return 0;
}
