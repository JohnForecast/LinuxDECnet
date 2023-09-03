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

static  char	nodetag[80],nametag[80],nodeadr[80],nodename[80];
static  char	linetag[80],devicename[80];
/*--------------------------------------------------------------------------*/
char *getexecdev(void)
{
	FILE		*dnhosts;
	char		nodeln[80];

	if ((dnhosts = fopen(SYSCONF_PREFIX "/etc/decnet.conf","r")) == NULL)
	{
		printf("getexecdev: Can not open " SYSCONF_PREFIX "/etc/decnet.conf\n");
		errno = ENOENT;
		return NULL;
	}
	while (fgets(nodeln,80,dnhosts) != NULL)
	{
		sscanf(nodeln,"%s%s%s%s%s%s\n",nodetag,nodeadr,nametag,
		       nodename,linetag,devicename);
		if (strncmp(nodetag,"#",1) != 0)
		{
		   if (((strcmp(nodetag,"executor") != 0) &&
	    	       (strcmp(nodetag,"node")     != 0)) ||
		       (strcmp(nametag,"name")     != 0))
		   {
		       printf("getexecdev: Invalid decnet.conf syntax\n");
		       errno = ENOENT;
		       return NULL;
		   }
		   if (strcmp(linetag,"line") == 0)
		   {
			fclose(dnhosts);
			return devicename;
		    }
		}
	}
	return 0;
}
/*--------------------------------------------------------------------------*/
