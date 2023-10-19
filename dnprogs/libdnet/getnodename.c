/*
 * (C) 1998 Steve Whitehouse
 * (C) 2008 Christine Caulfield, copied code from getnodeadd

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
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>

#include "netdnet/dn.h"

static char             nodetag[80],nametag[80],nodeadr[80],nodename[80];

int getnodename(char *name, size_t len)
{
	FILE		*dnhosts;
	char		nodeln[80];

	if ((dnhosts = fopen(SYSCONF_PREFIX "/etc/decnet.conf","r")) == NULL)
	{
		printf("getnodename: Can not open " SYSCONF_PREFIX "/etc/decnet.conf\n");
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
		       printf("getnodename: Invalid decnet.conf syntax\n");
			 fclose(dnhosts);
		       return 0;
		   }
		   if (strcmp(nodetag,"executor") == 0)
		   {
			int i = 0;

			fclose(dnhosts);

			memset(name, 0, len);
			while ((i <= (len - 1)) && (nodename[i] != '\0')) {
				if (islower(nodename[i]))
					nodename[i] = toupper(nodename[i]);
				name[i] = nodename[i];
				i++;
			}
			return 0;
		   }
		   else
		   {
			   errno = ENOENT;
			   return -1;
		   }
		}
	}

	fclose(dnhosts);
	errno = ENOENT;
	return -1;
}

