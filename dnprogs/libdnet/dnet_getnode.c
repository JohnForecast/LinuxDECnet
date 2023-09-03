/******************************************************************************
    (c) 1999 ChristineCaulfield                 christine.caulfield@googlemail.com

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
#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>

static char             nodetag[80],nametag[80],nodeadr[80],nodename[80];
static char             asc_addr[8];

struct getnode_struct
{
    FILE *fp;
    char node[32];
};
/*--------------------------------------------------------------------------*/
void *dnet_getnode(void)
{
    struct getnode_struct *gs = malloc(sizeof(struct getnode_struct));

    if (!gs) return NULL;

    if ((gs->fp = fopen(SYSCONF_PREFIX "/etc/decnet.conf","r")) == NULL)
    {
	fprintf(stderr, "dnet_getnode: Can not open " SYSCONF_PREFIX "/etc/decnet.conf\n");
	return NULL;
    }
    
    return gs;
}

char *dnet_nextnode(void *g)
{
    struct getnode_struct *gs = (struct getnode_struct *)g;
    char line[256];

    if (feof(gs->fp)) return NULL;
	
 getloop:
    if (fgets(line, sizeof(line), gs->fp))
    {
	char *l = line + strspn(line, " \t"); // Span blanks
	if (l[0] == '#') goto getloop;
	    
	if (sscanf(line,"%s%s%s%s\n",nodetag,nodeadr,nametag,nodename) != 4) goto getloop;

	strcpy(gs->node, nodename);
	return gs->node;
    }
    else
    {
	return NULL;
    }
}

void dnet_endnode(void *g)
{
    struct getnode_struct *gs = (struct getnode_struct *)g;
    fclose(gs->fp);
    free(gs);
}

