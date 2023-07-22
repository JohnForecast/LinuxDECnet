/******************************************************************************
    (c) 1998-1999 Christine Caulfield               christine.caulfield@googlemail.com
    
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 ******************************************************************************
 */
// rename.cc
// Code for a RENAME task within a FAL server process.
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <syslog.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
#include <glob.h>
#include <regex.h>
#include <string.h>
#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>

#include "logging.h"
#include "connection.h"
#include "protocol.h"
#include "vaxcrc.h"
#include "params.h"
#include "task.h"
#include "server.h"
#include "rename.h"

fal_rename::fal_rename(dap_connection &c, int v, fal_params &p):
    fal_task(c,v,p)
{
}

fal_rename::~fal_rename()
{
}

bool fal_rename::process_message(dap_message *m)
{
    if (verbose > 2) DAPLOG((LOG_DEBUG, "in fal_rename::process_message\n"));

    switch (m->get_type())
    {
    case dap_message::ACCESS:
        {
	    dap_access_message *am = (dap_access_message *)m;

	    // Convert the name if necessary
	    if (is_vms_name(am->get_filespec()))
	    {
		make_unix_filespec(oldname, am->get_filespec());
	    }
	    else
	    {
		strcpy(oldname, am->get_filespec());
		add_vroot(oldname);
	    }
	    display = am->get_display();
	}
	break;

    case dap_message::NAME:
        {
	    char newname[PATH_MAX];

	    dap_name_message *nm = (dap_name_message *)m;
	    if (nm->get_nametype() != dap_name_message::FILESPEC)
	    {
		DAPLOG((LOG_ERR, "Invalid NAME type %d\n", nm->get_nametype()));
		errno = EINVAL;
		return_error();
		return false;
	    }

	    // Convert the name if necessary
	    if (is_vms_name(nm->get_namespec()))
	    {
		make_unix_filespec(newname, nm->get_namespec());
	    }
	    else
	    {
		strcpy(newname, nm->get_namespec());
		add_vroot(oldname);
	    }
	    int status = rename(oldname, newname);

	    if (verbose > 1) 
		DAPLOG((LOG_DEBUG, "fal_rename: from %s to %s, result = %d\n",
			oldname, newname, status));

	    if (status)
	    {
		return_error();
	    }
	    else
	    {
		conn.set_blocked(true);
		dap_ack_message ack;

		// Send old and new names back if the client requested
		// them. 
		if (display & dap_access_message::DISPLAY_NAME_MASK)
		{
		    if (!send_name(oldname)) return false;
		    ack.write(conn);

		    nm->write(conn); // Send original name back
		    ack.write(conn);
		}		    
		dap_accomp_message acc;
		acc.set_cmpfunc(dap_accomp_message::RESPONSE);
		acc.write(conn);
		conn.set_blocked(false);
	    }
        }
	return false;// Finished
    }
    return true;
}

bool fal_rename::send_name(char *name)
{
    dap_name_message name_msg;

    if (vms_format)
    {
	char vmsname[PATH_MAX];
	
	make_vms_filespec(name, vmsname, true);
	
	name_msg.set_namespec(vmsname);
	name_msg.set_nametype(dap_name_message::FILESPEC);
    }
    else
    {
	name_msg.set_namespec(name);
	name_msg.set_nametype(dap_name_message::FILENAME);
    }
    return name_msg.write(conn);
}
