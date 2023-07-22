/******************************************************************************
    (c) 1998-2000 Christine Caulfield               christine.caulfield@googlemail.com

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
// submit.cc
// Code for a SUBMIT  task within a FAL server process.
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
#include "submit.h"

#ifndef SUBMIT_COMMAND
#define SUBMIT_COMMAND "at -f %s now "
#endif


fal_submit::fal_submit(dap_connection &c, int v, fal_params &p):
    fal_task(c,v,p)
{
}

fal_submit::~fal_submit()
{
}

bool fal_submit::process_message(dap_message *m)
{
    if (verbose > 2) DAPLOG((LOG_DEBUG, "in fal_submit::process_message\n"));

    switch (m->get_type())
    {
    case dap_message::ACCESS:
        {
	    glob_t gl;
	    int    status;
	    int    pathno = 0;
	    char   unixname[PATH_MAX];

	    dap_access_message *am = (dap_access_message *)m;

	    // Convert the name if necessary
	    if (is_vms_name(am->get_filespec()))
	    {
		make_unix_filespec(unixname, am->get_filespec());
	    }
	    else
	    {
		strcpy(unixname, am->get_filespec());
		add_vroot(unixname);
	    }

	    // Create the list of files
	    status = glob(unixname, 0, NULL, &gl);
	    if (status)
	    {
		// glob does not return errno codes
		switch (status)
		{
		case GLOB_NOSPACE:
		    return_error(ENOMEM);
		    break;
#ifdef GLOB_ABORTED
		case GLOB_ABORTED:
#else
		case GLOB_ABEND:
#endif
		    return_error(EIO);
		    break;
#ifdef GLOB_NOMATCH
		case GLOB_NOMATCH:
		    return_error(ENOENT);
		    break;
#endif
		default:
		    return_error();
		    break;
		}
		return false;
	    }
	    conn.set_blocked(true);

	    if (gl.gl_pathc == 1)
	    {
	        if (!send_file_attributes(gl.gl_pathv[0], am->get_display(),
					  SEND_DEV))
		{
		    return_error();
		    return false;
		}
	    }

	    // Submit all the files
	    do
	    {
	        char cmd[PATH_MAX + strlen(SUBMIT_COMMAND)+1];

		sprintf(cmd, SUBMIT_COMMAND, gl.gl_pathv[pathno]);
		status = system(cmd);

		if (verbose > 1)
		    DAPLOG((LOG_DEBUG, "in fal_submit: '%s', result = %d\n", gl.gl_pathv[pathno], status));

		pathno++;
	    } while (status == 0 && gl.gl_pathv[pathno]);

	    if (status) // Send error code
	    {
		return_error();
	    }
	    else
	    {
		dap_accomp_message acc;
		acc.set_cmpfunc(dap_accomp_message::RESPONSE);
		acc.write(conn);
	    }
	    globfree(&gl);
	    if (!conn.set_blocked(false)) return false;
	}
    }
    return false; //Finished
}


