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
// server.cc
// Code for a single FAL server process.
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <ctype.h>
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
#include "directory.h"
#include "open.h"
#include "create.h"
#include "erase.h"
#include "rename.h"
#include "submit.h"

#define min(a,b) (a)<(b)?(a):(b)
#define MAX_BUFSIZE 65535

// Called to close down the FAL server process. Because child processes get 
// deleted this ensures that things are tidied up in the right order.
// We DON'T delete the connection here because it belongs to fal.cc and not us.
void fal_server::closedown()
{
    if (attrib_msg)  delete attrib_msg;
    if (alloc_msg)   delete alloc_msg;
    if (protect_msg) delete protect_msg;
}

// Main loop for FAL server process
bool fal_server::run()
{
    dap_message *m = NULL;
    bool finished = false;

// This makes it easier for me to debug child processes
    if (getenv("FAL_CHILD_DEBUG")) sleep(100000);

    attrib_msg  = NULL;
    alloc_msg   = NULL;
    protect_msg = NULL;

    if (!exchange_config())
    {
	DAPLOG((LOG_ERR, "Did not get CONFIG message\n"));
	return false;
    }
    current_task = NULL;

    do
    {
	m = dap_message::read_message(conn, true);
	if (m)
	{
	    if (verbose > 2)
		DAPLOG((LOG_ERR ,"Next message: %s\n", m->type_name()));

	    // All actions are initiated by ACCESS messages.
	    // If we get an ACCESS message before a task has completed then
	    // we just abandon it and start a new one.
	    if (m->get_type() == dap_message::ACCESS)
	    {
		if (current_task) delete current_task;
		create_access_task(m);
		
		if (!current_task) // Wot??
		{
		    dap_status_message st;
		    
		    st.set_code(020342); // Operation unsupported
		    st.write(conn);
		    return false;
		}
	    }

	    // Deal with messages where we don't have a current task
	    if (!current_task)
	    {
		switch (m->get_type())
		{
		case dap_message::ACCESS:
		    // dealt with above
		    break;

		    // These three are all to do with file attributes. We save
		    // these messages and pass them on to the task if asked.
		case dap_message::ATTRIB:
		    {
			if (attrib_msg) delete attrib_msg;
			attrib_msg = (dap_attrib_message *)m;
			m = NULL; // Do not delete it
		    }
		    break;

		case dap_message::ALLOC:
		    {
			if (alloc_msg) delete alloc_msg;
			alloc_msg = (dap_alloc_message *)m;
			m = NULL; // Do not delete it
		    }
		    break;

		case dap_message::PROTECT:
		    {
			if (protect_msg) delete protect_msg;
			protect_msg = (dap_protect_message *)m;
			m = NULL; // Do not delete it
		    }
		    break;
		    
		    // These we just discard 'cos there's no point to them
		case dap_message::DATE:
		    break;

		    // We get these when the remote end starts a new task
		case dap_message::CONFIG:
		    {
			dap_config_message cfg;
			cfg.write(conn);
		    }
		    break;

		    // Just reply to any ACCOMP messages. Our state machine
                    // obviously is different to DEC's FAL.
		case dap_message::ACCOMP:
		    {
			dap_accomp_message reply;
			reply.set_cmpfunc(dap_accomp_message::RESPONSE);
			reply.write(conn);
		    } 
		    break;

		default:
		    {
			DAPLOG((LOG_ERR, "task type %d not supported\n",
				m->get_type()));
			dap_status_message st;

			st.set_code(020342); // Operation unsupported
			st.write(conn);

			return false;
		    }
		}
	    }

	    // Tell the task to do its work.
	    if (current_task && !current_task->process_message(m))
	    {
		// Task completed
		delete current_task;
		current_task = NULL;
	    }
	}
	else
	{
	    finished = true; // Error on reading. Probably the remote task
                             // closed the connection.
	}

	// Delete the message
	if (m) delete m;

    } while (!finished);

    // If we ended because of a comms error then say so.
    if (conn.get_error())
    {
	if (verbose) DAPLOG((LOG_ERR, "%s\n", conn.get_error()));
	return false;
    }
    return true;
}

// Exchange config message
bool fal_server::exchange_config()
{

// Send our config message
    dap_config_message *newcm = new dap_config_message(MAX_BUFSIZE);
    if (!newcm->write(conn)) return false;
    delete newcm;

// Read the client's config message
    dap_message *m=dap_message::read_message(conn, true);
    if (!m) // Comms error
    {
	DAPLOG((LOG_ERR, "%s\n", conn.get_error()));
	return false;
    }

// Check it's OK and set the connection buffer size
    dap_config_message *cm = (dap_config_message *)m;
    if (m->get_type() == dap_message::CONFIG)
    {
	cm = (dap_config_message *)m;

	if (verbose > 1)
	    DAPLOG((LOG_DEBUG, "Remote buffer size is %d\n", 
		    cm->get_bufsize()));
	conn.set_blocksize(min(MAX_BUFSIZE,cm->get_bufsize()));
	if (verbose > 1)
	    DAPLOG((LOG_DEBUG, "Using block size %d\n", 
		    conn.get_blocksize()));

	need_crcs = cm->need_crc();
	if (verbose > 1 && need_crcs)
	    DAPLOG((LOG_DEBUG, "Remote end supports CRCs\n"));

	params.remote_os = cm->get_os();
	if (verbose > 1)
	    DAPLOG((LOG_DEBUG, "Remote OS is %d\n", params.remote_os));

	// CC Warning, dodgy logic!
	params.can_do_stmlf = true;
	if (params.remote_os == dap_config_message::OS_RSX11M ||
	    params.remote_os == dap_config_message::OS_RSX11MP)
	params.can_do_stmlf = false;
    }
    else
    {
	DAPLOG((LOG_ERR, "Got %s instead of CONFIG\n", m->type_name()));
	return false;
    }
    delete m;

    return true;
}

// Create a task to process an ACCESS message
void fal_server::create_access_task(dap_message *m)
{
    dap_access_message *am = (dap_access_message *)m;

    if (verbose > 1)
    {
	DAPLOG((LOG_DEBUG, "ACCESS: func: %s\n", func_name(am->get_accfunc())));
	DAPLOG((LOG_DEBUG, "ACCESS: file: %s\n", am->get_filespec()));
    }
    
    // Do what we need to do
    switch(am->get_accfunc())
    {
    case dap_access_message::OPEN:
	current_task = new fal_open(conn, verbose, params,
				    attrib_msg, alloc_msg, protect_msg);
	break;
    case dap_access_message::CREATE:
	current_task = new fal_create(conn, verbose, params, 
				      attrib_msg, alloc_msg, protect_msg);
	break;
    case dap_access_message::RENAME:
	current_task = new fal_rename(conn, verbose, params);
	break;
    case dap_access_message::ERASE:
	current_task = new fal_erase(conn, verbose, params);
	break;
    case dap_access_message::DIRECTORY:
	current_task = new fal_directory(conn, verbose, params);
	break;
    case dap_access_message::SUBMIT:
	current_task = new fal_submit(conn, verbose, params);
	break;

    default:
	current_task = NULL;
	return;

    }
    current_task->set_crc(need_crcs);
}


// Return the DAP ACCESS function name
const char *fal_server::func_name(int number)
{
    static char num[32];

    switch (number)
    {
    case dap_access_message::OPEN:
        return "OPEN";
        break;
    case dap_access_message::CREATE:
        return "CREATE";
        break;
    case dap_access_message::RENAME:
        return "RENAME";
        break;
    case dap_access_message::ERASE:
        return "ERASE";
        break;
    case dap_access_message::DIRECTORY:
        return "DIRECTORY";
        break;
    case dap_access_message::SUBMIT:
        return "SUBMIT";
        break;
    default:
	sprintf(num, "UNKNOWN: %d", number);
	return num;
    }
}
