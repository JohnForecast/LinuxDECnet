/******************************************************************************
    (c) 1998-2006 Christine Caulfield               christine.caulfield@googlemail.com

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
// directory.cc
// Code for a directory task within a FAL server process.
#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <syslog.h>
#include <limits.h>
#include <regex.h>
#include <pwd.h>
#include <grp.h>
#include <glob.h>
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

fal_directory::fal_directory(dap_connection &c, int v, fal_params &p):
    fal_task(c,v,p)
{
    name_msg   = new dap_name_message();
    prot_msg   = new dap_protect_message();
    date_msg   = new dap_date_message();
    ack_msg    = new dap_ack_message();
    attrib_msg = new dap_attrib_message();
    alloc_msg  = new dap_alloc_message();
}

fal_directory::~fal_directory()
{
    delete name_msg;
    delete prot_msg;
    delete date_msg;
    delete ack_msg;
    delete attrib_msg;
    delete alloc_msg;
}

bool fal_directory::process_message(dap_message *m)
{
    if (verbose > 2)
	DAPLOG((LOG_DEBUG, "in fal_directory::process_message \n"));

    char volume[PATH_MAX];
    char directory[PATH_MAX];
    char filespec[PATH_MAX];

    switch (m->get_type())
    {
    case dap_message::ACCESS:
        {
	    glob_t gl;
	    int    status;
	    int    pathno = 0;
	    char   *dirdir = NULL;
	    bool   double_wildcard = false;

	    dap_access_message *am = (dap_access_message *)m;
	    if (am->get_filespec())
		strcpy(filespec, am->get_filespec());
	    else
		filespec[0] = '\0';

	    // If we are talking to VMS or RSX and it did not send a filespec
	    // then default to *.*
	    // And if VMS or RSX add ;* if it did not sent it
	    if (params.remote_os == dap_config_message::OS_VAXVMS ||
	    	params.remote_os == dap_config_message::OS_RSX11MP ||
	    	params.remote_os == dap_config_message::OS_RSX11M) {
		 if (filespec[0] == '\0') {
			strcpy(filespec, "[]*.*");
		 } else if (!strchr(filespec, ';')) {
			 strcat(filespec, ";*");
		 }
	    }

	    split_filespec(volume, directory, filespec);

	    // If there are two wildcards then we need to be prepared
	    // to send multiple DIRECTORY name records as we change
	    // directories.
	    // We don't want to do this normally because glob() follows
	    // symlinks to the output can get confusing.
	    if (strchr(filespec, '*') != strrchr(filespec, '*'))
	    {
		double_wildcard = true;
	    }
	    else
	    {
		// Send the one-and-only VOLUME/DIRECTORY info
		name_msg->set_nametype(dap_name_message::VOLUME);
		name_msg->set_namespec(volume);
		if (!name_msg->write(conn)) return false;

		name_msg->set_nametype(dap_name_message::DIRECTORY);
		name_msg->set_namespec(directory);
		if (!name_msg->write(conn)) return false;
	    }


            // if the remote end asked for *.DIR then remove the .DIR bit
	    // but only spit out directories (see below)
	    if (vms_format && ((dirdir = strstr(filespec, ".dir"))) )
	    {
		*dirdir = '\0';
	    }

	    // If the name format is Unix and the name is a directory
	    // then add * so the user gets a directory listing
	    if (!vms_format)
	    {
		// If the filename is empty then make it '.'
                // The code below will make it ./* so the user gets a listing
                // of the home directory...magic!
		if (filespec[0] == '\0')
		{
		    filespec[0] = '.';
		    filespec[1] = '\0';
		}
		add_vroot(filespec);

		struct stat st;
		stat(filespec, &st);

		if (S_ISDIR(st.st_mode))
		{
		    if (verbose > 2) DAPLOG((LOG_INFO, "Adding * to Unix dir name.\n"));
		    strcat(filespec, "/*");
		}
	    }

	    // Convert % wildcards to ?
	    if (vms_format) convert_vms_wildcards(filespec);

	    // Create the list of files
	    status = glob(filespec, GLOB_MARK | GLOB_NOCHECK, NULL, &gl);
	    if (status)
	    {
		return_error();
		return false;
	    }

	    // Enable blocked output for the whole of the transmission.
	    // the connection will send a buffer full at a time.
	    conn.set_blocked(true);

	    // Keep a track of the last path so we know when to send
            // a new directory spec.
	    char last_path[PATH_MAX] = {'\0'};

	    // Display the file names
	    while (gl.gl_pathv[pathno])
	    {
		// Ignore metafile directory
		if (strcmp(gl.gl_pathv[pathno], METAFILE_DIR)==0) continue;

		if (vms_format && double_wildcard)
		{
		    char dir_path[PATH_MAX];
		    strcpy(dir_path, gl.gl_pathv[pathno]);
		    if (strrchr(dir_path, '/'))
			*strrchr(dir_path, '/') = '\0';

		    if (strcmp(last_path, dir_path))
		    {
			char filespec[PATH_MAX];

			make_vms_filespec(gl.gl_pathv[pathno], filespec, true);
			split_filespec(volume, directory, filespec);

			name_msg->set_nametype(dap_name_message::VOLUME);
			name_msg->set_namespec(volume);
			if (!name_msg->write(conn)) return false;

			name_msg->set_nametype(dap_name_message::DIRECTORY);
			name_msg->set_namespec(directory);
			if (!name_msg->write(conn)) return false;
			strcpy(last_path, dir_path);
		    }
		}

		// If the requested filespec has ".DIR" in it then
		// only send directories.
		if (vms_format && dirdir)
		{
		    if (gl.gl_pathv[pathno][strlen(gl.gl_pathv[pathno])-1] == '/')
			if (!send_dir_entry(gl.gl_pathv[pathno], am->get_display()))
			{
			    return_error();
			    return false;
			}
		}
		else
		{
		    if (!send_dir_entry(gl.gl_pathv[pathno], am->get_display()))
		    {
		        return_error();
			return false;
		    }
		}
		pathno++;
	    }
	    globfree(&gl);
	    dap_accomp_message accomp;
	    accomp.set_cmpfunc(dap_accomp_message::RESPONSE);
	    if (!accomp.write(conn)) return false;

	    // Switch blocking off now
	    if (!conn.set_blocked(false))
	    {
		return_error();
	    }
	    return false; // Completed
	}
    }
    return true;
}

// We don't use send_file_attributes from fal_task because we need
// munge the resultant name a bit more than it, also the NAME file
// is mandatory for directory listings (quite reasonable really!)
bool fal_directory::send_dir_entry(char *path, int display)
{
    struct stat st;

    if (verbose > 2) DAPLOG((LOG_INFO, "DISPLAY field = 0x%x\n", display));
    conn.set_blocked(true);

    // Send the resolved name. Always send the name even if the file
    // does not exist. This keeps the error handling correct at the VMS end.
    if (vms_format)
    {
	char vmsname[PATH_MAX];
	make_vms_filespec(path, vmsname, false);

	unsigned int lastdot = strlen(vmsname);
	unsigned int dotcount = 0;
	unsigned int i;

// Hack the name around to keep VMS happy. If there is more than one dot
// in the name then convert the first ones to hyphens,
// also convert some other illegal characters to hyphens too.
// There may need to be more here as odd characters to seem to upset VMS
// greatly.
// CC: TODO - move this back into task.cc so we can do more generic
// 	       conversions of "illegal" filenames
	for (i=0; i< strlen(vmsname); i++)
	{
	    if (vmsname[i] == '~' ||
		vmsname[i] == ' ') vmsname[i] = '-';

	    if (vmsname[i] == '.')
	    {
		lastdot = i;
		dotcount++;
	    }
	}
	// Do those superflous dots
	if (dotcount > 1)
	{
	    for (i=0; i< strlen(vmsname); i++)
	    {
		if (vmsname[i] == '.' && i != lastdot) vmsname[i] = '-';
	    }
	  }
	name_msg->set_namespec(vmsname);
    }
    else
    {
	char publicname[PATH_MAX];
	strcpy(publicname, path);
	remove_vroot(publicname);
        name_msg->set_namespec(publicname);
    }

    name_msg->set_nametype(dap_name_message::FILENAME);
    if (!name_msg->write(conn)) return false;

    // Stat the file and send the info.
    if (lstat(path, &st) == 0)
    {
        // Do an attrib message
	if (display & dap_access_message::DISPLAY_MAIN_MASK)
	{
	    attrib_msg->set_stat(&st, true);
	    if (!params.can_do_stmlf)
                attrib_msg->set_rfm(dap_attrib_message::FB$VAR);

	    fake_file_type(path, attrib_msg);
	    if (!attrib_msg->write(conn)) return false;
	}

	// There's hardly anything in this message but it keeps VMS quiet
	if (display & dap_access_message::DISPLAY_ALLOC_MASK)
	{
	    if (!alloc_msg->write(conn)) return false;
	}

	// Send the created and modified dates
	if (display & dap_access_message::DISPLAY_DATE_MASK)
	{
// Because Unix has no concept of a "Created" date we use the earliest
// of the modified and changed dates. Daft or what?
	    if (st.st_ctime < st.st_mtime)
		date_msg->set_cdt(st.st_ctime);
	    else
		date_msg->set_cdt(st.st_mtime);

	    date_msg->set_rdt(st.st_mtime);
	    date_msg->set_rvn(1);
	    if (!date_msg->write(conn)) return false;
	}

	// Send the protection
	if (display & dap_access_message::DISPLAY_PROT_MASK)
	{
	    prot_msg->set_protection(st.st_mode);
	    prot_msg->set_owner(st.st_gid, st.st_uid);
	    if (!prot_msg->write(conn)) return false;
	}

	// Finish with an ACK
	if (!ack_msg->write(conn)) return false;
    }
    else
    {
	if (verbose) DAPLOG((LOG_WARNING, "DIR: cannot stat %s: %s\n", path, strerror(errno)));
        dap_status_message st;
        st.set_errno();
        st.write(conn);
    }
    return true;
}

