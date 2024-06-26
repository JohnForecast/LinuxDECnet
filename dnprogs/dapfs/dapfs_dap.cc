/******************************************************************************
    (c) 2005-2008 Christine Caulfield             christine.caulfield@gmail.com

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

#define _FILE_OFFSET_BITS 64
#define FUSE_USE_VERSION 25

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <sys/statfs.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>
#include "dn_endian.h"
#include "connection.h"
#include "protocol.h"
#include "dapfs_dap.h"
extern "C" {
#include "filenames.h"
#include "dapfs.h"
}

// CC This isn't going to work!
static dap_connection conn(debuglevel);

static int dap_connect(dap_connection &c)
{
	char dirname[256] = {'\0'};
	if (!c.connect(prefix, dap_connection::FAL_OBJECT, dirname))
	{
		return -ENOTCONN;
	}

	// Exchange config messages
	if (!c.exchange_config())
	{
		fprintf(stderr, "Error in config: %s\n", c.get_error());
		return -ENOTCONN;
	}
	return 0;
}

static void restart_dap()
{
	syslog(LOG_INFO, "Restarting dapfs connection\n");
	conn.close();
	dap_connect(conn);
}

int get_object_info(char *command, char *reply)
{
	dap_connection dummy(0); // So we can use parse()
	struct accessdata_dn accessdata;
	char node[BUFLEN], filespec[VMSNAME_LEN];
	int sockfd;
	int status;
	struct nodeent	*np;
	struct sockaddr_dn sockaddr;
	fd_set fds;
	struct timeval tv;

	memset(&accessdata, 0, sizeof(accessdata));
	memset(&sockaddr, 0, sizeof(sockaddr));

	/* This should always succeed, otherwise we would never get here */
	if (!dummy.parse(prefix, accessdata, node, filespec))
		return -1;


	// Try very hard to get the local username for proxy access.
	// This code copied from libdap for consistency
	char *local_user = cuserid(NULL);
	if (!local_user || local_user == (char *)0xffffffff)
		local_user = getenv("LOGNAME");

	if (!local_user) local_user = getenv("USER");
	if (local_user)
	{
		strcpy((char *)accessdata.acc_acc, local_user);
		accessdata.acc_accl = strlen((char *)accessdata.acc_acc);
		makeupper((char *)accessdata.acc_acc);
	}
	else
		accessdata.acc_acc[0] = '\0';

	np = getnodebyname(node);

	if ((sockfd=socket(AF_DECnet, SOCK_SEQPACKET, DNPROTO_NSP)) == -1)
	{
		return -1;
	}

	// Provide access control and proxy information
	if (setsockopt(sockfd, DNPROTO_NSP, SO_CONACCESS, &accessdata,
		       sizeof(accessdata)) < 0)
	{
		return -1;
	}

	/* Open up object number 0 with the name of the task */
	sockaddr.sdn_family   = AF_DECnet;
	sockaddr.sdn_flags	  = 0x00;
	sockaddr.sdn_objnum	  = 0x00;
	memcpy(sockaddr.sdn_objname, "DAPFS", 5);
	sockaddr.sdn_objnamel = dn_htons(5);
	memcpy(sockaddr.sdn_add.a_addr, np->n_addr,2);
	sockaddr.sdn_add.a_len = 2;

	if (connect(sockfd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0)
	{
		close(sockfd);
		return -1;
	}

// Now run the command
	if (write(sockfd, command, strlen(command)) < (int)strlen(command))
	{
		close(sockfd);
		return -1;
	}

// Wait for completion (not for ever!!)
	FD_ZERO(&fds);
	FD_SET(sockfd, &fds);
	tv.tv_usec = 0;
	tv.tv_sec = 3;
	status = select(sockfd+1, &fds, NULL, NULL, &tv);
	if (status <= 0)
	{
		close(sockfd);
		return -1;
	}
	status = read(sockfd, reply, BUFLEN);
	close (sockfd);
	return status;
}

static void add_to_stat(dap_message *m, struct stat *stbuf)
{
	switch (m->get_type())
	{
	case dap_message::NAME:
	{
		dap_name_message *nm = (dap_name_message *)m;

		// If name ends in .DIR;1 then add directory attribute
		if (nm->get_nametype() == dap_name_message::FILENAME) {
			if (strstr(nm->get_namespec(), ".DIR;1")) {
				stbuf->st_mode &= ~S_IFREG;
				stbuf->st_mode |= S_IFDIR;
			}
			else {
				stbuf->st_mode |= S_IFREG;
			}
		}
	}
	break;

	case dap_message::PROTECT:
	{
		dap_protect_message *pm = (dap_protect_message *)m;
		stbuf->st_mode |= pm->get_mode();
		stbuf->st_uid = 0;
		stbuf->st_gid = 0;
	}
	break;

	case dap_message::ATTRIB:
	{
		dap_attrib_message *am = (dap_attrib_message *)m;
		stbuf->st_size = am->get_size();
		stbuf->st_blksize = am->get_bsz();
		stbuf->st_blocks = am->get_alq();
		/* Samba needs this */
		stbuf->st_nlink = 1;
	}
	break;

	case dap_message::DATE:
	{
		dap_date_message *dm = (dap_date_message *)m;
		stbuf->st_atime = dm->get_rdt_time();
		stbuf->st_ctime = dm->get_cdt_time();
		stbuf->st_mtime = dm->get_cdt_time();
	}
	break;
	}
}

int dapfs_getattr_dap(const char *path, struct stat *stbuf)
{
	char vmsname[VMSNAME_LEN];
	char name[80];
	int ret = 0;
	int size;

	make_vms_filespec(path, vmsname, 0);

	dap_access_message acc;
	acc.set_accfunc(dap_access_message::DIRECTORY);
	acc.set_accopt(1);
	acc.set_filespec(vmsname);
	acc.set_display(dap_access_message::DISPLAY_MAIN_MASK |
			dap_access_message::DISPLAY_DATE_MASK |
			dap_access_message::DISPLAY_PROT_MASK);
	if (!acc.write(conn)) {
		restart_dap();
		return -EIO;
	}

	dap_message *m;

	// Loop through the files we find
	while ( ((m=dap_message::read_message(conn, true) )) )
	{
		add_to_stat(m, stbuf);
		if (m->get_type() == dap_message::ACCOMP) {
			delete m;
			goto finished;
		}

		if (m->get_type() == dap_message::STATUS)
		{
			dap_status_message *sm = (dap_status_message *)m;
			if (sm->get_code() == 0x4030) // Locked
			{
				dap_contran_message cm;
				cm.set_confunc(dap_contran_message::SKIP);
				if (!cm.write(conn)) {
					restart_dap();
					delete m;
					return -EIO;
				}
			}
			else
			{
				ret = -ENOENT; // TODO better error ??

				// Clean connection status.
				dap_contran_message cm;
				cm.set_confunc(dap_contran_message::SKIP);
				if (!cm.write(conn)) {
					restart_dap();
					ret = -EIO;
				}
			}
		}
		delete m;
	}
finished:
	return ret;
}

int dapfs_readdir_dap(const char *path, void *buf, fuse_fill_dir_t filler,
		      off_t offset, struct fuse_file_info *fi)
{
	dap_connection c(debuglevel);
	char vmsname[VMSNAME_LEN];
	char wildname[strlen(path)+2];
	char name[80];
	struct stat stbuf;
	int size;
	int ret;

	ret = dap_connect(c);
	if (ret)
		return ret;

	memset(&stbuf, 0, sizeof(stbuf));

	// Add wildcard to path
	if (path[strlen(path)-1] == '/') {
		sprintf(wildname, "%s*.*", path);
		path = wildname;
	}
	else {
		strcpy(wildname, path);
		strcat(wildname, "/*.*");
		path = wildname;
	}

	make_vms_filespec(path, vmsname, 0);

	dap_access_message acc;
	acc.set_accfunc(dap_access_message::DIRECTORY);
	acc.set_accopt(1);
	acc.set_filespec(vmsname);
	acc.set_display(dap_access_message::DISPLAY_MAIN_MASK |
			dap_access_message::DISPLAY_DATE_MASK |
			dap_access_message::DISPLAY_PROT_MASK);
	if (!acc.write(c)) {
		c.close();
		return -EIO;
	}

	bool name_pending = false;
	dap_message *m;
	char volname[256];

	// Loop through the files we find
	while ( ((m=dap_message::read_message(c, true) )) )
	{
		add_to_stat(m, &stbuf);

		switch (m->get_type())
		{
		case dap_message::ACK:
			// Got all the file info
			if (name_pending)
			{
				char unixname[BUFLEN];

				make_unix_filespec(unixname, name);
				if (strstr(unixname, ".dir") == unixname+strlen(unixname)-4)
				{
					char *ext = strstr(unixname, ".dir");
					if (ext) *ext = '\0';
				}

				/* Tell Fuse */
				filler(buf, unixname, &stbuf, 0);

				/* Prepare for next name */
				name_pending = false;
				memset(&stbuf, 0, sizeof(stbuf));
			}
			break;

		case dap_message::NAME:
		{
			dap_name_message *nm = (dap_name_message *)m;

			if (nm->get_nametype() == dap_name_message::VOLUME)
			{
				strcpy(volname, nm->get_namespec());
			}

			if (nm->get_nametype() == dap_name_message::FILENAME)
			{
				strcpy(name, nm->get_namespec());
				name_pending = true;
			}
		}
		break;

	        case dap_message::STATUS:
		{
			// Send a SKIP if the file is locked, else it's an error
			dap_status_message *sm = (dap_status_message *)m;
			if (sm->get_code() == 0x4030)
			{
				dap_contran_message cm;
				cm.set_confunc(dap_contran_message::SKIP);
				if (!cm.write(c))
				{
					fprintf(stderr, "Error sending skip: %s\n", c.get_error());
					delete m;
					goto finished;
				}
			}
			else
			{
				printf("Error opening %s: %s\n", vmsname, sm->get_message());
				name_pending = false;
				goto flush;
			}
			break;
		}
		case dap_message::ACCOMP:
			goto flush;
		}
		delete m;
	}

finished:
	// An error:
	fprintf(stderr, "Error: %s\n", c.get_error());
	c.close();
	return 2;

flush:
	delete m;
	if (name_pending)
	{
		char unixname[BUFLEN];
		make_unix_filespec(unixname, name);
		if (strstr(unixname, ".dir") == unixname+strlen(unixname)-4)
		{
			char *ext = strstr(unixname, ".dir");
			if (ext) *ext = '\0';
		}
		filler(buf, unixname, &stbuf, 0);
	}
	c.close();
	return 0;
}

/* Path already has version number appended to it -- this may be a mistake :) */
int dap_delete_file(const char *path)
{
	char vmsname[VMSNAME_LEN];
	char name[80];
	int ret;
	int size;

	make_vms_filespec(path, vmsname, 0);

	if (vmsname[strlen(vmsname)-1] == '.')
		vmsname[strlen(vmsname)-1] = '\0';

	dap_access_message acc;
	acc.set_accfunc(dap_access_message::ERASE);
	acc.set_accopt(1);
	acc.set_filespec(vmsname);
	acc.set_display(0);
        if (!acc.write(conn)) {
		restart_dap();
		return -EIO;
	}

	// Wait for ACK or status
	ret = 0;
	while(1) {
		dap_message *m = dap_message::read_message(conn, true);

		switch (m->get_type())
		{
		case dap_message::ACCOMP:
			delete m;
			goto end;
		break;

		case dap_message::STATUS:
		{
			dap_status_message *sm = (dap_status_message *)m;
			ret = -EPERM; // Default error!
			delete m;
			goto end;
		}
		break;
		}
		delete m;
	}

	end:
	return ret;
}

int dap_rename_file(const char *from, const char *to)
{
	char vmsfrom[VMSNAME_LEN];
	char vmsto[VMSNAME_LEN];
	char dirname[BUFLEN];
	int ret;
	int size;
	struct stat stbuf;

	// If it's a directory then add .DIR to the name
	if ( (ret = dapfs_getattr_dap(from, &stbuf))) {
		strcpy(dirname, from);
		strcat(dirname, ".dir");
		if ( (ret = dapfs_getattr_dap(dirname, &stbuf)))
			return ret;
		from = dirname;
	}

	make_vms_filespec(from, vmsfrom, 0);
	make_vms_filespec(to, vmsto, 0);

	if (from == dirname) {

		// Set prot=RWED on 'from' directory or we can't rename it.
		// Don't regard this as fatal, subsequent calls will return -EPERM
		// anyway if it's really wrong.
		char setprot[2 * VMSNAME_LEN];
		char reply[BUFLEN];
		int len;

		sprintf(setprot, "SETPROT %s O:RWED", vmsfrom);
		len = get_object_info(setprot, reply);
		if (len != 2) // "OK"
			syslog(LOG_WARNING, "dapfs: can't set protection on directory %s", vmsfrom);

		// Fix the TO name too.
		// TODO Odd dotting here, not sure why. just work around it for now
		if (vmsto[strlen(vmsto)-1] == '.')
			strcat(vmsto, "DIR");
		else
			strcat(vmsto, ".DIR");
	}

	dap_access_message acc;
	acc.set_accfunc(dap_access_message::RENAME);
	acc.set_accopt(1);
	acc.set_filespec(vmsfrom);
	acc.set_display(0);
        if (!acc.write(conn)) {
		restart_dap();
		return -EIO;
	}

	dap_name_message nam;
	nam.set_nametype(dap_name_message::FILESPEC);
	nam.set_namespec(vmsto);
	if (!nam.write(conn)) {
		restart_dap();
		return -EIO;
	}

	// Wait for ACK or status
	ret = 0;
	while (1) {
		dap_message *m = dap_message::read_message(conn, true);
		switch (m->get_type())
		{
		case dap_message::ACCOMP:
			goto end;

		case dap_message::STATUS:
		{
			dap_status_message *sm = (dap_status_message *)m;
			ret = -EPERM; // Default error!
			goto end;
		}
		}
	}
	end:
	return ret;
}


int dap_init()
{
	struct accessdata_dn accessdata;
	char node[BUFLEN], filespec[VMSNAME_LEN];

	if (dap_connect(conn))
		return -ENOTCONN;

	return 0;
}
