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
// task.cc
// Base class for a task within a FAL server process.
// All real tasks subclass this but we provide here some basic services such
// as filename conversion and parsing that they all need.
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <syslog.h>
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

// Send and error packet based on errno
void fal_task::return_error()
{
    return_error(errno);
}

// Send and error packet based on the passed error code
void fal_task::return_error(int code)
{
    if (verbose > 1)
	DAPLOG((LOG_ERR, "fal_task error: %s\n", strerror(code)));

    // If the other end went away there's no point in sending the message
    if (code == ENOTCONN) return;

    dap_status_message sm;
    sm.set_errno(code);
    sm.write(conn);
    conn.set_blocked(false);
}

void fal_task::set_crc(bool onoff)
{
    need_crc = onoff;
}

void fal_task::calculate_crc(unsigned char *buf, int len)
{
    crc.calc4shift(buf, len);
}


// A test to see if the file is a VMS-type filespec or a Unix one
// Also sets the 'vms_format' boolean
bool fal_task::is_vms_name(char *name)
{
    if ( (strchr(name, '[') && strchr(name, ']')) ||
	  strchr(name, ';') || strchr(name, ':') )
	return vms_format=true;

    // If the filename is all upper case then
    // we also assume it's 'VMS' format. Though in this
    // case it's more likely to have come from RSX...
    unsigned int i;
    bool allupper = true;
    for (i=0; i<strlen(name); i++)
	    if (!isupper(name[i]))
		    allupper = false;

    if (allupper && strlen(name))
	    return vms_format=true;
    else
	    return vms_format=false;
}

/* Add the virtual "root" directory to the filename */
void fal_task::add_vroot(char *name)
{
    // Add in the vroot
    if (params.vroot_len)
    {
	int oldlen = strlen(name);

	/* Security measure...if the name has ".." in it then blank the whole lot out and
	   confuse the user.
	   well, it stops them escaping the root
	*/
	if (strstr(name, ".."))
	    name[0] = '\0';

	if (verbose > 3) DAPLOG((LOG_DEBUG, "add_vroot: name is %s, vroot='%s' (len=%d)\n", name, params.vroot, params.vroot_len));
	memmove(name + params.vroot_len, name, oldlen);
	memmove(name, params.vroot, params.vroot_len);

	/* Make sure it's NUL-terminated */
	name[oldlen+params.vroot_len] = '\0';

	if (verbose > 3) DAPLOG((LOG_DEBUG, "add_vroot: name is now %s\n", name));
    }
}

/* Remove the virtual "root" directory to the filename */
void fal_task::remove_vroot(char *name)
{
    if (params.vroot_len)
    {
	if (verbose > 3) DAPLOG((LOG_INFO, "remove_vroot: name is %s\n", name));

	memmove(name, name + params.vroot_len-1, strlen(name)+1);

	if (verbose > 3) DAPLOG((LOG_INFO, "remove_vroot: name is now %s\n", name));
    }

}

// Splits a filename up into volume, directory and file parts.
// The volume and directory are just for display purposes (they get sent back
// to the client). file is the (possibly) wildcard filespec to use for
// searching for files.
//
// Unix filenames are just returned as-is.
//
// volume and directory are assumed to be long enough for PATH_MAX. file
// also contains the input filespec.
//
void fal_task::split_filespec(char *volume, char *directory, char *file)
{
#if 1
    // If the remote client is VMS or RSX then lower-case the filename
#if 1
    if (params.remote_os == dap_config_message::OS_VAXVMS ||
        params.remote_os == dap_config_message::OS_RSX11M ||
#else
    if (params.remote_os == dap_config_message::OS_RSX11M ||
#endif
        params.remote_os == dap_config_message::OS_RSX11MP)
    {
	dap_connection::makelower(file);
    }
#endif
    if (is_vms_name(file))
    {
	// This converts the VMS name to a Unix name and back again. This
	// involves calling parse_vms_filespec twice and ourself once more.
	// YES THIS IS RIGHT! We need to make sense of the input file name
	// in our own terms and then send back our re-interpretation of
	// the input filename. This is what any sensible operating
	// system would do. (VMS certainly does!)

	// Convert it to a Unix filespec
	char unixname[PATH_MAX];
	char vmsname[PATH_MAX];

	make_unix_filespec(unixname, file);

	// Parse that Unix name
	strcpy(file, unixname);
	split_filespec(volume, directory, file);

	if (verbose > 1)
	    DAPLOG((LOG_DEBUG, "Unix filespec is %s\n", unixname));

	// Then convert it back to VMS
	make_vms_filespec(unixname, vmsname, true);

	if (verbose > 1)
	    DAPLOG((LOG_DEBUG, "VMS filespec is %s\n", vmsname));

	// Split up the VMS spec for returning in bits
	parse_vms_filespec(volume, directory, vmsname);

	// Make sure we set this back to true after we called ourself with a
	// Unix filespec
	vms_format = true;
	return;
    }

    // We don't fill in the volume for unix filespecs
    volume[0] = '\0';
    directory[0] = '\0';
}

// Convert a Unix-style filename to a VMS-style name
// No return code because this routine cannot fail :-)
void fal_task::make_vms_filespec(const char *unixname, char *vmsname, bool full)
{
    char        fullname[PATH_MAX];
    int         i;
    char       *lastslash;
    struct stat st;

    // Resolve all relative bits and symbolic links
    realpath(unixname, fullname);

    // Remove the vroot, but leave a leading slash
    remove_vroot(fullname);

    // Find the last slash in the name
    lastslash = fullname + strlen(fullname);
    while (*(--lastslash) != '/') ;

    // If the filename has no extension then add one. VMS seems to
    // expect one as does dapfs.
    if (!strchr(lastslash, '.'))
        strcat(fullname, ".");

    // If it's a directory then add .DIR;1
    if (lstat(unixname, &st)==0 && S_ISDIR(st.st_mode))
    {
        // Take care of dots embedded in directory names (/etc/rc.d)
        if (fullname[strlen(fullname)-1] != '.')
	    strcat(fullname, ".");

        strcat(fullname, "DIR;1"); // last dot has already been added
    }
    else // else just add a version number unless the file already has one
    {
	if (!strchr(fullname, ';'))
	    strcat(fullname, ";1");
    }

    // If we were only asked for the short name then return that bit now
    if (!full)
    {
	i=strlen(fullname);
	while (fullname[i--] != '/') ;
	strcpy(vmsname, &fullname[i+2]);

	// Make it all uppercase
	dap_connection::makeupper(vmsname);
	return;
    }

    // Count the slashes. If there is one slash we emit a filename like:
    // SYSDISK:[000000]filename
    // For two we use:
    // SYSDISK:[DIR]filename
    // for three or more we use:
    // DIR:[DIR1]filename
    // and so on...

    int slashes = 0;

    // Oh, also make it all upper case for VMS's benefit.
    for (i=0; i<(int)strlen(fullname); i++)
    {
	if (islower(fullname[i])) fullname[i] = toupper(fullname[i]);
	if (fullname[i] == '/')
	{
	    slashes++;
	}
    }

    // File is in the root directory
    if (slashes == 1)
    {
	sprintf(vmsname, "%s:[000000]%s", sysdisk_name, fullname+1);
	return;
    }

    // File is in a directory immediately below the root directory
    if (slashes == 2)
    {
	char *second_slash = strchr(fullname+1, '/');

	*second_slash = '\0';

	strcpy(vmsname, sysdisk_name);
	strcat(vmsname, ":[");
	strcat(vmsname, fullname+1);
	strcat(vmsname, "]");
	strcat(vmsname, second_slash+1);

	return;
    }

    // Most user filenames end up here
    char *slash2 = strchr(fullname+1, '/');

    *slash2 = '\0';
    strcpy(vmsname, fullname+1);
    strcat(vmsname, ":[");

    // Do the directory depth
    lastslash = slash2;

    for (i=1; i<slashes-1; i++)
    {
	char *slash = strchr(lastslash+1, '/');
	if (slash)
	{
	    *slash = '\0';
	    strcat(vmsname, lastslash+1);
	    strcat(vmsname, ".");
	    lastslash = slash;
	}
    }
    vmsname[strlen(vmsname)-1] = ']';
    strcat(vmsname, lastslash+1);
}

// Split out the volume, directory and file portions of a VMS file spec
// We assume that the VMS name is (quite) well formed.
void fal_task::parse_vms_filespec(char *volume, char *directory, char *file)
{
    char *colon = strchr(file, ':');
    char *ptr = file;

    volume[0] = '\0';
    directory[0] = '\0';

    if (colon) // We have a volume name
    {
	char saved = *(colon+1);
	*(colon+1) = '\0';
	strcpy(volume, file);
	ptr = colon+1;
	*ptr = saved;
    }

    char *enddir = strchr(ptr, ']');

    // Don't get caught out by concatenated filespecs
    // like dua0:[home.christine.][test]
    if (enddir && enddir[1] == '[')
	enddir=strchr(enddir+1, ']');

    if (*ptr == '[' && enddir) // we have a directory
    {
	char saved = *(enddir+1);

	*(enddir+1) = '\0';
	strcpy(directory, ptr);
	ptr = enddir+1;
	*ptr = saved;
    }

    // Copy the rest of the filename using memmove 'cos it might overlap
    if (ptr != file)
	memmove(file, ptr, strlen(ptr)+1);

}

// Convert a VMS filespec into a Unix filespec
// volume names are turned into directories in the root directory
// (unless they are SYSDISK which is our pseudo name)
void fal_task::make_unix_filespec(char *unixname, char *vmsname)
{
    char volume[PATH_MAX];
    char dir[PATH_MAX];
    char file[PATH_MAX];
    int  ptr;
    int  i;

    strcpy(file, vmsname);

    // Remove the trailing version number
    char *semi = strchr(file, ';');
    if (semi) *semi = '\0';

    // If the filename has a trailing dot them remove that too
    if (file[strlen(file)-1] == '.')
        file[strlen(file)-1] = '\0';

    unixname[0] = '\0';

    // Split it into its component parts
    parse_vms_filespec(volume, dir, file);

    // Remove the trailing colon from the volume name
    if (volume[strlen(volume)-1] == ':')
	volume[strlen(volume)-1] = '\0';

    // If the filename has the dummy SYSDISK volume then start from the
    // filesystem root
    if (strcasecmp(volume, sysdisk_name) == 0)
    {
	strcpy(unixname, "/");
    }
    else
    {
	if (volume[0] != '\0')
	{
	    strcpy(unixname, "/");
	    strcat(unixname, volume);
	}
    }
    ptr = strlen(unixname);

    // Copy the directory
    for (i=0; i< (int)strlen(dir); i++)
    {
	// Remove '[]' as it's a no-op
	if (dir[i] == '[' &&
	    dir[i+1] == ']')
	{
	    i++;
	    ptr = 0;
	    continue;
	}

	// If the directory name starts [. then it is relative to the
	// user's home directory and we lose the starting slash
	// If there is also a volume name present then it all falls
	// to bits but then it's pretty dodgy on VMS too.
	if (dir[i] == '[' &&
	    dir[i+1] == '.')
	{
	    i++;
	    ptr = 0;
	    continue;
	}

	if (dir[i] == '[' ||
	    dir[i] == ']' ||
	    dir[i] == '.')
	{
	    unixname[ptr++] = '/';
	}
	else
	{
	    // Skip root directory specs
	    if (dir[i] == '0' && (strncmp(&dir[i], "000000", 6) == 0))
	    {
		i += 5;
		continue;
	    }
	    if (dir[i] == '0' && (strncmp(&dir[i], "0,0", 3) == 0))
	    {
		i += 2;
		continue;
	    }
	    unixname[ptr++] = dir[i];
	}
    }
    unixname[ptr++] = '\0'; // so that strcat will work properly

    // A special case (ugh!), if VMS sent us '*.*' (maybe as part of *.*;*)
    // then change it to just '*' so we get all the files.
    if (strcmp(file, "*.*") == 0) strcpy(file, "*");

    strcat(unixname, file);

    // Finally convert it all to lower case. This is not the greatest way to
    // cope with it but because VMS will upper-case everything anyway we
    // can't really distinguish case. I know samba does fancy stuff with
    // matching various combinations of case but I really can't be bothered.
    dap_connection::makelower(unixname);

    // If the name ends in .dir and there is a directory of that name without
    // the .dir then remove it (the .dir, not the directory!)
    if (strstr(unixname, ".dir") == unixname+strlen(unixname)-4)
    {
	char dirname[strlen(unixname)+1];
	struct stat st;

	strcpy(dirname, unixname);
	char *ext = strstr(dirname, ".dir");
	if (ext) *ext = '\0';
	if (stat(dirname, &st) == 0 &&
	    S_ISDIR(st.st_mode))
	{
	    char *ext = strstr(unixname, ".dir");
	    if (ext) *ext = '\0';
	}
    }
    add_vroot(unixname);
}

// Convert VMS wildcards to Unix wildcards
// In fact all this does is substitute ? for % in the string.
// elipses are NOT catered for because there is no Unix equivalent.
// This is NOT done in the normal VMS->Unix conversion for all sorts of
// complicated reasons.
void fal_task::convert_vms_wildcards(char *filespec)
{
    unsigned int i = strlen(filespec);

    while (i--)
    {
	if (filespec[i] == '%') filespec[i] = '?';
    }
}

//
// Most of the subclasses use these routines to send the file attributes in
// response to an ACCESS message.
// The option to send the DEV field is really for CREATE because when VMS
// sees the block device it tries to send the file in block mode and we then
// end up with an RMS file on Linux and that's not very useful.
bool fal_task::send_file_attributes(char *filename, int display, dev_option show_dev)
{
    unsigned int blocksize;
    bool records;

    return send_file_attributes(blocksize, records, filename, display, show_dev);
}


bool fal_task::send_file_attributes(unsigned int &block_size,
				    bool &use_records,
				    char *filename,
				    int display,
				    dev_option show_dev)
{
    struct stat st;
    bool send_dev(false);
    if (show_dev == SEND_DEV) send_dev = true;

    if (verbose > 2) DAPLOG((LOG_INFO, "DISPLAY field = 0x%x\n", display));

    if (stat(filename, &st) == 0)
    {
	conn.set_blocked(true);

	// Do an attrib message -- and save the file attributes
	if (display & dap_access_message::DISPLAY_MAIN_MASK)
	{
	    dap_attrib_message attrib_msg;

	    attrib_msg.set_stat(&st, send_dev);
	    if (!params.can_do_stmlf)
		attrib_msg.set_rfm(dap_attrib_message::FB$VAR);
	    fake_file_type(block_size, use_records, filename, &attrib_msg);

	    if (show_dev == DEV_DEPENDS_ON_TYPE)
	    {
// These are the file types we can not handle natively.
		if (!(attrib_msg.get_rfm() == dap_attrib_message::FB$VAR) ||
		      attrib_msg.get_org() != dap_attrib_message::FB$SEQ)
		{
		    attrib_msg.remove_dev();
		}
	    }

	    if (!attrib_msg.write(conn)) return false;
	}

	// There's hardly anything in this message but it keeps VMS quiet
	if (display & dap_access_message::DISPLAY_ALLOC_MASK)
	{
	    dap_alloc_message alloc_msg;

	    if (!alloc_msg.write(conn)) return false;
	}

	// Send the created and modified dates
	if (display & dap_access_message::DISPLAY_DATE_MASK)
	{
	    dap_date_message date_msg;

	    date_msg.set_cdt(st.st_ctime);
	    date_msg.set_rdt(st.st_mtime);
	    date_msg.set_rvn(1);
	    if (!date_msg.write(conn)) return false;
	}

	// Send the protection
	if (display & dap_access_message::DISPLAY_PROT_MASK)
	{
	    dap_protect_message prot_msg;

	    prot_msg.set_protection(st.st_mode);
	    prot_msg.set_owner(st.st_gid, st.st_uid);
	    if (!prot_msg.write(conn)) return false;
	}

	// Send the resolved name
	if (display & dap_access_message::DISPLAY_NAME_MASK)
	{
	    dap_name_message name_msg;

	    if (vms_format || 
		params.remote_os == dap_config_message::OS_RSX11M ||
	        params.remote_os == dap_config_message::OS_RSX11MP)
	    {
		char vmsname[PATH_MAX];

		make_vms_filespec(filename, vmsname, true);
		name_msg.set_namespec(vmsname);
		name_msg.set_nametype(dap_name_message::FILESPEC);
	    }
	    else
	    {
		name_msg.set_namespec(filename);
		name_msg.set_nametype(dap_name_message::FILENAME);
	    }
	    if (!name_msg.write(conn)) return false;
	}
    }
    else
    {
	DAPLOG((LOG_WARNING, "TASK: cannot stat %s: %s\n",
		filename, strerror(errno)));
	return false;
    }
    return true;
}

// Send an ACK and the whole block.
bool fal_task::send_ack_and_unblock()
{
    dap_ack_message ack_msg;
    if (!ack_msg.write(conn)) return false;
    return conn.set_blocked(false);
}


bool fal_task::fake_file_type(const char *name,
			      dap_attrib_message *attrib_msg)
{
    unsigned int blocksize;
    bool records;

    return fake_file_type(blocksize, records, name, attrib_msg);
}

bool fal_task::fake_file_type(unsigned int &blocksize, bool &send_records,
			      const char *name, dap_attrib_message *attrib_msg)
{
    struct stat st;

    if (stat(name, &st) == 0 && S_ISDIR(st.st_mode))
	attrib_msg->set_fop_bit(dap_attrib_message::FB$DIR);

    // Ignore Directories
    if (stat(name, &st) == 0 && S_ISDIR(st.st_mode)) return false;

    // Use ADF data if it exists
    if (params.use_adf &&
	read_adf(blocksize, send_records, name, attrib_msg))
	return true;

    // Use metafile data if it exists
    if (params.use_metafiles &&
	read_metafile(blocksize, send_records, name, attrib_msg))
	return true;

    // Guess file type
    if (params.auto_type == fal_params::GUESS_TYPE)
	return guess_file_type(blocksize, send_records, name, attrib_msg);
    if (params.auto_type == fal_params::CHECK_EXT)
	return check_file_type(blocksize, send_records, name, attrib_msg);

    return false;
}

// Guess the file type based on the first few bytes and set the attrib
// message
bool fal_task::guess_file_type(unsigned int &block_size, bool &send_records,
			       const char *name, dap_attrib_message *attrib_msg)
{
    char   buf[132]; // Arbitrary amounts R us
    FILE  *stream;

    stream = fopen(name, "r");
    if (!stream) return false; // Preserve attributes passed to us.

    if (::fread(buf, sizeof(buf), 1, stream))
    {
	fclose(stream);
	stream = NULL;
	int binary  = 0;
	int foundlf = 0;

	for (unsigned int i=0; i<sizeof(buf); i++)
	{
	    if (!isgraph(buf[i]) && !isspace(buf[i]))
	    {
		binary++;
		break;
	    }
	    if (buf[i] == '\n') foundlf++;
	}

	if (binary)
	{
	    attrib_msg->set_rfm(dap_attrib_message::FB$FIX);
	    attrib_msg->set_mrs(512);
	    attrib_msg->clear_rat_bit(dap_attrib_message::FB$CR);
	    block_size = 512;
	    if (verbose > 1) DAPLOG((LOG_INFO, "sending file %s as blocked binary\n", name));
	    send_records = false;
	    return true;
	}
	else
	{
	    if (foundlf && foundlf < 100)
	    {
//		attrib_msg->set_rfm(dap_attrib_message::FB$VAR);
		attrib_msg->set_rat_bit(dap_attrib_message::FB$CR);
		attrib_msg->set_mrs(32768);// ??
		send_records = true;
		if (verbose > 1) DAPLOG((LOG_INFO, "sending %s file as records\n", name));
		return true;
	    }
	}
    }
    if (stream) fclose(stream);

    // Not enough to go on. Send it STREAMLF
    if (verbose > 1) DAPLOG((LOG_INFO, "sending file as streamlf\n"));
    return false;
}


// Check the file type against a list of extensions in a file and set
// the attrib message
bool fal_task::check_file_type(unsigned int &blocksize, bool &send_records,
			       const char *name, dap_attrib_message *attrib_msg)
{
    if (!auto_types_list) open_auto_types_file();
    if (!auto_types_list) return false;

    if (verbose > 2) DAPLOG((LOG_INFO, "Checking %s against types list\n", name));

    auto_types *current = auto_types_list;
    bool finished = false;
    while (current && !finished)
    {
	if (verbose>1) DAPLOG((LOG_INFO, "Checking %s %s\n", current->ext, name+(strlen(name) - current->len)));
	if (strcmp(current->ext, name+(strlen(name) - current->len)) == 0)
	{
	    send_records = current->send_records;
	    if (send_records)
	    {
		if (verbose>1) DAPLOG((LOG_INFO, "Sending records\n"));
//		attrib_msg->set_rfm(dap_attrib_message::FB$VAR);
		attrib_msg->set_rat_bit(dap_attrib_message::FB$CR);
		attrib_msg->set_mrs(32768);// ??
	    }
	    else
	    {
		if (verbose>1) DAPLOG((LOG_INFO, "Sending blocks with size %ds\n", current->block_size));
		attrib_msg->set_rfm(dap_attrib_message::FB$FIX);
		attrib_msg->set_mrs(current->block_size);
		attrib_msg->clear_rat_bit(dap_attrib_message::FB$CR);
		blocksize = current->block_size;
	    }
	    finished = true;
	}
	current = current->next;
    }

    return finished;
}

//
// Open the auto_types file and parse it into a list of structures
//
void fal_task::open_auto_types_file()
{
    int           auto_file_fd = -1;
    size_t        file_size;
    const char   *auto_file_contents;

    if (params.use_file)
    {
	auto_file_fd = open(params.auto_file, O_RDONLY);
	if (auto_file_fd > -1)
	{
	    if (verbose>1) DAPLOG((LOG_INFO, "Opening auto-types file %s\n", params.auto_file));

	    struct stat st;
	    fstat(auto_file_fd, &st);
	    file_size = st.st_size;
	    auto_file_contents = (const char *)mmap(0, st.st_size, PROT_READ,
						    MAP_SHARED, auto_file_fd,
						    0);
	    if (!auto_file_contents)
	    {
		DAPLOG((LOG_ERR, "Error in mmap of file %s. File type checking disabled\n", params.auto_file));
		params.auto_type = fal_params::NONE;
		return;
	    }
	}
	else
	{
	    DAPLOG((LOG_ERR, "Can't open auto file %s. File type checking disabled\n", params.auto_file));
	    params.auto_type = fal_params::NONE;
	    return;
	}
    }
    else
    {
	if (verbose>1) DAPLOG((LOG_INFO, "Using builtin auto-types file\n"));
	auto_file_contents = default_types_file;
    }

// Parse file into a list

    const char *fileptr = auto_file_contents;
    char extension[40];
    bool use_records;
    unsigned int block_size;
    auto_types *last_type = NULL;

    while (fileptr)
    {
	fileptr += strspn(fileptr, " \t");

	// Ignore comments and blank lines
	if (*fileptr != '#' && *fileptr != '\n' && *fileptr != '\0')
	{
	    use_records = true;
	    block_size = 0;

	    // File extension
	    int extlen = strcspn(fileptr, " \t");
	    if (extlen > 0)
	    {
		strncpy(extension, fileptr, extlen);
		extension[extlen] = '\0';
	    }
	    fileptr += extlen + strspn(fileptr+extlen, " \t");
	    if (*fileptr == 'b') use_records = false;
	    if (!use_records) // Get block size
	    {
		char num[40];
		fileptr += strspn(fileptr, " \t");
		fileptr += strcspn(fileptr, " \t");
		int numlen = strcspn(fileptr, "\n");
		if (numlen)
		{
		    strncpy(num, fileptr, numlen);
		    num[numlen] = '\0';

		    block_size = atoi(num);
		}
	    }
	    auto_types *new_type = new auto_types(extension, use_records, block_size);
	    if (verbose > 2)
		DAPLOG((LOG_DEBUG, "Type: %s, %c, %d\n",
			extension, use_records?'r':'b', block_size));


	    // Add to the list
	    if (last_type)
	    {
		last_type->next = new_type;
	    }
	    else
	    {
		auto_types_list = new_type;
	    }
	    last_type = new_type;
	}
	fileptr = strchr(fileptr, '\n');
        if (fileptr) fileptr++;
    }


// Close the file if we opened it.
    if (auto_file_fd != -1)
    {
	munmap((char *)auto_file_contents, file_size);
	close(auto_file_fd);
    }
}

// Build the ADF name
bool fal_task::adf_filename(const char *file, char *adfname)
{
    const char *endpath = strrchr(file, '/');
    int         pathlen=0;

    adfname[0] = '\0';

    if (endpath && endpath[1] != '\0')  // Name may be unqualified
    {
	pathlen = endpath-file+1;
	strncpy(adfname, file, pathlen);
	adfname[pathlen] = '\0';
    }
    else
    {
	endpath = file;
    }

    adfname[pathlen] = '\0';
    strcat(adfname, ".$ADF$");
    strcat(adfname, endpath+1);

    if (!strchr(adfname, ';')) strcat(adfname, ";1");

    if (verbose > 2) DAPLOG((LOG_DEBUG, "ADF name is %s\n", adfname));

// See if the adf exists, return false if it does not
    struct stat st;
    if (stat(adfname, &st) == -1 && errno == ENOENT)
    {
	return false;
    }
    return true;
}

// Get the metafile name for a file.
void fal_task::meta_filename(const char *file, char *metafile)
{
    const char *endpath = strrchr(file, '/');
    int         pathlen=0;

    metafile[0] = '\0';

    // Directories have a slash on the end of the name...
    if (endpath && endpath[1] != '\0')  // Name may be unqualified
    {
	pathlen = endpath-file+1;
	strncpy(metafile, file, pathlen);
	metafile[pathlen] = '\0';
    }
    else
    {
	endpath = file;
    }

    metafile[pathlen] = '\0';
    strcat(metafile, METAFILE_DIR);

// See if the metafile directory exists, maybe create it
    struct stat st;
    if (stat(metafile, &st) == -1 && errno == ENOENT)
    {
	// Make Unix do as it's fucking told.
	mode_t old_umask = umask(0);
	mkdir(metafile, 0777);
	umask(old_umask);
    }
    strcat(metafile, "/");
    strcat(metafile, endpath);
}

// Read file metadata - return true if it exists, false otherwise
bool fal_task::read_metafile(unsigned int &block_size, bool &send_records,
			     const char *name, dap_attrib_message *attrib_msg)
{
    char metafile[PATH_MAX];
    struct stat st;

    meta_filename(name, metafile);

    if (stat(metafile, &st) == 0)
    {
	FILE *mf = fopen(metafile, "r");
	if (mf)
	{
	    if (verbose>1) DAPLOG((LOG_INFO, "opened %s\n", metafile));
	    metafile_data metadata;

	    if (::fread(&metadata, sizeof(metadata), 1, mf) != 1)
	    {
		fclose(mf);
		return false;
	    }

	    // V2 metafiles can have a list of record pointers
	    if (metadata.version > 1 && metadata.num_records > 0)
	    {
		if (verbose > 1) DAPLOG((LOG_INFO, "Read metafile with %d records\n", metadata.num_records));
		metadata.records = new unsigned short[metadata.num_records];
		::fread(metadata.records, sizeof(short), metadata.num_records,
			mf);
	    }
	    fclose(mf);

	    current_record = 0;
	    record_lengths = metadata.records;
	    num_records    = metadata.num_records;

	    // Check the version.
	    if (metadata.version > metafile_data::METAFILE_VERSION)
	    {
		DAPLOG((LOG_INFO, "metadata for file %s, has wrong version %d. It will be ignored\n", name, metadata.version));
		return false;
	    }
	    attrib_msg->set_rfm(metadata.rfm);
	    attrib_msg->set_mrs(metadata.mrs);
	    attrib_msg->set_rat(metadata.rat);
	    attrib_msg->set_lrl(metadata.lrl);
	    block_size = metadata.mrs;
	    if (metadata.rfm & dap_attrib_message::FB$FIX)
	    {
		send_records = false;
	    }
	    else
	    {
		// For variable-length records we always send as records if we
		// need to consult the metadata.
		if (metadata.rfm & dap_attrib_message::FB$VAR &&
		    record_lengths != NULL)
		{
		    if (verbose>1) DAPLOG((LOG_DEBUG, "Sending VAR file as records\n"));
		    send_records = true;
		}
		else
		{
		    // Shouldn't really get here, but just in case...
		    send_records = true;
		    attrib_msg->set_rfm(dap_attrib_message::FB$STMLF);
		}
	    }
	    return true;
	}
	else
	{
	    if (verbose) DAPLOG((LOG_INFO, "Can't open existing metafile %s\n", metafile));
	}
    }
    return false;
}

// Create new metafile
void fal_task::create_metafile(char *name, dap_attrib_message *attrib_msg)
{
    char metafile[PATH_MAX];

    meta_filename(name, metafile);

    if (verbose > 1) DAPLOG((LOG_INFO, "Creating metafile %s\n", metafile));
    FILE *mf = fopen(metafile, "w+");
    if (mf)
    {
	metafile_data metadata;
	metadata.rfm = attrib_msg->get_rfm();
	metadata.rat = attrib_msg->get_rat();
	metadata.mrs = attrib_msg->get_mrs();
	metadata.version = metafile_data::METAFILE_VERSION;
	metadata.num_records = current_record;

	// Calculate Longest Record Length.
	unsigned int lrl = 0;
	for (unsigned int i=0; i<current_record; i++)
	    if (record_lengths[i] > lrl) lrl = record_lengths[i];

	// Our record lengths include the terminating LF so
	// subtract that from the length.
        // If there are no records then put MRS in there.
	metadata.lrl = (lrl?(lrl - 1):metadata.mrs);

	// Write it out.
	if (::fwrite(&metadata, sizeof(metadata), 1, mf) != 1)
	{
	    if (verbose) DAPLOG((LOG_ERR, "Error writing metadata file %s\n", metafile));
	}

	// Save record lengths
	if (record_lengths && current_record > 0)
	{
	    if (verbose > 1) DAPLOG((LOG_INFO, "Writing metafile with %d records\n", current_record));
	    ::fwrite(record_lengths, sizeof(short), current_record, mf);
	}

	// Set the file ownership & protecttion of the metafile so it
	// matches the real file.
	struct stat st;
	if (stat(name, &st) == 0)
	{
	    fchown(fileno(mf), st.st_uid, st.st_gid);
	    fchmod(fileno(mf), st.st_mode & 0777);
	}
	fclose(mf);
    }
}

// Read VMS NFS "ADF" file - return true if it exists, false otherwise
bool fal_task::read_adf(unsigned int &block_size, bool &send_records,
			const char *name, dap_attrib_message *attrib_msg)
{
    char adfname[PATH_MAX];
    adf_struct adfs;
    FILE *adf;

    // Build the ADF file name
    if (!adf_filename(name, adfname)) return false;

    adf = fopen(adfname, "r");
    if (adf)
    {
	if (::fread(&adfs, sizeof(adfs), 1, adf) != 1)
	{
	    fclose(adf);
	    return false;
	}
	fclose(adf);

	adfs.rfm = adfs.rfm & 0xF;
	attrib_msg->set_rfm(adfs.rfm);
	attrib_msg->set_mrs(adfs.mrs);
	attrib_msg->set_rat(adfs.rat);
	block_size = adfs.mrs;

	if (adfs.rfm & dap_attrib_message::FB$FIX)
	{
	    send_records = false;
	}
	else
	{
	    // Shouldn't really get here, but just in case...
	    send_records = true;
//	    attrib_msg->set_rfm(dap_attrib_message::FB$STMLF);
	}
	return true;
    }

    return false;
}


// These two functions (rename and unlink) override the default Unix versions
// and rename/delete the metafiles associated with those real files
int fal_task::rename(char *oldfile, char *newfile)
{
    int status;
    status = ::rename(oldfile, newfile);

    if (params.use_metafiles)
    {
	char old_metafile[PATH_MAX];
	char new_metafile[PATH_MAX];

	meta_filename(oldfile, old_metafile);
	meta_filename(newfile, new_metafile);

	if (verbose>1) DAPLOG((LOG_INFO, "renaming metafile %s to %s\n",
			       old_metafile, new_metafile));
	::rename(old_metafile, new_metafile);
    }
    return status;
}

int fal_task::unlink(char *file)
{
    int status;
    status = ::unlink(file);

    if (params.use_metafiles)
    {
	char metafile[PATH_MAX];

	meta_filename(file, metafile);

	if (verbose>1) DAPLOG((LOG_INFO, "unlinking metafile %s\n",
			       metafile));

	::unlink(metafile);
    }
    return status;
}


fal_task::auto_types *fal_task::auto_types_list = NULL;

const char *fal_task::sysdisk_name = "SYSDISK";

const char *fal_task::default_types_file  = "#\n\
#Generic types\n\
.txt  r\n\
.c    r\n\
.cc   r\n\
.log  r\n\
.html r\n\
# VMS types\n\
.com  r\n\
.lis  r\n\
.bck  b 32256\n\
.save b 8192\n\
.exe  b 512\n\
.zip  b 512\n\
#Linux types\n\
.tar  b 10240\n\
.gz   b 512\n\
.tgz  b 512\n\
.bz2  b 512\n\
# End of file\n";
