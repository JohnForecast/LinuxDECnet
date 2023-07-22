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
// open.cc
// Code for a OPEN task within a FAL server process.
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>
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
#include <string.h>
#include <regex.h>
#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>

#include "logging.h"
#include "connection.h"
#include "protocol.h"
#include "vaxcrc.h"
#include "params.h"
#include "task.h"
#include "server.h"
#include "open.h"
#include "dn_endian.h"

#ifndef PRINT_COMMAND
#define PRINT_COMMAND "lpr %s"
#endif

#ifndef SUBMIT_COMMAND
#define SUBMIT_COMMAND "at -f %s now "
#endif

// This is the initial allocation and expansion value for
// the array or record lengths.
#define RECORD_LENGTHS_SIZE 100

fal_open::fal_open(dap_connection &c, int v, fal_params &p,
		   dap_attrib_message *att,
		   dap_alloc_message   *alloc,
		   dap_protect_message *protect):
    fal_task(c,v,p)
{
    use_records  = true;
    streaming    = false;
    write_access = false;
    block_size   = 512;
    stream       = NULL;
    attrib_msg   = att;
    create       = false;
    buf          = new char[conn.get_blocksize()];
    protect_msg  = protect;
    if (att->get_fop_bit(dap_attrib_message::FB$CIF)) create = true;
}

fal_open::~fal_open()
{
    delete[] buf;
}

bool fal_open::process_message(dap_message *m)
{
    if (verbose > 2)
	DAPLOG((LOG_DEBUG, "in fal_open::process_message\n"));

    char volume[PATH_MAX];
    char directory[PATH_MAX];
    char filespec[PATH_MAX];

    switch (m->get_type())
    {
    case dap_message::ACCESS:
        {
	    int    status;
	    if (verbose > 1)
		DAPLOG((LOG_DEBUG, "fal_open: ACCESS message:\n"));

	    dap_access_message *am = (dap_access_message *)m;

	    // Get the filespec and split it into bits
	    strcpy(filespec, am->get_filespec());
	    split_filespec(volume, directory, filespec);

	    // If the host supports BIO then send it as blocks
	    if (am->get_fac() & (1<<dap_access_message::FB$BIO))
	    {
		if (verbose > 1) DAPLOG((LOG_INFO, "sending file using BIO\n"));
		use_records = false;
	    }

	    // Enable write access ?
	    if (am->get_fac() & (1<<dap_access_message::FB$PUT) ||
		am->get_fac() & (1<<dap_access_message::FB$UPD))
	    {
		write_access=true;
	    }

	    // Convert % wildcards to ?
	    if (vms_format) 
		convert_vms_wildcards(filespec);
	    else
		add_vroot(filespec);

	    // Expand wildcards
	    status = glob(filespec, GLOB_NOCHECK|GLOB_MARK, NULL, &gl);
	    if (status)
	    {
		return_error();
		return false;
	    }
	    glob_entry = 0;
	    display = am->get_display();

	    // Open the file
	    if (!create)
	    {
		stream = fopen(gl.gl_pathv[glob_entry], write_access?"r+":"r");
		if (!stream)
		{
		    return_error();
		    return false;
		}
	    }
	    else
	    {
		if (!create_file(gl.gl_pathv[glob_entry]))
		{
		    return_error();
		    return false;
		}
	    }
  	    num_records   = 0;
	    current_record = 0;
	    if (record_lengths) { delete[] record_lengths; record_lengths = NULL; }

	    // If we have opened an exisiting Linux file then clear the
            // PRN attribute so the records get handled correctly.
	    attrib_msg->clear_rat_bit(dap_attrib_message::FB$PRN);

	    // Send whatever attributes were requested;
	    // Only send the DEV field if the target file is
            // one we can handle natively because
	    // DEV (as a disk device) makes VMS send files in block mode.
	    if (verbose > 1) DAPLOG((LOG_INFO, "org = %d, rfm = %d\n",
				     attrib_msg->get_org(),
				     attrib_msg->get_rfm()));

	    if (!create)
	    {
	        if (!send_file_attributes(block_size, use_records,
					  gl.gl_pathv[glob_entry],
					  am->get_display(),
					  DEV_DEPENDS_ON_TYPE))
		{
		    return_error();
		    return false;
		}
	    }
	    else
	    {
	        if (!send_file_attributes(block_size, use_records,
					  gl.gl_pathv[glob_entry],
					  am->get_display(),
					  DONT_SEND_DEV))
		{
		    return_error();
		    return false;
		}
	    }
	    return send_ack_and_unblock(); 
	}
	break;

    case dap_message::CONTROL:
        {
	    dap_control_message *cm = (dap_control_message *)m;

	    set_control_options(cm);

	    switch (cm->get_ctlfunc())
	    {
	    case dap_control_message::CONNECT:
		send_ack_and_unblock();
		break;

	    case dap_control_message::GET:
	        {
		    long key = cm->get_long_key();
		    return send_file(cm->get_rac(), key);
		}
		break;

	    case dap_control_message::PUT:
	        // We have already parsed the messge options
		break;

	    case dap_control_message::REWIND:
		fseek(stream, 0L, SEEK_SET);
		break;

	    case dap_control_message::FLUSH:
		fflush(stream);
		break;

	    case dap_control_message::FIND:
	        {
		    long key = cm->get_long_key();
		    if (key) fseek(stream, 512 * (key-1), SEEK_SET);
		}
		break;

	    case dap_control_message::DISPLAY:
	        if (!send_file_attributes(block_size, use_records, gl.gl_pathv[glob_entry],
		    cm->get_display(), SEND_DEV)) return false;
		send_ack_and_unblock();
	 	break;

	    default:
		DAPLOG((LOG_WARNING, "unexpected CONTROL message type %d received\n", cm->get_ctlfunc() ));
		return false;
	    }
        }
	break;

    case dap_message::ACCOMP:
        {
	    dap_accomp_message *am = (dap_accomp_message *)m;
	    dap_accomp_message reply;

	    if (verbose > 1)
		DAPLOG((LOG_DEBUG, "fal_open: ACCOMP message: type %d\n",
			am->get_cmpfunc()));

	    switch (am->get_cmpfunc())
	    {
	    case dap_accomp_message::END_OF_STREAM:
		reply.set_cmpfunc(dap_accomp_message::RESPONSE);
		reply.write(conn);
		return true;

	    case dap_accomp_message::CLOSE:

		// This option needs to be done before close
		if (am->get_fop_bit(dap_attrib_message::FB$TEF) ||
		    attrib_msg->get_fop_bit(dap_attrib_message::FB$TEF))
		    truncate_file();

		// finished task
		if (stream)
		{
		    fclose(stream);
		    stream = NULL;
		}

		// Do post-close options
		if (am->get_fop_bit(dap_attrib_message::FB$SPL) ||
		    attrib_msg->get_fop_bit(dap_attrib_message::FB$SPL))
		    print_file();
		if (am->get_fop_bit(dap_attrib_message::FB$DLT) ||
		    attrib_msg->get_fop_bit(dap_attrib_message::FB$DLT))
		    delete_file();

		// write metafile
		if (params.use_metafiles && create)
		    create_metafile(gl.gl_pathv[glob_entry], attrib_msg);

		// move onto next file
		if (glob_entry < gl.gl_pathc-1)
		{
		    glob_entry++;
		    stream = fopen(gl.gl_pathv[glob_entry], write_access?"w":"r");
		    if (!stream)
		    {
			return_error();
			return false;
		    }
		    num_records    = 0;
		    current_record = 0;
		    if (record_lengths) delete[] record_lengths;

		    if (!send_file_attributes(block_size, use_records, gl.gl_pathv[glob_entry],
					      display, SEND_DEV))
			return false;
		    return send_ack_and_unblock();
		}
		else // End of wildcard list
		{
		    reply.set_cmpfunc(dap_accomp_message::RESPONSE);
		    reply.write(conn);
		    return false;
		}
		return true;

	    default:
		DAPLOG((LOG_WARNING, "unexpected ACCOMP message type %d received\n", am->get_cmpfunc() ));
		return false;
	    }
        }

    case dap_message::DATA:
	if (!put_record((dap_data_message *)m))
	{
	    return_error();
	    return false;
	}
	return true;
	break;

    case dap_message::ACK:
	return true;
	break;

    case dap_message::STATUS:
        {
	    dap_status_message *sm = (dap_status_message *)m;

	    if ((sm->get_code() & 0x0FFF) != 0x10)
	    {
		DAPLOG((LOG_WARNING, "Error in receiving data: %s",
			sm->get_message() ));
		return false;
	    }
	    return true;
	}
	break;

    default:
	DAPLOG((LOG_WARNING, "unexpected message type %d received\n",
		m->get_type() ));
	return false;
    }
    return true;
}

// Send the whole file or the next record/block
bool fal_open::send_file(int rac, long vbn)
{
    int   buflen;
    int   bs = block_size;
    long  record_pos; // for RFA sending
    unsigned int total=0;
    dap_data_message data_msg;
    bool  ateof(false);


    if (verbose > 2) DAPLOG((LOG_DEBUG, "sending file contents. block size is %d. streaming = %d, use_records=%d, vbn=%d\n", bs, streaming, use_records, vbn));

    // We've already sent the last record...
    if (!streaming && use_records && feof(stream))
    {
	if (verbose > 1) DAPLOG((LOG_DEBUG, "Already sent file records. Sending EOF now\n"));

	send_eof();
	return true;
    }

    // If we are streaming then send as much as possible in a block,
    // if not then we block data & status message. Ether way we enable
    // blocking here.
    conn.set_blocked(true);

    // Seek to VBN or RFA (VBNs start at one)
    if (vbn || rac == dap_control_message::RB$RFA)
    {
	if (rac == dap_control_message::RB$RFA)
	    fseek(stream, vbn, SEEK_SET);
	else
	    fseek(stream, 512 * (vbn-1), SEEK_SET);
    }

    record_pos = ftell(stream);

    while (!feof(stream))
    {
	if (use_records)
	{
	    // Do we need to use the stored record lengths from the metafile ?
	    if (attrib_msg->get_rfm() == dap_attrib_message::FB$VAR &&
		record_lengths != NULL)
	    {
		if (current_record < num_records)
		{
		    if (::fread(buf, 1, record_lengths[current_record], stream) < 1)
			ateof = true;

		    // We read a whole record (including our "compatibility" LF)
		    // which VMS does not want.
		    buflen = record_lengths[current_record++]-1;
		}
		else
		{
		    send_eof();
		    return true;
		}
	    }
	    else
	    {
		// Read up to the next LF or EOF
		int newchar;
		buflen = 0;
		do
		{
		    newchar = getc(stream);
		    if (newchar != EOF)
		    {
			buf[buflen++] = (char) newchar;
		    }
		} while (newchar != EOF && newchar != '\n' && buflen < conn.get_blocksize()-10);
		ateof = feof(stream);
		/* Remove the trailing LF for non STMLF capable OSs */
		if (newchar == '\n')
			buflen--;
	    }
	}
	else // Block read
	{
	    buflen = ::fread(buf, 1, bs, stream);
	    if (!buflen) ateof = true;

	    // Always send a full block or VMS complains.
	    buflen=bs;
	}

	// We got some data
	if (!ateof)
	{
	    data_msg.set_data(buf, buflen);
	    if (!data_msg.write_with_len(conn)) return false;

	    if (verbose > 2) DAPLOG((LOG_DEBUG, "sent %d bytes of data\n", buflen));
	    total += buflen;
	}
	else
        {
	    if (verbose) DAPLOG((LOG_INFO, "Read past end of file\n"));
            dap_status_message status;
	    status.set_code(0x5027); // EOF
            status.write(conn);
	    conn.set_blocked(false);
	    return true;
        }

	// If we are streaming then check for any OOB status messages - the
	// client may have died or run out of disk space f'rinstance
	if (streaming)
	{
	    dap_message *d = dap_message::read_message(conn, false);
	    if (d)
	    {
		if (verbose > 1) DAPLOG((LOG_INFO, "Got OOB message: %s\n",
					 d->type_name()));
		if (d->get_type() == dap_message::STATUS)
		{
		    dap_status_message *sm = (dap_status_message *)d;
		    DAPLOG((LOG_INFO, "Error sending: %s\n", sm->get_message()));
		    return false;
		}
		if (d->get_type() == dap_message::ACCOMP)
	        {
		    dap_accomp_message am;

		    // Make sure this is the first thing sent. Anything pending
		    // is no longer required.
		    conn.clear_output_buffer();

		    am.set_cmpfunc(dap_accomp_message::RESPONSE);
		    am.write(conn);
		    conn.set_blocked(false);
		    return false;
		}
	    }
	}

	// If we are not streaming then return after one record/block
	if (!streaming) break;
    }

    if (streaming)
    {
	if (verbose > 1) DAPLOG((LOG_DEBUG, "sent file contents: %d bytes\n", total));
	conn.set_blocked(false); // Send data in a block on its own.
	send_eof();
    }
    else // STATUS for last record sent
    {
	dap_status_message status;

	status.set_code(010225); // Operation successful
	DAPLOG((LOG_DEBUG, "Sending RFA of %d\n", record_pos ));
	status.set_rfa( record_pos );
	status.write(conn);
	conn.set_blocked(false);
    }
    return true;
}

// Write some data to the file
bool fal_open::put_record(dap_data_message *dm)
{
    char *dataptr = dm->get_dataptr();
    int   datalen = dm->get_datalen();

// If we are receiving records then we may have to convert VMS record
// formats into Unix stream style.
    if (use_records)
    {
        // Print files have a two-byte header indicating the line length.
	if (attrib_msg->get_rat_bit(dap_attrib_message::FB$PRN))
	{
	    dataptr += attrib_msg->get_fsz();
	    datalen -= attrib_msg->get_fsz();
	}

        // FORTRAN files: First byte indicates carriage control
	if (attrib_msg->get_rat_bit(dap_attrib_message::FB$FTN))
	{
	    switch (dataptr[0])
	    {
	    case '+': // No new line
		dataptr[0] = '\r';
		break;

	    case '1': // Form Feed
		dataptr[0] = '\f';
		break;

	    case '0': // Two new lines
		dataptr[0] = '\n';
		if (!fwrite("\n", 1, 1, stream)) return false;
		break;


	    case ' ': // new line
	    default:  // Default to a new line. This seems to be what VMS does.
		dataptr[0] = '\n';
		break;
	    }
	}
    }

    if (datalen==0) {
//	DAPLOG((LOG_WARNING, "fal_open::put_record: length=0\n"));
    } else {
	// Write the data
	if (!fwrite(dataptr, datalen, 1, stream)) return false;
    }

    if ((params.remote_os == dap_config_message::OS_RSX11M ||
         params.remote_os == dap_config_message::OS_RSX11MP) &&
	 use_records) {
	// give every line an eol
        if (!fwrite("\n", 1, 1, stream)) return false;
    }

    // If we are writing variable-length records then keep a list of
    // their lengths in the metadata.
    if (attrib_msg->get_rfm() == dap_attrib_message::FB$VAR && use_records &&
	params.use_metafiles)
    {
	if (!record_lengths)
	{
	    record_lengths = new unsigned short[RECORD_LENGTHS_SIZE];
	    num_records = RECORD_LENGTHS_SIZE;
	}

	// See if we need to expand the array.
	if (current_record >= num_records)
	{
	    num_records += RECORD_LENGTHS_SIZE;
	    unsigned short *temp = new unsigned short[num_records];
	    memcpy(temp, record_lengths, sizeof(unsigned short)*current_record);
	    delete[] record_lengths;
	    record_lengths = temp;
	    if (verbose) DAPLOG((LOG_INFO, "Expanding records array to %d entries\n", num_records));
	}
	record_lengths[current_record++] = datalen;
    }

    // Send STATUS message if in stop/go mode
    if (!streaming)
    {
	dap_status_message st;
	st.set_code(0x1095);
	st.write(conn);
	conn.set_blocked(false);
    }
    return true;
}


// Print the file
void fal_open::print_file()
{
    char cmd[strlen(gl.gl_pathv[glob_entry])+strlen(PRINT_COMMAND)+2];

    sprintf(cmd, PRINT_COMMAND, gl.gl_pathv[glob_entry]);

    int status = system(cmd);

    if (verbose > 1) DAPLOG((LOG_INFO, "Print file status = %d\n", status));
}

// Delete the file
void fal_open::delete_file()
{
    int status = unlink(gl.gl_pathv[glob_entry]);

    if (verbose > 1) DAPLOG((LOG_INFO, "Delete file status = %d\n", status));
}

// truncate the file a its current length
void fal_open::truncate_file()
{
    ftruncate(fileno(stream), ftell(stream));
}

// Set variables and options according the the contents of a
// CONTROL message.
void fal_open::set_control_options(dap_control_message *cm)
{
    if (verbose > 1)
        DAPLOG((LOG_DEBUG, "fal_open: CONTROL: type %d, rac=%x\n",
		cm->get_ctlfunc(), cm->get_rac() ));

  // Determine whether to enable streaming or not
    int access_mode = cm->get_rac();
    if (access_mode == dap_control_message::SEQFT ||
	access_mode == dap_control_message::BLOCKFT)
    {
        streaming = true;
    }

  // Block transfer ??
    if (access_mode == dap_control_message::BLOCKFT ||
	access_mode == dap_control_message::BLOCK)
    {
        if (verbose > 1) DAPLOG((LOG_INFO, "sending file as blocks\n"));
        use_records = false;
    }

  // Append??
    if (cm->get_rop_bit(dap_control_message::RB$EOF))
    {
        if (verbose > 1) DAPLOG((LOG_INFO, "Seeking to EOF\n"));
        fseek(stream, 0L, SEEK_END);
    }
}

void fal_open::send_eof()
{
    dap_status_message status;

    status.set_code(050047); // EOF
    status.write(conn);
    conn.set_blocked(false);
}

// Actually create the file using (as close as we can get) the attributes
// given us by the client
bool fal_open::create_file(char *filespec)
{
    char unixname[PATH_MAX];

    // Convert the name if necessary
    if (is_vms_name(filespec))
    {
	make_unix_filespec(unixname, filespec);
    }
    else
    {
	strcpy(unixname, filespec);
    }

// Create the file with the supplied protection (if available)
    int fd=-1;

    unlink(unixname); // Delete it first

    if (protect_msg && protect_msg->get_mode())
    {
	fd = open(unixname, O_CREAT | O_RDWR, protect_msg->get_mode());
    }
    else // Use default mask
    {
	int mask = umask(0);
	umask(mask);

	fd = open(unixname, O_CREAT | O_RDWR, 0666 & ~mask);
    }

    if (fd == -1) return false;

    stream = fdopen(fd, "w+");
    if (!stream)
    {
	close(fd);
	return false;
    }

    return true;
}
