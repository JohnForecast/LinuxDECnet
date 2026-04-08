/******************************************************************************
    connection.cc from libdap

    Copyright (C) 1998-2009 Christine Caulfield       christine.caulfield@googlemail.com

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


// connection.cc
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>
#include <regex.h>
#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>
#ifdef SHADOW_PWD
#include <shadow.h>
#endif

#include "logging.h"
#include "connection.h"
#include "protocol.h"
#include "dn_endian.h"

#define min(a,b) (a)<(b)?(a):(b)

// Construct an un-connected object
dap_connection::dap_connection(int verbosity)
{
    blocksize = MAX_READ_SIZE;
    initialise(verbosity);
    create_socket();
}

// Construct an already-connected object (called from waitfor())
dap_connection::dap_connection(int socket, int bs, int verbosity)
{
    initialise(verbosity);
    blocksize   = bs;
    sockfd      = socket;
}

// Generic initialisation process
void dap_connection::initialise(int verbosity)
{
    buf       = new char[MAX_READ_SIZE];
    bufptr    = 0;
    buflen    = 0;

    // This should be big enough to handle a full buffer PLUS
    // a complete message. ie twice the max buffer size.
    outbuf    = new char[MAX_READ_SIZE*2];
    outbufptr = 0;
    last_msg_start = 0;

    verbose     = verbosity;
    have_shadow = -1; // We don't know yet
    connected   = true;
    blocked     = false;

    listening   = false;

    lasterror   = errstring;
    errstring[0]= '\0';
    closed      = false;
    connect_timeout = 60;

#ifdef NO_BLOCKING
    blocking_allowed = false; // More useful for debugging
#else
    blocking_allowed = true;
#endif
}

// Tidy up
dap_connection::~dap_connection()
{
    // Make sure the output buffer is flushed before we finish up
    if (!closed) close();
}

void dap_connection::close()
{
    if (!closed)
    {
        if (outbufptr && blocked) set_blocked(false);
        if (sockfd) ::close(sockfd);

        delete[] buf;
        delete[] outbuf;
        closed = true;
    }
}

bool dap_connection::set_socket_buffer_size()
{
    int bs;

    // Make sure the kernel buffer is large enough for our blocks
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &blocksize, sizeof(blocksize)) < 0)
    {
        sprintf(errstring, "setsockopt (SNDBUF) failed: %s", strerror(errno));
        lasterror = errstring;
        return false;
    }

    bs = MAX_READ_SIZE * 4;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &bs, sizeof(bs)) < 0)
    {
        sprintf(errstring, "setsockopt (RCVBUF) failed: %s", strerror(errno));
        lasterror = errstring;
        return false;
    }

    return true;
}

// Create a DECnet socket
void dap_connection::create_socket()
{
    if ((sockfd=socket(AF_DECnet,SOCK_SEQPACKET,DNPROTO_NSP)) == -1)
    {
        sprintf(errstring, "socket failed: %s", strerror(errno));
        lasterror = errstring;
        exit(1);
    }
}

// Connect to a named object
bool dap_connection::connect(char *node, char *user, char *password,
                             char *object)
{
    struct sockaddr_dn   sockaddr;

    sockaddr.sdn_family   = AF_DECnet;
    sockaddr.sdn_flags    = 0x00;
    sockaddr.sdn_objnum   = 0x00;

    if (strlen(object) > 16)
    {
        strcpy(errstring, "connect: object name too long");
        lasterror=errstring;
        return false;
    }
    memcpy(sockaddr.sdn_objname, object, strlen(object));
    sockaddr.sdn_objnamel = dn_htons(strlen(object));

    return do_connect(node, user, password, sockaddr);
}

// Connect to an object number
bool dap_connection::connect(char *node, char *user, char *password,
                             int object)
{
    struct sockaddr_dn   sockaddr;

    sockaddr.sdn_family   = AF_DECnet;
    sockaddr.sdn_flags    = 0x00;
    sockaddr.sdn_objnum   = object;
    sockaddr.sdn_objnamel = 0x00;

    return do_connect(node, user, password, sockaddr);
}


// Connect to an object number and a DECnet name specification.
// Returns the remaining filespec
bool dap_connection::connect(char *fspec, int object, char *tailspec)
{
    struct sockaddr_dn   sockaddr;
    struct accessdata_dn accessdata;
    char   node[MAX_NODE+1];

    if (!parse(fspec, accessdata, node, tailspec)) return false;

    sockaddr.sdn_family   = AF_DECnet;
    sockaddr.sdn_flags    = 0x00;
    sockaddr.sdn_objnum   = object;
    sockaddr.sdn_objnamel = 0x00;

    return do_connect(node,
                      (char *)accessdata.acc_user,
                      (char *)accessdata.acc_pass, sockaddr);
}

// Connect to an object name and a DECnet name specification
// Return the trailing filespec
bool dap_connection::connect(char *fspec, char *object, char *tailspec)
{
    struct sockaddr_dn   sockaddr;
    struct accessdata_dn accessdata;
    char node[MAX_NODE+1];

    if (!parse(fspec, accessdata, node, tailspec)) return false;


    sockaddr.sdn_family   = AF_DECnet;
    sockaddr.sdn_flags    = 0x00;
    sockaddr.sdn_objnum   = 0x00;

    if (strlen(object) > 16)
    {
        strcpy(errstring, "connect: object name too long");
        lasterror=errstring;
        return false;
    }
    memcpy(sockaddr.sdn_objname, object, strlen(object));
    sockaddr.sdn_objnamel = dn_htons(strlen(object));

    return do_connect(node,
                      (char *)accessdata.acc_user,
                      (char *)accessdata.acc_pass, sockaddr);
}



// Private connect method
bool dap_connection::do_connect(const char *node, const char *user,
                                const char *password,
                                struct sockaddr_dn &sockaddr)
{
    struct accessdata_dn accessdata;
    struct sockaddr_dn s = sockaddr;

    binadr = getnodebyname(node);
    if (!binadr)
    {
        strcpy(errstring, "Unknown node name");
        lasterror = errstring;
        return false;
    }

    /* If the password is "-" and fd 0 is a tty then
       prompt for a password */
    if (password[0] == '-' && password[1] == '\0' && isatty(0))
    {
        password = getpass("Password: ");
        if (password == NULL || strlen(password) > (unsigned int)MAX_PASSWORD)
        {
            strcpy(errstring, "Password input cancelled");
            lasterror = errstring;
            return false;
        }

    }

    memcpy(accessdata.acc_user, user, strlen(user));
    memcpy(accessdata.acc_pass, password, strlen(password));
    memcpy(s.sdn_add.a_addr, binadr->n_addr, sizeof(s.sdn_add.a_addr));

    // Try very hard to get the local username for proxy access
#ifdef __FreeBSD__
// FIXME: FreeBSD does not export prototype even if correct header is included
    char *local_user = NULL;
#else
    char *local_user = cuserid(NULL);
#endif
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


    accessdata.acc_userl = strlen(user);
    accessdata.acc_passl = strlen(password);

    if (setsockopt(sockfd, DNPROTO_NSP, SO_CONACCESS, &accessdata,
                   sizeof(accessdata)) < 0)
    {
        sprintf(errstring, "setsockopt (CONACCESS) failed: %s", strerror(errno));
        lasterror = errstring;
        return false;
    }

    if (!set_socket_buffer_size())
        return false;

    // Set connect timeout
    struct timeval timeout = {connect_timeout, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    if (::connect(sockfd, (struct sockaddr *)&s,
                  sizeof(sockaddr)) < 0)
    {
        if (errno == ECONNREFUSED)
        {
            sprintf(errstring, "connect failed: %s", connerror(strerror(errno)));
        }
        else
        {
            sprintf(errstring, "connect failed: %s", strerror(errno));
        }
        lasterror = errstring;
        return false;
    }

// Make sure we get a blocking socket to start with
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags & ~O_NONBLOCK);

    bufptr = buflen = 0;
    connected = true;

    return true;
}

// Read a packet
int dap_connection::read(bool block)
{
    int flags=0;
    int saved_errno;

    if (!block)
    {
        flags = fcntl(sockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    }

    buflen=::dnet_recv(sockfd, buf, blocksize, MSG_EOR);
    saved_errno = errno;

    // Reset flags
    if (!block)
    {
        fcntl(sockfd, F_SETFL, flags);
    }

    // No data and we were told not to block
    if (buflen < 0 && saved_errno == EAGAIN) return false; // No data

    if (buflen < 0)
    {
        if (saved_errno == ENOTCONN)
        {
            sprintf(errstring, "read failed: %s", connerror(strerror(saved_errno)));
        }
        else
        {
            sprintf(errstring, "DAP read error: %s", strerror(saved_errno));
        }
        lasterror = errstring;
        return false;
    }
    if (buflen == 0)
    {
        lasterror = (char *)"Remote end closed connection";
        return false;
    }

    if (verbose > 2) DAPLOG((LOG_DEBUG, "read: read %d bytes\n", buflen));
    bufptr=0;
    end_of_msg = buflen; // Until told differently
    return true;
}

int dap_connection::read_if_necessary(bool block)
{
    if (bufptr >= buflen)
        return read(block);
    else
        return 1;
}

// Send a completed packet to the remote machine
int dap_connection::write()
{
    int er;

    if (outbuf[last_msg_start+1] & 0x02)
    {
        // Add in length
        if (outbuf[last_msg_start+1] & 0x04) // LEN256 header
        {
                unsigned short len = dn_htons(outbufptr - last_msg_start - 4);
                memcpy(&outbuf[last_msg_start+2], &len, sizeof(unsigned short));
        }
        else
        {
            outbuf[last_msg_start+2] = outbufptr - last_msg_start - 3;
        }
    }

// If the caller wants blocked output we haven't filled the buffer
// then return now.
    if (blocked && (outbufptr < blocksize))
    {
        last_msg_start = outbufptr;
        return true;
    }

// If this message has overflowed the buffer size then send what we have
// and hang onto the rest.
    if (blocked && (outbufptr >= blocksize))
    {
        if (verbose > 2)
            DAPLOG((LOG_INFO, "block is over-full(%d), Sending %d bytes\n",
                    outbufptr, last_msg_start));

        er=::write(sockfd,outbuf,last_msg_start);
        if (er < 0)
        {
            if (errno == ENOTCONN)
                sprintf(errstring, "write failed: %s", connerror(strerror(errno)));
            else
                sprintf(errstring, "DAP write error: %s", strerror(errno));
            lasterror = errstring;
            return false;
        }

// Move the remaining message to the start of the buffer.
        memmove(outbuf, outbuf+last_msg_start, outbufptr - last_msg_start);
        outbufptr -= last_msg_start;
        last_msg_start = outbufptr;

        if (verbose > 2)
            DAPLOG((LOG_INFO, "Wrote %d bytes, buffer size is now %d bytes\n",
                    er, outbufptr));
        return true;
    }

// Normal send for unblocked output.
    er=::write(sockfd,outbuf,outbufptr);
    if (er < 0)
    {
        if (errno == ENOTCONN)
            sprintf(errstring, "write failed: %s", connerror(strerror(errno)));
        else
            sprintf(errstring, "DAP write error: %s", strerror(errno));
        lasterror = errstring;
        return false;
    }
    if (verbose > 2) DAPLOG((LOG_DEBUG, "wrote %d bytes\n", er));

    outbufptr = last_msg_start = 0;

    return true;
}

// Returns a pointer to a specific number of bytes in the buffer and
// increments the buffer pointer.
// Not the most C++ way of doing it but quick!
char *dap_connection::getbytes(int num)
{
    char *ptr;

    if (bufptr+num > buflen)
    {
        DAPLOG((0, "ATTEMPT TO READ PAST BUFFER. bufptr=%d, num=%d,buflen=%d\n",
                bufptr, num, buflen));
        *(int *)0 = 0xdeadbeef;
        return NULL;
    }

    ptr = &buf[bufptr];

    bufptr += num;

    return ptr;
}

// Returns a pointer to a specific number of bytes in the buffer
// if there are that many.
// Return NULL if there are not enough available.
char *dap_connection::peekbytes(int num)
{
    char *ptr;

    if (bufptr+num > buflen)
    {
        return NULL;
    }
    ptr = &buf[bufptr];
    return ptr;
}

// Returns true if there are 'num' bytes left in the message
bool dap_connection::have_bytes(int num)
{
    if (bufptr+num > end_of_msg)
        return false;
    else
        return true;
}

// Copy some bytes to the output buffer
int dap_connection::putbytes(void *bytes, int num)
{
    memcpy(&outbuf[outbufptr], bytes, num);
    outbufptr += num;

    return true;
}

int  dap_connection::check_length(int needed)
{
    if (verbose > 3) DAPLOG((LOG_DEBUG, "check_length(): %d bytes needed\n", needed));
    if (!needed) return true;


    if (buflen < bufptr+needed)
    {
        // The required buffer size
        int reqd_length = needed;
        int left = buflen - bufptr; /* what's left unread */

        /* Move what we have to the start of the buffer */
        memmove(buf, buf+bufptr, left);

        buflen = left;
        while (buflen < reqd_length)
        {
          if (verbose > 2)
            DAPLOG((LOG_DEBUG, "check_length(): reading up to %d bytes to fill record. bufptr=%d, buflen=%d\n",
                    reqd_length - buflen, bufptr, buflen));

          /* read enough to satisfy what's needed */
           int readlen = ::dnet_recv(sockfd, buf+buflen, reqd_length-buflen, MSG_EOR);
           if (readlen < 0)
           {
               sprintf(errstring, "read failed: %s", strerror(errno));
               lasterror = errstring;
               return false;
           }
           if (verbose > 2) DAPLOG((LOG_DEBUG, "check_length(): read %d bytes\n", readlen));
           buflen += readlen;
        }
        bufptr=0;
    }

    // Use this to mark the end of the current DAP message.
    // bufptr will be 0 if we read a new block and non-zero otherwise.
    end_of_msg = bufptr + needed;

    return true;
}

// Set the maximum number of bytes to be read per block.
// usually called after a CONFIG negotiation.
void dap_connection::set_blocksize(int bs)
{
    blocksize = bs;
    set_socket_buffer_size();
}

int dap_connection::get_blocksize()
{
    return blocksize;
}

// You (obviously) must call this before connecting
void dap_connection::set_connect_timeout(int seconds)
{
    connect_timeout = seconds;
}

//
// Wait for an incoming connection
// Returns a constructed new dap_connection object
// Clients may call either this or connect() BUT NOT BOTH
dap_connection *dap_connection::waitfor()
{
    int                  status;
    struct sockaddr_dn   sockaddr;
    unsigned int         len = sizeof(sockaddr);

    // Set up the listing context
    if (!listening)
    {
        set_socket_buffer_size();

        status = listen(sockfd, 5);
        if (status)
        {
            sprintf(errstring, "listen failed: %s", strerror(errno));
            lasterror = errstring;
            return NULL;
        }
        listening = true;
    }

    // Wait for a connection
    status = accept(sockfd, (struct sockaddr *)&sockaddr, &len);
    if (status < 0 && errno != EINTR)
    {
        sprintf(errstring, "accept failed: %s", strerror(errno));
        lasterror = errstring;
        return NULL;
    }

    // We were interrupted, return a NULL pointer
    if (status < 0 && errno == EINTR) return NULL;

    // Return a new connection object
    return new dap_connection(status, blocksize, verbose);
}


// Bind to an object number
bool dap_connection::bind(int object)
{
    sockaddr_dn bind_sockaddr;

    memset(&bind_sockaddr, 0, sizeof(bind_sockaddr));
    bind_sockaddr.sdn_family    = AF_DECnet;
    bind_sockaddr.sdn_flags     = 0x00;
    bind_sockaddr.sdn_objnum    = object;
    bind_sockaddr.sdn_objnamel  = 0x00;

    int status = ::bind(sockfd,  (struct sockaddr *)&bind_sockaddr,
                        sizeof(bind_sockaddr));
    if (status)
    {
        sprintf(errstring, "bind failed: %s", strerror(errno));
        lasterror=errstring;
        return false;
    }
    return true;
}

// Bind to a named object
bool dap_connection::bind(char *object)
{
    sockaddr_dn bind_sockaddr;

    memset(&bind_sockaddr, 0, sizeof(bind_sockaddr));
    bind_sockaddr.sdn_family = AF_DECnet;
    bind_sockaddr.sdn_flags     = 0x00;
    bind_sockaddr.sdn_objnum    = 0x00;

    if (strlen(object) > 16)
    {
        strcpy(errstring, "bind: object name too long");
        lasterror=errstring;
        return false;
    }
    memcpy(bind_sockaddr.sdn_objname, object, strlen(object));
    bind_sockaddr.sdn_objnamel  = dn_htons(strlen(object));

    int status = ::bind(sockfd,  (struct sockaddr *)&bind_sockaddr,
                        sizeof(bind_sockaddr));
    if (status)
    {
        sprintf(errstring, "bind failed: %s", strerror(errno));
        lasterror=errstring;
        return false;
    }
    return true;
}

// Bind to SDF_WILD
bool dap_connection::bind_wild()
{
    sockaddr_dn         bind_sockaddr;

    memset(&bind_sockaddr, 0, sizeof(bind_sockaddr));
    bind_sockaddr.sdn_family    = AF_DECnet;
#ifdef SDF_WILD
    bind_sockaddr.sdn_flags     = SDF_WILD;
#endif
    bind_sockaddr.sdn_objnum    = 0;
    bind_sockaddr.sdn_objnamel  = 0;

    int status = ::bind(sockfd,  (struct sockaddr *)&bind_sockaddr,
                        sizeof(bind_sockaddr));
    if (status)
    {
        sprintf(errstring, "bind failed: %s", strerror(errno));
        lasterror=errstring;
        return false;
    }
    return true;
}


char *dap_connection::get_error()
{
    return lasterror;
}

// Returns remaining message length
int dap_connection::get_length()
{
    return buflen-bufptr;
}

// Called in dire emergencies. Usually when the caller wants to send
// a response to an unexpected message from the remote end (eg. I ran out of
// disk space so stop sending)
void dap_connection::clear_output_buffer()
{
    if (verbose > 2) DAPLOG((LOG_INFO, "Output buffer cleared\n"));
    outbufptr = 0;
    last_msg_start = 0;
}


// Enable/disable blocked requests.
// If blocking is being switched off we may also flush the buffer if there
// is something to send.
// Clients should ALWAYS check the return from this function.
int dap_connection::set_blocked(bool onoff)
{
    if (blocked == onoff) return true; // Nothing to do

    if (!blocking_allowed) return true;  // Remote end doesn't support it

    // Enabled blocked output
    if (!blocked && onoff)
    {
        if (verbose > 2) DAPLOG((LOG_INFO, "Blocked output is ON\n"));
        blocked = true;
        return true;
    }

    // Blocking is being switched off
    blocked = false;
    if (outbufptr == 0) return true; // Nothing to send;

    if (verbose > 2)
        DAPLOG((LOG_INFO, "Blocked output is OFF, sending %d bytes\n", outbufptr));

    // Send what we have saved up.
    int er=::write(sockfd,outbuf,outbufptr);
    if (er < 0)
    {
        if (errno == ENOTCONN)
            sprintf(errstring, "write failed: %s", connerror(strerror(errno)));
        else
            sprintf(errstring, "DAP write error: %s", strerror(errno));
        lasterror = errstring;
        return false;
    }
    if (verbose > 2) DAPLOG((LOG_INFO, "wrote %d bytes\n", er));

    outbufptr = 0;
    last_msg_start = 0;
    return true;
}

// Parse a filespec into its component parts
// Input is a transparent DECnet filespec in 'fname'
// Output is a completed accessdata structure
// and filespec
//
// Automatically determine whether to use DECnet-VMS syntax:
//
//      node"username password account"::filespec
//
// or DECnet-Ultrix (and RSX-11) syntax:
//
//      node/username/password/account::filespec
//
// based on the first character following the node name.
bool dap_connection::parse(const char *fname,
                           struct accessdata_dn &accessdata,
                           char *node, char *filespec)
{
    enum  {NODE, USER, PASSWORD, ACCOUNT, NAME, FINISHED} state;
    int   n0=0;
    int   n1=0;
    char  sep, term;

    if (!fname) return false;

    memset(&accessdata, 0, sizeof(struct accessdata_dn));

    state = NODE; /* Node is mandatory */

    while (state != FINISHED)
    {
        switch (state)
        {
        case NODE:
            if (fname[n0] != ':' && fname[n0] != '\"' &&
                fname[n0] != '\'' && fname[n0] != '/')
            {
                if (n1 >= MAX_NODE ||
                    fname[n0] == ' ' || fname[n0] == '\n')
                {
                    lasterror = (char *)"File name parse error";
                    return false;
                }
                node[n1++] = fname[n0++];
            }
            else
            {
                node[n1] = '\0';
                n1 = 0;
                switch (fname[n0])
                {
                case '\"':
                case '\'':
                    sep = ' ';
                    term = fname[n0++];
                    state = USER;
                    break;

                case '/':
                    sep = '/';
                    term = 0;
                    n0++;
                    state = USER;
                    break;

                default:
                    n0 += 2;
                    state = NAME;
                    break;
                }
            }
            break;

        case USER:
            if (fname[n0] != sep && fname[n0] != (term ? term : ':'))
            {
                if (n1 >= MAX_USER)
                {
                    lasterror = (char *)"File name parse error";
                    return false;
                }
                accessdata.acc_user[n1++] = fname[n0++];
            }
            else
            {
                accessdata.acc_user[n1] = '\0';
                n1 = 0;
                if (fname[n0] == sep)
                {
                    state = PASSWORD;
                    n0++;
                }
                else
                {
                    state = NAME;
                    n0 += term ? 3 : 2;
                }
            }
            break;

        case PASSWORD:
            if (fname[n0] != sep && fname[n0] != (term ? term : ':'))
            {
                if (n1 >= MAX_PASSWORD)
                {
                    lasterror = (char *)"File name parse error";
                    return false;
                }
                accessdata.acc_pass[n1++] = fname[n0++];
            }
            else
            {
                accessdata.acc_pass[n1] = '\0';
                n1 = 0;
                if (fname[n0] == sep)
                {
                    state = ACCOUNT;
                    n0++;
                }
                else
                {
                    state = NAME;
                    n0 += term ? 3 : 2;
                }
            }
            break;
                
        case ACCOUNT:
            if (fname[n0] != sep && fname[n0] != (term ? term : ':'))
            {
                if (n1 >= MAX_ACCOUNT)
                {
                    lasterror = (char *)"File name parse error";
                    return false;
                }
                accessdata.acc_acc[n1++] = fname[n0++];
            }
            else
            {
                accessdata.acc_acc[n1] = '\0';
                n1 = 0;
                state = NAME;
                n0 += term ? 3 : 2;
            }
            break;

        case NAME:
            strcpy(filespec, fname+n0);
            state = FINISHED;
            break;

        case FINISHED:
            break;
        }
    }

    /* tail end validation */
    binadr = getnodebyname(node);
    if (!binadr)
    {
        lasterror = (char *)"Unknown or invalid node name ";
        return false;
    }

    /* Complete the accessdata structure */
    accessdata.acc_userl = strlen((char *)accessdata.acc_user);
    accessdata.acc_passl = strlen((char *)accessdata.acc_pass);
    accessdata.acc_accl  = strlen((char *)accessdata.acc_acc);
    return true;
}


// When talking to small systems that don't support blocking we can disable
// it altogether.
void dap_connection::allow_blocking(bool onoff)
{
    blocking_allowed = onoff;
}

// Send a CRC
int dap_connection::send_crc(unsigned short crc)
{
    char crcbuf[2] = {(char)(crc&0xff), (char)(crc>>8)};

    return putbytes(crcbuf,2);
}

// A couple of general utility methods:
void dap_connection::makelower(char *s)
{
    for (unsigned int i=0; s[i]; i++) s[i] = tolower(s[i]);
}

void dap_connection::makeupper(char *s)
{
    for (unsigned int i=0; s[i]; i++) s[i] = toupper(s[i]);
}

// Always returns false. Sets the error string to strerror(errno)
bool dap_connection::error_return(char *txt)
{
    sprintf(errstring, "%s: %s", txt, strerror(errno));
    lasterror = errstring;
    return false;
}

// Exchange CONFIG messages with the other side.
bool dap_connection::exchange_config()
{
// Send our config message
    dap_config_message *newcm = new dap_config_message(MAX_READ_SIZE);
    if (!newcm->write(*this)) return false;
    delete newcm;

// Read the other end's config message
    dap_message *m=dap_message::read_message(*this, true);
    if (!m) // Comms error
    {
        DAPLOG((LOG_ERR, "%s\n", get_error()));
        return false;
    }

// Check it's OK and set the connection buffer size
    dap_config_message *cm = (dap_config_message *)m;
    if (m->get_type() == dap_message::CONFIG)
    {
        cm = (dap_config_message *)m;

        if (verbose > 1)
            DAPLOG((LOG_DEBUG, "Remote buffer size is %d\n", cm->get_bufsize()));

        // Blocksize of zero means we can do what we like!
        if (cm->get_bufsize() == 0)
            set_blocksize(MAX_READ_SIZE);
        else
            set_blocksize(min(MAX_READ_SIZE, cm->get_bufsize()));
        if (verbose > 1)
            DAPLOG((LOG_DEBUG, "Using block size %d\n", get_blocksize()));

        remote_os = cm->get_os();
        if (verbose > 1)
        {
            DAPLOG((LOG_DEBUG, "Remote OS is %d\n", remote_os));
            DAPLOG((LOG_DEBUG, "Remote version is %d.%d.%d\n",
                    cm->get_vernum(), cm->get_econum(), cm->get_usrnum()));
        }
    }
    else
    {
        return false;
    }
    delete m;

    return true;
}

// Return the text of a connection error
const char *dap_connection::connerror(char *default_msg)
{
#ifdef DSO_CONDATA
    struct optdata_dn optdata;
    unsigned int len = sizeof(optdata);
    const char *msg;

    if (getsockopt(sockfd, DNPROTO_NSP, DSO_DISDATA,
                   &optdata, &len) == -1)
    {
        return default_msg;
    }

    // Turn the rejection reason into text
    switch (optdata.opt_status)
    {
    case DNSTAT_REJECTED: msg="Rejected by object";
        break;
    case DNSTAT_RESOURCES: msg="No resources available";
        break;
    case DNSTAT_NODENAME: msg="Unrecognised node name";
        break;
    case DNSTAT_LOCNODESHUT: msg="Local Node is shut down";
        break;
    case DNSTAT_OBJECT: msg="Unrecognised object";
        break;
    case DNSTAT_OBJNAMEFORMAT: msg="Invalid object name format";
        break;
    case DNSTAT_TOOBUSY: msg="Object too busy";
        break;
    case DNSTAT_NODENAMEFORMAT: msg="Invalid node name format";
        break;
    case DNSTAT_REMNODESHUT: msg="Remote Node is shut down";
        break;
    case DNSTAT_ACCCONTROL: msg="Login information invalid at remote node";
        break;
    case DNSTAT_NORESPONSE: msg="No response from object";
        break;
    case DNSTAT_NODEUNREACH: msg="Node Unreachable";
        break;
    case DNSTAT_MANAGEMENT: msg="Abort by management/third party";
        break;
    case DNSTAT_ABORTOBJECT: msg="Remote object aborted the link";
        break;
    case DNSTAT_NODERESOURCES: msg="Node does not have sufficient resources for a new link";
        break;
    case DNSTAT_OBJRESOURCES: msg="Object does not have sufficient resources for a new link";
        break;
    case DNSTAT_BADACCOUNT: msg="The Account field in unacceptable";
        break;
    case DNSTAT_TOOLONG: msg="A field in the access control message was too long";
        break;
    default: msg=default_msg;
        break;
    }
    return msg;
#else
    return default_msg;
#endif
}
