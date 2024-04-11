/******************************************************************************
    (c) 2002-2008      Christine Caulfield          christine.caulfield@googlemail.com

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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <ctype.h>
#include <termios.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/fcntl.h>
#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>
#include "dn_endian.h"
#include "dnlogin.h"

// If we don't have MSG_NOSIGNAL, ignore it for now
// TODO: is this correct to just ignore it?
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* Foundation services messages */
#define FOUND_MSG_BIND        1
#define FOUND_MSG_UNBIND      2
#define FOUND_MSG_BINDACCEPT  4
#define FOUND_MSG_ENTERMODE   5
#define FOUND_MSG_EXITMODE    6
#define FOUND_MSG_CONFIRMMODE 7
#define FOUND_MSG_NOMODE      8
#define FOUND_MSG_COMMONDATA  9
#define FOUND_MSG_MODEDATA   10


static const char *hosttype[] = {
        "RT-11",
        "RSTS/E",
        "RSX-11S",
        "RSX-11M",
        "RSX-11D",
        "IAS",
        "VMS",
        "TOPS-20",
        "TOPS-10",
        "OS8",
        "RTS-8",
        "RSX-11M+",
        "DEC Unix", "??14", "??15", "??16", "??17",
        "Ultrix-32",
        "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
        "", "",
        "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
        "", "",
        "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
        "", "",
        "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
        "", "",
        "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
        "", "",
        "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
        "", "",
        "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
        "", "",
        "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
        "", "",
        "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
        "Unix-dni", "Linux"
};


/* Header for a single-message "common data" message */
struct common_header
{
        char msg;
        char pad;
        unsigned short len;
};


static int sockfd = -1;
static int (*terminal_processor)(char *, int);

static int send_bindaccept(void)
{
        int wrote;
        char bindacc_msg[] =
                {
                        FOUND_MSG_BINDACCEPT,
                        2,4,0,          /* Version triplet */
                        193,0,          /* OS = Linux */
                        0,0,0,0,        /* Empty rev string */
                        0,0,0,0,
                        0,0,            /* No logical terminal ID */
                        0               /* No options set */
                };

        wrote = write(sockfd, bindacc_msg, sizeof(bindacc_msg));
        if (wrote != sizeof(bindacc_msg))
        {
                fprintf(stderr, "%s\n", found_connerror());
                return -1;
        }
        return 0;
}


int found_getsockfd()
{
        return sockfd;
}

/* Write "Common data" with a foundation header */
int found_common_write(char *buf, int len)
{
        struct iovec vectors[2];
        struct msghdr msg;
        struct common_header header;

        DEBUG_FOUND("sending %d bytes\n", len);
        if (debug & DEBUG_FLAG_FOUND2)
        {
                int i;
                DEBUG_FOUND2("sending: ");
                for (i=0; i<len; i++)
                        DEBUGLOG(DEBUG_FLAG_FOUND2, "%02x  ", (char)buf[i]);
                DEBUGLOG(DEBUG_FLAG_FOUND2, "\n\n");
        }


        memset(&msg, 0, sizeof(msg));
        vectors[0].iov_base = (void *)&header;
        vectors[0].iov_len  = sizeof(header);
        vectors[1].iov_base = buf;
        vectors[1].iov_len  = len;

        msg.msg_name    = NULL;
        msg.msg_namelen = 0;
        msg.msg_iovlen  = 2;
        msg.msg_iov     = vectors;
        msg.msg_flags   = 0;

        header.msg = FOUND_MSG_COMMONDATA;
        header.pad = 0;
        header.len = dn_htons(len);

        DEBUG_FOUND("sending common message %d bytes:\n", len);

        return sendmsg(sockfd, &msg, MSG_EOR);
}

int found_read()
{
        int len;
        char inbuf[1024];

        if ( (len=dnet_recv(sockfd, inbuf, sizeof(inbuf), MSG_EOR|MSG_DONTWAIT|MSG_NOSIGNAL)) <= 0)

        {
                if (len == -1 && (errno == EAGAIN || errno == ESPIPE))
                        return 0;
                /* Remote end shut down */
                if (len == 0)
                        return -1;
                if (len == -1 && errno == EPIPE) /* Old kernel bug */
                        return -1;

                if (len < 0 && errno != EINVAL)/* Shurely shome mishtake */
                        fprintf(stderr, "%s\n", strerror(errno));
                return -1;
        }

        DEBUG_FOUND("got message %d bytes:\n", len);
        if (debug & DEBUG_FLAG_FOUND2)
        {
                int i;

                DEBUG_FOUND2("read: ");
                for (i=0; i<len; i++)
                        DEBUGLOG(DEBUG_FLAG_FOUND2,  "%02x  ", (char)inbuf[i]);
                DEBUGLOG(DEBUG_FLAG_FOUND2, "\n\n");
        }


        /* Dispatch foundation messages */
        switch (inbuf[0])
        {
        case FOUND_MSG_BIND:
                DEBUG_FOUND("connected to %s host\n", hosttype[inbuf[4]-1]);
                return send_bindaccept();

        case FOUND_MSG_UNBIND:
                DEBUG_FOUND("Unbind from host. reason = %d\n", inbuf[1]);
                return -1;

        case FOUND_MSG_ENTERMODE:
        {
                char nomode_msg[] = {0x8};
                DEBUG_FOUND("Request to enter mode = %d\n", inbuf[1]);
                write(sockfd, nomode_msg, sizeof(nomode_msg));
                return 0;
        }

        /* Common data goes straight to the terminal processor */
        case FOUND_MSG_COMMONDATA:
        {
                int ptr = 2;
                while (ptr < len)
                {
                        int msglen = inbuf[ptr] | inbuf[ptr+1]<<8;

                        DEBUG_FOUND("commondata: %d bytes\n",msglen);

                        ptr += 2;
                        terminal_processor(inbuf+ptr, msglen);
                        ptr += msglen;
                }
        }
        break;

        case 3: /* Reserved */
                break;

        default:
                fprintf(stderr, "Unknown foundation services message %d received\n",
                        inbuf[0]);
        }
        return 0;
}

/* Open the DECnet connection */
int found_setup_link(char *node, int object, int (*processor)(char *, int), 
                     int connect_timeout)
{
        struct nodeent *np;
        struct sockaddr_dn sockaddr;
        struct accessdata_dn accessdata;
        char *local_user;
        struct timeval timeout = {connect_timeout,0};

        if ( (np=getnodebyname(node)) == NULL)
        {
                printf("Unknown node name %s\n",node);
                return -1;
        }


        if ((sockfd = socket(AF_DECnet, SOCK_SEQPACKET, DNPROTO_NSP)) == -1)
        {
                perror("socket");
                return -1;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)))
                perror("setting snd timeout");

        /* Send the logged in userID for niceness sake */
        memset(&accessdata, 0, sizeof(accessdata));
        local_user = cuserid(NULL);
        if (!local_user || local_user == (char *)0xffffffff)
                local_user = getenv("LOGNAME");

        if (!local_user) local_user = getenv("USER");
        if (local_user)
        {
                strcpy((char *)accessdata.acc_acc, local_user);
                accessdata.acc_accl = strlen((char *)accessdata.acc_acc);
                setsockopt(sockfd, DNPROTO_NSP, SO_CONACCESS, &accessdata,
                           sizeof(accessdata));
        }

        sockaddr.sdn_family = AF_DECnet;
        sockaddr.sdn_flags = 0x00;
        sockaddr.sdn_objnum = object;

        sockaddr.sdn_objnamel = 0x00;
        sockaddr.sdn_add.a_len = 0x02;

        memcpy(sockaddr.sdn_add.a_addr, np->n_addr, 2);

        if (connect(sockfd, (struct sockaddr *) &sockaddr, sizeof(sockaddr)) < 0)
        {
                fprintf(stderr, "Cannot connect to %s: %s\n", node, found_connerror());
                return -1;
        }

        terminal_processor = processor;
        return 0;
}


/* Return the text of a connection error */
char *found_connerror()
{
        int saved_errno = errno;
#ifdef DSO_DISDATA
        struct optdata_dn optdata;
        unsigned int len = sizeof(optdata);
        char *msg;

        if (errno == ETIMEDOUT ||
            getsockopt(sockfd, DNPROTO_NSP, DSO_CONDATA, &optdata, &len) == -1)
        {
                return strerror(saved_errno);
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
        default: msg=strerror(saved_errno);
                break;
        }
        return msg;
#else
        return strerror(saved_errno);
#endif
}
