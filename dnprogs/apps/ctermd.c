/******************************************************************************
    (c) 1995-2002 E.M. Serrat             emserrat@geocities.com

    Conversion to dnetd (c) 1999 by Christine Caulfield

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
*******************************************************************************/

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <syslog.h>
#include <ctype.h>
#include <regex.h>
#include <stdlib.h>
#include <utmp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>
#ifdef DNETUSE_DEVPTS
#include <pty.h>
#endif

#include "dn_endian.h"

static  struct  sockaddr_dn             sockaddr;
static  char                            *line;
static  int                             s,t,net,pty,len;
static  int                             read_present;
/*-----------------------------------------------------------------------*/
void cterm_child(int s)
{
        int     sts;
        wait (&sts);
}
/*-----------------------------------------------------------------------*/
void cterm_setchar(void)
{
        char    cterm_setchar_msg[] = { 0x09,0x00,      /* common data  */
                                        0x0d,0x00,      /* Length       */
                                        0x0b,0x00,
                                        0x06,0x02,      /* Input ESC seq*/
                                                        /* Recognition  */
                                        0x01,
                                        0x07,0x02,      /*output ESC seq*/
                                                        /* Recognition  */
                                        0x01,

                                        0x02,0x02,0x19,
                                        0xff,0x00
                                      };

        if (write(net,cterm_setchar_msg,sizeof(cterm_setchar_msg)) <  0)
        {
                perror("Cterm setchar");
                exit(-1);
        }
}
/*-----------------------------------------------------------------------*/
void cterm_bind(void)
{
        char    cterm_bind_msg[] = {0x01,0x02,0x04,0x00,0x07,0x00,0x10,0x00};
        char    cterm_init_msg[] = {0x09,0x00,          /* common data */
                                    0x1b,0x00,          /* Block length*/
                                    0x01,0x00,          /* init messg */
                                    0x01,0x04,0x00,     /* Version     */
                                    0,0,0,0,0,0,0,0,    /* descrip     */
                                    0x01,0x02,0x00,0x02,
                                    0x02,0x02,0xf4,0x03,
                                    0x03,0x04,0xfe,0x7f,0x00,0x00};
        char    buf[512];

        if (write(net,cterm_bind_msg,sizeof(cterm_bind_msg)) < 0)
        {
                perror("Cterm bind request failed");
                exit (-1);
        }

        if (read(net,buf,sizeof(buf)) < 0)
        {
                perror("Cterm bind accept failed");
                exit (-1);
        }

        if (buf[0] != 0x04)
        {
                printf("Error Setting up cterm link\n");
                exit(-1);
        }

        if (write(net,cterm_init_msg,sizeof(cterm_init_msg)) < 0)
        {
                perror("Cterm init message failed");
                exit (-1);
        }
        if (read(net,buf,sizeof(buf)) < 0)
        {
                perror("Cterm init receive failed");
                exit (-1);
        }
        cterm_setchar();
}
/*-----------------------------------------------------------------------*/
void cterm_unbind (void)
{
        char    cterm_unbind_msg[3] = {0x02,0x03,0x00};
        write(net,cterm_unbind_msg,3);
}
/*-----------------------------------------------------------------------*/
void cterm_reset(int s)
{
        struct  utmp    entry;
        struct  utmp    *lentry;
        char    *p;

        cterm_unbind();
        sleep(1); /* ugh!. Wait for data-ack to arrive */
#ifndef DNETUSE_DEVPTS
        p=line+sizeof("/dev/")-1;

        setutent();
        memcpy(entry.ut_line,p,strlen(p));
        entry.ut_line[strlen(p)]='\0';
        lentry=getutline(&entry);
        lentry->ut_type=DEAD_PROCESS;

        memset(lentry->ut_line,0,UT_LINESIZE);
        memset(lentry->ut_user,0,UT_NAMESIZE);
        lentry->ut_time=0;
        pututline(lentry);

        (void)chmod(line,0666);
        (void)chown(line,0,0);
        *p='p';
        (void)chmod(line,0666);
        (void)chown(line,0,0);
#endif
        close(pty);
        close(net);
        exit(1);
}
/*-----------------------------------------------------------------------*/
void cterm_purge(void)
{
        char    buf[4000];
        char    Control_c = 0x03;
        long    numbytes;

        write(pty,&Control_c,1);
        ioctl(pty,FIONREAD,&numbytes);
        while (numbytes)
        {
                read(pty,buf,numbytes);
                ioctl(pty,FIONREAD,&numbytes);
        }
}
/*-----------------------------------------------------------------------*/
void cterm_unread (void)
{
        char    cterm_unread_msg[] = {  0x09,0x00,0x02,0x00,0x05,0x00 };
        write(net,cterm_unread_msg,sizeof(cterm_unread_msg));
        read_present=0;
}
/*-----------------------------------------------------------------------*/
void cterm_read (void)
{
        char    cterm_stread_msg[] = {  0x09,0x00,0x31,0x00,
                                        0x02,
                                        0x40,0x4A,0x02,
                                        0xa0,0x00,0x00,0x00,
                                        0x00,0x00,0x00,0x00,
                                        0x00,0x00,0x00,0x00,
                                        0x20,
                                        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                                        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                                        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                                        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
                                     };
        write(net,cterm_stread_msg,sizeof(cterm_stread_msg));
        read_present=1;
}
/*-----------------------------------------------------------------------*/
void cterm_write (char *buf)
{
        char    cterm_write_msg[] = {   0x09,0x00,
                                        0x00,0x00,
                                        0x07,0x30,0x00,0x00,0x00};
        char    lclbuf[1400];
        short   *blklen;
        int     wrtlen;
        int     l;

        memcpy(&lclbuf[0],cterm_write_msg,9);
        blklen=(short *)&lclbuf[2];
        l = 5 + strlen(buf);
        lclbuf[2] = l & 0xFF;
        lclbuf[3] = (l>>8) & 0xFF;

        memcpy(&lclbuf[9],buf,strlen(buf));
        wrtlen=strlen(buf)+9;

        if (write(net,lclbuf,wrtlen) < 0)
        {
                perror("cterm_write");
                exit(-1);
        }

}
/*-----------------------------------------------------------------------*/
void cterm (void)
{
        char     buf[100];
        fd_set   rdfs;
        int      cnt;
        struct   sigaction siga;
        sigset_t ss;

        setsid();

        sigemptyset(&ss);
        siga.sa_handler=cterm_reset;
        siga.sa_mask  = ss;
        siga.sa_flags = 0;
        sigaction(SIGCHLD, &siga, NULL);

        signal(SIGTSTP, SIG_IGN);
        signal(SIGTTOU, SIG_IGN);

        cterm_write("CTERM Version 1.0.6\r\nDECnet for Linux\r\n\n");
        cterm_read();

        for (;;)
        {
                FD_ZERO(&rdfs);
                FD_SET(pty,&rdfs);
                FD_SET(net,&rdfs);

                 if (select(FD_SETSIZE,&rdfs,NULL,NULL, NULL) > 0)
                 {
                  if (FD_ISSET(pty,&rdfs))
                  {
                        cnt=read(pty,buf,sizeof(buf)-1);
                        if (cnt <= 0) break;
                        buf[cnt]='\0';
                        cterm_write(buf);
                   }

                   if (FD_ISSET(net,&rdfs))
                   {
                        cnt=read(net,buf,sizeof(buf));
                        if (cnt <= 0) break;

                        switch (buf[4])
                        {
                        case 0x03:
                                if ( (buf[12] == 0x19) || (buf[12] == 3) )
                                {
                                        buf[12]=0x03;
                                        cterm_purge();
                                }
                                write(pty,&buf[12],cnt-12);
                                cterm_read();
                                break;
                        case 0x04:
                                if ( (buf[6] == 0x19) || (buf[6] == 3) )
                                {
                                        buf[6]=0x03;
                                        cterm_purge();
                                }
                                write(pty,&buf[6],1);
                                cterm_read();
                        }
                     }
                    }
        }
        cterm_reset(0);
}
/*-----------------------------------------------------------------------*/
void doit  (void)
{
        int     i,c;
        struct  stat    stb;
        char    ptyname[] = "/dev/ptyCP";
        int     gotpty =0;

        cterm_bind();

#ifdef DNETUSE_DEVPTS
        if (openpty(&pty, &t,NULL, NULL, NULL) == 0)
          gotpty = 1;
        else
        {
            cterm_write("No ptys available for connection");
            exit(-1);
        }
#else
        for (c='p'; c <= 'z'; c++)
        {
                line = ptyname;
                line[strlen("/dev/pty")] = c;
                line[strlen("/dev/ptyC")] = '0';
                if (stat(line,&stb) < 0)
                        break;
                for (i=0; i < 16; i++)
                {
                        line[strlen("/dev/ptyC")]= "0123456789abcdef"[i];
                        if ( (pty=open(line,O_RDWR)) > 0)
                        {
                                gotpty = 1;
                                break;
                        }
                }
                if (gotpty) break;
        }
        if (!gotpty)
        {
                cterm_write("No ptys available for connection");
                exit(-1);
        }


        line[strlen("/dev/")] = 't';
        if ( (t=open(line,O_RDWR)) < 0)
        {
                cterm_write("Error connecting to physical terminal");
                exit(-1);
        }
#endif
        if ( fchmod(t,0) )
        {
                cterm_write("Error setting terminal mode");
                exit(-1);
        }

        if ( ( i=fork() ) < 0)
        {
                cterm_write("Error forking");
                exit(-1);
        }
        if (i)
        {
                cterm();
        }

        setsid();

        close(pty); close(net);
        if (t != 0) dup2 (t,0);
        if (t != 1) dup2 (t,1);
        if (t != 2) dup2 (t,2);

        if (t > 2) close(t);

        ioctl(0, TIOCSCTTY, (char *)NULL);


        putenv("TERM=vt100");
        execlp("/bin/login", "login", (char *)0);
        cterm_write("Error executing login command");
        exit(-1);
}

void usage(char *prog, FILE *f)
{
    fprintf(f,"\n%s options:\n", prog);
    fprintf(f," -v        Verbose messages\n");
    fprintf(f," -h        Show this help text\n");
    fprintf(f," -d        Run in debug mode - don't do initial fork\n");
    fprintf(f," -l<type>  Logging type(s:syslog, e:stderr, m:mono)\n");
    fprintf(f," -V        Show version number\n\n");
}


/*-----------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
    int verbosity;
    int debug = 0;
    char log_char = 's';
    char opt;

    /* Deal with command-line arguments.*/
    opterr = 0;
    optind = 0;
    while ((opt=getopt(argc,argv,"?vVdhl:")) != EOF)
    {
        switch(opt)
        {
        case 'h':
            usage(argv[0], stdout);
            exit(0);

        case '?':
            usage(argv[0], stderr);
            exit(0);

        case 'v':
            verbosity++;
            break;

        case 'd':
            debug++;
            break;

        case 'V':
            printf("\nctermd from dnprogs version %s\n\n", VERSION);
            exit(1);
            break;

        case 'l':
            if (optarg[0] != 's' &&
                optarg[0] != 'm' &&
                optarg[0] != 'e')
            {
                usage(argv[0], stderr);
                exit(2);
            }
            log_char = optarg[0];
            break;

        }
    }

    /* Initialise logging */
    init_daemon_logging("ctermd", log_char);

    net = dnet_daemon(DNOBJECT_CTERM, NULL, verbosity, !debug);

    if (net > -1)
    {
        dnet_accept(net, 0, NULL, 0);
        doit();
    }
    return 0;
}
/*-------------------------------------------------------------------------*/

