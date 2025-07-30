/*---------------------------------------------------------------------------

	Program:	SETHOST
	Function:	Terminal emulation using CTERM over DECnet
	Author:		Eduardo Marcelo Serrat
	Modified by:    Christine James Caulfield
	                Made endian and alignment-independant
			Paul Koning:
			Support for other than VMS servers.
                        ECalderon:

-----------------------------------------------------------------------------*/

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <ctype.h>
#include <termios.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/fcntl.h>
#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>
#include "cterm.h"
#include "dn_endian.h"

#define	TRUE	1
#define FALSE	0

typedef enum { CTERM, RSTS, RSX, VMS, TOPS20 } term_flavor;

struct	sockaddr_dn		sockaddr;
struct	accessdata_dn		accessdata;
struct	termios			raw,cooked;
struct	logical_terminal_characteristics
				log_char = {FALSE,3,{5,'V','T','2','0','0'}
					    ,TRUE,
					    TRUE,TRUE,TRUE,TRUE,80,24,0,0,
					    0,1,1,1,1};
struct	physical_terminal_characteristics
				phy_char = {9600,9600,8,FALSE,1,FALSE,FALSE,
					    FALSE,0,0,FALSE,FALSE};
struct	handler_maintained_characteristics
				han_char = {FALSE,FALSE,FALSE,TRUE,TRUE,TRUE,
					    1,FALSE,FALSE};
unsigned char			char_attr[256];

char				*nodename;
unsigned char			inpbuf[132],buf[1600], ahead[32];
short				bufptr,blklen,cnt;
static int			sockfd, ttyfd;
static int			rptr=0,wptr=0,
				aheadcnt=0,inpcnt=0,inpptr=0;
static short			wrpflg=FALSE, read_present=FALSE,lockflg=FALSE,
				discard=FALSE,unbind=FALSE,hold=FALSE,
				redisplay=FALSE,output_lost=FALSE,
				uu,c,f,v,k,ii,ddd,n,t,q,zz,ee,
				max_len,end_of_data,timeout,end_of_prompt,
				start_of_display,low_water,escseq=FALSE,
				esclen=0;
static	struct	nodeent		*np;
unsigned char			term_tab[32];
term_flavor			flavor;

unsigned char exit_char = 0x1D;

unsigned char escbuf[32];
static int      debug=0; /*ed*/
unsigned char tty; /*moved from dterm_bind_reply ed*/
static int htype; /*ed*/

static void (*kb_handler)(int);

/* Routines in this program:
static void usage(char *prog, FILE *f)
void set_exit_char(char *string)
static inline void set_short(short *dest, short src)
static void ct_reset_term(void)
short	escseq_terminator(char car)
static void ct_terminate_read(char flgs)
static	short	ct_is_terminator(char car)
static void ct_timeout_proc(int x)
static void ct_echo_input_char(char *c)
static void ct_echo_input_char(char *c)
static void ct_input_proc (char car)
static int	ct_out_of_band (int car)
static void	ct_setup(void)
static unsigned char	read_ahead(void)
static int	insert_ahead(char c)
static void dterm_bind_reply (void)
static void	ct_setup_link(void)
static void	ct_init_term(void)
static void ct_preinput_proc(int x)
static void rsts_preinput_proc(int x)
static void rsx_preinput_proc(int x)
static void tops_preinput_proc(int x)
static void ct_print_char(char *c)
static void ct_echo_prompt(char *c)
static void ct_read_req(void)
static void ct_unread_req(void)
static void ct_clearinput_req(void)
static void ct_write_req(void)
static void ct_readchar_req(void)
static void ct_writechar_req(void)
static void ct_checkinput_req(void)
static void ct_read_pkt(void)
static void proc_rsts_pkt(void)
static void proc_rsx_pkt(void)
static void proc_tops_pkt(void)
static void proc_cterm_pkt (void)
static void ct_proc_pkt(void)
int main(int argc, char *argv[])
*/
/*-------------------------------------------------------------------------*/
static void usage(char *prog, FILE *f)

{
    if (debug == 2) { printf(" Entered static void usage...\n");}

    fprintf(f, "\nUSAGE: %s [OPTIONS] node\n\n", prog);

    fprintf(f,"\nOptions:\n");
    fprintf(f,"  -? -h        display this help message\n");
    fprintf(f,"  -V           show version number\n");
    fprintf(f,"  -e <char>    set escape char\n");
    fprintf(f,"  -d           debug information\n");
    fprintf(f,"  -t           trace procedure entry\n");

    fprintf(f,"\n");
}
/*-------------------------------------------------------------------------*/
void set_exit_char(char *string)
{
  int newchar = 0;
  if (debug == 2) { printf(" Entered void set_exit_char...\n");}
  if (string[0] == '^')
  {
      newchar = toupper(string[1]) - '@';
  }
  else
      newchar = strtol(string, NULL, 0); /* Just a number */

  /* Make sure it's reasonable */
  if (newchar > 0 && newchar < 256) exit_char = newchar;

}

/*-------------------------------------------------------------------------*/
static inline void set_short(short *dest, short src)
{       if (debug == 2) { printf(" Entered inline void set_short...\n");}
/* I've assumed that BIG-ENDIAN means SPARC in this context and that SPARCs
   are fussy about alignment.
   Anything little-endian is assumed non-fussy.
*/
#if __BYTE_ORDER != 1234
    swab((void *)&src, (void *)dest, 2);
#else
    *dest = src;
#endif

}
/*-------------------------------------------------------------------------*/
static void ct_reset_term(void)
{       if (debug == 2) { printf(" Entered static void ct_reset_term...\n");}
	if (tcsetattr(ttyfd, TCSANOW, &cooked) < 0)
	{
		perror("tcsetattr");
		exit(-1);
	}
	close(ttyfd);
}
/*-------------------------------------------------------------------------*/
short	escseq_terminator(char car)
{
	char	escend [23] = {'A','B','C','D','M','P','Q','R','S',
			     'l','m','n','p','q','r','s','t','u','v',
			     'w','x','Y','~'};

	int	i;

        if (debug == 2) { printf(" Entered short escseq_terminator...\n");}
	for (i=0; i < 23; i++) if (car==escend[i]) return 1;
	return 0;
}
/*-------------------------------------------------------------------------*/
static void ct_terminate_read(char flgs)
{
	char	readbuf[132];
	char	t;
	short	*p;
	int	i;
        if (debug == 2) { printf(" Entered static void ct_terminate_read...\n");}

	read_present = FALSE;
	alarm(0);

	readbuf[0] = 0x09;
	readbuf[1] = 0x00;
	readbuf[4] = 0x03;
	if (aheadcnt > 0) t = 0x10;
	else		  t = 0x00;
	readbuf[5] = flgs | t;
	readbuf[6] = readbuf[7] = 0x00;
	readbuf[8] = 0x00;
	readbuf[9] = 0x00;
	p=(void *)&readbuf[10];
	if (inpcnt > 0) set_short(p, inpcnt - 1);
	else            set_short(p, 0);
	if (escseq)
	{
		set_short(p, inpcnt - esclen);
		esclen=escseq=0;
	}

	for (i=0; i < inpcnt; i++)
	{
		readbuf[i+12] = inpbuf[end_of_prompt + i];
	}
	p=(void *)&readbuf[2];
	set_short(p, inpcnt + 8);

	if (write(sockfd,readbuf,inpcnt+12) < 0)
	{
		perror("Terminate Read message");
		ct_reset_term();
		exit(-1);
	}
	inpcnt=inpptr=0;
}
/*-------------------------------------------------------------------------*/
static	short	ct_is_terminator(char car)
{
	short	termind,msk,aux;
        if (debug == 2) { printf(" Entered static short ct_is_terminator...\n");}
        /*printf(" Htype = %d",htype); ed*/
        if (( htype == 12 ) && (car > 97) && (car < 123) ) { car = car - 32;}
        if (debug == 1) {printf(" car = %d\n",car);} /*ed*/
	termind=car / 8;
	aux = car - (termind * 8);
	msk= (1 << aux);

	if (term_tab[termind] && msk) return 1;
	return 0;
}

/*-------------------------------------------------------------------------*/
static void ct_timeout_proc(int x)
{       if (debug == 2) { printf(" Entered static void ct_timeout_proc...\n");}
	ct_terminate_read(5);
}
/*-------------------------------------------------------------------------*/
static void ct_echo_input_char(char *c)
{
	char	car;
        if (debug == 2) { printf(" Entered static void ct_echo_input_char...\n");}

	if ((n) || ((t==0) && ct_is_terminator(*c))) return;
	while (lockflg||hold) ;
	if (ii==2)
	{
		car=toupper(*c);
		write(ttyfd,&car,1);
		*c=car;
	}
	else
		write(ttyfd,c,1);
}
/*-------------------------------------------------------------------------*/
static void ct_input_proc (char car)
{
	char	clrchar[3] = {0x08,0x20,0x08};
        if (debug == 2) { printf(" Entered static void ct_input_proc...\n");}

	if ((car == DEL) && ( (zz == 2) || (!ct_is_terminator(car))))
	{
		if (inpcnt > 0)
		{
			inpcnt -= 1;
			inpptr -= 1;
			if (n==0)
				write(ttyfd,&clrchar,3);
		}
		return;
	}
/*
	if ((zz == 2 ) && (car == ESC) && (han_char.input_escseq_recognition))
*/
	if (car == ESC)
		escseq=TRUE;
	if (!escseq)
		ct_echo_input_char(&car);

	inpbuf[inpptr++]=car;
	inpcnt += 1;
	if (inpcnt == max_len) ct_terminate_read(4);
	if (escseq)
	{
		esclen += 1;

		if (escseq_terminator(car))  ct_terminate_read(1);
		return;
	}
	if (zz==2)
	{
		if  (car < 0x1B)
		ct_terminate_read(0);
	}
	else
	{
		if (ct_is_terminator(car)) ct_terminate_read(0);
	}
}
/*-------------------------------------------------------------------------*/
static int	ct_out_of_band (int car)
{
	char	msg[7] = {0x09,0x00,0x03,0x00,0x04,0x00,0x00};
	char	oo,d,i,ee,f;
	if (debug == 2) { printf(" Entered static int ct_out_of_band...\n");}

	if (flavor != CTERM) return 0;

	oo=char_attr[car] & 0x03;
	i =(char_attr[car] & 0x04) >> 2;
	d =(char_attr[car] & 0x08) >> 3;
	ee=(char_attr[car] & 0x30) >> 4;
	f =(char_attr[car] & 0x40) >> 6;

	if (oo==0) return 0;
	msg[5]=d;
	msg[6]=car;
	if (write(sockfd,msg,7) < 0)
	{
		perror("Out of band Msg");
		ct_reset_term();
		exit(-1);
	}
	if (d) discard=TRUE;
	if (ee)
	{
		if ( (car==CTRL_C) || (car==CTRL_Y) )
			write(ttyfd,"\n*Interrupt*\n",13);
	}
	if (oo==1)
		aheadcnt=rptr=wptr=wrpflg=0;
	if (oo==3)
		redisplay=TRUE;
	if ((oo==3) && (i==1)) return 0;

	return 1;

}
/*-------------------------------------------------------------------------*/
/*-------------------------------------------------------------------------*/
/*-------------------------------------------------------------------------*/
/*-------------------------------------------------------------------------*/
/*-------------------------------------------------------------------------*/
static void	ct_setup(void)
{
	int	i;
        if (debug == 2) { printf(" Entered static void ct_setup...\n");}

	for (i=0; i < 32; i++) term_tab[i]=0;
	for (i=0; i < 256; i++) char_attr[i]=0;


	if ( (np=getnodebyname(nodename)) == NULL)
	{
	   printf("Unknown node %s\n",nodename);
	   exit(0);
	}
}
/*-------------------------------------------------------------------------*/
/*-------------------------------------------------------------------------*/
static unsigned char	read_ahead(void)
{
	char	c;
        if (debug == 2) { printf(" Entered static unsigned char read_ahead...\n");}

	if ((rptr+wrpflg) == wptr) return -1;
	c=ahead[rptr];
	aheadcnt -= 1;
	rptr=(rptr+1) & 31;
	if (rptr == 0) wrpflg=0;
	return c;
}
/*------------------------------------------------------------------------*/

static int	insert_ahead(char c)
{
	int	er;
	char	buf[6] = {0x09,0x00,0x02,0x00,0x0E,0x01};

        if (debug == 2) { printf(" Entered insert_ahead...\n");}
	if (( rptr == wptr) && (wrpflg) ) return -1;
	ahead[wptr] = c;
	wptr=(wptr+1) & 31;
	if ( wptr == rptr ) wrpflg = 1;
	aheadcnt += 1;
	if ( (aheadcnt == 1) && (han_char.input_count_state > 1) )
	{
		if (!read_present)
		{
			if ( (er=write(sockfd,buf,6)) < 0 )
			{
				perror("Error sending count state msg");
				ct_reset_term();
				exit(-1);
			}
		}
	}
	return 0;
}
/*-------------------------------------------------------------------------*/
static void dterm_bind_reply (void)
{
	unsigned char	rsts_bind[3] = {0x01,0x03,0x00};
	unsigned char	rsts_ctrl[8] = {0x02,0x08,0x00,0x01,0x09,0x01,0x00,0x00};
	/* unsigned char	tty;  now declared global ED*/
        unsigned char	rsxm_bind[3] = {0x01,0x03,0x00};
        unsigned char	rsxm_ctrl[8] = {0x02,0x08,0x00,0x01,0x04,0x02,0x00,0x00};
        int i; /*ed*/
        if (debug == 2) { printf(" Entered static void dterm_bind_reply...\n");}

	switch (flavor)
	{
	case RSTS:
		if ( (cnt=write(sockfd, rsts_bind, 3)) < 0)
		{
			printf("dterm_bind_reply: error sending bind accept\n");
			exit(-1);
		}
		/* figure out the terminal type data to send */
		tty = 0;
		if (!(cooked.c_iflag & ISTRIP))
			tty |= 64;	/* 8-bit support */
		if ((cooked.c_oflag & TABDLY) != XTABS)
			tty |= 2;	/* hardware tab */
		if (!(cooked.c_lflag & XCASE))
			tty |= 4 | 8;	/* lower case support */
		if (cooked.c_lflag & ECHOE)
			tty |= 1;	/* video terminal */
		rsts_ctrl[6] = tty;	/* modify the control message */
		if ( (cnt=write(sockfd, rsts_ctrl, 8)) < 0)
		{
			printf("dterm_bind_reply: error sending control message\n");
			exit(-1);
		}
		cnt = bufptr;		/* no data left in this packet */
		read_present = TRUE;	/* always a "read present" */
		break;
	case RSX:
		printf ("RSX flavor not yet implemented\n");
		exit (-1);
	case VMS:
		printf ("can't speak old DTERM protocol to VMS\n");
		exit(-1);
	case TOPS20:
		/* nothing to send */
		cnt = bufptr;		/* no data left in this packet */
		read_present = TRUE;	/* always a "read present" */
		break;
	case CTERM:
		/* keep the compiler happy by mentioning this case */
		break;
	}
}
/*-------------------------------------------------------------------------*/

static const char *hosttype[] = {
	"RT-11",
	"RSTS/E",
	"RSX-11S",
	"RSX-11M",
	"RSX-11D",
	"IAS",
	"VAX/VMS",
	"TOPS-20",
	"TOPS-10",
	"OS8",
	"RTS-8",
	"RSX-11M+",
	"??13", "??14", "??15", "??16", "??17",
        "","","","","","","","","","","","","","","","","","","","",
        "","","","","","","","","","","","","","","","","","","","",
        "","","","","","","","","","","","","","","","","","","","",
        "","","","","","","","","","","","","","","","","","","","",
        "","","","","","","","","","","","","","","","","","","","",
        "","","","","","","","","","","","","","","","","","","","",
        "","","","","","","","","","","","","","","","","","","","",
        "","","","","","","","","","","","","","","","","","","","",
        "","","","","","","","","","","","","","","","","",
        "Unix-dni"};

static void	ct_setup_link(void)
{
	char		*local_user;
	int		i;
        int             loop;

	unsigned char	initsq[31]={0x09,0x00,27,0x00,0x01,0x00,0x01,0x04,0x00,
				    'L','n','x','C','T','E','R','M',
				    0x01,0x02,0x00,0x02,     /* Max msg size*/
				    0x02,0x02,0xF4,0x03,     /* Max input buf*/
				    0x03,0x04,0xFE,0x7F,0x00,/* Supp. Msgs   */
				    0x00
				   };
        if (debug == 2) { printf(" Entered static void	ct_setup_link...\n");}

	printf("sethost V1.0.4\n");
	printf("Connecting to %s\n",nodename);
  	if ((sockfd=socket(AF_DECnet,SOCK_SEQPACKET,DNPROTO_NSP)) == -1)
	{
    		perror("socket");
    		exit(-1);
  	}


	/* Try very hard to get the local username */
    	local_user = cuserid(NULL);
    	if (!local_user || local_user == (char *)0xffffffff)
      		local_user = getenv("LOGNAME");
    	if (!local_user) local_user = getenv("USER");
    	if (local_user)
    	{

		strcpy((char *)accessdata.acc_acc, local_user);
		accessdata.acc_accl = strlen((char *)accessdata.acc_acc);
        	for (i=0; i<accessdata.acc_accl; i++)
            	accessdata.acc_acc[i] = toupper(accessdata.acc_acc[i]);
    	}
    	else
        	accessdata.acc_acc[0] = '\0';
    	accessdata.acc_accl  = strlen((char *)accessdata.acc_acc);

	if (setsockopt(sockfd,DNPROTO_NSP,SO_CONACCESS,&accessdata,
                       sizeof(accessdata)) < 0)
	{
		perror("setsockopt");
		exit(-1);
	}
	sockaddr.sdn_family = AF_DECnet;
	sockaddr.sdn_flags	= 0x00;
	sockaddr.sdn_objnum	= 0x2A;			/* CTERM*/
	sockaddr.sdn_objnamel	= 0x00;
 	sockaddr.sdn_add.a_len=0x02;
	memcpy(sockaddr.sdn_add.a_addr, np->n_addr,2);

	if (connect(sockfd, (struct sockaddr *)&sockaddr,
		sizeof(sockaddr)) < 0)
	{
		perror("connect (cterm)");
		//exit(-1);
	}

	if ( (cnt=dnet_recv(sockfd, buf, sizeof(buf), MSG_EOR)) < 0)
	{
		int status = 0;
		/* try to do it the old way */
#ifdef DSO_CONDATA
		/* get the reject reason code */
		struct optdata_dn optdata;
		unsigned int len = sizeof(optdata);
		char *msg;
                if (debug == 1)
                {
                printf("ct_setup_link no-read trying old way!\n"); /*ed*/
                }
                if (getsockopt(sockfd, DNPROTO_NSP, DSO_DISDATA,
			       &optdata, &len) != -1)
		{
			status = optdata.opt_status;
		}
#endif
		close (sockfd);
		if (status != DNSTAT_OBJECT)
		{
			printf ("ct_setup_link: error %d connecting to host\n",
				status);
			exit(-1);
		}

		if ((sockfd=socket(AF_DECnet,SOCK_SEQPACKET,DNPROTO_NSP)) == -1)
		{
			perror("socket, 2nd time");
			exit(-1);
		}
		sockaddr.sdn_objnum	= DNOBJECT_DTERM;
		if (connect(sockfd, (struct sockaddr *)&sockaddr,
			    sizeof(sockaddr)) < 0)
		{
			perror("connect (dterm)");
			exit(-1);
		}

		if ( (cnt=dnet_recv(sockfd,buf,sizeof(buf),MSG_EOR)) < 0)
		{
			printf("ct_setup_link: error receiving bind from host\n");
			exit(-1);
		}
		if (buf[6] & 1)
			flavor = RSTS;
		else if (buf[6] & 2)
			flavor = RSX;
		else if (buf[6] & 4)
			flavor = VMS;
		else if (buf[6] & 8)
			flavor = TOPS20;
		else
		{
			printf ("unrecognized old DTERM flavor %d\n", buf[6]);
			exit(-1);
		}
		dterm_bind_reply ();
		if (buf[4] > 18 || buf[4] < 1)
			printf ("Dterm connection to unknown host type %d.",
				buf[4]);
		else
			printf("Dterm connection to %s host.",
			       hosttype[buf[4] - 1]);
		printf ("  Escape Sequence  is ^]\n\n\n");
	}
	else
	{
		flavor = CTERM;			/* speaking new protocol */
                htype = buf[4];   /*save host type ed*/
                if (debug == 1)
                {
                printf("ct_setup_link Debug Information:\n"); /*ed*/
                printf(" ct_setup_link: prot buf[6]: %d\n",buf[6]); /*ed*/
                printf(" ct_setup_link: osys buf[4]: %d\n",buf[4]); /*ed*/
                printf(" ct_setup_link:      buf[3]: %d\n",buf[3]); /*ed*/
                printf(" ct_setup_link:      buf[2]: %d\n",buf[2]); /*ed*/
                printf(" ct_setup_link: cmd  buf[0]: %d\n",buf[0]); /*ed*/
                }
                if (buf[0] != 0x01)
		{
			printf("ct_setup_link: Not bind from host\n");
			exit(-1);
		}
		buf[0]=0x04;				/* bind accept flag	*/

		if ( (cnt=write(sockfd,buf,6)) < 0)
		{
			printf("ct_setup_link: error sending bind accept\n");
			exit(-1);
		}

		if ( (cnt=dnet_recv(sockfd,buf,sizeof(buf),MSG_EOR)) < 0)
		{
			printf("ct_setup_link: error receiving initiate/host\n");
			exit(-1);
		}

		if ( (cnt=write(sockfd,initsq,sizeof(initsq))) < 0)
		{
                 if (debug == 1)
                  {
                   for (loop = 1; loop < 7 ; loop++)
                    {  if ( (cnt=write(sockfd,initsq,sizeof(initsq))) < 0)
		        printf("ct_setup_link: loop initsq error = %d\n",cnt);
                         /*ed*/
                    }
                   }
                    printf("ct_setup_link: error sending init sequence\n");
		    exit(-1);
		}

		blklen=buf[2] | (buf[3]<<8);
		bufptr=blklen+4;
		printf("Cterm connection. Escape Sequence  is ^]\n\n\n");
	}
}

/*-------------------------------------------------------------------------*/
static void	ct_init_term(void)
{
        if (debug == 2) { printf(" Entered static void ct_init_term...\n");}

	if ((ttyfd=open("/dev/tty",O_RDWR)) < 0)
	{
		perror("Open /dev/tty");
		exit(-1);
	}
        fcntl(ttyfd, F_SETFL, fcntl(ttyfd, F_GETFL, 0) | O_NONBLOCK);

	memcpy(&raw,&cooked,sizeof(struct termios));

	cfmakeraw(&raw);
	if (tcsetattr(ttyfd, TCSANOW, &raw) < 0)
	{
		perror("tcsetattr");
		exit(-1);
	}
}
/*-------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------*/
static void ct_preinput_proc(int x)
{
	char	c;
	char	buf[80];
	int	i,cntx;
        if (debug == 2) { printf(" Entered static void ct_preinput_proc...\n");}

	cntx=read(ttyfd,&buf,80);
	for (i=0; i < cntx; i++)
	{
		c=buf[i];
		if (c==exit_char)
		{
			ct_reset_term();
			printf("\n\nControl returned to local host.\n");
			close(sockfd);
			exit(1);
		}
		/* FIXME? Should bs->del conversion be done here? */
		if (c==BS) c=DEL;
		switch(c)
		{
			case CTRL_X:	wptr = rptr = wrpflg = 0;
					break;
			case CTRL_O:	discard = ~discard;
					if (discard)
					   write(ttyfd,"\n*output off*\n",14);
					else
					   write(ttyfd,"\n*output on*\n",13);
					break;
			case CTRL_S:	hold=TRUE;
					break;
			case CTRL_Q:	hold=FALSE;
					break;
			default:
					if (ct_out_of_band(c)) break;
					if (read_present)
					{
						ct_input_proc(c);
						if (q) alarm(timeout);
					}
					else
					      if (insert_ahead(c) < 0)
					       	  write(ttyfd,&BELL,1);
		}
	}
}
/*-------------------------------------------------------------------------*/
static void rsts_preinput_proc(int x)
{
	char	c;
	char	buf[84];
	int	i,cntx;
        if (debug == 2) { printf(" Entered static void rsts_preinput_proc...\n");}

	cntx=read(ttyfd, &buf[4], 80);
	for (i=0; i < cntx; i++)
	{
		c=buf[i + 4];
		if (c==exit_char)
		{
			ct_reset_term();
			printf("\n\nControl returned to local host.\n");
			close(sockfd);
			exit(1);
		}
	}
	/* fill in data message header */
	buf[0] = 5;
	buf[1] = cntx + 4;
	buf[2] = 0;
	buf[3] = cntx;
	if (write(sockfd, buf, cntx + 4) < 0)
	{
		if (errno == ENOTCONN)
			printf("\n\nControl returned to local host.\n");
		else
			perror("terminal input data message");
		ct_reset_term();
		exit(-1);
	}
}
/*-------------------------------------------------------------------------*/
static void rsx_preinput_proc(int x)
{       if (debug == 2) { printf(" Entered static void rsx_preinput_proc...\n");}
	printf ("rsx_preinput_proc NYI\n");
	exit(-1);
}
/*-------------------------------------------------------------------------*/
static void tops_preinput_proc(int x)
{
	char	c;
	char	buf[80];
	int	i,cntx;
        if (debug == 2) { printf(" Entered static void tops_preinput_proc...\n");}

	cntx=read(ttyfd, &buf, 80);
	for (i=0; i < cntx; i++)
	{
		c=buf[i];
		if (c==exit_char)
		{
			ct_reset_term();
			printf("\n\nControl returned to local host.\n");
			close(sockfd);
			exit(1);
		}
	}
	if (write(sockfd, buf, cntx) < 0)
	{
		if (errno == ENOTCONN)
			printf("\n\nControl returned to local host.\n");
		else
			perror("terminal input data message");
		ct_reset_term();
		exit(-1);
	}
}
/*-------------------------------------------------------------------------*/
static void ct_print_char(char *c)
{       if (debug == 2) { printf(" Entered static void ct_print_char...\n");}
	if (discard)
	{
         if (debug == 2) { printf(" ct_print_char...discard!!!\n");} /*ed*/
		output_lost=TRUE;
		return;
	}
	while (hold) ;
	write(ttyfd,c,1);
}
/*-------------------------------------------------------------------------*/
/*-------------------------------------------------------------------------*/
/*-------------------------------------------------------------------------*/
/*-------------------------------------------------------------------------*/
/*-------------------------------------------------------------------------*/
/*-------------------------------------------------------------------------*/
/*-------------------------------------------------------------------------*/
/*-------------------------------------------------------------------------*/
/*-------------------------------------------------------------------------*/
/*-------------------------------------------------------------------------*/
/*-------------------------------------------------------------------------*/
/*-------------------------------------------------------------------------*/
/*-------------------------------------------------------------------------*/
/*-------------------------------------------------------------------------*/
/*-------------------------------------------------------------------------*/


static void ct_echo_prompt(char *c)
{       if (debug == 2) { printf(" Entered static void ct_echo_prompt...\n");}
	while (lockflg||hold) ;
	write(ttyfd,c,1);
}
/*-------------------------------------------------------------------------*/
static void ct_read_req(void)
{
	unsigned char	flg;
	char		car;
	short	*p,i,termlen,procnt;
        if (debug == 2) { printf(" Entered static void ct_read_req...\n");}

	bufptr += 1;				/* Point to first flag char*/
	flg=buf[bufptr];

	uu = flg & 0x03;
	c  = (flg & 0x04) >> 2;
	f  = (flg & 0x08) >> 3;
	v  = (flg & 0x10) >> 4;
	k  = (flg & 0x20) >> 5;
 	ii = (flg & 0xC0) >> 6;

	bufptr  += 1;
	flg=buf[bufptr];

	ddd = (flg & 0x07);
	n   = (flg & 0x08) >> 3;
	t   = (flg & 0x10) >> 4;
	q   = (flg & 0x20) >> 5;
	zz  = (flg & 0xC0) >> 6;

	bufptr  += 1;
	flg=buf[bufptr];

	ee  = (flg & 0x03);
	bufptr += 1;				/* Point to next char */

	p=(void *)&buf[bufptr];
	max_len=dn_ntohs(*p);
	bufptr += 2;

	p=(void *)&buf[bufptr];
	end_of_data=dn_ntohs(*p);
	bufptr += 2;

	p=(void *)&buf[bufptr];
	timeout=dn_ntohs(*p);
	bufptr += 2;

	p=(void *)&buf[bufptr];
	end_of_prompt=dn_ntohs(*p);
	bufptr += 2;

	p=(void *)&buf[bufptr];
	start_of_display=dn_ntohs(*p);
	bufptr += 2;

	p=(void *)&buf[bufptr];
	low_water=dn_ntohs(*p);
	bufptr += 2;
	termlen = buf[bufptr];
	bufptr += 1;
	procnt=17;
	for (i=0; i < termlen; i++)
	{
		term_tab[i]=buf[bufptr];
		bufptr += 1;
		procnt += 1;
	}
	if (c) aheadcnt=rptr=wptr=wrpflg=inpcnt=inpptr=0;
	while (procnt < blklen)
	{
		inpbuf[inpptr++]=buf[bufptr];
		ct_echo_prompt((char *)&buf[bufptr]);
		if (inpptr > end_of_prompt) inpcnt += 1;
		bufptr += 1;
		procnt += 1;
	}
	read_present = TRUE;
	while ((read_present) && (aheadcnt > 0))
	{
		car=read_ahead();
		ct_input_proc(car);
	}
	if (read_present)
		if ((q==1) && (timeout==0) ) ct_terminate_read(5);
	if ((read_present) && (q==1)) alarm(timeout);
}
/*-------------------------------------------------------------------------*/
static void ct_unread_req(void)
{       if (debug == 2) { printf(" Entered static void ct_unread_req...\n");}
	bufptr += 1;				/* Point to unread flag	*/

	if (buf[bufptr] == 0) ct_terminate_read(6);
	else
		if ((aheadcnt+inpcnt)==0) ct_terminate_read(6);
	bufptr += 1;
}
/*-------------------------------------------------------------------------*/
static void ct_clearinput_req(void)
{       if (debug == 2) { printf(" Entered static void ct_clearinput_req...\n");}
	bufptr += 2;
	rptr=wptr=wrpflg=inpcnt=0;
}
/*--------------------------------------------------------------------------*/
static void ct_write_req(void)
{
	short	procnt, flgs,i;
	short	uu,l,d,b,e,pp,qq,s,t;
	char	prefix,postfix,c,lf=0x0A;
	char	msg[8] = {0x09,0x00,0x08,0x00,0x00,0x00,0x00,0x00};
        if (debug == 2) { printf(" Entered static void ct_write_req...\n");}

	bufptr += 1;				/* Skip op code		*/
	flgs=buf[bufptr] | (buf[bufptr+1]<<8);
	bufptr += 2;
	procnt = 3;

	uu = flgs & 0x02;
	l  = (flgs & 0x04) >> 2;
	d  = (flgs & 0x08) >> 3;
	b  = (flgs & 0x10) >> 4;
	e  = (flgs & 0x20) >> 5;
	pp = (flgs & 0xC0) >> 6;
	qq = (flgs & 0x300) >> 8;
	s  = (flgs & 0x400) >> 10;
	t  = (flgs & 0x800) >> 11;

	prefix = buf[bufptr];
	bufptr += 1;
	postfix = buf[bufptr];
	bufptr += 1;
	procnt += 2;
	output_lost=FALSE;


	if (uu==0) lockflg=FALSE;
	else lockflg=TRUE;

	if (d) discard=FALSE;
	if (pp==1)
	{
		for (i=0; i < pp; i++) ct_print_char(&lf);
	}
	if (pp==2) ct_print_char(&prefix);


	while (procnt < blklen)
	{
		c=buf[bufptr];
		bufptr += 1;
		procnt += 1;
		ct_print_char(&c);
	}
	if (qq==1)
	{
		for (i=0; i < qq; i++) ct_print_char(&lf);
	}
	if (qq==2) ct_print_char(&postfix);

	if (uu==2) lockflg=FALSE;
	if (uu==3)
	{
		lockflg=FALSE;
		redisplay=TRUE;
	}

	if (s==1)
	{
		if (output_lost) msg[3]=0x01;
		if (write(sockfd,msg,8) < 0)
		{
			perror("Write completion");
			ct_reset_term();
			exit(-1);
		}
	}
	if (redisplay)
	{
		redisplay=FALSE;
		for (i=0; i < inpptr; i++)
		{
			if (i < end_of_prompt) ct_echo_prompt((char *)&inpbuf[i]);
			else ct_echo_input_char((char *)&inpbuf[i]);
		}
	}
}
/*-------------------------------------------------------------------------*/
static void ct_readchar_req(void)
{
	char	c;
	short	*p;
	short	selector,procnt,ouptr;
	unsigned char	outbuf[300];
        if (debug == 2) { printf(" Entered static void ct_readchar_req...\n");}

	bufptr += 2;				/* Skip op code 	*/
	procnt = 2;
	outbuf[0] = 0x09;			/* Common data block	*/
	outbuf[1] = 0x00;			/* Flag			*/
	outbuf[4] = 0x0B;
	outbuf[5] = 0x00;

	ouptr = 6;				/* Reserve space for block
						   len field		*/

	while (procnt < blklen)
	{
		p=(void *)&buf[bufptr];		/* Point to selector	*/
		selector=dn_ntohs(*p);
		if ((selector & 0x300) == 0x000) /* Physical Charac	*/
		{
        if (debug == 2) { printf(" ct_readchar_req...Phys char!\n");}
		   switch (selector & 0xFF)
		   {
			case 0x01:	/* Input speed			*/
					p=(void *)&outbuf[ouptr];
					set_short(p, 0x0001);
					ouptr +=2;
					p=(void *)&outbuf[ouptr];
					set_short(p,phy_char.input_speed);
					ouptr +=2;
					procnt += 2;
					bufptr += 2;
					break;

			case 0x02:	/* Output speed			*/
					p=(void *)&outbuf[ouptr];
					set_short(p,0x0002);
					ouptr +=2;
					p=(void *)&outbuf[ouptr];
					set_short(p,phy_char.output_speed);
					ouptr +=2;
					procnt += 2;
					bufptr += 2;
					break;

			case 0x03:	/* Character size		*/
					p=(void *)&outbuf[ouptr];
					set_short(p,0x0003);
					ouptr +=2;
					p=(void *)&outbuf[ouptr];
					set_short(p,phy_char.character_size);
					ouptr +=2;
					procnt += 2;
					bufptr += 2;
					break;

			case 0x04:	/* Parity enable		*/
					p=(void *)&outbuf[ouptr];
					set_short(p,0x0004);
					ouptr +=2;
					outbuf[ouptr]=phy_char.parity_enable;
					ouptr +=1;
					procnt += 2;
					bufptr += 2;
					break;

			case 0x05:	/* Parity type			*/
					p=(void *)&outbuf[ouptr];
					set_short(p,0x0005);
					ouptr +=2;
					p=(void *)&outbuf[ouptr];
					set_short(p,phy_char.parity_type);
					ouptr +=2;
					procnt += 2;
					bufptr += 2;
					break;

			case 0x06:	/* Modem Present		*/
					p=(void *)&outbuf[ouptr];
					set_short(p,0x0006);
					ouptr +=2;
					outbuf[ouptr]=phy_char.modem_present;
					ouptr +=1;
					procnt += 2;
					bufptr += 2;
					break;

			case 0x07:	/* Auto baud detect		*/
					p=(void *)&outbuf[ouptr];
					set_short(p,0x0007);
					ouptr +=2;
					outbuf[ouptr]=phy_char.auto_baud_detect;
					ouptr +=1;
					procnt += 2;
					bufptr += 2;
					break;

			case 0x08:	/* Management guaranteed	*/
					p=(void *)&outbuf[ouptr];
					set_short(p,0x0008);
					ouptr +=2;
					outbuf[ouptr]=phy_char.management_guaranteed;
					ouptr +=1;
					procnt += 2;
					bufptr += 2;
					break;

			case 0x09:	/* SW 1				*/
					procnt += 2;
					bufptr += 2;
					break;

			case 0x0A:	/* SW 2				*/
					procnt += 2;
					bufptr += 2;
					break;

			case 0x0B:	/* Eight bit			*/
					p=(void *)&outbuf[ouptr];
					set_short(p,0x000B);
					ouptr +=2;
					outbuf[ouptr]=phy_char.eigth_bit;
					ouptr +=1;
					procnt += 2;
					bufptr += 2;
					break;

			case 0x0C:	/* Terminal Management		*/
					p=(void *)&outbuf[ouptr];
					set_short(p,0x000C);
					ouptr +=2;
					outbuf[ouptr]=phy_char.terminal_management_enabled;
					ouptr +=1;
					procnt += 2;
					bufptr += 2;
					break;
		   }
		}
		if ((selector & 0x300) == 0x100) /* Logical Characteristics*/
		{
        if (debug == 2) { printf(" ct_readchar_req...Log char!\n");}
		   switch(selector & 0xFF)
		   {
			case 0x01:	/* Mode writing allowed		*/
					p=(void *)&outbuf[ouptr];
					set_short(p,0x0101);
					ouptr +=2;
					outbuf[ouptr]=log_char.mode_writing_allowed;
					ouptr +=1;
					procnt += 2;
					bufptr += 2;
					break;

			case 0x02:	/* Terminal attributes		*/
					p=(void *)&outbuf[ouptr];
					set_short(p,0x0102);
					ouptr +=2;
					p=(void *)&outbuf[ouptr];
					set_short(p,log_char.terminal_attributes);
					ouptr +=2;
					procnt += 2;
					bufptr += 2;
					break;

			case 0x03:	/* Terminal Type		*/
					p=(void *)&outbuf[ouptr];
					set_short(p,0x0103);
					ouptr +=2;
					p=(void *)&outbuf[ouptr];
					memcpy((void *)p,log_char.terminal_type,6);
					ouptr +=6;
					procnt += 2;
					bufptr += 2;
					break;

			case 0x04:	/* Output flow control		*/
					p=(void *)&outbuf[ouptr];
					set_short(p,0x0104);
					ouptr +=2;
					outbuf[ouptr]=log_char.output_flow_control;
					ouptr +=1;
					procnt += 2;
					bufptr += 2;
					break;

			case 0x05:	/* Output page stop		*/
					p=(void *)&outbuf[ouptr];
					set_short(p,0x0105);
					ouptr +=2;
					outbuf[ouptr]=log_char.output_page_stop;
					ouptr +=1;
					procnt += 2;
					bufptr += 2;
					break;

			case 0x06:	/* Flow char pass through	*/
					p=(void *)&outbuf[ouptr];
					set_short(p,0x0106);
					ouptr +=2;
					outbuf[ouptr]=log_char.flow_character_pass_through;
					ouptr +=1;
					procnt += 2;
					bufptr += 2;
					break;

			case 0x07:	/* Input flow control		*/
					p=(void *)&outbuf[ouptr];
					set_short(p,0x0107);
					ouptr +=2;
					outbuf[ouptr]=log_char.input_flow_control;
					ouptr +=1;
					procnt += 2;
					bufptr += 2;
					break;

			case 0x08:	/* Loss notification		*/
					p=(void *)&outbuf[ouptr];
					set_short(p,0x0108);
					ouptr +=2;
					outbuf[ouptr]=log_char.loss_notification;
					ouptr +=1;
					procnt += 2;
					bufptr += 2;
					break;

			case 0x09:	/* Line width			*/
					p=(void *)&outbuf[ouptr];
					set_short(p,0x0109);
					ouptr +=2;
					p=(void *)&outbuf[ouptr];
					set_short(p,log_char.line_width);
					ouptr +=2;
					procnt += 2;
					bufptr += 2;
					break;

			case 0x0A:	/* Page length			*/
					p=(void *)&outbuf[ouptr];
					set_short(p,0x010A);
					ouptr +=2;
					p=(void *)&outbuf[ouptr];
					set_short(p,log_char.page_length);
					ouptr +=2;
					procnt += 2;
					bufptr += 2;
					break;

			case 0x0B:	/* Stop length			*/
					p=(void *)&outbuf[ouptr];
					set_short(p,0x010B);
					ouptr +=2;
					p=(void *)&outbuf[ouptr];
					set_short(p,log_char.stop_length);
					ouptr +=2;
					procnt += 2;
					bufptr += 2;
					break;

			case 0x0C:	/* CR-FILL			*/
					p=(void *)&outbuf[ouptr];
					set_short(p,0x010C);
					ouptr +=2;
					p=(void *)&outbuf[ouptr];
					set_short(p,log_char.cr_fill);
					ouptr +=2;
					procnt += 2;
					bufptr += 2;
					break;

			case 0x0D:	/* LF-FILL			*/
					p=(void *)&outbuf[ouptr];
					set_short(p,0x010D);
					ouptr +=2;
					p=(void *)&outbuf[ouptr];
					set_short(p,log_char.lf_fill);
					ouptr +=2;
					procnt += 2;
					bufptr += 2;
					break;

			case 0x0E:	/* wrap				*/
					p=(void *)&outbuf[ouptr];
					set_short(p,0x010E);
					ouptr +=2;
					p=(void *)&outbuf[ouptr];
					set_short(p,log_char.wrap);
					ouptr +=2;
					procnt += 2;
					bufptr += 2;
					break;

			case 0x0F:	/* Horizontal tab		*/
					p=(void *)&outbuf[ouptr];
					set_short(p,0x010F);
					ouptr +=2;
					p=(void *)&outbuf[ouptr];
					set_short(p,log_char.horizontal_tab);
					ouptr +=2;
					procnt += 2;
					bufptr += 2;
					break;

			case 0x10:	/* Vertical tab			*/
					p=(void *)&outbuf[ouptr];
					set_short(p,0x0110);
					ouptr +=2;
					p=(void *)&outbuf[ouptr];
					set_short(p,log_char.vertical_tab);
					ouptr +=2;
					procnt += 2;
					bufptr += 2;
					break;

			case 0x11:	/* Form feed			*/
					p=(void *)&outbuf[ouptr];
					set_short(p,0x0111);
					ouptr +=2;
					p=(void *)&outbuf[ouptr];
					set_short(p,log_char.form_feed);
					ouptr +=2;
					procnt += 2;
					bufptr += 2;
					break;
		   }
		}
		if ((selector & 0x300) == 0x200) /* Handler Charact	*/
		{
        if (debug == 2) { printf(" ct_readchar_req...Han char! %d\n",selector);}
		   switch (selector & 0xFF)
		   {
			   case 0x01:	/* IGNORE INPUT 		*/
                           if (debug == 2) { printf(" Han char case 1!\n");}
					p=(void *)&outbuf[ouptr];
					set_short(p,0x0201);
					ouptr += 2;
					outbuf[ouptr]=han_char.ignore_input;
					ouptr += 1;
					procnt += 2;
					bufptr += 2;
					break;
			   case 0x02:	/* Character Attributes 	*/
                           if (debug == 2) { printf(" Han char case 2!\n");}
					p=(void *)&outbuf[ouptr];
					set_short(p,0x0202);
					ouptr += 2;
					bufptr += 1;
					c=buf[bufptr];
					outbuf[ouptr]=c;
					outbuf[ouptr+1]=0xFF;
					outbuf[ouptr+2]=char_attr[(int)c];
					ouptr += 3;
					procnt += 3;
					bufptr += 3;
					break;
			   case 0x03:	/* Control-o pass through 	*/
                           if (debug == 2) { printf(" Han char case 3!\n");}
					p=(void *)&outbuf[ouptr];
					set_short(p,0x0203);
					ouptr += 2;
					outbuf[ouptr]=han_char.control_o_pass_through;
					ouptr += 1;
					procnt += 2;
					bufptr += 2;
					break;

			   case 0x04:	/* Raise Input			*/
                           if (debug == 2) { printf(" Han char case 4!\n");}
					p=(void *)&outbuf[ouptr];
					set_short(p,0x0204);
					ouptr += 2;
					outbuf[ouptr]=han_char.raise_input;
					ouptr += 1;
					procnt += 2;
					bufptr += 2;
					break;

			   case 0x05:	/* Normal Echo			*/
                           if (debug == 2) { printf(" Han char case 5!\n");}
					p=(void *)&outbuf[ouptr];
					set_short(p,0x0205);
					ouptr += 2;
					outbuf[ouptr]=han_char.normal_echo;
					ouptr += 1;
					procnt += 2;
					bufptr += 2;
					break;

			   case 0x06:	/* Input Escape Seq Recognition */
                           if (debug == 2) { printf(" Han char case 6!\n");}
					p=(void *)&outbuf[ouptr];
					set_short(p,0x0206);
					ouptr += 2;
					outbuf[ouptr]=han_char.input_escseq_recognition;
					ouptr += 1;
					procnt += 2;
					bufptr += 2;
					break;

			   case 0x07:	/* Output Esc Seq Recognition	*/
                           if (debug == 2) { printf(" Han char case 7!\n");}
					p=(void *)&outbuf[ouptr];
					set_short(p,0x0207);
					ouptr += 2;
					outbuf[ouptr]=han_char.output_escseq_recognition;
					ouptr += 1;
					procnt += 2;
					bufptr += 2;
					break;

			   case 0x08:	/* Input count state		*/
                           if (debug == 2) { printf(" Han char case 8!\n");}
					p=(void *)&outbuf[ouptr];
					set_short(p,0x0208);
					ouptr += 2;
					p=(void *)&outbuf[ouptr];
					set_short(p,han_char.input_count_state);
					ouptr += 2;
					procnt += 2;
					bufptr += 2;
					break;

			   case 0x09:	/* Auto Prompt			*/
                           if (debug == 2) { printf(" Han char case 9!\n");}
					p=(void *)&outbuf[ouptr];
					set_short(p,0x0209);
					ouptr += 2;
					outbuf[ouptr]=han_char.auto_prompt;
					ouptr += 1;
					procnt += 2;
					bufptr += 2;
					break;

			   case 0x0A:	/* Error processing option	*/
                           if (debug == 2) { printf(" Han char case A!\n");}
					p=(void *)&outbuf[ouptr];
					set_short(p,0x020A);
					ouptr += 2;
					outbuf[ouptr]=han_char.error_processing;
					ouptr += 1;
					procnt += 2;
					bufptr += 2;
					break;

			   case 0x0B:	/* Error processing option rsxm+ ed*/
                           if (debug == 2) { printf(" Han char case B!\n");}
					p=(void *)&outbuf[ouptr];
					set_short(p,0x020B);
					ouptr += 2;
					outbuf[ouptr]=han_char.error_processing;
					ouptr += 1;
					procnt += 2;
					bufptr += 2;
					break;
			}
		}
	}
	p=(void *)&outbuf[2];
	set_short(p,ouptr - 6);
	if (write(sockfd,outbuf,ouptr) < 0)
	{
		perror("Error writing characteristics");
		ct_reset_term();
		exit(-1);
	}
}
/*-------------------------------------------------------------------------*/
static void ct_writechar_req(void)
{
	char	c;
	short	*p;
	short	selector, procnt;
        if (debug == 2) { printf(" Entered static void ct_writechar_req...\n");}

	bufptr += 2;				/* Skip op code		*/
	procnt = 2;
	while (procnt < blklen)
	{
		selector=buf[bufptr] | (buf[bufptr+1]<<8);
		if ((selector & 0x300) != 0x200)
		{
			bufptr=cnt; procnt=blklen;
			break;
		}
		selector &= 0xFF;
		bufptr += 2;			/* Point to selector value */
		switch(selector)
		{

		   case 0x01:	/* IGNORE INPUT 		*/
				han_char.ignore_input = buf[bufptr];
				procnt += 3;
				bufptr += 1;
				break;
		   case 0x02:	/* Character Attributes 	*/
				c=buf[bufptr];
				if (buf[bufptr+1] & 0x03)
				   char_attr[(int)c] |= (buf[bufptr+2] & 0x03);
				if (buf[bufptr+1] & 0x04)
				   char_attr[(int)c] |= (buf[bufptr+2] & 0x04);
				if (buf[bufptr+1] & 0x08)
				   char_attr[(int)c] |= (buf[bufptr+2] & 0x08);
				if (buf[bufptr+1] & 0x30)
				   char_attr[(int)c] |= (buf[bufptr+2] & 0x30);
				if (buf[bufptr+1] & 0x40)
				   char_attr[(int)c] |= (buf[bufptr+2] & 0x40);
				procnt += 5;
				bufptr += 3;
				break;
		   case 0x03:	/* Control-o pass through 	*/
				han_char.control_o_pass_through = buf[bufptr];
				procnt += 3;
				bufptr += 1;
				break;
		   case 0x04:	/* Raise Input			*/
				han_char.raise_input = buf[bufptr];
				procnt += 3;
				bufptr += 1;
				break;
		   case 0x05:	/* Normal Echo			*/
				han_char.normal_echo = buf[bufptr];
				procnt += 3;
				bufptr += 1;
				break;

		   case 0x06:	/* Input Escape Seq Recognition */
				han_char.input_escseq_recognition = buf[bufptr];
				procnt += 3;
				bufptr += 1;
				break;

		   case 0x07:	/* Output Esc Seq Recognition	*/
				han_char.output_escseq_recognition=buf[bufptr];
				procnt += 3;
				bufptr += 1;
				break;

		   case 0x08:	/* Input count state		*/
				p=(void *)&buf[bufptr];

/* SPARC machines can't handle the off alignment either... */
#if __BYTE_ORDER != 1234
				swab((void *)&han_char.input_count_state, (void *)p, 4);
#else
				han_char.input_count_state = *p;
#endif
				procnt += 4;
				bufptr += 2;
				break;

		   case 0x09:	/* Auto Prompt			*/
				han_char.auto_prompt = buf[bufptr];
				procnt += 3;
				bufptr += 1;
				break;

		   case 0x0A:	/* Error processing option	*/
				han_char.error_processing = buf[bufptr];
				procnt += 3;
				bufptr += 1;
				break;
		}
	}
}
/*-------------------------------------------------------------------------*/
static void ct_checkinput_req(void)
{
	unsigned char	msg[8] = {0x09,0x00,0x04,0x00,0x0D,0x00,0x00,0x00};
	short 	*p = (void *)&msg[4];
        if (debug == 2) { printf(" Entered static void ct_checkinput_req...\n");}

	set_short(p, aheadcnt+inpcnt);
	if (write(sockfd,msg,8) < 0)
	{
		perror("input count msg");
		ct_reset_term();
		exit(-1);
	}
}
/*-------------------------------------------------------------------------*/
static void ct_read_pkt(void)
{
	fd_set	rdfs;
	int	retval;
        if (debug == 2) { printf(" Entered static void ct_read_pkt...\n");}

	do {
		FD_ZERO(&rdfs);
		FD_SET(sockfd,&rdfs);
		FD_SET(ttyfd,&rdfs);
		retval=select(FD_SETSIZE,&rdfs,NULL,NULL, NULL);
	} while (retval <= 0);


	if (FD_ISSET(sockfd, &rdfs))
	{
	    cnt=dnet_recv(sockfd,buf,sizeof(buf),MSG_EOR);
	    if (cnt <= 0)
	    {
		unbind = TRUE;
		return;
	    }
	    if (flavor == CTERM)
	    {
		if (buf[0] == 0x09) bufptr = 2;
		if ( (cnt==3) && (buf[0] == 0x02)) unbind = TRUE;
	    }
	    else
	    {
		if (cnt == 0)
		    unbind = TRUE;
		bufptr = 0;
	    }
	}
      	if (FD_ISSET(ttyfd, &rdfs))
	{
	    kb_handler(0);
	}

}
/*-------------------------------------------------------------------------*/
static void proc_rsts_pkt(void)
{
	int data_cnt;
	if (cnt==bufptr) return;
        if (debug == 2) { printf(" Entered static void proc_rsts_pkt...\n");}

	if (buf[1] + (buf[2] << 8) != cnt)
	{
		printf ("proc_rsts_pkt: wrong packet length in header\n");
		ct_reset_term();
		exit(-1);
	}
	switch (*buf)
	{
	case 2:
		/* process control message, TBS */
		break;
	case 5:
		/* process data message */
		data_cnt = buf[3];
		if (data_cnt > cnt - 4)
		{
			printf ("proc_rsts_pkt: wrong data length in data packet header\n");
			ct_reset_term();
			exit(-1);
		}
		write(ttyfd, buf + 4, data_cnt);
	}
	bufptr = cnt;
}
/*-------------------------------------------------------------------------*/
static void proc_rsx_pkt(void)
{       if (debug == 2) { printf(" Entered static void proc_rsx_pkt...\n");}
	printf ("not yet implemented -- proc_rsx_pkt\n");
	exit(-1);
}
/*-------------------------------------------------------------------------*/
static void proc_tops_pkt(void)
{       if (debug == 2) { printf(" Entered static void proc_tops_pkt...\n");}
	/* message is just plain terminal output data */
	write(ttyfd, buf, cnt);
	bufptr = cnt;
}
/*-------------------------------------------------------------------------*/
static void proc_cterm_pkt (void)
{       if (debug == 2) { printf(" Entered static void proc_cterm_pkt...\n");}

	blklen=buf[bufptr] | (buf[bufptr+1]<<8);
	bufptr += 2;
	switch(buf[bufptr])
	{
	case 0x02:		/* Start Read 		*/
		ct_read_req();
		break;
	case 0x05:		/* Unread		*/
		ct_unread_req();
		break;
	case 0x06:		/* Clear Input		*/
		ct_clearinput_req();
		break;
	case 0x07:		/* Write		*/
		ct_write_req();
		break;
	case 0x0A:		/* Read Characteristics */
		ct_readchar_req();
		break;
	case 0x0B:		/* Write Characteristics*/
		ct_writechar_req();
		break;
	case 0x0C:		/* Check Input		*/
		ct_checkinput_req();
		break;
	default:
		bufptr = cnt;
	}
}
/*-------------------------------------------------------------------------*/
static void ct_proc_pkt(void)
{       if (debug == 2) { printf(" Entered static void ct_proc_pkt...\n");}

	if (cnt==bufptr) ct_read_pkt();			/* Get next pkt    */
	while (!unbind)
	{
		if (cnt == 0) continue;
		switch (flavor)
		{
		case CTERM:
			proc_cterm_pkt ();
			break;
		case RSTS:
			proc_rsts_pkt ();
			break;
		case RSX:
			proc_rsx_pkt ();
			break;
		case TOPS20:
			proc_tops_pkt ();
			break;
		case VMS:
			/* keep the compiler happy by mentioning this case */
			break;
		}
		if (cnt==bufptr) ct_read_pkt();
	}
	printf("\r\n\nReturned to local host.\r\n");
}
/*-------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
    struct sigaction sa;
    sigset_t ss;

    int verbosity;
    /*int debug = 0;*/
    char log_char = 'l';
    char opt;
    if (debug == 2) { printf(" Entered int main...\n");}

    /* Deal with command-line arguments. */
    opterr = 0;
    optind = 0;
    while ((opt=getopt(argc,argv,"?Vhdte:")) != EOF)
    {
	switch(opt)
	{
	case 'h':
	    usage(argv[0], stdout);
	    exit(0);

	case '?':
	    usage(argv[0], stderr);
	    exit(0);

	case 'V':
	    printf("\nsethost from dnprogs version %s\n\n", VERSION);
	    exit(1);
	    break;

	case 'e':
	    set_exit_char(optarg);
	    break;

        case 'd':
            debug = 1;
            break;

        case 't':
            debug = 2;
            break;
	}
    }

    if (optind >= argc)
    {
	usage(argv[0], stderr);
	exit(2);
    }

    nodename = argv[optind];

    ct_setup();				/* Resolve remote node addr*/
    /* ct_setup_link may use "cooked" to send terminal characteristics
     * to the other end
     */
    if (tcgetattr(ttyfd, &cooked) < 0)
    {
	    perror("tcgetattr");
	    exit(-1);
    }
    ct_setup_link();			/* Setup link		   */

    ct_init_term();				/* Set terminal in raw mode*/

    sigemptyset(&ss);
    sa.sa_handler = ct_timeout_proc;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGALRM, &sa, NULL);

    if (debug == 1)
    {
    printf("Connection to %d flavour",flavor); /*ed*/
    }
    switch (flavor)
    {
    case CTERM:
	    kb_handler = ct_preinput_proc;
	    break;
    case RSTS:
	    kb_handler = rsts_preinput_proc;
	    break;
    case RSX:
	    kb_handler = rsx_preinput_proc;
	    break;
    case TOPS20:
	    kb_handler = tops_preinput_proc;
	    break;
    case VMS:
	    /* keep the compiler happy by mentioning this case */
	    break;
    }
    alarm(0);

    ct_proc_pkt();				/* Process input packets   */

    ct_reset_term();

    return 0;
}
