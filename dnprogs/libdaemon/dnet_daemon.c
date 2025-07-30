/******************************************************************************
    dnet_daemon.c from libdnet_daemon

    Copyright (C) 1999 Christine Caulfield       christine.caulfield@googlemail.com

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
#include <limits.h>
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
#include "dn_endian.h"

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif
#define MAX_FORKS 10
typedef int bool_t;

#define NODE_LENGTH 20
#define USERNAME_LENGTH 65

#define ALLOW_FILE      SYSCONF_PREFIX "/etc/nodes.allow"
#define DENY_FILE       SYSCONF_PREFIX "/etc/nodes.deny"

// Structure of an item in the DECnet proxy database
// These lengths are generous to allow for regular expressions
struct proxy
{
    char node[NODE_LENGTH];
    char remuser[USERNAME_LENGTH];
    char localuser[USERNAME_LENGTH];

    regex_t node_r;
    regex_t remuser_r;

    struct proxy *next;
};

// Object definition from dnetd.conf
struct object
{
    char  name[USERNAME_LENGTH]; // Object name
    unsigned int number;         // Object number
    bool_t  proxy;               // Whether to use proxies
    char  user[USERNAME_LENGTH]; // User to use if proxies not used
    char  daemon[PATH_MAX];      // Name of daemon
    int   auto_accept;           // Auto Accept incoming connections

    struct object *next;
};

static struct proxy  *proxy_db  = NULL;
static struct object *object_db = NULL;
static struct object *thisobj   = NULL;
static const char *proxy_filename = SYSCONF_PREFIX "/etc/decnet.proxy";
static const char *dnetd_filename = SYSCONF_PREFIX "/etc/dnetd.conf";
static bool_t volatile do_shutdown = FALSE;
static int verbose;
static char errstring[1024];
static struct optdata_dn optdata;
static bool_t have_optdata = FALSE;
static char *lasterror="";

// Catch child process shutdown
static void sigchild(int s)
{
    int status, pid;

    // Make sure we reap all children
    do
    {
	pid = waitpid(-1, &status, WNOHANG);
	if (pid > 0 && verbose) DNETLOG((LOG_INFO, "Reaped child process %d\n", pid));
    }
    while (pid > 0);
}

// Catch termination signal
void sigterm(int s)
{
    do_shutdown = TRUE;
    if (verbose) DNETLOG((LOG_INFO, "Caught SIGTERM, going down\n"));
}


// A couple of general utility methods:
static void makelower(char *s)
{
    unsigned int i;
    for (i=0; s[i]; i++) s[i] = tolower(s[i]);
}


// Read the proxy database into memory
static void load_proxy_database(void)
{
    FILE         *f;
    char          buf[4096];
    int           line;
    struct proxy *new_proxy;
    struct proxy *last_proxy = NULL;

    f = fopen(proxy_filename, "r");
    if (!f)
    {
	DNETLOG((LOG_ERR, "Can't open proxy database: %s\n", strerror(errno)));
	return;
    }

    line = 0;

    while (!feof(f))
    {
	char *bufp = buf;
	char *colons;

	line++;
	if (!fgets(buf, sizeof(buf), f)) break;

	// Skip whitespace
	while (*bufp == ' ' || *bufp == '\t') bufp++;

	if (*bufp == '#' || *bufp == '\n') continue; // Comment or blank line

	// Remove trailing LF
	if (buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';

	colons = strstr(bufp, "::");
	if (colons)
	{
	    // Look for the local user after a space or tab
	    char *space = strchr(colons, ' ');
	    char *end;
	    char *local;

	    if (!space) space = strchr(colons, '\t');
	    if (!space)
	    {
		DNETLOG((LOG_ERR, "Error on line %d of proxy file: no space\n", line));
		continue;
	    }
	    *colons = '\0';
	    if (strlen(bufp) > 20)
	    {
		DNETLOG((LOG_ERR, "Error on line %d of proxy file: nodename too long\n", line));
		continue;
	    }
	    *space='\0';
	    if (strlen(colons+2) > 65)
	    {
		DNETLOG((LOG_ERR, "Error on line %d of proxy file: remote username too long\n", line));
		continue;
	    }
	    if (strlen(space+1) > 65)
	    {
		DNETLOG((LOG_ERR, "Error on line %d of proxy file: local username too long\n", line));
		continue;
	    }

	    // Skip whitespace
	    local = space+1;
	    while (*local == ' ' || *local == '\t') local++;

	    // Terminate the local user at another whitespace char or a hash
	    // to allow comments
	    if ( ((end=strchr(local, ' '))) )  *end = '\0';
	    if ( ((end=strchr(local, '\t'))) ) *end = '\0';
	    if ( ((end=strchr(local, '#'))) )  *end = '\0';

	    if (strlen(local) == 0)
	    {
		DNETLOG((LOG_ERR, "Error on line %d of proxy file: no local username\n", line));
		continue;
	    }

	    new_proxy = malloc(sizeof(struct proxy));
	    memset(new_proxy, 0, sizeof(struct proxy)); // Needed to clear regexps

	    strcpy(new_proxy->node, bufp);
	    strcpy(new_proxy->remuser, colons+2);
	    strcpy(new_proxy->localuser, local);

	    // Compile the regular expressions
	    if (regcomp(&new_proxy->node_r, new_proxy->node, REG_ICASE))
	    {
		DNETLOG((LOG_ERR, "Error on line %d of proxy file: node regexp is invalid\n", line));
		free(new_proxy);
		continue;
	    }
	    if (regcomp(&new_proxy->remuser_r, new_proxy->remuser, REG_ICASE))
	    {
		DNETLOG((LOG_ERR, "Error on line %d of proxy file: remote user regexp is invalid\n", line));
		free(new_proxy);
		continue;
	    }

	    // Add to the list
	    if (last_proxy)
	    {
		last_proxy->next = new_proxy;
	    }
	    else
	    {
		proxy_db = new_proxy;
	    }
	    last_proxy = new_proxy;
	}
	else
	{
	    DNETLOG((LOG_ERR, "Error on line %d of proxy file: no ::\n", line));
	    continue;
	}
    }
    fclose(f);
}


// Free up the proxy database structure so we can re-read it later.
static void free_proxy(void)
{
    struct proxy *p = proxy_db;
    struct proxy *next_p;

    while (p)
    {
	regfree(&p->node_r);
	regfree(&p->remuser_r);
	next_p=p->next;
	free(p);
	p=next_p;
    }
    proxy_db = NULL;
}

// Always returns false. Sets the error string to strerror(errno)
static bool_t error_return(char *txt)
{
    snprintf(errstring, sizeof(errstring), "%s: %s", txt, strerror(errno));
    lasterror = errstring;
    return FALSE;
}


// Check the proxy database for authentication
static bool_t check_proxy_database(char *nodename,
				   char *remoteuser,
				   char *localuser)
{
    bool_t found = FALSE;
    struct proxy *p;

// Re-read the proxy database 'cos it has changed.
    free_proxy();
    load_proxy_database();

    // Look for the user and nodename in the list
    p = proxy_db;

    while (p && !found)
    {
	if (regexec(&p->node_r, nodename, 0, NULL, 0) == 0 &&
	    regexec(&p->remuser_r, remoteuser, 0, NULL, 0) == 0)
	{
	    found = TRUE;
	    if (p->localuser[0] == '*')
	    {
		strcpy(localuser, remoteuser);
	    }
	    else
	    {
		strcpy(localuser, p->localuser);
	    }
	    if (verbose > 1) DNETLOG((LOG_INFO, "Using proxy name %s\n", localuser));
	}
	p = p->next;
    }
    return found;
}

//
// Wait for an incoming connection
// Returns a new fd or -1
static int waitfor(int sockfd)
{
    int                  status;
    int                  newsock;
    unsigned int         len;
    struct sockaddr_dn	 sockaddr;
    static bool_t listening = FALSE;

    memset(&sockaddr, 0, sizeof(sockaddr));

    // Set up the listing context
    if (!listening)
    {
	status = listen(sockfd, 5);
	if (status)
	{
	    snprintf(errstring, sizeof(errstring),
		     "listen failed: %s", strerror(errno));
	    lasterror = errstring;
	    return -1;
	}
	listening = TRUE;
    }

    // Wait for a connection
    memset(&sockaddr, 0, sizeof(sockaddr));
    len = sizeof(sockaddr);
    newsock = accept(sockfd, (struct sockaddr *)&sockaddr, &len);
    if (newsock < 0 && errno != EINTR)
    {
        snprintf(errstring, sizeof(errstring),
		 "accept failed: %s", strerror(errno));
	lasterror = errstring;
	return -1;
    }

    // We were interrupted, return a bad fd
    if (newsock < 0 && errno == EINTR) return -1;

    // Return the new fd
    return newsock;
}


// No prizes for guessing what this does.
// Returns are as for the syscall fork().
// Actually, it also sets the current directory too.
static int fork_and_setuid(int sockfd)
{
    struct  accessdata_dn accessdata;
    char   *cryptpass;
    char    username[USERNAME_LENGTH];
    char    password[USERNAME_LENGTH];
    char    remote_user[USERNAME_LENGTH];
    char    nodename[NODE_LENGTH];
    struct  sockaddr_dn  sockaddr;
    unsigned int len = sizeof(accessdata);
    int      er;
    unsigned int namlen = sizeof(sockaddr);
    pid_t   newpid;
    uid_t   newuid;
    gid_t   newgid;
    bool_t  use_proxy;
    struct  passwd *pw;
    int     have_shadow = -1;
    memset(&sockaddr, 0, sizeof(sockaddr));

    // Get the name (or address if we cant find the name) of the remote system.
    // (a) for logging and (b) for checking in the proxy database.
    // (c) for checking against the object database
    er = getpeername(sockfd, (struct sockaddr *)&sockaddr, &namlen);
    if (!er)
    {
        strcpy(nodename, dnet_htoa(&sockaddr.sdn_add));
    }
    else
    {
	snprintf(nodename, sizeof(nodename), "%d.%d",
		(sockaddr.sdn_add.a_addr[1] >> 2),
		(((sockaddr.sdn_add.a_addr[1] & 0x03) << 8) |
		 sockaddr.sdn_add.a_addr[0]));
    }

    // Only do this if we are dnetd
    if (object_db)
    {
	struct  sockaddr_dn  sockaddr;
	struct object *obj = object_db;

    	memset(&sockaddr, 0, sizeof(sockaddr));
	getsockname(sockfd, (struct sockaddr *)&sockaddr, &namlen);

	while (obj)
	{
	    if ((sockaddr.sdn_objnamel && !obj->number &&
		 (!strcmp((char *)sockaddr.sdn_objname, obj->name) ||
		  !strcmp(obj->name, "*"))) ||
		(sockaddr.sdn_objnum == obj->number && obj->number))
		 {
		     thisobj = obj;
		     break;
		 }
	    obj = obj->next;
	}
    }

// Get the remote user spec.
    if (getsockopt(sockfd, DNPROTO_NSP, SO_CONACCESS, &accessdata,
		   &len) < 0)
    {
        snprintf(errstring, sizeof(errstring),
		 "getsockopt failed: %s", strerror(errno));
	lasterror = errstring;
	return -1;
    }
    memcpy(username, accessdata.acc_user, accessdata.acc_userl);
    username[accessdata.acc_userl] = '\0';

    memcpy(password, accessdata.acc_pass, accessdata.acc_passl);
    password[accessdata.acc_passl] = '\0';
#ifdef SDF_UICPROXY // Steve's kernel
    memcpy(remote_user, sockaddr.sdn_objname, dn_ntohs(sockaddr.sdn_objnamel));
    remote_user[dn_ntohs(sockaddr.sdn_objnamel)] = '\0';
#else // Eduardo's kernel
    memcpy(remote_user, accessdata.acc_acc, accessdata.acc_accl);
    remote_user[accessdata.acc_accl] = '\0';
#endif
    // Make the user names all lower case. I'm sorry if you have mixed
    // case usernames on your system, you'll just have to use the proxy
    // database; VMS usernames are case blind.
    makelower(remote_user);
    makelower(username);


    if (verbose)
    {
	if (username[0])
	{
	    DNETLOG((LOG_DEBUG, "Connection from: %s\"%s password\"::%s\n",
		     nodename, username, remote_user));
	}
	else
	{
	    DNETLOG((LOG_DEBUG, "Connection from: %s::%s\n",
		     nodename, remote_user));
	}
    }

// Check proxy database if no local user was passed
// this overwrites 'username' with the proxied user

    if (!thisobj)
    {
	if (username[0] == '\0')
	{
	    use_proxy = check_proxy_database(nodename, remote_user, username);
	}
	else
	{
	    use_proxy = FALSE;
	}
    }
    else // Overrides from the object database
    {
	if (!thisobj->proxy)
	{
	    if (verbose) DNETLOG((LOG_INFO, "using user %s from dnetd.conf\n", thisobj->user));
	    strcpy(username, thisobj->user);
	    use_proxy = TRUE;
	}
	else
	{
	    if (username[0] == '\0')
	    {
		if (verbose) DNETLOG((LOG_INFO, "dnetd.conf, checking proxy\n"));
		use_proxy = check_proxy_database(nodename, remote_user, username);
	    }
	    else
	    {
		if (verbose) DNETLOG((LOG_INFO, "dnetd.conf, using passed username: %s\n", thisobj->user));
		use_proxy = FALSE;
	    }
	}
    }

    pw = getpwnam(username);
    if (!pw)
    {
	snprintf(errstring, sizeof(errstring),
		 "Unknown username '%s' - access denied", username);
	lasterror=errstring;
	dnet_reject(sockfd, DNSTAT_ACCCONTROL, NULL, 0);
	return -1;
    }
    newuid = pw->pw_uid;
    newgid = pw->pw_gid;

// If we are using a proxy then we don't need to verify the password
    if (!use_proxy)
    {
#ifdef SHADOW_PWD
	// See if we REALLY have shadow passwords
	if (have_shadow == -1)
	{
	    struct stat shadstat;
	    if (stat("/etc/shadow", &shadstat) == 0)
		have_shadow = 1;
	    else
		have_shadow = 0;
	}

	if (have_shadow)
	{
	    struct spwd *spw = getspnam(username);
	    if (!spw)
	    {
		snprintf(errstring, sizeof(errstring),
			 "Error reading /etc/shadow entry for %s: %s",
			 username, strerror(errno));
		lasterror=errstring;
		if (verbose) DNETLOG((LOG_DEBUG, "UID is %d\n", getuid()));
		dnet_reject(sockfd, DNSTAT_ACCCONTROL, NULL, 0);
		return -1;
	    }
	    endspent(); // prevent caching of passwords

	    // Check the shadow password
	    cryptpass = crypt(password, spw->sp_pwdp);
	    if (strcmp(cryptpass, spw->sp_pwdp))
	    {
		// If that failed then lower-case the password and try again.
		// This is really for RSX which sends the password in all caps
		makelower(password);
		cryptpass = crypt(password, spw->sp_pwdp);
		if (strcmp(cryptpass, spw->sp_pwdp))
		{
		    snprintf(errstring, sizeof(errstring),
			     "Incorrect password for %s", username);
		    lasterror=errstring;
		    dnet_reject(sockfd, DNSTAT_ACCCONTROL, NULL, 0);
		    return -1;
		}
	    }
	}
	else
#endif
	{
	    // Check the (non-shadow) password
 	    cryptpass = crypt(password, pw->pw_passwd);
	    if (strcmp(cryptpass, pw->pw_passwd))
	    {
		// Check lower-case password as above.
		makelower(password);
		cryptpass = crypt(password, pw->pw_passwd);
		if (strcmp(cryptpass, pw->pw_passwd))
		{
		    snprintf(errstring, sizeof(errstring),
			     "Incorrect password for %s", username);
		    lasterror=errstring;
		    dnet_reject(sockfd, DNSTAT_ACCCONTROL, NULL, 0);
		    return -1;
		}
	    }
	}
    }

// NO_FORK is just for testing. It creates a single-shot server that is
// easier to debug.
#ifdef NO_FORK
    newpid = 0;
#else
    newpid = fork();
#endif

    switch (newpid)
    {
    case -1:
	snprintf(errstring, sizeof(errstring),
		 "fork failed: %s", strerror(errno));
	lasterror = errstring;
	break;

    case 0: // Child
#ifndef NO_FORK
        if (initgroups(username, newgid) < 0)
	{
	    error_return("init groups failed");
	    return -1;
	}
	if (setgid(newgid) < 0)
	{
	    error_return("setgid failed");
	    return -1;
	}
	if (setuid(newuid) < 0)
	{
	    error_return("setuid failed");
	    return -1;
	}
#endif
	if (chdir(pw->pw_dir))
	{
	    DNETLOG((LOG_WARNING, "Cannot chdir to %s : %m\n", pw->pw_dir));
	    chdir("/");
	}
	break;

    default: // Parent
	break;
    }
    return newpid;
}

static void load_dnetd_conf(void)
{
    FILE          *f;
    char           buf[4096];
    int            line;
    struct object *last_object = NULL;

    f = fopen(dnetd_filename, "r");
    if (!f)
    {
        DNETLOG((LOG_ERR, "Can't open dnetd.conf database: %s\n",
                 strerror(errno)));
	return;
    }

    line = 0;

    while (!feof(f))
    {
	char tmpbuf[1024];
	char *bufp;
	char *comment;
	struct object *newobj;
	int    state = 1;

	line++;
	if (!fgets(buf, sizeof(buf), f)) break;

	// Skip whitespace
	bufp = buf;
	while (*bufp == ' ' || *bufp == '\t') bufp++;

	if (*bufp == '#') continue; // Comment

	// Remove trailing LF
	if (buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';

	// Remove any trailing comments
	comment = strchr(bufp, '#');
	if (comment) *comment = '\0';

	if (*bufp == '\0') continue; // Empty line

	// Split into fields
	newobj = malloc(sizeof(struct object));
	state = 1;
	bufp = strtok(bufp, " \t");
	while(bufp)
	{
	    char *nextspace = bufp+strlen(bufp);
	    if (*nextspace == ' ' || *nextspace == '\t') *nextspace = '\0';
	    switch (state)
	    {
	    case 1:
		strcpy(newobj->name, bufp);
		break;
	    case 2:
		strcpy(tmpbuf, bufp);
		if ( strcmp(tmpbuf, "*") == 0 ) {
		    if ( strcmp(newobj->name, "*") == 0 ) {
			newobj->number = 0;
		    } else {
			newobj->number = getobjectbyname(newobj->name);
		    }
		} else {
		    newobj->number = atoi(tmpbuf);
		}
		break;
	    case 3:
		newobj->proxy = (toupper(bufp[0])=='Y'?TRUE:FALSE);
		newobj->auto_accept = 0;
		if ( bufp[1] == ',' && bufp[2] != ' ' && bufp[2] != '\t' ) {
		    switch (toupper(bufp[2])) {
			case 'Y':
			case 'A':
			    newobj->auto_accept =  1;
			    break;
			case 'R':
			    newobj->auto_accept = -1;
			    break;
			case 'N':
			default:
			    newobj->auto_accept =  0;
			    break;
		    }
		}
		break;
	    case 4:
		strcpy(newobj->user, bufp);
		break;
	    case 5:
		strcpy(newobj->daemon, bufp);
		break;
	    default:
		// Copy parameters
		strcat(newobj->daemon, " ");
		strcat(newobj->daemon, bufp);
		break;
	    }
	    bufp = strtok(NULL, " \t");
	    state++;
	}

	// Did we get all the info ?
	if (state > 5)
	{
	    // Add to the list
	    if (last_object)
	    {
		last_object->next = newobj;
	    }
	    else
	    {
		object_db = newobj;
	    }
	    last_object = newobj;
	}
	else
	{
	    DNETLOG((LOG_ERR, "Error in dnet.conf line %d, state = %d\n", line, state));
	    free(newobj);
	}
    }

}

// Bind to an object number
bool_t bind_number(int sockfd, int object)
{
    struct sockaddr_dn bind_sockaddr;
    int status;

    memset(&bind_sockaddr, 0, sizeof(bind_sockaddr));
    bind_sockaddr.sdn_family    = AF_DECnet;
    bind_sockaddr.sdn_flags	= 0;
    bind_sockaddr.sdn_objnum	= object;
    bind_sockaddr.sdn_objnamel	= 0;

    status = bind(sockfd,  (struct sockaddr *)&bind_sockaddr,
		  sizeof(bind_sockaddr));
    if (status)
    {
	snprintf(errstring, sizeof(errstring),
		 "bind failed: %s\n", strerror(errno));
	lasterror=errstring;
	return FALSE;
    }
    return TRUE;
}

// Bind to an object number
bool_t bind_name(int sockfd, char *object)
{
    struct sockaddr_dn bind_sockaddr;
    int status;

    memset(&bind_sockaddr, 0, sizeof(bind_sockaddr));
    bind_sockaddr.sdn_family    = AF_DECnet;
    bind_sockaddr.sdn_flags	= 0;
    bind_sockaddr.sdn_objnum	= 0;
    bind_sockaddr.sdn_objnamel	= dn_htons(strlen(object));
    strcpy((char *)bind_sockaddr.sdn_objname, object);

    status = bind(sockfd,  (struct sockaddr *)&bind_sockaddr,
			sizeof(bind_sockaddr));
    if (status)
    {
	snprintf(errstring, sizeof(errstring),
		"bind failed: %s", strerror(errno));
	lasterror=errstring;
	return FALSE;
    }
    return TRUE;
}

// Bind to the wildcard object
bool_t bind_wild(int sockfd)
{
    struct sockaddr_dn bind_sockaddr;
    int status;

    memset(&bind_sockaddr, 0, sizeof(bind_sockaddr));
    bind_sockaddr.sdn_family    = AF_DECnet;
    bind_sockaddr.sdn_flags	= SDF_WILD;
    bind_sockaddr.sdn_objnum	= 0;
    bind_sockaddr.sdn_objnamel	= 0;

    status = bind(sockfd,  (struct sockaddr *)&bind_sockaddr,
			sizeof(bind_sockaddr));
    if (status)
    {
	snprintf(errstring, sizeof(errstring),
		 "bind failed: %s", strerror(errno));
	lasterror=errstring;
	return FALSE;
    }
    return TRUE;
}


// Called by DECnet daemons. If stdin is already a DECnet socket then
// just return 0 (stdin's file descriptor). otherwise we
// bind to the object and wait. When we get a connection we fork
// and (optionally) setuid, and return. The parent then loops back (ie it
// never returns).
//
// This is the keystone of all DECnet daemons that can be called from dnetd
//
int dnet_daemon(int object, char *named_object,
		int verbosity, bool_t do_fork)
{
    struct sockaddr_dn  sa, remotesa;
    unsigned int        namelen = sizeof(struct sockaddr_dn);
    bool_t              bind_status  = FALSE;
    pid_t               pid;
    int                 sockfd;
    int                 acceptmode;
    int                 i;
    struct              sigaction siga;
    sigset_t            ss;
    const char        * proc = NULL;

    memset(&sa, 0, sizeof(sa));

// Are we the execed child of dnetd?
    if (getsockname(STDIN_FILENO, (struct sockaddr *)&sa, &namelen) == 0)
    {
	if (sa.sdn_family != AF_DECnet)
	{
	    // Argh, a socket but not a DECnet one!!!!!
	    DNETLOG((LOG_ERR, "Got connection from socket of type %d. This is a bad configuration error\n", sa.sdn_family));
	    return -1;
	}
	if (verbosity) DNETLOG((LOG_INFO, "starting child process\n"));
	return STDIN_FILENO;
    }

    // We need to start a server.
    if (getuid() != 0)
    {
	fprintf(stderr, "You must be root to start a DECnet server\n");
	return -1;
    }

    // Fork into the background
#ifndef NO_FORK
    if (do_fork) // Also available at run-time
    {
	switch ( pid=fork() )
	{
	case -1:
	    perror("server: can't fork");
	    exit(2);

	case 0: // child
	    break;

	default: // Parent.
	    if (verbosity > 1) printf("server: forked process %d\n", pid);
	    exit(0);
	}

	// Detach ourself from the calling environment
	for (i=0; i<FD_SETSIZE; i++)
	    close(i);
	setsid();
	chdir("/");
    }
#endif

// We are now a daemon...

    // Set up signal handlers.
    do_shutdown = FALSE;
    signal(SIGHUP,  SIG_IGN);

    sigemptyset(&ss);
    siga.sa_handler=sigchild;
    siga.sa_mask  = ss;
    siga.sa_flags = 0;
    sigaction(SIGCHLD, &siga, NULL);

    siga.sa_handler=sigterm;
    sigaction(SIGTERM, &siga, NULL);


    verbose = verbosity;

    // Create the socket
    if ((sockfd=socket(AF_DECnet,SOCK_SEQPACKET,DNPROTO_NSP)) == -1)
    {
        snprintf(errstring, sizeof(errstring), "socket failed: %s", strerror(errno));
	lasterror = errstring;
	return -1;
    }

    if (have_optdata)
	setsockopt(sockfd, DNPROTO_NSP, SO_CONDATA,
		   &optdata, sizeof(optdata));

#ifdef DSO_ACCEPTMODE
    acceptmode = ACC_DEFER;
    setsockopt(sockfd, DNPROTO_NSP, DSO_ACCEPTMODE, &acceptmode, 4);
#endif

// Bind the object
    if (object)
    {
	bind_status = bind_number(sockfd, object);
    }
    else
    {
	if (named_object)
	    bind_status = bind_name(sockfd, named_object);
	else
	    bind_status = bind_wild(sockfd);
    }

    // If that failed then all bets are off.
    if (!bind_status)
    {
	DNETLOG((LOG_ERR, "Can't bind: %m\n"));
	return -1; // Can't bind
    }

    if (verbose) DNETLOG((LOG_INFO, "Ready\n"));

    // Main loop.
    do
    {
	int fork_fail = 0;
	int newone;
	int ret;

	// Wait for a new connection.
	newone = waitfor(sockfd);
	if (newone > -1)
	{
	    // check /etc/nodes.{allow,deny} if connection is allowed
	    namelen = sizeof(remotesa);

	    if (getsockname(newone, (struct sockaddr *)&sa, &namelen) == -1) {
		dnet_reject(newone, DNSTAT_FAILED, NULL, 0);
		DNETLOG((LOG_ALERT, "Can not read local sockname\n"));
	    }

	    namelen = sizeof(remotesa);

	    if ( getpeername(newone, (struct sockaddr *) &remotesa, &namelen) == -1 ) {
		dnet_reject(newone, DNSTAT_FAILED, NULL, 0);
		DNETLOG((LOG_ALERT, "Can not read peers sockname\n"));
		continue;
	    }

	    // first we check if we do not have a allow match, if we have we can continue.
	    // if we don't have one we need to check the deny list.
	    if ( dnet_priv_check(ALLOW_FILE, proc, &sa, &remotesa) != 1 ) {
		// check deny list.
		// if we have a nodes.deny file we continue, if we don't we ignore it.
		// we check for file existance not readability here to avoid
		// errors by wrong file permittions and such.
		if ( access(DENY_FILE, F_OK) == 0 ) {
		    // check the file itself. We do not reject in case of no match (0).
		    // in case of match (1) or error (-1) we reject.
		    if ( dnet_priv_check(DENY_FILE, proc, &sa, &remotesa) != 0 ) {
			dnet_reject(newone, DNSTAT_ACCCONTROL, NULL, 0);
			continue;
		    }
		}
	    }

	    // load dnetd's object databse if we don't have it already loaded.
	    if (!object_db) load_dnetd_conf();

	    ret = fork_and_setuid(newone);

	    switch (ret)
	    {
	    case -1:
		if (++fork_fail > MAX_FORKS)
		{
		    DNETLOG((LOG_ALERT, "fork failed too often. giving up\n"));
		    exit(100);
		}

		// Oh no, it all went horribly wrong.
		DNETLOG((LOG_ERR, "Fork_and_setuid failed: %s\n", lasterror));
		close(newone);
		continue;

	    case 0: // child
		if (object_db && thisobj != NULL) {
		    // check if we are going to do auto accept or reject.
		    switch (thisobj->auto_accept) {
			case  1:
			    dnet_accept(newone, 0, NULL, 0);
			    break;
			case -1:
			    dnet_reject(newone, DNSTAT_REJECTED, NULL, 0);
			    exit(101);
			    break;
		    }
		}
		return newone;
		break;

	    default: // parent, just tidy up and loop back
		fork_fail = 0;
		close(newone);
		break;
	    }
	}
    }
    while (!do_shutdown);
    exit(0);
}

void dnet_accept(int sockfd, short status, char *data, int len)
{
#ifdef DSO_CONDATA
    if (status || len)
    {
	struct optdata_dn optdata;

	optdata.opt_sts=status;
	optdata.opt_optl=dn_htons(len);
	if (len && data) memcpy(optdata.opt_data, data, len);

	setsockopt(sockfd, DNPROTO_NSP, DSO_CONDATA,
		   &optdata, sizeof(optdata));
    }
    setsockopt(sockfd, DNPROTO_NSP, DSO_CONACCEPT, NULL, 0);
#endif
}

void dnet_reject(int sockfd, short status, char *data, int len)
{
#ifdef DSO_DISDATA
    if (status || len)
    {
	struct optdata_dn optdata;

	optdata.opt_sts=status;
	optdata.opt_optl=dn_htons(len);
	if (data && len) memcpy(optdata.opt_data, data, len);
	setsockopt(sockfd, DNPROTO_NSP, DSO_DISDATA,
		   &optdata, sizeof(optdata));
    }
    setsockopt(sockfd, DNPROTO_NSP, DSO_CONREJECT, NULL, 0);
#endif
    close(sockfd);
}

char *dnet_daemon_name(void)
{
    if (thisobj)
	return thisobj->daemon;
    else
	return NULL;
}

// For daemons not run by dnetd and using Eduardo's kernel
void dnet_set_optdata(char *data, int len)
{
#ifndef DSO_ACCEPTMODE
    optdata.opt_optl=dn_htons(len);
    optdata.opt_sts=0;
    if (len && data) memcpy(optdata.opt_data, data, len);
    have_optdata = TRUE;
#endif
}
