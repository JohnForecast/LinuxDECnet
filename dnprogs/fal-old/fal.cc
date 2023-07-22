/******************************************************************************
    (c) 1998-2002 Christine Caulfield             christine.caulfield@googlemail.com

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
////
// fal.cc
// DECnet File Access Listener for Linux
////
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <limits.h>
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <syslog.h>
#include <pwd.h>
#include <grp.h>
#include <regex.h>
#include <signal.h>
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

#define LOCAL_AUTO_FILE ".fal_auto"

void usage(char *prog, FILE *f);

static int verbose = 0;
static dap_connection *global_connection = NULL;

// You are here
int main(int argc, char *argv[])
{
    int    dont_fork = 0;
    bool   allow_user_override = false;
    char   opt;
    char   log_char = 'l'; // Default to syslog(3)
    struct fal_params p;

// Set defaults
    p.verbosity = 0;                // Softly-softly.
    p.auto_type = fal_params::NONE; // Do not guess file types
    p.use_file  = false;            // Use built-in defaults
    p.use_metafiles = false;
    p.use_adf   = false;
    p.vroot[0]  = '\0';
    p.vroot_len = 0;

#ifdef NO_FORK
    dont_fork = 1;
#endif

    // Deal with command-line arguments. Do these before the check for root
    // so we can check the version number and get help without being root.
    opterr = 0;
    optind = 0;
    while ((opt=getopt(argc,argv,"?vVhdmtul:a:f:r:")) != EOF)
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
	    p.verbosity++;
	    break;

	case 'u':
	    allow_user_override = true;
	    break;

	case 'd':
	    dont_fork++;
	    break;

	case 'm':
	    p.use_metafiles = true;
	    break;

	case 't':
	    p.use_adf = true;
	    break;

	case 'r':
	    strcpy(p.vroot, optarg);

	    // Virtual root must end in (one) slash
	    if (p.vroot[strlen(p.vroot)-1] != '/')
		strcat(p.vroot, "/");
	    p.vroot_len = strlen(p.vroot);
	    break;

	case 'V':
	    printf("\nfal from dnprogs version %s\n\n", VERSION);
	    exit(1);
	    break;

	case 'a':
	    if (optarg[0] == 'g') p.auto_type = fal_params::GUESS_TYPE;
	    if (optarg[0] == 'e') p.auto_type = fal_params::CHECK_EXT;
	    if (p.auto_type == fal_params::NONE)
	    {
		fprintf(stderr, "Invalid auto type : '%s'\n", optarg);
		usage(argv[0], stderr);
		exit(2);
	    }
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

	case 'f':
	    // Make sure we save the full path name becase we 'chdir' a lot
	    realpath(optarg, p.auto_file);
	    p.use_file = true;
	    break;
	}
    }

    verbose = p.verbosity; // Our local copy

    // Check for the types file
    if (p.use_file)
    {
	struct stat st;
	if (stat(p.auto_file, &st))
	{
	    fprintf(stderr, "Unable to access types file '%s'\n", p.auto_file);
	    usage(argv[0], stderr);
	    exit(2);
	}
    }

    // Initialise logging
    init_logging("fal", log_char, true);
    init_daemon_logging((char *)"fal", log_char);

    // Check the vroot exists and is a directory
    if (p.vroot_len)
    {
	struct stat st;
	if (stat(p.vroot, &st) == -1)
	{
	    DAPLOG((LOG_ERR, "Virtual root %s does not exist. FAL won't start\n", p.vroot));
	    exit(4);
	}
	if (!S_ISDIR(st.st_mode))
	{
	    DAPLOG((LOG_ERR, "Virtual root %s is not a directory. FAL won't start\n", p.vroot));
	    exit(4);
	}

	if (p.verbosity)
	    DAPLOG((LOG_INFO, "Using virtual root %s\n", p.vroot));
    }

    // Be a daemon
    int sockfd = dnet_daemon(DNOBJECT_FAL,
			     NULL, verbose, dont_fork?0:1);
    if (sockfd > -1)
    {
	// We are now running as the target user and in her/his home directory

	// Look for a local conversion override
	if (allow_user_override)
	{
	    struct stat st;
	    if (stat(LOCAL_AUTO_FILE, &st) == 0)
	    {
		FILE *f = fopen(LOCAL_AUTO_FILE, "r");
		if (f)
		{
		    char line[132];
		    fgets(line, sizeof(line), f);
		    fclose(f);
		    if (strncasecmp(line, "none", 4) == 0)
			p.auto_type = fal_params::NONE;
		    if (strncasecmp(line, "ext", 3) == 0)
			p.auto_type = fal_params::CHECK_EXT;
		    if (strncasecmp(line, "guess", 5) == 0)
			p.auto_type = fal_params::GUESS_TYPE;

		    if (verbose) DAPLOG((LOG_INFO, "Using conversion type '%s' in local file.\n", p.type_name()));
		}
	    }
	}

	dnet_accept(sockfd, 0, NULL, 0);
	dap_connection *newone = new dap_connection(sockfd, 65535, verbose);

	fal_server f(*newone, p);
	f.run();
	f.closedown();
	newone->set_blocked(false);
	delete newone;
    }
}


void usage(char *prog, FILE *f)
{
    fprintf(f,"%s options:\n", prog);
    fprintf(f," -d        Don't fork\n");
    fprintf(f," -a<type>  Auto file type(g:guess, e:check extension)\n");
    fprintf(f," -f<file>  File containing types for -ae\n");
    fprintf(f," -l<type>  Logging type(s:syslog, e:stderr, m:mono)\n");
    fprintf(f," -r<dir>   base directory for FAL file operations\n");
    fprintf(f," -u        Allow users to override global auto_types\n");
    fprintf(f," -v        Verbose (repeat to increase verbosity)\n");
    fprintf(f," -m        Use meta-files to preserve file info\n");
    fprintf(f," -t        Use VMS NFS $ADF$ files (readonly)\n");
    fprintf(f," -V        Show version\n");
    fprintf(f," -h        Help\n");
}
