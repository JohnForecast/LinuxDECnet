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
// create.cc
// Code for a CREATE task within a FAL server process.
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
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
#include "open.h"
#include "server.h"
#include "create.h"

fal_create::fal_create(dap_connection &c, int v, fal_params &p,
		       dap_attrib_message  *attrib,
		       dap_alloc_message   *alloc,
		       dap_protect_message *protect):
    fal_open(c,v,p, attrib, alloc, protect)
{
    create = true;
}

fal_create::~fal_create()
{
}
