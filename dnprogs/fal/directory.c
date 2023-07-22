/******************************************************************************
    (C) John Forecast                           john@forecast.name

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
******************************************************************************/

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <glob.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>
#include "dap.h"

extern int verbosity;

extern uint8_t remOS, remFS, remLen;

/*
 * Create a protection image field in the buffer
 */
static void buildProtection(
  void *buf,
  mode_t mode,
  int isowner
)
{
  DAPexInit(buf, 3);
  if (!isowner)
    DAPexSetBit(buf, DAP_PROT_DENY_DELETE);
  if ((mode & S_IROTH) == 0)
    DAPexSetBit(buf, DAP_PROT_DENY_READ);
  if ((mode & S_IWOTH) == 0)
    DAPexSetBit(buf, DAP_PROT_DENY_WRITE);
  if ((mode & S_IXOTH) == 0)
    DAPexSetBit(buf, DAP_PROT_DENY_EXEC);
  DAPexDone(buf);
}

/*
 * Send requested attributes message(s) associated with a directory
 * entry.
 */
static void sendAttributes(
  char *basedir,
  char *entry,
  uint8_t *display
)
{
  struct stat statbuf;
  char fullspec[PATH_MAX];

  strcpy(fullspec, basedir);
  strcat(fullspec, entry);

  if (stat(fullspec, &statbuf) == 0) {
    if (display != NULL) {
      if (DAPexGetBit(display, DAP_DSP_MAIN)) {
        void *buf = DAPbuildHeader1Len(DAP_MSG_ATTRIBUTES);

        DAPexInit(buf, 6);
        DAPexSetBit(buf, DAP_ATTR_RFM);
        DAPexSetBit(buf, DAP_ATTR_ALQ);
        DAPexSetBit(buf, DAP_ATTR_EBK);
        DAPexSetBit(buf, DAP_ATTR_FFB);
        DAPexDone(buf);
        DAPbPut(buf, DAP_RFM_STM);
        DAPint2i(buf, 5, statbuf.st_blocks);
        DAPint2i(buf, 5, (statbuf.st_size + 511) / 512);
        DAP2bPut(buf, statbuf.st_size % 512);
        DAPwrite(buf);
      }
      
      if (DAPexGetBit(display, DAP_DSP_DATETIME)) {
        void *buf = DAPbuildHeader1Len(DAP_MSG_DATETIME);

        DAPexInit(buf, 6);
        DAPexSetBit(buf, DAP_DMNU_CDT);
        DAPexSetBit(buf, DAP_DMNU_RDT);
        DAPexDone(buf);
        DAPaddDateTime(buf, &statbuf.st_ctim);
        DAPaddDateTime(buf, &statbuf.st_mtim);
        DAPwrite(buf);
      }

      if (DAPexGetBit(display, DAP_DSP_PROTECT)) {
        struct passwd *pwd = getpwuid(statbuf.st_uid);
        char *owner = (pwd == NULL) ? "" : pwd->pw_name;
        void *buf = DAPbuildHeader1Len(DAP_MSG_PROTECT);

        DAPexInit(buf, 6);
        DAPexSetBit(buf, DAP_PMNU_OWNER);
        DAPexSetBit(buf, DAP_PMNU_PROTOWN);
        DAPexSetBit(buf, DAP_PMNU_PROTGRP);
        DAPexSetBit(buf, DAP_PMNU_PROTWLD);
        DAPexDone(buf);
        DAPstring2i(buf, 40, owner);
        buildProtection(buf, statbuf.st_mode >> 6, 1);
        buildProtection(buf, statbuf.st_mode >> 3, 0);
        buildProtection(buf, statbuf.st_mode, 0);
        DAPwrite(buf);
      }
    }
  }
}

/*
 * Get the base directory we will be looking at. Make sure that the directory
 * is terminated  by "/". As above, if the string is too long, it will be
 * truncated to the first 5 characters followed by ".../".
 */
static void BaseDirectory(
  char *dir,
  char *filespec
)
{
  char *cwd = get_current_dir_name();
  char *base = filespec[0] == '/' ? filespec : cwd;
  
  if (strlen(base) >= DAP_NAME_MAX_NAMESPEC) {
    strncpy(dir, base, 5);
    dir[5] = '\0';
    strcat(dir, ".../");
  } else {
    strcpy(dir, base);
    if ((strlen(dir) == 0) || (dir[strlen(dir) - 1] != '/'))
      strcat(dir, "/");
  }
  free(cwd);
}

/*
 * Find the longest common directory prefix for the list of names returned
 * by glob(). The resulting string is dynamically allocated (NULL if memory
 * allocation failed) and needs to be released by the caller using free().
 */
char *DirectoryPrefix(
  glob_t *gl
)
{
  char *prefix = NULL, *cp;
  int i;
  
  if (gl->gl_pathc >= 2) {
    if ((prefix = strdup(gl->gl_pathv[0])) != NULL) {
      size_t len = strlen(prefix);

      /*
       * Strip off any trailing '/'s
       */
      while ((len != 0) && (prefix[len - 1] == '/')) {
        prefix[len - 1] = '\0';
        len--;
      }

      if (len != 0) {
        if ((cp = rindex(prefix, '/')) != NULL)
          *cp = '\0';

        /*
         * Scan the remaining strings to find the longest common directory
         * prefix
         */
        for (i = 0; i < gl->gl_pathc && (prefix[0] != '\0'); i++) {
          do {
            size_t plen = strlen(prefix);
            
            if (strlen(gl->gl_pathv[i]) >= plen)
              if (strncmp(prefix, gl->gl_pathv[i], plen) == 0)
                break;

            /*
             * Prefix did not match, backup one directory name and try again
             */
            if ((cp = rindex(prefix, '/')) != NULL)
              *cp = '\0';
            else prefix[0] = '\0';
          } while (prefix[0] != 0);
        }
      }
    }
  }
  return prefix;
}

/*
 * Generate a directory listing. Note that "name" must point to a buffer
 * with at space for at least 2 characters to be appended to the end of
 * the string.
 */
void ListDirectory(
  char *name,
  uint8_t *display
)
{
  struct stat statbuf;
  char *filespec = name;
  glob_t gl;
  int i, status;
  void *buf;
  size_t len;
  
  if (verbosity)
    dnetlog(LOG_DEBUG, "ListDirectory(%s) operation\n", name);
  
  /*
   * Unfortunately, the client system sends the requested directory/file
   * in its native format. So, for instance, VMS will send "*.*;*" for a
   * "DIR remote::" request. Here we will try to map most of the known
   * system default requests (e.g. in this case map "*.*;*" to "*").
   */
  switch (remOS) {
    case DAP_OS_VAXVMS:
      if (strcmp(filespec, "*.*;*") == 0)
        filespec = "*";
      break;

      /*** More to go here ***/
  }

  /*
   * Always map an empty filespec to "*".
   */
  if (filespec[0] == '\0')
    filespec = "*";

  if (verbosity)
    if (filespec != name)
      dnetlog(LOG_DEBUG, "Mapped \"%s\" => \"%s\"\n", name, filespec);

  /*
   * Remove any trailing '/' characters.
   */
  while (((len = strlen(filespec)) > 1) && (filespec[len - 1] == '/'))
    filespec[len - 1] = '\0';

  if (stat(filespec, &statbuf) == 0) {
    if ((statbuf.st_mode & S_IFDIR) != 0)
      strcat(filespec, "/*");
  }
  
  status = glob(filespec, GLOB_MARK, NULL, &gl);

  if (status != 0) {
    ReportError(DAP_MAC_OPEN | DAP_MIC_IO_ER_FNF);
    return;
  }

  if (gl.gl_pathc > 0) {
    char basedir[DAP_NAME_MAX_NAMESPEC + 2];

    BaseDirectory(basedir, filespec);

    DAPsendName(DAP_NAME_TYPE_VOLUME, "");
    DAPsendName(DAP_NAME_TYPE_DIRECTORY, basedir);
    
    for (i = 0; i < gl.gl_pathc; i++) {
      DAPsendName(DAP_NAME_TYPE_FILENAME, gl.gl_pathv[i]);
      sendAttributes(basedir, gl.gl_pathv[i], display);
      if (remOS == DAP_OS_TOPS10)
        DAPsendAcknowledge();
    }
  }
  globfree(&gl);

  /*
   * Indicate we are done with the directory listing
   */
  buf = DAPbuildHeader(DAP_MSG_COMPLETE);
  DAPbPut(buf, DAP_AFNC_RESPONSE);
  DAPwrite(buf);
}
