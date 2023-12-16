/******************************************************************************
    (c) 1998-2008      Christine Caulfield          christine.caulfield@googlemail.com

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
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>
#include <unistd.h>
#include <regex.h>

#include "connection.h"
#include "protocol.h"
#include "logging.h"


bool show_full_details(char *dirname, dap_connection &conn);
void print_short(
    unsigned int filename_width,
    int show_size,
    int show_date,
    int show_owner,
    int show_protection,
    int single_column,
    int entries_per_line,
    long size,
    char *name,
    char *owner,
    char *cdt,
    char *prot,
    int *printed
);

void print_long
(
    dap_name_message    *name_msg,
    dap_attrib_message  *attrib_msg,
    dap_date_message    *date_msg,
    dap_protect_message *protect_msg
);



static void     dndir_usage(FILE *f)
{
    fprintf(f, "\nUSAGE: dndir [OPTIONS] 'node\"user password\"::filespec'\n\n");
    fprintf(f, "NOTE: The VMS filename really should be in single quotes to\n");
    fprintf(f, "      protect it from the shell\n");

    fprintf(f, "\nOptions:\n");
    fprintf(f, "  -s           show file size\n");
    fprintf(f, "  -d           show file creation date\n");
    fprintf(f, "  -p           show file protection\n");
    fprintf(f, "  -o           show file owner\n");
    fprintf(f, "  -b           show file size in bytes rather than blocks\n");
    fprintf(f, "  -l           long format - show all the above\n");
    fprintf(f, "  -e           show everything (a bit like DIR/FULL)\n");
    fprintf(f, "  -n           don't show header. Useful for shell scripts\n");
    fprintf(f, "  -c           Force single-column output on ttys (default for files)\n");
    fprintf(f, "  -t           Show total bytes/blocks\n");
    fprintf(f, "  -T <secs>    Set connection timeout (default 60 seconds)\n");
    fprintf(f, "  -w <size>    width of multi-column output\n");
    fprintf(f, "  -f <size>    maximum width of filename field\n");
    fprintf(f, "  -? -h        display this help message\n");
    fprintf(f, "  -v           increase verbosity\n");
    fprintf(f, "  -V           show version number\n");

    fprintf(f, "\nExamples:\n\n");
    fprintf(f, " dndir -l 'myvax::*.*'\n");
    fprintf(f, " dndir 'cluster\"christine thecats\"::disk$users:[cats.pics]*.jpg;'\n");
    fprintf(f, "\n");
}


int main(int argc, char *argv[])
{
    int     opt;
    char    name[80],cdt[25],owner[20],prot[22];
    long    size = 0L;
    int     show_date = 0;
    int     show_size = 0;
    int     show_owner = 0;
    int     show_protection = 0;
    int     show_total = 0;
    int     show_header = 1;
    int     show_bytes = 0;
    int     show_full = 0;
    int     single_column = 0;
    int     term_width;
    int     entries_per_line;
    int     printed;
    int     just_shown_header = 0;
    int     verbosity = 0;
    int     connect_timeout = 60;
    unsigned long total = 0;
    unsigned int  filename_width = 18;

    if (argc < 2)
    {
        dndir_usage(stdout);
        exit(0);
    }

    // Get the terminal width and use it for the default
    if (isatty(STDOUT_FILENO))
    {
        struct winsize w;
        int st;

        st = ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
        if (st)
        {
            perror("ioctl on stdout");
            term_width = 80;
        }
        else
        {
            term_width = w.ws_col;
        }
        if (!term_width) term_width = 80;
    }
    else
    {
        single_column = 1; // Output to a file
        term_width = 132;
    }


// Get command-line options
    opterr = 0;
    optind = 0;
    while ((opt=getopt(argc,argv,"?hvVvcepndlostbw:f:T:")) != EOF)
    {
        switch(opt)
        {
        case 'h':
            dndir_usage(stdout);
            exit(1);

        case '?':
            dndir_usage(stderr);
            exit(1);

        case 'p':
            show_protection++;
            single_column++;
            break;

        case 'o':
            show_owner++;
            single_column++;
            break;

        case 'c':
            single_column++;
            break;

        case 'b':
            show_bytes++;
            break;

        case 's':
            show_size++;
            single_column++;
            break;

        case 'd':
            show_date++;
            single_column++;
            break;

        case 'l':
            show_date++;
            show_size++;
            show_protection++;
            show_owner++;
            single_column++;
            show_bytes++;
            break;

        case 'e':
            show_full++;
            single_column++;
            show_date=0;
            show_size=0;
            show_protection=0;
            show_owner=0;
            show_bytes=0;
            break;

        case 'n':
            show_header=0;
            break;

        case 't':
            show_total++;
            break;

        case 'v':
            verbosity++;
            break;

        case 'w':
            term_width=atoi(optarg);
            break;

        case 'T':
            connect_timeout=atoi(optarg);
            break;

        case 'f':
            filename_width=atoi(optarg);
            break;

        case 'V':
            printf("\ndndir from dnprogs version %s\n\n", VERSION);
            exit(1);
            break;
        }
    }

    if (optind >= argc)
    {
        dndir_usage(stderr);
        exit(2);
    }


    init_logging("dndir", 'e', false);

    // Work out the width of the printout
    entries_per_line = term_width / (filename_width+2);
    printed = 0;

    dap_connection conn(verbosity);
    char dirname[256] = {'\0'};
    conn.set_connect_timeout(connect_timeout);
    if (!conn.connect(argv[optind], dap_connection::FAL_OBJECT, dirname))
    {
        fprintf(stderr, "%s\n", conn.get_error());
        return -1;
    }

    // Exchange config messages
    if (!conn.exchange_config())
    {
        fprintf(stderr, "Error in config: %s\n", conn.get_error());
        return -1;
    }

    // Default to a full wildcard if no filename is given. This will cope with
    // the situation where no directory is provided (node::) and where a
    // directory (node::[christine]) is provided. Logical names must end with
    // a colon for this to happen or we will not be able to distinguish them
    // from filenames

    // Make use of the remote system type to decide whether a full wildcard
    // is "*.*;*" (system supports file versions), "*.*" (systems with file
    // extensions) and "*" (for unix-like systems)
    char lastchar('\0');
    if (dirname[0]) lastchar = dirname[strlen(dirname)-1];
    if (lastchar == ']' || lastchar == ':' || dirname[0] == '\0')
        switch (conn.get_remote_os())
        {
            case dap_config_message::OS_RSX11S:
            case dap_config_message::OS_RSX11M:
            case dap_config_message::OS_RSX11D:
            case dap_config_message::OS_IAS:
            case dap_config_message::OS_VAXVMS:
            case dap_config_message::OS_TOPS20:
            case dap_config_message::OS_RSX11MP:
                strcat(dirname, "*.*;*");
                break;

            case dap_config_message::OS_ULTRIX:
            case dap_config_message::OS_ULTRIX11:
            case dap_config_message::OS_LINUX:
	    case dap_config_message::OS_PYDECNET:
                strcat(dirname, "*");
                break;

            default:
              strcat(dirname, "*.*");
                break;
        }

    dap_access_message acc;
    acc.set_accfunc(dap_access_message::DIRECTORY);
    acc.set_accopt(1);
    acc.set_filespec(dirname);
    acc.set_display(dap_access_message::DISPLAY_MAIN_MASK |
                    dap_access_message::DISPLAY_DATE_MASK |
                    dap_access_message::DISPLAY_PROT_MASK);
    acc.write(conn);

    bool name_pending = false;
    if (show_full)
    {
        if (show_full_details(dirname, conn)) goto finished;

    }
    else
    {
        dap_message *m;
        char volname[256];

        // Loop through the files we find
        while ( ((m=dap_message::read_message(conn, true) )) )
        {
            switch (m->get_type())
            {
                case dap_message::NAME:
                {
                    dap_name_message *nm = (dap_name_message *)m;

                    if (name_pending)
                    {
                        name_pending = false;
                        
                        if (show_total) total += size;
                        print_short(filename_width,
                                    show_size,
                                    show_date,
                                    show_owner,
                                    show_protection,
                                    single_column,
                                    entries_per_line,
                                    size,
                                    name, owner, cdt,prot, &printed);
                    }
                    
                    if (nm->get_nametype() == dap_name_message::VOLUME &&
                        show_header)
                    {
                        printf("\nDirectory of %s",nm->get_namespec());
                        just_shown_header = 1;
                        strcpy(volname, nm->get_namespec());
                    }

                    if (nm->get_nametype() == dap_name_message::DIRECTORY &&
                        show_header)
                    {
                        if (!just_shown_header)
                        {
                            // space out directories.
                            printf("\n\nDirectory of %s", volname);
                        }
                        printf("%s\n\n",nm->get_namespec());
                        just_shown_header = 0;
                    }

                    if (nm->get_nametype() == dap_name_message::FILENAME)
                    {
                        strcpy(name, nm->get_namespec());
                        name_pending = true;
                    }
                }
                break;

                case dap_message::PROTECT:
                {
                    dap_protect_message *pm = (dap_protect_message *)m;
                    strcpy(owner, pm->get_owner());
                    strcpy(prot, pm->get_protection());
                }
                break;

                case dap_message::ATTRIB:
                {
                    dap_attrib_message *am = (dap_attrib_message *)m;
                    if (show_bytes)
                        size = am->get_size();
                    else
                        size = am->get_alq();
                }
                break;

                case dap_message::DATE:
                {
                    dap_date_message *dm = (dap_date_message *)m;
                    strcpy(cdt, dm->make_y2k(dm->get_cdt()));
                }
                break;

                case dap_message::ACK:
                {
                    if (name_pending)
                    {
                            name_pending = false;
                            if (show_total) total += size;
                            print_short(filename_width,
                                        show_size,
                                        show_date,
                                        show_owner,
                                        show_protection,
                                        single_column,
                                        entries_per_line,
                                        size,
                                        name, owner, cdt,prot, &printed);
                    }
                }
                break;

                case dap_message::STATUS:
                {
                    // Send a SKIP if the file is locked, else it's an error
                    dap_status_message *sm = (dap_status_message *)m;
                    if (sm->get_code() == 0x4030)
                    {
                        printf("%-*s", filename_width, name);
                        if (single_column)
                        {
                            printf("File is currently locked by another user\n");
                        }
                        else
                        {
                            if (++printed >= entries_per_line)
                            {
                                printf("\n");
                                printed = 0;
                            }
                        }
                        name_pending = false;

                        dap_contran_message cm;
                        cm.set_confunc(dap_contran_message::SKIP);
                        if (!cm.write(conn))
                        {
                            fprintf(stderr, "Error sending skip: %s\n", conn.get_error());
                            goto finished;
                        }
                    }
                    else
                    {
                        printf("Error opening %s: %s\n", dirname,
                               sm->get_message());
                        name_pending = false;
                        goto flush;
                    }
                    break;
                }
            case dap_message::ACCOMP:
                goto flush;
            }
            delete m;
        }

        // An error:
        fprintf(stderr, "Error: %s\n", conn.get_error());
        return 2;
    }

 flush:
    if (name_pending)
    {
        if (show_total) total += size;
        print_short(filename_width,
                    show_size,
                    show_date,
                    show_owner,
                    show_protection,
                    single_column,
                    entries_per_line,
                    size,
                    name, owner, cdt,prot, &printed);
    }

 finished:
    conn.close();

    if (!single_column) printf("\n");

    if (show_total)
    {
        if (show_bytes)
        {
            printf("\n%-*s  %7ld\n\n", filename_width, "Total bytes", total);
        }
        else
        {
            printf("\n%-*s  %7ld\n\n", filename_width, "Total blocks", total);
        }
    }
    return 0;
}


// Emulate (as far as we can) DIR/FULL
bool show_full_details(char *dirname, dap_connection &conn)
{
    dap_message *m;
    dap_name_message       *vol_name_msg = NULL;
    dap_name_message       *dir_name_msg = NULL;
    dap_name_message       *name_msg     = NULL;
    dap_protect_message    *protect_msg  = NULL;
    dap_date_message       *date_msg     = NULL;
    dap_attrib_message     *attrib_msg   = NULL;
    bool                    name_pending = false;

    printf("\n");

    // Loop through the files we find
    while ( ((m=dap_message::read_message(conn, true) )) )
    {
        switch (m->get_type())
        {
            case dap_message::NAME:
                name_msg = (dap_name_message *)m;
                switch (name_msg->get_nametype())
                {
                case dap_name_message::VOLUME:
                    vol_name_msg = name_msg;
                    break;
                case dap_name_message::DIRECTORY:
                    dir_name_msg = name_msg;
                    printf("Directory %s%s\n\n",
                           vol_name_msg->get_namespec(),
                           dir_name_msg->get_namespec());
                    break;
                case dap_name_message::FILENAME:
                    name_pending = true;
                }
                break;

            case dap_message::ATTRIB:
                attrib_msg = (dap_attrib_message *)m;
                break;

            case dap_message::DATE:
                date_msg = (dap_date_message *)m;
                break;

            case dap_message::PROTECT:
                protect_msg = (dap_protect_message *)m;
                break;

            case dap_message::STATUS:
            {
                // Send a SKIP if the file is locked, else it's an error
                dap_status_message *sm = (dap_status_message *)m;
                if (sm->get_code() == 0x4030)
                {
                    printf("%s  File current locked by another user\n\n",
                           name_msg->get_namespec());

                    dap_contran_message cm;
                    cm.set_confunc(dap_contran_message::SKIP);
                    if (!cm.write(conn))
                    {
                        fprintf(stderr, "Error sending skip: %s\n", conn.get_error());
                        return false;
                    }
                }
                else
                {
                    printf("Error opening %s: %s\n", dirname,
                           sm->get_message());
                    return false;
                }
                name_pending = false;
            }
            break;

            case dap_message::ACK:
                if (name_pending)
                {
                    name_pending = false;
                    print_long(name_msg, attrib_msg, date_msg, protect_msg);

                    delete name_msg;
                    delete protect_msg;
                    delete attrib_msg;
                    delete date_msg;
                }
                break;

            case dap_message::ACCOMP:
                goto full_flush;
        }
    }

 full_flush:
    if (name_pending)
    {
        print_long(name_msg, attrib_msg, date_msg, protect_msg);

        delete name_msg;
        delete protect_msg;
        delete attrib_msg;
        delete date_msg;
    }
    return true;
}

// Print the file in short format
void print_short(
    unsigned int filename_width,
    int show_size,
    int show_date,
    int show_owner,
    int show_protection,
    int single_column,
    int entries_per_line,
    long size,
    char *name,
    char *owner,
    char *cdt,
    char *prot,
    int *printed
)
{
    printf("%-*s", filename_width, name);
    if (show_size || show_date || show_owner || show_protection)
        printf("  ");
    if (single_column)
    {
        if (strlen(name) >= filename_width &&
            (show_protection || show_date ||
             show_owner || show_date || show_size))
        {
            printf("\n%-*s  ",filename_width, "");
        }
        if (show_size)
            printf("%7ld ", size);
        if (show_date)
            printf("%s ", cdt);
        if (show_owner)
            printf("%s ", owner);
        if (show_protection)
            printf("%s", prot);
        printf("\n");
    }
    else
    {
        if (++(*printed) >= entries_per_line)
        {
            printf("\n");
            *printed = 0;
        }

        // Long filename, skip a field.
        if (strlen(name) >= filename_width && *printed)
        {
            if (*printed+1 >= entries_per_line)
            {
                printf("\n");
                *printed = 0;
            }
            else
            {
                printf("%-*s",(int)(filename_width-(strlen(name)-filename_width)), "");
            }
            ++(*printed);
        }
    }
}


// Print directory in long format
void print_long
(
    dap_name_message   *name_msg,
    dap_attrib_message *attrib_msg,
    dap_date_message   *date_msg,
    dap_protect_message   *protect_msg
)
{
    printf("%s\n", name_msg->get_namespec());
    printf("Size:       %7d/%-7d    Owner:    %s\n",
           attrib_msg->get_ebk(),
           attrib_msg->get_alq(),
           protect_msg->get_owner());
    printf("Created:   %s\n",
           date_msg->make_y2k(date_msg->get_cdt()));
    printf("Revised:   %s (%d)\n",
           date_msg->make_y2k(date_msg->get_rdt()),
           date_msg->get_rvn());
    if (date_msg->get_edt()[0] == '\0')
        printf("Expires:   <None specified>\n");
    else
        printf("Expires:   %s\n",
               date_msg->make_y2k(date_msg->get_edt()));

    if (date_msg->get_bdt()[0] == '\0')
        printf("Backup:    <No backup recorded>\n");
    else
        printf("Backup:    %s\n",
               date_msg->make_y2k(date_msg->get_bdt()));

    printf("File organization:  ");
    switch (attrib_msg->get_org())
    {
    case dap_attrib_message::FB$SEQ:
        printf("Sequential\n");
        break;
    case dap_attrib_message::FB$REL:
        printf("Relative\n");
        break;
    case dap_attrib_message::FB$IDX:
        printf("Indexed\n");
        break;
    default:
        printf("Unknown\n");
        break;
    }

    if (attrib_msg->get_fop_bit(dap_attrib_message::FB$DIR))
        printf("                    Directory file\n");

    printf("Record Format:      ");
    switch (attrib_msg->get_rfm())
    {
    case dap_attrib_message::FB$UDF:
        printf("Undefined\n");
        break;
    case dap_attrib_message::FB$FIX:
        printf("Fixed length %d byte records\n", attrib_msg->get_mrs());
        break;
    case dap_attrib_message::FB$VAR:
        printf("Variable");
        if (attrib_msg->get_lrl())
            printf(", maximum %d bytes", attrib_msg->get_lrl());
        printf("\n");
        break;
    case dap_attrib_message::FB$VFC:
        printf("VFC, %d byte header\n", attrib_msg->get_fsz());
        break;
    case dap_attrib_message::FB$STM:
        printf("Stream\n");
        break;
    case dap_attrib_message::FB$STMCR:
        printf("Stream_CR\n");
        break;
    case dap_attrib_message::FB$STMLF:
        printf("Stream_LF\n");
        break;
    }

    printf("Record Attributes:  ");
    bool done_one=false;
    if (attrib_msg->get_rat() & 1<<dap_attrib_message::FB$FTN)
    {
        printf("Fortran carriage control");
        done_one=true;
    }

    if (attrib_msg->get_rat() & 1<<dap_attrib_message::FB$CR)
    {
        if (done_one) printf(", ");
        printf("Carriage return carriage control");
        done_one=true;
    }

    if (attrib_msg->get_rat() & 1<<dap_attrib_message::FB$PRN)
    {
        if (done_one) printf(", ");
        printf("Print file carriage control");
        done_one=true;
    }

    if (attrib_msg->get_rat() & 1<<dap_attrib_message::FB$BLK)
    {
        if (done_one) printf(", ");
        printf("Non-spanned");
        done_one=true;
    }

    if (attrib_msg->get_rat() & 1<<dap_attrib_message::FB$LSA)
    {
        if (done_one) printf(", ");
        printf("Line Sequenced ASCII");
        done_one=true;
    }
    if (!done_one) printf("None");
    printf("\n");

    printf("File protection:    ");
    char prot[64];
    strcpy(prot, protect_msg->get_protection()+1);
    prot[strlen(prot)-1] = '\0';

    char *p = strtok(prot, ",");
    for (int c=0; c<4; c++)
    {
        switch(c)
        {
        case 0:
            printf("System:");
            break;
        case 1:
            printf(", Owner:");
            break;
        case 2:
            printf(", Group:");
            break;
        case 3:
            printf(", World:");
            break;
        }
        if (p) printf("%s", p);
        p=strtok(NULL, ",");
    }
    printf("\n\n");
}
