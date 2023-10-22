/*
 * phone_ncurses.c
 *
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <ncurses.h>
#include <panel.h>

#include "phone.h"
#include "backend.h"

#define MAX_WINDOWS 6

static WINDOW* setup_ncurses(void);
static void new_talk_window(int, char *);
static void draw_window_decorations(int win);

// Callback routines.
static void add_new_caller(int, int, char *, fd_callback);
static void show_error(int level, char *msg);
static void delete_caller(int);
static void quit(void);
static void write_text(char *name, char *msg);
static void hold_window(int held, char *name);
static int  get_fds(struct fd_list *fds);
static void answer_caller(int int_fd, int out_fd);
static void lost_server(void);
static void open_display_window(char *);
static void display_line(char *text);
static void rearrange_windows(int num);

static void draw_title(WINDOW *window);

static int     Finished = FALSE;
static int     Switch_Hook_Char = '%';
static WINDOW *Main_Window;
static enum {STATE_TALK, STATE_COMMAND} state = STATE_COMMAND;
static int     Screen_Width, Screen_Height;
static int     local_sock;
static char   *end_message=NULL;
static WINDOW *display_window = NULL;
static PANEL  *display_panel  = NULL;
static int     sigwinch_happened = 0;

/* Cursor position in command mode */
static int  cmd_x=1,  cmd_y=1;
static char command[80];

// All the information about a user. userinfo[0] is the local user.
static struct user_info
{
    PANEL      *panel;
    WINDOW     *window; // The window belonging to the panel.
    int         fd;
    int         out_fd;
    char        name[64];
    int         window_bottom;
    int         held; // 0=not held, 1=held by me, 2=held by remote
    fd_callback fd_callback;
} userinfo[MAX_WINDOWS];
static int num_users=1;
static int num_connected_users=1;

// Called when a user presses a key
static int getch_callback(int fd)
{
    int key;

    key = getch();
    if (key == ERR) return 0;

// If we are dialling then any key will cancel.
    cancel_dial();

    // Display window is open - close it.
    if (display_window)
    {
	del_panel(display_panel);
        delwin(display_window);
	update_panels();
	show_error(0, "");
	doupdate();
	display_window = NULL;
    }

// Deal with global key assignments first
    if (key == 4) // Ctrl-D
    {
	Finished = TRUE;
	return 0 ;
    }

    if (key == 23) // Ctrl-W refreshes the screen
    {
	wrefresh(curscr);
	return 0;
    }

    if (key == 26) // Ctrl-Z is hangup
    {
	do_command("hangup");
	return 0;
    }

    // Switch-hook char - change mode to command
    if (state == STATE_TALK && key == Switch_Hook_Char)
    {
	state = STATE_COMMAND;
	cmd_x=1;
	cmd_y=1;

	// Clear the last command
	wmove(Main_Window, cmd_y, cmd_x);
	wclrtoeol(Main_Window);
	wrefresh(Main_Window);
	return 0;
    }

    // Draw the key pressed or do the necessary action.
    if (state == STATE_TALK)
    {
        int i;
	int x,y;

	getyx(userinfo[0].window, y, x);
	wattrset(userinfo[0].window, A_NORMAL | COLOR_PAIR(COLOR_WHITE));
	/* Draw char - interpret CR */
	if (isprint(key))
	    wechochar(userinfo[0].window, key);

	// CR may need to scroll the window.
	if (key == '\r')
	{
	    getyx(userinfo[0].window, y, x);
	    if (y == userinfo[0].window_bottom)
	    {
		wmove(userinfo[0].window, y, 0);
		scroll(userinfo[0].window);
	    }
	    else
	    {
		wmove(userinfo[0].window, y+1, 0);
	    }
	}

	if (key == '\014')
	{
	    werase(userinfo[0].window);
	    draw_window_decorations(0);
	    wmove(userinfo[0].window, 1, 0);
	}

	if (key == KEY_BACKSPACE && x > 0)
	{
	    wmove(userinfo[0].window, y, x-1);
	    wechochar(userinfo[0].window, ' ');
	    wmove(userinfo[0].window, y, x-1);
	    key = 127; // convert to VMS Backspace
	}
	wrefresh(userinfo[0].window);

	// Send char to remote system(s)
	for (i=1; i<num_users; i++)
	{
	    char keychar = key;
	    send_data(userinfo[i].out_fd, (char *)&keychar, 1);
	}
	return 0;
    }

    if (state == STATE_COMMAND)
    {
	/* Draw char - collect chars and interpret LF */
	if (isprint(key) && key != Switch_Hook_Char)
	{
	    wattrset(Main_Window, A_NORMAL | COLOR_PAIR(COLOR_WHITE));
	    command[cmd_x-1] = key;
	    mvwprintw(Main_Window, cmd_y,cmd_x++, "%c", key);
	}

	if (key == KEY_BACKSPACE && cmd_x > 1)
	{
	    cmd_x--;
	    mvwprintw(Main_Window, cmd_y, cmd_x," ");
	    wmove(Main_Window, cmd_y, cmd_x);
	}


	if (key == '\r')    // Action command
	{
	    command[cmd_x-1] = '\0';

	    do_command(command);
	    cmd_x=1;
	    cmd_y=1;

	    // Clear the last command
	    wmove(Main_Window, cmd_y, cmd_x);
	    wclrtoeol(Main_Window);

	    if (num_connected_users > 1 && !userinfo[0].held)
	    {
		state = STATE_TALK;
	    }
	}
    }
    wrefresh(stdscr);
    return 0;
}

// Set up the screen
int ncurses_init(char s)
{
    int     length;
    WINDOW* window;
    struct  callback_routines cr;

    Switch_Hook_Char = s;
    window = setup_ncurses();
    if (window)
    {
	cr.new_caller    = add_new_caller;
	cr.delete_caller = delete_caller;
	cr.show_error    = show_error;
	cr.write_text    = write_text;
	cr.get_fds       = get_fds;
	cr.answer        = answer_caller;
	cr.hold          = hold_window;
	cr.lost_server   = lost_server;
	cr.open_display_window = open_display_window;
	cr.display_line  = display_line;
	cr.quit          = quit;
	register_callbacks(&cr);
    }
    return 0;
}

static void resize_screen(int rows, int cols)
{
	resize_term(rows, cols);
	Screen_Width = cols;
	Screen_Height = rows;
	wresize(stdscr, rows, cols);

	werase(Main_Window);
	draw_title(Main_Window);
	wrefresh(stdscr);

	/* Resize all sub-windows with conversations in */
	rearrange_windows(num_users);
	wrefresh(curscr);
}

// Main loop for ncurses display
int ncurses_run(char *init_cmd)
{
    int    status, i;
    char   my_title[255];
    struct timeval tv = {0,0};

    userinfo[0].fd          = STDIN_FILENO;
    userinfo[0].fd_callback = getch_callback;
    new_talk_window(0, get_local_name());

    local_sock = init_backend();
    if (local_sock == -1)
    {
	Finished = 1; /* That didn't last long did it! */
	end_message = "The phone server is not running, please contact your system administrator";
    }

    if (num_connected_users > 1) state = STATE_TALK;
    while (!Finished)
    {
	fd_set fds;
	int    i;

	FD_ZERO(&fds);
	if (local_sock != -1) FD_SET(local_sock, &fds);
	for (i=0; i<num_users; i++)
	    FD_SET(userinfo[i].fd, &fds);

	status = select(FD_SETSIZE, &fds, NULL, NULL, init_cmd?&tv:NULL);
	if (status < 0)
	{
	    if (sigwinch_happened)
	    {
		    struct winsize size;

		    if (ioctl(fileno(stdout), TIOCGWINSZ, &size) == 0) {
			    resize_screen(size.ws_row, size.ws_col);
		    }
		    sigwinch_happened = 0;
	    }

#ifdef ERESTART
	    if (errno != EINTR && errno != ERESTART)
#else
	    if (errno != EINTR)
#endif
	    {
	        perror("Error in select");
		end_message="An error occurred in select()";
		Finished = 1;
	    }
	}
	else
	{
	    if (local_sock != -1 && FD_ISSET(local_sock, &fds))
	        localsock_callback(local_sock);

	    for (i=0; i<num_users; i++)
	    {
	        if (FD_ISSET(userinfo[i].fd, &fds))
		    userinfo[i].fd_callback(userinfo[i].fd);
	    }
	}

	// Execute initial command after a loop around select() so we get
	// any connections from the server established before attempting an
	// intial ANSWER or REJECT command
	if (init_cmd)
	{
	    do_command(init_cmd);
	    init_cmd = NULL;
	}
    }

/*
 * Close any DECnet connections
 */
    for (i=1; i<num_users; i++)
    {
	close_connection(userinfo[i].out_fd); // Sends hangup.
	close(userinfo[i].fd);
	close(userinfo[i].out_fd);
    }

/*
 * Clear up after ncurses
 */
    clear();
    refresh();
    endwin();

    if (end_message)
	    printf("%s\n", end_message);

    return 0;
}

static void window_size_change(int sig)
{
	sigwinch_happened = 1;
}

static void draw_title(WINDOW *window)
{
    char date[32];
    time_t the_time;
    struct tm the_tm;

    /* Format the day */
    the_time = time(NULL);
    the_tm = *localtime(&the_time);
    strftime(date, sizeof(date), "%d-%b-%Y", &the_tm);

/* Draw the main title */
    wattrset(window, A_BOLD | COLOR_PAIR(COLOR_YELLOW));
    mvwprintw(window, 0,Screen_Width/2-10,"%s", "Linux Phone Facility");

    wattrset(window, A_BOLD | COLOR_PAIR(COLOR_WHITE));
    mvwprintw(window, 0,Screen_Width-11,"%s", date);

/* Draw the prompt */
    wattrset(window, A_DIM | COLOR_PAIR(COLOR_WHITE));
    mvwprintw(window, 1,0,"%c", Switch_Hook_Char);

    wattrset(window, A_DIM | COLOR_PAIR(COLOR_WHITE));
    mvwprintw(window, 3,0,"%s", "");

    wmove(window, 3, 0);
    wattrset(window, A_BOLD | COLOR_PAIR(COLOR_WHITE));
    whline(window, ACS_HLINE, Screen_Width);
    wmove(window, 1, 1);
}

/*
 * Initialise ncurses and return the top-level window ID
 */
static WINDOW* setup_ncurses()
{
    WINDOW* window = NULL;

    window = initscr();
    if (window == NULL)
    {
	perror("Cannot init ncurses");
	return NULL;
    }

/* Setup terminal attributes */

    start_color();        /* Enable colour processing */
    noecho();             /* Don't echo input chars */
    nonl();               /* no newline at end of strings */
    keypad(stdscr, TRUE); /* Enable F-keys */
    cbreak();             /* No processing of control characters */
    raw();                /* Disable ^C, ^Z */
    meta(stdscr, TRUE);   /* Enable meta-keys */
    getmaxyx(stdscr, Screen_Height, Screen_Width);    /* Get the screen size */

    signal(SIGWINCH, window_size_change);

/* Set up colour pairs that match the foreground colours */
    init_pair(COLOR_BLACK,   COLOR_BLACK,   COLOR_BLACK);
    init_pair(COLOR_RED,     COLOR_RED,     COLOR_BLACK);
    init_pair(COLOR_GREEN,   COLOR_GREEN,   COLOR_BLACK);
    init_pair(COLOR_YELLOW,  COLOR_YELLOW,  COLOR_BLACK);
    init_pair(COLOR_BLUE,    COLOR_BLUE,    COLOR_BLACK);
    init_pair(COLOR_MAGENTA, COLOR_MAGENTA, COLOR_BLACK);
    init_pair(COLOR_CYAN,    COLOR_CYAN,    COLOR_BLACK);
    init_pair(COLOR_WHITE,   COLOR_WHITE,   COLOR_BLACK);

    draw_title(window);

/* Update the whole screen now we have created all the windows. From now
   on all updates will be optimised */
    wrefresh(stdscr);
    Main_Window = window;
    return window;
}

//
// Create a new talk window
//
static void new_talk_window(int num, char *name)
{
    // Create a window with gash dimensions
    userinfo[num].window = newwin(Screen_Height, Screen_Width,0,0);
    userinfo[num].panel = new_panel(userinfo[num].window);
    userinfo[num].held = 0;
    strcpy(userinfo[num].name, name);

    // Arrange according to screen space
    rearrange_windows(num+1);
    scrollok(userinfo[num].window, TRUE);

    wmove(userinfo[num].window, 1, 0);
    wrefresh(userinfo[num].window);
}

// Resize and move the windows to accomodate a new/deleted user
static void rearrange_windows(int num)
{
    int win_height;
    int win_y;
    int i;

    win_height = (Screen_Height-4) / (num);

    // Impose a maximum height of half the display area.
    if (win_height > (Screen_Height-4)/2)
	win_height = (Screen_Height-4)/2;

    for (i=0; i<num; i++)
    {
	int x,y;

	// Save cursor position
	getyx(userinfo[i].window, y, x);

	win_y = 4 + (win_height*(i));

	// Remove the bottom rule when growing windows
	wmove(userinfo[i].window, userinfo[i].window_bottom+1, 0);
	wclrtoeol(userinfo[i].window);

	wresize(userinfo[i].window, win_height, Screen_Width);
	wsetscrreg(userinfo[i].window, 1, win_height-2);

	move_panel(userinfo[i].panel, win_y, 0);

	userinfo[i].window_bottom = win_height-2;
	draw_window_decorations(i);

	// Restore cursor position
	wmove(userinfo[i].window, y,x);
    }
    update_panels();
    doupdate();
}

/* ------------------------------------------------------------------------- */
/*                Routines that can be called from the back-end              */
/* ------------------------------------------------------------------------- */
static void add_new_caller(int in_fd, int out_fd, char *name, fd_callback fdc)
{
    userinfo[num_users].fd          = in_fd;
    userinfo[num_users].out_fd      = out_fd;
    userinfo[num_users].fd_callback = fdc;
    strcpy(userinfo[num_users].name, name);

    // Only create the window if the user has been answered.
    if (out_fd != -1)
    {
	new_talk_window(num_users, name);
    }
    else
    {
	userinfo[num_users].panel  = NULL;
	userinfo[num_users].window = NULL;
    }
    num_users++;
}


static void show_error(int level, char *msg)
{
    // Ring the bell if the first char was a 7 (BEL)
    if (msg[0] == 7)
    {
	msg++;
	beep();
    }

    wattrset(Main_Window, A_BOLD | COLOR_PAIR(COLOR_WHITE));
    wmove(Main_Window, cmd_y+1, 0);
    wclrtoeol(Main_Window);
    mvwprintw(Main_Window, cmd_y+1,0, "%s", msg);
    wrefresh(Main_Window);
}

static void write_text(char *name, char *msg)
{
    int i,j;

    for (i=0; i<num_users; i++)
    {
	if (strcmp(name, userinfo[i].name) == 0)
	{
	    int x,y;

	    wattrset(userinfo[i].window, A_NORMAL | COLOR_PAIR(COLOR_WHITE));

	    for (j=0; j<strlen(msg); j++)
	    {
		if (isprint(msg[j]))
		    wechochar(userinfo[i].window, msg[j]);

		if (msg[j] == '\r')
		{
		    getyx(userinfo[i].window, y, x);
		    if (y == userinfo[i].window_bottom)
		    {
			wmove(userinfo[i].window, y, 0);
			scroll(userinfo[i].window);
		    }
		    else
		    {
			wmove(userinfo[i].window, y+1, 0);
		    }
		}

		if (msg[j] == '\014') // Clear window
		{
		    werase(userinfo[i].window);
		    draw_window_decorations(i);
		    wmove(userinfo[i].window, 1, 0);
		}

		if (msg[j] == 127) // Backspace
		{
		    getyx(userinfo[i].window, y, x);
		    if (x)
		    {
			wmove(userinfo[i].window, y, x-1);
			wechochar(userinfo[i].window, ' ');
			wmove(userinfo[i].window, y, x-1);
		    }
		}
	    }
	    wrefresh(userinfo[i].window);
	}
    }
}

static void lost_server()
{
  local_sock = -1;
  show_error(1, "phoned server has died");
}


static void quit()
{
    Finished = 1;
}

static void delete_caller(int fd)
{
    int i,j;
    int done = 0;

    for (i=1; i<num_users && !done; i++)
    {
	if (userinfo[i].fd == fd ||
	    userinfo[i].out_fd == fd)
	{
	    close(fd);
	    close(userinfo[i].out_fd);
	    if (userinfo[i].panel)
	    {
		del_panel(userinfo[i].panel);
		delwin(userinfo[i].window);
		update_panels();
	    }

	    // Remove it from the list
	    if (i != num_users)
	    {
		for (j=num_users-1; j>i; j--)
		{
		    userinfo[j-1] = userinfo[j];
		}
	    }
	    num_users--;
	    num_connected_users--;
	    done = 1;
	    break;
	}
    }

    // These two lines ensure that the last remote window is removed from
    // the screen  when that user hangs up
    wmove(Main_Window, 4, 0);
    wclrtobot(Main_Window);

    // If we are not talking to anyone then go back to command mode
    wmove(Main_Window, cmd_y, cmd_x);
    if (num_connected_users == 1) state = STATE_COMMAND;

    // Re-arrange the rest of the screen - calls doupdate()
    rearrange_windows(num_users);
}

// This just draws the window title and dividing lines
static void draw_window_decorations(int win)
{
    wattrset(userinfo[win].window, A_BOLD | COLOR_PAIR(COLOR_WHITE));

    wmove(userinfo[win].window, 0, 0);
    wclrtoeol(userinfo[win].window);

    mvwprintw(userinfo[win].window, 0,
	      Screen_Width/2-strlen(userinfo[win].name)/2, "%s",
	      userinfo[win].name);

    if (userinfo[win].held)
    {
	wattrset(userinfo[win].window, A_NORMAL | COLOR_PAIR(COLOR_WHITE));
	if (userinfo[win].held == 2)
	    mvwprintw(userinfo[win].window, 0, 0, "%s", "(YOU HAVE HELD)");
	else
	    mvwprintw(userinfo[win].window, 0, Screen_Width-14, "%s", "(HAS YOU HELD)");

    }

    wattrset(userinfo[win].window, A_BOLD | COLOR_PAIR(COLOR_WHITE));
    wmove(userinfo[win].window, userinfo[win].window_bottom+1, 0);
    whline(userinfo[win].window, ACS_HLINE, Screen_Width);
}

static void hold_window(int held, char *name)
{
    int i;
    int y,x;

    userinfo[0].held = held; // Also hold main window
    if (held)
	state = STATE_COMMAND; // and force command mode
    else
	state = STATE_TALK;    // back to command mode

    for (i=0; i<num_users; i++)
    {
	if (strcmp(name, userinfo[i].name) == 0)
	{
	    getyx(userinfo[i].window, y, x);

	    userinfo[i].held = held;
	    draw_window_decorations(i);
	    wmove(userinfo[i].window, y,x);
	    wrefresh(userinfo[i].window);
	}
    }
}

static int get_fds(struct fd_list *fds)
{
    int i;
    for (i=1; i<num_users; i++)
    {
	fds[i-1].out_fd       = userinfo[i].out_fd;
	fds[i-1].in_fd        = userinfo[i].fd;
	fds[i-1].remote_name  = userinfo[i].name;
    }
    return num_users-1;
}

static void answer_caller(int in_fd, int out_fd)
{
    int i;

    for (i=1; i<num_users; i++)
    {
	if (userinfo[i].fd == in_fd)
	{
	    userinfo[i].out_fd = out_fd;
	    new_talk_window(i, userinfo[i].name);
	    num_connected_users++;
	    state = STATE_TALK;
	    break;
	}
    }
}

/* Two routines dealing with the full-screen display window
   for HELP and DIRECTORY
 */
static void open_display_window(char *title)
{
    display_window = newwin(Screen_Height-4, Screen_Width,4,0);
    display_panel  = new_panel(display_window);

    update_panels();
    doupdate();
}

static void display_line(char *text)
{
    if (!display_window) return;

    waddstr(display_window, text);
    waddstr(display_window, "\n");
    wrefresh(display_window);
}

