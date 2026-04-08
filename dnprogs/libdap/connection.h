#ifndef LIBDAP_CONNECTION_H
#define LIBDAP_CONNECTION_H

// connection.h
//
// Encapsulates a DAP connection. Incoming and Outgoing
//

class dap_connection
{
 public:
    dap_connection(int verbosity);
    dap_connection(int socket, int bs, int verbosity);
    ~dap_connection();

    bool connect(char *node,  char *user, char *password, char *object);
    bool connect(char *node,  char *user, char *password, int   object);
    bool connect(char *fspec, int   object, char *tailspec);
    bool connect(char *fspec, char *object, char *tailspec);

    bool bind(char *object);
    bool bind(int object);
    bool bind_wild();
    
    dap_connection *waitfor();

    char *getbytes(int num);
    char *peekbytes(int num);
    int   putbytes(void *bytes, int num);
    int   check_length(int);
    int   get_length();
    int   read(bool);
    int   read_if_necessary(bool);
    int   write();
    int   send_crc(unsigned short);
    char *get_error();
    void  set_blocksize(int);
    int   get_blocksize();
    bool  have_bytes(int);
    int   set_blocked(bool onoff);
    void  allow_blocking(bool onoff);
    int   verbosity() {return verbose;};
    bool  parse(const char *fname,
		struct accessdata_dn &accessdata, char *node, char *filespec);
    void close();
    int  get_fd() { return sockfd; }
    int  get_remote_os() { return remote_os; };
    bool exchange_config();
    void clear_output_buffer();
    void set_connect_timeout(int seconds);
    
// Static utility functions
    static void makelower(char *s);
    static void makeupper(char *s);
    
 private:
    char  *buf;
    char  *outbuf;
    int    sockfd;
    int    bufptr;
    int    outbufptr;
    int    buflen;
    int    blocksize;
    int    have_shadow;
    int    verbose;
    bool   connected;
    bool   listening;
    bool   blocked;
    bool   blocking_allowed;
    bool   closed;
    int    last_msg_start;
    int    end_of_msg;
    int    remote_os;
    int    connect_timeout;
    struct nodeent *binadr;
    
    char *lasterror;
    char  errstring[256];

    static const int MAX_READ_SIZE = 16384;

    void create_socket();
    void initialise(int);
    bool set_socket_buffer_size();
    bool do_connect(const char *node, const char *user,
		    const char *password, sockaddr_dn &sockaddr);

    bool error_return(char *);
    const char *connerror(char *);
    
/* DECnet phase IV limits */
    static const int MAX_NODE     = 6;
    static const int MAX_USER     = 12;
    static const int MAX_PASSWORD = 40;
    static const int MAX_ACCOUNT  = 40;

 public:
    // Some DECnet object numbers
    static const unsigned int FAL_OBJECT    = 17;
    static const unsigned int NML_OBJECT    = 19;
    static const unsigned int MIRROR_OBJECT = 25;
    static const unsigned int EVL_OBJECT    = 26;
    static const unsigned int MAIL_OBJECT   = 27;
    static const unsigned int PHONE_OBJECT  = 29;
    static const unsigned int CTERM_OBJECT  = 42;
};
#endif
