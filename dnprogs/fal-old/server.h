// Class for FAL server. This class receives messages and passes them down to
// fal_task objects that do the real work.
// It is the basic child of the FAL listener and encapsulates the job of a
// forked process that handles a single connection.
//
// The only DAP message handled by the server is the mandatory CONFIG message,
// all others are passed down to dap_task classes.

class fal_server
{
  public:
    fal_server(dap_connection &c, fal_params &p):
	conn(c),
	verbose(p.verbosity),
	params(p)
	{}
    ~fal_server() {};
    bool run();
    void closedown();
    
 private:
    void create_access_task(dap_message *m);
    bool exchange_config();
    const char *func_name(int);
    
    dap_connection    &conn;
    fal_task          *current_task;
    int                verbose;
    bool               need_crcs;
    struct fal_params  params;

    dap_attrib_message  *attrib_msg;
    dap_alloc_message   *alloc_msg;
    dap_protect_message *protect_msg;
};
