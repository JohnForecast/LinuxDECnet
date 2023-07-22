
class fal_open: public fal_task
{
  public:
    fal_open(dap_connection &c, int v, fal_params &p,
	     dap_attrib_message *,
	     dap_alloc_message *,
	     dap_protect_message *);

    virtual ~fal_open();
    virtual bool process_message(dap_message *m);

  protected:

    glob_t        gl;
    unsigned int  glob_entry; // file entry in the glob structure

    int           display;
    FILE         *stream;
    bool          use_records;
    bool          write_access;
    bool          streaming; // no CONTROL message between records
    char         *buf;
    bool          create;
    unsigned int  block_size;

    dap_attrib_message  *attrib_msg;
    dap_alloc_message   *alloc_msg;
    dap_protect_message *protect_msg;

    bool send_file(int, long);
    void print_file();
    void delete_file();
    void truncate_file();
    bool put_record(dap_data_message *);
    void set_control_options(dap_control_message *);
    bool create_file(char *);
    void send_eof();

};
