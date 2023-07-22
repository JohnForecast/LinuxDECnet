
class fal_directory: public fal_task
{
  public:
    fal_directory(dap_connection &c, int v, fal_params &p);
    virtual ~fal_directory();
    virtual bool process_message(dap_message *m);
    
  private:
    dap_name_message       *name_msg;
    dap_protect_message    *prot_msg;
    dap_date_message       *date_msg;
    dap_ack_message        *ack_msg;
    dap_attrib_message     *attrib_msg;
    dap_alloc_message      *alloc_msg;

    bool send_dir_entry(char *path, int);
};
