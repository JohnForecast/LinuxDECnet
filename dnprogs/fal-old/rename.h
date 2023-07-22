
class fal_rename: public fal_task
{
  public:
    fal_rename(dap_connection &c, int v, fal_params &p);
    virtual ~fal_rename();
    virtual bool process_message(dap_message *m);
    
  private:
    char oldname[PATH_MAX];
    int  display;

    bool send_name(char *);
};
