
class fal_submit: public fal_task
{
  public:
    fal_submit(dap_connection &c, int v, fal_params &p);
    virtual ~fal_submit();
    virtual bool process_message(dap_message *m);
    
  private:
};
