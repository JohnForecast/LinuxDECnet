
class fal_erase: public fal_task
{
  public:
    fal_erase(dap_connection &c, int v, fal_params &p);
    virtual ~fal_erase();
    virtual bool process_message(dap_message *m);
    
  private:
};
