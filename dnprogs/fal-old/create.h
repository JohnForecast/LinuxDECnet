
class fal_create: public fal_open
{
  public:
    fal_create(dap_connection &c, int v, fal_params &p,
	       dap_attrib_message *,
	       dap_alloc_message *,
	       dap_protect_message *);
    virtual ~fal_create();
    
  private:

};


