

#ifndef METAFILE_DIR
#define METAFILE_DIR ".fal"
#endif

// Base class for FAL tasks
// It incorporates the messaging base and also the wherewithall
// to parse VMS filenames and calculate CRCs
class fal_task
{
  public:
    fal_task(dap_connection &c, int v, fal_params &p):
	conn(c),
	verbose(v),
	crc(DAPPOLY, DAPINICRC),
	params(p),
	record_lengths(NULL)
	{}
    virtual bool process_message(dap_message *m)=0;
    virtual ~fal_task()
	{
	    if (record_lengths)
		delete[] record_lengths;
	}
    void set_crc(bool);
    void calculate_crc(unsigned char *, int);

  protected:
    dap_connection &conn;
    int             verbose;
    bool            vms_format;
    bool            need_crc;
    vaxcrc          crc;
    fal_params     &params;

    // Bits for dealing with variable-length records.
    unsigned int    current_record;
    unsigned short *record_lengths;
    unsigned int    num_records;

    // Whether we send the DEV part of the attributes message
    typedef enum { SEND_DEV, DONT_SEND_DEV, DEV_DEPENDS_ON_TYPE} dev_option;

    virtual bool send_file_attributes(char *, int, dev_option);
    virtual bool send_file_attributes(unsigned int &, bool &, char *, int,
				      dev_option);

    void return_error();
    void return_error(int);
    void split_filespec(char *, char *, char *);
    void make_vms_filespec(const char *, char *, bool);
    void parse_vms_filespec(char *, char *, char *);
    void make_unix_filespec(char *, char *);
    void convert_vms_wildcards(char *);
    void add_vroot(char *);
    void remove_vroot(char *);
    bool is_vms_name(char *);
    bool send_ack_and_unblock();

    void open_auto_types_file();
    int  unlink(char *);
    int rename(char *, char *);
    bool check_file_type(unsigned int &block_size, bool &send_records,
			 const char *name,
			 dap_attrib_message *attrib_msg);
    bool guess_file_type(unsigned int &block_size, bool &send_records,
			 const char *name,
			 dap_attrib_message *attrib_msg);
    bool fake_file_type(unsigned int &block_size, bool &send_records,
			const char *name,
			dap_attrib_message *attrib_msg);
    bool read_metafile(unsigned int &block_size, bool &send_records,
		       const char *name,
		       dap_attrib_message *attrib_msg);
    bool read_adf(unsigned int &block_size, bool &send_records,
		  const char *name,
		  dap_attrib_message *attrib_msg);
    bool fake_file_type(const char *name, dap_attrib_message *attrib_msg);
    void create_metafile(char *name, dap_attrib_message *attrib_msg);

    // The pseudo device name we use
    static const char *sysdisk_name;

 private:
    void meta_filename(const char *file, char *metafile);
    bool adf_filename(const char *file, char *metafile);

    // auto_types structure
    class auto_types
    {
    public:
	auto_types(char *_ext, bool _records, unsigned int _block)
	{
	    strcpy(ext, _ext);
	    send_records = _records;
	    block_size = _block;
	    len = strlen(ext);
	    next = NULL;
	}

	char ext[40];
	unsigned int  block_size;
	int len;
	bool send_records;
	auto_types *next;
    };

    // Structure of the metafile
    class metafile_data
    {
    public:
	unsigned short version;
	unsigned short rfm;
	unsigned int   rat;
	unsigned short mrs;
	unsigned short lrl;

	// For variable-length records with no carriage control:
	unsigned int  num_records;
	unsigned short *records; // This is really written after the structure

	static const int METAFILE_VERSION = 2;
    };

    // This is reverse-engineered so there's loads missing.
    class adf_struct
    {
    public:
	char  unknown1[6];
	short revn;         // Revision count
	char  unknown2[4];
	char  rfm;
	char  rat;
	short rsz;
	char  unknown3[10];
	short bks;
	short mrs;
	short ext; // Extend size
	// The rest is a mystery to me.
    };

    static auto_types *auto_types_list;
    static const char *default_types_file;
};

