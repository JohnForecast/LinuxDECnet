// This is really just a struct.
// All the relevant command-line parameters are passed down
// to the work classes using this class.
class fal_params
{
 public:
    int   verbosity;
    enum  {GUESS_TYPE, CHECK_EXT, NONE} auto_type;
    char  auto_file[PATH_MAX];
    char  vroot[PATH_MAX];
    int   vroot_len;
    bool  use_file;
    bool  use_metafiles;
    bool  use_adf;
    bool  can_do_stmlf;
    int   remote_os;

    const char *type_name()
    {
	switch(auto_type)
	{
	case GUESS_TYPE:
	    return "guess";
	case CHECK_EXT:
	    return "ext";
	case NONE:
	    return "none";
	default:
	    return "ugh";
	}
    }
};
