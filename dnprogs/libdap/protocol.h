#ifndef LIBDAP_PROTOCOL_H
#define LIBDAP_PROTOCOL_H
// protocol.h
//
// Definitions of the protocol entities used by the DAP
// protocol.
//
// I've put the whole of the DAP protocol in these two files - I've no
// religious reasons for having each class in it's own file.
// This may be a little unwieldy but maybe less so than several dozen little
// files.

// dap_item is the granddaddy of them all.
class dap_item
{
 public:
    virtual bool read(dap_connection&) = 0;
    virtual bool write(dap_connection&) = 0;
    virtual ~dap_item() {}
};

class dap_bytes : public dap_item // number of bytes
{
 public:
    dap_bytes(int size):
        length(size)
        {
            value = (unsigned char *)malloc(size+1); // May be a string
            memset(value, 0, size);
        }

    virtual ~dap_bytes()
        {
            free(value);
        }

    unsigned char  get_byte(int bytenum);
    char          *get_string();
    unsigned short get_short();
    unsigned int   get_int();

    void set_byte(int bytenum, unsigned char newval);
    void set_short(unsigned short newval);
    void set_int(unsigned int newval);
    void set_string(const char *newval);
    void set_value(const char *newval, int len);

    virtual bool read(dap_connection&);
    virtual bool write(dap_connection&);

 private:
    int            length;
    unsigned char *value;
};


class dap_ex : public dap_item // EX extensible field
{
 public:
    dap_ex(int size):
        length(size),
        real_length(1)
        {
            value = (unsigned char *)malloc(size);
            memset(value, 0, size);
        }

    virtual ~dap_ex()
        {
            free(value);
        }

    virtual bool read(dap_connection&);
    virtual bool write(dap_connection&);

    bool          get_bit(int bit);
    unsigned char get_byte(int byte);
    void          set_bit(int bit);
    void          clear_bit(int bit);
    void          set_byte(int bytenum, unsigned char newval);
    void          clear_all() {memset(value, 0, length);}

 private:
    unsigned char length;
    unsigned char real_length;
    unsigned char *value;
};


class dap_image : public dap_item // "I" field
{
 public:
    dap_image(int size):
        length(size),
        real_length(0)
        {
            value = (unsigned char *)malloc(size+1); // May well be a string.
            memset(value, 0, size);
        }

    virtual ~dap_image()
        {
            free(value);
        }

    virtual bool read(dap_connection&);
    virtual bool write(dap_connection&);

    unsigned char  get_byte(int bytenum);
    char          *get_string();
    unsigned short get_short();
    unsigned int   get_int();
    unsigned char  get_length() {return real_length;};
    void           set_string(const char *);
    void           set_value(const char *, int);
    void           set_int(unsigned int v);
    void           set_short(unsigned short v);

 private:
    unsigned char  length;
    unsigned char  real_length;
    unsigned char *value;
};

// Base DAP message class
class dap_message
{
 public:
    dap_message() {}
    virtual ~dap_message() {};

    virtual bool read(dap_connection&)=0;
    virtual bool write(dap_connection&)=0;

    static dap_message *read_message(dap_connection&, bool);
    static int          peek_message_type(dap_connection&);

    unsigned char get_type();
    const char *type_name();
    static const char *type_name(int);

    // Message Types;
    static const unsigned char CONFIG  = 1;
    static const unsigned char ATTRIB  = 2;
    static const unsigned char ACCESS  = 3;
    static const unsigned char CONTROL = 4;
    static const unsigned char CONTRAN = 5;
    static const unsigned char ACK     = 6;
    static const unsigned char ACCOMP  = 7;
    static const unsigned char DATA    = 8;
    static const unsigned char STATUS  = 9;
    static const unsigned char KEYDEF  = 10;
    static const unsigned char ALLOC   = 11;
    static const unsigned char SUMMARY = 12;
    static const unsigned char DATE    = 13;
    static const unsigned char PROTECT = 14;
    static const unsigned char NAME    = 15;
    static const unsigned char ACL     = 16;


 protected:
    unsigned char msg_type;
    int           length;
    unsigned char flags;

    int send_header(dap_connection &c);
    int send_long_header(dap_connection &c);
    int send_header(dap_connection &c, bool);
    int get_header(dap_connection &c);
};


//-----------------------------------------------------------------------------
//                These are the actual DAP message classes
//-----------------------------------------------------------------------------

// CONFIG message TYPE=1
class dap_config_message: public dap_message
{
 public:
    dap_config_message(int bufsize):
        bufsiz(2),
        ostype(1),
        filesys(1),
        version(5),
        syscap(12),
        buffer_size(bufsize)
        {msg_type = CONFIG;}

    dap_config_message():
        bufsiz(2),
        ostype(1),
        filesys(1),
        version(5),
        syscap(12),
        buffer_size(0)
        {msg_type = CONFIG;}

    virtual bool read(dap_connection&);
    virtual bool write(dap_connection&);

    unsigned int get_bufsize()
        {
            return bufsiz.get_int();
        }

    bool need_crc();
    int  get_os()
        {
            return ostype.get_byte(0);
        }
    int  get_vernum()
        {
            return version.get_byte(0);
        }
    int  get_econum()
        {
            return version.get_byte(1);
        }
    int  get_usrnum()
        {
            return version.get_byte(3);
        }
    bool get_syscap_bit(int bit)
        {
                return syscap.get_bit(bit);
        }

    // OSs
    static const int OS_ILLEGAL =  0;
    static const int OS_RT11    =  1;
    static const int OS_RSTS    =  2;
    static const int OS_RSX11S  =  3;
    static const int OS_RSX11M  =  4;
    static const int OS_RSX11D  =  5;
    static const int OS_IAS     =  6;
    static const int OS_VAXVMS  =  7;
    static const int OS_TOPS20  =  8;
    static const int OS_TOPS10  =  9;
    static const int OS_RTS8    = 10;
    static const int OS_OS8     = 11;
    static const int OS_RSX11MP = 12;
    static const int OS_COPOS11 = 13;
    static const int OS_POS     = 14;
    static const int OS_VAXLELN = 15;
    static const int OS_CPM     = 16;
    static const int OS_MSDOS   = 17;
    static const int OS_ULTRIX  = 18;
    static const int OS_ULTRIX11 = 19;
    static const int OS_DTF_MVS = 21;
    static const int OS_MACOS   = 22;
    static const int OS_OS2     = 23;
    static const int OS_DTF_VM  = 24;
    static const int OS_OSF1    = 25;
    static const int OS_WIN_NT  = 26;
    static const int OS_WIN_95  = 27;

    static const int OS_PYDECNET= 192;          // User-defined range
    static const int OS_LINUX   = 193;
  
    // File systems
    static const int FS_ILLEGAL = 0;
    static const int FS_RMS_11  = 1;
    static const int FS_RMS_20  = 2;
    static const int FS_RMS_32  = 3;
    static const int FS_FCS_11  = 4;
    static const int FS_RT_11   = 5;
    static const int FS_NONE    = 6;
    static const int FS_TOPS_20 = 7;
    static const int FS_TOPS_10 = 8;
    static const int FS_OS_8    = 9;
    static const int FS_ULTRIX  = 14;

  static const int FS_LINUX     = 192;          // User-defined range
  
 private:
    dap_bytes bufsiz;
    dap_bytes ostype;
    dap_bytes filesys;
    dap_bytes version;
    dap_ex    syscap;
    unsigned  int buffer_size;
};

//ATTRIB message TYPE=2
class dap_attrib_message: public dap_message
{
 public:
    dap_attrib_message():
        attmenu(6),
        datatype(2),
        org(1),
        rfm(1),
        rat(3),
        bls(2),
        mrs(2),
        alq(5),
        bks(1),
        fsz(1),
        mrn(5),
        runsys(40),
        deq(2),
        fop(6),
        bsz(1),
        dev(6),
        sdc(6),
        lrl(2),
        hbk(5),
        ebk(5),
        ffb(2),
        sbn(5),
        jnl(4)
        {msg_type = ATTRIB;}

    virtual bool read(dap_connection&);
    virtual bool write(dap_connection&);

    int get_menu_bit(int);
    int get_datatype();
    int get_org();
    int get_rfm();
    int get_rat_bit(int);
    int get_rat();
    int get_bls();
    int get_mrs();
    int get_alq();
    int get_bks();
    int get_fsz();
    int get_mrn();
    int get_runsys();
    int get_deq();
    int get_fop_bit(int);
    int get_bsz();
    int get_dev_bit(int);
    int get_lrl();
    int get_hbk();
    int get_ebk();
    int get_ffb();
    int get_sbn();
    int get_jnl();

    void set_datatype(int);
    void set_org(int);
    void set_rfm(int);
    void set_rat(int);
    void set_rat_bit(int);
    void clear_rat_bit(int);
    void set_bls(int);
    void set_mrs(int);
    void set_alq(int);
    void set_bks(int);
    void set_fsz(int);
    void set_mrn(int);
    void set_runsys(int);
    void set_deq(int);
    void set_fop_bit(int);
    void set_fop(int);
    void set_bsz(int);
    void set_dev_bit(int);
    void set_dev_byte(int,int);
    void set_lrl(int);
    void set_hbk(int);
    void set_ebk(int);
    void set_ffb(int);
    void set_sbn(int);
    void remove_dev();

    void set_stat(struct stat *st, bool show_dev);
    void set_file(const char *file, bool show_dev);
    unsigned long get_size();

    // Bits in ATTMENU
    static const int MENU_DATATYPE = 0;
    static const int MENU_ORG = 1;
    static const int MENU_RFM = 2;
    static const int MENU_RAT = 3;
    static const int MENU_BLS = 4;
    static const int MENU_MRS = 5;
    static const int MENU_ALQ = 6;
    static const int MENU_BKS = 7;
    static const int MENU_FSZ = 8;
    static const int MENU_MRN = 9;
    static const int MENU_RUNSYS = 10;
    static const int MENU_DEQ = 11;
    static const int MENU_FOP = 12;
    static const int MENU_BSZ = 13;
    static const int MENU_DEV = 14;
    static const int MENU_SDC = 15;
    static const int MENU_LRL = 16;
    static const int MENU_HBK = 17;
    static const int MENU_EBK = 18;
    static const int MENU_FFB = 19;
    static const int MENU_SBN = 20;
    static const int MENU_JNL = 21;

    //DATATYPEs
    static const int ASCII      = 0;
    static const int IMAGE      = 1;
    static const int EBCDIC     = 2;
    static const int COMPRESSED = 3;
    static const int EXECUTABLE = 4;
    static const int PRIVILEGED = 5;
    static const int SENSITIVE  = 7;

    //ORGs:
    static const int FB$SEQ = 000;
    static const int FB$REL = 020;
    static const int FB$IDX = 040;
    static const int FB$HSH = 060;

    // RFMs:
    static const int FB$UDF = 0;
    static const int FB$FIX = 1;
    static const int FB$VAR = 2;
    static const int FB$VFC = 3;
    static const int FB$STM = 4;
    static const int FB$STMLF = 5; // These last two got from fab.h on VMS
    static const int FB$STMCR = 6;

    //RATs:
    static const int FB$FTN = 0;
    static const int FB$CR  = 1;
    static const int FB$PRN = 2;
    static const int FB$BLK = 3;
    static const int FB$LSA = 6;
    static const int FB$MACY11 = 7;

    //FOPs:
    static const int FB$RWO = 0;
    static const int FB$RWC = 1;
    static const int FB$POS = 3;
    static const int FB$DLK = 4;
    static const int FB$DIR = 5;
    static const int LOCKED = 6;
    static const int FB$CTG = 7;
    static const int FB$SUP = 8;
    static const int FB$NED = 9;
    static const int FB$TMP = 10;
    static const int FB$MKD = 11;
    static const int FB$DMO = 13;
    static const int FB$WCK = 14;
    static const int FB$RCK = 15;
    static const int FB$CIF = 16;
    static const int FB$LKO = 17;
    static const int FB$SQO = 18;
    static const int FB$MXV = 19;
    static const int FB$SPL = 20;
    static const int FB$SCF = 21;
    static const int FB$DLT = 22;
    static const int FB$CBT = 23;
    static const int FB$WAT = 24;
    static const int FB$DFW = 25;
    static const int FB$TEF = 26;
    static const int FB$OFP = 27;

    //DEVs:
    static const int FB$REC = 0;
    static const int FB$CCL = 1;
    static const int FB$TRM = 2;
    static const int FB$MDI = 3;
    static const int FB$SDI = 4;
    static const int FB$SQD = 5;
    static const int NULL_DEVICE = 6;
    static const int FB$FOD = 7;
    static const int SHARED = 8;
    static const int FB$SPL_DEV = 9; // So as not to conflict with FOP's FB$SPL
    static const int FB$MNT = 10;
    static const int FB$DMT = 11;
    static const int FB$ALL = 12;
    static const int FB$IDV = 13;
    static const int FB$ODV = 14;
    static const int FB$SWL = 15;
    static const int FB$AVL = 16;
    static const int FB$ELG = 17;
    static const int FB$MBX = 18;
    static const int FB$RTM = 19;
    static const int FB$RAD = 20;
    static const int READ_CHECK_ENABLED  = 21;
    static const int WRITE_CHECK_ENABLED = 22;
    static const int FOREIGN = 23;
    static const int NETWORK_DEVICE = 24;
    static const int GENERIC_DEVICE = 25;

 private:
    dap_ex    attmenu;
    dap_ex    datatype;
    dap_bytes org;
    dap_bytes rfm;
    dap_ex    rat;
    dap_bytes bls;
    dap_bytes mrs;
    dap_image alq;
    dap_bytes bks;
    dap_bytes fsz;
    dap_image mrn;
    dap_image runsys;
    dap_bytes deq;
    dap_ex    fop;
    dap_bytes bsz;
    dap_ex    dev;
    dap_ex    sdc;
    dap_bytes lrl;
    dap_image hbk;
    dap_image ebk;
    dap_bytes ffb;
    dap_image sbn;
    dap_ex    jnl;
};

//ACCESS message TYPE=3
class dap_access_message: public dap_message
{
 public:
    dap_access_message():
        accfunc(1),
        accopt(5),
        filespec(255),
        fac(3),
        shr(3),
        display(4),
        password(255)
        {msg_type = ACCESS;}

    virtual bool read(dap_connection&);
    virtual bool write(dap_connection&);

    void set_accfunc(int);
    void set_accopt(int);
    void set_filespec(const char *);
    void set_fac(int);
    void set_shr(int);
    void set_display(int);

    int   get_accfunc();
    int   get_accopt();
    char *get_filespec();
    int   get_fac();
    int   get_shr();
    int   get_display();

    // Values for accfunc
    static const int OPEN      = 1;
    static const int CREATE    = 2;
    static const int RENAME    = 3;
    static const int ERASE     = 4;
    static const int DIRECTORY = 6;
    static const int SUBMIT    = 8;

    // bits for fac & shr
    static const int FB$PUT = 0;
    static const int FB$GET = 1;
    static const int FB$DEL = 2;
    static const int FB$UPD = 3;
    static const int FB$TRN = 4;
    static const int FB$BIO = 5;
    static const int FB$BRO = 6;
    static const int FB$APP = 7; // FAC (Append)
    static const int FB$NIL = 7; // SHR (no access by other users)

    // bits for DISPLAY
    static const int DISPLAY_MAIN    = 0;
    static const int DISPLAY_KEY     = 1;
    static const int DISPLAY_ALLOC   = 2;
    static const int DISPLAY_SUMMARY = 3;
    static const int DISPLAY_DATE    = 4;
    static const int DISPLAY_PROT    = 5;
    static const int DISPLAY_ACL     = 7;
    static const int DISPLAY_NAME    = 8;
    static const int DISPLAY_3PTNAME = 9;
    static const int DISPLAY_COLLTBL = 10;
    static const int DISPLAY_CDA     = 11;
    static const int DISPLAY_TCL     = 12;

    // masks for DISPLAY
    static const int DISPLAY_MAIN_MASK    =   1;
    static const int DISPLAY_KEY_MASK     =   2;
    static const int DISPLAY_ALLOC_MASK   =   4;
    static const int DISPLAY_SUMMARY_MASK =   8;
    static const int DISPLAY_DATE_MASK    =  16;
    static const int DISPLAY_PROT_MASK    =  32;
    static const int DISPLAY_ACL_MASK     = 128;
    static const int DISPLAY_NAME_MASK    = 256;
    static const int DISPLAY_3PTNAME_MASK = 512;
    static const int DISPLAY_COLLTBL_MASK = 1024;
    static const int DISPLAY_CDA_MASK    = 2048;
    static const int DISPLAY_TCL_MASK    = 4096;

 private:
    dap_bytes accfunc;
    dap_ex    accopt;
    dap_image filespec;
    dap_ex    fac;
    dap_ex    shr;
    dap_ex    display;
    dap_image password;
};

//CONTROL message TYPE=4
class dap_control_message: public dap_message
{
 public:
    dap_control_message():
        ctlfunc(1),
        ctlmenu(4),
        rac(1),
        key(255),
        krf(1),
        rop(6),
        hsh(5),
        display(4),
        blkcnt(1),
        usz(2)
        {msg_type = CONTROL;}

    virtual bool read(dap_connection&);
    virtual bool write(dap_connection&);

    void set_ctlfunc(int f);
    void set_rac(int r);
    void set_key(const char *k);
    void set_key(const char *k, int l);
    void set_krf(int f);
    void set_rop_bit(int f);
    void set_rop(int f);
    void set_display(int);
    void set_blkcnt(int);
    void set_usz(int);

    int   get_ctlfunc();
    int   get_rac();
    char *get_key();
    int   get_krf();
    bool  get_rop_bit(int f);
    int   get_display();
    unsigned long get_long_key();
    int   get_blkcnt();
    int   get_usz();

    // ctlfunc - Control functions:
    static const int GET            = 1;
    static const int CONNECT        = 2;
    static const int UPDATE         = 3;
    static const int PUT            = 4;
    static const int DELETE         = 5;
    static const int REWIND         = 6;
    static const int TRUNCATE       = 7;
    static const int MODIFY         = 8;
    static const int RELEASE        = 9;
    static const int FREE           = 10;
    static const int FLUSH          = 12;
    static const int NXTVOL         = 13;
    static const int FIND           = 14;
    static const int EXTEND         = 15;
    static const int DISPLAY        = 16;
    static const int SPACE_FORWARD  = 17;
    static const int SPACE_BACKWARD = 18;
    static const int CHECKPOINT     = 19;
    static const int RECOVERY_GET   = 20;
    static const int RECOVERY_PUT   = 21;

    // RAC:
    static const int RB$SEQ  = 0;
    static const int RB$KEY  = 1;
    static const int RB$RFA  = 2;
    static const int SEQFT   = 3;
    static const int BLOCK   = 4;
    static const int BLOCKFT = 5;

    // ROP:
    static const int RB$EOF  = 0;
    static const int RB$FDL  = 1;
    static const int RB$UIF  = 2;
    static const int RB$HSH  = 3;
    static const int RB$LOA  = 4;
    static const int RB$ULK  = 5;
    static const int RB$TPT  = 6;
    static const int RB$RAH  = 7;
    static const int RB$WBH  = 8;
    static const int RB$KGE  = 9;
    static const int RB$KGT  = 10;
    static const int RB$NLK  = 11;
    static const int RB$RLK  = 12;
    static const int RB$BIO  = 13;
    static const int RB$LIM  = 14;
    static const int RB$NXR  = 15;
    static const int RB$WAT  = 16;
    static const int RB$RRL  = 17;
    static const int RB$REA  = 18;
    static const int RB$KLE  = 19;
    static const int RB$KLT  = 20;

 private:
    dap_bytes ctlfunc;
    dap_ex    ctlmenu;
    dap_bytes rac;
    dap_image key;
    dap_bytes krf;
    dap_ex    rop;
    dap_image hsh;
    dap_ex    display;
    dap_bytes blkcnt;
    dap_bytes usz;
};

//CONTRAN (Continue Transfer) message TYPE=5
class dap_contran_message: public dap_message
{
 public:
    dap_contran_message():
        confunc(1)
        {msg_type = CONTRAN;}

    virtual bool read(dap_connection&);
    virtual bool write(dap_connection&);

    static const int TRY_AGAIN = 1;
    static const int SKIP      = 2;
    static const int ABORT     = 3;
    static const int RESUME    = 4;
    static const int TERMINATE = 5;
    static const int RESYNC    = 6;

    int get_confunc();
    void set_confunc(int f);

 private:
    dap_bytes confunc;
};

//ACK TYPE=6
class dap_ack_message: public dap_message
{
 public:
    dap_ack_message()
        {msg_type = ACK;}

    virtual bool read(dap_connection&);
    virtual bool write(dap_connection&);
};


//ACCOMP (Access Complete) message TYPE=7
class dap_accomp_message: public dap_message
{
 public:
    dap_accomp_message():
        cmpfunc(1),
        fop(6),
        check(2),
        send_fop(false)
        {msg_type = ACCOMP;}

    virtual bool read(dap_connection&);
    virtual bool write(dap_connection&);

    int  get_cmpfunc();
    int  get_fop_bit(int);
    int  get_check();

    void set_cmpfunc(int f);
    void set_fop_bit(int bit);
    void set_check(int c);

    // CMPFUNCs:
    static const int CLOSE         = 1;
    static const int RESPONSE      = 2;
    static const int PURGE         = 3;
    static const int END_OF_STREAM = 4;
    static const int SKIP          = 5;
    static const int CHANGE_BEGIN  = 6;
    static const int CHANGE_END    = 7;
    static const int TERMINATE     = 8;

 private:
    dap_bytes cmpfunc;
    dap_ex    fop;
    dap_bytes check;

    bool      send_fop;
};


//DATA message TYPE=8
class dap_data_message: public dap_message
{
 public:
    dap_data_message():
        recnum(5),
        data(NULL),
        local_data(false)
        {msg_type = DATA;}

    ~dap_data_message();

    virtual bool read(dap_connection&);
    virtual bool write(dap_connection&);
    virtual bool write_with_len(dap_connection&);
    virtual bool write_with_len256(dap_connection&);

    int   get_recnum();
    int   get_datalen();
    char *get_dataptr();
    void  set_recnum(int r);
    void  get_data(char *, int *);
    void  set_data(const char *, int);

 private:
    dap_image  recnum;
    char      *data;
    bool       local_data; // data pointer is allocated
};


//STATUS message TYPE=9
class dap_status_message: public dap_message
{
 public:
    dap_status_message():
        stscode(2),
        rfa(8),
        recnum(8),
        stv(8)
        {msg_type = STATUS;}

    virtual bool read(dap_connection&);
    virtual bool write(dap_connection&);

    int   get_code();
    long  get_rfa();
    void  set_code(int s);
    void  set_errno();
    void  set_errno(int);
    void  set_rfa(long);
    const char *get_message();


 private:
    dap_bytes stscode;
    dap_image rfa;
    dap_image recnum;
    dap_image stv;

    int   errno_to_stscode();
};

//KEYDEF message TYPE=10
class dap_key_message: public dap_message
{
 public:
    dap_key_message():
        keymenu(6),
        flg(3),
        dfl(2),
        ifl(2),
        nsg(1),
        ref(1),
        knm(40),
        nul(1),
        ian(1),
        lan(1),
        dan(1),
        dtp(1),
        rvb(8),
        hal(5),
        dvb(8),
        dbs(1),
        ibs(1),
        lvl(1),
        tks(1),
        mrl(2)
        {msg_type = KEYDEF;}

    virtual bool read(dap_connection&);
    virtual bool write(dap_connection&);
    ~dap_key_message();

    // Flags - bit positions
    static const unsigned int XB$DUP = 1;
    static const unsigned int XB$CHG = 2;
    static const unsigned int XB$NUL = 3;

    int get_flag();
    int get_nsg();
    int get_ref();
    char *get_name();
    int get_siz(int);
    int get_pos(int);

    void set_knm(char *);
    void set_ref(int);


 private:
    dap_ex keymenu;
    dap_ex flg;
    dap_bytes dfl;
    dap_bytes ifl;
    dap_bytes nsg;
    dap_bytes **pos;
    dap_bytes **siz;
    dap_bytes ref;
    dap_image knm;
    dap_bytes nul;
    dap_bytes ian;
    dap_bytes lan;
    dap_bytes dan;
    dap_bytes dtp;
    dap_image rvb;
    dap_image hal;
    dap_image dvb;
    dap_bytes dbs;
    dap_bytes ibs;
    dap_bytes lvl;
    dap_bytes tks;
    dap_bytes mrl;
};

//ALLOC message TYPE=11
class dap_alloc_message: public dap_message
{
 public:
    dap_alloc_message():
        allmenu(6),
        vol(2),
        aln(1),
        aop(4),
        loc(8),
        rfi(16),
        alq(5),
        aid(1),
        bkz(1),
        deq(2)
        {msg_type = ALLOC;}

    virtual bool read(dap_connection&);
    virtual bool write(dap_connection&);

 private:
    dap_ex    allmenu;
    dap_bytes vol;
    dap_bytes aln;
    dap_ex    aop;
    dap_image loc;
    dap_image rfi;
    dap_image alq;
    dap_bytes aid;
    dap_bytes bkz;
    dap_bytes deq;
};

//SUMMARY message TYPE=12
class dap_summary_message: public dap_message
{
 public:
    dap_summary_message():
        summenu(6),
        nok(1),
        noa(1),
        nor(1),
        pvn(2)
        {msg_type = SUMMARY;}

    virtual bool read(dap_connection&);
    virtual bool write(dap_connection&);

    int get_nok();
    int get_noa();
    int get_nor();
    int get_pvn();

 private:
    dap_ex    summenu;
    dap_bytes nok;
    dap_bytes noa;
    dap_bytes nor;
    dap_bytes pvn;
};

//DATE message TYPE=13
class dap_date_message: public dap_message
{
 public:
    dap_date_message():
        datmenu(6),
        cdt(18),
        rdt(18),
        edt(18),
        rvn(2),
        bdt(18),
        udt(18) // Ultrix date
        {msg_type = DATE;}

    virtual bool read(dap_connection&);
    virtual bool write(dap_connection&);

    char *get_cdt();
    char *get_rdt();
    char *get_edt();
    char *get_bdt();
    char *get_udt();

    time_t get_cdt_time();
    time_t get_rdt_time();
    time_t get_edt_time();
    time_t get_bdt_time();
    time_t get_udt_time();
    int    get_rvn();

    void set_cdt(time_t);
    void set_rdt(time_t);
    void set_edt(time_t);
    void set_bdt(time_t);

    void set_rvn(int);

    char *make_y2k(char *dt);

 private:
    dap_ex    datmenu;
    dap_bytes cdt;
    dap_bytes rdt;
    dap_bytes edt;
    dap_bytes rvn;
    dap_bytes bdt; // backup date is not mentioned in the DAP spec but
                   // it exists in real life I promise you.
    dap_bytes udt; // Gah! another one. This one from Ultrix

    char *time_to_string(time_t);
    time_t string_to_time_t(const char *);


    static const char *months[];
    static const int NUM_MONTHS = 12;
};


//PROTECT message TYPE=14
class dap_protect_message: public dap_message
{
 public:
    dap_protect_message():
        protmenu(6),
        owner(40),
        protsys(3),
        protown(3),
        protgrp(3),
        protwld(3)
        {msg_type = PROTECT;}

    virtual bool read(dap_connection&);
    virtual bool write(dap_connection&);

    void set_owner(gid_t, uid_t); // Converts GID/UID to names
    void set_owner(const char *); // Any old name will do here.
    void set_protection(mode_t);
    int  set_protection(char *);

    const char    *get_owner();
    const char    *get_protection(); // In VMS format
    mode_t   get_mode();       // In Unix format

 private:
    dap_ex    protmenu;
    dap_image owner;
    dap_ex    protsys;
    dap_ex    protown;
    dap_ex    protgrp;
    dap_ex    protwld;

    unsigned char unix_to_vms(unsigned int);
};


//NAME message TYPE=15
class dap_name_message: public dap_message
{
 public:
    dap_name_message():
        nametype(3),
        namespec(200)
        {msg_type = NAME;}

    virtual bool read(dap_connection&);
    virtual bool write(dap_connection&);

    int   get_nametype();
    char *get_namespec();

    void  set_nametype(int);
    void  set_namespec(const char *);

    static const int FILESPEC  = 1;
    static const int FILENAME  = 2;
    static const int DIRECTORY = 4;
    static const int VOLUME    = 8;

 private:
    dap_ex    nametype;
    dap_image namespec;
};

#endif
