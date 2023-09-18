include ../Makefile.common

LIBOBJS=dnet_daemon.o dnetlog.o dnet_priv_check.o
PICOBJS=dnet_daemon.po dnetlog.po dnet_priv_check.po
MANPAGES3=dnet_daemon.3

LIBNAME=libdnet_daemon
LIB_MINOR_VERSION=43.1
LIB_VERSION=$(MAJOR_VERSION).$(LIB_MINOR_VERSION)

SHAREDLIB=$(LIBNAME).so.$(LIB_VERSION)
STATICLIB=$(LIBNAME).a


all: $(STATICLIB) $(SHAREDLIB)

$(STATICLIB): $(LIBOBJS)
	ar -rv $@ $^

$(SHAREDLIB): $(PICOBJS)
	$(CC) $(CFLAGS) -shared -o $@ -Wl,-soname=$(LIBNAME).so.$(MAJOR_VERSION) $^ $(LIBCRYPT) -L../libdnet/ -ldnet
	ln -sf $(SHAREDLIB) $(LIBNAME).so.$(MAJOR_VERSION)
	ln -sf $(LIBNAME).so.$(MAJOR_VERSION) $(LIBNAME).so

.c.o:
	$(CC) $(CFLAGS) $(SYSCONF_PREFIX) -c -o $@ $<

.c.po:
	$(CC) $(CFLAGS) $(SYSCONF_PREFIX) -fPIC -c -o $@ $<

dep depend:	
	$(CC) $(CFLAGS) -MM *.c >.depend 2>/dev/null

clean:
	rm -f *.o *.po *.bak $(STATICLIB) $(SHAREDLIB) $(LIBNAME).so* .depend

install:
	install -m 0644 $(STRIPBIN) $(SHAREDLIB) $(libprefix)/$(libdir)
	install -m 0644 $(STATICLIB) $(libprefix)/$(libdir)
	ln -sf $(SHAREDLIB) $(libprefix)/$(libdir)/$(LIBNAME).so.$(MAJOR_VERSION)
	ln -sf $(LIBNAME).so.$(MAJOR_VERSION) $(libprefix)/$(libdir)/$(LIBNAME).so
	install -d $(manprefix)/man/man3
	install -m 0644 $(MANPAGES3) $(manprefix)/man/man3
	ln -sf dnet_daemon.3 $(manprefix)/man/man3/dnet_accept.3
	ln -sf dnet_daemon.3 $(manprefix)/man/man3/dnet_reject.3

.SUFFIXES: .po

ifeq (.depend,$(wildcard .depend))
include .depend
endif

