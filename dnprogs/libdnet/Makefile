#--------------------------------------------------------------------------
# Makefile for libdnet
#--------------------------------------------------------------------------
include ../Makefile.common
CC=gcc
AR=ar
ARFLAGS=rcs
MANPAGES3=dnet_htoa.3 dnet_ntoa.3 dnet_addr.3 dnet_conn.3 \
	getnodeadd.3 getnodebyname.3 setnodeent.3 libdnet.3 \
	getnodebyaddr.3 dnet_getnode.3 dnet_eof.3
LIBOBJS :=dnet_htoa.o dnet_ntoa.o dnet_addr.o dnet_conn.o getnodeadd.o \
	getnodebyname.o getnodebyaddr.o setnodeent.o getexecdev.o \
	getnodename.o setnodename.o dnet_getnode.o dnet_pton.o dnet_ntop.o \
	dnet_recv.o dnet_eof.o getobjectbyX.o cuserid.o
PICOBJS:=dnet_htoa.po dnet_ntoa.po dnet_addr.po dnet_conn.po getnodeadd.po \
	getnodebyname.po getnodebyaddr.po setnodeent.po getexecdev.po \
	getnodename.po setnodename.po dnet_getnode.po dnet_pton.po dnet_ntop.po\
	dnet_recv.po dnet_eof.po getobjectbyX.po cuserid.po

LIBNAME=libdnet
LIB_MINOR_VERSION=43.2
LIB_VERSION=$(MAJOR_VERSION).$(LIB_MINOR_VERSION)

SHAREDLIB=$(LIBNAME).so.$(LIB_VERSION)

ifeq ($(OSNAME),FreeBSD)
COMPLIB=-lcompat
else
COMPLIB=
endif

all:  libdnet.a $(SHAREDLIB)

dep:

libdnet.a: ${LIBOBJS} 
	${AR} ${ARFLAGS} libdnet.a ${LIBOBJS}
  
$(SHAREDLIB): ${PICOBJS}
	${CC} ${LDFLAGS} -shared -o $@ ${PICOBJS} -Wl,-soname=libdnet.so.$(MAJOR_VERSION) $(COMPLIB)
	ln -sf $(SHAREDLIB) $(LIBNAME).so.$(MAJOR_VERSION)
	ln -sf $(LIBNAME).so.$(MAJOR_VERSION) $(LIBNAME).so

.c.o:
	$(CC) $(CFLAGS) $(SYSCONF_PREFIX) -c -o $@ $<

.c.po:
	$(CC) $(CFLAGS) -fPIC -shared $(SYSCONF_PREFIX) -c -o $@ $<

install: libdnet.a $(SHAREDLIB)
	install -d $(libprefix)$(libdir)
	install -m 0644 libdnet.a $(libprefix)$(libdir)/libdnet.a
	install -m 0644 $(STRIPBIN) $(SHAREDLIB) $(libprefix)$(libdir)/$(SHAREDLIB)
	ln -sf $(SHAREDLIB) $(libprefix)$(libdir)/$(LIBNAME).so.$(MAJOR_VERSION)
	ln -sf $(SHAREDLIB) $(libprefix)$(libdir)/$(LIBNAME).so
	ln -sf $(LIBNAME).so.$(MAJOR_VERSION) $(libprefix)$(libdir)/$(LIBNAME).so

	install -d $(manprefix)/man/man3
	install -m 0644 $(MANPAGES3) $(manprefix)/man/man3
	ln -sf dnet_getnode.3 $(manprefix)/man/man3/dnet_nextnode.3
	ln -sf dnet_getnode.3 $(manprefix)/man/man3/dnet_endnode.3

clean:
	rm -f *.a *.o *.po *.so* *~

.SUFFIXES: .po

# DO NOT DELETE
