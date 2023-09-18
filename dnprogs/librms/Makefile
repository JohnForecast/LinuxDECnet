include ../Makefile.common

LIBOBJS=open.o close.o readwrite.o getreply.o parse.o
PICOBJS=open.po close.po readwrite.po getreply.po parse.po
EXAMPLE1OBJS=example.o
EXAMPLE2OBJS=t_example.o

LIBNAME=librms
LIB_MINOR_VERSION=43.0
LIB_VERSION=$(MAJOR_VERSION).$(LIB_MINOR_VERSION)

EXAMPLE1=example
EXAMPLE2=t_example
EXAMPLES=$(EXAMPLE1) $(EXAMPLE2)

SHAREDLIB=$(LIBNAME).so.$(LIB_VERSION)
STATICLIB=$(LIBNAME).a
INCLUDEFILES=rms.h fabdef.h rabdef.h

CFLAGS+=-I. -I../include -I../libdap -fdollars-in-identifiers
LDFLAGS+=-Wl,-rpath-link,../libdnet -Wl,-rpath-link,../libdap

all: $(STATICLIB) $(SHAREDLIB) $(EXAMPLES)

$(STATICLIB): $(LIBOBJS)
	ar -rv $@ $^

$(SHAREDLIB): $(PICOBJS)
	$(CXX) $(CXXFLAGS) -shared -o $@ -Wl,-soname=$(LIBNAME).so.$(MAJOR_VERSION) $^ $(LIBS)
	ln -sf $(SHAREDLIB) $(LIBNAME).so.$(MAJOR_VERSION)
	ln -sf $(LIBNAME).so.$(MAJOR_VERSION) $(LIBNAME).so

$(EXAMPLE1): $(EXAMPLE1OBJS) $(SHAREDLIB)
	$(CC) $(CXXFLAGS) $(LDFLAGS) -o $@ $< -L. -lrms

$(EXAMPLE2): $(EXAMPLE2OBJS) $(SHAREDLIB)
	$(CC) $(CXXFLAGS) $(LDFLAGS) -o $@ $< -L. -lrms

.cc.o:
	$(CXX) $(CXXFLAGS) -c -o $@ $<

.cc.po:
	$(CXX) $(CXXFLAGS) -fPIC -c -o $@ $<

dep depend:	
	$(CC) $(CFLAGS) -MM *.cc *.c >.depend 2>/dev/null

clean:
	rm -f *.o *.po *.bak .depend $(STATICLIB) $(SHAREDLIB) $(LIBNAME).so* $(EXAMPLES)

install:
	install -d $(prefix)/lib
	install -m 0644 $(STRIPBIN) $(SHAREDLIB) $(libprefix)/$(libdir)
	install -m 0644 $(STATICLIB) $(libprefix)/$(libdir)
	install -d $(prefix)/include
	install -m 0644 $(INCLUDEFILES) $(libprefix)/include
	ln -sf $(SHAREDLIB) $(libprefix)/$(libdir)/$(LIBNAME).so.$(MAJOR_VERSION)
	ln -sf $(LIBNAME).so.$(MAJOR_VERSION) $(libprefix)/$(libdir)/$(LIBNAME).so

.SUFFIXES: .po

ifeq (.depend,$(wildcard .depend))
include .depend
endif

