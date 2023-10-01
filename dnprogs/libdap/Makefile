include ../Makefile.common

LIBOBJS=connection.o protocol.o vaxcrc.o logging.o
PICOBJS=connection.po protocol.po vaxcrc.po logging.po

LIBNAME=libdnet-dap
LIB_MINOR_VERSION=46.0
LIB_VERSION=$(MAJOR_VERSION).$(LIB_MINOR_VERSION)

SHAREDLIB=$(LIBNAME).so.$(LIB_VERSION)
STATICLIB=$(LIBNAME).a

CXXFLAGS+=-Wno-format-y2k

all: $(STATICLIB) $(SHAREDLIB)

$(STATICLIB): $(LIBOBJS)
	ar -rv $@ $^

$(SHAREDLIB): $(PICOBJS)
	$(CXX) $(CXXFLAGS) -shared -o $@ -Wl,-soname=$(LIBNAME).so.$(MAJOR_VERSION) $^ -L../libdnet/ -ldnet
	ln -sf $(SHAREDLIB) $(LIBNAME).so.$(MAJOR_VERSION)
	ln -sf $(LIBNAME).so.$(MAJOR_VERSION) $(LIBNAME).so

.cc.o:
	$(CXX) $(CXXFLAGS) $(SYSCONF_PREFIX) -c -o $@ $<

.cc.po:
	$(CXX) $(CXXFLAGS) $(SYSCONF_PREFIX) -fPIC -c -o $@ $<

dep depend:	
	$(CXX) $(CXXFLAGS) -MM *.cc >.depend 2>/dev/null

clean:
	rm -f *.o *.po *.bak .depend $(STATICLIB) $(SHAREDLIB) $(LIBNAME).so*

install:
	install -m 0644 $(STRIPBIN) $(SHAREDLIB) $(libprefix)$(libdir)
	install -m 0644 $(STATICLIB) $(libprefix)$(libdir)
	ln -sf $(SHAREDLIB) $(libprefix)$(libdir)/$(LIBNAME).so.$(MAJOR_VERSION)
	ln -sf $(LIBNAME).so.$(MAJOR_VERSION) $(libprefix)$(libdir)/$(LIBNAME).so

.SUFFIXES: .po

ifeq (.depend,$(wildcard .depend))
include .depend
endif
