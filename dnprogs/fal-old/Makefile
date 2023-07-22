# Makefile for FAL

include ../Makefile.common

PROG1=fal

MANPAGES=fal.8 decnet.proxy.5

PROG1OBJS=fal.o server.o task.o directory.o open.o create.o erase.o rename.o \
          submit.o

all: $(PROG1)

$(PROG1): $(PROG1OBJS) $(DEPLIBS) $(DEPLIBDAEMON)
	$(CXX) -o $@ $(CXXFLAGS) $(PROG1OBJS) $(LIBS) $(LIBDAEMON) $(LIBDNET)

install:
	install -d $(prefix)/sbin
	install -d $(manprefix)/man/man8
	install -d $(manprefix)/man/man5
	install -m 0755 $(STRIPBIN) $(PROG1) $(prefix)/sbin
	install -m 0644 fal.8 $(manprefix)/man/man8
	install -m 0644 decnet.proxy.5 $(manprefix)/man/man5

dep depend:	
	$(CXX) $(CXXFLAGS) -MM *.cc >.depend 2>/dev/null

clean:
	rm -f $(PROG1) *.o *.bak .depend


ifeq (.depend,$(wildcard .depend))
include .depend
endif
