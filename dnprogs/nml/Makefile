# Makefile for NML

include ../Makefile.common

PROG1=dnetnml
MANPAGES8=dnetnml.8
PROG1OBJS=main.o nice.o nml.o

CFLAGS+=-I ../dnroute/netlink/include

all: $(PROG1)

.c.o:
	$(CC) $(CFLAGS) $(SYSCONF_PREFIX) -c -o $@ $<

$(PROG1): $(PROG1OBJS) $(DEPLIBDNET) $(DEPLIBDAEMON)
	$(CC) $(CFLAGS) -o $@ $(PROG1OBJS) $(LIBDNET) $(LIBDAEMON) -L ../dnroute/netlink -lnetlink

install:
	install -d $(prefix)/sbin
	install -d $(manprefix)/man/man8
	install -m 0755 $(STRIPBIN) $(PROG1) $(prefix)/sbin
	install -m 0644 $(MANPAGES8) $(manprefix)/man/man8

dep depend:	
	$(CC) $(CFLAGS) -MM *.c >.depend 2>/dev/null

clean:
	rm -f $(PROG1) *.o *.bak .depend


ifeq (.depend,$(wildcard .depend))
include .depend
endif
