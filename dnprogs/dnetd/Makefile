# Makefile for DECnet super server

include ../Makefile.common

PROG1=dnetd

MANPAGES8=dnetd.8
MANPAGES5=dnetd.conf.5

PROG1OBJS=dnetd.o task_server.o

all: $(PROG1)

.c.o:
	$(CC) $(CFLAGS) $(BINARY_PREFIX) -c -o $@ $<

$(PROG1): $(PROG1OBJS) $(DEPLIBDNET) $(DEPLIBDAEMON)
	$(CC) $(CFLAGS) -o $@ $(PROG1OBJS) $(LIBDAEMON) $(LIBDNET) $(PTSLIBS)

install:
	install -d $(prefix)/bin
	install -d $(manprefix)/man/man5
	install -d $(manprefix)/man/man8
	install -m 0750 $(STRIPBIN) $(PROG1) $(prefix)/sbin
	install -m 0644 $(MANPAGES5) $(manprefix)/man/man5
	install -m 0644 $(MANPAGES8) $(manprefix)/man/man8
	if [ ! -f $(sysconfprefix)/etc/dnetd.conf ]; then install -m 640 dnetd.conf $(sysconfprefix)/etc; fi
	if [ ! -f $(sysconfprefix)/etc/decnet.proxy ]; then install -m 640 ../fal/decnet.proxy $(sysconfprefix)/etc; fi

location:
	$(info $(prefix))

dep depend:	
	$(CC) $(CFLAGS) -MM *.c >.depend 2>/dev/null

clean:
	rm -f $(PROG1) *.o *.bak .depend


ifeq (.depend,$(wildcard .depend))
include .depend
endif

