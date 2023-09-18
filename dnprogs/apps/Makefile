#
# Makefile for Eduardo's & contributed apps
#
include ../Makefile.common
CC        = gcc
INCDIR	  = -I.
#------------------------------------------------------------------------------

PROG1OBJS = startnet.o
PROG2OBJS = sethost.o 
PROG4OBJS = dnping.o
PROG5OBJS = ctermd.o
PROG7OBJS = rmtermd.o

PROG1 = startnet
PROG2 = sethost
PROG4 = dnping
PROG5 = ctermd
PROG7 = rmtermd
MANPAGES1 = sethost.1 dnping.1
MANPAGES5 = decnet.conf.5
MANPAGES8 = ctermd.8 rmtermd.8 setether.8

ALLPROGS=$(PROG1) $(PROG2) $(PROG4) $(PROG5) $(PROG7)

all: $(ALLPROGS)

$(PROG1): $(PROG1OBJS) $(DEPLIBDNET)
	$(CC) -o $@ $(CFLAGS) $(PROG1OBJS) -Wl,-Bstatic $(LIBDNET) -Wl,-Bdynamic

$(PROG2): $(PROG2OBJS) $(DEPLIBDNET)
	$(CC) -o $@ $(CFLAGS) $(PROG2OBJS) $(LIBDNET)

$(PROG4): $(PROG4OBJS) $(DEPLIBDNET)
	$(CC) -o $@ $(CFLAGS) $(PROG4OBJS) $(LIBDNET)

$(PROG5): $(PROG5OBJS) $(DEPLIBDNET) $(DEPLIBDAEMON)
	$(CC) -o $@ $(CFLAGS) $(PROG5OBJS) $(LIBDAEMON) $(LIBDNET) $(PTSLIBS)

$(PROG7): $(PROG7OBJS) $(DEPLIBDNET) $(DEPLIBDAEMON)
	$(CC) -o $@ $(CFLAGS) $(PROG7OBJS) $(LIBDAEMON) $(LIBDNET) $(PTSLIBS)


dep:	
	$(CC) $(CFLAGS) -MM *.c >.depend 2>/dev/null

clean:
	rm -f $(ALLPROGS) *.o *.a *.so *~ .depend

install:
	install -d $(prefix)/sbin
	install -d $(prefix)/bin
	install -d $(manprefix)/man/man1
	install -d $(manprefix)/man/man5
	install -d $(manprefix)/man/man8
	install -d $(sysconfprefix)/etc
	install -m 0755 $(STRIPBIN) $(PROG2) $(prefix)/bin
	install -m 0755 $(STRIPBIN) $(PROG4) $(prefix)/bin
	install -m 0755 $(STRIPBIN) $(PROG5) $(prefix)/sbin
	install -m 0700 setether.sh $(prefix)/sbin/setether
	install -m 0755 $(STRIPBIN) $(PROG7) $(prefix)/sbin
	install -m 0644 $(MANPAGES1) $(manprefix)/man/man1
	install -m 0644 $(MANPAGES5) $(manprefix)/man/man5
	install -m 0644 $(MANPAGES8) $(manprefix)/man/man8
	if [ ! -f $(sysconfprefix)/etc/decnet.conf ]; then \
		install -m 0644 decnet.conf $(sysconfprefix)/etc/decnet.conf.sample; \
	fi

ifeq (.depend,$(wildcard .depend))
include .depend
endif

