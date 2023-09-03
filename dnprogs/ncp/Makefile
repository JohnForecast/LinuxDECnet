# Makefile for NCP
CFLAGS=-g -O0

include ../Makefile.common

PROG1=ncp
MANPAGES1=ncp.1
PROG1OBJS=ncp.o tables.o show.o nice.o network.o line.o node.o logging.o \
  circuit.o module.o area.o zero.o copy.o
LIBS=-lreadline -lhistory

all: $(PROG1)

.c.o:
	$(CC) $(CFLAGS) $(SYSCONF_PREFIX) -c -o $@ $<

$(PROG1): $(PROG1OBJS) $(DEPLIBDNET)
	$(CC) $(CFLAGS) -o $@ $(PROG1OBJS) $(LIBDNET) $(LIBS)

install:
	install -d $(prefix)/sbin
	install -d $(manprefix)/man/man1
	install -m 0755 $(STRIPBIN) $(PROG1) $(prefix)/sbin
	install -m 644 $(MANPAGES1) $(manprefix)/man/man1

dep depend:
	$(CC) $(CFLAGS) -MM *.c >,depnd 2>/dev/null

clean:
	rm -f $(PROG1) *.o *.bak .depend

ifeq (.depend,$(wildcard .depend))
include .depend
endif

