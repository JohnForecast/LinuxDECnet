include ../../Makefile.common
export TOP=../..

PROG1=dnetcat
PROG2=dnetstat
PROG3=dnnode

MANPAGES1=man1/dnetcat.1 man1/dnetstat.1 man1/dnnode.1

PROG1OBJS=dnetcat.o
PROG2OBJS=dnetstat.o
PROG3OBJS=dnnode.o

all: $(PROG1) $(PROG2) $(PROG3)

$(PROG1): $(PROG1OBJS) $(DEPLIBDNET) $(DEPLIBDAEMON) 
	$(CC) $(CFLAGS) -o $@ $(PROG1OBJS) $(LIBDNET) $(LIBDAEMON)

$(PROG2): $(PROG2OBJS) $(DEPLIBDNET) $(UULIB)
	$(CC) $(CFLAGS) -o $@ $(PROG2OBJS) $(LIBDNET) 

$(PROG3): $(PROG3OBJS) $(DEPLIBDNET)
	$(CC) $(CFLAGS) -o $@ $(PROG3OBJS) $(LIBDNET)

install:
	install -d $(prefix)/bin
	install -d $(manprefix)/man/man1
	install -m 0755 $(STRIPBIN) $(PROG1) $(prefix)/bin
	install -m 0755 $(STRIPBIN) $(PROG2) $(prefix)/bin
	install -m 0755 $(STRIPBIN) $(PROG3) $(prefix)/bin
	install -m 0644 $(MANPAGES1) $(manprefix)/man/man1

dep depend:	
	$(CC) $(CFLAGS) -MM *.c >.depend 2>/dev/null

clean:
	rm -f $(PROG1) $(PROG2) $(PROG3) *.o *.bak .depend


ifeq (.depend,$(wildcard .depend))
include .depend
endif
