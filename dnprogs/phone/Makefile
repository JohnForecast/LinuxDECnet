# Makefile for phone progs

include ../Makefile.common

#
# Look for gtk-config on the path
#
# We need GTK+ version 1.2. I daren't say 1.2 or higher (tho' I will
# allow point releases) because GTK+ changes so much between releases.
#
# Don't make a GTK version for release binaries because it adds too many
# unnecessary dependancies
#
GTK_VERSION=$(shell gtk-config --version 2>/dev/null | cut -d. -f1-2)
ifndef RELEASE
ifeq ($(GTK_VERSION), 1.2)
HAVE_GTK=true
INSTALLDEPS=install_pixmaps
PIXMAPDIR=$(prefix)/X11/pixmaps/phone
endif
endif

#sometimes GTK cannot be used and then
#HAVE_GTK=

LIBPANEL=-lpanel
LIBNCURSES=-lncurses

PROG1=phone
PROG2=phoned

MANPAGES1=phone.1
MANPAGES8=phoned.8

PROG1OBJS=main.o phone_ncurses.o backend.o
PROG2OBJS=phoned.o phone_server.o

all: $(PROG1) $(PROG2)

ifdef HAVE_GTK
PROG1OBJS+=gtkphonesrc.o gtkphonesig.o phone_gtk.o
GTKLIBS=$(shell gtk-config --libs)
CFLAGS+=-DHAVE_GTK $(BINARY_PREFIX) -DPIXMAPDIR=\"$(PIXMAPDIR)\"
endif

$(PROG1): $(PROG1OBJS) $(DEPLIBDNET)
	$(CC) $(CFLAGS) -o $@ $(PROG1OBJS) $(LIBPANEL) $(LIBNCURSES) $(LIBDNET) $(GTKLIBS)
  
$(PROG2): $(PROG2OBJS) $(DEPLIBDNET)
	$(CC) $(CFLAGS) -o $@ $(PROG2OBJS) $(LIBDNET)

#
# These will only be built if HAVE_GTK is defined
#
gtkphonesrc.o: gtkphonesrc.c
	$(CC) $(CFLAGS) -c -o $@ $< `gtk-config --cflags`

gtkphonesig.o: gtkphonesig.c
	$(CC) $(CFLAGS) -c -o $@ $< `gtk-config --cflags`

phone_gtk.o: phone_gtk.c
	$(CC) $(CFLAGS) -c -o $@ $< `gtk-config --cflags`

install: $(INSTALLDEPS)
	install -d $(prefix)/bin
	install -d $(manprefix)/man/man1
	install -d $(manprefix)/man/man8
	install -m 0755 $(STRIPBIN) $(PROG1) $(prefix)/bin
	install -m 0755 $(STRIPBIN) $(PROG2) $(prefix)/sbin
	install -m 0644 $(MANPAGES1) $(manprefix)/man/man1
	install -m 0644 $(MANPAGES8) $(manprefix)/man/man8

install_pixmaps:
ifndef RELEASE
	install -d $(PIXMAPDIR)
	install -m 0644 pixmaps/*.xpm $(PIXMAPDIR)
endif

location:
	$(info $(prefix))

dep depend:	
	$(CC) $(CFLAGS) -MM *.c >.depend 2>/dev/null

clean:
	rm -f $(PROG1) $(PROG2) *.o *.bak .depend



ifeq (.depend,$(wildcard .depend))
include .depend
endif
