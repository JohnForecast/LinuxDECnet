include ../Makefile.common

DNROUTE=dnroute

DNEIGH=dneigh

#CFLAGS	+= -Inetlink/include $(SYSCONF_PREFIX)

#all: $(DNROUTE) $(DNEIGH)
all: $(DNEIGH)

$(DNEIGH): dneigh.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIBDNET)

#$(DNROUTE): get_neigh.c send_route.c routing_msg.c csum.c hash.c pidfile.c netlink/libnetlink.a
#	$(CC) $(CFLAGS) -o $@ $^ -Lnetlink -lnetlink $(LIBDNET)

#netlink/libnetlink.a:
#	$(MAKE) -C netlink

install:
	install -d $(prefix)/sbin
	install -d $(manprefix)/man/man8
#	install -m 0755 $(STRIPBIN) dnroute $(prefix)/sbin
	install -m 0755 dneigh $(prefix)/sbin
	ln -sf dneigh $(prefix)/sbin/dnetinfo
#	install -m 0644 dnroute.8 $(manprefix)/man/man8
	install -m 0644 dnetinfo.8 $(manprefix)/man/man8
	ln -sf dnetinfo.8 $(manprefix)/man/man8/dneigh.8

clean:
	rm -f $(DNROUTE) $(DNEIGH) *~ *.o netlink/*.o netlink/*.a
