# Makefile for scripts
#
# With luck this should cope with Debian, Redhat, SuSE, Caldera & Slackware type
# distributions - but no promises.
#


include ../Makefile.common

all: 


install:
ifndef MAKEDEB
	if [ -d /var/lib/dpkg ]; then \
	  install -Dm 0700 decnet.sh $(sysconfprefix)/etc/init.d/decnet.sh; \
	elif [ -d /var/lib/YaST ]; then \
	  install -Dm 0700 decnet.sh $(sysconfprefix)/sbin/init.d/decnet; \
	elif [ -d /var/lib/rpm ]; then \
	  install -Dm 0700 decnet.sh $(sysconfprefix)/etc/rc.d/init.d/decnet; \
	elif [ -d /var/lib/portage ]; then \
	  install -Dm 0700 dnetd $(sysconfprefix)/etc/init.d/dnetd; \
	  install -Dm 0700 dnetconf $(sysconfprefix)/etc/conf.d/dnetd; \
        else install -Dm 0700 rc.decnet $(sysconfprefix)/etc/rc.d/rc.decnet; \
	fi
endif
	install -m 0755 setup.sh $(prefix)/sbin/decnetconf
	install -m 0644 decnetconf.8 $(manprefix)/man/man8
	install -m 0755 dnetLoadModule $(prefix)/sbin

dep depend:	


clean:


# DO NOT DELETE THIS LINE -- make  depend  depends  on it.
