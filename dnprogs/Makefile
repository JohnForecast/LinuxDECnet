

include Makefile.common

#
# PKGNAME determines the .tar.gz file name and also is the directory name
#
PKGNAME=dnprogs
DATE="$(shell date +'%Y%m%d')"

SUBDIRS_LINUX=apps phone dnroute nml multinet

SUBDIRS=include libdnet libdaemon libdap librms fal dndir dnsubmit dndel \
	dncopy dts dtr dntask dnlogin mail ncp dnetd libvaxdata \
	scripts \
	contrib/ph3-der-loewe \

ifeq ($(OSNAME),Linux)
SUBDIRS+= $(SUBDIRS_LINUX)
endif

#ifneq ($(wildcard /usr/include/fuse.h),)
#SUBDIRS+= dapfs
#endif

all: 	
	@set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i $@ ; done

install:
	@set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i $@ ; done

dep depend:	
	@set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i $@ ; done

tags:	
	etags */*.cc */*.c


clean:
	rm -rf debian/tmp
	rm -f debian/files
	rm -f debian/substvars
	rm -f debian/*~
	rm -rf rpmbuild
	rm -rf RPMS
	rm -rf SOURCES
	rm -rf SRPMS
	rm -rf BUILD
	rm -f .rpm*
	rm -f build
	rm -f core
	@for i in $(SUBDIRS); do $(MAKE) -C $$i $@ ; done

debclean:
	debian/rules clean
#
# Make the distribution tar file
#
dist:	clean
	cp debian/changelog NEWS
	for i in $(SUBDIRS); do cd $$i; rm -f .depend; cd ..; done
	if [ -L ../$(PKGNAME)-$(VERSION) ]; then rm ../$(PKGNAME)-$(VERSION); fi
	if [ ! -d ../$(PKGNAME)-$(VERSION) ]; then cd ..; ln -s $(PKGNAME) $(PKGNAME)-$(VERSION); fi
	cd ..; tar -czvhf /var/tmp/$(PKGNAME)-$(VERSION).tar.gz -X$(PKGNAME)-$(VERSION)/excludes-dist $(PKGNAME)-$(VERSION)/;
	if [ -L ../$(PKGNAME)-$(VERSION) ]; then rm ../$(PKGNAME)-$(VERSION); fi

#
# Make a snapshot release
#
snap:	
	for i in $(SUBDIRS); do cd $$i; rm -f .depend; cd ..; done	
	if [ -L ../$(PKGNAME)-$(DATE) ]; then rm ../$(PKGNAME)-$(DATE); fi
	if [ ! -d ../$(PKGNAME)-$(DATE) ]; then cd ..; ln -s $(PKGNAME) $(PKGNAME)-$(DATE); fi
	cd ..; tar -czvhf /var/tmp/$(PKGNAME)-$(DATE).tar.gz -X$(PKGNAME)-$(DATE)/excludes-dist $(PKGNAME)-$(DATE);
	if [ -L ../$(PKGNAME)-$(DATE) ]; then rm ../$(PKGNAME)-$(DATE); fi

#
# Make RPM package for Red Hat systems.
#
rpm:	
	rm -rf rpmbuild BUILD RPMS SOURCES
	$(MAKE) clean
	$(MAKE) dist
	echo "%_topdir `pwd`" > .rpmmacros
	echo "`rpm --showrc|grep \^macrofiles`:`pwd`/.rpmmacros" >.rpmrc
	$(MAKE) prefix=/usr RELEASE=true -j
	$(MAKE) DESTDIR=`pwd`/rpmbuild RELEASE=true install
	find `pwd`/rpmbuild/usr/share/man/ -type f|xargs gzip -9
	ln -sf libdnet.so.2 rpmbuild/usr/lib/libdnet.so.1
	mkdir SOURCES SRPMS
	cp /var/tmp/$(PKGNAME)-$(VERSION).tar.gz SOURCES
	install -d rpmbuild/etc/rc.d/init.d
	install -d rpmbuild/usr/doc
	rm rpmbuild/usr/share/man/man1/dntype.1
	rm rpmbuild/usr/share/man/man1/dnprint.1
	rm rpmbuild/usr/share/man/man3/dnet_accept.3
	rm rpmbuild/usr/share/man/man3/dnet_reject.3
	rm rpmbuild/usr/share/man/man3/dnet_endnode.3
	rm rpmbuild/usr/share/man/man3/dnet_nextnode.3
	rm rpmbuild/usr/share/man/man8/dneigh.8
	ln -s dncopy.1.gz rpmbuild/usr/share/man/man1/dntype.1.gz
	ln -s dnsubmit.1.gz rpmbuild/usr/share/man/man1/dnprint.1.gz
	ln -s dnet_daemon.3.gz rpmbuild/usr/share/man/man3/dnet_accept.3.gz
	ln -s dnet_daemon.3.gz rpmbuild/usr/share/man/man3/dnet_reject.3.gz
	ln -s dnet_getnode.3.gz rpmbuild/usr/share/man/man3/dnet_endnode.3.gz
	ln -s dnet_getnode.3.gz rpmbuild/usr/share/man/man3/dnet_nextnode.3.gz
	ln -s dnetinfo.8.gz rpmbuild/usr/share/man/man8/dneigh.8.gz
	sed -e's@/usr/local@/usr@g' < scripts/decnet.sh >rpmbuild/etc/rc.d/init.d/decnet
	sed -e's/%%PACKAGENAME%%/$(PKGNAME)/g'                          \
	    -e's/%%VERSION%%/$(VERSION)/g'                              \
	    -e's/%%MAJOR_VERSION%%/$(MAJOR_VERSION)/g'                  \
	    -e's@%%PREFIX%%@/usr@g'                                     \
	    -e's@%%LIBPREFIX%%@/usr@g'                                  \
	    -e's@%%CONFPREFIX%%@/@g'                                    \
	   < rpm.spec >$(PKGNAME).spec
	mkdir -p BUILD RPMS/$(ARCH)
	cp README Documentation/*.README BUILD
	cp debian/changelog BUILD/NEWS
	cp libvaxdata/libvaxdata.pdf BUILD
	rpmbuild -ba --target $(ARCH) --buildroot `pwd`/rpmbuild -v --rcfile .rpmrc $(PKGNAME).spec
	rm -f $(PKGNAME).spec .rpmrc .rpmmacros

#
# Make Debian package.
#
deb:
	rm -f Documentation/*~ Documentation/*.bak
	dpkg-buildpackage -ICVS -rfakeroot 
#
# Dummy rule for sub-directories
#
dummy:


# DO NOT DELETE THIS LINE -- make  depend  depends  on it.
