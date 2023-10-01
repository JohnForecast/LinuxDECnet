include ../Makefile.common

ARCH=$(shell uname -m)

all:
	cd linux; $(MAKE) -f makefile.gcc

clean:
	cd linux; $(MAKE) -f makefile.gcc clean

install:
	install -d $(prefix)/include
	install -m 0644 src/convert_vax_data.h $(prefix)/include
	install -d $(prefix)/lib
	install -m0644 linux/$(ARCH)/libvaxdata.a $(libprefix)$(libdir)
