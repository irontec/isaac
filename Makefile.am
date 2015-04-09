SUBDIRS = src modules
EXTRA_DIST = bootstrap.sh

config: conf
conf:
	cd $@ && $(MAKE) $(AM_MAKEFLAGS) install

ivozng:
	cd ivozng && $(MAKE) $(AM_MAKEFLAGS)

install-ivozng: ivozng-install	
ivozng-install: ivozng
	cd ivozng && $(MAKE) $(AM_MAKEFLAGS) install

clean-local:
	cd ivozng && $(MAKE) $(AM_MAKEFLAGS) clean
	
.PHONY: config conf ivozng