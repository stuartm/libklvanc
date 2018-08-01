AUTOMAKE_OPTIONS = foreign
SUBDIRS = src tools
EXTRA_DIST = doxygen/libklvanc.doxyconf doxygen/include

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libklvanc.pc

docs:
	cd doxygen && doxygen libklvanc.doxyconf

test:
	cd tools && make test
