# AES Crypt
# Copyright (C) 2007, 2008, 2009, 2013 Paul E. Jones <paulej@packetizer.com>
# Copyright (C) 2013, 2014 Alon Bar-Lev <alon.barlev@gmail.com>
#
# This software is licensed as "freeware."  Permission to distribute
# this software in source and binary forms is hereby granted without a
# fee.  THIS SOFTWARE IS PROVIDED 'AS IS' AND WITHOUT ANY EXPRESSED OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
# THE AUTHOR SHALL NOT BE HELD LIABLE FOR ANY DAMAGES RESULTING FROM
# THE USE OF THIS SOFTWARE, EITHER DIRECTLY OR INDIRECTLY, INCLUDING,
# BUT NOT LIMITED TO, LOSS OF DATA OR DATA BEING RENDERED INACCURATE.
#

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(NULL)

TESTS = \
	sha.test \
	aes.test \
	file-test.sh \
	$(NULL)

bin_PROGRAMS = \
	aescrypt \
	aescrypt_keygen \
	$(NULL)

noinst_PROGRAMS = \
	sha.test \
	aes.test \
	$(NULL)

dist_noinst_SCRIPTS = \
	file-test.sh \
	$(NULL)

aescrypt_SOURCES = \
	aescrypt.c \
	aes.c aes.h \
	sha256.c sha256.h \
	password.c password.h \
	keyfile.c keyfile.h \
	aescrypt.h \
	aesrandom.c aesrandom.h \
	util.c util.h \
	$(NULL)

aescrypt_keygen_SOURCES = \
	aescrypt_keygen.c \
	password.c password.h \
	util.c util.h \
	$(NULL)

sha_test_SOURCES = \
	sha256.c sha256.h \
	$(NULL)
sha_test_CPPFLAGS = \
	-DTEST \
	$(NULL)

aes_test_SOURCES = \
	aes.c aes.h \
	$(NULL)
aes_test_CPPFLAGS = \
	-DTEST \
	$(NULL)

clean-local:
	rm -f *.log *.trs

if WINDOWS
RCCOMPILE = $(RC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) \
	$(AM_CPPFLAGS) $(CPPFLAGS)
LTRCCOMPILE = $(LIBTOOL) --mode=compile --tag=RC $(RCCOMPILE)

.rc.lo:
	$(LTRCCOMPILE) -i "$<" -o "$@"

.rc.o:
	$(RCCOMPILE) -i "$<" -o "$@"

.mc.rc:
	$(WINDMC) "$<"

aescrypt_SOURCES += aescrypt_win_resources.rc
aescrypt_keygen_SOURCES += aescrypt_win_resources.rc
endif
