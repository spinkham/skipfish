#
# skipfish - Makefile
# -------------------
#
# Author: Michal Zalewski <lcamtuf@google.com>
#
# Copyright 2009, 2010, 2011 by Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

PROGNAME   = skipfish
VERSION    = 2.09b

SRCDIR     = src
SFILES     = http_client.c database.c crawler.c analysis.c report.c \
             checks.c signatures.c auth.c
IFILES     = alloc-inl.h string-inl.h debug.h types.h http_client.h \
             database.h crawler.h analysis.h config.h report.h \
             checks.h signatures.h auth.h

OBJFILES   = $(patsubst %,$(SRCDIR)/%,$(SFILES))
INCFILES   = $(patsubst %,$(SRCDIR)/%,$(IFILES))

CFLAGS_GEN = -Wall -funsigned-char -g -ggdb -I/usr/local/include/ \
             -I/opt/local/include/ $(CFLAGS) -DVERSION=\"$(VERSION)\"
CFLAGS_DBG = -DLOG_STDERR=1 -DDEBUG_ALLOCATOR=1 $(CFLAGS_GEN)
CFLAGS_OPT =  -O3 -Wno-format $(CFLAGS_GEN)

LDFLAGS   += -L/usr/local/lib/ -L/opt/local/lib
LIBS      += -lcrypto -lssl -lidn -lz -lpcre

all: $(PROGNAME)

$(PROGNAME): $(SRCDIR)/$(PROGNAME).c $(OBJFILES) $(INCFILES)
	$(CC) $(LDFLAGS) $(SRCDIR)/$(PROGNAME).c -o $(PROGNAME) \
        $(CFLAGS_OPT) $(OBJFILES) $(LIBS)
	@echo
	@echo "See doc/dictionaries.txt to pick a dictionary for the tool."
	@echo
	@echo "Having problems with your scans? Be sure to visit:"
	@echo "http://code.google.com/p/skipfish/wiki/KnownIssues"
	@echo

debug: $(SRCDIR)/$(PROGNAME).c $(OBJFILES) $(INCFILES)
	$(CC) $(LDFLAGS) $(SRCDIR)/$(PROGNAME).c -o $(PROGNAME) \
        $(CFLAGS_DBG) $(OBJFILES) $(LIBS)

clean:
	rm -f $(PROGNAME) *.exe *.o *~ a.out core core.[1-9][0-9]* *.stackdump \
	      LOG same_test
	rm -rf tmpdir

same_test: $(SRCDIR)/same_test.c $(OBJFILES) $(INCFILES)
	$(CC) $(SRCDIR)/same_test.c -o same_test $(CFLAGS_DBG) $(OBJFILES) $(LDFLAGS) \
	      $(LIBS)

publish: clean
	cd ..; rm -rf skipfish-$(VERSION); cp -pr skipfish skipfish-$(VERSION); \
	  tar cfvz ~/www/skipfish.tgz skipfish-$(VERSION)
	chmod 644 ~/www/skipfish.tgz
