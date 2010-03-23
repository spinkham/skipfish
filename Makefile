#
# skipfish - Makefile
# -------------------
#
# Author: Michal Zalewski <lcamtuf@google.com>
#
# Copyright 2009, 2010 by Google Inc. All Rights Reserved.
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

OBJFILES   = http_client.c database.c crawler.c analysis.c report.c
INCFILES   = alloc-inl.h string-inl.h debug.h types.h http_client.h \
             database.h crawler.h analysis.h config.h report.h

CFLAGS_GEN = -Wall -funsigned-char -g -ggdb -D_FORTIFY_SOURCE=0 \
             -I/usr/local/include/ -I/opt/local/include/ $(CFLAGS)
CFLAGS_DBG = $(CFLAGS_GEN) -DLOG_STDERR=1 -DDEBUG_ALLOCATOR=1
CFLAGS_OPT = $(CFLAGS_GEN) -O3 -Wno-format
LDFLAGS   += -lcrypto -lssl -lidn -lz -L/usr/local/lib/ -L/opt/local/lib

all: $(PROGNAME)

$(PROGNAME): $(PROGNAME).c $(OBJFILES) $(INCFILES)
	$(CC) $(PROGNAME).c -o $(PROGNAME) $(CFLAGS_OPT) $(OBJFILES) $(LDFLAGS)
	@echo
	@echo "See dictionaries/README-FIRST to pick a dictionary for the tool."
	@echo
	@echo "Having problems with your scans? Be sure to visit:"
	@echo "http://code.google.com/p/skipfish/wiki/KnownIssues"
	@echo

debug: $(PROGNAME).c $(OBJFILES) $(INCFILES)
	$(CC) $(PROGNAME).c -o $(PROGNAME) $(CFLAGS_DBG) $(OBJFILES) $(LDFLAGS)

clean:
	rm -f $(PROGNAME) *.exe *.o *~ a.out core core.[1-9][0-9]* *.stackdump \
	      LOG same_test
	rm -rf tmpdir

same_test: same_test.c $(OBJFILES) $(INCFILES)
	$(CC) same_test.c -o same_test $(CFLAGS_DBG) $(OBJFILES) $(LDFLAGS)

publish: clean
	cd ..; tar cfvz ~/www/skipfish.tgz skipfish
	chmod 644 ~/www/skipfish.tgz
