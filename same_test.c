/*
   skipfish - same_page() test utility
   -----------------------------------

   Author: Michal Zalewski <lcamtuf@google.com>

   Copyright 2009, 2010, 2011 by Google Inc. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <sys/stat.h>

#include "types.h"
#include "alloc-inl.h"
#include "string-inl.h"

#include "crawler.h"
#include "analysis.h"
#include "database.h"
#include "http_client.h"
#include "report.h"

#ifdef DEBUG_ALLOCATOR
struct TRK_obj* TRK[ALLOC_BUCKETS];
u32 TRK_cnt[ALLOC_BUCKETS];
#endif /* DEBUG_ALLOCATOR */

#define MAX_LEN (1024*1024)

u8 p1[MAX_LEN], p2[MAX_LEN];

int main(int argc, char** argv) {
  static struct http_response r1, r2;
  s32 l1, l2;

  l1 = read(8, p1, MAX_LEN);
  l2 = read(9, p2, MAX_LEN);

  if (l1 < 0 || l2 < 0)
    FATAL("Usage: ./same_test 8<file1 9<file2");

  r1.code = 123;
  r2.code = 123;

  r1.payload = p1;
  r2.payload = p2;
  r1.pay_len = l1;
  r2.pay_len = l2;

  fprint_response(&r1);
  fprint_response(&r2);

  debug_same_page(&r1.sig, &r2.sig);

  if (same_page(&r1.sig, &r2.sig))
    DEBUG("=== PAGES SEEM THE SAME ===\n");
  else
    DEBUG("=== PAGES ARE DIFFERENT ===\n");

  return 0;

}
