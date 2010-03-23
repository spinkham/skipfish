/*
   skipfish - main entry point
   ---------------------------

   Author: Michal Zalewski <lcamtuf@google.com>

   Copyright 2009, 2010 by Google Inc. All Rights Reserved.

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
struct __AD_trk_obj* __AD_trk[ALLOC_BUCKETS];
u32 __AD_trk_cnt[ALLOC_BUCKETS];
#endif /* DEBUG_ALLOCATOR */


/* *BSD where J or Z is set are incompatible with our allocator. */
const char* malloc_options  = "jz";
const char* _malloc_options = "jz";


void usage(char* argv0) {
  SAY("Usage: %s [ options ... ] -o output_dir start_url [ start_url2 ... ]\n\n"

      "Authentication and access options:\n\n"

      "  -A user:pass   - use specified HTTP authentication credentials\n"
      "  -F host:IP     - pretend that 'host' resolves to 'IP'\n"
      "  -C name=val    - append a custom cookie to all requests\n"
      "  -H name=val    - append a custom HTTP header to all requests\n"
      "  -b (i|f)       - use headers consistent with MSIE / Firefox\n"
      "  -N             - do not accept any new cookies\n\n"

      "Crawl scope options:\n\n"

      "  -d max_depth   - maximum crawl tree depth (%u)\n"
      "  -c max_child   - maximum children to index per node (%u)\n"
      "  -r r_limit     - max total number of requests to send (%u)\n"
      "  -p crawl%%      - node and link crawl probability (100%%)\n"
      "  -q hex         - repeat probabilistic scan with given seed\n"
      "  -I string      - only follow URLs matching 'string'\n"
      "  -X string      - exclude URLs matching 'string'\n"
      "  -S string      - exclude pages containing 'string'\n"
      "  -D domain      - crawl cross-site links to another domain\n"
      "  -B domain      - trust, but do not crawl, another domain\n"
      "  -O             - do not submit any forms\n"
      "  -P             - do not parse HTML, etc, to find new links\n\n"

      "Reporting options:\n\n"

      "  -o dir         - write output to specified directory (required)\n"
      "  -J             - be less noisy about MIME / charset mismatches\n"
      "  -M             - log warnings about mixed content\n"
      "  -E             - log all HTTP/1.0 / HTTP/1.1 caching intent mismatches\n"
      "  -U             - log all external URLs and e-mails seen\n"
      "  -Q             - completely suppress duplicate nodes in reports\n\n"

      "Dictionary management options:\n\n"

      "  -W wordlist    - load an alternative wordlist (%s)\n"
      "  -L             - do not auto-learn new keywords for the site\n"
      "  -V             - do not update wordlist based on scan results\n"
      "  -Y             - do not fuzz extensions in directory brute-force\n"
      "  -R age         - purge words hit more than 'age' scans ago\n"
      "  -T name=val    - add new form auto-fill rule\n"
      "  -G max_guess   - maximum number of keyword guesses to keep (%d)\n\n"

      "Performance settings:\n\n"

      "  -g max_conn    - max simultaneous TCP connections, global (%u)\n"
      "  -m host_conn   - max simultaneous connections, per target IP (%u)\n"
      "  -f max_fail    - max number of consecutive HTTP errors (%u)\n"
      "  -t req_tmout   - total request response timeout (%u s)\n"
      "  -w rw_tmout    - individual network I/O timeout (%u s)\n"
      "  -i idle_tmout  - timeout on idle HTTP connections (%u s)\n"
      "  -s s_limit     - response size limit (%u B)\n\n"

      "Send comments and complaints to <lcamtuf@google.com>.\n", argv0,
      max_depth, max_children, max_requests, DEF_WORDLIST, MAX_GUESSES,
      max_connections, max_conn_host, max_fail, resp_tmout, rw_tmout,
      idle_tmout, size_limit);

  exit(1);
}


/* Ctrl-C handler... */

static u8 stop_soon, clear_screen;

static void ctrlc_handler(int sig) {
  stop_soon = 1;
}


/* Screen resizing handler. */

static void resize_handler(int sig) {
  clear_screen = 1;
}


/* Main entry point */

int main(int argc, char** argv) {
  s32 opt;
  u32 loop_cnt = 0, purge_age = 0, seed;
  u8 dont_save_words = 0, show_once = 0;
  u8 *wordlist = (u8*)DEF_WORDLIST, *output_dir = NULL;

  struct timeval tv;
  u64 st_time, en_time;

  signal(SIGINT, ctrlc_handler);
  signal(SIGWINCH, resize_handler);
  signal(SIGPIPE, SIG_IGN);
  SSL_library_init();

  /* Come up with a quasi-decent random seed. */

  gettimeofday(&tv, NULL);
  seed = tv.tv_usec ^ (tv.tv_sec << 16) ^ getpid();

  SAY("skipfish version " VERSION " by <lcamtuf@google.com>\n");

  while ((opt = getopt(argc, argv,
          "+A:F:C:H:b:Nd:c:r:p:I:X:S:D:PJOYQMUEW:LVT:G:R:B:q:g:m:f:t:w:i:s:o:h")) > 0)

    switch (opt) {

      case 'A': {
          u8* x = (u8*)strchr(optarg, ':');
          if (!x) FATAL("Credentials must be in 'user:pass' form.");
          *(x++) = 0;
          auth_user = (u8*)optarg;
          auth_pass = x;
          auth_type = AUTH_BASIC;
          break;
        }

      case 'F': {
          u8* x = (u8*)strchr(optarg, '=');
          u32 fake_addr;
          if (!x) FATAL("Fake mappings must be in 'host=IP' form.");
          *x = 0;
          fake_addr = inet_addr((char*)x + 1);
          if (fake_addr == (u32)-1)
            FATAL("Could not parse IP address '%s'.", x + 1);
          fake_host((u8*)optarg, fake_addr);
          break;
        }

      case 'H': {
          u8* x = (u8*)strchr(optarg, '=');
          if (!x) FATAL("Extra headers must be in 'name=value' form.");
          *x = 0;
          if (!strcasecmp(optarg, "Cookie"))
            FATAL("Do not use -H to set cookies (try -C instead).");
          SET_HDR((u8*)optarg, x + 1, &global_http_par);
          break;
        }

      case 'C': {
          u8* x = (u8*)strchr(optarg, '=');
          if (!x) FATAL("Cookies must be in 'name=value' form.");
          if (strchr(optarg, ';'))
            FATAL("Split multiple cookies into separate -C options.");
          *x = 0;
          SET_CK((u8*)optarg, x + 1, &global_http_par);
          break;
        }

      case 'D':
        if (*optarg == '*') optarg++;
        APPEND_FILTER(allow_domains, num_allow_domains, optarg);
        break;

      case 'B':
        if (*optarg == '*') optarg++;
        APPEND_FILTER(trust_domains, num_trust_domains, optarg);
        break;

      case 'I':
        if (*optarg == '*') optarg++;
        APPEND_FILTER(allow_urls, num_allow_urls, optarg);
        break;

      case 'X':
        if (*optarg == '*') optarg++;
        APPEND_FILTER(deny_urls, num_deny_urls, optarg);
        break;

      case 'J':
        relaxed_mime = 1;
        break;

      case 'S':
        if (*optarg == '*') optarg++;
        APPEND_FILTER(deny_strings, num_deny_strings, optarg);
        break;

      case 'T': {
          u8* x = (u8*)strchr(optarg, '=');
          if (!x) FATAL("Rules must be in 'name=value' form.");
          *x = 0;
          add_form_hint((u8*)optarg, x + 1);
          break;
        }

      case 'N':
        ignore_cookies = 1;
        break;

      case 'Y':
        no_fuzz_ext = 1;
        break;

      case 'q':
        if (sscanf(optarg, "0x%08x", &seed) != 1)
          FATAL("Invalid seed format.");
        srandom(seed);
        break;

      case 'Q':
        suppress_dupes = 1;
        break;

      case 'P':
        no_parse = 1;
        break;

      case 'V':
        dont_save_words = 1;
        break;

      case 'M':
        warn_mixed = 1;
        break;

      case 'U':
        log_ext_urls = 1;
        break;

      case 'L':
        dont_add_words = 1;
        break;

      case 'E':
        pedantic_cache = 1;
        break;

      case 'O':
        no_forms = 1;
        break;

      case 'R':
        purge_age = atoi(optarg);
        if (purge_age < 3) FATAL("Purge age invalid or too low (min 3).");
        break;

      case 'd':
        max_depth = atoi(optarg);
        if (max_depth < 2) FATAL("Invalid value '%s'.", optarg);
        break;

      case 'c':
        max_children = atoi(optarg);
        if (!max_children) FATAL("Invalid value '%s'.", optarg);
        break;

      case 'p':
        crawl_prob = atoi(optarg);
        if (!crawl_prob) FATAL("Invalid value '%s'.", optarg);
        break;

      case 'W':
        wordlist = (u8*)optarg;
        break;

      case 'b':
        if (optarg[0] == 'i') browser_type = BROWSER_MSIE; else
        if (optarg[0] == 'f') browser_type = BROWSER_FFOX; else
          usage(argv[0]);
        break;

      case 'g':
        max_connections = atoi(optarg);
        if (!max_connections) FATAL("Invalid value '%s'.", optarg);
        break;

      case 'm':
        max_conn_host = atoi(optarg);
        if (!max_conn_host) FATAL("Invalid value '%s'.", optarg);
        break;

      case 'G':
        max_guesses = atoi(optarg);
        if (!max_guesses) FATAL("Invalid value '%s'.", optarg);
        break;

      case 'r':
        max_requests = atoi(optarg);
        if (!max_requests) FATAL("Invalid value '%s'.", optarg);
        break;

      case 'f':
        max_fail = atoi(optarg);
        if (!max_fail) FATAL("Invalid value '%s'.", optarg);
        break;

      case 't':
        resp_tmout = atoi(optarg);
        if (!resp_tmout) FATAL("Invalid value '%s'.", optarg);
        break;

      case 'w':
        rw_tmout = atoi(optarg);
        if (!rw_tmout) FATAL("Invalid value '%s'.", optarg);
        break;

      case 'i':
        idle_tmout = atoi(optarg);
        if (!idle_tmout) FATAL("Invalid value '%s'.", optarg);
        break;

      case 's':
        size_limit = atoi(optarg);
        if (!size_limit) FATAL("Invalid value '%s'.", optarg);
        break;

      case 'o':
        if (output_dir) FATAL("Multiple -o options not allowed.");
        output_dir = (u8*)optarg;

        rmdir(optarg);

        if (mkdir(optarg, 0755))
          PFATAL("Unable to create '%s'.", output_dir);

        break;

      default:
        usage(argv[0]);

  }

  if (access(ASSETS_DIR "/index.html", R_OK))
    PFATAL("Unable to access '%s/index.html' - wrong directory?", ASSETS_DIR);

  srandom(seed);

  if (optind == argc)
    FATAL("Scan target not specified (try -h for help).");

  if (!output_dir)
    FATAL("Output directory not specified (try -h for help).");

  if (resp_tmout < rw_tmout) 
    resp_tmout = rw_tmout;

  if (max_connections < max_conn_host)
    max_connections = max_conn_host;

  load_keywords((u8*)wordlist, purge_age);

  /* Schedule all URLs in the command line for scanning */

  while (optind < argc) {

    struct http_request *req = ck_alloc(sizeof(struct http_request));

    if (parse_url((u8*)argv[optind], req, NULL))
      FATAL("One of specified scan targets is not a valid absolute URL.");

    if (!url_allowed_host(req))
      APPEND_FILTER(allow_domains, num_allow_domains,
                    __DFL_ck_strdup(req->host));

    if (!url_allowed(req))
      FATAL("URL '%s' explicitly excluded by -I / -X rules.", argv[optind]);

    maybe_add_pivot(req, NULL, 2);
    destroy_request(req);

    optind++;
  }

  gettimeofday(&tv, NULL);
  st_time = tv.tv_sec * 1000 + tv.tv_usec / 1000;

  SAY("\x1b[H\x1b[J");

  while ((next_from_queue() && !stop_soon) || (!show_once++)) {

    if ((loop_cnt++ % 20) && !show_once) continue;

    if (clear_screen) {
      SAY("\x1b[H\x1b[2J");
      clear_screen = 0;
    }

    SAY(cYEL "\x1b[H"
           "skipfish version " VERSION " by <lcamtuf@google.com>\n\n" cNOR);

    http_stats(st_time);
    SAY("\n");
    database_stats();
    SAY("\n        \r");

  }

  gettimeofday(&tv, NULL);
  en_time = tv.tv_sec * 1000 + tv.tv_usec / 1000;

  if (stop_soon)
    SAY(cYEL "[!] " cBRI "Scan aborted by user, bailing out!" cNOR "\n");

  if (!dont_save_words) save_keywords((u8*)wordlist);

  write_report(output_dir, en_time - st_time, seed);

#ifdef LOG_STDERR
  SAY("\n== PIVOT DEBUG ==\n");
  dump_pivots(0, 0);
  SAY("\n== END OF DUMP ==\n\n");
#endif /* LOG_STDERR */

  SAY(cLGN "[+] " cBRI "This was a great day for science!" cRST "\n\n");

#ifdef DEBUG_ALLOCATOR
  if (!stop_soon) {
    destroy_database();
    destroy_http();
    destroy_signatures();
    __AD_report();
  }
#endif /* DEBUG_ALLOCATOR */

  return 0;

}
