/*
   skipfish - main entry point
   ---------------------------

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
#include <termios.h>
#include <fcntl.h>

#include "types.h"
#include "alloc-inl.h"
#include "string-inl.h"

#include "crawler.h"
#include "checks.h"
#include "analysis.h"
#include "database.h"
#include "http_client.h"
#include "report.h"
#include "signatures.h"
#include "auth.h"

#ifdef DEBUG_ALLOCATOR
struct TRK_obj* TRK[ALLOC_BUCKETS];
u32 TRK_cnt[ALLOC_BUCKETS];
#endif /* DEBUG_ALLOCATOR */

/* Ctrl-C handler... */

static u8 stop_soon, clear_screen;

static void ctrlc_handler(int sig) {
  stop_soon = 1;
}


/* Screen resizing handler. */

static void resize_handler(int sig) {
  clear_screen = 1;
}


/* Usage info. */

static void usage(char* argv0) {
  SAY("Usage: %s [ options ... ] -W wordlist -o output_dir start_url [ start_url2 ... ]\n\n"

      "Authentication and access options:\n\n"

      "  -A user:pass      - use specified HTTP authentication credentials\n"
      "  -F host=IP        - pretend that 'host' resolves to 'IP'\n"
      "  -C name=val       - append a custom cookie to all requests\n"
      "  -H name=val       - append a custom HTTP header to all requests\n"
      "  -b (i|f|p)        - use headers consistent with MSIE / Firefox / iPhone\n"
#ifdef PROXY_SUPPORT
     "   -J proxy          - use a specified HTTP proxy server\n"
#endif /* PROXY_SUPPORT */
      "  -N                - do not accept any new cookies\n"
      "  --auth-form url   - form authentication URL\n"
      "  --auth-user user  - form authentication user\n"
      "  --auth-pass pass  - form authentication password\n"
      "  --auth-verify-url -  URL for in-session detection\n\n"

      "Crawl scope options:\n\n"

      "  -d max_depth     - maximum crawl tree depth (%u)\n"
      "  -c max_child     - maximum children to index per node (%u)\n"
      "  -x max_desc      - maximum descendants to index per branch (%u)\n"
      "  -r r_limit       - max total number of requests to send (%u)\n"
      "  -p crawl%%        - node and link crawl probability (100%%)\n"
      "  -q hex           - repeat probabilistic scan with given seed\n"
      "  -I string        - only follow URLs matching 'string'\n"
      "  -X string        - exclude URLs matching 'string'\n"
      "  -K string        - do not fuzz parameters named 'string'\n"
      "  -D domain        - crawl cross-site links to another domain\n"
      "  -B domain        - trust, but do not crawl, another domain\n"
      "  -Z               - do not descend into 5xx locations\n"
      "  -O               - do not submit any forms\n"
      "  -P               - do not parse HTML, etc, to find new links\n\n"

      "Reporting options:\n\n"

      "  -o dir          - write output to specified directory (required)\n"
      "  -M              - log warnings about mixed content / non-SSL passwords\n"
      "  -E              - log all HTTP/1.0 / HTTP/1.1 caching intent mismatches\n"
      "  -U              - log all external URLs and e-mails seen\n"
      "  -Q              - completely suppress duplicate nodes in reports\n"
      "  -u              - be quiet, disable realtime progress stats\n"
      "  -v              - enable runtime logging (to stderr)\n\n"

      "Dictionary management options:\n\n"

      "  -W wordlist     - use a specified read-write wordlist (required)\n"
      "  -S wordlist     - load a supplemental read-only wordlist\n"
      "  -L              - do not auto-learn new keywords for the site\n"
      "  -Y              - do not fuzz extensions in directory brute-force\n"
      "  -R age          - purge words hit more than 'age' scans ago\n"
      "  -T name=val     - add new form auto-fill rule\n"
      "  -G max_guess    - maximum number of keyword guesses to keep (%d)\n\n"
      "  -z sigfile      - load signatures from this file\n\n"

      "Performance settings:\n\n"

      "  -g max_conn     - max simultaneous TCP connections, global (%u)\n"
      "  -m host_conn    - max simultaneous connections, per target IP (%u)\n"
      "  -f max_fail     - max number of consecutive HTTP errors (%u)\n"
      "  -t req_tmout    - total request response timeout (%u s)\n"
      "  -w rw_tmout     - individual network I/O timeout (%u s)\n"
      "  -i idle_tmout   - timeout on idle HTTP connections (%u s)\n"
      "  -s s_limit      - response size limit (%u B)\n"
      "  -e              - do not keep binary responses for reporting\n\n"

      "Safety settings:\n\n"

      "  -l max_req      - max requests per second (%f)\n"
      "  -k duration     - stop scanning after the given duration h:m:s\n\n"

      "Send comments and complaints to <heinenn@google.com>.\n", argv0,
      max_depth, max_children, max_descendants, max_requests,
      MAX_GUESSES, max_connections, max_conn_host,
      max_fail, resp_tmout, rw_tmout, idle_tmout, size_limit, max_requests_sec);

  exit(1);
}


/* Welcome screen. */

#ifdef SHOW_SPLASH
void splash_screen(void) {
  char keybuf[8];
  u32  time_cnt = 0;

  SAY("\x1b[H\x1b[J");

  SAY(cBRI "Welcome to " cYEL "skipfish" cBRI ". Here are some useful tips:\n\n"

      "1) To abort the scan at any time, press " cCYA "Ctrl-C" cBRI ". A partial report will be written\n"
      "   to the specified location. To view a list of currently scanned URLs, you can\n"
      "   press " cCYA "space" cBRI " at any time during the scan.\n\n"

      "2) Watch the number requests per second shown on the main screen. If this figure\n"
      "   drops below 100-200, the scan will likely take a very long time.\n\n"

      "3) The scanner does not auto-limit the scope of the scan; on complex sites, you\n"
      "   may need to specify locations to exclude, or limit brute-force steps.\n\n"

      "4) There are several new releases of the scanner every month. If you run into\n"
      "   trouble, check for a newer version first, let the author know next.\n\n"

      "More info: " cYEL "http://code.google.com/p/skipfish/wiki/KnownIssues\n\n" cBRI);

  if (!no_fuzz_ext && (keyword_orig_cnt * wg_extension_cnt) > 1000) {

    SAY(cLRD 

        "NOTE: The scanner is currently configured for directory brute-force attacks,\n"
        "and will make about " cBRI "%u" cLRD " requests per every fuzzable location. If this is\n"
        "not what you wanted, stop now and consult the documentation.\n\n",
        keyword_orig_cnt * wg_extension_cnt);

  }

  SAY(cLBL "Press any key to continue (or wait 60 seconds)... ");

  while (!stop_soon && fread(keybuf, 1, sizeof(keybuf), stdin) == 0 && time_cnt++ < 600) 
    usleep(100000);
  
}
#endif /* SHOW_SPLASH */


/* Load URLs from file. */

static void read_urls(u8* fn) {
  FILE* f = fopen((char*)fn, "r");
  u8    tmp[MAX_URL_LEN];
  u32   loaded = 0;

  if (!f) FATAL("Unable to open '%s'.", fn);

  while (fgets((char*)tmp, MAX_URL_LEN, f)) {
    struct http_request *req;
    u8* url = tmp;
    u8* ptr;
    u32 l;

    while (isspace(*url)) url++;

    /* Check if we're reading a pivots.txt file and grab the URL */
    if(!strncmp((char*)url,"GET ", 4) || !strncmp((char*)url,"POST ", 4)) {
      url += 4;

      /* If the server response code is a 404, than we'll skip the URL
      to avoid wasting time on things that are likely not to exist. */
      if(inl_findstr(url, (u8*)"code=404", MAX_URL_LEN))
        continue;

      ptr = url;
      /* Find the next space to terminate the URL */
      while(ptr && !isspace(*ptr)) ptr++;

      if(!ptr) FATAL("URL parsing failed at line: %s", tmp);

      *ptr = 0;
    /* Else we expect a simple flat file with URLs */
    } else {
      l = strlen((char*)url);
      while (l && isspace(url[l-1])) l--;
      url[l] = 0;
    }

    if (*url == '#' || !*url) continue;

    req = ck_alloc(sizeof(struct http_request));

    if (parse_url(url, req, NULL))
      FATAL("Scan target '%s' in file '%s' is not a valid absolute URL.", url, fn);

    if (!url_allowed_host(req))
      APPEND_FILTER(allow_domains, num_allow_domains,
                    __DFL_ck_strdup(req->host));

    if (!url_allowed(req))
      FATAL("URL '%s' in file '%s' explicitly excluded by -I / -X rules.",
            url, fn);

    maybe_add_pivot(req, NULL, 2);
    destroy_request(req);
    loaded++;

  }

  fclose(f);

  if (!loaded) FATAL("No valid URLs found in '%s'.", fn);

}


/* Main entry point */

int main(int argc, char** argv) {
  s32 opt;
  u32 loop_cnt = 0, purge_age = 0, seed;
  u8 sig_loaded = 0, show_once = 0, no_statistics = 0,
     display_mode = 0, has_fake = 0;
  s32 oindex = 0;
  u8 *wordlist = NULL, *output_dir = NULL;
  u8 *sig_list_strg = NULL;
  u8 *gtimeout_str = NULL;
  u32 gtimeout = 0;

  struct termios term;
  struct timeval tv;
  u64 st_time, en_time;

  signal(SIGINT, ctrlc_handler);
  signal(SIGWINCH, resize_handler);
  signal(SIGPIPE, SIG_IGN);
  SSL_library_init();

/* Options, options, and options */

  static struct option long_options[] = {
    {"auth", required_argument, 0, 'A' },
    {"host", required_argument, 0, 'F' },
    {"cookie", required_argument, 0, 'C' },
    {"reject-cookies", required_argument, 0, 'N' },
    {"header", required_argument, 0, 'H' },
    {"user-agent", required_argument, 0, 'b' },
#ifdef PROXY_SUPPORT
    {"proxy", required_argument, 0, 'J' },
#endif /* PROXY_SUPPORT */
    {"max-depth", required_argument, 0, 'd' },
    {"max-child", required_argument, 0, 'c' },
    {"max-descendants", required_argument, 0, 'x' },
    {"max-requests", required_argument, 0, 'r' },
    {"max-rate", required_argument, 0, 'l'},
    {"probability", required_argument, 0, 'p' },
    {"seed", required_argument, 0, 'q' },
    {"include", required_argument, 0, 'I' },
    {"exclude", required_argument, 0, 'X' },
    {"skip-param", required_argument, 0, 'K' },
    {"skip-forms", no_argument, 0, 'O' },
    {"include-domain", required_argument, 0, 'D' },
    {"ignore-links", no_argument, 0, 'P' },
    {"no-ext-fuzzing", no_argument, 0, 'Y' },
    {"log-mixed-content", no_argument, 0, 'M' },
    {"skip-error-pages", no_argument, 0, 'Z' },
    {"log-external-urls", no_argument, 0, 'U' },
    {"log-cache-mismatches", no_argument, 0, 'E' },
    {"form-value", no_argument, 0, 'T' },
    {"rw-wordlist", required_argument, 0, 'W' },
    {"no-keyword-learning", no_argument, 0, 'L' },
    {"mode", required_argument, 0, 'J' },
    {"wordlist", required_argument, 0, 'S'},
    {"trust-domain", required_argument, 0, 'B' },
    {"max-connections", required_argument, 0, 'g' },
    {"max-host-connections", required_argument, 0, 'm' },
    {"max-fail", required_argument, 0, 'f' },
    {"request-timeout", required_argument, 0, 't' },
    {"network-timeout", required_argument, 0, 'w' },
    {"idle-timeout", required_argument, 0, 'i' },
    {"response-size", required_argument, 0, 's' },
    {"discard-binary", required_argument, 0, 'e' },
    {"output", required_argument, 0, 'o' },
    {"help", no_argument, 0, 'h' },
    {"quiet", no_argument, 0, 'u' },
    {"verbose", no_argument, 0, 'v' },
    {"scan-timeout", required_argument, 0, 'k'},
    {"signatures", required_argument, 0, 'z'},
    {"checks", no_argument, 0, 0},
    {"checks-toggle", required_argument, 0, 0},
    {"no-checks", no_argument, 0, 0},
    {"fast", no_argument, 0, 0},
    {"auth-form", required_argument, 0, 0},
    {"auth-form-target", required_argument, 0, 0},
    {"auth-user", required_argument, 0, 0},
    {"auth-user-field", required_argument, 0, 0},
    {"auth-pass", required_argument, 0, 0},
    {"auth-pass-field", required_argument, 0, 0},
    {"auth-verify-url", required_argument, 0, 0},
    {0, 0, 0, 0 }

  };
  /* Come up with a quasi-decent random seed. */

  gettimeofday(&tv, NULL);
  seed = tv.tv_usec ^ (tv.tv_sec << 16) ^ getpid();

  SAY("skipfish version " VERSION " by <lcamtuf@google.com>\n");

  while ((opt = getopt_long(argc, argv,
          "+A:B:C:D:EF:G:H:I:J:K:LMNOPQR:S:T:UW:X:YZ"
          "b:c:d:ef:g:hi:k:l:m:o:p:q:r:s:t:uvw:x:z:",
          long_options, &oindex)) >= 0)

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

#ifdef PROXY_SUPPORT
      case 'J':  {
          u8* x = (u8*)strchr(optarg, ':');
          if (!x) FATAL("Proxy data must be in 'host:port' form.");
          *(x++) = 0;
          use_proxy = (u8*)optarg;
          use_proxy_port = atoi((char*)x);
          if (!use_proxy_port) FATAL("Incorrect proxy port number.");
          break;
        }
#endif /* PROXY_SUPPORT */

      case 'F': {
          u8* x = (u8*)strchr(optarg, '=');
          u32 fake_addr;
          if (!x) FATAL("Fake mappings must be in 'host=IP' form.");
          *x = 0;
          fake_addr = inet_addr((char*)x + 1);
          if (fake_addr == (u32)-1)
            FATAL("Could not parse IP address '%s'.", x + 1);
          fake_host((u8*)optarg, fake_addr);
          has_fake = 1;
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

      case 'K':
        APPEND_FILTER(skip_params, num_skip_params, optarg);
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

      case 'x':
        max_descendants = atoi(optarg);
        if (!max_descendants) FATAL("Invalid value '%s'.", optarg);
        break;

      case 'p':
        crawl_prob = atoi(optarg);
        if (!crawl_prob) FATAL("Invalid value '%s'.", optarg);
        break;

      case 'W':
        if (wordlist)
          FATAL("Only one -W parameter permitted (use -S to load supplemental dictionaries).");

        if (!strcmp(optarg, "-")) wordlist = (u8*)"/dev/null";
        else wordlist = (u8*)optarg;

        break;

      case 'S':
        load_keywords((u8*)optarg, 1, 0);
        break;

      case 'z':
        load_signatures((u8*)optarg);
        sig_loaded = 1;
        break;

      case 'b':
        if (optarg[0] == 'i') browser_type = BROWSER_MSIE; else
        if (optarg[0] == 'f') browser_type = BROWSER_FFOX; else
        if (optarg[0] == 'p') browser_type = BROWSER_PHONE; else
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

      case 'l':
        max_requests_sec = atof(optarg);
        if (!max_requests_sec) FATAL("Invalid value '%s'.", optarg);
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

      case 'u':
        no_statistics = 1;
        break;

      case 'v':
        verbosity++;
        break;


      case 'e':
        delete_bin = 1;
        break;

      case 'k':
        if (gtimeout_str) FATAL("Multiple -k options not allowed.");
        gtimeout_str = (u8*)optarg;
        break;

      case 'Z':
        no_500_dir = 1;
        break;

      case 0:
        if (!strcmp("checks", long_options[oindex].name ))
          display_injection_checks();
        if (!strcmp("checks-toggle", long_options[oindex].name ))
          toggle_injection_checks((u8*)optarg, 1, 1);
        if (!strcmp("no-checks", long_options[oindex].name ))
          no_checks = 1;
        if (!strcmp("signatures", long_options[oindex].name ))
          load_signatures((u8*)optarg);
        if(!strcmp("fast", long_options[oindex].name ))
          toggle_injection_checks((u8*)"2,4,5,13,14,15,16", 0, 0);
        if (!strcmp("auth-form", long_options[oindex].name ))
          auth_form = (u8*)optarg;
        if (!strcmp("auth-user", long_options[oindex].name ))
          auth_user = (u8*)optarg;
        if (!strcmp("auth-pass", long_options[oindex].name ))
          auth_pass = (u8*)optarg;
        if (!strcmp("auth-pass-field", long_options[oindex].name ))
          auth_pass_field = (u8*)optarg;
        if (!strcmp("auth-user-field", long_options[oindex].name ))
          auth_user_field = (u8*)optarg;
        if (!strcmp("auth-form-target", long_options[oindex].name ))
          auth_form_target = (u8*)optarg;
        if (!strcmp("auth-verify-url", long_options[oindex].name ))
          auth_verify_url = (u8*)optarg;

        break;

      default:
        usage(argv[0]);

  }

#ifdef PROXY_SUPPORT
  if (has_fake && use_proxy)
    FATAL("-F and -J should not be used together.");
#endif /* PROXY_SUPPORT */

  if (access(ASSETS_DIR "/index.html", R_OK))
    PFATAL("Unable to access '%s/index.html' - wrong directory?", ASSETS_DIR);

  srandom(seed);

  if (optind == argc)
    FATAL("Scan target not specified (try -h for help).");

  if (!output_dir)
    FATAL("Output directory not specified (try -h for help).");

  if(verbosity && !no_statistics && isatty(2))
    FATAL("Please use -v in combination with the -u flag or, "
          "run skipfish while redirecting stderr to a file. ");


  if (resp_tmout < rw_tmout)
    resp_tmout = rw_tmout;

  if (max_connections < max_conn_host)
    max_connections = max_conn_host;

  /* Parse the timeout string - format h:m:s */
  if (gtimeout_str) {
    int i = 0;
    int m[3] = { 1, 60, 3600 };

    u8* tok = (u8*)strtok((char*)gtimeout_str, ":");

    while(tok && i <= 2) {
      gtimeout += atoi((char*)tok) * m[i];
      tok = (u8*)strtok(NULL, ":");
      i++;
    }

    if(!gtimeout)
      FATAL("Wrong timeout format, please use h:m:s (hours, minutes, seconds)");
    DEBUG("* Scan timeout is set to %d seconds\n", gtimeout);
  }


  if (!wordlist) {
    wordlist = (u8*)"/dev/null";
    DEBUG("* No wordlist specified with -W: defaulting to /dev/null\n");
  }

  /* If no signature files have been specified via command-line: load
     the default file */
  if (!sig_loaded)
    load_signatures((u8*)SIG_FILE);

  load_keywords(wordlist, 0, purge_age);

  /* Load the signatures list for the matching */
  if (sig_list_strg) load_signatures(sig_list_strg);

  /* Try to authenticate when the auth_user and auth_pass fields are set. */
  if (auth_user && auth_pass) {
    authenticate();

    while (next_from_queue()) {
      usleep(1000);
    }

    switch (auth_state) {
      case ASTATE_DONE:
        DEBUGC(L1, "*- Authentication succeeded!\n");
        break;

      default:
        DEBUG("Auth state: %d\n", auth_state);
        FATAL("Authentication failed (use -uv for more info)\n");
        break;
    }
  }

  /* Schedule all URLs in the command line for scanning. */

  while (optind < argc) {
    struct http_request *req;

    /* Support @ notation for reading URL lists from files. */

    if (argv[optind][0] == '@') {
      read_urls((u8*)argv[optind++] + 1);
      continue;
    }

    req = ck_alloc(sizeof(struct http_request));

    if (parse_url((u8*)argv[optind], req, NULL))
      FATAL("Scan target '%s' is not a valid absolute URL.", argv[optind]);

    if (!url_allowed_host(req))
      APPEND_FILTER(allow_domains, num_allow_domains,
                    __DFL_ck_strdup(req->host));

    if (!url_allowed(req))
      FATAL("URL '%s' explicitly excluded by -I / -X rules.", argv[optind]);

    maybe_add_pivot(req, NULL, 2);
    destroy_request(req);

    optind++;
  }

  /* Char-by char stdin. */

  tcgetattr(0, &term);
  term.c_lflag &= ~ICANON;
  tcsetattr(0, TCSANOW, &term);
  fcntl(0, F_SETFL, O_NONBLOCK);

  gettimeofday(&tv, NULL);
  st_time = tv.tv_sec * 1000LL + tv.tv_usec / 1000;

#ifdef SHOW_SPLASH
  if (!no_statistics) splash_screen();
#endif /* SHOW_SPLASH */

  if (!no_statistics) SAY("\x1b[H\x1b[J");
  else SAY(cLGN "[*] " cBRI "Scan in progress, please stay tuned...\n");

  u64 refresh_time = 0;

  /* Enter the crawler loop */
  while ((next_from_queue() && !stop_soon) || (!show_once++)) {

    u8 keybuf[8];

    u64 end_time;
    u64 run_time;
    struct timeval tv_tmp;

    gettimeofday(&tv_tmp, NULL);
    end_time = tv_tmp.tv_sec * 1000LL + tv_tmp.tv_usec / 1000;

    run_time = end_time - st_time;
    if (gtimeout > 0 && run_time && run_time/1000 > gtimeout) {
      DEBUG("* Stopping scan due to timeout\n");
      stop_soon = 1;
    }

    req_sec = (req_count - queue_cur / 1.15) * 1000 / (run_time + 1);

    if (no_statistics || ((loop_cnt++ % 100) && !show_once && idle == 0))
      continue;

    if (end_time > refresh_time) {
      refresh_time = (end_time + 10);

      if (clear_screen) {
        SAY("\x1b[H\x1b[2J");
        clear_screen = 0;
      }

      SAY(cYEL "\x1b[H"
          "skipfish version " VERSION " by lcamtuf@google.com\n\n"
           cBRI "  -" cPIN " %s " cBRI "-\n\n" cNOR,
           allow_domains[0]);


      if (!display_mode) {
        http_stats(st_time);
        SAY("\n");
        database_stats();
      } else {
        http_req_list();
      }

      SAY("        \r");
    }

    if (fread(keybuf, 1, sizeof(keybuf), stdin) > 0) {
      display_mode ^= 1;
      clear_screen = 1;
    }
  }

  gettimeofday(&tv, NULL);
  en_time = tv.tv_sec * 1000LL + tv.tv_usec / 1000;

  SAY("\n");

  if (stop_soon)
    SAY(cYEL "[!] " cBRI "Scan aborted by user, bailing out!" cNOR "\n");

  term.c_lflag |= ICANON;
  tcsetattr(0, TCSANOW, &term);
  fcntl(0, F_SETFL, O_SYNC);

  save_keywords((u8*)wordlist);

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
    destroy_signature_lists();
    destroy_http();
    destroy_signatures();
    __TRK_report();
  }
#endif /* DEBUG_ALLOCATOR */

  fflush(0);

  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();

  return 0;

}
