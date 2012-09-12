/*
   skipfish - configurable settings
   --------------------------------

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

#ifndef _HAVE_CONFIG_H
#define _HAVE_CONFIG_H

#define USE_COLOR               1       /* Use terminal colors             */

#define SHOW_SPLASH             1       /* Annoy user with a splash screen */

/* Define this to enable experimental HTTP proxy support, through the -J
   option in the command line. This mode will not work as expected for
   HTTPS requests at this time - sorry. */

// #define PROXY_SUPPORT           1

/* Default paths to runtime files: */

#define ASSETS_DIR              "assets"

/* Default signature file */
#define SIG_FILE                "signatures/signatures.conf"

/* Various default settings for HTTP client (cmdline override): */

#define MAX_CONNECTIONS         40      /* Simultaneous connection cap     */
#define MAX_CONN_HOST           10      /* Per-host connction cap          */
#define MAX_REQUESTS            1e8     /* Total request count cap         */
#define MAX_REQUESTS_SEC        0.0     /* Max requests per second         */
#define MAX_FAIL                100     /* Max consecutive failed requests */
#define RW_TMOUT                10      /* Individual network R/W timeout  */
#define RESP_TMOUT              20      /* Total request time limit        */
#define IDLE_TMOUT              10      /* Connection tear down threshold  */
#define SIZE_LIMIT              400000  /* Response size cap               */
#define MAX_GUESSES             256     /* Guess-based wordlist size limit */

/* HTTP client constants: */

#define MAX_URL_LEN             2048    /* Maximum length of an URL        */
#define MAX_DNS_LEN             255     /* Maximum length of a host name   */
#define READ_CHUNK              4096    /* Read buffer size                */

/* Define this to use FILO, rather than FIFO, scheduling for new requests.
   FILO ensures a more uniform distribution of requests when fuzzing multiple
   directories at once, but may reduce the odds of spotting some stored
   XSSes, and increase memory usage a bit. */

// #define QUEUE_FILO              1

/* Dummy file to upload to the server where possible. */

#define DUMMY_EXT               "gif"
#define DUMMY_FILE              "GIF89a,\x01<html>"
#define DUMMY_MIME              "image/gif"

/* Allocator settings: */

#define MAX_ALLOC       0x50000000      /* Refuse larger allocations.      */

/* Detect use-after-free, at the expense of some performance cost: */

#ifdef DEBUG_ALLOCATOR
#define CHECK_UAF           1
#endif /* DEBUG_ALLOCATOR */

/* Configurable settings for crawl database (cmdline override): */

#define MAX_DEPTH       16              /* Maximum crawl tree depth        */
#define MAX_CHILDREN    512             /* Maximum children per tree node  */
#define MAX_DESCENDANTS 8192            /* Maximum descendants per branch  */
#define MAX_SAMENAME    3               /* Identically named path nodes    */

/* Crawl / analysis constants: */

#define MAX_WORD        64              /* Maximum wordlist item length    */
#define GUESS_PROB      50              /* Guess word addition probability */
#define WORD_HASH       256             /* Hash table for wordlists        */
#define SNIFF_LEN       1024            /* MIME sniffing buffer size       */
#define MAX_SAMPLES     1024            /* Max issue / MIME samples        */
#define MAX_JS_WHITE    16              /* Maximum JS wspaces before id    */

/* Page fingerprinting constants: */

#define FP_SIZE         10              /* Page fingerprint size           */
#define FP_MAX_LEN      15              /* Maximum word length to count    */
#define FP_T_REL        5               /* Relative matching tolerance (%) */
#define FP_T_ABS        6               /* Absolute matching tolerance     */
#define FP_B_FAIL       3               /* Max number of failed buckets    */

#define BH_CHECKS       15              /* Page verification check count   */

/* Crawler / probe constants: */

#define BOGUS_FILE     "sfi9876"        /* Name that should not exist      */
#define BOGUS_EXT      "sfish"          /* Nonsensical file extension      */
#define BOGUS_PARAM    "9876sfi"        /* Meaningless parameter           */
#define MAX_404        4                /* Maximum number of 404 sigs      */
#define PAR_MAX_DIGITS 6                /* Max digits in a fuzzable int    */
#define PAR_INT_FUZZ   100              /* Fuzz by + / - this much         */

#ifdef QUEUE_FILO
#define DICT_BATCH     100              /* Brute-force queue block         */
#else
#define DICT_BATCH     300              /* Brute-force queue block         */
#endif /* ^QUEUE_FILO */

/* Single query for IPS detection - Evil Query of Doom (tm). */

#define IPS_TEST \
  "?_test1=c:\\windows\\system32\\cmd.exe" \
  "&_test2=/etc/passwd" \
  "&_test3=|/bin/sh" \
  "&_test4=(SELECT * FROM nonexistent) --" \
  "&_test5=>/no/such/file" \
  "&_test6=<script>alert(1)</script>" \
  "&_test7=javascript:alert(1)"

/* A benign query with a similar character set to compare with EQoD. */

#define IPS_SAFE \
  "?_test1=ccddeeeimmnossstwwxy.:\\\\\\" \
  "&_test2=acdepsstw//" \
  "&_test3=bhins//" \
  "&_test4=CEEFLMORSTeeinnnosttx-*" \
  "&_test5=cefhilnosu///" \
  "&_test6=acceiilpprrrssttt1)(" \
  "&_test7=aaaceijlprrsttv1):("

/* XSRF token detector settings: */

#define XSRF_B16_MIN    8               /* Minimum base10/16 token length  */
#define XSRF_B16_MAX    45              /* Maximum base10/16 token length  */
#define XSRF_B16_NUM    2               /* ...minimum digit count          */
#define XSRF_B64_MIN    6               /* Minimum base32/64 token length  */
#define XSRF_B64_MAX    32              /* Maximum base32/64 token length  */
#define XSRF_B64_NUM    1               /* ...minimum digit count &&       */
#define XSRF_B64_CASE   2               /* ...minimum uppercase count      */
#define XSRF_B64_NUM2   3               /* ...digit count override         */
#define XSRF_B64_SLASH  2               /* ...maximum slash count          */

#ifdef _VIA_CRAWLER_C

/* The URL and string we use in the RFI test */

#ifdef RFI_SUPPORT
#define RFI_HOST   "http://www.google.com/humans.txt#foo="
#define RFI_STRING "we can shake a stick"
#endif

#endif /* _VIA_CRAWLER_C */

#ifdef _VIA_DATABASE_C

/* Domains we always trust (identical to -B options). These entries do not
   generate cross-domain content inclusion warnings. NULL-terminated. */

static const char* always_trust_domains[] = {
  ".google-analytics.com",
  ".googleapis.com",
  ".googleadservices.com",
  ".googlesyndication.com",
  "www.w3.org",
  0
};

#endif /* _VIA_DATABASE_C */

#ifdef _VIA_ANALYSIS_C

/* NULL-terminated list of JSON-like response prefixes we consider to
   be sufficiently safe against cross-site script inclusion (courtesy
   ratproxy). */

static const char* json_safe[] = {
  "while(1);",                          /* Parser looping                  */
  "while (1);",                         /* ...                             */
  "while(true);",                       /* ...                             */
  "while (true);",                      /* ...                             */
  "&&&",                                /* Parser breaking                 */
  "//OK[",                              /* Line commenting                 */
  "{\"",                                /* Serialized object               */
  "{{\"",                               /* Serialized object               */
  "throw 1; <",                         /* Magical combo                   */
  ")]}'",                               /* Recommended magic               */
  0
};

/* NULL-terminated list of known valid charsets. Charsets not on the list are
   considered dangerous (as they may trigger charset sniffing).

   Note that many common misspellings, such as "utf8", are not valid and NOT
   RECOGNIZED by browsers, leading to content sniffing. Do not add them here.

   Also note that SF does not support encoding not compatible with US ASCII
   transport (e.g., UTF-16, UTF-32). Lastly, variable-length encodings
   other than utf-8 may have character consumption issues that are not
   tested for at this point. */

static const char* valid_charsets[] = {
  "utf-8",                              /* Valid 8-bit safe Unicode       */
  "iso8859-1",                          /* Western Europe                 */
  "iso8859-2",                          /* Central Europe                 */
  "iso8859-15",                         /* New flavor of ISO8859-1        */
  "iso8859-16",                         /* New flavor of ISO8859-2        */
  "iso-8859-1",                         /* Browser-supported misspellings */
  "iso-8859-2",                         /* -                              */
  "iso-8859-15",                        /* -                              */
  "iso-8859-16",                        /* -                              */
  "windows-1252",                       /* Microsoft's Western Europe     */
  "windows-1250",                       /* Microsoft's Central Europe     */
  "us-ascii",                           /* Old school but generally safe  */
  "koi8-r",                             /* 8-bit and US ASCII compatible  */
  0
};


/* Default form auto-fill rules - used to pair up form fields with fun
   values! Do not attempt security attacks here, though - this is to maximize
   crawl coverage, not to exploit anything. The last item must have a name
   of NULL, and the value will be used as a default option when no other
   matches found. */

static const char* form_suggestion[][2] = {

  { "phone"    , "6505550100" },        /* Reserved */
  { "zip"      , "94043" },
  { "first"    , "John"  },
  { "last"     , "Smith" },
  { "name"     , "Smith" },
  { "mail"     , "skipfish@example.com" },
  { "street"   , "1600 Amphitheatre Pkwy" },
  { "city"     , "Mountain View" },
  { "state"    , "CA" },
  { "country"  , "US" },
  { "language" , "en" },
  { "company"  , "ACME" },
  { "search"   , "skipfish" },
  { "login"    , "skipfish" },
  { "user"     , "skipfish" },
  { "nick"     , "skipfish" },
  { "pass"     , "skipfish" },
  { "pwd"      , "skipfish" },
  { "year"     , "2010" },
  { "card"     , "4111111111111111" }, /* Reserved */
  { "code"     , "000" },
  { "cvv"      , "000" },
  { "expir"    , "1212" },
  { "ssn"      , "987654320" },        /* Reserved */
  { "url"      , "http://example.com/?sfish_form_test" },
  { "site"     , "http://example.com/?sfish_form_test" },
  { "domain"   , "example.com" },
  { "search"   , "a" },
  { "comment"  , "skipfish" },
  { "desc"     , "skipfish" },
  { "title"    , "skipfish" },
  { "subject"  , "skipfish" },
  { "message"  , "skipfish" },
  { NULL       , "1" }

};

#endif /* _VIA_ANALYSIS_C */

#endif /* ! _HAVE_CONFIG_H */
