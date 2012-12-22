/*
   skipfish - option and config parsing
   ------------------------------------

   Author: Niels Heinen <heinenn@google.com>

   Copyright 2012 by Google Inc. All Rights Reserved.

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

#ifndef __OPTIONS_H
#define __OPTIONS_H

#include <unistd.h>
#include <getopt.h>

/* Config file reader function */

int read_config_file(const char *filename, int *_argc, char ***_argv);

/* Config parsing cleanup function that releases memory */

void destroy_config();

/* Long flags */

#ifdef _VIA_OPTIONS_C

#define MAX_LINE_LEN 2048
#define MAX_ARGS 100

#else

/* The option string for getopt_long */

#define OPT_STRING "+A:B:C:D:EF:G:H:I:J:K:LMNOPQR:S:T:UW:X:YZ" \
                   "b:c:d:ef:g:hi:k:l:m:o:p:q:r:s:t:uvw:x:z:"

struct option long_options[] = {
    {"auth", required_argument, 0, 'A' },
    {"host", required_argument, 0, 'F' },
    {"cookie", required_argument, 0, 'C' },
    {"reject-cookies", no_argument, 0, 'N' },
    {"header", required_argument, 0, 'H' },
    {"user-agent", required_argument, 0, 'b' },
#ifdef PROXY_SUPPORT
    {"proxy", required_argument, 0, 'J' },
#endif /* PROXY_SUPPORT */
    {"max-crawl-depth", required_argument, 0, 'd' },
    {"max-crawl-child", required_argument, 0, 'c' },
    {"max-crawl-descendants", required_argument, 0, 'x' },
    {"max-request-total", required_argument, 0, 'r' },
    {"max-request-rate", required_argument, 0, 'l'},
    {"crawl-probability", required_argument, 0, 'p' },
    {"seed", required_argument, 0, 'q' },
    {"include-string", required_argument, 0, 'I' },
    {"exclude-string", required_argument, 0, 'X' },
    {"skip-parameter", required_argument, 0, 'K' },
    {"no-form-submits", no_argument, 0, 'O' },
    {"include-domain", required_argument, 0, 'D' },
    {"no-html-parsing", no_argument, 0, 'P' },
    {"no-extension-brute", no_argument, 0, 'Y' },
    {"log-mixed-content", no_argument, 0, 'M' },
    {"skip-error-pages", no_argument, 0, 'Z' },
    {"log-external-urls", no_argument, 0, 'U' },
    {"log-cache-mismatches", no_argument, 0, 'E' },
    {"form-value", required_argument, 0, 'T' },
    {"rw-wordlist", required_argument, 0, 'W' },
    {"no-keyword-learning", no_argument, 0, 'L' },
    {"wordlist", required_argument, 0, 'S'},
    {"trust-domain", required_argument, 0, 'B' },
    {"max-connections", required_argument, 0, 'g' },
    {"max-host-connections", required_argument, 0, 'm' },
    {"max-failed-requests", required_argument, 0, 'f' },
    {"request-timeout", required_argument, 0, 't' },
    {"network-timeout", required_argument, 0, 'w' },
    {"idle-timeout", required_argument, 0, 'i' },
    {"response-size", required_argument, 0, 's' },
    {"discard-binary", no_argument, 0, 'e' },
    {"output", required_argument, 0, 'o' },
    {"help", no_argument, 0, 'h' },
    {"quiet", no_argument, 0, 'u' },
    {"verbose", no_argument, 0, 'v' },
    {"scan-timeout", required_argument, 0, 'k'},
    {"signatures", required_argument, 0, 'z'},
    {"checks", no_argument, 0, 0},
    {"checks-toggle", required_argument, 0, 0},
    {"no-injection-tests", no_argument, 0, 0},
    {"fast", no_argument, 0, 0},
    {"flush-to-disk", no_argument, 0, 0},
    {"config", required_argument, 0, 0},
    {"auth-form", required_argument, 0, 0},
    {"auth-form-target", required_argument, 0, 0},
    {"auth-user", required_argument, 0, 0},
    {"auth-user-field", required_argument, 0, 0},
    {"auth-pass", required_argument, 0, 0},
    {"auth-pass-field", required_argument, 0, 0},
    {"auth-verify-url", required_argument, 0, 0},
    {0, 0, 0, 0 }

};

#endif /* !__VIA_OPTIONS_C */

#endif /* __OPTIONS_H */
