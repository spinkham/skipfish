/*

   skipfish - debugging and messaging macros
   -----------------------------------------

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

#ifndef _HAVE_DEBUG_H
#define _HAVE_DEBUG_H

#include <stdio.h>
#include "config.h"

#ifdef USE_COLOR
#  define cBLK "\x1b[0;30m"
#  define cRED "\x1b[0;31m"
#  define cGRN "\x1b[0;32m"
#  define cBRN "\x1b[0;33m"
#  define cBLU "\x1b[0;34m"
#  define cMGN "\x1b[0;35m"
#  define cCYA "\x1b[0;36m"
#  define cNOR "\x1b[0;37m"
#  define cGRA "\x1b[1;30m"
#  define cLRD "\x1b[1;31m"
#  define cLGN "\x1b[1;32m"
#  define cYEL "\x1b[1;33m"
#  define cLBL "\x1b[1;34m"
#  define cPIN "\x1b[1;35m"
#  define cLCY "\x1b[1;36m"
#  define cBRI "\x1b[1;37m"
#  define cRST "\x1b[0m"
#else
#  define cBLK ""
#  define cRED ""
#  define cGRN ""
#  define cBRN ""
#  define cBLU ""
#  define cMGN ""
#  define cCYA ""
#  define cNOR ""
#  define cGRA ""
#  define cLRD ""
#  define cLGN ""
#  define cYEL ""
#  define cLBL ""
#  define cPIN ""
#  define cLCY ""
#  define cBRI ""
#  define cRST ""
#endif /* ^USE_COLOR */

#ifdef LOG_STDERR
#  define DEBUG(x...) fprintf(stderr,x)
#else
#  define DEBUG(x...)
#endif /* ^LOG_STDERR */

#define F_DEBUG(x...) fprintf(stderr,x)
#define SAY(x...)   printf(x)

#define L1 1       /* Informative, one line messages     */
#define L2 2       /* Expand the above, dump reqs, resps */
#define L3 3       /* todo(heinenn) do we need this..    */

#ifdef LOG_STDERR
  #define DEBUGC(_l, x...) DEBUG(x)
#else
  #define DEBUGC(_l, x...) do { \
    if(_l <= verbosity) { \
      fprintf(stderr, x); \
    } \
  } while (0)
#endif /* LOG_STDERR */


#define WARN(x...) do { \
    F_DEBUG(cYEL "[!] WARNING: " cBRI x); \
    F_DEBUG(cRST "\n"); \
  } while (0)

#define FATAL(x...) do { \
    F_DEBUG(cLRD "[-] PROGRAM ABORT : " cBRI x); \
    F_DEBUG(cLRD "\n    Stop location : " cNOR "%s(), %s:%u\n" cRST, \
            __FUNCTION__, __FILE__, __LINE__); \
    exit(1); \
  } while (0)

#define ABORT(x...) do { \
    F_DEBUG(cLRD "[-] PROGRAM ABORT : " cBRI x); \
    F_DEBUG(cLRD "\n    Stop location : " cNOR "%s(), %s:%u\n" cRST, \
            __FUNCTION__, __FILE__, __LINE__); \
    abort(); \
  } while (0)

#define PFATAL(x...) do { \
    F_DEBUG(cLRD "[-]  SYSTEM ERROR : " cBRI x); \
    F_DEBUG(cLRD "\n    Stop location : " cNOR "%s(), %s:%u\n", \
            __FUNCTION__, __FILE__, __LINE__); \
    perror(cLRD "       OS message " cNOR); \
    F_DEBUG(cRST); \
    exit(1); \
  } while (0)


#endif /* ! _HAVE_DEBUG_H */
