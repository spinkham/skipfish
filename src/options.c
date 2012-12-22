/*
   skipfish - Config parsing
   ----------------------------------------

   Author: Niels Heinen <heinenn@google.com>,

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

#include <ctype.h>

#define _VIA_OPTIONS_C

#include "options.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "string-inl.h"

u8 **fargv;
u32 fargc = 0;

/* This function reads the configuration file turns them into
   flags that are given to getopt_long. */

int read_config_file(const char *filename, int *_argc, char ***_argv) {

  FILE *fh;
  char line[MAX_LINE_LEN + 1];
  char *val, *ptr;
  u8 *tmp;
  u32 idx, i;

  APPEND_STRING(fargv, fargc, ck_strdup((u8*)*_argv[0]));

  fh = fopen(filename, "r");
  if (!fh) PFATAL("Unable to read config from: %s", filename);

  while (!feof(fh) && fargc < MAX_ARGS && fgets(line, MAX_LINE_LEN, fh)) {

    /* Skip comments and empty lines */
    if (line[0] == '\n' || line[0] == '\r' || line[0] == '#')
      continue;

    /* NULL terminate the key */
    idx = strcspn(line, " \t=");
    if (idx == strlen(line))
      FATAL("Config key error at line: %s", line);
    line[idx] = '\0';

    /* Find the beginning of the value. */
    val = line + (idx + 1);
    idx = strspn(val, " \t=");
    if (idx == strlen(val))
      FATAL("Config value error at line: %s", line);
    val = val + idx;

    /* Trim the unwanted characters from the value */
    ptr = val + (strlen(val) - 1);
    while(*ptr && *ptr < 0x21) {
      *ptr = 0;
      ptr--;
    }

    /* Done! Now we have a key/value pair. If the flag is set to 'false'
       we will disregard this line. If the value is 'true', we will set
       the flag without a value. In any other case, we will set the flag
       and value */

    if (val[0] == '\0')
      FATAL("Empty value in config line: %s", line);

    if (strcasecmp("false", val) == 0)
      continue;

    tmp = ck_alloc(strlen(line) + 3);
    sprintf((char*)tmp, "--%s", line);

    APPEND_STRING(fargv, fargc, tmp);
    if (strncasecmp("true", val, 3) != 0)
      APPEND_STRING(fargv, fargc, ck_strdup((u8*)val));

  }

  /* Copy arguments from command line into our array */
  for (i=1; i<*_argc && fargc < MAX_ARGS; ++i)
    APPEND_STRING(fargv, fargc, ck_strdup((u8*)(*_argv)[i]));

  /* Replace original flags */
  *_argc = fargc;
  *_argv = (char **)fargv;

  fclose(fh);
  return 0;
}

/* Helper function to cleanup memory */

void destroy_config() {

  if (fargc == 0) return;

  while (fargc-- != 0)
    ck_free(fargv[fargc]);
  ck_free(fargv);

}
