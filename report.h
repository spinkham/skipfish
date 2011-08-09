/*
   skipfish - post-processing and reporting
   ----------------------------------------

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

#ifndef _HAVE_REPORT_H

#include "types.h"

extern u8 suppress_dupes;

/* Writes report to index.html in the current directory. Will create
   subdirectories, helper files, etc. */

void write_report(u8* out_dir, u64 scan_time, u32 seed);

/* Destroys all signatures created for pivot and issue clustering purposes. */

void destroy_signatures(void);

#endif /* !_HAVE_REPORT_H */
