/*
   skipfish - crawler state machine
   --------------------------------

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

#ifndef _HAVE_CRAWLER_H

#include "types.h"
#include "http_client.h"
#include "database.h"

extern u32 crawl_prob;          /* Crawl probability (1-100%)  */
extern u8  no_parse,            /* Disable HTML link detection */
           warn_mixed,          /* Warn on mixed content?      */
           no_fuzz_ext,         /* Don't fuzz ext in dirs?     */
           no_500_dir,          /* Don't assume dirs on 500    */
           delete_bin,          /* Don't keep binary responses */
           log_ext_urls;        /* Log external URLs?          */

/* Provisional debugging callback. */

u8 show_response(struct http_request* req, struct http_response* res);

/* Asynchronous request callback for the initial PSTATE_FETCH request of
   PIVOT_UNKNOWN resources. */

u8 fetch_unknown_callback(struct http_request* req, struct http_response* res);

/* Asynchronous request callback for the initial PSTATE_FETCH request of
   PIVOT_FILE resources. */

u8 fetch_file_callback(struct http_request* req, struct http_response* res);

/* Asynchronous request callback for the initial PSTATE_FETCH request of
   PIVOT_DIR resources. */

u8 fetch_dir_callback(struct http_request* req, struct http_response* res);

/* Initializes the crawl of try_list items for a pivot point (if any still
   not crawled). */

void crawl_par_trylist_init(struct pivot_desc* pv);

/* Adds new name=value to form hints list. */

void add_form_hint(u8* name, u8* value);

/* Macros to access various useful pivot points: */

#define MREQ(_x) (req->pivot->misc_req[_x])
#define MRES(_x) (req->pivot->misc_res[_x])
#define RPAR(_req) ((_req)->pivot->parent)
#define RPREQ(_req) ((_req)->pivot->req)
#define RPRES(_req) ((_req)->pivot->res)

/* Debugging instrumentation for callbacks and callback helpers: */

#ifdef LOG_STDERR

#define DEBUG_CALLBACK(_req, _res) do { \
    u8* _url = serialize_path(_req, 1, 1); \
    DEBUG("* %s: URL %s (%u, len %u)\n", __FUNCTION__, _url, (_res) ? \
          (_res)->code : 0, (_res) ? (_res)->pay_len : 0); \
    ck_free(_url); \
  } while (0)

#define DEBUG_HELPER(_pv) do { \
    u8* _url = serialize_path((_pv)->req, 1, 1); \
    DEBUG("* %s: URL %s (%u, len %u)\n", __FUNCTION__, _url, (_pv)->res ? \
          (_pv)->res->code : 0, (_pv)->res ? (_pv)->res->pay_len : 0); \
    ck_free(_url); \
  } while (0)

#else

#define DEBUG_CALLBACK(_req, _res)
#define DEBUG_HELPER(_pv)

#endif /* ^LOG_STDERR */

#endif /* !_HAVE_CRAWLER_H */
