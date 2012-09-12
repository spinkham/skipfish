/*
   skipfish - crawler state machine
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

#ifndef _HAVE_CRAWLER_H

#include "types.h"
#include "http_client.h"
#include "database.h"

/* Function called during startup to build the test/check structure */

void replace_slash(struct http_request* req, u8* new_val);
void handle_error(struct http_request* req, struct http_response* res, u8* desc, u8 stop);
void inject_done(struct pivot_desc*);
void destroy_misc_data(struct pivot_desc* pv, struct http_request* self);
struct pivot_desc* dir_parent(struct pivot_desc* pv);
void authenticate();

/* Internal helper macros: */

#define TPAR(_req) ((_req)->par.v[(_req)->pivot->fuzz_par])

#define SET_VECTOR(_state, _req, _str) do { \
    if (_state == PSTATE_CHILD_INJECT) { \
      replace_slash((_req), (u8*)_str); \
    } else { \
      ck_free(TPAR(_req)); \
      TPAR(_req) = ck_strdup((u8*)_str); \
    } \
  } while (0)

#define APPEND_VECTOR(_state, _req, _str) do { \
    if (_state == PSTATE_CHILD_INJECT) { \
      replace_slash((_req), (u8*)_str); \
    } else { \
      u8* _n = ck_alloc(strlen((char*)TPAR(_req)) + strlen((char*)_str) + 1); \
      sprintf((char*)_n, "%s%s", TPAR(_req), _str); \
      ck_free(TPAR(_req)); \
      TPAR(_req) = _n; \
    } \
  } while (0)

/* Classifies a response, with a special handling of "unavailable" and
   "gateway timeout" codes. */

#define FETCH_FAIL(_res) ((_res)->state != STATE_OK || (_res)->code == 503 || \
  (_res)->code == 504)


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

u8 unknown_retrieve_check(struct http_request* req, struct http_response* res);

/* Asynchronous request callback for the initial PSTATE_FETCH request of
   PIVOT_FILE resources. */

u8 file_retrieve_check(struct http_request* req, struct http_response* res);

/* Asynchronous request callback for the initial PSTATE_FETCH request of
   PIVOT_DIR resources. */

u8 dir_retrieve_check(struct http_request* req, struct http_response* res);

/* Initializes the crawl of try_list items for a pivot point (if any still
   not crawled). */

void param_trylist_start(struct pivot_desc* pv);

/* Adds new name=value to form hints list. */

void add_form_hint(u8* name, u8* value);

/* Macros to access various useful pivot points: */

#define RPAR(_req) ((_req)->pivot->parent)
#define RPREQ(_req) ((_req)->pivot->req)
#define RPRES(_req) ((_req)->pivot->res)
#define MREQ(_x) (req->pivot->misc_req[_x])
#define MRES(_x) (req->pivot->misc_res[_x])


/* Debugging instrumentation for callbacks and callback helpers: */

#ifdef LOG_STDERR

#define DEBUG_CALLBACK(_req, _res) do { \
    u8* _url = serialize_path(_req, 1, 1); \
    DEBUG("* %s: URL %s (%u, len %u)\n", __FUNCTION__, _url, (_res) ? \
          (_res)->code : 0, (_res) ? (_res)->pay_len : 0); \
    ck_free(_url); \
  } while (0)

#define DEBUG_MISC_CALLBACK(_req, _res) do { \
  int i; \
  for (i = 0; i < req->pivot->misc_cnt; i++) \
    DEBUG_CALLBACK(MREQ(i), MRES(i)); \
  } while (0)

#define DEBUG_PIVOT(_text, _pv) do { \
    u8* _url = serialize_path((_pv)->req, 1, 1); \
    DEBUG("* %s: %s\n", _text, _url); \
    ck_free(_url); \
  } while (0)

#define DEBUG_STATE_CALLBACK(_req, _state, _type)  do { \
    u8* _url = serialize_path(_req, 1, 1); \
    DEBUG("* %s::%s: URL %s (running: %s)\n", __FUNCTION__, _state, _url, \
          _type ? "checks" : "tests"); \
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
#define DEBUG_MISC_CALLBACK(_req, _res)
#define DEBUG_STATE_CALLBACK(_req, _res, _cb)
#define DEBUG_HELPER(_pv)
#define DEBUG_PIVOT(_text, _pv)

#endif /* ^LOG_STDERR */

#endif /* !_HAVE_CRAWLER_H */
