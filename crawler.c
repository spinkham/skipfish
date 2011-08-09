/*
   skipfish - crawler state machine
   --------------------------------

   Includes dictionary and security injection logic.

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

#define _VIA_CRAWLER_C

#include "debug.h"
#include "config.h"
#include "types.h"
#include "http_client.h"
#include "database.h"
#include "crawler.h"
#include "analysis.h"

u32 crawl_prob = 100;    /* Crawl probability (1-100%)     */
u8  no_fuzz_ext;         /* Don't fuzz extensions for dirs */
u8  no_500_dir;          /* Don't crawl 500 directories    */
u8  delete_bin;          /* Don't keep binary responses    */

/*

  *************************
  **** GENERAL HELPERS ****
  *************************

  Assorted functions used by all the crawl callbacks for manipulating
  requests, parsing responses, etc.

 */


/* Classifies a response, with a special handling of "unavailable" and
   "gateway timeout" codes. */

#define FETCH_FAIL(_res) ((_res)->state != STATE_OK || (_res)->code == 503 || \
  (_res)->code == 504)


/* Dumps request, response (for debugging only). */

u8 show_response(struct http_request* req, struct http_response* res) {

  dump_http_request(req);

  if (FETCH_FAIL(res)) {
    SAY("^^^ REQUEST SHOWN ABOVE CAUSED ERROR: %d ^^^\n", res->state);
    return 0;
  }

  dump_http_response(res);

  return 0; /* Do not keep req/res */

}


/* Strips trailing / from a directory request, optionally replaces it with
   a new value. */

static void replace_slash(struct http_request* req, u8* new_val) {
  u32 i;

  for (i=0;i<req->par.c;i++)
    if (req->par.t[i] == PARAM_PATH && !req->par.n[i] && !req->par.v[i][0]) {
      if (new_val) {
        ck_free(req->par.v[i]);
        req->par.v[i] = ck_strdup(new_val);
      } else req->par.t[i] = PARAM_NONE;
      return;
    }

  /* Could not find a slash segment - create a new segment instead. */

  set_value(PARAM_PATH, 0, new_val, -1, &req->par);

}


/* Releases children for crawling (called once parent node had 404, IPS
   probes done, etc). Note that non-directories might have locked
   children too. */

static void unlock_children(struct pivot_desc* pv) {
  u32 i;

  DEBUG_HELPER(pv);

  for (i=0;i<pv->child_cnt;i++)
    if (pv->child[i]->state == PSTATE_PENDING) {

      DEBUG_PIVOT("Unlocking", pv->child[i]);

      pv->child[i]->state = PSTATE_FETCH;

      if (!pv->child[i]->res) async_request(pv->child[i]->req);
      else switch (pv->child[i]->type) {

        case PIVOT_DIR:     dir_retrieve_check(pv->req, pv->res); break;
        case PIVOT_PARAM:
        case PIVOT_FILE:    file_retrieve_check(pv->req, pv->res); break;
        case PIVOT_UNKNOWN: unknown_retrieve_check(pv->req, pv->res); break;
        default: FATAL("Unknown pivot type '%u'", pv->type);

      }

    }

}


/* Handles response error for callbacks in a generalized manner. If 'stop' is
   1, marks the entire pivot as busted, unlocks children. */

static void handle_error(struct http_request* req, struct http_response* res,
                         u8* desc, u8 stop) {

  DEBUG_CALLBACK(req, res);

  if (res->state == STATE_SUPPRESS) {
    problem(PROB_LIMITS, req, res, (u8*)"Too many previous fetch failures",
            req->pivot, 0);
  } else {
    problem(PROB_FETCH_FAIL, req, res, desc, req->pivot, 0);
  }

  if (stop) {
    req->pivot->state = PSTATE_DONE;
    unlock_children(req->pivot);
  }

}


/* Finds nearest "real" directory parent, so that we can consult it for 404
   signatures, etc. Return NULL also if dir found, but signature-less. */

static struct pivot_desc* dir_parent(struct pivot_desc* pv) {
  struct pivot_desc* ret;

  ret = pv->parent;

  while (ret && ret->type != PIVOT_DIR && ret->type != PIVOT_SERV) 
    ret = ret->parent;

  if (ret && !ret->r404_cnt) return NULL;
  return ret;
}


/* Deletes any cached requests and responses stored by injection probes. */

static void destroy_misc_data(struct pivot_desc* pv,
                              struct http_request* self) {
  u32 i;

  for (i=0;i<MISC_ENTRIES;i++) {

    if (pv->misc_req[i] != self) {

      if (pv->misc_req[i])
        destroy_request(pv->misc_req[i]);

      if (pv->misc_res[i])
        destroy_response(pv->misc_res[i]);

    }

    pv->misc_req[i] = NULL;
    pv->misc_res[i] = NULL;

  }

  pv->misc_cnt = 0;

}



/*

  ***************************************
  **** ASSORTED FORWARD DECLARATIONS ****
  ***************************************

 */

static u8 dir_404_check(struct http_request*, struct http_response*);
static u8 dir_up_behavior_check(struct http_request*, struct http_response*);
static u8 dir_ips_check(struct http_request*, struct http_response*);
static void inject_start(struct pivot_desc*);
static void inject_start2(struct pivot_desc*);
static void dir_dict_start(struct pivot_desc*);
static u8 dir_dict_check(struct http_request*, struct http_response*);
static u8 dir_dict_bogus_check(struct http_request*, struct http_response*);
static u8 put_upload_check(struct http_request*, struct http_response*);
static u8 inject_behavior_check(struct http_request*, struct http_response*);
static u8 inject_dir_listing_check(struct http_request*, struct http_response*);
static u8 inject_xml_check(struct http_request*, struct http_response*);
static u8 inject_shell_check(struct http_request*, struct http_response*);
static u8 inject_xss_check(struct http_request*, struct http_response*);
static u8 inject_prologue_check(struct http_request*, struct http_response*);
static u8 inject_redir_check(struct http_request*, struct http_response*);
static u8 inject_split_check(struct http_request*, struct http_response*);
static u8 inject_sql_check(struct http_request*, struct http_response*);
static u8 inject_format_check(struct http_request*, struct http_response*);
static u8 inject_integer_check(struct http_request*, struct http_response*);
static void param_numerical_start(struct pivot_desc*);
static u8 param_behavior_check(struct http_request*, struct http_response*);
static u8 unknown_retrieve_check2(struct http_request*, struct http_response*);
static u8 param_numerical_check(struct http_request*, struct http_response*);
static u8 param_dict_check(struct http_request*, struct http_response*);
static u8 param_trylist_check(struct http_request*, struct http_response*);
static void param_dict_start(struct pivot_desc*);
static void param_start(struct pivot_desc*);
static void inject_done(struct pivot_desc*);
static u8 param_ognl_check(struct http_request*, struct http_response*);
static u8 dir_case_check(struct http_request* req, struct http_response* res);


/*

  ******************************
  **** ACTUAL STATE MACHINE ****
  ******************************

  The following is a rough sketch of what's going on here.

  == Pivot creation states ==

  Path elements:

    root       - PSTATE_DONE, no callback

    server     - PSTATE_FETCH, dir_retrieve_check

    dir        - PSTATE_FETCH, dir_retrieve_check
                 PSTATE_PENDING if parent state <= PSTATE_IPS_CHECK

    last seg   - PSTATE_FETCH, unknown_retrieve_check
                 PSTATE_PENDING if parent state <= PSTATE_IPS_CHECK

    file       - PSTATE_FETCH, file_retrieve_check
                 PSTATE_PENDING if parent state <= PSTATE_IPS_CHECK

    If element in name=value format, also add value to pivot's trylist.
    Call param_trylist_start if pivot already in PSTATE_DONE.

  Query elements:

    PSTATE_FETCH, file_retrieve_check
    PSTATE_PENDING if parent dir state <= PSTATE_IPS_CHECK

    Add value to pivot's trylist. Call param_trylist_start if pivot already
    in PSTATE_DONE.

  == Initial fetch actions ==

  unknown_retrieve_check:

    Initial retrieval of an unknown path element.

    File not found: unlock_children, -> param_start
    Otherwise: -> file_retrieve_check or -> unknown_retrieve_check2

  unknown_retrieve_check2:

    Secondary check to detect dir-like behavior (for unknown_retrieve_check).

    -> dir_retrieve_check or -> file_retrieve_check

  file_retrieve_check:

    Initial retrieval of a file, query parameter, or so.

    -> secondary_ext_start (async)
    -> dir_case_start (async)
    unlock_children

    Query value pivot: -> param_start
    Other pivots: PSTATE_CHILD_INJECT, -> inject_start

  dir_retrieve_check:

    Initial retrival of a directory or PATHINFO resource.

    -> secondary_ext_start (async)
    PSTATE_404_CHECK, -> dir_404_check

  == Basic directory checks ==

  dir_404_check:

    Performs basic 404 signature detection. Calls itself in a loop.

    -> dir_case_start (async)
    PSTATE_PARENT_CHECK, -> dir_up_behavior_check

  dir_up_behavior_check:

    Checks if path hierarchy is honored by the server.

    PSTATE_IPS_CHECK, -> dir_ips_check

  dir_ips_check:

    Checks for IPS-like behavior.

    unlock_children
    PSTATE_CHILD_INJECT, -> inject_start

  dir_case_start:

    Asynchronous handler to check directory case-sensitivity.

    -> dir_case_check

  dir_case_check:

    Case sensitivity callback. No further branching.

  == Parameter behavior (name=val pivots only) ==

  param_start:

    Initial parametric testing entry point.

    Non-fuzzable parameter: PSTATE_DONE
    Otherwise: PSTATE_PAR_CHECK, -> param_behavior_check

  param_behavior_check:

    Parameter behavior check callback.

    -> param_ognl_check (async)
    PSTATE_PAR_INJECT, -> inject_start

  param_ognl_check:

    Asynchronous OGNL behavior check. No further branching.

  == Injection attacks ==

  inject_start:

    Injection testing entry point.

    Directory: -> put_upload_check
    Other cases: -> inject_start2

  put_upload_check:

    Check for PUT upload vulnerabilities (dir only).

    -> inject_start2

  inject_start2:

    Injection testing entry point for non-dir nodes.

    -> inject_behavior_check

  inject_behavior_check:

    Parameter behavior consistency test.

    Bad pivot: -> inject_done
    OK pivot: -> inject_dir_listing_check

  inject_dir_listing_check:

    Directory listing probe.

    -> inject_xml_check

  inject_xml_check:

    Server-side XML injection probe.

    -> inject_shell_check

  inject_shell_check:

    Shell injection probe.

    -> inject_xss_check

  inject_xss_check:

    Reflected XSS probe.

    -> inject_prologue_check

  inject_prologue_check:

    Attacker-controlled response check.

    -> inject_redir_check

  inject_redir_check:

    Probe for redirection vulnerabilities.

    -> inject_split_check

  inject_split_check:

    Header splitting probe.

    -> inject_sql_check

  inject_sql_check:

    SQL injection probe.

    -> inject_format_check

  inject_format_check:
 
    Format string vulnerability probe.

    -> inject_integer_check

  inject_integer_check:

    Integer overflow probe.

    -> inject_done

  inject_done:

    Injection testing wrap-up.

    Path element: PSTATE_CHILD_DICT, -> dir_dict_start if fuzzable dir
                  -> param_start if not dir or no 404 sigs
                  PSTATE_DONE if not allowed or varies randomly

    Other parametric: -> param_numerical_start
                      PSTATE_DONE if varies randomly

  == Parameter brute-force (name=val only) ==

  param_numerical_start:

    Begin numerical brute-force if applicable.

    Numerical: PSTATE_PAR_NUMBER, -> param_numerical_check
    Otherwise: PSTATE_PAR_DICT, -> param_dict_start

  param_numerical_check:

    Numerical brute-force callback. May store results as PIVOT_VALUE /
    PSTATE_DONE nodes.

    -> secondary_ext_start (async)
    PSTATE_PAR_DICT, -> param_dict_start

  param_dict_start:

    Dictionary brute-force init / resume.

    Out of keywords: -> param_trylist_start
    Otherwise: -> param_dict_check

  param_dict_check:

    Dictionary brute-force callback. May store results as PIVOT_VALUE /
    PSTATE_DONE nodes.

    -> secondary_ext_start (async)
    Loops to -> param_trylist_start if not called via secondary_ext_check

  param_trylist_start:

    Begins trylist fuzzing, or resumes from offset.

    Bad pivot or no more keywords: PSTATE_DONE
    Otherwise: PSTATE_PAR_TRYLIST, -> param_trylist_check

  param_trylist_check:

  Trylist dictionary callback. May store results as PIVOT_VALUE / PSTATE_DONE
  nodes.

    -> secondary_ext_start (async)
    PSTATE_DONE

  == Directory brute-force ==

  dir_dict_start:

    Dictionary brute-force init / resume.

    Bad pivot or no more keywords: -> param_start
    Otherwise: -> dir_dict_bogus_check

  dir_dict_bogus_check:

    Check for good keyword candidates, proceed with extension fuzzing.
    -> dir_dict_check

    Loops over to -> dir_dict_start

  dir_dict_check:

    Dictionary brute-force callback.
 
    Loops over to -> dir_dict_start if not called via secondary_ext_start.

  == Secondary extension brute-force ==

  secondary_ext_start:

    Asynchronous secondary extension check

    Query: -> param_dict_check
    Path: -> dir_dict_check

 */


static void dir_case_start(struct pivot_desc* pv) {
  u32 i, len;
  s32 last = -1;
  struct http_request* n;

  if (pv->parent->c_checked) return;

  DEBUG_HELPER(pv);

  for (i=0;i<pv->req->par.c;i++)
    if (PATH_SUBTYPE(pv->req->par.t[i]) && pv->req->par.v[i][0]) last = i;

  if (last < 0) return;

  len = strlen((char*)pv->req->par.v[last]);

  for (i=0;i<len;i++) if (isalpha(pv->req->par.v[last][i])) break;

  if (i == len) return;

  pv->parent->c_checked = 1;

  n = req_copy(pv->req, pv, 1);
  n->callback = dir_case_check;

  /* Change case. */

  n->par.v[last][i] = islower(n->par.v[last][i]) ? toupper(n->par.v[last][i]) :
                      tolower(n->par.v[last][i]);

  DEBUG("* candidate parameter: %s -> %s\n", pv->req->par.v[last],
        n->par.v[last]);

  async_request(n);

}


static u8 dir_case_check(struct http_request* req,
                         struct http_response* res) {

  DEBUG_CALLBACK(req, res);

  if (FETCH_FAIL(res)) {
    RPAR(req)->c_checked = 0;
    return 0;
  }

  if (!same_page(&res->sig, &RPRES(req)->sig))
    RPAR(req)->csens = 1;

  return 0;

}


static void secondary_ext_start(struct pivot_desc* pv, struct http_request* req,
                                struct http_response* res, u8 is_param) {

  u8 *base_name, *fpos, *lpos, *ex;
  s32 tpar = -1, i = 0, spar = -1;

  DEBUG_HELPER(req->pivot);
  DEBUG_HELPER(pv);

  if (is_param) {

    tpar = pv->fuzz_par;

  } else {

    /* Find last path segment other than NULL-''. */
    for (i=0;i<req->par.c;i++)
      if (PATH_SUBTYPE(req->par.t[i])) {
        if ((req->par.t[i] == PARAM_PATH &&
            !req->par.n[i] && !req->par.v[i][0])) spar = i; else tpar = i;
      }

  }

  if (tpar < 0) return;

  base_name = req->par.v[tpar];

  /* Reject parameters with no '.' (unless in no_fuzz_ext mode),
     with too many '.'s, or '.' in an odd location. */

  fpos = (u8*)strchr((char*)base_name, '.');

  if (!no_fuzz_ext || fpos)
    if (!fpos || fpos == base_name || !fpos[1]) return;

  lpos = (u8*)strrchr((char*)base_name, '.');

  if (fpos != lpos) return;

  i = 0;

  while ((ex = wordlist_get_extension(i, 0))) {
    u8* tmp = ck_alloc(strlen((char*)base_name) + strlen((char*)ex) + 2);
    u32 c;

    /* Avoid foo.bar.bar. */

    if (lpos && !strcasecmp((char*)lpos + 1, (char*)ex)) {
      i++;
      ck_free(tmp);
      continue;
    }

    sprintf((char*)tmp, "%s.%s", base_name, ex);

    /* Matching child? If yes, don't bother. */

    for (c=0;c<pv->child_cnt;c++)
      if (!((is_c_sens(pv) ? strcmp : strcasecmp)((char*)tmp,
          (char*)pv->child[c]->name))) break;

    /* Matching current node? */

    if (pv->fuzz_par != -1 &&
        !((is_c_sens(pv) ? strcmp : strcasecmp)((char*)tmp,
        (char*)pv->req->par.v[pv->fuzz_par]))) c = ~pv->child_cnt;

    if (c == pv->child_cnt) {
      struct http_request* n = req_copy(req, pv, 1);

      /* Remove trailing slash if present. */
      if (spar >= 0) n->par.t[spar] = PARAM_NONE;

      ck_free(n->par.v[tpar]);
      n->par.v[tpar] = tmp;

      n->user_val = 1;

      memcpy(&n->same_sig, &res->sig, sizeof(struct http_sig));

      n->callback = is_param ? param_dict_check : dir_dict_check;
      /* Both handlers recognize user_val == 1 as a special indicator. */
      async_request(n);

    } else ck_free(tmp);

    i++;
  }

}


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


static void inject_start(struct pivot_desc* pv) {

  DEBUG_HELPER(pv);

  /* Do a PUT probe, but only on directories proper. */

  if (pv->type == PIVOT_DIR || pv->type == PIVOT_SERV) {
    struct http_request* n;
    n = req_copy(pv->req, pv, 1);
    if (n->method) ck_free(n->method);
    n->method   = ck_strdup((u8*)"PUT");
    n->callback = put_upload_check;
    replace_slash(n, (u8*)("PUT-" BOGUS_FILE));
    async_request(n);
  } else {
    inject_start2(pv);
  }

}


static u8 put_upload_check(struct http_request* req,
                           struct http_response* res) {

  DEBUG_CALLBACK(req, res);

  if (FETCH_FAIL(res)) {
    handle_error(req, res, (u8*)"during PUT checks", 0);
  } else {
    if (res->code >= 200 && res->code < 300 &&
        !same_page(&RPRES(req)->sig, &res->sig)) {
      problem(PROB_PUT_DIR, req, res, 0, req->pivot, 0);
    }
  }

  inject_start2(req->pivot);
  return 0;

}


static void inject_start2(struct pivot_desc* pv) {
  struct http_request* n;
  u32 i;

  DEBUG_HELPER(pv);

  pv->misc_cnt = BH_CHECKS;

  for (i=0;i<BH_CHECKS;i++) {
    n = req_copy(pv->req, pv, 1);
    n->callback = inject_behavior_check;
    n->user_val = i;
    async_request(n);
  }
}


static u8 inject_behavior_check(struct http_request* req,
                                struct http_response* res) {
  struct http_request* n;
  u32 orig_state = req->pivot->state;
  u8* tmp = NULL;

  /* pv->state may change after async_request() calls in
     insta-fail mode, so we should cache accordingly. */

  DEBUG_CALLBACK(req, res);

  if (FETCH_FAIL(res)) {
    handle_error(req, res, (u8*)"during page variability checks", 0);
  } else {
    if (!same_page(&RPRES(req)->sig, &res->sig)) {
      req->pivot->res_varies = 1;
      problem(PROB_VARIES, req, res, 0, req->pivot, 0);
    }
  }

  if ((--req->pivot->misc_cnt)) return 0;

  /* If response fluctuates, do not perform any injection checks at all. */

  if (req->pivot->res_varies) {
    inject_done(req->pivot);
    return 0;
  }

  /* Directory listing - 4 requests. The logic here is a bit
     different for parametric targets (which are easy to examine with 
     a ./ trick) and directories (which require a more complex 
     comparison). */

  req->pivot->misc_cnt = 0;

  n = req_copy(req->pivot->req, req->pivot, 1);

  if (orig_state == PSTATE_CHILD_INJECT) {
    replace_slash(n, (u8*)".");
    set_value(PARAM_PATH, NULL, (u8*)"", -1, &n->par);
  } else {
    tmp = ck_alloc(strlen((char*)TPAR(n)) + 5);
    sprintf((char*)tmp, ".../%s", TPAR(n));
    ck_free(TPAR(n));
    TPAR(n) = ck_strdup(tmp);
    req->pivot->i_skip_add = 6;
  }

  n->callback = inject_dir_listing_check;
  n->user_val = 0;
  async_request(n);

  n = req_copy(req->pivot->req, req->pivot, 1);

  if (orig_state == PSTATE_CHILD_INJECT) {
    replace_slash(n, (u8*)".sf");
    set_value(PARAM_PATH, NULL, (u8*)"", -1, &n->par);
  } else {
    ck_free(TPAR(n));
    TPAR(n) = ck_strdup(tmp + 2);
  }

  n->callback = inject_dir_listing_check;
  n->user_val = 1;
  async_request(n);

  n = req_copy(req->pivot->req, req->pivot, 1);

  if (orig_state == PSTATE_CHILD_INJECT) {
    replace_slash(n, (u8*)"\\.\\");
  } else {
    tmp[3] = '\\';
    ck_free(TPAR(n));
    TPAR(n) = ck_strdup(tmp);
  }

  n->callback = inject_dir_listing_check;
  n->user_val = 2;
  async_request(n);

  n = req_copy(req->pivot->req, req->pivot, 1);

  if (orig_state == PSTATE_CHILD_INJECT) {
    replace_slash(n, (u8*)"\\.sf\\");
  } else {
    ck_free(TPAR(n));
    TPAR(n) = ck_strdup(tmp + 2);
    ck_free(tmp);
  }

  n->callback = inject_dir_listing_check;
  n->user_val = 3;
  async_request(n);

  if (orig_state != PSTATE_CHILD_INJECT) {

    n = req_copy(req->pivot->req, req->pivot, 1);

    ck_free(TPAR(n));
    TPAR(n) = ck_strdup((u8*)"../../../../../../../../etc/hosts");

    n->callback = inject_dir_listing_check;
    n->user_val = 4;
    async_request(n);

    n = req_copy(req->pivot->req, req->pivot, 1);

    ck_free(TPAR(n));
    TPAR(n) = ck_strdup((u8*)"..\\..\\..\\..\\..\\..\\..\\..\\boot.ini");

    n->callback = inject_dir_listing_check;
    n->user_val = 5;
    async_request(n);

  }


  return 0;

}


static u8 inject_dir_listing_check(struct http_request* req,
                                   struct http_response* res) {
  struct http_request* n;
  u32 orig_state = req->pivot->state;

  DEBUG_CALLBACK(req, res);

  if (req->pivot->i_skip[0 + req->pivot->i_skip_add]) return 0;

  if (FETCH_FAIL(res)) {
    handle_error(req, res, (u8*)"during directory listing / traversal attacks", 0);
    req->pivot->i_skip[0 + req->pivot->i_skip_add] = 1;
    goto schedule_next;
  }

  req->pivot->misc_req[req->user_val] = req;
  req->pivot->misc_res[req->user_val] = res;

  if (req->pivot->i_skip_add) {
    if ((++req->pivot->misc_cnt) != 6) return 1;
  } else {
    if ((++req->pivot->misc_cnt) != 4) return 1;
  }

  /* Got all responses. For directories, this is:

       pivot   = /
       misc[0] = /./
       misc[1] = /.sf/
       misc[2] = \.\
       misc[3] = \.sf\

     Here, if pivot != misc[0], and misc[0] != misc[1], we probably
     managed to list a hidden dir. The same test is carried out for
     misc[2] and misc[3].

     For parameters, this is:

       misc[0] = .../known_val
       misc[1] = ./known_val
       misc[2] = ...\known_val
       misc[3] = .\known_val
       misc[4] = ../../../../../../../../etc/hosts
       misc[5] = ..\..\..\..\..\..\..\..\boot.ini

     Here, the test is simpler: if misc[1] != misc[0], or misc[3] !=
     misc[2], we probably have a bug. The same if misc[4] or misc[5]
     contain magic strings, but misc[0] doesn't.

 */

  if (orig_state == PSTATE_CHILD_INJECT) {

    if (MRES(0)->code < 300 &&
        !same_page(&MRES(0)->sig, &RPRES(req)->sig) &&
        !same_page(&MRES(0)->sig, &MRES(1)->sig)) {
      problem(PROB_DIR_LIST, MREQ(0), MRES(0),
        (u8*)"unique response for /./", 
        req->pivot, 0);

      /* Use pivot's request, rather than MREQ(0), for link scraping;
         MREQ(0) contains an "illegal" manually constructed path. */

      RESP_CHECKS(RPREQ(req), MRES(0));
    }

    if (MRES(2)->code < 300 &&
        !same_page(&MRES(2)->sig, &RPRES(req)->sig) &&
        !same_page(&MRES(2)->sig, &MRES(3)->sig)) {
      problem(PROB_DIR_LIST, MREQ(2), MRES(2), 
        (u8*)"unique response for \\.\\", 
        req->pivot, 0);
      RESP_CHECKS(MREQ(2), MRES(2));
    }

  } else {

    if (!same_page(&MRES(0)->sig, &MRES(1)->sig)) {
      problem(PROB_DIR_TRAVERSAL, MREQ(1), MRES(1), 
        (u8*)"responses for ./val and .../val look different", 
        req->pivot, 0);
      RESP_CHECKS(MREQ(0), MRES(0));
    }

    if (!same_page(&MRES(2)->sig, &MRES(3)->sig)) {
      problem(PROB_DIR_TRAVERSAL, MREQ(3), MRES(3),
        (u8*)"responses for .\\val and ...\\val look different", 
        req->pivot, 0);
      RESP_CHECKS(MREQ(2), MRES(2));
    }

    if (inl_findstr(MRES(4)->payload, (u8*)"127.0.0.1", 512) &&
        !inl_findstr(MRES(0)->payload, (u8*)"127.0.0.1", 512)) {
      problem(PROB_DIR_TRAVERSAL, MREQ(4), MRES(4),
        (u8*)"response resembles /etc/hosts", req->pivot, 0);
    }

    if (inl_findstr(MRES(5)->payload, (u8*)"[boot loader]", 512) &&
        !inl_findstr(MRES(0)->payload, (u8*)"[boot loader]", 512)) {
      problem(PROB_DIR_TRAVERSAL, MREQ(5), MRES(5),
        (u8*)"response resembles c:\\boot.ini", req->pivot, 0);
    }

  }

schedule_next:

  destroy_misc_data(req->pivot, req);

  /* Backend XML injection - 2 requests. */

  n = req_copy(RPREQ(req), req->pivot, 1);
  SET_VECTOR(orig_state, n, "sfish>'>\"><sfish></sfish>");
  n->callback = inject_xml_check;
  n->user_val = 0;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  SET_VECTOR(orig_state, n, "sfish>'>\"></sfish><sfish>");
  n->callback = inject_xml_check;
  n->user_val = 1;
  async_request(n);

  return 0;

}


static u8 inject_xml_check(struct http_request* req,
                           struct http_response* res) {
  struct http_request* n;
  u32 orig_state = req->pivot->state;

  DEBUG_CALLBACK(req, res);

  if (req->pivot->i_skip[1 + req->pivot->i_skip_add]) return 0;

  if (FETCH_FAIL(res)) {
    handle_error(req, res, (u8*)"during backend XML injection attacks", 0);
    req->pivot->i_skip[1 + req->pivot->i_skip_add] = 1;
    goto schedule_next;
  }

  req->pivot->misc_req[req->user_val] = req;
  req->pivot->misc_res[req->user_val] = res;
  if ((++req->pivot->misc_cnt) != 2) return 1;

  /* Got all responses:

       misc[0] = valid XML
       misc[1] = bad XML

     If misc[0] != misc[1], we probably have XML injection on backend side. */

  if (!same_page(&MRES(0)->sig, &MRES(1)->sig)) {
    problem(PROB_XML_INJECT, MREQ(0), MRES(0), 
      (u8*)"responses for <sfish></sfish> and </sfish><sfish> look different",
      req->pivot, 0);
    RESP_CHECKS(MREQ(1), MRES(1));
  }

schedule_next:

  destroy_misc_data(req->pivot, req);

  /* Shell command injection - 9 requests. */

  n = req_copy(RPREQ(req), req->pivot, 1);
  APPEND_VECTOR(orig_state, n, "`true`");
  n->callback = inject_shell_check;
  n->user_val = 0;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  APPEND_VECTOR(orig_state, n, "`false`");
  n->callback = inject_shell_check;
  n->user_val = 1;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  APPEND_VECTOR(orig_state, n, "`uname`");
  n->callback = inject_shell_check;
  n->user_val = 2;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  APPEND_VECTOR(orig_state, n, "\"`true`\"");
  n->callback = inject_shell_check;
  n->user_val = 3;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  APPEND_VECTOR(orig_state, n, "\"`false`\"");
  n->callback = inject_shell_check;
  n->user_val = 4;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  APPEND_VECTOR(orig_state, n, "\"`uname`\"");
  n->callback = inject_shell_check;
  n->user_val = 5;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  APPEND_VECTOR(orig_state, n, "'`true`'");
  n->callback = inject_shell_check;
  n->user_val = 6;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  APPEND_VECTOR(orig_state, n, "'`false`'");
  n->callback = inject_shell_check;
  n->user_val = 7;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  APPEND_VECTOR(orig_state, n, "'`uname`'");
  n->callback = inject_shell_check;
  n->user_val = 8;
  async_request(n);

  return 0;

}


static u8 inject_shell_check(struct http_request* req,
                             struct http_response* res) {
  struct http_request* n;
  u32 orig_state = req->pivot->state;

  DEBUG_CALLBACK(req, res);

  if (req->pivot->i_skip[2 + req->pivot->i_skip_add]) return 0;

  if (FETCH_FAIL(res)) {
    handle_error(req, res, (u8*)"during path-based shell injection attacks", 0);
    req->pivot->i_skip[2 + req->pivot->i_skip_add] = 1;
    goto schedule_next;
  }

  req->pivot->misc_req[req->user_val] = req;
  req->pivot->misc_res[req->user_val] = res;
  if ((++req->pivot->misc_cnt) != 9) return 1;

  /* Got all responses:

       misc[0] = `true`
       misc[1] = `false`
       misc[2] = `uname`
       misc[3] = "`true`"
       misc[4] = "`false`"
       misc[5] = "`uname`"
       misc[6] = '`true`'
       misc[7] = "`false`"
       misc[8] = '`uname`'

     If misc[0] == misc[1], but misc[0] != misc[2], we probably have shell
     injection. Ditto for the remaining triplets. We use the `false` case
     to avoid errors on search fields, etc. */

  if (same_page(&MRES(0)->sig, &MRES(1)->sig) &&
      !same_page(&MRES(0)->sig, &MRES(2)->sig)) {
    problem(PROB_SH_INJECT, MREQ(0), MRES(0), 
      (u8*)"responses to `true` and `false` different than to `uname`",
      req->pivot, 0);
    RESP_CHECKS(MREQ(2), MRES(2));
  }

  if (same_page(&MRES(3)->sig, &MRES(4)->sig) &&
      !same_page(&MRES(3)->sig, &MRES(5)->sig)) {
    problem(PROB_SH_INJECT, MREQ(3), MRES(3),
      (u8*)"responses to `true` and `false` different than to `uname`",
      req->pivot, 0);
    RESP_CHECKS(MREQ(5), MRES(5));
  }

  if (same_page(&MRES(6)->sig, &MRES(7)->sig) &&
      !same_page(&MRES(6)->sig, &MRES(8)->sig)) {
    problem(PROB_SH_INJECT, MREQ(6), MRES(6),
      (u8*)"responses to `true` and `false` different than to `uname`",
      req->pivot, 0);
    RESP_CHECKS(MREQ(8), MRES(8));
  }

schedule_next:

  destroy_misc_data(req->pivot, req);

  /* Cross-site scripting - two requests (also test common
     "special" error pages). */

  n = req_copy(RPREQ(req), req->pivot, 1);
  APPEND_VECTOR(orig_state, n, new_xss_tag(NULL));
  set_value(PARAM_HEADER, (u8*)"Referer", new_xss_tag(NULL), 0, &n->par);
  register_xss_tag(n);
  n->callback = inject_xss_check;
  n->user_val = 0;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  SET_VECTOR(orig_state, n, new_xss_tag((u8*)".htaccess.aspx"));
  register_xss_tag(n);
  n->callback = inject_xss_check;
  n->user_val = 1;
  async_request(n);

  return 0;

}


static u8 inject_xss_check(struct http_request* req,
                           struct http_response* res) {
  struct http_request* n;
  u32 orig_state = req->pivot->state;

  DEBUG_CALLBACK(req, res);

  /* Note that this is not a differential check, so we can let
     503, 504 codes slide. */

  if (res->state != STATE_OK) {
    handle_error(req, res, (u8*)"during cross-site scripting attacks", 0);
    goto schedule_next;
  }

  /* Content checks do automatic HTML parsing and XSS detection.
     scrape_page() is generally not advisable here. */

  content_checks(req, res);

  /* Attacker-controlled response start - 1 request */

schedule_next:

  if (req->user_val) return 0;

  n = req_copy(RPREQ(req), req->pivot, 1);
  SET_VECTOR(orig_state, n, (u8*)"SKIPFISH~STRING");
  n->callback = inject_prologue_check;
  async_request(n);

  return 0;

}


static u8 inject_prologue_check(struct http_request* req,
                                struct http_response* res) {
  struct http_request* n;
  u32 orig_state = req->pivot->state;

  DEBUG_CALLBACK(req, res);

  /* Likewise, 503 / 504 is OK here. */

  if (res->state != STATE_OK) {
    handle_error(req, res, (u8*)"during response prologue attacks", 0);
    goto schedule_next;
  }

  if (res->pay_len && !prefix(res->payload, (u8*)"SKIPFISH~STRING") &&
      !GET_HDR((u8*)"Content-Disposition", &res->hdr))
    problem(PROB_PROLOGUE, req, res, NULL, req->pivot, 0);

schedule_next:

  /* XSS checks - 3 requests */

  n = req_copy(RPREQ(req), req->pivot, 1);
  SET_VECTOR(orig_state, n, "http://skipfish.invalid/;?");
  n->callback = inject_redir_check;
  n->user_val = 0;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  SET_VECTOR(orig_state, n, "//skipfish.invalid/;?");
  n->callback = inject_redir_check;
  n->user_val = 1;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  SET_VECTOR(orig_state, n, "skipfish://invalid/;?");
  n->callback = inject_redir_check;
  n->user_val = 2;
  async_request(n);

  return 0;

}


static u8 inject_redir_check(struct http_request* req,
                             struct http_response* res) {
  struct http_request* n;
  u8* val;
  u32 orig_state = req->pivot->state;

  DEBUG_CALLBACK(req, res);

  /* Likewise, not a differential check. */

  if (res->state != STATE_OK) {
    handle_error(req, res, (u8*)"during URL injection attacks", 0);
    goto schedule_next;
  }

  /* Check Location, Refresh headers. */

  val = GET_HDR((u8*)"Location", &res->hdr);

  if (val) {

    if (!case_prefix(val, "http://skipfish.invalid/") ||
        !case_prefix(val, "//skipfish.invalid/"))
      problem(PROB_URL_REDIR, req, res, (u8*)"injected URL in 'Location' header",
              req->pivot, 0);

    if (!case_prefix(val, "skipfish:"))
      problem(PROB_URL_XSS, req, res, (u8*)"injected URL in 'Location' header",
              req->pivot, 0);

  }

  val = GET_HDR((u8*)"Refresh", &res->hdr);

  if (val && (val = (u8*)strchr((char*)val, '=')) && val++) {
    u8 semi_safe = 0;

    if (*val == '\'' || *val == '"') { val++; semi_safe++; }

    if (!case_prefix(val, "http://skipfish.invalid/") ||
        !case_prefix(val, "//skipfish.invalid/"))
      problem(PROB_URL_REDIR, req, res, (u8*)"injected URL in 'Refresh' header",
              req->pivot, 0);

    /* Unescaped semicolon in Refresh headers is unsafe with MSIE6. */

    if (!case_prefix(val, "skipfish:") ||
        (!semi_safe && strchr((char*)val, ';')))
      problem(PROB_URL_XSS, req, res, (u8*)"injected URL in 'Refresh' header",
              req->pivot, 0);

  }

  /* META tags and JS will be checked by content_checks(). We're not
     calling scrape_page(), because we don't want to accumulate bogus,
     injected links. */

  content_checks(req, res);

schedule_next:

  if (req->user_val != 2) return 0;

  /* Header splitting - 2 requests */

  n = req_copy(RPREQ(req), req->pivot, 1);
  APPEND_VECTOR(orig_state, n, "bogus\nSkipfish-Inject:bogus");
  n->callback = inject_split_check;
  n->user_val = 0;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  APPEND_VECTOR(orig_state, n, "bogus\rSkipfish-Inject:bogus");
  n->callback = inject_split_check;
  n->user_val = 1;
  async_request(n);

  return 0;

}


static u8 inject_split_check(struct http_request* req,
                             struct http_response* res) {
  u8 is_num = 0;
  struct http_request* n;
  u32 orig_state = req->pivot->state;

  DEBUG_CALLBACK(req, res);

  /* Not differential. */

  if (res->state != STATE_OK) {
    handle_error(req, res, (u8*)"during header injection attacks", 0);
    goto schedule_next;
  }

  /* Check headers - that's all! */

  if (GET_HDR((u8*)"Skipfish-Inject", &res->hdr))
    problem(PROB_HTTP_INJECT, req, res, 
      (u8*)"successfully injected 'Skipfish-Inject' header into response",
      req->pivot, 0);

schedule_next:

  if (req->user_val != 1) return 0;

  /* SQL injection - 10 requests */

  if (orig_state != PSTATE_CHILD_INJECT) {
    u8* pstr = TPAR(RPREQ(req));
    u32 c = strspn((char*)pstr, "01234567890.+-");
    if (pstr[0] && !pstr[c]) is_num = 1;
  }

  n = req_copy(RPREQ(req), req->pivot, 1);
  if (!is_num) SET_VECTOR(orig_state, n, "9-8");
  else APPEND_VECTOR(orig_state, n, "-0");
  n->callback = inject_sql_check;
  n->user_val = 0;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  if (!is_num) SET_VECTOR(orig_state, n, "8-7");
  else APPEND_VECTOR(orig_state, n, "-0-0");
  n->callback = inject_sql_check;
  n->user_val = 1;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  if (!is_num) SET_VECTOR(orig_state, n, "9-1");
  else APPEND_VECTOR(orig_state, n, "-0-9");
  n->callback = inject_sql_check;
  n->user_val = 2;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  APPEND_VECTOR(orig_state, n, "\\\'\\\"");
  set_value(PARAM_HEADER, (u8*)"User-Agent", (u8*)"sfish\\\'\\\"", 0, &n->par);
  set_value(PARAM_HEADER, (u8*)"Referer", (u8*)"sfish\\\'\\\"", 0, &n->par);
  set_value(PARAM_HEADER, (u8*)"Accept-Language", (u8*)"sfish\\\'\\\",en", 0,
            &n->par);
  n->callback = inject_sql_check;
  n->user_val = 3;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  APPEND_VECTOR(orig_state, n, "\'\"");
  set_value(PARAM_HEADER, (u8*)"User-Agent", (u8*)"sfish\'\"", 0, &n->par);
  set_value(PARAM_HEADER, (u8*)"Referer", (u8*)"sfish\'\"", 0, &n->par);
  set_value(PARAM_HEADER, (u8*)"Accept-Language", (u8*)"sfish\'\",en", 0,
            &n->par);
  n->callback = inject_sql_check;
  n->user_val = 4;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  APPEND_VECTOR(orig_state, n, "\\\\\'\\\\\"");
  set_value(PARAM_HEADER, (u8*)"User-Agent", (u8*)"sfish\\\\\'\\\\\"", 0, &n->par);
  set_value(PARAM_HEADER, (u8*)"Referer", (u8*)"sfish\\\\\'\\\\\"", 0, &n->par);
  set_value(PARAM_HEADER, (u8*)"Accept-Language", (u8*)"sfish\\\\\'\\\\\",en", 0,
            &n->par);
  n->callback = inject_sql_check;
  n->user_val = 5;
  async_request(n);

  /* This is a special case to trigger fault on blind numerical injection. */

  n = req_copy(RPREQ(req), req->pivot, 1);
  if (!is_num) SET_VECTOR(orig_state, n, "9 - 1");
  else APPEND_VECTOR(orig_state, n, " - 0 - 0");
  n->callback = inject_sql_check;
  n->user_val = 6;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  if (!is_num) SET_VECTOR(orig_state, n, "9 1 -");
  else APPEND_VECTOR(orig_state, n, " 0 0 - -");
  n->callback = inject_sql_check;
  n->user_val = 7;
  async_request(n);

  /* Another round of SQL injection checks for a different escaping style. */

  n = req_copy(RPREQ(req), req->pivot, 1);
  APPEND_VECTOR(orig_state, n, "''''\"\"\"\"");
  set_value(PARAM_HEADER, (u8*)"User-Agent", (u8*)"sfish''''\"\"\"\"", 0, 
            &n->par);
  set_value(PARAM_HEADER, (u8*)"Referer", (u8*)"sfish''''\"\"\"\"", 0, &n->par);
  set_value(PARAM_HEADER, (u8*)"Accept-Language", (u8*)"sfish''''\"\"\"\",en",
            0, &n->par);
  n->callback = inject_sql_check;
  n->user_val = 8;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  APPEND_VECTOR(orig_state, n, "'\"'\"'\"'\"");
  set_value(PARAM_HEADER, (u8*)"User-Agent", (u8*)"sfish'\"'\"'\"'\"", 0,
            &n->par);
  set_value(PARAM_HEADER, (u8*)"Referer", (u8*)"sfish'\"'\"'\"'\"", 0,
            &n->par);
  set_value(PARAM_HEADER, (u8*)"Accept-Language", 
            (u8*)"sfish'\"'\"'\"'\",en", 0, &n->par);
  n->callback = inject_sql_check;
  n->user_val = 9;
  async_request(n);

  /* TODO: We should probably also attempt cookie vectors here. */

  return 0;

}


static u8 inject_sql_check(struct http_request* req,
                           struct http_response* res) {
  struct http_request* n;
  u32 orig_state = req->pivot->state;
  DEBUG_CALLBACK(req, res);

  if (req->pivot->i_skip[3 + req->pivot->i_skip_add]) return 0;

  if (FETCH_FAIL(res)) {
    handle_error(req, res, (u8*)"during SQL injection attacks", 0);
    req->pivot->i_skip[3 + req->pivot->i_skip_add] = 1;
    goto schedule_next;
  }

  req->pivot->misc_req[req->user_val] = req;
  req->pivot->misc_res[req->user_val] = res;
  if ((++req->pivot->misc_cnt) != 10) return 1;

  /* Got all data:

       misc[0] = 9-8 (or orig-0)
       misc[1] = 8-7 (or orig-0-0)
       misc[2] = 9-1 (or orig-0-9)
       misc[3] = [orig]\'\"
       misc[4] = [orig]'"
       misc[5] = [orig]\\'\\"
       misc[6] = 9 - 1 (or orig - 0 - 0)
       misc[7] = 9 1 - (or orig 0 0 - -)

       misc[8] == [orig]''''""""
       misc[9] == [orig]'"'"'"'"

     If misc[0] == misc[1], but misc[0] != misc[2], probable (numeric) SQL
     injection. Ditto for misc[1] == misc[6], but misc[6] != misc[7]. 

     If misc[3] != misc[4] and misc[3] != misc[5], probable text SQL 
     injection.

     If misc[4] == misc[9], and misc[8] != misc[9], probable text SQL
     injection.

   */

  if (same_page(&MRES(0)->sig, &MRES(1)->sig) &&
      !same_page(&MRES(0)->sig, &MRES(2)->sig)) {
    problem(PROB_SQL_INJECT, MREQ(0), MRES(0),
      (u8*)"response suggests arithmetic evaluation on server side (type 1)",
      req->pivot, 0);
    RESP_CHECKS(MREQ(0), MRES(0));
    RESP_CHECKS(MREQ(2), MRES(2));
  }

  if (same_page(&MRES(1)->sig, &MRES(6)->sig) &&
      !same_page(&MRES(6)->sig, &MRES(7)->sig)) {
    problem(PROB_SQL_INJECT, MREQ(7), MRES(7),
      (u8*)"response suggests arithmetic evaluation on server side (type 2)",
      req->pivot, 0);
    RESP_CHECKS(MREQ(6), MRES(6));
    RESP_CHECKS(MREQ(7), MRES(7));
  }

  if (!same_page(&MRES(3)->sig, &MRES(4)->sig) && 
      !same_page(&MRES(3)->sig, &MRES(5)->sig)) {
    problem(PROB_SQL_INJECT, MREQ(4), MRES(4), 
      (u8*)"response to '\" different than to \\'\\\"", req->pivot, 0);
    RESP_CHECKS(MREQ(3), MRES(3));
    RESP_CHECKS(MREQ(4), MRES(4));
  }

  if (same_page(&MRES(4)->sig, &MRES(9)->sig) && 
      !same_page(&MRES(8)->sig, &MRES(9)->sig)) {
    problem(PROB_SQL_INJECT, MREQ(4), MRES(4), 
      (u8*)"response to ''''\"\"\"\" different than to '\"'\"'\"'\"", req->pivot, 0);
    RESP_CHECKS(MREQ(8), MRES(8));
    RESP_CHECKS(MREQ(9), MRES(9));
  }

schedule_next:

  destroy_misc_data(req->pivot, req);

  /* Format string attacks - 2 requests. */

  n = req_copy(RPREQ(req), req->pivot, 1);
  SET_VECTOR(orig_state, n, "sfish%dn%dn%dn%dn%dn%dn%dn%dn");
  n->callback = inject_format_check;
  n->user_val = 0;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  SET_VECTOR(orig_state, n, "sfish%nd%nd%nd%nd%nd%nd%nd%nd");
  n->callback = inject_format_check;
  n->user_val = 1;
  async_request(n);

  return 0;
}


static u8 inject_format_check(struct http_request* req,
                              struct http_response* res) {
  struct http_request* n;
  u32 orig_state = req->pivot->state;
  DEBUG_CALLBACK(req, res);

  if (req->pivot->i_skip[4 + req->pivot->i_skip_add]) return 0;

  if (FETCH_FAIL(res)) {
    handle_error(req, res, (u8*)"during format string attacks", 0);
    req->pivot->i_skip[4 + req->pivot->i_skip_add] = 1;
    goto schedule_next;
  }

  req->pivot->misc_req[req->user_val] = req;
  req->pivot->misc_res[req->user_val] = res;
  if ((++req->pivot->misc_cnt) != 2) return 1;

  /* Got all data:

       misc[0] = %dn... (harmless)
       misc[1] = %nd... (crashy)

     If misc[0] != misc[1], probable format string vuln.

   */

  if (!same_page(&MRES(0)->sig, &MRES(1)->sig)) {
    problem(PROB_FMT_STRING, MREQ(1), MRES(1),
      (u8*)"response to %dn%dn%dn... different than to %nd%nd%nd...",
      req->pivot, 0);
    RESP_CHECKS(MREQ(1), MRES(1));
  }

schedule_next:

  destroy_misc_data(req->pivot, req);

  /* Integer overflow bugs - 9 requests. */

  n = req_copy(RPREQ(req), req->pivot, 1);
  SET_VECTOR(orig_state, n, "-0000012345");
  n->callback = inject_integer_check;
  n->user_val = 0;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  SET_VECTOR(orig_state, n, "-2147483649");
  n->callback = inject_integer_check;
  n->user_val = 1;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  SET_VECTOR(orig_state, n, "-2147483648");
  n->callback = inject_integer_check;
  n->user_val = 2;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  SET_VECTOR(orig_state, n, "0000012345");
  n->callback = inject_integer_check;
  n->user_val = 3;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  SET_VECTOR(orig_state, n, "2147483647");
  n->callback = inject_integer_check;
  n->user_val = 4;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  SET_VECTOR(orig_state, n, "2147483648");
  n->callback = inject_integer_check;
  n->user_val = 5;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  SET_VECTOR(orig_state, n, "4294967295");
  n->callback = inject_integer_check;
  n->user_val = 6;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  SET_VECTOR(orig_state, n, "4294967296");
  n->callback = inject_integer_check;
  n->user_val = 7;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  SET_VECTOR(orig_state, n, "0000023456");
  n->callback = inject_integer_check;
  n->user_val = 8;
  async_request(n);

  return 0;
}


static u8 inject_integer_check(struct http_request* req,
                               struct http_response* res) {

  DEBUG_CALLBACK(req, res);

  if (req->pivot->i_skip[5 + req->pivot->i_skip_add]) return 0;

  if (FETCH_FAIL(res)) {
    handle_error(req, res, (u8*)"during integer overflow attacks", 0);
    req->pivot->i_skip[5 + req->pivot->i_skip_add] = 1;
    goto schedule_next;
  }

  req->pivot->misc_req[req->user_val] = req;
  req->pivot->misc_res[req->user_val] = res;
  if ((++req->pivot->misc_cnt) != 9) return 1;

  /* Got all data:

       misc[0] = -12345 (baseline)
       misc[1] = -(2^31-1)
       misc[2] = -2^31
       misc[3] = 12345 (baseline)
       misc[4] = 2^31-1
       misc[5] = 2^31
       misc[6] = 2^32-1
       misc[7] = 2^32
       misc[8] = 23456 (validation)

     If misc[3] != misc[8], skip tests - we're likely dealing with a
     search field instead.

     If misc[0] != misc[1] or misc[2], probable integer overflow;
     ditto for 3 vs 4, 5, 6, 7.

   */

  if (!same_page(&MRES(3)->sig, &MRES(8)->sig))
    goto schedule_next;

  if (!same_page(&MRES(0)->sig, &MRES(1)->sig)) {
    problem(PROB_INT_OVER, MREQ(1), MRES(1), 
      (u8*)"response to -(2^31-1) different than to -12345",
      req->pivot, 0);
    RESP_CHECKS(MREQ(1), MRES(1));
  }

  if (!same_page(&MRES(0)->sig, &MRES(2)->sig)) {
    problem(PROB_INT_OVER, MREQ(2), MRES(2), 
      (u8*)"response to -2^31 different than to -12345",
      req->pivot, 0);
    RESP_CHECKS(MREQ(2), MRES(2));
  }

  if (!same_page(&MRES(3)->sig, &MRES(4)->sig)) {
    problem(PROB_INT_OVER, MREQ(4), MRES(4),
      (u8*)"response to 2^31-1 different than to 12345",
      req->pivot, 0);
    RESP_CHECKS(MREQ(4), MRES(4));
  }

  if (!same_page(&MRES(3)->sig, &MRES(5)->sig)) {
    problem(PROB_INT_OVER, MREQ(5), MRES(5), 
      (u8*)"response to 2^31 different than to 12345",
      req->pivot, 0);
    RESP_CHECKS(MREQ(5), MRES(5));
  }

  if (!same_page(&MRES(3)->sig, &MRES(6)->sig)) {
    problem(PROB_INT_OVER, MREQ(6), MRES(6),
      (u8*)"response to 2^32-1 different than to 12345",
      req->pivot, 0);
    RESP_CHECKS(MREQ(6), MRES(6));
  }

  if (!same_page(&MRES(3)->sig, &MRES(7)->sig)) {
    problem(PROB_INT_OVER, MREQ(7), MRES(7),
      (u8*)"response to 2^32 different than to 12345",
      req->pivot, 0);
    RESP_CHECKS(MREQ(7), MRES(7));
  }

schedule_next:

  destroy_misc_data(req->pivot, req);
  inject_done(req->pivot);

  return 0;

}


static void inject_done(struct pivot_desc* pv) {

  if (pv->state == PSTATE_CHILD_INJECT) {

    if (url_allowed(pv->req) && !pv->res_varies) {

      if ((pv->type == PIVOT_DIR || pv->type == PIVOT_SERV) 
          && pv->r404_cnt && !pv->bad_parent) {
        pv->state   = PSTATE_CHILD_DICT;
        pv->cur_key = 0;
        dir_dict_start(pv);
      } else {
        param_start(pv);
      }

    } else {

      pv->state = PSTATE_DONE;
      if (delete_bin) maybe_delete_payload(pv);
      return;

    }

  } else {

    if (pv->bogus_par || pv->res_varies) {
      pv->state = PSTATE_DONE;
      if (delete_bin) maybe_delete_payload(pv);
    } else {
      param_numerical_start(pv);
    }

  }

}


static void param_start(struct pivot_desc* pv) {
  struct http_request* n;
  u32 i;

  if (pv->fuzz_par < 0 || !url_allowed(pv->req) || !param_allowed(pv->name)) {
    pv->state = PSTATE_DONE;
    if (delete_bin) maybe_delete_payload(pv);
    return;
  }

  DEBUG_HELPER(pv);

  pv->state = PSTATE_PAR_CHECK;

  /* Parameter behavior. */

  pv->ck_pending += BH_CHECKS;

  for (i=0;i<BH_CHECKS;i++) {
    n = req_copy(pv->req, pv, 1);
    ck_free(TPAR(n));
    TPAR(n) = ck_strdup((u8*)BOGUS_PARAM);
    n->callback = param_behavior_check;
    n->user_val = i;
    async_request(n);
  }

}


static u8 param_behavior_check(struct http_request* req,
                               struct http_response* res) {

  struct http_request* n;
  u8* tmp;

  DEBUG_CALLBACK(req, res);

  if (FETCH_FAIL(res)) {
    handle_error(req, res, (u8*)"during parameter behavior tests", 0);
    goto schedule_next;
  }

  if (same_page(&res->sig, &RPRES(req)->sig)) {
    DEBUG("* Parameter seems to have no effect.\n");
    req->pivot->bogus_par = 1;
    goto schedule_next;
  }

  DEBUG("* Parameter seems to have some effect:\n");
  debug_same_page(&res->sig, &RPRES(req)->sig);

  if (req->pivot->bogus_par) {
    DEBUG("* We already classified it as having no effect, whoops.\n");
    req->pivot->res_varies = 1;
    problem(PROB_VARIES, req, res, 0, req->pivot, 0);
    goto schedule_next;
  }

  /* If we do not have a signature yet, record it. Otherwise, make sure
     it did not change. */

  if (!req->pivot->r404_cnt) {

    DEBUG("* New signature, recorded.\n");
    memcpy(&req->pivot->r404[0], &res->sig, sizeof(struct http_sig));
    req->pivot->r404_cnt = 1;

  } else {

    if (!same_page(&res->sig, &req->pivot->r404[0])) {
      DEBUG("* Signature does not match previous responses, whoops.\n");
      req->pivot->res_varies = 1;
      problem(PROB_VARIES, req, res, 0, req->pivot, 0);
      goto schedule_next;
    }

  }

schedule_next:

  if ((--req->pivot->ck_pending)) return 0;

  /* All probes failed? Assume bogus parameter, what else to do... */

  if (!req->pivot->r404_cnt) 
    req->pivot->bogus_par = 1;

  /* If the parameter has an effect, schedule OGNL checks. */

  if (!req->pivot->bogus_par && !req->pivot->res_varies &&
       req->par.n[req->pivot->fuzz_par]) {

    n = req_copy(req->pivot->req, req->pivot, 1);
    tmp = ck_alloc(strlen((char*)n->par.n[req->pivot->fuzz_par]) + 8);
    sprintf((char*)tmp, "[0]['%s']", n->par.n[req->pivot->fuzz_par]);
    ck_free(n->par.n[req->pivot->fuzz_par]);
    n->par.n[req->pivot->fuzz_par] = tmp;
    n->callback = param_ognl_check;
    n->user_val = 0;
    async_request(n);

    n = req_copy(req->pivot->req, req->pivot, 1);
    ck_free(n->par.n[req->pivot->fuzz_par]);
    n->par.n[req->pivot->fuzz_par] = ck_strdup((u8*)"[0]['sfish']");
    n->callback = param_ognl_check;
    n->user_val = 1;
    async_request(n);

  }

  /* Injection attacks should be carried out even if we think this
     parameter has no visible effect; but injection checks will not proceed
     to dictionary fuzzing if bogus_par or res_varies is set. */

  req->pivot->state = PSTATE_PAR_INJECT;
  inject_start(req->pivot);

  return 0;

}


static u8 param_ognl_check(struct http_request* req,
                           struct http_response* res) {

  DEBUG_CALLBACK(req, res);

  if (FETCH_FAIL(res)) {
    handle_error(req, res, (u8*)"during OGNL tests", 0);
    return 0;
  }

  /* First response is meant to give the same result. Second
     is meant to give a different one. */

  if (req->user_val == 0) {
    if (same_page(&req->pivot->res->sig, &res->sig))
      req->pivot->ognl_check++;
  } else {
    if (!same_page(&req->pivot->res->sig, &res->sig))
      req->pivot->ognl_check++;
  }

  if (req->pivot->ognl_check == 2)
    problem(PROB_OGNL, req, res,
      (u8*)"response to [0]['name']=... identical to name=...", 
      req->pivot, 0);

  return 0;

}


static void param_numerical_start(struct pivot_desc* pv) {
  u8 *val = TPAR(pv->req), *out, fmt[16];
  u32 i, dig, tail;
  s32 val_i, range_st, range_en;
  u8  zero_padded = 0;

  DEBUG_HELPER(pv);

  if (!descendants_ok(pv)) goto schedule_next;

  /* Skip to the first digit, then to first non-digit. */

  i = 0;
  while (val[i] && !isdigit(val[i])) i++;
  if (!val[i]) goto schedule_next;

  dig = i;
  while (val[i] && isdigit(val[i])) i++;
  tail = i;

  /* Too many digits is a no-go. */

  if (tail - dig > PAR_MAX_DIGITS) goto schedule_next;

  if (val[dig] == '0' && tail - dig > 1) zero_padded = 1;

  val_i = atoi((char*)val + dig);
  range_st = val_i - PAR_INT_FUZZ;
  range_en = val_i + PAR_INT_FUZZ;
  if (range_st < 0) range_st = 0;

  if (zero_padded) sprintf((char*)fmt, "%%.%us%%0%uu%%s", dig, tail - dig);
  else sprintf((char*)fmt, "%%.%us%%%uu%%s", dig, tail - dig);

  out = ck_alloc(strlen((char*)val) + 16);

  /* Let's roll! */

  pv->state = PSTATE_PAR_NUMBER;

  pv->num_pending = range_en - range_st + 1;

  for (i=range_st;i<=range_en;i++) {
    struct http_request* n;

    if (i == val_i) { pv->num_pending--; continue; }

    sprintf((char*)out, (char*)fmt, val, i, val + tail);

    n = req_copy(pv->req, pv, 1);
    ck_free(TPAR(n));
    TPAR(n) = ck_strdup((u8*)out);
    n->callback = param_numerical_check;
    async_request(n);

  }

  ck_free(out);

  if (!pv->num_pending) goto schedule_next;
  return;

schedule_next:

  pv->state = PSTATE_PAR_DICT;
  param_dict_start(pv);

  /* Pew pew! */

}


static u8 param_numerical_check(struct http_request* req,
                                struct http_response* res) {
  struct pivot_desc *par, *n = NULL, *orig_pv = req->pivot;
  u32 i;

  DEBUG_CALLBACK(req, res);

  if (FETCH_FAIL(res)) {
    handle_error(req, res, (u8*)"during numerical brute-force tests", 0);
    goto schedule_next;
  }

  /* Looks like parent, or like its 404 signature? */

  if (same_page(&res->sig, &req->pivot->r404[0]) ||
      same_page(&res->sig, &req->pivot->res->sig))
    goto schedule_next;

  par = dir_parent(req->pivot);

  /* Check with parent if sigs available, but if not - no biggie. */

  if (par)
    for (i=0;i<par->r404_cnt;i++)
      if (same_page(&res->sig, &par->r404[i])) goto schedule_next;

  /* Matching child? If yes, don't bother. */

  for (i=0;i<req->pivot->child_cnt;i++)
    if (req->pivot->child[i]->type == PIVOT_VALUE &&
        !((is_c_sens(req->pivot) ? strcmp : strcasecmp)((char*)TPAR(req),
        (char*)req->pivot->child[i]->name))) goto schedule_next;

  if (!descendants_ok(req->pivot)) goto schedule_next;

  /* Hmm, looks like we're onto something. Let's manually create a dummy
     pivot and attach it to current node, without any activity planned.
     Attach any response notes to that pivot. */

  n = ck_alloc(sizeof(struct pivot_desc));

  n->type     = PIVOT_VALUE;
  n->state    = PSTATE_DONE;
  n->name     = ck_strdup(TPAR(req));
  n->req      = req;
  n->res      = res;
  n->fuzz_par = req->pivot->fuzz_par;
  n->parent   = req->pivot;

  DEBUG("--- New pivot (value): %s ---\n", n->name);

  req->pivot->child = ck_realloc(req->pivot->child, (req->pivot->child_cnt + 1)
                                 * sizeof(struct pivot_desc*));

  req->pivot->child[req->pivot->child_cnt++] = n;

  add_descendant(req->pivot);

  req->pivot = n;

  RESP_CHECKS(req, res);

  secondary_ext_start(orig_pv, req, res, 1);

  if (delete_bin) maybe_delete_payload(n);

schedule_next:

  if (!(--(orig_pv->num_pending))) {
    orig_pv->state = PSTATE_PAR_DICT;
    param_dict_start(orig_pv);
  }

  /* Copied over to pivot. */
  return n ? 1 : 0;

}


static void param_dict_start(struct pivot_desc* pv) {
  static u8 in_dict_init;
  struct http_request* n;
  u8 *kw, *ex;
  u32 i, c;
  u8 specific;

  /* Too many requests still pending, or already done? */

  if (in_dict_init || pv->pdic_pending > DICT_BATCH || 
      pv->state != PSTATE_PAR_DICT) return;

  DEBUG_HELPER(pv);

restart_dict:

  if (!descendants_ok(pv)) {
    param_trylist_start(pv);
    return;
  }

  i = 0;

  kw = (pv->pdic_guess ? wordlist_get_guess : wordlist_get_word)
       (pv->pdic_cur_key, &specific);

  if (!kw) {

    /* No more keywords. Move to guesswords if not there already, or
       advance to try list otherwise. */

    if (pv->pdic_guess) { param_trylist_start(pv); return; }

    pv->pdic_guess   = 1;
    pv->pdic_cur_key = 0;
    goto restart_dict;

  }

  /* Use crawl_prob/100 dictionary entries. */

  if (R(100) < crawl_prob) {

    /* Schedule extension-less probe, if the keyword is not
       on the child list. */

    for (c=0;c<pv->child_cnt;c++)
      if (pv->type == PIVOT_VALUE &&
          !((is_c_sens(pv) ? strcmp : strcasecmp)((char*)kw,
          (char*)pv->child[c]->name))) break;

    /* ...and does not match the node itself. */

    if (pv->fuzz_par != -1 &&
        !((is_c_sens(pv) ? strcmp : strcasecmp)((char*)kw,
        (char*)pv->req->par.v[pv->fuzz_par]))) c = ~pv->child_cnt;

    if (c == pv->child_cnt) {
      n = req_copy(pv->req, pv, 1);
      ck_free(TPAR(n));
      TPAR(n) = ck_strdup(kw);
      n->callback = param_dict_check;
      n->user_val = 0;
      pv->pdic_pending++;
      in_dict_init = 1;
      async_request(n);
      in_dict_init = 0;
    }

    /* Schedule probes for all extensions for the current word, but
       only if the original parameter contained '.' somewhere,
       and only if string is not on the try list. Special handling
       for specific keywords with '.' inside. */

    if (!no_fuzz_ext && strchr((char*)TPAR(pv->req), '.'))
      while ((ex = wordlist_get_extension(i, specific))) {

        u8* tmp = ck_alloc(strlen((char*)kw) + strlen((char*)ex) + 2);

        sprintf((char*)tmp, "%s.%s", kw, ex);

        for (c=0;c<pv->child_cnt;c++)
          if (pv->type == PIVOT_VALUE &&
              !((is_c_sens(pv) ? strcmp : strcasecmp)((char*)tmp,
              (char*)pv->child[c]->name))) break;

        if (pv->fuzz_par != -1 &&
            !((is_c_sens(pv) ? strcmp : strcasecmp)((char*)tmp,
            (char*)pv->req->par.v[pv->fuzz_par]))) c = ~pv->child_cnt;

        if (c == pv->child_cnt) {
          n = req_copy(pv->req, pv, 1);
          ck_free(TPAR(n));
          TPAR(n) = tmp;
          n->user_val = 0;
          n->callback = param_dict_check;
          pv->pdic_pending++;
          in_dict_init = 1;
          async_request(n);
          in_dict_init = 0;
        } else ck_free(tmp);

        i++;
      }

  }

  pv->pdic_cur_key++;

  if (pv->pdic_pending < DICT_BATCH) goto restart_dict;

}


static u8 param_dict_check(struct http_request* req,
                           struct http_response* res) {
  struct pivot_desc *par, *n = NULL, *orig_pv = req->pivot;
  u8 keep = 0;
  u32 i;

  DEBUG_CALLBACK(req, res);

  if (!req->user_val)
    req->pivot->pdic_pending--;

  if (FETCH_FAIL(res)) {
    handle_error(req, res, (u8*)"during parameter brute-force tests", 0);
    goto schedule_next;
  }

  /* Same as parent or parent's 404? Don't bother. */

  if (same_page(&res->sig, &req->pivot->r404[0]) ||
      same_page(&res->sig, &RPRES(req)->sig)) goto schedule_next;

  par = dir_parent(req->pivot);

  if (par)
    for (i=0;i<par->r404_cnt;i++)
      if (same_page(&res->sig, &par->r404[i])) goto schedule_next;

  /* Matching child? If yes, don't bother. */

  for (i=0;i<req->pivot->child_cnt;i++)
    if (req->pivot->child[i]->type == PIVOT_VALUE &&
        !((is_c_sens(req->pivot) ? strcmp : strcasecmp)((char*)TPAR(req),
        (char*)req->pivot->child[i]->name))) goto schedule_next;

  if (!descendants_ok(req->pivot)) goto schedule_next;

  n = ck_alloc(sizeof(struct pivot_desc));

  n->type     = PIVOT_VALUE;
  n->state    = PSTATE_DONE;
  n->name     = ck_strdup(TPAR(req));
  n->req      = req;
  n->res      = res;
  n->fuzz_par = req->pivot->fuzz_par;
  n->parent   = req->pivot;

  DEBUG("--- New pivot (value): %s ---\n", n->name);

  req->pivot->child = ck_realloc(req->pivot->child, (req->pivot->child_cnt + 1)
                                 * sizeof(struct pivot_desc*));

  req->pivot->child[req->pivot->child_cnt++] = n;

  add_descendant(req->pivot);

  req->pivot = n;

  keep = 1;

  RESP_CHECKS(req, res);

  if (!req->user_val)
    secondary_ext_start(orig_pv, req, res, 1);

  if (delete_bin) maybe_delete_payload(n);

schedule_next:

  if (!req->user_val) 
    param_dict_start(orig_pv);

  return keep;

}


void param_trylist_start(struct pivot_desc* pv) {
  u32 i;

  /* If the parameter does not seem to be doing anything, there is
     no point in going through the try list if restarted. */

  if (pv->fuzz_par == -1 || pv->bogus_par || pv->res_varies
      || !descendants_ok(pv)) {

    pv->state = PSTATE_DONE;
    if (delete_bin) maybe_delete_payload(pv);

    return;
  } else
    pv->state = PSTATE_PAR_TRYLIST;

  DEBUG_HELPER(pv);

  for (i=pv->try_cur;i<pv->try_cnt;i++) {
    u32 c;

    /* If we already have a child by this name, don't poke it again. */

    for (c=0;c<pv->child_cnt;c++)
      if (!((is_c_sens(pv) ? strcmp : strcasecmp)((char*)pv->try_list[i],
            (char*)pv->child[c]->name))) continue;

    /* Matching current node? Ditto. */

    if (pv->fuzz_par != -1 &&
        !((is_c_sens(pv) ? strcmp : strcasecmp)((char*)pv->try_list[i],
        (char*)pv->req->par.v[pv->fuzz_par]))) continue;

    if (c == pv->child_cnt) {

      if (R(100) < crawl_prob) {
        struct http_request* n;

        pv->try_pending++;

        n = req_copy(pv->req, pv, 1);
        ck_free(TPAR(n));
        TPAR(n) = ck_strdup(pv->try_list[i]);
        n->callback = param_trylist_check;
        async_request(n);
      }

    } else {
      if (!pv->child[c]->linked) pv->child[c]->linked = 1;
    }

  }

  pv->try_cur = i;

  if (!pv->try_pending) {
    pv->state = PSTATE_DONE;
    if (delete_bin) maybe_delete_payload(pv);
    return;
  }

}


static u8 param_trylist_check(struct http_request* req,
                              struct http_response* res) {
  struct pivot_desc *par, *n = NULL;
  struct pivot_desc* orig_pv = req->pivot;
  u32 i;

  DEBUG_CALLBACK(req, res);

  if (FETCH_FAIL(res)) {
    handle_error(req, res, (u8*)"during try list fetches", 0);
    goto schedule_next;
  }

  /* Same as parent or parent's 404? Don't bother. */

  if (same_page(&res->sig, &req->pivot->r404[0]) ||
      same_page(&res->sig, &RPRES(req)->sig)) goto schedule_next;

  par = dir_parent(req->pivot);

  if (par)
    for (i=0;i<par->r404_cnt;i++)
      if (same_page(&res->sig, &par->r404[i])) goto schedule_next;

  /* Name matching known child? If yes, don't bother. */

  for (i=0;i<req->pivot->child_cnt;i++)
    if (req->pivot->child[i]->type == PIVOT_VALUE &&
        !((is_c_sens(req->pivot) ? strcmp : strcasecmp)((char*)TPAR(req),
        (char*)req->pivot->child[i]->name))) goto schedule_next;

  if (!descendants_ok(req->pivot)) goto schedule_next;

  n = ck_alloc(sizeof(struct pivot_desc));

  n->type     = PIVOT_VALUE;
  n->state    = PSTATE_DONE;
  n->name     = ck_strdup(TPAR(req));
  n->req      = req;
  n->res      = res;
  n->fuzz_par = req->pivot->fuzz_par;
  n->parent   = req->pivot;

  DEBUG("--- New pivot (value): %s ---\n", n->name);

  req->pivot->child = ck_realloc(req->pivot->child, (req->pivot->child_cnt + 1)
                                 * sizeof(struct pivot_desc*));

  req->pivot->child[req->pivot->child_cnt++] = n;

  add_descendant(req->pivot);

  req->pivot = n;

  RESP_CHECKS(req, res);

  secondary_ext_start(orig_pv, req, res, 1);

  if (delete_bin) maybe_delete_payload(n);

schedule_next:

  if (!(--(orig_pv->try_pending))) {
    orig_pv->state = PSTATE_DONE;
    if (delete_bin) maybe_delete_payload(orig_pv);
  }

  /* Copied over to pivot. */
  return n ? 1 : 0;

}


u8 file_retrieve_check(struct http_request* req, struct http_response* res) {
  u32 i = 0;
  struct pivot_desc* par;

  RPRES(req) = res;
  DEBUG_CALLBACK(req, res);

  if (FETCH_FAIL(res)) {
    handle_error(req, res, (u8*)"during initial file fetch", 1);
    return 1;
  }

  /* Matches parent's 404? */

  par = dir_parent(req->pivot);

  if (par)
    for (i=0;i<par->r404_cnt;i++)
      if (same_page(&res->sig, &par->r404[i])) break;

  /* If no signatures on parents, fall back to a basic 404 check, it's
     the least we could do. */

  if ((!par && res->code == 404) || (par && i != par->r404_cnt)) {

    req->pivot->missing = 1;

  } else {

    if (res->code > 400)
      problem(PROB_NO_ACCESS, req, res, NULL, req->pivot, 0);

    /* Do not bother with checks on files or params if
       content identical to parent. */

    if (!RPAR(req)->res || !same_page(&res->sig, &RPAR(req)->res->sig)) {
      RESP_CHECKS(req, res);
      if (par && req->pivot->type != PIVOT_PARAM) 
        secondary_ext_start(par, req, res, 0);
    }

    if (req->pivot->type == PIVOT_FILE)
      dir_case_start(req->pivot);

  }

  /* On non-param nodes, we want to proceed with path-based injection
     checks. On param nodes, we want to proceed straght to parametric
     testng, instead. */

  unlock_children(req->pivot);

  if (req->pivot->type == PIVOT_PARAM) {
    param_start(req->pivot);
  } else {
    req->pivot->state = PSTATE_CHILD_INJECT;
    inject_start(req->pivot);
  }


  /* This is the initial callback, keep the response. */
  return 1;

}


u8 dir_retrieve_check(struct http_request* req, struct http_response* res) {
  struct http_request* n;
  struct pivot_desc* par;
  RPRES(req) = res;

  DEBUG_CALLBACK(req, res);

  /* Error at this point means we should give up on other probes in this
     directory. */

  if (FETCH_FAIL(res)) {
    handle_error(req, res, (u8*)"during initial directory fetch", 1);
    return 1;
  }

  if (req->pivot->type == PIVOT_SERV)
    PIVOT_CHECKS(req, res);

  /* The next step is checking 404 responses for all extensions (starting
     with an empty one), which would also determine if the directory exists
     at all, etc. We make an exception for server pivot, though, which is
     presumed to be a directory (so we do PIVOT_CHECKS right away). */

  req->pivot->state = PSTATE_404_CHECK;
  n = req_copy(req, req->pivot, 1);
  replace_slash(n, (u8*)BOGUS_FILE);

  n->user_val = 0;
  n->callback = dir_404_check;

  req->pivot->r404_pending++;

  async_request(n);

  par = dir_parent(req->pivot);
  if (par) secondary_ext_start(par, req, res, 0);

  /* Header, response belong to pivot - keep. */
  return 1;
}


static u8 dir_404_check(struct http_request* req,
                        struct http_response* res) {

  struct http_request* n;
  u32 i;
  s32 ppval = -1, pval = -1, val = -1;

  DEBUG_CALLBACK(req, res);

  if (req->pivot->r404_skip) goto schedule_next;

  if (FETCH_FAIL(res)) {
    handle_error(req, res, (u8*)"during 404 response checks", 0);
    goto schedule_next;
  }

  /* If the first 404 probe returned something that looks like the
     "root" page for the currently tested directory, panic. But don't
     do that check on server pivots, or if valid redirect detected
     earlier. */

  if (!req->user_val && !req->pivot->sure_dir && 
      req->pivot->type != PIVOT_SERV && RPRES(req) && 
      same_page(&res->sig, &RPRES(req)->sig)) {
    DEBUG("* First 404 probe identical with parent!\n");
    goto schedule_next;
  } else if (!req->user_val) {
    DEBUG("* First 404 probe differs from parent (%d)\n",
          RPRES(req) ? RPRES(req)->code : 0);
  }

  /* Check if this is a new signature. */

  for (i=0;i<req->pivot->r404_cnt;i++)
    if (same_page(&res->sig, &req->pivot->r404[i])) break;

  if (i == req->pivot->r404_cnt) {
    struct pivot_desc* par;

    DEBUG("* New signature found (%u).\n", req->pivot->r404_cnt);

    /* Need to add a new one. Make sure we're not over the limit. */

    if (req->pivot->r404_cnt >= MAX_404) {

       req->pivot->r404_skip = 1;

       problem(PROB_404_FAIL, RPREQ(req), RPRES(req),
               (u8*)"too many 404 signatures found", req->pivot, 0);

       goto schedule_next;

    }

    memcpy(&req->pivot->r404[i], &res->sig, sizeof(struct http_sig));

    req->pivot->r404_cnt++;

    /* Is this a new signature not seen on parent? Notify if so,
       and check it thoroughly. */

    par = dir_parent(req->pivot);

    if (par) {

      for (i=0;i<par->r404_cnt;i++)
        if (same_page(&res->sig, &par->r404[i])) break;

    }

    if (!par || i == par->r404_cnt) {
      problem(PROB_NEW_404, req, res, NULL, req->pivot, 1);
      RESP_CHECKS(req, res);
    }

  }

schedule_next:

  /* First probe OK? */

  if (!req->user_val) {
    u8* nk;
    u32 cur_ext = 0;

    /* First probe should already yield a 404 signature. */

    if (!req->pivot->r404_cnt) {
      DEBUG("* First probe failed to yield a signature.\n");
      goto bad_404;
    }

    DEBUG("* First probe yielded a valid signature.\n");

    /* At this point, we can be reasonably sure the response is
       meaningful. */

    PIVOT_CHECKS(req->pivot->req, req->pivot->res);
    dir_case_start(req->pivot);

    /* Aaand schedule all the remaining probes. Repeat BH_CHECKS
       times to also catch random variations. */

    while ((nk = wordlist_get_extension(cur_ext++, 0))) {
      u8* tmp = ck_alloc(strlen(BOGUS_FILE) + strlen((char*)nk) + 2);

      sprintf((char*)tmp, "%s.%s", BOGUS_FILE, nk);

      for (i=0;i<BH_CHECKS;i++) {

        n = req_copy(RPREQ(req), req->pivot, 1);
        replace_slash(n, tmp);
        n->callback = dir_404_check;
        n->user_val   = 1;

        /* r404_pending is at least 1 to begin with, so this is safe
           even if async_request() has a synchronous effect. */

        req->pivot->r404_pending++;
        async_request(n);
 
      }

      ck_free(tmp);

    }

    /* Also issue 404 probe for "lpt9", as "con", "prn", "nul", "lpt#",
       etc, are handled in a really annoying way by IIS. */

    n = req_copy(RPREQ(req), req->pivot, 1);
    replace_slash(n, (u8*)"lpt9");
    n->callback = dir_404_check;
    n->user_val = 1;
    req->pivot->r404_pending++;
    async_request(n);

    /* ...and for ~user, since this sometimes has a custom response, too. */

    n = req_copy(RPREQ(req), req->pivot, 1);
    replace_slash(n, (u8*)"~" BOGUS_FILE);
    n->callback = dir_404_check;
    n->user_val = 1;
    req->pivot->r404_pending++;
    async_request(n);

    /* Lastly, make sure that directory 404 is on file. */

    n = req_copy(RPREQ(req), req->pivot, 1);
    replace_slash(n, (u8*)BOGUS_FILE);
    set_value(PARAM_PATH, 0, (u8*)"", -1, &n->par);
    n->callback = dir_404_check;
    n->user_val = 1;
    req->pivot->r404_pending++;
    async_request(n);

  }

  if (--(req->pivot->r404_pending)) return 0;

  /* If we're here, all probes completed, and we had no major errors.
     If no signatures gathered, try to offer useful advice. */

bad_404:

  if (!req->pivot->r404_cnt || req->pivot->r404_skip) {

    DEBUG("* 404 detection failed.\n");

    if (RPRES(req)->code == 404) {

      req->pivot->missing = 1;

    } else if (RPRES(req)->code >= 400) {

      problem(PROB_NO_ACCESS, RPREQ(req), RPRES(req), NULL, req->pivot, 0);

      /* Additional check for 401, 500 codes, as we're not calling
         content_checks() otherwise. */

      if (RPRES(req)->code == 401)
        problem(PROB_AUTH_REQ, RPREQ(req), RPRES(req), NULL, req->pivot, 0);
      else if (RPRES(req)->code >= 500)
        problem(PROB_SERV_ERR, RPREQ(req), RPRES(req), NULL, req->pivot, 0);

    } else {

      if (req->pivot->type != PIVOT_SERV) {
        req->pivot->type = PIVOT_PATHINFO;
        replace_slash(req->pivot->req, NULL);
      } else 
        problem(PROB_404_FAIL, RPREQ(req), RPRES(req),
                (u8*)"no distinctive 404 behavior detected", req->pivot, 0);
    }

    req->pivot->r404_cnt = 0;

    /* We can still try parsing the response, if it differs from parent
       and is not on parent's 404 list. */

    if (!RPAR(req)->res) { 
      PIVOT_CHECKS(req->pivot->req, req->pivot->res);
    } else {

      if (!same_page(&RPRES(req)->sig, &RPAR(req)->res->sig)) {

        struct pivot_desc* par;
        par = dir_parent(req->pivot);

        if (par) {

          for (i=0;i<par->r404_cnt;i++)
            if (same_page(&res->sig, &par->r404[i])) break;

        }

        if (!par || i == par->r404_cnt) 
          PIVOT_CHECKS(req->pivot->req, req->pivot->res);

      }

    }  

  } else DEBUG("* 404 detection successful: %u signatures.\n", req->pivot->r404_cnt);

  /* Note that per-extension 404 probes coupled with a limit on the number of
     404 signatures largely eliminates the need for BH_COUNT identical probes
     to confirm sane behavior here. */

  /* The next probe is checking if /foo/current_path/ returns the same
     response as /bar/current_path/. If yes, then the directory probably
     should not be fuzzed. */

  req->pivot->state = PSTATE_PARENT_CHECK;

  n = req_copy(RPREQ(req), req->pivot, 1);
  n->callback = dir_up_behavior_check;
  n->user_val = 0;

  /* Last path element is /; previous path element is current dir name; 
     previous previous element is parent dir name. Find and replace it. */

  for (i=0;i<n->par.c;i++) {
    if (PATH_SUBTYPE(n->par.t[i])) {
      ppval = pval;
      pval = val;
      val = i;
    }
  }

  if (ppval != -1 && req->pivot->r404_cnt) {

    ck_free(n->par.v[ppval]);
    n->par.v[ppval] = ck_strdup((u8*)BOGUS_FILE);
    async_request(n);

  } else {

    /* Top-level dir - nothing to replace. Do a dummy call to 
       dir_up_behavior_check() to proceed directly to IPS checks. */

    n->user_val = 1;
    dir_up_behavior_check(n, res);
    destroy_request(n);

  }

  return 0;

}


static u8 dir_up_behavior_check(struct http_request* req,
                                struct http_response* res) {

  struct http_request* n;

  DEBUG_CALLBACK(req, res);

  if (req->user_val || req->pivot->r404_skip) {
    DEBUG("* Check not carried out (non-existent / bad parent).\n");
    goto schedule_next;
  }

  if (FETCH_FAIL(res)) {
    handle_error(req, res, (u8*)"during parent checks", 0);
    goto schedule_next;
  }

  if (same_page(&res->sig, &RPRES(req)->sig)) {
    problem(PROB_PARENT_FAIL, req, res, 0, req->pivot, 0);
    DEBUG("* Parent may be bogus, skipping.\n");
    req->pivot->bad_parent = 1;
  } else {
    DEBUG("* Parent behaves OK.\n");
  }

  /* Regardless of the outcome, let's schedule a final IPS check. Theoretically,
     a single request would be fine; but some servers, such as gws, tend
     to respond to /?foo very differently than to /. */

schedule_next:

  req->pivot->state = PSTATE_IPS_CHECK;

  n = req_copy(RPREQ(req), req->pivot, 1);
  tokenize_path((u8*)IPS_TEST, n, 0);
  n->callback = dir_ips_check;
  n->user_val = 0;
  async_request(n);

  n = req_copy(RPREQ(req), req->pivot, 1);
  tokenize_path((u8*)IPS_SAFE, n, 0);
  n->callback = dir_ips_check;
  n->user_val = 1;
  async_request(n);

  return 0;

}


static u8 dir_ips_check(struct http_request* req,
                        struct http_response* res) {
  struct pivot_desc* par;

  DEBUG_CALLBACK(req, res);

  if (req->pivot->i_skip[4]) return 0;

  if (req->user_val == 1 && FETCH_FAIL(res)) {
    handle_error(req, res, (u8*)"during IPS tests", 0);
    req->pivot->i_skip[4] = 1;
    goto schedule_next;
  }

  req->pivot->misc_req[req->user_val] = req;
  req->pivot->misc_res[req->user_val] = res;
  if ((++req->pivot->misc_cnt) != 2) return 1;

  par = dir_parent(req->pivot);

  if (!par || !par->uses_ips) {

    if (MRES(0)->state != STATE_OK)
      problem(PROB_IPS_FILTER, MREQ(0), MRES(0),
              (u8*)"request timed out (could also be a flaky server)",
              req->pivot, 0);
    else if (!same_page(&MRES(0)->sig, &MRES(1)->sig))
      problem(PROB_IPS_FILTER, MREQ(0), MRES(0), NULL, req->pivot, 0);

  } else {

    if (MRES(0)->state == STATE_OK && same_page(&MRES(0)->sig, &MRES(1)->sig))
      problem(PROB_IPS_FILTER_OFF, MREQ(0), MRES(0), NULL, req->pivot, 0);

  }

schedule_next:

  destroy_misc_data(req->pivot, req);

  /* Schedule injection attacks. */

  unlock_children(req->pivot);

  req->pivot->state = PSTATE_CHILD_INJECT;
  inject_start(req->pivot);

  return 0;
}


static void dir_dict_start(struct pivot_desc* pv) {
  static u8 in_dict_init;
  struct http_request* n;
  u8 *kw;
  u8 specific;

  /* Too many requests still pending, or already moved on to
     parametric tests? */

  if (in_dict_init || pv->pending > DICT_BATCH || pv->state != PSTATE_CHILD_DICT)
    return;

  if (!descendants_ok(pv)) {
    param_start(pv);
    return;
  }

  if (pv->no_fuzz) {
    if (pv->no_fuzz == 1)
      problem(PROB_LIMITS, pv->req, pv->res, 
              (u8*)"Recursion limit reached, not fuzzing", pv, 0);
    else
      problem(PROB_LIMITS, pv->req, pv->res, 
              (u8*)"Directory out of scope, not fuzzing", pv, 0);
    param_start(pv);
    return;
  }

  DEBUG_HELPER(pv);

restart_dict:

  kw = (pv->guess ? wordlist_get_guess : wordlist_get_word)
       (pv->cur_key, &specific);

  if (!kw) {

    /* No more keywords. Move to guesswords if not there already, or
       advance to parametric tests otherwise. */

    if (pv->guess) { param_start(pv); return; }

    pv->guess   = 1;
    pv->cur_key = 0;
    goto restart_dict;

  }

  /* Only schedule crawl_prob% dictionary entries. */

  if (R(100) < crawl_prob) {

    /* First, schedule a request for /foo.bogus to see if extension
       fuzzing is advisable. */

    u8* tmp = ck_alloc(strlen((char*)kw) + strlen((char*)BOGUS_EXT) + 2);

    sprintf((char*)tmp, "%s.%s", kw, BOGUS_EXT);

    n = req_copy(pv->req, pv, 1);
    replace_slash(n, tmp);
    n->callback = dir_dict_bogus_check;
    n->trying_key = kw;
    n->trying_spec = specific;
    pv->pending++;
    in_dict_init = 1;
    async_request(n);
    in_dict_init = 0;

    ck_free(tmp);

  }

  pv->cur_key++;

  /* Grab more keywords until we have a reasonable number of parallel requests
     scheduled. */

  if (pv->pending < DICT_BATCH) goto restart_dict;

}


static u8 dir_dict_bogus_check(struct http_request* req,
                               struct http_response* res) {

  struct http_request* n;
  u32 i, c;

  DEBUG_CALLBACK(req, res);

  if (FETCH_FAIL(res)) {

    handle_error(req, res, (u8*)"during path-based dictionary probes", 0);
    i = ~req->pivot->r404_cnt;

  } else {

    if (!req->pivot->r404_cnt)
      DEBUG("Bad pivot with no sigs! Pivot name = '%s'\n",
            req->pivot->name);

    for (i=0;i<req->pivot->r404_cnt;i++)
      if (same_page(&res->sig, &req->pivot->r404[i])) break;

  }

  /* Do not schedule probes for .ht* files if default Apache config spotted. */

  if (i == req->pivot->r404_cnt && res->code == 403 &&
      prefix(req->trying_key, ".ht")) goto schedule_next;

  /* New file? Add pivot for the extension. */

  if (i == req->pivot->r404_cnt) maybe_add_pivot(req, res, 0);

  /* Schedule extension probes only if bogus extension resulted in known 404. */

  if (i != req->pivot->r404_cnt && !no_fuzz_ext) {
    u8* ex;

    i = 0;

    while ((ex = wordlist_get_extension(i, req->trying_spec))) {

      u8* tmp = ck_alloc(strlen((char*)req->trying_key) +
                strlen((char*)ex) + 2);

      sprintf((char*)tmp, "%s.%s", req->trying_key, ex);

      /* See if that file is already known... */

      for (c=0;c<req->pivot->child_cnt;c++)
        if (!((is_c_sens(req->pivot) ? strcmp : strcasecmp)((char*)tmp,
            (char*)req->pivot->child[c]->name))) break;

      /* When dealing with name=value pairs, also compare to
         currently fuzzed value string. */

      if (req->pivot->fuzz_par != -1 &&
          !((is_c_sens(req->pivot) ? strcmp : strcasecmp)((char*)tmp,
            (char*)req->pivot->req->par.v[req->pivot->fuzz_par]))) 
        c = ~req->pivot->child_cnt;

      /* Not found - schedule a probe. */

      if (c == req->pivot->child_cnt) {
        n = req_copy(req->pivot->req, req->pivot, 1);
        replace_slash(n, tmp);
        n->callback = dir_dict_check;
        n->user_val = 0;
        req->pivot->pending++;
        async_request(n);
      }

      ck_free(tmp);

      i++;
    }

  }

  /* Regardless of this, also schedule requests for /$name and /$name/. */

  for (c=0;c<req->pivot->child_cnt;c++)
    if (!((is_c_sens(req->pivot) ? strcmp : strcasecmp)((char*)req->trying_key,
      (char*)req->pivot->child[c]->name))) break;

  if (req->pivot->fuzz_par != -1 &&
      !((is_c_sens(req->pivot) ? strcmp : strcasecmp)((char*)req->trying_key,
         (char*)req->pivot->req->par.v[req->pivot->fuzz_par]))) 
    c = ~req->pivot->child_cnt;

  if (c == req->pivot->child_cnt) {
    n = req_copy(req->pivot->req, req->pivot, 1);
    replace_slash(n, req->trying_key);
    n->callback = dir_dict_check;
    n->user_val = 0;
    req->pivot->pending++;
    async_request(n);

    if (prefix(req->trying_key, (u8*)".ht")) {

      n = req_copy(req->pivot->req, req->pivot, 1);
      replace_slash(n, req->trying_key);
      set_value(PARAM_PATH, NULL, (u8*)"", -1, &n->par);
      n->user_val = 0;
      n->callback = dir_dict_check;
      req->pivot->pending++;
      async_request(n);

    }

  }

schedule_next:

  /* Calling dir_dict_start() ensures that, if no new requests were scheduled
     earlier on and nothing else is pending, that we will still advance to
     parametric checks. */

  req->pivot->pending--;
  dir_dict_start(req->pivot);

  return 0;

}


static u8 dir_dict_check(struct http_request* req,
                         struct http_response* res) {
  u32 i;

  DEBUG_CALLBACK(req, res);

  if (FETCH_FAIL(res)) {
    handle_error(req, res, (u8*)"during path-based dictionary probes", 0);
  } else {

    /* Check if 404... */

    for (i=0;i<req->pivot->r404_cnt;i++)
      if (same_page(&res->sig, &req->pivot->r404[i])) break;

    /* Special case for secondary extension fuzzing - skip secondary
       extensions that seemingly return the same document. */

    if (req->user_val && same_page(&res->sig, &req->same_sig))
      i = ~req->pivot->r404_cnt;

    /* If not 404, do response, and does not look like
       parent's original file signature, add pivot. */

    if (i == req->pivot->r404_cnt) maybe_add_pivot(req, res, 0);

  }

  /* Try replenishing the queue. */

  if (!req->user_val) {
    req->pivot->pending--;
    dir_dict_start(req->pivot);
  }

  return 0;

}


u8 unknown_retrieve_check(struct http_request* req, struct http_response* res) {
  u32 i = 0 /* bad gcc */;
  struct pivot_desc *par;
  struct http_request* n;
  u8* name = NULL;

  RPRES(req) = res;
  DEBUG_CALLBACK(req, res);

  if (FETCH_FAIL(res)) {
    handle_error(req, res, (u8*)"during initial resource fetch", 1);
    return 1;
  }

  /* Matches parent's 404? */

  par = dir_parent(req->pivot);

  if (par)
    for (i=0;i<par->r404_cnt;i++)
      if (same_page(&res->sig, &par->r404[i])) break;

  /* Again, 404 is the least we could do. */

  if ((!par && res->code == 404) || (par && i != par->r404_cnt)) {

    req->pivot->missing = 1;
    unlock_children(req->pivot);
    param_start(req->pivot);
    return 1;

  }

  /* If the response looks like parent's original unknown_callback()
     response, assume file. This is a workaround for some really
     quirky architectures. */

  if (par && res->pay_len && res->code == 200 &&
      same_page(&par->unk_sig, &res->sig)) {

    req->pivot->type = PIVOT_FILE;
    return file_retrieve_check(req, res);

  }

  /* Another workaround for quirky frameworks: identical signature
     as parent's both probes, and 3xx code. */

  if (par && res->code >= 300 && res->code < 400 &&
      same_page(&par->unk_sig, &res->sig) && 
      same_page(&par->res->sig, &res->sig)) {

    req->pivot->type = PIVOT_FILE;
    return file_retrieve_check(req, res);

  }

  /* Special handling for .ht* */

  if (req->pivot->type < PIVOT_PARAM) {
    u32 i;

    /* Find last path segment. */

    for (i=0;i<req->par.c;i++)
      if (PATH_SUBTYPE(req->par.t[i])) name = req->par.v[i];

    if (name && !prefix(name, (u8*)".ht")) {
      req->pivot->type = PIVOT_FILE;
      return file_retrieve_check(req, res);
    }

  }

  /* Schedule a request to settle the type of this pivot point. */

  n = req_copy(req, req->pivot, 1);
  set_value(PARAM_PATH, NULL, (u8*)"", -1, &n->par);
  n->callback = unknown_retrieve_check2;
  n->user_val = 0;

  if (name) {
    u8* ppos = (u8*) strrchr((char*)name, '.');
    if (!ppos || ppos == name) n->user_val = 1;
  }

  async_request(n);

  /* This is the initial callback, keep the response. */

  return 1;

}


static u8 unknown_retrieve_check2(struct http_request* req,
                                  struct http_response* res) {
  u8 keep = 0;

  DEBUG_CALLBACK(req, res);

  if (FETCH_FAIL(res)) {
    handle_error(req, res, (u8*)"during node type checks", 0);
    goto schedule_next;
  }

  /* If pivot == res, we are probably dealing with PATH_INFO-style
     plot device, which is best approached as a directory anyway
     (worst-case scenario, dir handlers will dismiss it as
     misbehaving and demote it to PIVOT_PATHINFO after some extra
     checks).

     If pivot != res, and res is not a 404 response, assume dir;
     and if it is 404, assume file, except if pivot redirected to res.

     We also have a special case if the original request returned a
     non-empty 2xx response, but the new one returned 3xx-5xx - this is
     likely a file, too. */

  if (same_page(&RPRES(req)->sig, &res->sig)) goto assume_dir; else {
    u32 i = 0;
    struct pivot_desc* par = dir_parent(req->pivot);

    if (res->code == 404 && RPRES(req)->code >= 300 && RPRES(req)->code < 400) {
      u8 *loc = GET_HDR((u8*)"Location", &RPRES(req)->hdr);

      if (loc) {
        u8* path = serialize_path(req, 1, 0);

        if (!strcasecmp((char*)path, (char*)loc)) {
          ck_free(path);
          req->pivot->sure_dir = 1;
          goto assume_dir;
        }

        ck_free(path);

      }

    }

    if (par) {
      for (i=0;i<par->r404_cnt;i++)
        if (same_page(&res->sig, &par->r404[i])) break;

      /* Do not use extension-originating signatures for settling non-extension
         cases. */

      if (i && req->user_val) i = par->r404_cnt;

    }

    if ((!par && res->code == 404) || (par && i != par->r404_cnt) || 
        (RPRES(req)->code < 300 && res->code >= 300 && RPRES(req)->pay_len)) {

      req->pivot->type = PIVOT_FILE;

    } else {

assume_dir:

      /* If any of the responses is 500, and the user asked for 500 to
         be treated specially to work around quirky frameworks,
         assume file right away. */

      if (no_500_dir && (res->code >= 500 || RPRES(req)->code >= 500)) {
        DEBUG("Feels like a directory, but assuming file pivot as per -Z flag.\n");
        req->pivot->type = PIVOT_FILE;
        goto schedule_next;
      }

      req->pivot->type = PIVOT_DIR;

      /* Perform content checks before discarding the old payload. */

      if (!same_page(&RPRES(req)->sig, &res->sig))
        content_checks(RPREQ(req), RPRES(req));

      /* Replace original request, response with new data. */

      destroy_request(RPREQ(req));

      if (RPRES(req)) {
        memcpy(&req->pivot->unk_sig, &RPRES(req)->sig, sizeof(struct http_sig));
        destroy_response(RPRES(req));
      }

      RPREQ(req) = req;
      RPRES(req) = res;

      keep = 1;

    }

  }

schedule_next:

  /* Well, we need to do something. */

  if (req->pivot->type == PIVOT_DIR || req->pivot->type == PIVOT_SERV)
    dir_retrieve_check(RPREQ(req), RPRES(req));
  else file_retrieve_check(RPREQ(req), RPRES(req));

  return keep;
}

