/*
   skipfish - database & crawl management
   --------------------------------------

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

#ifndef _HAVE_DATABASE_H
#define _HAVE_DATABASE_H

#include "debug.h"
#include "config.h"
#include "types.h"
#include "http_client.h"

/* Testing pivot points - used to organize the scan: */

/* - Pivot types: */

#define PIVOT_NONE              0               /* Invalid                   */
#define PIVOT_ROOT              1               /* Root pivot                */

#define PIVOT_SERV              10              /* Top-level host pivot      */
#define PIVOT_DIR               11              /* Directory pivot           */
#define PIVOT_FILE              12              /* File pivot                */
#define PIVOT_PATHINFO          13              /* PATH_INFO script          */

#define PIVOT_UNKNOWN           18              /* (Currently) unknown type  */

#define PIVOT_PARAM             100             /* Parameter fuzzing pivot   */
#define PIVOT_VALUE             101             /* Parameter value pivot     */

/* - Pivot states (initialized to PENDING or FETCH by database.c, then
     advanced by crawler.c): */

#define PSTATE_NONE             0               /* Invalid                   */
#define PSTATE_PENDING          1               /* Pending parent tests      */

#define PSTATE_FETCH            10              /* Initial data fetch        */

#define PSTATE_TYPE_CHECK       20              /* Type check (unknown only) */
#define PSTATE_404_CHECK        22              /* 404 check (dir only)      */
#define PSTATE_PARENT_CHECK     24              /* Parent check (dir only)   */
#define PSTATE_IPS_CHECK        26              /* IPS filtering check       */

/* For directories only (injecting children nodes): */

#define PSTATE_CHILD_INJECT     50              /* Common security attacks   */
#define PSTATE_CHILD_DICT       55              /* Dictionary brute-force    */

/* For parametric nodes only (replacing parameter value): */

#define PSTATE_PAR_CHECK        60              /* Parameter works at all?   */
#define PSTATE_PAR_INJECT       65              /* Common security attacks   */
#define PSTATE_PAR_NUMBER       70              /* Numeric ID traversal      */
#define PSTATE_PAR_DICT         75              /* Dictionary brute-force    */
#define PSTATE_PAR_TRYLIST      99              /* 'Try list' fetches        */

#define PSTATE_DONE             100             /* Analysis done             */

/* - Descriptor of a pivot point: */

struct pivot_desc {
  u8 type;                                      /* PIVOT_*                   */
  u8 state;                                     /* PSTATE_*                  */
  u8 linked;                                    /* Linked to? (0/1/2)        */
  u8 missing;                                   /* Determined to be missing? */

  u8 csens;                                     /* Case sensitive names?     */
  u8 c_checked;                                 /* csens check done?         */

  u8* name;                                     /* Directory / script name   */

  struct http_request* req;                     /* Prototype HTTP request    */

  s32  fuzz_par;                                /* Fuzz target parameter     */
  u8** try_list;                                /* Values to try             */
  u32  try_cnt;                                 /* Number of values to try   */
  u32  try_cur;                                 /* Last tested try list offs */

  struct pivot_desc* parent;                    /* Parent pivot, if any      */
  struct pivot_desc** child;                    /* List of children          */
  u32 child_cnt;                                /* Number of children        */
  u32 desc_cnt;                                 /* Number of descendants     */

  struct issue_desc* issue;                     /* List of issues found      */
  u32 issue_cnt;                                /* Number of issues          */
  u32 desc_issue_cnt;                           /* Number of child issues    */

  struct http_response* res;                    /* HTTP response seen        */

  u8 res_varies;                                /* Response varies?          */
  u8 bad_parent;                                /* Parent is well-behaved?   */

  /* Fuzzer and probe state data: */

  u8 no_fuzz;                                   /* Do not attepmt fuzzing.   */
  u8 sure_dir;                                  /* Very sure it's a dir?     */

  u8  uses_ips;                                 /* Uses IPS filtering?       */

  u32 cur_key;                                  /* Current keyword           */
  u32 pdic_cur_key;                             /* ...for param dict         */

  u8 guess;                                     /* Guess list keywords?      */
  u8 pdic_guess;                                /* ...for param dict         */

  u32 pending;                                  /* Number of pending reqs    */
  u32 pdic_pending;                             /* ...for param dict         */
  u32 num_pending;                              /* ...for numerical enum     */
  u32 try_pending;                              /* ...for try list           */
  u32 r404_pending;                             /* ...for 404 probes         */
  u32 ck_pending;                               /* ...for behavior checks    */

  struct http_sig r404[MAX_404];                /* 404 response signatures   */
  u32 r404_cnt;                                 /* Number of sigs collected  */
  struct http_sig unk_sig;                      /* Original "unknown" sig.   */

  /* Injection attack logic scratchpad: */

  struct http_request*  misc_req[10];           /* Saved requests            */
  struct http_response* misc_res[10];           /* Saved responses           */
  u8 misc_cnt;                                  /* Request / response count  */

  u8 i_skip[15];                                /* Injection step skip flags */
  u8 i_skip_add;
  u8 r404_skip;

  u8 bogus_par;                                 /* fuzz_par does nothing?    */

  u8 ognl_check;                                /* OGNL check flags          */

  /* Reporting information: */

  u32 total_child_cnt;                          /* All children              */
  u32 total_issues[6];                          /* Issues by severity        */
  u8  dupe;                                     /* Looks like a duplicate?   */
  u32 pv_sig;                                   /* Simple pivot signature    */

};

extern struct pivot_desc root_pivot;

/* Checks child / descendant limits. */

u8 descendants_ok(struct pivot_desc* pv);

/* Increases descendant count. */

void add_descendant(struct pivot_desc* pv);

/* Maps a parsed URL (in req) to the pivot tree, creating or modifying nodes
   as necessary, and scheduling them for crawl; via_link should be 1 if the
   URL came from an explicit link or user input, 0 if brute-forced.

   Always makes a copy of req, res; they can be destroyed safely; via_link
   set to 2 means we're sure it's a valid link; 1 means "probably". */

void maybe_add_pivot(struct http_request* req, struct http_response* res,
                     u8 via_link);

/* Creates a working copy of a request for use in db and crawl functions. If all
   is 0, does not copy path, query parameters, or POST data (but still
   copies headers); and forces GET method. */

struct http_request* req_copy(struct http_request* req,
                              struct pivot_desc* pv, u8 all);

/* Finds the host-level pivot point for global issues. */

struct pivot_desc* host_pivot(struct pivot_desc* pv);

/* Case sensitivity helper. */

u8 is_c_sens(struct pivot_desc* pv);

/* Recorded security issues: */

/* - Informational data (non-specific security-relevant notes): */

#define PROB_NONE               0               /* Invalid                   */

#define PROB_SSL_CERT           10101           /* SSL issuer data           */

#define PROB_NEW_COOKIE         10201           /* New cookie added          */
#define PROB_SERVER_CHANGE      10202           /* New Server: value seen    */
#define PROB_VIA_CHANGE         10203           /* New Via: value seen       */
#define PROB_X_CHANGE           10204           /* New X-*: value seen       */
#define PROB_NEW_404            10205           /* New 404 signatures seen   */

#define PROB_NO_ACCESS          10401           /* Resource not accessible   */
#define PROB_AUTH_REQ           10402           /* Authentication requires   */
#define PROB_SERV_ERR           10403           /* Server error              */

#define PROB_EXT_LINK           10501           /* External link             */
#define PROB_EXT_REDIR          10502           /* External redirector       */
#define PROB_MAIL_ADDR          10503           /* E-mail address seen       */
#define PROB_UNKNOWN_PROTO      10504           /* Unknown protocol in URL   */
#define PROB_UNKNOWN_FIELD      10505           /* Unknown form field        */

#define PROB_FORM               10601           /* XSRF-safe form            */
#define PROB_PASS_FORM          10602           /* Password form             */
#define PROB_FILE_FORM          10603           /* File upload form          */

#define PROB_USER_LINK          10701           /* User-supplied A link      */

#define PROB_BAD_MIME_STAT      10801           /* Bad MIME type, low risk   */
#define PROB_GEN_MIME_STAT      10802           /* Generic MIME, low risk    */
#define PROB_BAD_CSET_STAT      10803           /* Bad charset, low risk     */
#define PROB_CFL_HDRS_STAT      10804           /* Conflicting hdr, low risk */

#define PROB_FUZZ_DIGIT         10901           /* Try fuzzing file name     */
#define PROB_OGNL               10902           /* OGNL-like parameter       */

/* - Internal warnings (scan failures, etc): */

#define PROB_FETCH_FAIL         20101           /* Fetch failed.             */
#define PROB_LIMITS             20102           /* Crawl limits exceeded.    */

#define PROB_404_FAIL           20201           /* Behavior probe failed.    */
#define PROB_PARENT_FAIL        20202           /* Parent behavior problem   */
#define PROB_IPS_FILTER         20203           /* IPS behavior detected.    */
#define PROB_IPS_FILTER_OFF     20204           /* IPS no longer active.     */
#define PROB_VARIES             20205           /* Response varies.          */

#define PROB_NOT_DIR            20301           /* Node should be a dir.     */

/* - Low severity issues (limited impact or check specificity): */

#define PROB_URL_AUTH           30101           /* HTTP credentials in URL   */

#define PROB_SSL_CERT_DATE      30201           /* SSL cert date invalid     */
#define PROB_SSL_SELF_CERT      30202           /* Self-signed SSL cert      */
#define PROB_SSL_BAD_HOST       30203           /* Certificate host mismatch */
#define PROB_SSL_NO_CERT        30204           /* No certificate data?      */

#define PROB_DIR_LIST           30301           /* Dir listing bypass        */

#define PROB_URL_REDIR          30401           /* URL redirection           */
#define PROB_USER_URL           30402           /* URL content inclusion     */

#define PROB_EXT_OBJ            30501           /* External obj standalone   */
#define PROB_MIXED_OBJ          30502           /* Mixed content standalone  */

#define PROB_VULN_FORM          30601           /* Form w/o anti-XSRF token  */
#define PROB_JS_XSSI            30602           /* Script with no XSSI prot  */

#define PROB_CACHE_LOW          30701           /* Cache nit-picking         */


/* - Moderate severity issues (data compromise): */

#define PROB_BODY_XSS           40101           /* Document body XSS         */
#define PROB_URL_XSS            40102           /* URL-based XSS             */
#define PROB_HTTP_INJECT        40103           /* Header splitting          */
#define PROB_USER_URL_ACT       40104           /* Active user content       */

#define PROB_EXT_SUB            40201           /* External subresource      */
#define PROB_MIXED_SUB          40202           /* Mixed content subresource */

#define PROB_BAD_MIME_DYN       40301           /* Bad MIME type, hi risk    */
#define PROB_GEN_MIME_DYN       40302           /* Generic MIME, hi risk     */
#define PROB_BAD_CSET_DYN       40304           /* Bad charset, hi risk      */
#define PROB_CFL_HDRS_DYN       40305           /* Conflicting hdr, hi risk  */

#define PROB_FILE_POI           40401           /* Interesting file          */
#define PROB_ERROR_POI          40402           /* Interesting error message */

#define PROB_DIR_TRAVERSAL      40501           /* Directory traversal       */

#define PROB_CACHE_HI           40601           /* Serious caching issues    */

#define PROB_PASS_NOSSL         40701           /* Password form, no HTTPS   */

/* - High severity issues (system compromise): */

#define PROB_XML_INJECT         50101           /* Backend XML injection     */
#define PROB_SH_INJECT          50102           /* Shell cmd injection       */
#define PROB_SQL_INJECT         50103           /* SQL injection             */
#define PROB_FMT_STRING         50104           /* Format string attack      */
#define PROB_INT_OVER           50105           /* Integer overflow attack   */

#define PROB_SQL_PARAM          50201           /* SQL-like parameter        */

#define PROB_PUT_DIR            50301           /* HTTP PUT accepted         */

/* - Severity macros: */

#define PSEV(_x) ((_x) / 10000)
#define PSEV_INFO 1
#define PSEV_WARN 2
#define PSEV_LOW  3
#define PSEV_MED  4
#define PSEV_HI   5

/* Issue descriptor: */

struct issue_desc {
  u32   type;                                   /* PROB_*                    */
  u8*   extra;                                  /* Problem-specific string   */
  struct http_request* req;                     /* HTTP request sent         */
  struct http_response* res;                    /* HTTP response seen        */
};

/* Register a problem, if not duplicate (res, extra may be NULL): */

void problem(u32 type, struct http_request* req, struct http_response* res,
             u8* extra, struct pivot_desc* pv, u8 allow_dup);

/* Compare the checksums for two responses: */

u8 same_page(struct http_sig* sig1, struct http_sig* sig2);

/* URL filtering constraints (exported from database.c): */

#define APPEND_FILTER(_ptr, _cnt, _val) do { \
   (_ptr) = ck_realloc(_ptr, ((_cnt) + 1) * sizeof(u8*)); \
   (_ptr)[_cnt] = (u8*)(_val); \
   (_cnt)++; \
 } while (0)

extern u8 **deny_urls, **deny_strings, **allow_urls, **allow_domains,
          **trust_domains, **skip_params;

extern u32 num_deny_urls,
           num_deny_strings,
           num_allow_urls,
           num_allow_domains,
           num_trust_domains,
           num_skip_params;

extern u32 max_depth,
           max_children,
           max_descendants,
           max_trylist,
           max_guesses;

extern u32 guess_cnt,
           extension_cnt,
           keyword_total_cnt,
           keyword_orig_cnt;

/* Check if the URL is permitted under current rules (0 = no, 1 = yes): */

u8 url_allowed_host(struct http_request* req);
u8 url_trusted_host(struct http_request* req);
u8 url_allowed(struct http_request* req);
u8 param_allowed(u8* pname);

/* Keyword management: */

extern u8  dont_add_words;

/* Adds a new keyword candidate to the "guess" list. */

void wordlist_add_guess(u8* text);

/* Adds non-sanitized keywords to the list. */

void wordlist_confirm_word(u8* text);

/* Returns wordlist item at a specified offset (NULL if no more available). */

u8* wordlist_get_word(u32 offset);

/* Returns keyword candidate at a specified offset (or NULL). */

u8* wordlist_get_guess(u32 offset);

/* Returns extension at a specified offset (or NULL). */

u8* wordlist_get_extension(u32 offset);

/* Loads keywords from file. */

void load_keywords(u8* fname, u32 purge_age);

/* Saves all keywords to a file. */

void save_keywords(u8* fname);

/* Database maintenance: */

/* Dumps pivot database, for debugging purposes. */

void dump_pivots(struct pivot_desc* cur, u8 nest);

/* Deallocates all data, for debugging purposes. */

void destroy_database();

/* Prints DB stats. */

void database_stats();

/* XSS manager: */

/* Creates a new stored XSS id (buffer valid only until next call). */

u8* new_xss_tag(u8* prefix);

/* Registers last XSS tag along with a completed http_request. */

void register_xss_tag(struct http_request* req);

/* Returns request associated with a stored XSS id. */

struct http_request* get_xss_request(u32 xid, u32 sid);

/* Dumps signature data: */

void dump_signature(struct http_sig* sig);

/* Displays debug information for same_page() checks. */

void debug_same_page(struct http_sig* sig1, struct http_sig* sig2);

#endif /* _HAVE_DATABASE_H */

