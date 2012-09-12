/*
   skipfish - database & crawl management
   --------------------------------------

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

#define _VIA_DATABASE_C

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "debug.h"
#include "config.h"
#include "types.h"
#include "http_client.h"
#include "database.h"
#include "crawler.h"
#include "analysis.h"
#include "string-inl.h"

struct pivot_desc root_pivot;

u8 **deny_urls,                         /* List of banned URL substrings   */
   **allow_urls,                        /* List of required URL substrings */
   **allow_domains,                     /* List of allowed vhosts          */
   **trust_domains,                     /* List of trusted vhosts          */
   **skip_params;                       /* List of parameters to ignore    */

u32 num_deny_urls,
    num_allow_urls,
    num_allow_domains,
    num_trust_domains,
    num_skip_params;

u32 max_depth       = MAX_DEPTH,
    max_children    = MAX_CHILDREN,
    max_descendants = MAX_DESCENDANTS,
    max_guesses     = MAX_GUESSES;

u8  dont_add_words;                     /* No auto dictionary building     */

#define KW_SPECIFIC 0
#define KW_GENERIC  1
#define KW_GEN_AUTO 2

struct kw_entry {
  u8* word;                             /* Keyword itself                  */
  u32 hit_cnt;                          /* Number of confirmed sightings   */
  u8  is_ext;                           /* Is an extension?                */
  u8  hit_already;                      /* Had its hit count bumped up?    */
  u8  read_only;                        /* Read-only dictionary?           */
  u8  class;                            /* KW_*                            */
  u32 total_age;                        /* Total age (in scan cycles)      */
  u32 last_age;                         /* Age since last hit              */
};

static struct kw_entry*
  keyword[WORD_HASH];                   /* Keyword collection (bucketed)   */

static u32 keyword_cnt[WORD_HASH];      /* Per-bucket keyword counts       */

struct ext_entry {
  u32 bucket;
  u32 index;
};

static struct ext_entry *wg_extension,     /* Extension list */
                        *ws_extension;

static u8 **guess;                      /* Keyword candidate list          */

u32 guess_cnt,                          /* Number of keyword candidates    */
    ws_extension_cnt,                   /* Number of specific extensions   */
    wg_extension_cnt,                   /* Number of extensions            */
    keyword_total_cnt,                  /* Current keyword count           */
    keyword_orig_cnt;                   /* At-boot keyword count           */

static u32 cur_xss_id, scan_id;         /* Stored XSS manager IDs          */
static struct http_request** xss_req;   /* Stored XSS manager req cache    */


/* Checks descendant counts. */

u8 descendants_ok(struct pivot_desc* pv) {

  if (pv->child_cnt > max_children) return 0;

  while (pv) {
    if (pv->desc_cnt > max_descendants) return 0;
    pv = pv->parent;
  }

  return 1;

}


void add_descendant(struct pivot_desc* pv) {

  while (pv) {
    pv->desc_cnt++;
    pv = pv->parent;
  }

}

/* Maps a parsed URL (in req) to the pivot tree, creating or modifying nodes
   as necessary, and scheduling them for crawl. This should be called only
   on requests that were *not* yet retrieved. */

void maybe_add_pivot(struct http_request* req, struct http_response* res,
                     u8 via_link) {

  struct pivot_desc *cur = NULL;

  u32 i, par_cnt = 0, path_cnt = 0, last_val_cnt = 0, pno;
  u8 ends_with_slash = 0;
  u8* last_val = 0;

#ifdef LOG_STDERR

  u8* url = serialize_path(req, 1, 1);
  DEBUG("--- New pivot requested: %s (%d) --\n", url, via_link);
  ck_free(url);

#endif /* LOG_STDERR */

  if (!req) FATAL("Invalid request data.");

  /* Initialize root pivot if not done already. */

  if (!root_pivot.type) {
    root_pivot.type     = PIVOT_ROOT;
    root_pivot.state    = PSTATE_DONE;
    root_pivot.linked   = 2;
    root_pivot.fuzz_par = -1;
    root_pivot.name     = ck_strdup((u8*)"[root]");
  }

  if (!url_allowed(req)) { url_scope++; return; }

  /* Count the number of path and query parameters in the request. */

  for (i=0;i<req->par.c;i++) {

    if (QUERY_SUBTYPE(req->par.t[i]) || POST_SUBTYPE(req->par.t[i])) par_cnt++;

    if (PATH_SUBTYPE(req->par.t[i])) {

      if (req->par.t[i] == PARAM_PATH && !req->par.n[i] &&
          req->par.v[i] && !req->par.v[i][0])
        ends_with_slash = 1;
      else
        ends_with_slash = 0;

      if (req->par.v[i][0]) last_val = req->par.v[i];

      path_cnt++;

    }

    /* While we're at it, try to learn new keywords. */

    if (PATH_SUBTYPE(req->par.t[i]) || QUERY_SUBTYPE(req->par.t[i])) {
      if (req->par.n[i]) wordlist_confirm_word(req->par.n[i]);
      wordlist_confirm_word(req->par.v[i]);
    }

  }

  /* Try to find pivot point for the host. */

  for (i=0;i<root_pivot.child_cnt;i++) {
    cur = root_pivot.child[i];
    if (!strcasecmp((char*)cur->req->host, (char*)req->host) &&
        cur->req->port == req->port &&
        cur->req->proto == req->proto) break;
  }

  if (i == root_pivot.child_cnt) {

    /* No server pivot found, we need to create one. */

    cur = ck_alloc(sizeof(struct pivot_desc));

    root_pivot.child = ck_realloc(root_pivot.child,
      (root_pivot.child_cnt + 1) * sizeof(struct pivot_desc*));

    root_pivot.child[root_pivot.child_cnt++] = cur;

    add_descendant(&root_pivot);

    cur->type     = PIVOT_SERV;
    cur->state    = PSTATE_FETCH;
    cur->linked   = 2;
    cur->fuzz_par = -1;
    cur->parent   = &root_pivot;

    /* Copy the original request, sans path. Create a dummy
       root dir entry instead. Derive pivot name by serializing
       the URL of the associated stub request. */

    cur->req = req_copy(req, cur, 0);
    set_value(PARAM_PATH, NULL, (u8*)"", -1, &cur->req->par);
    cur->name = serialize_path(cur->req, 1, 0);
    cur->req->callback = dir_retrieve_check;

    /* If matching response not provided, schedule request. */

    if (res && !par_cnt && path_cnt == 1) {
      cur->res = res_copy(res);
      dir_retrieve_check(req, cur->res);
    } else async_request(cur->req);

    wordlist_confirm_word(req->host);

  }

  /* One way or the other, 'cur' now points to server pivot. Let's
     walk through all path elements, and follow or create sub-pivots
     for them. */

  pno = 0;

  for (i=0;i<path_cnt;i++) {
    u8* pname;
    u32 c, ccnt;

    while (!PATH_SUBTYPE(req->par.t[pno])) pno++;

    /* Bail out on the trailing NULL-'' indicator, if present. It is
       used to denote a directory, and will always be the last path
       element. */

    if (i == path_cnt - 1 && req->par.t[pno] == PARAM_PATH &&
        !req->par.n[pno] && !req->par.v[pno][0]) break;

    pname = req->par.n[pno] ? req->par.n[pno] : req->par.v[pno];

    ccnt  = cur->child_cnt;

    /* Try to find a matching node. */

    for (c=0;c<ccnt;c++)
      if (!(is_c_sens(cur) ? strcmp : strcasecmp)((char*)pname,
           (char*)cur->child[c]->name)) {
        cur = cur->child[c];
        if (cur->linked < via_link) cur->linked = via_link;
        break;
      }

    if (c == ccnt) {

      /* Node not found. We need to create one. */

      struct pivot_desc* n;

      /* Enforce user limits. */

      if ((i + 1) >= max_depth || !descendants_ok(cur)) {
        problem(PROB_LIMITS, req, res, (u8*)"Child node limit exceeded", cur, 
                0);
        return;
      }

      /* Enforce duplicate name limits as a last-ditch effort to prevent
         endless recursion. */

      if (last_val && !strcmp((char*)last_val, (char*)req->par.v[pno]))
        last_val_cnt++;

      if (last_val_cnt > MAX_SAMENAME) {
        problem(PROB_LIMITS, req, res,
                (u8*)"Duplicate name recursion limit exceeded", cur, 0);
        return;
      }

      /* Create and link back to parent. */

      n = ck_alloc(sizeof(struct pivot_desc));

      cur->child = ck_realloc(cur->child, (cur->child_cnt + 1) *
                              sizeof(struct pivot_desc*));

      cur->child[cur->child_cnt++] = n;

      add_descendant(cur);

      n->parent  = cur;
      n->linked  = via_link;
      n->name    = ck_strdup(pname);

      /* Copy the original request, then copy over path up to the
         current point. */

      n->req     = req_copy(req, n, 0);

      for (c=0;c<=pno;c++)
        if (PATH_SUBTYPE(req->par.t[c]))
          set_value(req->par.t[c], req->par.n[c], req->par.v[c], -1,
                    &n->req->par);

      /* If name is parametric, indicate which parameter to fuzz. */

      if (req->par.n[pno]) n->fuzz_par = n->req->par.c - 1;
        else n->fuzz_par = -1;

      /* Do not fuzz out-of-scope or limit exceeded dirs... */

      if ((i + 1) == max_depth - 1) n->no_fuzz = 1;

      if (i != path_cnt - 1) {

        /* This is not the last path segment, so let's assume a "directory"
           (hierarchy node, to be more accurate), and schedule directory
           tests. */

        set_value(PARAM_PATH, NULL, (u8*)"", -1, &n->req->par);
        n->type = PIVOT_DIR;
        n->req->callback = dir_retrieve_check;

        if (!url_allowed(n->req)) n->no_fuzz = 2;

        /* Subdirectory tests require parent directory 404 testing to complete
           first. If these are still pending, wait a bit. */

        if (cur->state > PSTATE_IPS_CHECK) {

          n->state = PSTATE_FETCH;

          /* If this actually *is* the last parameter, taking into account the
             early-out hack mentioned above, and we were offered a response -
             make use of it and don't schedule a new request. */

          if (i == path_cnt - 2 && ends_with_slash && res) {

            n->res   = res_copy(res);
            dir_retrieve_check(n->req, n->res);

          } else async_request(n->req);

        } else n->state = PSTATE_PENDING;

      } else {

        /* Last segment. If no parameters, copy response body, mark type as
           "unknown", schedule extra checks. */

        if (!url_allowed(n->req)) n->no_fuzz = 2;

        if (!par_cnt) {

          n->type  = PIVOT_UNKNOWN;
          n->res   = res_copy(res);
          n->req->callback = unknown_retrieve_check;

          if (cur->state > PSTATE_IPS_CHECK) {

            n->state = PSTATE_FETCH;

            /* If we already have a response, call the callback directly
               (it will schedule further requests on its own). */

            if (!res) {
              n->state = PSTATE_FETCH;
              async_request(n->req);
            } else unknown_retrieve_check(n->req, n->res);

          } else n->state = PSTATE_PENDING;

        } else {

          /* Parameters found. Assume file, schedule a fetch. */

          n->type = PIVOT_FILE;
          n->req->callback = file_retrieve_check;

          if (cur->state > PSTATE_IPS_CHECK) {
            n->state = PSTATE_FETCH;
            async_request(n->req);
          } else n->state = PSTATE_PENDING;

        }

      }

      cur = n;

    }

    /* At this point, 'cur' points to a newly created or existing node
       for the path element. If this element is parametric, make sure
       that its value is on the 'try' list. */

    if (req->par.n[pno]) {

      for (c=0;c<cur->try_cnt;c++)
        if (cur->try_list[c] && !(is_c_sens(cur) ? strcmp : strcasecmp)
            ((char*)req->par.v[pno], (char*)cur->try_list[c])) break;

      /* Not found on the list - try adding. */

      if (c == cur->try_cnt) {

        cur->try_list = ck_realloc(cur->try_list, (cur->try_cnt + 1) *
                                   sizeof(u8*));
        cur->try_list[cur->try_cnt++] = ck_strdup(req->par.v[pno]);

        if (cur->state == PSTATE_DONE)
          param_trylist_start(cur);

      }

    }

    pno++;

  }

  /* Phew! At this point, 'cur' points to the final path element, and now,
     we just need to take care of parameters. Each parameter has its own
     pivot point, and a full copy of the request - unless on the 
     param_skip list. */

  pno = 0;

  for (i=0;i<par_cnt;i++) {
    u8* pname;
    u32 c, ccnt;

    while (!QUERY_SUBTYPE(req->par.t[pno]) && !POST_SUBTYPE(req->par.t[pno]))
      pno++;

    pname = req->par.n[pno] ? req->par.n[pno] : (u8*)"[blank]";
    ccnt  = cur->child_cnt;

    /* Try to find a matching node. */

    for (c=0;c<ccnt;c++)
      if (!(is_c_sens(cur) ? strcmp : strcasecmp)((char*)pname,
            (char*)cur->child[c]->name)) {
        cur = cur->child[c];
        if (cur->linked < via_link) cur->linked = via_link;
        break;
      }

    if (c == ccnt) {

      /* Node not found. We need to create one. */

      struct pivot_desc* n;

      /* Enforce user limits. */

      if (!descendants_ok(cur)) {
        problem(PROB_LIMITS, req, res, (u8*)"Child node limit exceeded", cur, 0);
        return;
      }

      /* Create and link back to parent. */

      n = ck_alloc(sizeof(struct pivot_desc));

      cur->child = ck_realloc(cur->child, (cur->child_cnt + 1) *
                              sizeof(struct pivot_desc*));

      cur->child[cur->child_cnt++] = n;

      add_descendant(cur);

      n->parent  = cur;
      n->type    = PIVOT_PARAM;
      n->linked  = via_link;
      n->name    = ck_strdup(pname);

      /* Copy the original request, in full. Remember not to fuzz
         file inputs. */

      n->req      = req_copy(req, n, 1);
      n->fuzz_par = req->par.t[pno] == PARAM_POST_F ? -1 : pno;
      n->res      = res_copy(res);

      /* File fetcher does everything we need. */

      n->req->callback = file_retrieve_check;

      if (cur->state > PSTATE_IPS_CHECK) {
        n->state = PSTATE_FETCH;
        if (res) file_retrieve_check(n->req, n->res);
        else async_request(n->req);
      } else n->state = PSTATE_PENDING;

      cur = n;

    }

    /* Ok, again, 'cur' is at the appropriate node. Make sure the
       current value is on the 'try' list. */

    for (c=0;c<cur->try_cnt;c++)
      if (cur->try_list[c] && !(is_c_sens(cur) ? strcmp : strcasecmp)
          ((char*)req->par.v[pno], (char*)cur->try_list[c])) break;

    /* Not found on the list - try adding. */

    if (c == cur->try_cnt) {

      cur->try_list = ck_realloc(cur->try_list, (cur->try_cnt + 1) *
                                 sizeof(u8*));
      cur->try_list[cur->try_cnt++] = ck_strdup(req->par.v[pno]);

      if (cur->state == PSTATE_DONE)
        param_trylist_start(cur);

    }

    /* Parameters are not hierarchical, so go back to the parent node. */

    cur = cur->parent;
    pno++;

  }

  /* Done, at last! */

}


/* Finds the host-level pivot point for global issues. */

struct pivot_desc* host_pivot(struct pivot_desc* pv) {
  while (pv->parent && pv->parent->parent) pv = pv->parent;
  return pv;
}


/* Gets case sensitivity info from the nearest DIR / SERV node. */

u8 is_c_sens(struct pivot_desc* pv) {
  while (pv->parent && (pv->type != PIVOT_DIR || pv->type != PIVOT_SERV))
    pv = pv->parent;
  return pv->csens;
}

/* Lookup an issue title */

u8* lookup_issue_title(u32 id) {
  u32 i = 0;

  while(pstructs[i].id && pstructs[i].id != id)
    i++;

  return pstructs[i].title;
}

/* Registers a problem, if not duplicate (res, extra may be NULL): */

void problem(u32 type, struct http_request* req, struct http_response* res,
             u8* extra, struct pivot_desc* pv, u8 allow_dup) {

  u32 i;

  if (pv->type == PIVOT_NONE) FATAL("Uninitialized pivot point");
  if (type == PROB_NONE || !req) FATAL("Invalid issue data");

#ifdef LOG_STDERR
  DEBUG("--- NEW PROBLEM - type: %u, extra: '%s' ---\n", type, extra);
#endif /* LOG_STDERR */

  /* Check for duplicates */

  if (!allow_dup)
    for (i=0;i<pv->issue_cnt;i++)
      if (type == pv->issue[i].type && !strcmp(extra ? (char*)extra : "",
          pv->issue[i].extra ? (char*)pv->issue[i].extra : "")) return;

  pv->issue = ck_realloc(pv->issue, (pv->issue_cnt + 1) *
                         sizeof(struct issue_desc));

  pv->issue[pv->issue_cnt].type  = type;
  pv->issue[pv->issue_cnt].extra = extra ? ck_strdup(extra) : NULL;
  pv->issue[pv->issue_cnt].req   = req_copy(req, pv, 1);
  pv->issue[pv->issue_cnt].res   = res_copy(res);

#ifndef LOG_STDERR
  u8* url = serialize_path(req, 1, 1);
  u8* title = lookup_issue_title(type);
  DEBUGC(L1, "\n--- NEW PROBLEM\n");
  DEBUGC(L1, "    - type: %u, %s\n", type, title);
  DEBUGC(L1, "    - url:  %s\n", url);
  DEBUGC(L2, "    - extra: %s\n", extra);
  ck_free(url);
#endif /* LOG_STDERR */

  /* Mark copies of half-baked requests as done. */

  if (res && res->state < STATE_OK) {
    pv->issue[pv->issue_cnt].res->state = STATE_OK;
    ck_free(pv->issue[pv->issue_cnt].res->payload);
    pv->issue[pv->issue_cnt].res->payload = 
      ck_strdup((u8*)"[...truncated...]\n");
    pv->issue[pv->issue_cnt].res->pay_len = 18;
  }

  pv->issue_cnt++;

  /* Propagate parent issue counts. */

  do { pv->desc_issue_cnt++; } while ((pv = pv->parent));

}



/* Three functions to check if the URL is permitted under current rules
   (0 = no, 1 = yes): */

u8 url_allowed_host(struct http_request* req) {
  u32 i;

  for (i=0;i<num_allow_domains;i++) {

    if (allow_domains[i][0] == '.') {

      u8* pos = inl_strcasestr(req->host, allow_domains[i]);

      if (pos && strlen((char*)req->host) ==
          strlen((char*)allow_domains[i]) + (pos - req->host))
        return 1;
 
    } else
      if (!strcasecmp((char*)req->host, (char*)allow_domains[i]))
        return 1;

  }

  return 0;
}


u8 url_trusted_host(struct http_request* req) {
  u32 i;

  i = 0;

  while (always_trust_domains[i]) {

    if (always_trust_domains[i][0] == '.') {

      u8* pos = inl_strcasestr(req->host, (u8*)always_trust_domains[i]);

      if (pos && strlen((char*)req->host) ==
          strlen(always_trust_domains[i]) + (pos - req->host))
        return 1;
    } else 
      if (!strcasecmp((char*)req->host, (char*)always_trust_domains[i]))
        return 1;

    i++;

  }

  for (i=0;i<num_trust_domains;i++) {

    u8* pos = inl_strcasestr(req->host, trust_domains[i]);

    if (pos && strlen((char*)req->host) ==
        strlen((char*)trust_domains[i]) + (pos - req->host))
      return 1;

  }

  return 0;
}


u8 url_allowed(struct http_request* req) {
  u8* url = serialize_path(req, 1, 0);
  u32 i;

  /* Check blacklist first */

  for (i=0;i<num_deny_urls;i++)
    if (inl_strcasestr(url, deny_urls[i])) {
      ck_free(url);
      return 0;
    }

  /* Check whitelist next */

  if (num_allow_urls) {
    u8 permit = 0;

    for (i=0;i<num_allow_urls;i++)
      if (inl_strcasestr(url, allow_urls[i])) {
        permit = 1;
        break;
      }

    if (!permit) { ck_free(url); return 0; }
  }

  ck_free(url);

  return url_allowed_host(req);

}


u8 param_allowed(u8* pname) {
  u32 i;

  for (i=0;i<num_skip_params;i++)
    if (!strcmp((char*)pname, (char*)skip_params[i])) return 0;

  return 1;

}

/* Compares the checksums for two responses: */

u8 same_page(struct http_sig* sig1, struct http_sig* sig2) {
  u32 i, bucket_fail = 0;
  s32 total_diff  = 0;
  u32 total_scale = 0;

  /* Different response codes: different page */
  if (sig1->code != sig2->code)
    return 0;

  /* One has text and the other hasnt: different page */
  if (sig1->has_text != sig2->has_text)
    return 0;

  for (i=0;i<FP_SIZE;i++) {
    s32 diff = sig1->data[i] - sig2->data[i];
    u32 scale = sig1->data[i] + sig2->data[i];

    if (abs(diff) > 1 + (scale * FP_T_REL / 100) ||
        abs(diff) > FP_T_ABS)
      if (++bucket_fail > FP_B_FAIL) return 0;

    total_diff     += diff;
    total_scale    += scale;

  }

  if (abs(total_diff) > 1 + (total_scale * FP_T_REL / 100))
    return 0;

  return 1;
}

/* Dumps signature data: */

void dump_signature(struct http_sig* sig) {
  u32 i;

  DEBUG("SIG %03d: ", sig->code);
  for (i=0;i<FP_SIZE;i++) DEBUG("[%04d] ", sig->data[i]);
  DEBUG("\n");

}


/* Debugs signature comparison: */

void debug_same_page(struct http_sig* sig1, struct http_sig* sig2) {

#ifdef LOG_STDERR

  u32 i;
  s32 total_diff  = 0;
  u32 total_scale = 0;

  dump_signature(sig1);
  dump_signature(sig2);

  DEBUG("         ");

  for (i=0;i<FP_SIZE;i++) {
    s32 diff = sig1->data[i] - sig2->data[i];
    DEBUG("[%04d] ", diff);
  }

  DEBUG("(diff)\n         ");

  for (i=0;i<FP_SIZE;i++) {
    s32 diff = sig1->data[i] - sig2->data[i];
    u32 scale = sig1->data[i] + sig2->data[i];

    if (abs(diff) > 1 + (scale * FP_T_REL / 100) ||
        abs(diff) > FP_T_ABS)
      DEBUG("[FAIL] "); else DEBUG("[pass] ");

    total_diff  += diff;
    total_scale += scale;
  }

  DEBUG("\n         ");

  for (i=0;i<FP_SIZE;i++) {
    u32 scale = sig1->data[i] + sig2->data[i];

    DEBUG("[%04d] ", (u32)( 1 + (scale * FP_T_REL / 100)));
  }

  DEBUG("(allow)\n");

  DEBUG("Total diff: %d, scale %d, allow %d. ",
    abs(total_diff), total_scale, 1 + (u32)(total_scale * FP_T_REL / 100));

  DEBUG("Both pages have text: ");
  if (sig1->has_text != sig2->has_text)
    DEBUG("no\n"); else DEBUG("yes\n");

#endif /* LOG_STDERR */

}



/* Keyword management: */


/* Word hashing helper. */

static inline u32 hash_word(u8* str) {
  register u32 ret = 0;
  register u8  cur;

  if (str)
    while ((cur=*str)) {
      ret = ~ret ^ (cur) ^
            (cur << 5)   ^ (~cur >> 5) ^
            (cur << 10)  ^ (~cur << 15) ^
            (cur << 20)  ^ (~cur << 25) ^
            (cur << 30);
      str++;
    }

  return ret % WORD_HASH;
}


/* Adds a new keyword candidate to the global "guess" list. This
   list is case-sensitive. */

void wordlist_add_guess(u8* text) {
  u32 target, i, kh;

  if (dont_add_words) return;

  /* Check if this is a bad or known guess or keyword. */

  if (!text || !text[0] || strlen((char*)text) > MAX_WORD) return;

  for (i=0;i<guess_cnt;i++)
    if (!strcmp((char*)text, (char*)guess[i])) return;

  kh = hash_word(text);

  for (i=0;i<keyword_cnt[kh];i++)
    if (!strcasecmp((char*)text, (char*)keyword[kh][i].word)) return;

  /* Initialize guess list if necessary. */

  if (!guess) guess = ck_alloc(max_guesses * sizeof(u8*));

  /* See if we can add a new one, or need to nuke something. */

  if (guess_cnt >= max_guesses) target = R(max_guesses);
    else target = guess_cnt++;

  ck_free(guess[target]);
  guess[target] = ck_strdup(text);

}


/* Adds a single, sanitized keyword to the list, or increases its hit count.
   Keyword list is case-sensitive. */

static void wordlist_confirm_single(u8* text, u8 is_ext, u8 class, u8 read_only,
                                    u32 add_hits, u32 total_age, u32 last_age) {
  u32 kh, i;

  if (!text || !text[0] || strlen((char*)text) > MAX_WORD) return;

  /* Check if this is a known keyword. */

  kh = hash_word(text);

  for (i=0;i<keyword_cnt[kh];i++)
    if (!strcmp((char*)text, (char*)keyword[kh][i].word)) {

      /* Known! Increase hit count, and if this is now
         tagged as an extension, add to extension list. */

      if (!keyword[kh][i].hit_already) {
        keyword[kh][i].hit_cnt    += add_hits;
        keyword[kh][i].hit_already = 1;
        keyword[kh][i].last_age    = 0;

        if (!keyword[kh][i].read_only && read_only)
          keyword[kh][i].read_only = 1;

      }

      if (!keyword[kh][i].is_ext && is_ext) {
        keyword[kh][i].is_ext = 1;

        wg_extension = ck_realloc(wg_extension, (wg_extension_cnt + 1) *
                    sizeof(struct ext_entry));
        wg_extension[wg_extension_cnt].bucket = kh;
        wg_extension[wg_extension_cnt++].index = i;
      }

      return;

    }

  /* Word not known (and i == keyword_cnt[kh]). Create a new wordlist entry. */

  keyword[kh] = ck_realloc(keyword[kh], (i + 1) * sizeof(struct kw_entry));
  keyword_cnt[kh]++;
  keyword_total_cnt++;

  keyword[kh][i].word      = ck_strdup(text);
  keyword[kh][i].is_ext    = is_ext;
  keyword[kh][i].class     = class;
  keyword[kh][i].read_only = read_only;
  keyword[kh][i].hit_cnt   = add_hits;
  keyword[kh][i].total_age = total_age;
  keyword[kh][i].last_age  = last_age;

  /* If this is a new keyword (not loaded from file), mark it as hit to
     avoid inflating hit_cnt. */

  if (!total_age) keyword[kh][i].hit_already = 1;

  if (is_ext) {

    wg_extension = ck_realloc(wg_extension, (wg_extension_cnt + 1) * 
                sizeof(struct ext_entry));
    wg_extension[wg_extension_cnt].bucket = kh;
    wg_extension[wg_extension_cnt++].index = i;

    /* We only add generic extensions to the ws list. */
    if (class == KW_GENERIC) {
      ws_extension = ck_realloc(ws_extension, (ws_extension_cnt + 1) * 
                sizeof(struct ext_entry));
      ws_extension[ws_extension_cnt].bucket = kh;
      ws_extension[ws_extension_cnt++].index = i;
    }
  }

}


/* Adds non-sanitized keywords to the list. */

void wordlist_confirm_word(u8* text) {
  u32 tlen, i, dcnt = 0, too_many_dots = 0;
  s32 ppos = -1;

  if (dont_add_words) return;

  /* Good keywords are expected to consist of A-Za-z 0-9_-~().:!^$ only.
     We expect at least one non-'.' character, at most one '.', and not more
     than four digits.

     If they do contain a dot at a position other than 0 or end-of-string,
     and the character after . is not a digit, we also extract and store an
     extension (which shouldn't be longer than 12 characters or so).

     This might misinterpret some TLDs as extensions (e.g, param=example.com),
     but the user is unlikely to be scanning so many different ccTLDs for this
     to affect the quality of the database. */

  if (!text || !text[0]) return;

  tlen = strlen((char*)text);

  for (i=0;i<tlen;i++) {
    if (!isalnum(text[i]) && !strchr(" _-~().:!^$", text[i])) return;
    if (isdigit(text[i])) dcnt++;
    if (text[i] == '.') {
      if (ppos != -1) too_many_dots = 1;
      ppos = i;
    }
  }

  /* If the format is foo.bar, check if the entire string is a known keyword. 
     If yes, don't try to look up and add individual components. */

  if (ppos != -1) {

    u32 kh = hash_word(text);

    for (i=0;i<keyword_cnt[kh];i++)
      if (!strcasecmp((char*)text, (char*)keyword[kh][i].word)) return;

  }

  /* Too many dots? Tokenize class paths and domains as individual keywords,
     still. */

  if (too_many_dots) {
    u8 *st = text, *en;

    do {
      en = (u8*)strchr((char*)st, '.');
      if (en) *en = 0;
      wordlist_confirm_word(st);
      if (en) *en = '.';
      st = en + 1;
    } while (en);

    return;
  }

  /* Too many digits? */
  if (dcnt > 4) return;

  if (ppos != -1) {

    /* Period only? Too long? */
    if (tlen == 1 || tlen - ppos > 12) return;

    if (ppos && ppos != tlen - 1 && !isdigit(text[ppos + 1])) {
      wordlist_confirm_single(text + ppos + 1, 1, KW_GEN_AUTO, 0, 1, 0, 0);
      text[ppos] = 0;
      wordlist_confirm_single(text, 0, KW_GEN_AUTO, 0, 1, 0, 0);
      text[ppos] = '.';
      return;
    }

  }

  wordlist_confirm_single(text, 0, KW_GEN_AUTO, 0, 1, 0, 0);
}


/* Returns wordlist item at a specified offset (NULL if no more available). */

u8* wordlist_get_word(u32 offset, u8* specific) {
  u32 cur_off = 0, kh;

  for (kh=0;kh<WORD_HASH;kh++) {
    if (cur_off + keyword_cnt[kh] > offset) break;
    cur_off += keyword_cnt[kh];
  }

  if (kh == WORD_HASH) return NULL;

  *specific = (keyword[kh][offset - cur_off].is_ext == 0 &&
               keyword[kh][offset - cur_off].class == KW_SPECIFIC);

  return keyword[kh][offset - cur_off].word;
}


/* Returns keyword candidate at a specified offset (or NULL). */

u8* wordlist_get_guess(u32 offset, u8* specific) {
  if (offset >= guess_cnt) return NULL;
  *specific = 0;
  return guess[offset];
}


/* Returns extension at a specified offset (or NULL). */

u8* wordlist_get_extension(u32 offset, u8 specific) {

  if (!specific) {
    if (offset >= wg_extension_cnt) return NULL;
    return keyword[wg_extension[offset].bucket][wg_extension[offset].index].word;
  }

  if (offset >= ws_extension_cnt) return NULL;
  return keyword[ws_extension[offset].bucket][ws_extension[offset].index].word;
}


/* Loads keywords from file. */

void load_keywords(u8* fname, u8 read_only, u32 purge_age) {
  FILE* in;
  u32 hits, total_age, last_age, lines = 0;
  u8 type[3];
  s32 fields;
  u8 kword[MAX_WORD + 1];
  char fmt[32];

  kword[MAX_WORD] = 0;

  in = fopen((char*)fname, "r");

  if (!in) {
    if (read_only)
      PFATAL("Unable to open read-only wordlist '%s'.", fname);
    else
      PFATAL("Unable to open read-write wordlist '%s' (see dictionaries/README-FIRST).", fname);
  }

  sprintf(fmt, "%%2s %%u %%u %%u %%%u[^\x01-\x1f]", MAX_WORD);

wordlist_retry:

  while ((fields = fscanf(in, fmt, type, &hits, &total_age, &last_age, kword))
          == 5) {

    u8 class = KW_GEN_AUTO;

    if (type[0] != 'e' && type[0] != 'w')
      FATAL("Wordlist '%s': bad keyword type in line %u.\n", fname, lines + 1);

    if (type[1] == 's') class = KW_SPECIFIC; else
    if (type[1] == 'g') class = KW_GENERIC;

    if (!purge_age || last_age < purge_age)
      wordlist_confirm_single(kword, (type[0] == 'e'), class, read_only, hits,
                              total_age + 1, last_age + 1);
    lines++;
    fgetc(in); /* sink \n */
  }

  if (fields == 1 && !strcmp((char*)type, "#r")) {
    DEBUG("Found %s (readonly:%d)\n", type, read_only);
    if (!read_only)
      FATAL("Attempt to load read-only wordlist '%s' via -W (use -S instead).\n", fname);

    fgetc(in); /* sink \n */
    goto wordlist_retry;
  }

  if (fields != -1 && fields != 5)
    FATAL("Wordlist '%s': syntax error in line %u.\n", fname, lines);

  if (!lines && (read_only || !keyword_total_cnt))
    WARN("Wordlist '%s' contained no valid entries.", fname);

  DEBUG("* Read %d lines from dictionary '%s' (read-only = %d).\n", lines,
        fname, read_only);

  keyword_orig_cnt = keyword_total_cnt;

  fclose(in);

}


/* qsort() callback for sorting keywords in save_keywords(). */

static int keyword_sorter(const void* word1, const void* word2) {
  if (((struct kw_entry*)word1)->hit_cnt < ((struct kw_entry*)word2)->hit_cnt)
    return 1;
  else if (((struct kw_entry*)word1)->hit_cnt ==
           ((struct kw_entry*)word2)->hit_cnt)
    return 0;
  else return -1;
}


/* Saves all keywords to a file. */

void save_keywords(u8* fname) {
  struct stat st;
  FILE* out;
  s32 fd;
  u32 i, kh;
  u8* old;

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif /* !O_NOFOLLOW */

  /* Don't save keywords for /dev/null and other weird files. */

  if (stat((char*)fname, &st) || !S_ISREG(st.st_mode)) return;

  /* First, sort the list. */

  for (kh=0;kh<WORD_HASH;kh++)
    qsort(keyword[kh], keyword_cnt[kh], sizeof(struct kw_entry), keyword_sorter);

  old = ck_alloc(strlen((char*)fname) + 5);
  sprintf((char*)old, "%s.old", fname);

  /* Ignore errors for these two. */
  unlink((char*)old);
  rename((char*)fname, (char*)old);

  ck_free(old);

  fd = open((char*)fname, O_WRONLY | O_CREAT | O_EXCL, 0644);

  if (fd < 0 || !(out = fdopen(fd,"w"))) {
    WARN("Unable to save new wordlist to '%s'", fname);
    close(fd);
    return;
  }

  for (kh=0;kh<WORD_HASH;kh++)
    for (i=0;i<keyword_cnt[kh];i++) {
      u8 class = '?';

      if (keyword[kh][i].read_only) continue;

      if (keyword[kh][i].class == KW_SPECIFIC) class = 's'; else
      if (keyword[kh][i].class == KW_GENERIC) class = 'g';

      fprintf(out,"%c%c %u %u %u %s\n", keyword[kh][i].is_ext ? 'e' : 'w',
              class,
              keyword[kh][i].hit_cnt, keyword[kh][i].total_age,
              keyword[kh][i].last_age, keyword[kh][i].word);

    }

  SAY(cLGN "[+] " cNOR "Wordlist '%s' updated (%u new words added).\n",
      fname, keyword_total_cnt - keyword_orig_cnt);

  fclose(out);
  close(fd);

}


/* Displays pretty pivot statistics as we go. */

static u32 pivot_pending,
           pivot_init,
           pivot_attack,
           pivot_bf,
           pivot_done;

static u32 pivot_serv,
           pivot_dir,
           pivot_file,
           pivot_pinfo,
           pivot_param,
           pivot_value,
           pivot_missing,
           pivot_unknown;

static u32 issue_cnt[6],
           pivot_cnt;

static void pv_stat_crawl(struct pivot_desc* pv) {
  u32 i;

  pivot_cnt++;

  switch (pv->type) {
    case PIVOT_SERV:     pivot_serv++; /* Fall through */
    case PIVOT_DIR:      pivot_dir++; break;
    case PIVOT_FILE:     pivot_file++; break;
    case PIVOT_PATHINFO: pivot_pinfo++; break;
    case PIVOT_UNKNOWN:  pivot_unknown++; break;
    case PIVOT_PARAM:    pivot_param++; break;
    case PIVOT_VALUE:    pivot_value++; break;
  }

  if (pv->missing) pivot_missing++;

  switch (pv->state) {
    case PSTATE_PENDING: pivot_pending++; break;
    case PSTATE_FETCH ... PSTATE_IPS_CHECK: pivot_init++; break;
    case PSTATE_CHILD_INJECT:
    case PSTATE_PAR_INJECT: pivot_attack++; break;
    case PSTATE_DONE: pivot_done++; break;
    default: pivot_bf++;
  }

  for (i=0;i<pv->issue_cnt;i++)
    issue_cnt[PSEV(pv->issue[i].type)]++;

  for (i=0;i<pv->child_cnt;i++)
    pv_stat_crawl(pv->child[i]);

}


void database_stats() {

  pivot_pending = pivot_init = pivot_attack = pivot_bf = pivot_pinfo =
  pivot_done = pivot_serv = pivot_dir = pivot_file = pivot_param =
  pivot_value = pivot_missing = pivot_unknown = pivot_cnt = 0;

  memset(issue_cnt, 0, sizeof(issue_cnt));

  pv_stat_crawl(&root_pivot);

  SAY(cLBL "Database statistics:\n\n"
      cGRA "         Pivots : " cNOR "%u total, %u done (%.02f%%)    \n"
      cGRA "    In progress : " cNOR "%u pending, %u init, %u attacks, "
                               "%u dict    \n"
      cGRA "  Missing nodes : " cNOR "%u spotted\n"
      cGRA "     Node types : " cNOR "%u serv, %u dir, %u file, %u pinfo, "
                               "%u unkn, %u par, %u val\n"
      cGRA "   Issues found : " cNOR "%u info, %u warn, %u low, %u medium, "
                               "%u high impact\n"
      cGRA "      Dict size : " cNOR "%u words (%u new), %u extensions, "
                               "%u candidates\n",
      pivot_cnt, pivot_done, pivot_cnt ? ((100.0 * pivot_done) / (pivot_cnt))
      : 0, pivot_pending, pivot_init, pivot_attack, pivot_bf, pivot_missing,
      pivot_serv, pivot_dir, pivot_file, pivot_pinfo, pivot_unknown,
      pivot_param, pivot_value, issue_cnt[1], issue_cnt[2], issue_cnt[3],
       issue_cnt[4], issue_cnt[5], keyword_total_cnt, keyword_total_cnt -
      keyword_orig_cnt, wg_extension_cnt, guess_cnt);

}


/* Dumps pivot database, for debugging purposes. */

void dump_pivots(struct pivot_desc* cur, u8 nest) {

  u8* indent = ck_alloc(nest + 1);
  u8* url;
  u32 i;

  if (!cur) cur = &root_pivot;

  memset(indent, ' ', nest);

  SAY(cBRI "\n%s== Pivot " cLGN "%s" cBRI " [%d] ==\n",
      indent, cur->name, cur->dupe);
  SAY(cGRA "%sType     : " cNOR, indent);

  switch (cur->type) {
    case PIVOT_NONE:     SAY(cLRD "PIVOT_NONE (bad!)\n" cNOR); break;
    case PIVOT_ROOT:     SAY("PIVOT_ROOT\n"); break;
    case PIVOT_SERV:     SAY("PIVOT_SERV\n"); break;
    case PIVOT_DIR:      SAY("PIVOT_DIR\n"); break;
    case PIVOT_FILE:     SAY("PIVOT_FILE\n"); break;
    case PIVOT_PATHINFO: SAY("PIVOT_PATHINFO\n"); break;
    case PIVOT_VALUE:    SAY("PIVOT_VALUE\n"); break;
    case PIVOT_UNKNOWN:  SAY("PIVOT_UNKNOWN\n"); break;
    case PIVOT_PARAM:    SAY("PIVOT_PARAM\n"); break;
    default:             SAY(cLRD "<UNKNOWN %u> (bad!)\n" cNOR, cur->type);
  }

  SAY(cGRA "%sState    : " cNOR, indent);

  switch (cur->state) {
    case PSTATE_NONE:         SAY(cLRD "PSTATE_NONE (bad!)\n" cNOR); break;
    case PSTATE_PENDING:      SAY("PSTATE_PENDING\n"); break;
    case PSTATE_FETCH:        SAY("PSTATE_FETCH\n"); break;
    case PSTATE_TYPE_CHECK:   SAY("PSTATE_TYPE_CHECK\n"); break;
    case PSTATE_404_CHECK:    SAY("PSTATE_404_CHECK\n"); break;
    case PSTATE_PARENT_CHECK: SAY("PSTATE_PARENT_CHECK\n"); break;
    case PSTATE_IPS_CHECK:    SAY("PSTATE_IPS_CHECK\n"); break;
    case PSTATE_CHILD_INJECT: SAY("PSTATE_CHILD_INJECT\n"); break;
    case PSTATE_CHILD_DICT:   SAY("PSTATE_CHILD_DICT\n"); break;
    case PSTATE_PAR_CHECK:    SAY("PSTATE_PAR_CHECK\n"); break;
    case PSTATE_PAR_INJECT:   SAY("PSTATE_PAR_INJECT\n"); break;
    case PSTATE_PAR_NUMBER:   SAY("PSTATE_PAR_NUMBER\n"); break;
    case PSTATE_PAR_DICT:     SAY("PSTATE_PAR_DICT\n"); break;
    case PSTATE_PAR_TRYLIST:  SAY("PSTATE_PAR_TRYLIST\n"); break;
    case PSTATE_DONE:         SAY("PSTATE_DONE\n"); break;
    default:                  SAY(cLRD "<UNKNOWN %u> (bad!)\n" cNOR,
                                     cur->state);
  }

  if (cur->missing) {
    if (cur->linked == 2)
      SAY(cGRA "%sMissing  : " cMGN "YES\n" cNOR, indent);
    else
      SAY(cGRA "%sMissing  : " cLBL "YES (followed a dodgy link)\n" cNOR,
          indent);
  }

  SAY(cGRA "%sFlags    : " cNOR "linked %u, case %u/%u, fuzz_par %d, ips %u, "
      "sigs %u, reqs %u, desc %u/%u\n", indent, cur->linked, cur->csens, cur->c_checked,
      cur->fuzz_par, cur->uses_ips, cur->r404_cnt, cur->pending, cur->child_cnt,
      cur->desc_cnt);

  if (cur->req) {
    url = serialize_path(cur->req, 1, 0);
    SAY(cGRA "%sTarget   : " cNOR "%s (" cYEL "%d" cNOR ")\n", indent, url,
        cur->res ? cur->res->code : 0);
    ck_free(url);

    if (cur->res)
      SAY(cGRA "%sMIME     : " cNOR "%s -> %s ["
          "%s:%s]\n", indent, cur->res->header_mime ? cur->res->header_mime :
          (u8*)"-", cur->res->sniffed_mime ? cur->res->sniffed_mime : (u8*)"-", 
          cur->res->header_charset ? cur->res->header_charset : (u8*)"-",
          cur->res->meta_charset ? cur->res->meta_charset : (u8*)"-");
  }

  if (cur->try_cnt) {
    SAY(cGRA "%sTry      : " cNOR, indent);
    for (i=0;i<cur->try_cnt;i++)
      SAY("%s%s", cur->try_list[i], (i == cur->try_cnt - 1) ? "" : ", ");
    SAY("\n");
  }

  /* Dump issues. */

  for (i=0;i<cur->issue_cnt;i++) {
    if (cur->issue[i].req) url = serialize_path(cur->issue[i].req, 0, 0);
      else url = ck_strdup((u8*)"[none]");
    SAY(cGRA "%s-> Issue : " cNOR "type %d, extra '%s', URL: " cLGN "%s"
        cNOR " (" cYEL "%u" cNOR ")\n", indent, cur->issue[i].type,
        cur->issue[i].extra, url, cur->issue[i].res ? cur->issue[i].res->code
        : 0);
    ck_free(url);
  }

  ck_free(indent);

  for (i=0;i<cur->child_cnt;i++)
    dump_pivots(cur->child[i], nest + 1);

}


/* Cleans up pivot structure for memory debugging. */

static void dealloc_pivots(struct pivot_desc* cur) {
  u32 i;

  if (!cur) cur = &root_pivot;

  if (cur->req) destroy_request(cur->req);
  if (cur->res) destroy_response(cur->res);

  ck_free(cur->name);

  if (cur->try_cnt) {
    for (i=0;i<cur->try_cnt;i++) ck_free(cur->try_list[i]);
    ck_free(cur->try_list);
  }

  if (cur->issue) {
    for (i=0;i<cur->issue_cnt;i++) {
      ck_free(cur->issue[i].extra);
      if (cur->issue[i].req) destroy_request(cur->issue[i].req);
      if (cur->issue[i].res) destroy_response(cur->issue[i].res);
    }
    ck_free(cur->issue);
  }

  for (i=0;i<cur->child_cnt;i++)
    dealloc_pivots(cur->child[i]);

  ck_free(cur->child);

  if (cur != &root_pivot) ck_free(cur);

}


/* Creates a new XSS location tag. */

u8* new_xss_tag(u8* prefix) {
  static u8* ret;

  if (ret) __DFL_ck_free(ret);
  ret = __DFL_ck_alloc((prefix ? strlen((char*)prefix) : 0) + 32);

  if (!scan_id) scan_id = R(999999) + 1;

  sprintf((char*)ret, "%s-->\">'>'\"<sfi%06uv%06u>",
          prefix ? prefix : (u8*)"", cur_xss_id, scan_id);

  return ret;

}


/* Registers last XSS tag along with a completed http_request */

void register_xss_tag(struct http_request* req) {
  xss_req = ck_realloc(xss_req, (cur_xss_id + 1) *
                       (sizeof(struct http_request*)));
  xss_req[cur_xss_id] = req_copy(req, 0, 1);
  cur_xss_id++;
}


/* Gets the request that submitted the tag in the first place */

struct http_request* get_xss_request(u32 xid, u32 sid) {
  if (sid != scan_id || xid >= cur_xss_id) return NULL;
  return xss_req[xid];
}


/* Cleans up other database entries, for memory profiling purposes. */

void destroy_database() {
  u32 i, kh;

  dealloc_pivots(0);

  ck_free(deny_urls);
  ck_free(allow_urls);
  ck_free(allow_domains);
  ck_free(trust_domains);

  ck_free(addl_form_name);
  ck_free(addl_form_value);
  ck_free(skip_params);

  for (kh=0;kh<WORD_HASH;kh++) {
    for (i=0;i<keyword_cnt[kh];i++) ck_free(keyword[kh][i].word);
    ck_free(keyword[kh]);
  }

  /* Extensions just referenced keyword[][] entries. */
  ck_free(wg_extension);
  ck_free(ws_extension);

  for (i=0;i<guess_cnt;i++) ck_free(guess[i]);
  ck_free(guess);

  for (i=0;i<cur_xss_id;i++) destroy_request(xss_req[i]);
  ck_free(xss_req);

}
