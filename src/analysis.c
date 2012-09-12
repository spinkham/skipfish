/*
   skipfish - content analysis
   ---------------------------

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

#define _VIA_ANALYSIS_C

#include "debug.h"
#include "config.h"
#include "types.h"
#include "http_client.h"
#include "database.h"
#include "crawler.h"
#include "analysis.h"
#include "signatures.h"
#include "pcre.h"

u8  no_parse,            /* Disable HTML link detection */
    warn_mixed,          /* Warn on mixed content       */
    log_ext_urls,        /* Log all external URLs       */
    no_forms,            /* Do not submit forms         */
    pedantic_cache,      /* Match HTTP/1.0 and HTTP/1.1 */
    no_checks;           /* No checks / crawl only mode */

/* Form autofill hints: */

u8** addl_form_name;
u8** addl_form_value;
u32  addl_form_cnt;


/* Runs some rudimentary checks on top-level pivot HTTP responses. */

void pivot_header_checks(struct http_request* req,
                         struct http_response* res) {

  u32 i;
  u8 *par_hdr, *cur_hdr;

  DEBUG_CALLBACK(req, res);

  /* Server: change. */

  cur_hdr = GET_HDR((u8*)"Server", &res->hdr);
  if (!RPAR(req)->res) par_hdr = NULL;
  else par_hdr = GET_HDR((u8*)"Server", &RPAR(req)->res->hdr);

  if (!cur_hdr) cur_hdr = (u8*)"[none]";
  if (!par_hdr) par_hdr = (u8*)"[none]";

  if (strcmp((char*)cur_hdr, (char*)par_hdr))
    problem(PROB_SERVER_CHANGE, req, res, cur_hdr, req->pivot, 0);

  /* Via: appears or disappears. */

  cur_hdr = GET_HDR((u8*)"Via", &res->hdr);
  if (!RPAR(req)->res) par_hdr = NULL;
  else par_hdr = GET_HDR((u8*)"Via", &RPAR(req)->res->hdr);

  if (cur_hdr != par_hdr)
    problem(PROB_VIA_CHANGE, req, res, cur_hdr ? cur_hdr : (u8*)"[none]",
            req->pivot, 0);

  /* New X-* header appears. */

  for (i=0;i<res->hdr.c;i++) {

    if (res->hdr.t[i] != PARAM_HEADER ||
        case_prefix(res->hdr.n[i], "X-")) continue;

    if (!RPAR(req)->res) par_hdr = NULL;
    else par_hdr = GET_HDR(res->hdr.n[i], &RPAR(req)->res->hdr);

    if (!par_hdr)
      problem(PROB_X_CHANGE, req, res, res->hdr.n[i], req->pivot,0);

  }

  /* Old X-* header disappears. */

  if (RPAR(req)->res)
    for (i=0;i<RPAR(req)->res->hdr.c;i++) {

      if (RPAR(req)->res->hdr.t[i] != PARAM_HEADER ||
          case_prefix(RPAR(req)->res->hdr.n[i], "X-")) continue;

      cur_hdr = GET_HDR(RPAR(req)->res->hdr.n[i], &res->hdr);

      if (!cur_hdr)
        problem(PROB_X_CHANGE, req, res, RPAR(req)->res->hdr.n[i], req->pivot, 0);

    }

}


/* Helper for scrape_response(). Tries to add a previously extracted link,
   also checks for cross-site and mixed content issues and similar woes.
   Subres is: 1 - redirect; 2 - IMG; 3 - IFRAME, EMBED, OBJECT, APPLET;
   4 - SCRIPT, LINK REL=STYLESHEET; 5 - form; 0 - everything else. */

static void test_add_link(u8* str, struct http_request* ref,
                          struct http_response* res, u8 subres, u8 sure) {
  struct http_request* n;

  DEBUG_CALLBACK(ref,res);
  DEBUG("* Alleged URL = '%s' [%u]\n", str, subres);

  /* Don't add injected links. */

  if (!case_prefix(str, "skipfish:") ||
      !case_prefix(str, "//skipfish.invalid/") ||
      inl_strcasestr(str, (u8*) "/" BOGUS_FILE) ||
      !case_prefix(str, "http://skipfish.invalid/")) return;

  /* Don't add links that look like they came from JS code with fragmented HTML
     snippets, etc. */

  if (!sure && (strchr("!()\"' +,^:", *str) ||
     (*str == '/' && strchr("()\"' +,^", str[1])))) return;

  if ((str[0] == '\'' || str[0] == '"') && (str[1] == '+' || str[1] == ' '))
    return;

  if (!case_prefix(str, "mailto:")) {

    if (log_ext_urls) {
      u8* qmark = (u8*)strchr((char*)str, '?');
      if (qmark) *qmark = 0;
      problem(PROB_MAIL_ADDR, ref, res, str + 7, host_pivot(ref->pivot),0);
      if (qmark) *qmark = '?';
    }

    return;
  }

  n = ck_alloc(sizeof(struct http_request));

  n->pivot = ref->pivot;

  if (!parse_url(str, n, ref)) {

    if (R(100) < crawl_prob) maybe_add_pivot(n, NULL, sure ? 2 : 1);

    /* Link to a third-party site? */

    if (!url_allowed_host(n) && !url_trusted_host(n))
      switch (subres) {

        case 0:
          if (log_ext_urls)
            problem(PROB_EXT_LINK, ref, res, str, host_pivot(ref->pivot), 0);
          break;

        case 1:
          if (log_ext_urls)
            problem(PROB_EXT_REDIR, ref, res, str, ref->pivot, 0);
          break;

        case 2:
        case 3:
          problem(PROB_EXT_OBJ, ref, res, str, ref->pivot, 0);
          break;

        case 4:
          problem(PROB_EXT_SUB, ref, res, str, ref->pivot, 0);
          break;

      }

    /* Mixed content? We don't care about <IMG> or redirectors
       here, though. */

    if (ref->proto == PROTO_HTTPS && n->proto == PROTO_HTTP &&
        subres > 2 && warn_mixed)
      switch (subres) {
        case 4: problem(PROB_MIXED_SUB, ref, res, str, ref->pivot, 0); break;
        case 5: problem(PROB_MIXED_FORM, ref, res, str, ref->pivot, 0); break;
        default: problem(PROB_MIXED_OBJ, ref, res, str, ref->pivot, 0);
      }

  } else if (!ref->proto) {

    /* Parser didn't recognize the protocol. If it's a
       hierarchical URL (foo://), log it. */

    u8* x = str;

    while (isalnum(*x)) x++;

    if (str != x && *x == ':' && x[1] == '/')
      problem(PROB_UNKNOWN_PROTO, ref, res, str, ref->pivot, 0);

  }

  destroy_request(n);
}


/* Another scrape_response() helper - decodes HTML escaping,
   maybe also JS escaping, from URLs. Returns a dynamically
   allocated copy. */

static u8* html_decode_param(u8* url, u8 also_js) {
  u32 len = strlen((char*)url);
  u8* ret = ck_alloc(len + 1);
  u32 i, pos = 0;

  /* If directed to do so, decode \x, \u, and \char sequences
     first. */

  if (also_js) {

    for (i=0;i<len;i++) {

      if (url[i] == '\\') {
        u32 act_val = 0;

        if (url[i+1] == 'x') {
          sscanf((char*)url + i + 2, "%2x", &act_val);
          i += 3;
        } else if (url[i+1] == 'u') {
          sscanf((char*)url + i + 2, "%4x", &act_val);
          i += 5;
        } else {
          act_val = url[i+1];
          i += 1;
        }

        if (!act_val || act_val > 0xff) act_val = '?';

        ret[pos++] = act_val;

      } else ret[pos++] = url[i];

    }

    ret[pos] = 0;
    url = ret;
    len = pos;
    pos = 0;
    ret = ck_alloc(len + 1);

  }

  /* Next, do old-school HTML decoding. There are many other named
     entities, of course, but the odds of them appearing in URLs
     without %-encoding are negligible. */

  for (i=0;i<len;i++) {

    if (url[i] == '&') {

      if (!case_prefix(url + i + 1, "amp;")) {
        ret[pos++] = '&';
        i += 4;
        continue;
      } else if (!case_prefix(url + i + 1, "quot;")) {
        ret[pos++] = '\'';
        i += 5;
        continue;
      } else if (!case_prefix(url + i + 1, "lt;")) {
        ret[pos++] = '<';
        i += 3;
        continue;
      } else if (!case_prefix(url + i + 1, "gt;")) {
        ret[pos++] = '>';
        i += 3;
        continue;
      } else if (url[i+1] == '#') {
        u32 act_val = 0;
        u8 semicol = 0;

        if (url[i+2] == 'x')
          sscanf((char*)url + i + 3, "%x%c", &act_val, &semicol);
        else sscanf((char*)url + i + 2, "%u%c", &act_val, &semicol);

        if (semicol == ';') {
          if (!act_val || act_val > 0xff) act_val = '?';
          ret[pos++] = act_val;
          i += strcspn((char*)url + i, ";");
          continue;
        }

        /* Fall through and output the sequence as-is. */

      }

    } else if (url[i] == '\r' || url[i] == '\n') continue;

    ret[pos++] = url[i];

  }

  ret[pos] = 0;
  if (also_js) ck_free(url);

  return ret;

}


/* Macro to test for tag names */

#define ISTAG(_val, _tag) \
  (!strncasecmp((char*)(_val), _tag, strlen((char*)(_tag))) && \
  (isspace((_val)[strlen((char*)_tag)]) || !(_val)[strlen((char*)_tag)]))

/* Macro to find and move past parameter name (saves result in
   _store, NULL if not found). Buffer needs to be NUL-terminated
   at nearest >. */

#define FIND_AND_MOVE(_store, _val, _param) { \
    (_store) = inl_strcasestr((u8*)_val, (u8*)_param); \
    if (_store) { \
      if (!isspace((_store)[-1])) (_store) = NULL; \
      else (_store) += strlen((char*)_param); \
    } \
 } while (0)

/* Macro to extract parameter value, handling quotes. */

#define EXTRACT_ALLOC_VAL(_store, _val) do { \
    u32 _val_len; \
    if (*(_val) == '\'') _val_len = strcspn((char*)++(_val), "'"); else \
    if (*(_val) == '"') _val_len = strcspn((char*)++(_val), "\""); else \
      _val_len = strcspn((char*)(_val), "> \t\r\n"); \
    (_store) = ck_memdup((_val), (_val_len) + 1); \
    (_store)[(_val_len)] = 0; \
  } while (0)


/* Adds a new item to the form hint system. */

void add_form_hint(u8* name, u8* value) {
  addl_form_name = ck_realloc(addl_form_name,
                             (addl_form_cnt + 1) * sizeof(u8*));

  addl_form_value = ck_realloc(addl_form_value,
                              (addl_form_cnt + 1) * sizeof(u8*));

  addl_form_name[addl_form_cnt] = name;
  addl_form_value[addl_form_cnt] = value;
  addl_form_cnt++;

}


/* Helper for collect_form_data() - comes up with a fitting value for
   a checkbox. Returns a static buffer. */

static u8* make_up_form_value(u8* name, struct http_request* req,
                              struct http_response* res) {
  u32 i;

  for (i=0;i<addl_form_cnt;i++)
    if (inl_strcasestr(name, addl_form_name[i]))
      return addl_form_value[i];

  i = 0;

  while (form_suggestion[i][0]) {
    if (inl_strcasestr(name, (u8*)form_suggestion[i][0]))
      return (u8*)form_suggestion[i][1];
    i++;
  }

  /* Let's hint we have no clue what to do. */

  problem(PROB_UNKNOWN_FIELD, req, res, name, host_pivot(req->pivot), 0);

  return (u8*)form_suggestion[i][1];

}


/* Helper for collect_form_data() - checks for probable anti-XSRF token
   values. */

static u8 maybe_xsrf(u8* token) {
  u8* tmp;
  u32 digit_cnt = 0, upper_cnt = 0, slash_cnt = 0;;
  static u8 tm_prefix[8];

  if (!tm_prefix[0])
    sprintf((char*)tm_prefix, "%lu", (long int)(time(0) / 100000));

  /* Unix time is not a valid token. */

  if (!case_prefix(token, tm_prefix)) return 0;

  tmp = token;
  while (*tmp && (isdigit(*tmp) || strchr("abcdef", tolower(*tmp)))) {
    if (isdigit(*tmp)) digit_cnt++;
    tmp++;
  }

  /* Looks like base 10 or 16... */

  if (!*tmp) {
    u32 len = tmp - token;
    if (len >= XSRF_B16_MIN && len <= XSRF_B16_MAX && digit_cnt >= XSRF_B16_NUM)
      return 1;
    return 0;
  }

  digit_cnt = 0;
  tmp = token;
  while (*tmp && (isalnum(*tmp) || strchr("=+/", *tmp))) {
    if (isdigit(*tmp)) digit_cnt++;
    if (isupper(*tmp)) upper_cnt++;
    if (*tmp == '/') slash_cnt++;
    tmp++;
  }

  /* Looks like base 32 or 64... */

  if (!*tmp) {
    u32 len = tmp - token;
    if (len >= XSRF_B64_MIN && len <= XSRF_B64_MAX && ((digit_cnt >=
        XSRF_B64_NUM && upper_cnt >= XSRF_B64_CASE) || digit_cnt >=
        XSRF_B64_NUM2) && slash_cnt <= XSRF_B64_SLASH) return 1;
    return 0;
  }

  /* Looks like... not a numerical token at all. */

  return 0;

}


/* Another helper for scrape_response(): examines all <input> tags
   up until </form>, then adds them as parameters to current request. */

void collect_form_data(struct http_request* req,
                       struct http_request* orig_req,
                       struct http_response* orig_res,
                       u8* cur_str, u8 is_post) {

  u8  has_xsrf = 0, pass_form = 0, file_form = 0;
  u32 tag_cnt = 0;

  DEBUG("* collect_form_data() entered\n");

  do {

    u8* tag_end;

    if (*cur_str == '<' && (tag_end = (u8*)strchr((char*)cur_str + 1, '>'))) {

      cur_str++;
      *tag_end = 0;

      if (!case_prefix(cur_str, "/form")) {
        *tag_end = '>';
        goto final_checks;
      }

      if (ISTAG(cur_str, "input") || ISTAG(cur_str, "textarea") ||
          ISTAG(cur_str, "select") || ISTAG(cur_str, "button")) {

        u8 *tag_name, *tag_value, *tag_type, *clean_name = NULL,
           *clean_value = NULL;

        FIND_AND_MOVE(tag_name, cur_str, "name=");
        FIND_AND_MOVE(tag_value, cur_str, "value=");
        FIND_AND_MOVE(tag_type, cur_str, "type=");

        if (!tag_name) goto next_tag;

        EXTRACT_ALLOC_VAL(tag_name, tag_name);
        clean_name = html_decode_param(tag_name, 0);
        ck_free(tag_name);
        tag_name = 0;

        if (tag_value) {
          EXTRACT_ALLOC_VAL(tag_value, tag_value);
          clean_value = html_decode_param(tag_value, 0);
          ck_free(tag_value);
          tag_value = 0;
        }

        if (tag_type)
          EXTRACT_ALLOC_VAL(tag_type, tag_type);
        else tag_type = ck_strdup((u8*)"text");

        tag_cnt++;

        if (!strcasecmp((char*)tag_type, "file")) {

          if (!is_post) {
            ck_free(req->method);
            req->method = ck_strdup((u8*)"POST");
            is_post = 1;
          }

          set_value(PARAM_POST_F, clean_name, clean_value ?
                    clean_value : (u8*)"", 0, &req->par);

        } else if (!strcasecmp((char*)tag_type, "reset")) {

          /* Do nothing - do not store. */
          tag_cnt--;

        } else if (!strcasecmp((char*)tag_type, "button") ||
                   !strcasecmp((char*)tag_type, "submit")) {

          set_value(is_post ? PARAM_POST : PARAM_QUERY, clean_name,
                    clean_value ? clean_value : (u8*)"", 0, &req->par);

        } else if (!strcasecmp((char*)tag_type, "checkbox")) {

          /* Turn checkboxes on. */

          set_value(is_post ? PARAM_POST : PARAM_QUERY, clean_name,
                    (u8*)"on", 0, &req->par);

        } else {

          u8* use_value = clean_value;

          /* Don't second-guess hidden fields. */

          if (strcasecmp((char*)tag_type, "hidden") &&
              (!use_value || !use_value[0])) {
            use_value = make_up_form_value(clean_name, orig_req, orig_res);
          } else {
            if (!use_value) use_value = (u8*)"";
          }

          /* Radio buttons are rolled back into a single parameter
             because we always replace offset 0 for given clean_name. */

          set_value(is_post ? PARAM_POST : PARAM_QUERY,
                    clean_name, use_value, 0, &req->par);

          if (!strcasecmp((char*)tag_type, "hidden") &&
              maybe_xsrf(use_value)) has_xsrf = 1;

        }

        if (!strcasecmp((char*)tag_type, "password") ||
            inl_strcasestr(tag_name, (u8*) "passw")) pass_form = 1;
        else if (!strcasecmp((char*)tag_type, "file")) file_form = 1;

        ck_free(tag_name);
        ck_free(tag_type);
        ck_free(tag_value);
        ck_free(clean_name);
        ck_free(clean_value);

      }

next_tag:

      *tag_end = '>';

    } else tag_end = cur_str;

    /* Skip to next tag. */

    cur_str = (u8*)strchr((char*)tag_end + 1, '<');

  } while (cur_str);

final_checks:

  if (pass_form) {

    if (warn_mixed && (req->proto != PROTO_HTTPS || orig_req->proto != PROTO_HTTPS)) 
      problem(PROB_PASS_NOSSL, req, orig_res, NULL, req->pivot, 0);
    else
      problem(PROB_PASS_FORM, req, orig_res, NULL, req->pivot, 0);

  } else {

    if (tag_cnt && !has_xsrf) {
      if (file_form)
        problem(PROB_FILE_FORM, req, orig_res, NULL, req->pivot, 0);
      problem(PROB_VULN_FORM, req, orig_res, NULL, req->pivot, 0);
    } else {
      if (file_form)
        problem(PROB_FILE_FORM, req, orig_res, NULL, req->pivot, 0);
      else
        problem(PROB_FORM, req, orig_res, NULL, req->pivot, 0);
    }
  }

}


/* Helper for scrape_response() and content_checks: is the
   file mostly ASCII? */

static u8 is_mostly_ascii(struct http_response* res) {
  u32 i, total, printable = 0;

  if (res->doc_type) return (res->doc_type == 2);

  total = (res->pay_len > 128) ? 128 : res->pay_len;

  if (!total) { res->doc_type = 2; return 1; }

  for (i=0;i<total;i++)
    if ((res->payload[i] >= 0x20 && res->payload[i] <= 0x7f)
        || (res->payload[i] && strchr("\t\r\n", res->payload[i])))
      printable++;

  if (printable * 100 / total < 90) {
    DEBUG("* looks like binary data (print = %u, total = %u)\n",
          printable, total);
    res->doc_type = 1;
    return 1;
  }

  DEBUG("* looks like text file (print = %u, total = %u)\n",
        printable, total);

  res->doc_type = 2;
  return 1;

}



struct http_request* make_form_req(struct http_request *req,
                                   struct http_request *base,
                                   u8* cur_str, u8* target) {

  u8 *method, *clean_url;
  u8 *dirty_url;
  struct http_request* n;
  u8 parse_form = 1;

  FIND_AND_MOVE(dirty_url, cur_str, "action=");
  FIND_AND_MOVE(method, cur_str, "method=");

  /* See if we need to POST this form or not. */

  if (method && *method) {
    if (strchr("\"'", *method)) method++;
    if (tolower(method[0]) == 'p') parse_form = 2;
  }

  /* If a form target is specified, we need to use that */

  if (target) {
    dirty_url = ck_strdup(target);
  } else if (!dirty_url || !*dirty_url || !prefix(dirty_url, "\"\"") ||
             !prefix(dirty_url, "''")) {

    /* Forms with no URL submit to current location. */
    dirty_url = serialize_path(req, 1, 0);
  } else {
    /* Last, extract the URL from the tag */
    EXTRACT_ALLOC_VAL(dirty_url, dirty_url);
  }

  clean_url = html_decode_param(dirty_url, 0);
  ck_free(dirty_url);

  n = ck_alloc(sizeof(struct http_request));

  n->pivot = req->pivot;
  if (parse_form == 2) {
    ck_free(n->method);
    n->method = ck_strdup((u8*)"POST");
  } else {
    /* On GET forms, strip existing query params to get a submission
       target. */
    u8* qmark = (u8*)strchr((char*)clean_url, '?');
    if (qmark) *qmark = 0;
  }

  if (parse_url(clean_url, n, base ? base : req)) {
    DEBUG("Unable to parse_url from form: %s\n", clean_url);
    ck_free(clean_url);
    destroy_request(n);
    return NULL;
  }

  ck_free(clean_url);
  return n;

}


/* Analyzes response headers (Location, etc), body to extract new links,
   keyword guesses. This code is designed to be simple and fast, but it
   does not even try to understand the intricacies of HTML or whatever
   the response might be wrapped in. */

void scrape_response(struct http_request* req, struct http_response* res) {

  struct http_request *base = NULL;
  u8* cur_str;
  u32 i;

  DEBUG_CALLBACK(req, res);

  if (no_parse || res->scraped) return;

  res->scraped = 1;

  /* Do not scrape pages that are identical to their parent, or are parented
     by suspicious locations. */

  if (RPAR(req)->res && (same_page(&res->sig, &RPAR(req)->res->sig) ||
      RPAR(req)->bad_parent)) {
    DEBUG("* Not extracting links because page looks the same as parent.\n");
    return;
  }

  /* Handle Location, Refresh headers first. */

  if ((cur_str = GET_HDR((u8*)"Location", &res->hdr)))
    test_add_link(cur_str, req, res, 1, 1);

  if ((cur_str = GET_HDR((u8*)"Refresh", &res->hdr)) &&
      (cur_str = (u8*)strchr((char*)cur_str, '=')))
    test_add_link(cur_str + 1, req, res, 1, 1);

  if (!res->payload || !is_mostly_ascii(res)) return;

  cur_str = res->payload;

  /* PASS 1: Do a simplified check to what looks like proper,
     known HTML parameters bearing URLs. Note that payload is
     conveniently NUL-terminated. */

  do {

    u8 *tag_end;

    if (*cur_str == '<' && (tag_end = (u8*)strchr((char*)cur_str + 1, '>'))) {

      u32 link_type = 0;
      u8  set_base = 0;
      u8  is_post = 0;
      u8  *dirty_url = NULL, *clean_url = NULL, *meta_url = NULL,
          *delete_dirty = NULL;

      cur_str++;
      *tag_end = 0;

      /* Several tags we need to handle specially, either because they
         denote a particularly interesting content type (marked in
         link_type, see test_add_link()), or because they use a
         non-standard parameter for URL data. */

      if (ISTAG(cur_str, "meta")) {

        link_type = 1;
        FIND_AND_MOVE(dirty_url, cur_str, "content=");

        if (dirty_url) {
          EXTRACT_ALLOC_VAL(meta_url, dirty_url);
          dirty_url = inl_strcasestr(meta_url, (u8*)"URL=");
          if (dirty_url) dirty_url += 4;
        }

      } else if (ISTAG(cur_str, "img")) {

        link_type = 2;
        FIND_AND_MOVE(dirty_url, cur_str, "src=");

      } else if (ISTAG(cur_str, "object") || ISTAG(cur_str, "embed") ||
               ISTAG(cur_str, "applet") || ISTAG(cur_str, "iframe") ||
               ISTAG(cur_str, "frame")) {

        link_type = 3;
        FIND_AND_MOVE(dirty_url, cur_str, "src=");
        if (!dirty_url) FIND_AND_MOVE(dirty_url, cur_str, "codebase=");

      } else if (ISTAG(cur_str, "param") && inl_strcasestr(cur_str,
                 (u8*)"movie")) {

        link_type = 3;
        FIND_AND_MOVE(dirty_url, cur_str, "value=");

      } else if (ISTAG(cur_str, "script")) {

        link_type = 4;
        FIND_AND_MOVE(dirty_url, cur_str, "src=");

      } else if (ISTAG(cur_str, "link") && inl_strcasestr(cur_str,
                 (u8*)"stylesheet")) {

        link_type = 4;
        FIND_AND_MOVE(dirty_url, cur_str, "href=");

      } else if (ISTAG(cur_str, "base")) {

        set_base = 1;
        FIND_AND_MOVE(dirty_url, cur_str, "href=");

      } else if (ISTAG(cur_str, "form")) {

        /* Parse the form and kick off a new pivot for further testing */
        struct http_request* n = make_form_req(req, base, cur_str, NULL);
        if (n) {
          if (url_allowed(n) && R(100) < crawl_prob && !no_forms) {
            is_post = (n->method && !strcmp((char*)n->method, "POST"));

            collect_form_data(n, req, res, tag_end + 1, is_post);
            maybe_add_pivot(n, NULL, 5);
          }
          destroy_request(n);
        }

      } else {

        /* All other tags - other <link> types, <a>, <bgsound> -
           are handled in a generic way. */

        FIND_AND_MOVE(dirty_url, cur_str, "href=");
        if (!dirty_url) FIND_AND_MOVE(dirty_url, cur_str, "src=");

      }

      /* If we found no URL to speak of, we're done. */

      if (!dirty_url) {
        ck_free(meta_url);
        goto next_tag;
      }

      /* De-quotify and decode the value. */

      EXTRACT_ALLOC_VAL(dirty_url, dirty_url);
      clean_url = html_decode_param(dirty_url, 0);
      ck_free(dirty_url);
      ck_free(delete_dirty);
      ck_free(meta_url);

      if (!*clean_url) goto next_tag;

      test_add_link(clean_url, base ? base : req, res, link_type, 1);

      /* If we are dealing with a <base> tag, we need to create
         a new dummy request to use as a referrer. */

      if (set_base) {

        struct http_request* n = ck_alloc(sizeof(struct http_request));
        n->pivot = req->pivot;
        if (!parse_url(clean_url, n, base ? base : req)) base = n;

      }

next_tag:

      *tag_end = '>';

      if (clean_url) ck_free(clean_url);

    } else tag_end = cur_str;

    /* Skip to next tag. */

    if (*tag_end) cur_str = (u8*)strchr((char*)tag_end + 1, '<');
      else cur_str = 0;

  } while (cur_str);

  cur_str = res->payload;

  /* PASS 2: Extract links from non-HTML body, JS, etc; add keywords. */

  do {

    u32 clean_len, alpha_cnt = 0, lower_cnt = 0, lead = 0, seg_len;
    u8  *ext, *token, *clean_url, *tmp, *pos_at;
    u8  last = 0, saved;

    /* Skip leading whitespaces, terminators. */

    seg_len = strspn((char*)cur_str, " \t\r\n<>\"'");
    cur_str += seg_len;

    /* If there's a = character preceeded only by alnums or underscores,
       skip this chunk (to handle something=http://www.example.com/ neatly) */

    tmp = cur_str;
    while (*tmp && (isalnum(*tmp) || *tmp == '_')) tmp++;
    if (*tmp == '=') cur_str = tmp + 1;

    if (!*cur_str) break;
    seg_len = strcspn((char*)cur_str + 1, " \t\r\n<>\"'") + 1;

    /* Extract the segment, decoding JS and HTML on the go. */

    saved            = cur_str[seg_len];
    cur_str[seg_len] = 0;
    clean_url        = html_decode_param(cur_str, 1);
    cur_str[seg_len] = saved;

    tmp = clean_url;

    /* We want the entire extracted segment to consist only of nice
       characters we would expect in a URL. If not, panic. */

    while (*tmp) {
      if (!isalnum(*tmp) && !isspace(*tmp) &&
          !strchr("_-.:@/?&=#%;$!+~()[]{}\\|^*", *tmp)) goto url_done;
      tmp++;
    }

    clean_len = tmp - clean_url;

    /* Strip trailing characters that are unlikely to appear in valid URLs
       anyway, and could be a part of some message. */

    while (clean_len &&
           strchr(".,:?!-$&", clean_url[clean_len-1])) clean_len--;

    clean_url[clean_len] = 0;

    /* URL CHECK 1: Things that start with ./ or ../ are obviously URLs.
       We do not make assumptins about syntax such as /foo/, though, as
       it could very well be a regex in a JS block. */

    if (!prefix(clean_url, "./") || !prefix(clean_url, "../")) {
add_link:
      test_add_link(clean_url, base ? base : req, res, 0, 0);
      goto url_done;
    }

    /* URL CHECK 2: Things that start with <alnum>://<str> are quite
       clearly URLs. */

    while (clean_url[lead] && (isalnum(clean_url[lead]))) lead++;

    if (lead && !prefix(clean_url + lead, "://") &&
        clean_url[lead + 3]) goto add_link;

    /* URL CHECK 3: If the result ends with <str>.<known_ext>,
       and contains a slash anywhere, assume URL (without that
       slash check, we would get duped by 'domain.com'. */

    if (strchr((char*)clean_url, '/')) {

      i = 0;

      while ((ext = wordlist_get_extension(i++, 0))) {
        u32 ext_len = strlen((char*)ext);

        if (clean_len > ext_len + 2 &&
            !strncasecmp((char*)clean_url + clean_len - ext_len,
                         (char*)ext, ext_len) &&
            clean_url[clean_len - ext_len - 1] == '.') goto add_link;

      }

    }

    if (!(pos_at = (u8*)strchr((char*)clean_url, '@'))) {

      /* URL CHECK 4: ?<str>=<str> syntax is strongly indicative of
         an URL (only if not e-mail). */

      u8 *pos_qmark = (u8*)strchr((char*)clean_url, '?'),
         *pos_eq    = (u8*)strchr((char*)clean_url, '='),
         *pos_amp   = (u8*)strchr((char*)clean_url, '&');

      if (pos_qmark && pos_eq && pos_qmark + 1 < pos_eq && 
          pos_eq[1] && (!pos_amp || pos_amp > pos_eq) && 
          pos_eq[1] != '=' && !strchr((char*)clean_url, '(') &&
          !strchr((char*)clean_url, '[') &&
          (u8*)strchr((char*)clean_url, ':') < pos_eq)
        goto add_link;

    } else if (log_ext_urls) {

      /* EMAIL CHECK: If the string uses a limited set of characters,
         starts with alpha, ahs at least one period after @, and both
         @ and the period are immediately followed by alpha - assume
         e-mail. */

      u8 *pos_dot,
         *pos_qmark = (u8*)strchr((char*)clean_url, '?');

      if (pos_qmark && pos_qmark > pos_at) *pos_qmark = 0;

      lead = 0;

      while (clean_url[lead] && (isalnum(clean_url[lead]) ||
             strchr("._-+@", clean_url[lead]))) lead++;

      pos_dot = (u8*)strchr((char*)pos_at + 1, '.');

      if (!clean_url[lead] && pos_at && pos_dot && isalpha(clean_url[0]) &&
          isalpha(pos_at[1]) && isalpha(pos_dot[1])) {
        problem(PROB_MAIL_ADDR, req, res, clean_url, host_pivot(req->pivot), 0);
        goto url_done;
      }

    }

    /* LAST CHANCE: Try to detect base64; if the segment does not look like
       base64, add each segment to try_list. */

    tmp = clean_url;

    while (*tmp) {
      if (isalpha(*tmp)) {
        alpha_cnt++;
        if (islower(*tmp)) lower_cnt++;
      }
      tmp++;
    }

    if (alpha_cnt > 20 && (lower_cnt * 100 / alpha_cnt) > 35 &&
        (lower_cnt * 100 / alpha_cnt) < 65) goto url_done;

    token = clean_url;

    do {
      while (*token && !isalnum(*token)) token++;
      tmp = token;
      while (*tmp && isalnum(*tmp)) tmp++;
      if (!*tmp) last = 1;
      *tmp = 0;
      if (R(100) < GUESS_PROB) wordlist_add_guess(token);
      token = tmp + 1;
    } while (!last);

url_done:

    ck_free(clean_url);

    cur_str += seg_len;

  } while (*cur_str);

  if (base) destroy_request(base);

  /* Phew! */

}


/* Returns 1 if document looks like standalone CSS. */

static u8 is_css(struct http_response* res) {
  u8* text = res->payload;
  u8  first = 0, last = 0;

  if (res->css_type) return (res->css_type == 2);
  if (!text || !is_mostly_ascii(res)) return 0;

  do {

    /* Skip whitespaces... */

    while (isspace(*text)) text++;

    /* Skip HTML, CSS comments. */

    if (!prefix(text, "<!--")) {
      text += 4;
      continue;
    }

    if (*text == '/') {
      u8 *end;

      if (text[1] == '/') {
        end = text + strcspn((char*)text, "\r\n");
      } else if (text[1] == '*') {
        end = (u8*)strstr((char*)text + 2, "*/");
        if (end) end += 2;
      } else {
        res->css_type = 1;
        return 0;
      }

      text = end;
      continue;

    }

    /* @import, @media, or @charset is a clear indicator of CSS. */

    if (*text == '@' && (!case_prefix(text + 1, "import") ||
        !case_prefix(text + 1, "media") ||
        !case_prefix(text + 1, "charset"))) {
      res->css_type = 2;
      return 1;
    }

    /* { preceeded with at least one character conforming to the charset
       permitted for CSS selectors, and nothing else, is proof enough. Note
       that we need to handle all the CSS features, e.g.:

       foo, .bar { ... }
       * { ... }
       foo#bar { ... }
       foo[bar~="baz"] { ... }
       foo > bar { ... }

       Joy. */

    if (*text == '{') {

      /* Last non-whitespace before { must conform to a smaller subset that
         does not include =, etc. */

      if (!first || !last ||
          (!isalnum(last) && !strchr("-_]*", last))) {
        res->css_type = 1;
        return 0;
      } else {
        res->css_type = 2;
        return 1;
      }

    }

    if (first) {

      /* Subsequent non-whitespaces can enjoy the whole range of funny
         characters. */

      if (!isalnum(*text) && !strchr(":,.#_-*[]~=\"'>", *text)) {
        res->css_type = 1;
        return 0;
      }

    } else {

      /* First non-whitespace must conform to a narrow set. */

      if (!isalnum(*text) && !strchr(".#_-*", *text)) {
        res->css_type = 1;
        return 0;
      }

      first = 1;

    }

    last = *(text++);

  } while (text && *text);

  /* Reached end without hitting { or @? Not CSS then. */

  res->css_type = 1;
  return 0;

}


/* Returns 1 if document looks like JS / JSON. Note that this makes sense
   only after we ruled CSS via is_css() call. */

static u8 is_javascript(struct http_response* res) {
  u8* text = res->payload;
  u8  first = 0, i = 0;
  u32 white_cnt = 0;

  if (res->js_type) return (res->js_type == 2);
  if (!text || !is_mostly_ascii(res) || is_css(res)) return 0;

  do {

    /* Skip HTML, JS comments. Special case for MOTW. */

    if (!prefix(text, "<!--")) {

      text += 4;

      if (!prefix(text, " saved from url=")) {
        res->js_type = 1;
        return 0;
      }

      continue;
    }

    if (*text == '/') {
      u8 *end;

      if (text[1] == '/') {
        end = text + strcspn((char*)text, "\r\n");
      } else if (text[1] == '*') {
        end = (u8*)strstr((char*)text + 2, "*/");
        if (end) end += 2; else {
          res->js_type = 1;
          return 0;
        }
      } else {
        res->js_type = 1;
        return 0;
      }

      text = end;
      continue;

    }

    /* Known XSSI-busting prefixes imply JavaScript. */

    if (!first)
      while (json_safe[i]) {
        if (!case_prefix(text, json_safe[i])) {
          res->js_type   = 2;
          res->json_safe = 1;
          return 1;
        }
        i++;
      }

    /* Common syntax element that seem convincingly close to JS. */

    if (strchr("({[\"'", *text) || (first && strchr("=;", *text))) {
      res->js_type = 2;
      return 1;
    }

    /* Illegal identifier, or too many whitespaces? Bail out. */

    if (!isalnum(*text) && (!strchr(" \t\r\n_.$", *text) ||
        (white_cnt++) > MAX_JS_WHITE)) {
      res->js_type = 1;
      return 0;
    }

    first = 1;
    text++;

  } while (*text);

  res->js_type = 1;
  return 0;

}



/* Checks for XSS, bad coding practices in JavaScript. */

static void check_js_xss(struct http_request* req, struct http_response* res,
                         u8* body) {

  u8* text = body;
  u8  in_quot = 0, prev_space = 1;
  u32 tag_id, scan_id;
  u8* last_word = body;

  if (!text) return;

  do {

    /* Skip comments. */

    if (!in_quot && *text == '/') {
      u8 *end;

      if (text[1] == '/') {
        end = text + strcspn((char*)text, "\r\n");
      } else if (text[1] == '*') {
        end = (u8*)strstr((char*)text + 2, "*/");
        if (end) end += 2;
      } else return;

      text = end;
      continue;

    } else

    if (*text == '\\') { text += 2; continue; } else

    if (!in_quot && (*text == '\'' || *text == '"')) {

      in_quot = *text;

      /* If prev word is write, innerHTML, href, or open,
         and current string starts with //skipfishy thingees,
         complain. */

      if ((!prefix(last_word, "innerHTML") ||
          !prefix(last_word, "open") ||
          !prefix(last_word, "url") ||
          !prefix(last_word, "href") ||
          !prefix(last_word, "write")) &&
          (!case_prefix(text + 1,"//skipfish.invalid/") ||
          !case_prefix(text + 1,"http://skipfish.invalid/") ||
          !case_prefix(text + 1,"skipfish:")))
        problem(PROB_URL_XSS, req, res,
          (u8*)"injected URL in JS/CSS code", req->pivot, 0);

      u8* end_quote = text;
      while(*end_quote && end_quote++ && *end_quote != in_quot)
        if(*end_quote == '\\') end_quote++;

      /* Injected string is 'skip'''"fish""" (or it's encoded variants */
      if(end_quote && (!case_prefix(end_quote + 1,"skip'''") ||
                       !case_prefix(end_quote + 1,"fish\"\"\"")))
        problem(PROB_URL_XSS, req, res, (u8*)"injected string in JS/CSS code (quote escaping issue)", req->pivot, 0);

      if(end_quote && (!prefix(last_word, "on") ||
                       !prefix(last_word, "url") ||
                       !prefix(last_word, "href")) &&
         (!case_prefix(end_quote + 1,"skip&apos;&apos;&apos;") ||
          !case_prefix(end_quote + 1,"skip&#x27;&#x27;&#x27;") ||
          !case_prefix(end_quote + 1,"skip&quot;&quot;&quot;") ||
          !case_prefix(end_quote + 1,"skip&#x22;&#x22;&#x22;"))) {
        problem(PROB_URL_XSS, req, res, (u8*)"injected string in JS/CSS code (html encoded)", req->pivot, 0);

      }

    } else if (in_quot && *text == in_quot) in_quot = 0;

    else if (!in_quot && !case_prefix(text, "sfi") &&
        sscanf((char*)text, "sfi%06uv%06u", &tag_id, &scan_id) == 2) {
      struct http_request* orig = get_xss_request(tag_id, scan_id);

      if (orig)
        problem(PROB_BODY_XSS, orig, res, (u8*)
                "injected syntax in JS/CSS code", req->pivot, 0);
      else
        problem(PROB_BODY_XSS, req, res, (u8*)
                "injected syntax in JS/CSS code (from previous scans)",
                req->pivot, 0);

    } else if (isspace(*text) || *text == '.') prev_space = 1;

    else if (isalnum(*text) && prev_space) {
      last_word  = text;
      prev_space = 0;
    }

    text++;

  } while (text && *text);

}


static void detect_mime(struct http_request*, struct http_response*);
static void check_for_stuff(struct http_request*, struct http_response*);


/* Extracts date from HTTP headers. */

static u64 get_date(u8* str) {
#ifdef LOG_STDERR
  u8* orig = str;
#endif /* LOG_STDERR */
  u8 got_dow = 0;
  s64 month = -1, day = -1, year = -1, hr = -1, min = -1, sec = -1;
 
next_elem:

  if (month != -1 && day != -1 && year != -1 && hr != -1) {
    u64 ret = (sec + (min * 100) + (hr * 10000) +
              (day * 1000000LL) + (month * 100000000LL) +
              (year * 10000000000LL));
    DEBUG("* get_date() '%s' => %llu\n", orig, (long long)ret);
    return ret;
  }

  if (!*str) {
    DEBUG("* get_date() '%s' => FAIL (1)\n", orig);
    return 0;
  }

  /* Skip spaces, commas, dashes. */
  while (*str && strchr(" ,-", *str)) str++;

  /* Skip day of week. */

  if (!got_dow) {
    got_dow = 1;
    while (*str && isalpha(*str)) str++;
    goto next_elem;
  }

  /* Check if next element if a month. */

  if (month == -1 && isalpha(*str)) {

    month = 0;

#define SEL(_a,_b) ((((u32)(_a)) << 8) | (_b))

    switch (SEL(str[1], str[2])) {
      case SEL('e', 'c'): month++;
      case SEL('o', 'v'): month++;
      case SEL('c', 't'): month++;
      case SEL('e', 'p'): month++;
      case SEL('u', 'g'): month++;
      case SEL('u', 'l'): month++;
      case SEL('u', 'n'): month++;
      case SEL('a', 'y'): month++;
      case SEL('p', 'r'): month++;
      case SEL('a', 'r'): month++;
      case SEL('e', 'b'): month++;
      case SEL('a', 'n'): month++;
    }

    while (*str && isalpha(*str)) str++;
    goto next_elem;

  }

  /* Something that starts with a digit should be a day. */

  if (day == -1 && isdigit(*str)) {
    day = atoi((char*)str);
    while (*str && isdigit(*str)) str++;
    goto next_elem;
  }

  /* If we already have a day, the next digit-based thing
     might be time or year. Time would have nn:... */

  if (hr == -1 && isdigit(*str) && str[2] == ':') {
    sscanf((char*)str, "%02llu:%02llu:%02llu", (long long*)&hr,
                                               (long long*)&min,
                                               (long long*)&sec);
    while (*str && (isdigit(*str) || *str == ':')) str++;
    goto next_elem;
  }

  /* And year wouldn't. */

  if (year == -1 && isdigit(*str)) {
    year = atoi((char*)str);
    if (year < 1000) year += 1900; /* 94 -> 1994, 104 -> 2004, 04 -> 1904 */
    if (year < 1970) year += 100;  /* 1994 -> 1994, 2004 -> 2004, 1904 -> 2004 */
    while (*str && isdigit(*str)) str++;
    goto next_elem;
  }

  DEBUG("* get_date() '%s' => FAIL (2)\n", orig);
  return 0;

}


/* Analyzes response headers and body to detect stored XSS, redirection,
   401, 500 codes, exception messages, source code, caching issues, etc. */

u8 content_checks(struct http_request* req, struct http_response* res) {
  u8* tmp;
  u32 off, tag_id, scan_id;
  u8  high_risk = 0;

  DEBUG_CALLBACK(req, res);

  /* CHECK 0: signature matching */
  match_signatures(req, res);


  /* CHECK 1: Caching header logic. */

  if (req->proto == PROTO_HTTP) {

    u8 *exp = GET_HDR((u8*)"Expires", &res->hdr),
       *dat = GET_HDR((u8*)"Date", &res->hdr),
       *prg = GET_HDR((u8*)"Pragma", &res->hdr),
       *cc  = GET_HDR((u8*)"Cache-Control", &res->hdr),
       cacheable = 0;

    u8 h10c = 0, h11c = 0;

    /* Check implicit cacheability. */

    if ((!req->method || !strcmp((char*)req->method, "GET")))
      cacheable = 1;

    /* Determine HTTP/1.0 caching intent. Handle Expires: -1, etc, gracefully.
       Note that 'Expires' without 'Date' may cause problems with Opera,
       so we complain about this in pedantic mode. */

    if (exp) {
      if (!isalpha(exp[0])) {
        h10c = 1;
      } else if (dat) {
        if (get_date(exp) <= get_date(dat)) h10c = 1; else h10c = 2;
      } else if (cacheable && pedantic_cache) {
        problem(PROB_CACHE_LOW, req, res, (u8*)"'Expires' without 'Date'",
                req->pivot, 0);
      }
    }

    /* Check 'Pragma', and complain if there's a conflicting 'Expires'
       intent already detected. */

    if (prg && strstr((char*)prg, "no-cache")) {
      if (h10c == 2)
        problem(res->cookies_set ? PROB_CACHE_HI : PROB_CACHE_LOW, req, res, 
                (u8*)"conflicting 'Expires' and 'Pragma'", req->pivot, 0);
      h10c = 1;
    }

    /* Check HTTP/1.1 intent next. Detect conflicting keywords. */

    if (cc) {

      if (strstr((char*)cc, "no-cache") || strstr((char*)cc, "no-store") ||
          strstr((char*)cc, "private") || strstr((char*)cc, "max-age=0")) {

        h11c = 1;

        if (strstr((char*)cc, "public"))
          problem(res->cookies_set ? PROB_CACHE_HI : PROB_CACHE_LOW, req, res, 
                  (u8*)"conflicting 'Cache-Control' data", req->pivot, 0);

      } else h11c = 2;

    }

    DEBUG("* CACHE: 1.0 intent = %u, 1.1 intent = %u, impl = %u, cookie = %u\n",
          h10c, h11c, cacheable, res->cookies_set);

    /* Perform complex checks against all the data collected: */

    if (res->cookies_set && (h10c == 2 || h11c == 2)) {

      /* Explicit public intent on a cookie-setting response. This is
         obviously bad. */

      problem(PROB_CACHE_HI, req, res, (u8*)
              "caching explicitly permitted on a 'Set-Cookie' response",
              req->pivot, 0);

    } else if (res->cookies_set && !h10c && !h11c && cacheable &&
               (res->code != 302 && res->code != 303 && res->code != 307)) {

      /* Implicitly cacheable Set-Cookie response with no intent specified.
         Likewise, makes us unhappy. Unless the HTTP code is 302, 303 or 307
         in which case implicit caching is forbidden by rfc2616. */

      problem(PROB_CACHE_HI, req, res, (u8*)
              "implicitly cacheable 'Set-Cookie' response",
              req->pivot, 0);

    } else if (h10c && h11c && h10c != h11c) {

      /* Explicit, conflicting HTTP/1.1 and HTTP/1.0 intents are likely
         a problem for many implementations (although earlier checks
         already caught cacheability of sensitive responses). */

      problem(PROB_CACHE_LOW, req, res, (u8*)
              "conflicting 'Cache-Control' and 'Expires' / 'Pragma'",
              req->pivot, 0);

    } else if (pedantic_cache && h11c == 1 && !h10c && cacheable) {

      /* Legacy HTTP/1.0 proxies may fall back to implicit cacheability
         even if HTTP/1.1 intent is specified, but no HTTP/1.0 one.
         Complain about this in pedantic mode. */

      problem(PROB_CACHE_LOW, req, res, (u8*)
              "caching restricted by 'Cache-Control', but not 'Expires'",
              req->pivot, 0);

    }
  }

  /* Check if injection strings ended up in one of our cookie name or
     values and complain */

  u32 i = 0;
  while(injection_headers[i]) {
    off = 0;

    do {
      tmp = GET_HDR_OFF((u8*)injection_headers[i], &res->hdr,off++);
      if(tmp && strstr((char*)tmp, "skipfish://invalid/;"))
        problem(PROB_HEADER_INJECT,req, res,
               (u8*)injection_headers[i], req->pivot, 0);

    } while(tmp);
    i++;
  }

  /* CHECK 2: Log troubling response codes. */

  if (res->code == 401)
    problem(PROB_AUTH_REQ, req, res, NULL, req->pivot, 0);
  else if (res->code >= 500)
    problem(PROB_SERV_ERR, req, res, NULL, req->pivot, 0);

  if (!res->pay_len) return 0;

  if (!is_mostly_ascii(res)) goto binary_checks;

  /* CHECK 3: Parse HTML to detect various XSS issues. We are trying to do
     a much better job parsing HTML than in scrape_page(), because we do not
     want any false positives.

     It is a bit silly to have two separate HTML parsers in the code,
     so we should fix it at some point. */

  /* Full-body CSS / JS responses should be additionally checked for JS
     quoting errors. */

  if (is_javascript(res) || is_css(res)) check_js_xss(req, res, res->payload);

  tmp = res->payload;

  do {

    if (*tmp == '<') {
      u8* tag_name;
      u32 len = strcspn((char*)++tmp, ">= \t\r\n"), space_len;
      u8  remote_script = 0;

      /* Skip comments where possible. */

      if (!prefix(tmp, "!--")) {
        u8* next = (u8*)strstr((char*)tmp + 3, "-->");
        if (next) {
          tmp = next + 3;
          continue;
        }
      }

      /* Grab tag name. */

      tag_name = ck_memdup(tmp, len + 1);
      tag_name[len] = 0;
      tmp += len;

      /* Handle all parameters. */

      while (*tmp && *tmp != '>') {
        u8* param_name;
        u8* clean_val = NULL;
        u8* sfi_pos;

        /* Shoo, whitespaces. */

        space_len = strspn((char*)tmp, " \t\r\n");
        tmp += space_len;

        /* Grab parameter name. */

        len = strcspn((char*)tmp, "=> \t\r\n");
        param_name = ck_memdup(tmp, len + 1);
        param_name[len] = 0;
        tmp += len;

        /* Name followed by '='? Grab value. */

        u8 quote = 0;
        if (*tmp == '=') {
          u32 vlen;
          u8 save;

          tmp++;

          if (*tmp == '\'') {
            quote = 1;
            vlen = strcspn((char*)++tmp, "'");
          } else if (*tmp == '"') {
            quote = 1;
            vlen = strcspn((char*)++tmp, "\"");
          } else vlen = strcspn((char*)tmp, " \t\r\n>");

          save = tmp[vlen];
          tmp[vlen] = 0;
          clean_val = html_decode_param(tmp, 0);
          tmp[vlen] = save;
          tmp += vlen + quote;
        }

        /* CHECK X.X: Unquoted value can allow parameter XSS */
        if (!quote && clean_val && 
            !case_prefix(clean_val, "skipfish:"))
            problem(PROB_TAG_XSS, req, res, tag_name, req->pivot, 0);

        if (!strcasecmp((char*)tag_name, "script") &&
            !strcasecmp((char*)param_name, "src")) remote_script = 1;

        /* CHECK 3.1: URL XSS and redirection issues. */

        if ((!strcasecmp((char*)param_name, "href") ||
            !strcasecmp((char*)param_name, "src") ||
            !strcasecmp((char*)param_name, "action") ||
            (!strcasecmp((char*)param_name, "value") && 
             strcasecmp((char*)tag_name, "input")) ||
            !strcasecmp((char*)param_name, "codebase")) && clean_val) {

          /* Check links with the javascript scheme */
          if (!case_prefix(clean_val, "javascript:") ||
              !case_prefix(clean_val, "vbscript:"))
            check_js_xss(req, res, clean_val);

          if (!case_prefix(clean_val, "skipfish:"))
            problem(PROB_URL_XSS, req, res, tag_name, req->pivot, 0);

          /* A bit hairy, but in essence, links to attacker-supplied
             stylesheets or scripts are super-bad; OBJECTs and IFRAMEs
             are sorta noteworthy, depending on context; and A links
             are usually of little relevance. */

          if (!case_prefix(clean_val, "http://skipfish.invalid/") ||
              !case_prefix(clean_val, "//skipfish.invalid/")) {

            if (!strcasecmp((char*)tag_name, "script") ||
                !strcasecmp((char*)tag_name, "link"))
              problem(PROB_USER_URL_ACT, req, res, tag_name, req->pivot, 0);
            else if (!strcasecmp((char*)tag_name, "a"))
              problem(PROB_USER_LINK, req, res, tag_name, req->pivot, 0);
            else
              problem(PROB_USER_URL, req, res, tag_name, req->pivot, 0);

          }

        }

        /* CHECK 3.2: META REFRESH XSSes, redirection. Also extract
           charset, if available */

        if (!strcasecmp((char*)tag_name, "meta") &&
            !strcasecmp((char*)param_name, "content") && clean_val) {
          u8* url = inl_strcasestr(clean_val, (u8*)"URL=");
          u8  semi_safe = 0;

          if (url) {
            url += 4;
            if (*url == '\'' || *url == '"') { url++; semi_safe = 1; }

            if (!case_prefix(url, "http://skipfish.invalid/") ||
                !case_prefix(url, "//skipfish.invalid/"))
              problem(PROB_URL_REDIR, req, res, (u8*)"injected URL in META refresh",
                      req->pivot, 0);

            /* Unescaped semicolon in Refresh headers is unsafe with MSIE6. */

           if (!case_prefix(url, "skipfish:") ||
               (!semi_safe && strchr((char*)url, ';')))
             problem(PROB_URL_XSS, req, res, (u8*)"injected URL in META refresh",
                     req->pivot, 0);

          } else {
            u8* cset = inl_strcasestr(clean_val, (u8*)"charset=");
            if (cset) {
              if (res->meta_charset) {
                if (strcasecmp((char*)cset+8, (char*)res->meta_charset))
                  res->warn |= WARN_CFL_HDR;
              } else res->meta_charset = ck_strdup(cset + 8);
            }
          }

        }

        /* CHECK 3.3: JavaScript on*=, CSS style= parameters. */

        if ((!case_prefix(param_name, "on") ||
            !strcasecmp((char*)param_name, "style")) && clean_val) 
          check_js_xss(req, res, clean_val);

        /* CHECK 3.4: What looks like our sfi tags, not fully escaped. */

        if ((sfi_pos = (u8*)strstr((char*)param_name, "sfi")) &&
            sscanf((char*)sfi_pos, "sfi%06uv%06u", &tag_id, &scan_id) == 2) {

          struct http_request* orig = get_xss_request(tag_id, scan_id);

          if (orig)
            problem(PROB_BODY_XSS, orig, res, (u8*)
                    "injected 'sfi..' parameter value in a tag",
                    req->pivot,  0);
          else
            problem(PROB_BODY_XSS, req, res, (u8*)
                    "injected 'sfi...' parameter value in a tag (from previous"
                    " scans)", req->pivot, 0);

        }

        ck_free(clean_val);
        ck_free(param_name);

      }

      /* CHECK 3.5: Phew. Parameters analyzed. Let's check for XSS tags... */

      if (sscanf((char*)tag_name, "sfi%06uv%06u", &tag_id, &scan_id) == 2) {
        struct http_request* orig = get_xss_request(tag_id, scan_id);

        if (orig)
          problem(PROB_BODY_XSS, orig, res, (u8*)
                  "injected '<sfi...>' tag seen in HTML", req->pivot, 0);
        else
          problem(PROB_BODY_XSS, req, res, (u8*)
                  "injected '<sfi...>' tag seen in HTML (from previous scans)",
                  req->pivot,  0);
      }

      /* CHECK 3.6: Non-remote SCRIPTs are of interest to JS XSS logic. */

      if (!strcasecmp((char*)tag_name, "script") && !remote_script) {

        u8* next = inl_strcasestr(tmp, (u8*)"</script>");
        if (next) *next = 0;
        check_js_xss(req, res, tmp);
        if (next) *next = '<';
        /* Don't skip right away, as there might be some nested HTML inside. */
      }

      /* CHECK 3.7: ...and so are stylesheets. */

      if (!strcasecmp((char*)tag_name, "style")) {

        u8* next = inl_strcasestr(tmp, (u8*)"</style>");
        if (next) *next = 0;
        check_js_xss(req, res, tmp);
        if (next) *next = '<';

      }

      ck_free(tag_name);

    } else tmp = (u8*)strchr((char*)tmp, '<');

  } while (tmp && *tmp);

  /* CHECK 4: Known exceptions / error pages, etc. */

  detect_mime(req, res);
  res->sniffed_mime = (u8*)mime_map[res->sniff_mime_id][0];

  check_for_stuff(req, res);

binary_checks:

  detect_mime(req, res);
  res->sniffed_mime = (u8*)mime_map[res->sniff_mime_id][0];

  /* No MIME checks on Content-Disposition: attachment responses. */

  if ((tmp = GET_HDR((u8*)"Content-Disposition", &res->hdr)) &&
      inl_strcasestr(tmp, (u8*)"attachment")) return 0;

//  if (!relaxed_mime) {
//
//    /* CHECK 5A: Renderable documents that are not CSS or static JS are of
//       particular interest when it comes to MIME / charset mistakes. */
//
//    if (is_mostly_ascii(res) && !is_css(res) && (!is_javascript(res) ||
//        (!strstr((char*)res->payload, "function ") &&
//        !strstr((char*)res->payload, "function(")))) high_risk = 1;
//
//  } else

  {

    /* CHECK 5B: Documents with skipfish signature strings echoed back
       are of particular interest when it comes to MIME / charset mistakes. */

    u8* tmp = (u8*)strstr((char*)res->payload, "sfi");

    if ((tmp && isdigit(tmp[3]) && tmp[9] == 'v') ||
        strstr((char*)res->payload, "sfish") ||
        strstr((char*)res->payload, "skipfish")) high_risk = 1;

  }

  /* CHECK 6: MIME mismatch? Ignore cases where the response had a valid
     MIME type declared in headers, but we failed to map it to a known
     value... and also failed to sniff.

     Mismatch between MIME_ASC_HTML and MIME_XML_XHTML is not worth
     complaining about; the same about JS or CSS responses being
     sniffed as "unknown ASCII". */

  if (res->sniff_mime_id != res->decl_mime_id &&
      !((res->decl_mime_id == MIME_ASC_JAVASCRIPT ||
         res->decl_mime_id == MIME_ASC_CSS) && 
        res->sniff_mime_id == MIME_ASC_GENERIC) &&
      !(res->decl_mime_id == MIME_ASC_HTML && 
        res->sniff_mime_id == MIME_XML_XHTML) &&
      !(res->decl_mime_id == MIME_XML_XHTML && 
        res->sniff_mime_id == MIME_ASC_HTML) &&
      !(res->header_mime && !res->decl_mime_id &&
        (res->sniff_mime_id == MIME_ASC_GENERIC ||
         res->sniff_mime_id == MIME_BIN_GENERIC)))
    problem(high_risk ? PROB_BAD_MIME_DYN : PROB_BAD_MIME_STAT,
            req, res, res->sniffed_mime, req->pivot, 0);

  /* CHECK 7: application/octet-stream or text/plain; both have
     unintended consequences (but complain only if 3 didn't fire). */

  else if (res->header_mime && (!strcasecmp((char*)res->header_mime,
      "application/octet-stream") || !strcasecmp((char*)res->header_mime,
      "text/plain")))
    problem(high_risk ? PROB_GEN_MIME_DYN : PROB_GEN_MIME_STAT,
            req, res, res->sniffed_mime, req->pivot, 0);

  /* CHECK 8: Missing charset? */

  if (is_mostly_ascii(res) && !res->meta_charset && !res->header_charset)
    problem(high_risk ? PROB_BAD_CSET_DYN : PROB_BAD_CSET_STAT,
            req, res, 0, req->pivot, 0);

  /* CHECK 9: Duplicate, inconsistent C-T or charset? */

  if (is_mostly_ascii(res) && (res->warn & WARN_CFL_HDR || 
      (res->meta_charset && res->header_charset && 
      strcasecmp((char*)res->meta_charset, (char*)res->header_charset))))
    problem(high_risk ? PROB_CFL_HDRS_DYN : PROB_CFL_HDRS_STAT,
            req, res, 0, req->pivot, 0);

  /* CHECK 10: Made up charset? */

  if (res->header_charset || res->meta_charset) {
    u32 i = 0;

    while (valid_charsets[i]) {
      if (!strcasecmp((char*)valid_charsets[i], (char*)(res->header_charset ?
          res->header_charset : res->meta_charset))) break;
      i++;
    }

    if (!valid_charsets[i])
      problem(high_risk ? PROB_BAD_CSET_DYN : PROB_BAD_CSET_STAT,
              req, res, res->header_charset ?
              res->header_charset : res->meta_charset, req->pivot, 0);

  }

  return 0;
}


/* Does MIME detection on a message. Most of this logic is reused from
   ratproxy, with some improvements and additions. */

static void detect_mime(struct http_request* req, struct http_response* res) {
  u8 sniffbuf[SNIFF_LEN];
  s32 fuzzy_match = -1;

  if (res->sniff_mime_id) return;

  /* First, classify declared response MIME, if any. */

  if (res->header_mime) {
    u32 i;

    for (i=0;i<MIME_COUNT;i++) {
      u32 j = 0;

      /* Leading ? means we need to do a prefix match. */

      while (mime_map[i][j]) {
        if (mime_map[i][j][0] == '?') {
          if (!strncasecmp((char*)mime_map[i][j] + 1, (char*)res->header_mime,
               strlen((char*)mime_map[i][j] + 1))) fuzzy_match = i;
        } else {
          if (!strcasecmp((char*)mime_map[i][j], (char*)res->header_mime))
            break;
        }
        j++;
      }

      if (mime_map[i][j]) break;

    }

    if (i != MIME_COUNT) {
      res->decl_mime_id = i;
    } else if (fuzzy_match != -1) {
      res->decl_mime_id = fuzzy_match;
    }
  }

  /* Next, work out the actual MIME that should be set. Mostly
     self-explanatory. */

  memcpy(sniffbuf, res->payload,
         (res->pay_len > SNIFF_LEN - 1) ? (SNIFF_LEN - 1) : res->pay_len);

  sniffbuf[(res->pay_len > SNIFF_LEN - 1) ? (SNIFF_LEN - 1) : res->pay_len] = 0;

  if (is_mostly_ascii(res)) {

    /* ASCII checks. */

    if (is_javascript(res)) {
      res->sniff_mime_id = MIME_ASC_JAVASCRIPT;
      return;
    }

    if (is_css(res)) {
      res->sniff_mime_id = MIME_ASC_CSS;
      return;
    }


    if (!prefix(sniffbuf, "%!PS")) {
      res->sniff_mime_id = MIME_ASC_POSTSCRIPT;
      return;
    }

    if (!prefix(sniffbuf, "{\\rtf")) {
      res->sniff_mime_id = MIME_ASC_RTF;
      return;
    }

    /* Adobe PDF (may be mostly ASCII in some cases). */

    if (!prefix(sniffbuf, "%PDF")) {
      res->sniff_mime_id = MIME_EXT_PDF;
      return;
    }

    /* Several types of XML documents, taking into account that
       they might be missing their xmlns=, etc: */

    if (strstr((char*)sniffbuf, "<OpenSearch")) {
      res->sniff_mime_id = MIME_XML_OPENSEARCH;
      return;
    }

    if (strstr((char*)sniffbuf, "<channel>") ||
        strstr((char*)sniffbuf, "<description>") ||
        strstr((char*)sniffbuf, "<item>") ||
        strstr((char*)sniffbuf, "<rdf:RDF") ||
        strstr((char*)sniffbuf, "<rss")) {
      res->sniff_mime_id = MIME_XML_RSS;
      return;
    }

    if (strstr((char*)sniffbuf, "<feed") ||
        strstr((char*)sniffbuf, "<updated>")) {
      res->sniff_mime_id = MIME_XML_ATOM;
      return;
    }

    if (strstr((char*)sniffbuf, "<wml") ||
        inl_strcasestr(sniffbuf, (u8*)"<!DOCTYPE wml ")) {
      res->sniff_mime_id = MIME_XML_WML;
      return;
    }

    if (strstr((char*)sniffbuf, "<svg")) {
      res->sniff_mime_id = MIME_XML_SVG;
      return;
    }

    if (strstr((char*)sniffbuf, "<cross-domain-policy>")) {
      res->sniff_mime_id = MIME_XML_CROSSDOMAIN;
      return;
    }

    if (strstr((char*)sniffbuf, "<?xml") ||
        strstr((char*)sniffbuf, "<!DOCTYPE")) {

      if (inl_strcasestr(sniffbuf, (u8*)"<!DOCTYPE html") ||
          strstr((char*)sniffbuf, "http://www.w3.org/1999/xhtml"))
        res->sniff_mime_id = MIME_XML_XHTML;
      else
        res->sniff_mime_id = MIME_XML_GENERIC;

      return;

    }

    /* Do an unconvincing check for HTML once we ruled out
       known XML cases. */

    if (inl_strcasestr(sniffbuf, (u8*)"<html") ||
        inl_strcasestr(sniffbuf, (u8*)"<meta") ||
        inl_strcasestr(sniffbuf, (u8*)"<head") ||
        inl_strcasestr(sniffbuf, (u8*)"<title") ||
        inl_strcasestr(sniffbuf, (u8*)"<body") ||
        inl_strcasestr(sniffbuf, (u8*)"</body") ||
        inl_strcasestr(sniffbuf, (u8*)"<!doctype") ||
        inl_strcasestr(sniffbuf, (u8*)"<--") ||
        inl_strcasestr(sniffbuf, (u8*)"<style") ||
        inl_strcasestr(sniffbuf, (u8*)"<script") ||
        inl_strcasestr(sniffbuf, (u8*)"<font") ||
        inl_strcasestr(sniffbuf, (u8*)"<span") ||
        inl_strcasestr(sniffbuf, (u8*)"<div") ||
        inl_strcasestr(sniffbuf, (u8*)"<img") ||
        inl_strcasestr(sniffbuf, (u8*)"<form") ||
        inl_strcasestr(sniffbuf, (u8*)"<br") ||
        inl_strcasestr(sniffbuf, (u8*)"<td") ||
        inl_strcasestr(sniffbuf, (u8*)"<h1") ||
        inl_strcasestr(sniffbuf, (u8*)"<li") ||
        inl_strcasestr(sniffbuf, (u8*)"<p>") ||
        inl_strcasestr(sniffbuf, (u8*)"href=")) {
      res->sniff_mime_id = MIME_ASC_HTML;
      return;
    }

    /* OK, we're out of ideas. Let's do a last-resort check for XML again,
       now that HTML is also off the table. */

    if (strstr((char*)sniffbuf, "<![CDATA[") ||
        strstr((char*)sniffbuf, "</") || strstr((char*)sniffbuf, "/>")) {
      res->sniff_mime_id = MIME_XML_GENERIC;
      return;
    }

    res->sniff_mime_id = MIME_ASC_GENERIC;

  } else {

    /* Binary checks. Start with simple images (JPG, GIF, PNG, TIFF, BMP). */

    if (sniffbuf[0] == 0xFF && sniffbuf[1] == 0xD8 && sniffbuf[2] == 0xFF) {
      res->sniff_mime_id = MIME_IMG_JPEG;
      return;
    }

    if (!prefix(sniffbuf, "GIF8")) {
      res->sniff_mime_id = MIME_IMG_GIF;
      return;
    }

    if (sniffbuf[0] == 0x89 && !prefix(sniffbuf + 1, "PNG")) {
      res->sniff_mime_id = MIME_IMG_PNG;
      return;
    }

    if (!prefix(sniffbuf, "BM")) {
      res->sniff_mime_id = MIME_IMG_BMP;
      return;
    }

    if (!prefix(sniffbuf, "II") && sniffbuf[2] == 42 /* dec */) {
      res->sniff_mime_id = MIME_IMG_TIFF;
      return;
    }

    /* Next: RIFF containers (AVI, ANI, WAV). */

    if (!prefix(sniffbuf, "RIFF")) {

      if (sniffbuf[8] == 'A') {
        if (sniffbuf[9] == 'C')
          res->sniff_mime_id = MIME_IMG_ANI;
        else
          res->sniff_mime_id = MIME_AV_AVI;
      } else res->sniff_mime_id = MIME_AV_WAV;

      return;

    }

    /* Cursor / ICO drama (we roll it back into BMP, because few sites
       make the distinction anyway, and cursors are unlikely to be
       attacker-supplied)... */

    if (res->pay_len > 3 && !sniffbuf[0] && !sniffbuf[1] &&
        sniffbuf[2] && !sniffbuf[3]) {
      res->sniff_mime_id = MIME_IMG_BMP;
      return;
    }

    /* Windows Media container (WMV, WMA, ASF). */

    if (sniffbuf[0] == 0x30 && sniffbuf[1] == 0x26 && sniffbuf[2] == 0xB2) {
      res->sniff_mime_id = MIME_AV_WMEDIA;
      return;
    }

    /* MPEG formats, Ogg Vorbis, QuickTime, RealAudio, RealVideo. */

    if (sniffbuf[0] == 0xFF && sniffbuf[1] == 0xFB) {
      res->sniff_mime_id = MIME_AV_MP3;
      return;
    }

    if (sniffbuf[0] == 0x00 && sniffbuf[1] == 0x00 && sniffbuf[2] == 0x01 &&
        (sniffbuf[3] >> 4) == 0x0B) {
      res->sniff_mime_id = MIME_AV_MPEG;
      return;
    }

    if (!prefix(sniffbuf, "OggS")) {
      res->sniff_mime_id = MIME_AV_OGG;
      return;
    }

    if (sniffbuf[0] == 0x28 && !prefix(sniffbuf + 1, "RMF")) {
      res->sniff_mime_id = MIME_AV_RA;
      return;
    }

    if (sniffbuf[0] == 0x2E && !prefix(sniffbuf + 1, "RMF")) {
      res->sniff_mime_id = MIME_AV_RV;
      return;
    }

    if (!prefix(sniffbuf + 4, "free") ||
        !prefix(sniffbuf + 4, "mdat") ||
        !prefix(sniffbuf + 4, "wide") ||
        !prefix(sniffbuf + 4, "pnot") ||
        !prefix(sniffbuf + 4, "skip") ||
        !prefix(sniffbuf + 4, "moov")) {
      /* Oookay, that was weird... */
      res->sniff_mime_id = MIME_AV_QT;
      return;
    }

    /* Flash and FLV. */

    if (!prefix(sniffbuf, "FLV")) {
      res->sniff_mime_id = MIME_AV_FLV;
      return;
    }

    if (!prefix(sniffbuf, "FCWS") ||
        !prefix(sniffbuf, "CWS")) {
      res->sniff_mime_id = MIME_EXT_FLASH;
      return;
    }

    /* Adobe PDF. */

    if (!prefix(sniffbuf, "%PDF")) {
      res->sniff_mime_id = MIME_EXT_PDF;
      return;
    }

    /* JAR versus ZIP. A bit tricky, because, well, they are both just
       ZIP archives. */

    if (!prefix(sniffbuf, "PK") &&
        sniffbuf[2] < 6 && sniffbuf[3] < 7) {

      if (inl_memmem(res->payload, res->pay_len, "META-INF/", 9))
        res->sniff_mime_id = MIME_EXT_JAR;
      else
        res->sniff_mime_id = MIME_BIN_ZIP;
      return;

    }

    /* Java class files. */

    if (sniffbuf[0] == 0xCA && sniffbuf[1] == 0xFE && sniffbuf[2] == 0xBA &&
        sniffbuf[3] == 0xBE) {
      res->sniff_mime_id = MIME_EXT_CLASS;
      return;
    }

    /* The joy of Microsoft Office containers. */

    if (res->pay_len > 512 && sniffbuf[0] == 0xD0 && sniffbuf[1] == 0xCF &&
        sniffbuf[2] == 0x11 && sniffbuf[3] == 0xE0) {

      switch (sniffbuf[512]) {
        case 0xEC: res->sniff_mime_id = MIME_EXT_WORD; return;
        case 0xFD:
        case 0x09: res->sniff_mime_id = MIME_EXT_EXCEL; return;
        case 0x00:
        case 0x0F:
        case 0xA0: res->sniff_mime_id = MIME_EXT_PPNT; return;
      }

    }

    /* GZIP. Unfortunately, tar has no discernible header to speak of,
       so we just let it slide - few sites are serving tars on purpose
       anyway. */

    if (sniffbuf[0] == 0x1F && sniffbuf[1] == 0x8B && sniffbuf[2] == 0x08) {
      res->sniff_mime_id = MIME_BIN_GZIP;
      return;
    }

    /* CAB. */

    if (sniffbuf[0] == 'M' && sniffbuf[1] == 'S' && sniffbuf[2] == 'C' &&
        sniffbuf[3] == 'F' && !sniffbuf[4]) {
      res->sniff_mime_id = MIME_BIN_CAB;
      return;
    }

    res->sniff_mime_id = MIME_BIN_GENERIC;

  }

  /* No more ideas? */

}


/* "Stuff" means various error messages and cool, unusual content. For large
   files, this function may be sort-of expensive, but we need to look through
   the entire response, as not all messages are full-page errors, etc. */

static void check_for_stuff(struct http_request* req,
                            struct http_response* res) {

  u8 sniffbuf[SNIFF_LEN];
  u8* tmp;

  if (!res->pay_len || !is_mostly_ascii(res) || res->stuff_checked) return;

  /* We will use sniffbuf for checks that do not need to look through the
     entire file. */

  memcpy(sniffbuf, res->payload,
         (res->pay_len > SNIFF_LEN - 1) ? (SNIFF_LEN - 1) : res->pay_len);

  sniffbuf[(res->pay_len > SNIFF_LEN - 1) ? (SNIFF_LEN - 1) : res->pay_len] = 0;

  res->stuff_checked = 1;

  /* Assorted interesting error messages. */

  if (((tmp = (u8*)strstr((char*)res->payload, "ORA-")) ||
       (tmp = (u8*)strstr((char*)res->payload, "FRM-"))) &&
      isdigit(tmp[4]) && tmp[9] == ':') {
    problem(PROB_ERROR_POI, req, res, (u8*)"Oracle server error", req->pivot, 0);
    return;
  }


  if (inl_strcasestr(sniffbuf, (u8*)"\nAuthType ") ||
      (inl_strcasestr(sniffbuf, (u8*)"\nOptions ") && (
        inl_strcasestr(sniffbuf, (u8*)"\nOptions +") ||
        inl_strcasestr(sniffbuf, (u8*)"\nOptions -") ||
        inl_strcasestr(sniffbuf, (u8*)"\nOptions All") ||
        inl_strcasestr(sniffbuf, (u8*)"\nOptions Exec") ||
        inl_strcasestr(sniffbuf, (u8*)"\nOptions Follow") ||
        inl_strcasestr(sniffbuf, (u8*)"\nOptions In") ||
        inl_strcasestr(sniffbuf, (u8*)"\nOptions Mult") ||
        inl_strcasestr(sniffbuf, (u8*)"\nOptions Sym"))
      ) ||
      inl_strcasestr(sniffbuf, (u8*)"\n<Directory ") ||
      (inl_strcasestr(sniffbuf, (u8*)"\nRequire ") && (
        inl_strcasestr(sniffbuf, (u8*)"\nRequire valid") ||
        inl_strcasestr(sniffbuf, (u8*)"\nRequire user") ||
        inl_strcasestr(sniffbuf, (u8*)"\nRequire group") ||
        inl_strcasestr(sniffbuf, (u8*)"\nRequire file"))
      )) {
    problem(PROB_FILE_POI, req, res, (u8*)"Apache config file", req->pivot, 0);
    return;
  }

  if (res->sniff_mime_id == MIME_ASC_GENERIC) {
    u8* x = sniffbuf;

    /* Generic something:something[:...] password syntax. */

    while (*x && (isalnum(*x) || strchr("._-+$", *x)) &&
           (x - sniffbuf) < 64) x++;

    if (x != sniffbuf && *x == ':' && x[1] != '/' && x[1] != '.') {
      u8* start_x = ++x;

      while (*x && (isalnum(*x) || strchr("./*!+=$", *x)) &&
             (x - sniffbuf) < 128) x++;

      if (*x == ':' || ((start_x != x) && (!*x || *x == '\r' || *x == '\n')))
        problem(PROB_FILE_POI, req, res, (u8*)
                "Possible password file", req->pivot, 0);

    }
  }

  /* Add more directory signatures here... */

  if (strstr((char*)sniffbuf, "<A HREF=\"?N=D\">") ||
      strstr((char*)sniffbuf, "<a href=\"?C=N;O=D\">") ||
      strstr((char*)sniffbuf, "<h1>Index of /") ||
      strstr((char*)sniffbuf, ">[To Parent Directory]<")) {
    problem(PROB_DIR_LIST, req, res, (u8*)"Directory listing", req->pivot, 0);

    /* Since we have the listing, we'll skip bruteforcing directory */
    req->pivot->no_fuzz = 3;
    return;
  }

  if (res->sniff_mime_id == MIME_ASC_GENERIC) {
    u8* x = sniffbuf;
    u32 slashes = 0;

    /* Five slashes in the first line in a plaintext file should be a
       reasonably good check for CVS. */

    while (*x && *x != '\n' &&
           (x - sniffbuf) < 256) {
      if (*x == '/') slashes++;
      x++;
    }

    if (slashes == 5) {
      problem(PROB_FILE_POI, req, res, (u8*)"CVS RCS data", req->pivot, 0);
      return;
    }

  }

  if (strstr((char*)res->payload, "End Sub\n") ||
      strstr((char*)res->payload, "End Sub\r")) {
    problem(PROB_FILE_POI, req, res, (u8*)"Visual Basic source", req->pivot, 0);
    return;
  }


  /* Plain text, and every line contains ;, comma, or |? */

  if (res->sniff_mime_id == MIME_ASC_GENERIC) {
    u8* cur = res->payload;
    u8  all_delim = 0;
    u8* eol;

    do {
      u32 del = strcspn((char*)cur, ",|;\n");

      eol = (u8*)strchr((char*)cur, '\n');
      if(!eol) break;

      if (!cur[del] || cur[del] == '\n' || (cur[del] == ',' && 
          cur[del+1] == ' ')) {
        all_delim = 0;
        break;
      }

      all_delim = 1;
      cur = eol + 1;

    } while (eol && cur && *cur);

    if (all_delim) {
      problem(PROB_FILE_POI, req, res,
              (u8*)"Delimited database dump", req->pivot, 0);
      return;
    }

  }

  /* This is a bit dodgy, but the most prominent sign of non-browser JS on
     Windows is the instantiation of obscure ActiveX objects to access local
     filesystem, create documents, etc. Unfortunately, some sites may also be
     creating obscure ActiveX objects; these would likely need to be just
     blacklisted here. */

  if (is_javascript(res) && strstr((char*)res->payload, "new ActiveXObject(") &&
      !strstr((char*)res->payload, "XMLHTTP") &&
      !strstr((char*)res->payload, "ShockwaveFlash")) {
    problem(PROB_FILE_POI, req, res, (u8*)"server-side JavaScript source",
            req->pivot, 0);
    return;
  }

}


/* Deletes payload of binary responses if requested. This is called when pivot
   enters PSTATE_DONE. */

void maybe_delete_payload(struct pivot_desc* pv) {
  u8  tmp[64];
  u32 i;

  if (pv->res && pv->res->pay_len > 256 && !is_mostly_ascii(pv->res)) {
    ck_free(pv->res->payload);
    sprintf((char*)tmp, "[Deleted binary payload (%u bytes)]", pv->res->pay_len);
    pv->res->payload = ck_strdup(tmp);
    pv->res->pay_len = strlen((char*)tmp);
  }

  for (i=0;i<pv->issue_cnt;i++) {

    if (pv->issue[i].res && pv->issue[i].res->pay_len > 256 && 
        !is_mostly_ascii(pv->issue[i].res)) {
      ck_free(pv->issue[i].res->payload);
      sprintf((char*)tmp, "[Deleted binary payload (%u bytes)]", 
              pv->issue[i].res->pay_len);
      pv->issue[i].res->payload = ck_strdup(tmp);
      pv->issue[i].res->pay_len = strlen((char*)tmp);
    }

  }

}
