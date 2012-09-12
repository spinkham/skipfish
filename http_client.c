/*
   skipfish - high-performance, single-process asynchronous HTTP client
   --------------------------------------------------------------------

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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <idna.h>
#include <zlib.h>

#include "types.h"
#include "alloc-inl.h"
#include "string-inl.h"
#include "database.h"

#include "http_client.h"

/* Assorted exported settings: */

u32 max_connections  = MAX_CONNECTIONS,
    max_conn_host    = MAX_CONN_HOST,
    max_requests     = MAX_REQUESTS,
    max_fail         = MAX_FAIL,
    idle_tmout       = IDLE_TMOUT,
    resp_tmout       = RESP_TMOUT,
    rw_tmout         = RW_TMOUT,
    size_limit       = SIZE_LIMIT;

u8 browser_type      = BROWSER_FAST;
u8 auth_type         = AUTH_NONE;

float max_requests_sec = MAX_REQUESTS_SEC;

struct param_array global_http_par;

/* Counters: */

float req_sec;

u32 req_errors_net,
    req_errors_http,
    req_errors_cur,
    req_count,
    req_dropped,
    queue_cur,
    conn_cur,
    conn_count,
    conn_idle_tmout,
    conn_busy_tmout,
    conn_failed,
    req_retried,
    url_scope;

u64 bytes_sent,
    bytes_recv,
    bytes_deflated,
    bytes_inflated,
    iterations_cnt = 0;

u8 *auth_user,
   *auth_pass;


#ifdef PROXY_SUPPORT
u8* use_proxy;
u32 use_proxy_addr;
u16 use_proxy_port;
#endif /* PROXY_SUPPORT */

u8  ignore_cookies,
    idle;

/* Internal globals for queue management: */

static struct queue_entry* queue;
static struct conn_entry*  conn;
static struct dns_entry*   dns;

#ifdef QUEUE_FILO
static struct queue_entry* q_tail;
#endif /* QUEUE_FILO */

static u8 tear_down_idle;


/* Extracts parameter value from param_array. Name is matched if
   non-NULL. Returns pointer to value data, not a duplicate string;
   NULL if no match found. */

u8* get_value(u8 type, u8* name, u32 offset,
              struct param_array* par) {

  u32 i, coff = 0;

  for (i=0;i<par->c;i++) {
    if (type != par->t[i]) continue;
    if (name && (!par->n[i] || strcasecmp((char*)par->n[i], (char*)name)))
      continue;

    if (offset != coff) { coff++; continue; }
    return par->v[i];
  }

  return NULL;

}

/* Inserts or overwrites parameter value in param_array. If offset
   == -1, will append parameter to list. Duplicates strings,
   name and val can be NULL. */

void set_value(u8 type, u8* name, u8* val,
               s32 offset, struct param_array* par) {

  u32 i, coff = 0, matched = -1;

  /* If offset specified, try to find an entry to replace. */

  if (offset >= 0)
    for (i=0;i<par->c;i++) {
      if (type != par->t[i]) continue;
      if (name && (!par->n[i] || strcasecmp((char*)par->n[i], (char*)name)))
        continue;
      if (offset != coff) { coff++; continue; }
      matched = i;
      break;
    }

  if (matched == -1) {

    /* No offset or no match - append to the end of list. */

    par->t = ck_realloc(par->t, (par->c + 1) * sizeof(u8));
    par->n = ck_realloc(par->n, (par->c + 1) * sizeof(u8*));
    par->v = ck_realloc(par->v, (par->c + 1) * sizeof(u8*));
    par->t[par->c] = type;
    par->n[par->c] = ck_strdup(name);
    par->v[par->c] = ck_strdup(val);
    par->c++;

  } else {

    /* Matched - replace name & value. */

    ck_free(par->n[matched]);
    ck_free(par->v[matched]);
    par->n[matched] = ck_strdup(name);
    par->v[matched] = ck_strdup(val);

  }

}


/* Convert a fully-qualified or relative URL string to a proper http_request
   representation. Returns 0 on success, 1 on format error. */

u8 parse_url(u8* url, struct http_request* req, struct http_request* ref) {

  u8* cur = url;
  u32 maybe_proto = strcspn((char*)url, ":/?#@");
  u8 has_host = 0, add_slash = 1;

  if (strlen((char*)url) > MAX_URL_LEN) return 1;
  req->orig_url = ck_strdup(url);

  /* Interpret, skip protocol string if the URL seems to be fully-qualified;
     otherwise, copy from referring URL. We could be stricter here, as
     browsers bail out on seemingly invalid chars in proto names, but... */

  if (maybe_proto && url[maybe_proto] == ':') {

    if (!case_prefix(url, "http:")) {
      req->proto = PROTO_HTTP;
      cur += 5;
    } else if (!case_prefix(url, "https:")) {
      req->proto = PROTO_HTTPS;
      cur += 6;
    } else return 1;

  } else {

    if (!ref || !ref->proto) return 1;
    req->proto = ref->proto;

  }

  /* Interpret, skip //[login[:pass@](\[ipv4\]|\[ipv6\]|host)[:port] part of the
     URL, if present. Note that "http:blarg" is a valid relative URL to most
     browsers, and "//example.com/blarg" is a valid non-FQ absolute one.
     We need to mimick this, which complicates the code a bit.

     We only accept /, ?, #, and : to mark the end of a host name. Some browsers
     also allow \ or ;, but it's unlikely that we need to obey this. */

  if (cur[0] == '/' && cur[1] == '/') {

    u32 path_st;
    u8  *at_sign, *host, *x;
    u8  has_utf = 0;

    cur += 2;

    /* Detect, skip login[:pass]@; we only use cmdline-supplied credentials or
       wordlists into account. Be sure to report any embedded auth, though.

       Trivia: Firefox takes the rightmost, not the leftmost @ char into
       account. Not very important, but amusing. */

    at_sign = (u8*)strchr((char*)cur, '@');
    path_st = strcspn((char*)cur, "/?#");

    if (at_sign && path_st > (at_sign - cur)) {
      cur = at_sign + 1;
      if (!req->pivot) return 1;
      problem(PROB_URL_AUTH, ref, 0, url, req->pivot, 0);
    }

    path_st = strcspn((char*)cur, ":/?#");

    /* No support for IPv6 or [ip] notation for now, so let's just refuse to
       parse the URL. Also, refuse excessively long domain names for sanity. */

    if (*cur == '[') return 1;
    if (path_st > MAX_DNS_LEN) return 1;

    x = host = ck_memdup(cur, path_st + 1);
    host[path_st] = 0;

    /* Scan, normalize extracted host name. */

    while (*x) {

      switch (*x) {

        case 'A' ... 'Z':
          *x = tolower(*x);
          break;

        case 'a' ... 'z':
        case '0' ... '9':
        case '.':
        case '-':
        case '_':
          break;

        case 0x80 ... 0xff:
          has_utf = 1;
          break;

        default:
          /* Uh-oh, invalid characters in a host name - abandon ship. */
          ck_free(host);
          return 1;

      }

      x++;

    }

    /* Host names that contained high bits need to be converted to Punycode
       in order to resolve properly. */

    if (has_utf) {

      char* output = 0;

      if (idna_to_ascii_8z((char*)host, &output, 0) != IDNA_SUCCESS ||
          strlen(output) > MAX_DNS_LEN) {
        ck_free(host);
        free(output);
        return 1;
      }

      ck_free(host);
      host = ck_strdup((u8*)output);
      free(output);

    }

    req->host = host;
    cur += path_st;

    /* All right, moving on: if host name is followed by :, let's try to
       parse and validate port number; otherwise, assume 80 / 443, depending
       on protocol. */

    if (*cur == ':') {

      u32 digit_cnt = strspn((char*)++cur, "0123456789");
      u32 port = atoi((char*)cur);
      if (!digit_cnt || (cur[digit_cnt] && !strchr("/?#", cur[digit_cnt])))
        return 1;
      req->port = port;
      cur += digit_cnt;

    } else {

      if (req->proto == PROTO_HTTPS) req->port = 443; else req->port = 80;

    }

    has_host = 1;

  } else {

    /* No host name found - copy from referring request instead. */

    if (!ref || !ref->host) return 1;

    req->host = ck_strdup(ref->host);
    req->addr = ref->addr;
    req->port = ref->port;

  }

  if (!*cur || *cur == '#') {
    u32 i;

    /* No-op path. If the URL does not specify host (e.g., #foo), copy
       everything from referring request, call it a day. Otherwise
       (e.g., http://example.com#foo), let tokenize_path() run to
       add NULL-"" entry to the list. */

    if (!has_host) {
      for (i=0;i<ref->par.c;i++)
        if (PATH_SUBTYPE(ref->par.t[i]) || QUERY_SUBTYPE(ref->par.t[i]))
          set_value(ref->par.t[i], ref->par.n[i], ref->par.v[i], -1, &req->par);
      return 0;
    }

  }

  if (!has_host && *cur == '?') {
    u32 i;

    /* URL begins with ? and does not specify host (e.g., ?foo=bar). Copy all
       path segments, but no query, then fall through to parse the query
       string. */

    for (i=0;i<ref->par.c;i++)
      if (PATH_SUBTYPE(ref->par.t[i]))
        set_value(ref->par.t[i], ref->par.n[i], ref->par.v[i], -1, &req->par);

    /* In this case, we do not want tokenize_path() to tinker with the path
       in any way. */

    add_slash = 0;

  } else if (!has_host && *cur != '/') {

    /* The URL does not begin with / or ?, and does not specify host (e.g.,
       foo/bar?baz). Copy path from referrer, but drop the last "proper"
       path segment and everything that follows it. This mimicks browser
       behavior (for URLs ending with /, it just drops the final NULL-""
       pair). */

    u32 i;
    u32 path_cnt = 0, path_cur = 0;

    for (i=0;i<ref->par.c;i++)
      if (ref->par.t[i] == PARAM_PATH) path_cnt++;

    for (i=0;i<ref->par.c;i++) {
      if (ref->par.t[i] == PARAM_PATH) path_cur++;
      if (path_cur < path_cnt && PATH_SUBTYPE(ref->par.t[i]))
        set_value(ref->par.t[i], ref->par.n[i], ref->par.v[i], -1, &req->par);
    }

  }

  /* Tokenize the remaining path on top of what we parsed / copied over. */

  tokenize_path(cur, req, add_slash);
  return 0;

}


/* URL-decodes a string. 'Plus' parameter governs the behavior on +
   signs (as they have a special meaning only in query params, not in path). */

u8* url_decode_token(u8* str, u32 len, u8 plus) {
  u8 *ret = ck_alloc(len + 1);
  u8 *src = str, *dst = ret;
  char *hex_str = "0123456789abcdef";

  while (len--) {
    u8 c = *(src++);
    char *f, *s;

    if (plus && c == '+') c = ' ';

    if (c == '%' && len >= 2 && 
        (f = strchr(hex_str, tolower(src[0]))) &&
        (s = strchr(hex_str, tolower(src[1])))) {
      c = ((f - hex_str) << 4) | (s - hex_str);
      src += 2; len -= 2;
    }

    /* We can't handle NUL-terminators gracefully when deserializing request
       parameters, because param_array values are NUL-terminated themselves.
       Let's encode \0 as \xFF instead, and hope nobody notices. */

    if (!c) c = 0xff;

    *(dst++) = c;

  }

  *(dst++) = 0;

  ret = ck_realloc(ret, dst - ret);

  return ret;
}


/* URL-encodes a string according to custom rules. The assumption here is that
   the data is already tokenized at "special" boundaries such as ?, =, &, /,
   ;, !, $, and , so these characters must always be escaped if present in
   tokens. We otherwise let pretty much everything else go through, as it
   may help with the exploitation of certain vulnerabilities. */

u8* url_encode_token(u8* str, u32 len, u8* enc_set) {

  u8 *ret = ck_alloc(len * 3 + 1);
  u8 *src = str, *dst = ret;

  while (len--) {
    u8 c = *(src++);

    if (c <= 0x20 || c >= 0x80 || strchr((char*)enc_set, c))  {
      if (c == 0xFF) c = 0;
      sprintf((char*)dst, "%%%02X", c);
      dst += 3;
    } else *(dst++) = c;

  }

  *(dst++) = 0;

  ret = ck_realloc(ret, dst - ret);

  return ret;

}


/* Split path at known "special" character boundaries, URL decode values,
   then put them in the provided http_request struct. */

void tokenize_path(u8* str, struct http_request* req, u8 add_slash) {

  u8* cur;
  u8  know_dir = 0;

  while (*str == '/') str++;
  cur = str;

  /* Parse path elements first. */

  while (*cur && !strchr("?#", *cur)) {

    u32 next_seg, next_eq;

    u8 *name = NULL, *value = NULL;
    u8 first_el = (str == cur);


    if (first_el || *cur == '/') {

      /* Optimize out //, /\0, /./, and /.\0. They do indicate
         we are looking at a directory, so mark this. */

      if (!first_el && (cur[1] == '/' || !cur[1])) {
        cur++;
        know_dir = 1;
        continue;
      }

      if (cur[0 + !first_el] == '.' && (cur[1 + !first_el] == '/' ||
          !cur[1 + !first_el])) {
        cur += 1 + !first_el;
        know_dir = 1;
        continue;
      }

      /* Also optimize out our own \.\ prefix injected in directory
         probes. This is to avoid recursion if it actually worked in some
         way. */

      if (!prefix(cur, "/\\.\\") && (cur[4] == '/' || !cur[4])) {
        cur += 4;
        continue;
      }

      if (!case_prefix(cur, "/%5c.%5c") &&
          (cur[8] == '/' || !cur[8])) {
        cur += 8;
        continue;
      }

      /* If we encountered /../ or /..\0, remove everything up to and
         including the last "true" path element. It's also indicative
         of a directory, by the way. */

      if (cur[0 + !first_el] == '.' && cur[1 + !first_el] == '.' &&
          (cur[2 + !first_el] == '/' || !cur[2 + !first_el])) {

        u32 i, last_p = req->par.c;

        for (i=0;i<req->par.c;i++)
          if (req->par.t[i] == PARAM_PATH) last_p = i;

        for (i=last_p;i<req->par.c;i++) {
          req->par.t[i] = PARAM_NONE;
        }

        cur += 2 + !first_el;
        know_dir = 1;
        continue;

      }

    }

    /* If we're here, we have an actual item to add; cur points to
       the string if it's the first element, or to field separator
       if one of the subsequent ones. */

    next_seg = strcspn((char*)cur + 1, "/;,!$?#") + 1,
    next_eq  = strcspn((char*)cur + 1, "=/;,!$?#") + 1;
    know_dir = 0;

    if (next_eq < next_seg) {
      name  = url_decode_token(cur + !first_el, next_eq - !first_el, 0);
      value = url_decode_token(cur + next_eq + 1, next_seg - next_eq - 1, 0);
    } else {
      value = url_decode_token(cur + !first_el, next_seg - !first_el, 0);
    }

    /* If the extracted segment is just '.' or '..', but is followed by
       something else than '/', skip one separator. */

    if (!name && cur[next_seg] && cur[next_seg] != '/' && 
        (!strcmp((char*)value, ".") || !strcmp((char*)value, ".."))) {

      next_seg = strcspn((char*)cur + next_seg + 1, "/;,!$?#") + next_seg + 1,

      ck_free(name);
      ck_free(value);

      value = url_decode_token(cur + !first_el, next_seg - !first_el, 0);

    }


    switch (first_el ? '/' : *cur) {

      case ';': set_value(PARAM_PATH_S, name, value, -1, &req->par); break;
      case ',': set_value(PARAM_PATH_C, name, value, -1, &req->par); break;
      case '!': set_value(PARAM_PATH_E, name, value, -1, &req->par); break;
      case '$': set_value(PARAM_PATH_D, name, value, -1, &req->par); break;
      default:  set_value(PARAM_PATH, name, value, -1, &req->par);

    }

    ck_free(name);
    ck_free(value);

    cur += next_seg;

  }

  /* If the last segment was /, /./, or /../, *or* if we never added
     anything to the path to begin with, we want to store a NULL-""
     entry to denote it's a directory. */

  if (know_dir || (add_slash && (!*str || strchr("?#", *str))))
    set_value(PARAM_PATH, NULL, (u8*)"", -1, &req->par);

  /* Deal with regular query parameters now. This is much simpler,
     obviously. */

  while (*cur && !strchr("#", *cur)) {

    u32 next_seg = strcspn((char*)cur + 1, "#&;,!$") + 1;
    u32 next_eq  = strcspn((char*)cur + 1, "=#&;,!$") + 1;
    u8 *name = NULL, *value = NULL;

    /* foo=bar syntax... */

    if (next_eq < next_seg) {
      name  = url_decode_token(cur + 1, next_eq - 1, 1);
      value = url_decode_token(cur + next_eq + 1, next_seg - next_eq - 1, 1);
    } else {
      value = url_decode_token(cur + 1, next_seg - 1, 1);
    }

    switch (*cur) {

      case ';': set_value(PARAM_QUERY_S, name, value, -1, &req->par); break;
      case ',': set_value(PARAM_QUERY_C, name, value, -1, &req->par); break;
      case '!': set_value(PARAM_QUERY_E, name, value, -1, &req->par); break;
      case '$': set_value(PARAM_QUERY_D, name, value, -1, &req->par); break;
      default: set_value(PARAM_QUERY, name, value, -1, &req->par);

    }

    ck_free(name);
    ck_free(value);

    cur += next_seg;

  }

}


/* Reconstructs URI from http_request data. Includes protocol and host
   if with_host is non-zero. */

u8* serialize_path(struct http_request* req, u8 with_host, u8 with_post) {
  u32 i, cur_pos;
  u8 got_search = 0;
  u8* ret;

  NEW_STR(ret, cur_pos);

#define ASD(_p3) ADD_STR_DATA(ret, cur_pos, _p3)

  /* For human-readable uses... */

  if (with_host) {
    ASD("http");
    if (req->proto == PROTO_HTTPS) ASD("s");
    ASD("://");
    ASD(req->host);

    if ((req->proto == PROTO_HTTP && req->port != 80) ||
        (req->proto == PROTO_HTTPS && req->port != 443)) {
      u8 port[7];
      sprintf((char*)port, ":%u", req->port);
      ASD(port);
    }

  }

  /* First print path... */

  for (i=0;i<req->par.c;i++) {
    u8 *enc = (u8*)ENC_PATH;
    if(req->pivot && req->fuzz_par_enc && i == req->pivot->fuzz_par)
      enc = req->fuzz_par_enc;

    if (PATH_SUBTYPE(req->par.t[i])) {

      switch (req->par.t[i]) {

        case PARAM_PATH_S: ASD(";"); break;
        case PARAM_PATH_C: ASD(","); break;
        case PARAM_PATH_E: ASD("!"); break;
        case PARAM_PATH_D: ASD("$"); break;
        default: ASD("/");

      }

      if (req->par.n[i]) {
        u32 len = strlen((char*)req->par.n[i]);
        u8* str = url_encode_token(req->par.n[i], len, enc);
        ASD(str); ASD("=");
        ck_free(str);
      }
      if (req->par.v[i]) {
        u32 len = strlen((char*)req->par.v[i]);
        u8* str = url_encode_token(req->par.v[i], len, enc);
        ASD(str);
        ck_free(str);
      }

    }
  }

  /* Then actual parameters. */

  for (i=0;i<req->par.c;i++) {
    u8 *enc = (u8*)ENC_DEFAULT;
    if(req->pivot && req->fuzz_par_enc && i == req->pivot->fuzz_par)
      enc = req->fuzz_par_enc;

    if (QUERY_SUBTYPE(req->par.t[i])) {

      if (!got_search) {
        ASD("?");
        got_search = 1;
      } else switch (req->par.t[i]) {

        case PARAM_QUERY_S: ASD(";"); break;
        case PARAM_QUERY_C: ASD(","); break;
        case PARAM_QUERY_E: ASD("!"); break;
        case PARAM_QUERY_D: ASD("$"); break;
        default: ASD("&");

      }

      if (req->par.n[i]) {
        u32 len = strlen((char*)req->par.n[i]);
        u8* str = url_encode_token(req->par.n[i], len, enc);
        ASD(str); ASD("=");
        ck_free(str);
      }
      if (req->par.v[i]) {
        u32 len = strlen((char*)req->par.v[i]);
        u8* str = url_encode_token(req->par.v[i], len, enc);
        ASD(str);
        ck_free(str);
      }

    }
  }

  got_search = 0;

  if (with_post)
    for (i=0;i<req->par.c;i++) {

      u8 *enc = (u8*)ENC_DEFAULT;
      if(req->pivot && req->fuzz_par_enc && i == req->pivot->fuzz_par)
        enc = req->fuzz_par_enc;

      if (POST_SUBTYPE(req->par.t[i])) {

      if (!got_search) {
        ASD(" DATA:");
        got_search = 1;
      } else ASD("&");

      if (req->par.n[i]) {
        u32 len = strlen((char*)req->par.n[i]);
        u8* str = url_encode_token(req->par.n[i], len, enc);
        ASD(str); ASD("=");
        ck_free(str);
      }
      if (req->par.v[i]) {
        u32 len = strlen((char*)req->par.v[i]);
        u8* str = url_encode_token(req->par.v[i], len, enc);
        ASD(str);
        ck_free(str);
      }

    }
  }

#undef ASD

  TRIM_STR(ret, cur_pos);
  return ret;

}


/* Looks up IP for a particular host, returns data in network order.
   Uses standard resolver, so it is slow and blocking, but we only
   expect to call it a couple of times during a typical assessment.
   There are some good async DNS libraries to consider in the long run. */

u32 maybe_lookup_host(u8* name) {
  struct hostent* h;
  struct dns_entry *d = dns, *prev = NULL;
  u32 ret_addr = 0;
  struct in_addr in;

#ifdef PROXY_SUPPORT

  /* If configured to use proxy, look up proxy IP once; and return that
     address for all host names. */

  if (use_proxy) {

    if (!use_proxy_addr) {

     /* Don't bother resolving raw IP addresses, naturally. */

      if (inet_aton((char*)use_proxy, &in))
        return (use_proxy_addr = (u32)in.s_addr);

      h = gethostbyname((char*)use_proxy);

      /* If lookup fails with a transient error, be nice - try again. */

      if (!h && h_errno == TRY_AGAIN) h = gethostbyname((char*)name);

      if (!h || !(use_proxy_addr = *(u32*)h->h_addr_list[0]))
        FATAL("Unable to resolve proxy host name '%s'.", use_proxy);

    }

    return use_proxy_addr;

  }

  /* If no proxy... */

#endif /* PROXY_SUPPORT */

  /* Don't bother resolving raw IP addresses, naturally. */

  if (inet_aton((char*)name, &in))
    return (u32)in.s_addr;

  while (d) {
    if (!strcasecmp((char*)name, (char*)d->name)) return d->addr;
    prev = d;
    d = d->next;
  }

  h = gethostbyname((char*)name);

  /* If lookup fails with a transient error, be nice - try again. */

  if (!h && h_errno == TRY_AGAIN) h = gethostbyname((char*)name);

  if (h) {

    u32 i = 0;

    /* For each address associated with the host, see if we have any
       other hosts that resolved to that same IP. If yes, return
       that address; otherwise, just return first. This is for HTTP
       performance and bookkeeping reasons. */

    while (h->h_addr_list[i]) {
      d = dns;
      while (d) {
        if (d->addr == *(u32*)h->h_addr_list[i]) {
          ret_addr = d->addr;
          goto dns_got_name;
        }
        d = d->next;
      }
      i++;
    }

    ret_addr = *(u32*)h->h_addr_list[0];

  }

dns_got_name:

  if (!prev) d = dns = ck_alloc(sizeof(struct dns_entry));
    else d = prev->next = ck_alloc(sizeof(struct dns_entry));

  d->name = ck_strdup(name);
  d->addr = ret_addr;

  return ret_addr;

}


/* Creates an ad hoc DNS cache entry, to override NS lookups. */

void fake_host(u8* name, u32 addr) {
  struct dns_entry *d = dns, *prev = dns;

  while (d && d->next) { prev = d ; d = d->next;}

  if (!dns) d = dns = ck_alloc(sizeof(struct dns_entry));
    else d = prev->next = ck_alloc(sizeof(struct dns_entry));

  d->name = ck_strdup(name);
  d->addr = addr;

}


/* Prepares a serialized HTTP buffer to be sent over the network. */

u8* build_request_data(struct http_request* req) {

  u8 *ret_buf, *ck_buf, *pay_buf, *path;
  u32 ret_pos, ck_pos, pay_pos, i;
  u8  req_type = PARAM_NONE;

  if (req->proto == PROTO_NONE)
    FATAL("uninitialized http_request");

  NEW_STR(ret_buf, ret_pos);

  path = serialize_path(req, 0, 0);

#define ASD(_p3) ADD_STR_DATA(ret_buf, ret_pos, _p3)

  if (req->method) ASD(req->method); else ASD((u8*)"GET");
  ASD(" ");

#ifdef PROXY_SUPPORT

  /* For non-CONNECT proxy requests, insert http://host[:port] too. */

  if (use_proxy && req->proto == PROTO_HTTP) {
    ASD("http://");
    ASD(req->host);

    if (req->port != 80) {
      char port[7];
      sprintf((char*)port, ":%u", req->port);
      ASD(port);
    }

  }

#endif /* PROXY_SUPPORT */

  ASD(path);
  ASD(" HTTP/1.1\r\n");
  ck_free(path);

  ASD("Host: ");
  ASD(req->host);

  if ((req->proto == PROTO_HTTP && req->port != 80) ||
      (req->proto == PROTO_HTTPS && req->port != 443)) {
    char port[7];
    sprintf((char*)port, ":%u", req->port);
    ASD(port);
  }

  ASD("\r\n");

  /* Insert generic browser headers first. */

  if (browser_type == BROWSER_FAST) {

    ASD("Accept-Encoding: gzip\r\n");
    ASD("Connection: keep-alive\r\n");

    if (!GET_HDR((u8*)"User-Agent", &req->par))
      ASD("User-Agent: Mozilla/5.0 SF/" VERSION "\r\n");

    /* Some servers will reject to gzip responses unless "Mozilla/..."
       is seen in User-Agent. Bleh. */

  } else if (browser_type == BROWSER_FFOX) {

    if (!GET_HDR((u8*)"User-Agent", &req->par))
      ASD("User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; "
          "rv:1.9.1.2) Gecko/20090729 Firefox/3.5.2 SF/" VERSION "\r\n");

    ASD("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;"
        "q=0.8\r\n");

    if (!GET_HDR((u8*)"Accept-Language", &req->par))
      ASD("Accept-Language: en-us,en\r\n");

    ASD("Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n");
    ASD("Keep-Alive: 300\r\n");
    ASD("Connection: keep-alive\r\n");

  } else if (browser_type == BROWSER_MSIE) {

    ASD("Accept: */*\r\n");

    if (!GET_HDR((u8*)"Accept-Language", &req->par))
      ASD("Accept-Language: en,en-US;q=0.5\r\n");

    if (!GET_HDR((u8*)"User-Agent", &req->par))
      ASD("User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; "
          "Trident/4.0; .NET CLR 1.1.4322; InfoPath.1; .NET CLR "
          "2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; SF/"
          VERSION ")\r\n");

    ASD("Accept-Encoding: gzip, deflate\r\n");
    ASD("Connection: Keep-Alive\r\n");

  } else /* iPhone */ {

    if (!GET_HDR((u8*)"User-Agent", &req->par))
      ASD("User-Agent: Mozilla/5.0 (iPhone; U; CPU iPhone OS 4_1 like Mac OS "
          "X; en-us) AppleWebKit/532.9 (KHTML, like Gecko) Version/4.0.5 "
          "Mobile/8B117 Safari/6531.22.7 SF/" VERSION "\r\n");

    ASD("Accept: application/xml,application/xhtml+xml,text/html;q=0.9,"
        "text/plain;q=0.8,image/png,*/*;q=0.5\r\n");

    if (!GET_HDR((u8*)"Accept-Language", &req->par))
      ASD("Accept-Language: en-us\r\n");

    ASD("Accept-Encoding: gzip, deflate\r\n");
    ASD("Connection: keep-alive\r\n");

  }

  /* Request a limited range up front to minimize unwanted traffic.
     Note that some Oracle servers apparently fail on certain ranged
     requests, so allowing -H override seems like a good idea. */

  if (!GET_HDR((u8*)"Range", &global_http_par)) {
    u8 limit[32];
    sprintf((char*)limit, "Range: bytes=0-%u\r\n", size_limit - 1);
    ASD(limit);
  }

  /* Include a dummy "Referer" header, to avoid certain XSRF checks. */

  if (!GET_HDR((u8*)"Referer", &req->par)) {
    ASD("Referer: http");
    if (req->proto == PROTO_HTTPS) ASD("s");
    ASD("://");
    ASD(req->host);
    ASD("/\r\n");
  }

  /* Take care of HTTP authentication next. */

  if (auth_type == AUTH_BASIC) {
    u8* lp = ck_alloc(strlen((char*)auth_user) + strlen((char*)auth_pass) + 2);
    u8* lpb64;

    sprintf((char*)lp, "%s:%s", auth_user, auth_pass);

    lpb64 = b64_encode(lp, strlen((char*)lp));

    ASD("Authorization: Basic ");
    ASD(lpb64);
    ASD("\r\n");

    ck_free(lpb64);
    ck_free(lp);

  }

  /* Append any other requested headers and cookies. */

  NEW_STR(ck_buf, ck_pos);

  for (i=0;i<req->par.c;i++) {
    if (req->par.t[i] == PARAM_HEADER) {
      ASD(req->par.n[i]);
      ASD(": ");
      ASD(req->par.v[i]);
      ASD("\r\n");
    } else if (req->par.t[i] == PARAM_COOKIE) {
      if (ck_pos) ADD_STR_DATA(ck_buf, ck_pos, ";");
      ADD_STR_DATA(ck_buf, ck_pos, req->par.n[i]);
      ADD_STR_DATA(ck_buf, ck_pos, "=");
      ADD_STR_DATA(ck_buf, ck_pos, req->par.v[i]);
    }
  }

  /* Also include extra globals, if any (but avoid dupes). */

  for (i=0;i<global_http_par.c;i++) {
    if (global_http_par.t[i] == PARAM_HEADER &&
        !GET_HDR(global_http_par.n[i], &req->par)) {
      ASD(global_http_par.n[i]);
      ASD(": ");
      ASD(global_http_par.v[i]);
      ASD("\r\n");
    } else if (global_http_par.t[i] == PARAM_COOKIE &&
        !GET_CK(global_http_par.n[i], &req->par)) {
      if (ck_pos) ADD_STR_DATA(ck_buf, ck_pos, "; ");
      ADD_STR_DATA(ck_buf, ck_pos, global_http_par.n[i]);
      ADD_STR_DATA(ck_buf, ck_pos, "=");
      ADD_STR_DATA(ck_buf, ck_pos, global_http_par.v[i]);
    }
  }

  if (ck_pos) {
    ASD("Cookie: ");
    ASD(ck_buf);
    ASD("\r\n");
  }

  ck_free(ck_buf);

  /* Now, let's serialize the payload, if necessary. */

  for (i=0;i<req->par.c;i++) {
    switch (req->par.t[i]) {
      case PARAM_POST_F:
      case PARAM_POST_O:
        req_type  = req->par.t[i];
        break;
      case PARAM_POST:
        if (req_type == PARAM_NONE) req_type = PARAM_POST;
        break;
    }
  }

  NEW_STR(pay_buf, pay_pos);

  if (req_type == PARAM_POST) {

    /* The default case: application/x-www-form-urlencoded. */

    for (i=0;i<req->par.c;i++) {
      u8 *enc = (u8*)ENC_DEFAULT;
      if(req->pivot && req->fuzz_par_enc && i == req->pivot->fuzz_par)
        enc = req->fuzz_par_enc;

      if (req->par.t[i] == PARAM_POST) {
        if (pay_pos) ADD_STR_DATA(pay_buf, pay_pos, "&");
        if (req->par.n[i]) {
          u32 len = strlen((char*)req->par.n[i]);
          u8* str = url_encode_token(req->par.n[i], len, enc);
          ADD_STR_DATA(pay_buf, pay_pos, str);
          ADD_STR_DATA(pay_buf, pay_pos, "=");
          ck_free(str);
        }
        if (req->par.v[i]) {
          u32 len = strlen((char*)req->par.v[i]);
          u8* str = url_encode_token(req->par.v[i], len, enc);
          ADD_STR_DATA(pay_buf, pay_pos, str);
          ck_free(str);
        }
      }

    }

    ASD("Content-Type: application/x-www-form-urlencoded\r\n");

  } else if (req_type == PARAM_POST_O) {

    /* Opaque, non-escaped data of some sort. */

    for (i=0;i<req->par.c;i++)
      if (req->par.t[i] == PARAM_POST_O && req->par.v[i])
        ADD_STR_DATA(pay_buf, pay_pos, req->par.v[i]);

    ASD("Content-Type: text/plain\r\n");

  } else if (req_type == PARAM_POST_F) {
    u8 bound[20];

    /* MIME envelopes: multipart/form-data */

    sprintf((char*)bound, "sf%u", R(1000000));

    for (i=0;i<req->par.c;i++)
      if (req->par.t[i] == PARAM_POST || req->par.t[i] == PARAM_POST_F) {

        ADD_STR_DATA(pay_buf, pay_pos, "--");
        ADD_STR_DATA(pay_buf, pay_pos, bound);
        ADD_STR_DATA(pay_buf, pay_pos, "\r\n"
                     "Content-Disposition: form-data; name=\"");
        if (req->par.n[i])
          ADD_STR_DATA(pay_buf, pay_pos, req->par.n[i]);

        if (req->par.t[i] == PARAM_POST_F) {
          u8 tmp[64];
          sprintf((char*)tmp, "\"; filename=\"sfish%u." DUMMY_EXT "\"\r\n"
                  "Content-Type: " DUMMY_MIME "\r\n\r\n", R(16));
          ADD_STR_DATA(pay_buf, pay_pos, tmp);
          ADD_STR_DATA(pay_buf, pay_pos, new_xss_tag((u8*)DUMMY_FILE));
          register_xss_tag(req);
        } else {
          ADD_STR_DATA(pay_buf, pay_pos, "\"\r\n\r\n");
          if (req->par.v[i])
            ADD_STR_DATA(pay_buf, pay_pos, req->par.v[i]);
        }

        ADD_STR_DATA(pay_buf, pay_pos, "\r\n");
      }

    ADD_STR_DATA(pay_buf, pay_pos, "--");
    ADD_STR_DATA(pay_buf, pay_pos, bound);
    ADD_STR_DATA(pay_buf, pay_pos, "--\r\n");

    ASD("Content-Type: multipart/form-data; boundary=");
    ASD(bound);
    ASD("\r\n");

  } else if (req_type == 0) ASD("\r\n");

  /* Finalize HTTP payload... */

  for (i=0;i<pay_pos;i++)
    if (pay_buf[i] == 0xff) pay_buf[i] = 0x00;

  TRIM_STR(pay_buf, pay_pos);

  if (pay_pos) {
    u8 cl[40];
    sprintf((char*)cl, "Content-Length: %u\r\n\r\n", pay_pos);
    ASD(cl);
    ASD(pay_buf);
  }

  ck_free(pay_buf);

#undef ASD

  /* Phew! */

  TRIM_STR(ret_buf, ret_pos);
  return ret_buf;

}


/* Internal helper for parsing lines for parse_response(), etc. */

static u8* grab_line(u8* data, u32* cur_pos, u32 data_len) {
  u8 *cur_ptr   = data + *cur_pos,
     *start_ptr = cur_ptr,
     *end_ptr   = data + data_len,
     *ret;

  if (start_ptr == end_ptr) return 0;
  while (cur_ptr < end_ptr && *cur_ptr != '\n') cur_ptr++;
  if (cur_ptr != end_ptr) cur_ptr++;

  *cur_pos += cur_ptr - start_ptr;

  while (cur_ptr > start_ptr && strchr("\r\n", *(cur_ptr-1))) cur_ptr--;

  ret = ck_alloc(cur_ptr - start_ptr + 1);
  memcpy(ret, start_ptr, cur_ptr - start_ptr);
  ret[cur_ptr - start_ptr] = 0;

  return ret;

}


/* Builds response fingerprint data. These fingerprints are used to
   find "roughly comparable" pages based on their word length
   distributions (divided into FP_SIZE buckets). */

void fprint_response(struct http_response* res) {
  u32 i, c_len = 0, in_space = 0;

  res->sig.code = res->code;

  for (i=0;i<res->pay_len;i++)

    if (res->payload[i] <= 0x20 || strchr("<>\"'&:\\", (char)res->payload[i])) {

      if (!in_space) {

        in_space = 1;
        if (c_len && ++c_len <= FP_MAX_LEN)
          res->sig.data[c_len % FP_SIZE]++;
        c_len = 0;

      } else c_len++;

      if (res->payload[i] == '&')
        do { i++; } while (i < res->pay_len &&
                           (isalnum(res->payload[i]) || strchr("#;", (char)res->payload[i])));


    } else {

      if (in_space) {

        in_space = 0;
        if (c_len && ++c_len <= FP_MAX_LEN)
          res->sig.data[c_len % FP_SIZE]++;
        c_len = 0;

      } else {
        res->sig.has_text = 1;
        c_len++;
      }

    }

  if (c_len) res->sig.data[c_len % FP_SIZE]++;
}

/* Parses a network buffer containing raw HTTP response received over the
   network ('more' == the socket is still available for reading). Returns 0
   if response parses OK, 1 if more data should be read from the socket,
   2 if the response seems invalid, 3 if response OK but connection must be
   closed. */

u8 parse_response(struct http_request* req, struct http_response* res,
                  u8* data, u32 data_len, u8 more) {
  u8* cur_line = 0;
  s32 pay_len  = -1;
  u32 cur_data_off = 0,
      total_chunk = 0,
      http_ver;
  u8  chunked = 0, compressed = 0, must_close = 0;

  if (res->code)
    FATAL("struct http_response reused! Original code '%u'.", res->code);

#define NEXT_LINE() do { \
    if (cur_line) ck_free(cur_line); \
    cur_line = grab_line(data, &cur_data_off, data_len); \
  } while (0)

  /* First, let's do a superficial request completeness check. Be
     prepared for a premature end at any point. */

  NEXT_LINE(); /* HTTP/1.x xxx ... */

  if (!cur_line) return more ? 1 : 2;

  if (strlen((char*)cur_line) < 7 && more) {
    ck_free(cur_line);
    return 1;
  }

  if (prefix(cur_line, "HTTP/1.")) {
    ck_free(cur_line);
    return 2;
  }

  /* Scan headers for Content-Length, Transfer-Encoding, etc. */

  while (1) {

    NEXT_LINE(); /* Next header or empty line. */

    /* If headers end prematurely, and more data might arrive, ask for
       it; otherwise, just assume end of headers and continue. */

    if (!cur_line) {
      if (more) return 1;
      res->warn |= WARN_PARTIAL;
      break;
    }

    /* Empty line indicates the beginning of a payload. */

    if (!cur_line[0]) break;

    if (!case_prefix(cur_line, "Content-Length:")) {

      /* The value in Content-Length header would be useful for seeing if we
         have all the requested data already. Reject invalid values to avoid
         integer overflows, etc, though. */

      if (sscanf((char*)cur_line + 15, "%d", &pay_len) == 1) {
        if (pay_len < 0 || pay_len > 1000000000 /* 1 GB */) {
          ck_free(cur_line);
          return 2;
        }
      } else pay_len = -1;

    } else if (!case_prefix(cur_line, "Transfer-Encoding:")) {

      /* Transfer-Encoding: chunked must be accounted for to properly
         determine if we received all the data when Content-Length not found. */

      u8* x = cur_line + 18;

      while (isspace(*x)) x++;
      if (!strcasecmp((char*)x, "chunked")) chunked = 1;

    } else if (!case_prefix(cur_line, "Content-Encoding:")) {

      /* Content-Encoding is good to know, too. */

      u8* x = cur_line + 17;

      while (isspace(*x)) x++;

      if (!strcasecmp((char*)x, "deflate") || !strcasecmp((char*)x, "gzip"))
        compressed = 1;

    } else if (!case_prefix(cur_line, "Connection:")) {

      u8* x = cur_line + 11;

      while (isspace(*x)) x++;

      if (!strcasecmp((char*)x, "close")) must_close = 1;

    }
  }

  /* We are now at the beginning of the payload. Firstly, how about decoding
     'chunked' to see if we received a complete 0-byte terminator chunk
     already? */

  if (chunked) {
    while (1) {
      u32 chunk_len;

      NEXT_LINE(); /* Should be chunk size, hex. */

      if (!cur_line || sscanf((char*)cur_line, "%x", &chunk_len) != 1) {
        if (more) { ck_free(cur_line); return 1; }
        res->warn |= WARN_PARTIAL;
        break;
      }

      if (chunk_len > 1000000000 || total_chunk > 1000000000 /* 1 GB */) {
        ck_free(cur_line);
        return 2;
      }

      /* See if we actually enough buffer to skip the chunk. Bail out if
         not and more data might be coming; otherwise, adjust chunk size
         accordingly. */

      if (cur_data_off + chunk_len > data_len) {

        if (more) { ck_free(cur_line); return 1; }
        chunk_len = data_len - cur_data_off;
        total_chunk += chunk_len;

        res->warn |= WARN_PARTIAL;
        break;
      }

      total_chunk += chunk_len;

      cur_data_off += chunk_len;
      NEXT_LINE();

      /* No newline? */
      if (!cur_line) {
        if (more) return 1;
        res->warn |= WARN_PARTIAL;
      }

      /* All right, so that was the last, complete 0-size chunk?
         Exit the loop if so. */

      if (!chunk_len) break;

    }

    if (cur_data_off != data_len) res->warn |= WARN_TRAIL;

  } else if (pay_len == -1 && more) {

    /* If in a mode other than 'chunked', and C-L not received, but more
       data might be available - try to request it. */

    ck_free(cur_line);
    return 1;

  } else if (pay_len != 1) {

    if (cur_data_off + pay_len > data_len) {

      /* If C-L seen, but not nough data in the buffer, try to request more
         if possible, otherwise tag the response as partial. */

      if (more) { ck_free(cur_line); return 1; }
      res->warn |= WARN_PARTIAL;

    } else if (cur_data_off + pay_len < data_len) res->warn |= WARN_TRAIL;

  }

  /* Rewind, then properly parse HTTP headers, parsing cookies. */

  cur_data_off = 0;

  NEXT_LINE();

  if (strlen((char*)cur_line) < 13 ||
      sscanf((char*)cur_line, "HTTP/1.%u %u ", &http_ver, &res->code) != 2 ||
      res->code < 100 || res->code > 999) {
    ck_free(cur_line);
    return 2;
  }

  /* Some servers, when presented with 'Range' header, will return 200 on
     some queries for a particular resource, and 206 on other queries (e.g.,
     with query string), despite returning exactly as much data. As an
     ugly workaround... */

  if (res->code == 206) res->code = 200;

  if (http_ver == 0) must_close = 1;

  res->msg = ck_strdup(cur_line + 13);

  while (1) {
    u8* val;

    NEXT_LINE(); /* Next header or empty line. */

    if (!cur_line) return 2;
    if (!cur_line[0]) break;

    /* Split field name and value */

    val = (u8*) strchr((char*)cur_line, ':');
    if (!val) { ck_free(cur_line); return 2; }

    *val = 0;
    while (isspace(*(++val)));

    SET_HDR(cur_line, val, &res->hdr);
    if (!strcasecmp((char*)cur_line, "Set-Cookie") ||
        !strcasecmp((char*)cur_line, "Set-Cookie2")) {

       /* We could bother with a proper tokenizer here, but contrary to "teh
          standards", browsers generally don't accept multiple cookies in
          Set-Cookie headers, handle quoted-string encoding inconsistently,
          etc. So let's just grab the first value naively and move on. */

       u8* cval;
       u8* orig_val;

       cval = (u8*) strchr((char*)val, ';');
       if (cval) *cval = 0;
       cval = (u8*) strchr((char*)val, '=');
       if (cval) { *cval = 0; cval++; }

       /* If proper value not found, use NULL name and put whatever was
          found in the value field. */

       if (!cval) { cval = val; val = 0; }

       if (cval) SET_CK(val, cval, &res->hdr);

       if (val) {

         /* New or drastically changed cookies are noteworthy. */

         orig_val = GET_CK(val, &global_http_par);

         if (!orig_val || (strlen((char*)orig_val) != strlen((char*)cval) &&
             strncmp((char*)cval, (char*)orig_val, 3))) {
           res->cookies_set = 1;
           problem(PROB_NEW_COOKIE, req, res, val, req->pivot, 0);

         }

         /* Set cookie globally, but ignore obvious attempts to delete
            existing ones. */

         if (!ignore_cookies && val && cval[0])
           SET_CK(val, cval, &global_http_par);

      }
    }

    /* Content-Type is worth mining for MIME, charset data at this point. */

    if (!strcasecmp((char*)cur_line, "Content-Type")) {

      if (res->header_mime) {

        /* Duplicate Content-Type. Fetch previous value, if different,
           complain. */

        u8* tmp = GET_HDR((u8*)"Content-Type", &res->hdr);
        if (strcasecmp((char*)tmp, (char*)val)) res->warn |= WARN_CFL_HDR;

      } else {
        u8 *tmp = (u8*)strchr((char*)val, ';'), *cset;

        if (tmp) {
          *tmp = 0;
          if ((cset = (u8*)strchr((char*)tmp + 1, '=')))
            res->header_charset = ck_strdup(cset + 1);
        }

        res->header_mime = ck_strdup(val);
        if (tmp) *tmp = ';';
      }

    }

  }

  /* At the beginning of the payload again! */

  if (!chunked) {

    /* Identity. Ignore actual C-L data, use just as much as we collected. */

    res->pay_len = data_len - cur_data_off;
    res->payload = ck_alloc(res->pay_len + 1);
    res->payload[res->pay_len] = 0; /* NUL-terminate for safer parsing. */

    memcpy(res->payload, data + cur_data_off, res->pay_len);

  } else {

    u32 chunk_off = 0;

    /* Chunked - we should have the authoritative length of chunk
       contents in total_chunk already, and the overall structure
       validated, so let's just reparse quickly. */

    res->pay_len = total_chunk;
    res->payload = ck_alloc(total_chunk + 1);
    res->payload[res->pay_len] = 0;

    while (1) {
      u32 chunk_len;

      NEXT_LINE();

      if (!cur_line || sscanf((char*)cur_line, "%x", &chunk_len) != 1) break;

      if (cur_data_off + chunk_len > data_len)
        chunk_len = data_len - cur_data_off;

      memcpy(res->payload + chunk_off, data + cur_data_off, chunk_len);

      chunk_off += chunk_len;
      cur_data_off += chunk_len;

      NEXT_LINE();

      if (!chunk_len) break;
    }

  }

  ck_free(cur_line);

  if (compressed) {

    u8* tmp_buf;

    /* Deflate or gzip - zlib can handle both the same way. We lazily allocate
       a size_limit output buffer, then truncate it if necessary. */

    z_stream d;
    s32 err;

    tmp_buf = ck_alloc(size_limit + 1);

    d.zalloc    = 0;
    d.zfree     = 0;
    d.opaque    = 0;
    d.next_in   = res->payload;
    d.avail_in  = res->pay_len;
    d.next_out  = tmp_buf;
    d.avail_out = size_limit;

    /* Say hello to third-party vulnerabilities! */

    if (inflateInit2(&d, 32 + 15) != Z_OK) {
      inflateEnd(&d);
      ck_free(tmp_buf);
      return 2;
    }

    err = inflate(&d, Z_FINISH);
    inflateEnd(&d);

    if (err != Z_BUF_ERROR && err != Z_OK && err != Z_STREAM_END) {
      ck_free(tmp_buf);
      return 2;
    }

    ck_free(res->payload);

    bytes_deflated += res->pay_len;

    res->pay_len = size_limit - d.avail_out;
    res->payload = ck_realloc(tmp_buf, res->pay_len + 1);
    res->payload[res->pay_len] = 0;


    bytes_inflated += res->pay_len;

  }

#undef NEXT_LINE

  fprint_response(res);

  return must_close ? 3 : 0;
}


/* Performs a deep free() of struct http_request */

void destroy_request(struct http_request* req) {
  u32 i;

  for (i=0;i<req->par.c;i++) {
    ck_free(req->par.n[i]);
    ck_free(req->par.v[i]);
  }

  ck_free(req->par.t);
  ck_free(req->par.n);
  ck_free(req->par.v);

  ck_free(req->method);
  ck_free(req->host);
  ck_free(req->orig_url);
  ck_free(req);

}


/* Performs a deep free() of struct http_response */

void destroy_response(struct http_response* res) {
  u32 i;

  for (i=0;i<res->hdr.c;i++) {
    ck_free(res->hdr.n[i]);
    ck_free(res->hdr.v[i]);
  }

  ck_free(res->hdr.t);
  ck_free(res->hdr.n);
  ck_free(res->hdr.v);

  ck_free(res->meta_charset);
  ck_free(res->header_charset);
  ck_free(res->header_mime);

  ck_free(res->msg);
  ck_free(res->payload);
  ck_free(res);

}


/* Performs a deep free(), unlinking of struct queue_entry, and the
   underlying request / response pair. */

static void destroy_unlink_queue(struct queue_entry* q, u8 keep) {
  if (!keep) {
    if (q->req) destroy_request(q->req);
    if (q->res) destroy_response(q->res);
  }
  if (!q->prev) queue = q->next; else q->prev->next = q->next;
#ifdef QUEUE_FILO
  if (!q->next) q_tail = q->prev;
#endif /* QUEUE_FILO */
  if (q->next) q->next->prev = q->prev;
  ck_free(q);
  queue_cur--;
}


/* Performs a deep free(), unlinking, network shutdown for struct
   conn_entry, as well as the underlying queue entry, request
   and response structs. */

static void destroy_unlink_conn(struct conn_entry* c, u8 keep) {
  if (c->q) destroy_unlink_queue(c->q, keep);
  if (!c->prev) conn = c->next; else c->prev->next = c->next;
  if (c->next) c->next->prev = c->prev;
  if (c->srv_ssl) SSL_free(c->srv_ssl);
  if (c->srv_ctx) SSL_CTX_free(c->srv_ctx);
  ck_free(c->write_buf);
  ck_free(c->read_buf);
  close(c->fd);
  ck_free(c);
  conn_cur--;
}


/* Performs struct conn_entry for reuse following a clean shutdown. */

static void reuse_conn(struct conn_entry* c, u8 keep) {

  if (c->q) destroy_unlink_queue(c->q, keep);
  c->q = 0;
  ck_free(c->read_buf);
  ck_free(c->write_buf);
  c->read_buf = c->write_buf = NULL;
  c->read_len = c->write_len = c->write_off = 0;
  c->SSL_rd_w_wr = c->SSL_wr_w_rd = 0;
}


/* Schedules a new asynchronous request (does not make a copy of the
   original http_request struct, may deallocate it immediately or
   later on); req->callback() will be invoked when the request is
   completed (or fails - maybe right away). */

void async_request(struct http_request* req) {
  struct queue_entry *qe;
  struct http_response *res;

  if (req->proto == PROTO_NONE || !req->callback)
    FATAL("uninitialized http_request");

  res = ck_alloc(sizeof(struct http_response));

  req->addr = maybe_lookup_host(req->host);

  /* Don't try to issue extra requests if max_fail
     consecutive failures exceeded; but still try to
     wrap up the (partial) scan. */

  if (req_errors_cur > max_fail) {
    DEBUG("!!! Too many subsequent request failures!\n");
    res->state = STATE_SUPPRESS;
    if (!req->callback(req, res)) {
      destroy_request(req);
      destroy_response(res);
    }
    req_dropped++;
    return;
  }

  /* DNS errors mean instant fail. */

  if (!req->addr) {
    DEBUG("!!! DNS error!\n");
    res->state = STATE_DNSERR;
    if (!req->callback(req, res)) {
      destroy_request(req);
      destroy_response(res);
    }
    req_errors_net++;
    conn_count++;
    conn_failed++;
    return;
  }

  /* Enforce user limits. */

  if (req_count > max_requests) {
    DEBUG("!!! Total request limit exceeded!\n");
    res->state = STATE_SUPPRESS;
    if (!req->callback(req, res)) {
      destroy_request(req);
      destroy_response(res);
    }
    req_dropped++;
    return;
  }

  /* OK, looks like we're good to go. Insert the request
     into the the queue. */

#ifdef QUEUE_FILO

  qe = q_tail;
  q_tail = ck_alloc(sizeof(struct queue_entry));
  q_tail->req  = req;
  q_tail->res  = res;
  q_tail->prev = qe;

  if (q_tail->prev) q_tail->prev->next = q_tail;

  if (!queue) queue = q_tail;

#else

  qe = queue;

  queue = ck_alloc(sizeof(struct queue_entry));
  queue->req  = req;
  queue->res  = res;
  queue->next = qe;

  if (queue->next) queue->next->prev = queue;

#endif /* ^QUEUE_FILO */

  queue_cur++;
  req_count++;

}


/* Check SSL properties, raise security alerts if necessary. We do not perform
   a very thorough validation - we do not check for valid root CAs, bad ciphers,
   SSLv2 support, etc - as these are covered well by network-level security
   assessment tools anyway.

   We might eventually want to check aliases or support TLS SNI. */

static void check_ssl(struct conn_entry* c) {
  X509 *p;
  SSL_CIPHER *cp;

  /* Test if a weak cipher has been negotiated  */
  cp = SSL_get_current_cipher(c->srv_ssl);
  if(!(cp->algo_strength & SSL_MEDIUM) && !(cp->algo_strength & SSL_HIGH))
      problem(PROB_SSL_WEAK_CIPHER, c->q->req, 0,
        (u8*)SSL_CIPHER_get_name(cp),host_pivot(c->q->req->pivot), 0);


  p = SSL_get_peer_certificate(c->srv_ssl);

  if (p) {
    u32 cur_time = time(0);
    char *issuer, *host, *req_host;

    /* Check for certificate expiration... */

    if (ASN1_UTCTIME_cmp_time_t(p->cert_info->validity->notBefore, cur_time)
        != -1 ||
        ASN1_UTCTIME_cmp_time_t(p->cert_info->validity->notAfter, cur_time)
        != 1)
      problem(PROB_SSL_CERT_DATE, c->q->req, 0, 0,
              host_pivot(c->q->req->pivot), 0);

    /* Check for self-signed certs or no issuer data. */

    issuer = X509_NAME_oneline(p->cert_info->issuer,NULL,0);

    if (!issuer || !p->name || !strcmp(issuer, p->name))
      problem(PROB_SSL_SELF_CERT, c->q->req, 0, (u8*)issuer,
              host_pivot(c->q->req->pivot), 0);
    else
      problem(PROB_SSL_CERT, c->q->req, 0, (u8*)issuer,
              host_pivot(c->q->req->pivot), 0);

    free(issuer);

    /* Extract CN= from certificate name, compare to destination host. */

    host = strrchr(p->name, '=');
    req_host = (char*)c->q->req->host;

    if (host) {
      host++;
      if (host[0] == '*' && host[1] == '.') {
        host++;
        if (strlen(req_host) > strlen(host))
          req_host += strlen(req_host) - strlen(host);
      }
    }

    if (!host || strcasecmp(host, req_host))
      problem(PROB_SSL_BAD_HOST, c->q->req, 0, (u8*)host,
              host_pivot(c->q->req->pivot), 0);

    X509_free(p);

  } else problem(PROB_SSL_NO_CERT, c->q->req, 0, 0,
                 host_pivot(c->q->req->pivot), 0);

  c->ssl_checked = 1;
}


/* Associates a queue entry with an existing connection (if 'use_c' is
   non-NULL), or creates a new connection to host (if 'use_c' NULL). */

static void conn_associate(struct conn_entry* use_c, struct queue_entry* q) {
  struct conn_entry* c;

  if (use_c) {

    c = use_c;
    c->reused = 1;

  } else {

    struct sockaddr_in sin;

    /* OK, we need to create a new connection list entry and connect
       it to a target host. */

    c = ck_alloc(sizeof(struct conn_entry));

    conn_count++;

    c->proto = q->req->proto;
    c->addr  = q->req->addr;
    c->port  = q->req->port;

    c->fd = socket(PF_INET, SOCK_STREAM, 0);

    if (c->fd < 0) {

connect_error:

      if (c->fd >=0) close(c->fd);
      q->res->state = STATE_LOCALERR;
      destroy_unlink_queue(q, q->req->callback(q->req, q->res));
      req_errors_net++;
      req_errors_cur++;

      ck_free(c);
      conn_failed++;
      return;
    }

    sin.sin_family = PF_INET;

#ifdef PROXY_SUPPORT
    sin.sin_port   = htons(use_proxy ? use_proxy_port : c->port);
#else
    sin.sin_port   = htons(c->port);
#endif /* ^PROXY_SUPPORT */

    memcpy(&sin.sin_addr, &q->req->addr, 4);

    fcntl(c->fd, F_SETFL, O_NONBLOCK);

    if (connect(c->fd, (struct sockaddr*) &sin, sizeof(struct sockaddr_in)) &&
        (errno != EINPROGRESS)) goto connect_error;

    /* HTTPS also requires SSL state to be initialized at this point. */

    if (c->proto == PROTO_HTTPS) {

      c->srv_ctx = SSL_CTX_new(SSLv23_client_method());

      if (!c->srv_ctx) goto connect_error;

      SSL_CTX_set_mode(c->srv_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE |
                       SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

      c->srv_ssl = SSL_new(c->srv_ctx);

      if (!c->srv_ssl) {
        SSL_CTX_free(c->srv_ctx);
        goto connect_error;
      }

      SSL_set_fd(c->srv_ssl, c->fd);
      SSL_set_connect_state(c->srv_ssl);

    }

    /* Make it official. */

    c->next  = conn;
    conn     = c;
    if (c->next) c->next->prev = c;

    conn_cur++;

  }

  c->q = q;
  q->c = c;

  q->res->state = STATE_CONNECT;
  c->req_start  = c->last_rw = time(0);
  c->write_buf  = build_request_data(q->req);
  c->write_len  = strlen((char*)c->write_buf);

}


/* Processes the queue. Returns the number of queue entries remaining,
   0 if none. Will do a blocking select() to wait for socket state changes
   (or timeouts) if no data available to process. This is the main
   routine for the scanning loop. */

u32 next_from_queue(void) {

  u32 cur_time = time(0);

  if (conn_cur) {
    static struct pollfd* p;

    struct conn_entry* c = conn;
    u32 i = 0;

    /* First, go through all connections, handle connects, SSL handshakes, data
       reads and writes, and exceptions. */

    if (!p)
      p = __DFL_ck_alloc(sizeof(struct pollfd) * max_connections);

    while (c) {
      p[i].fd = c->fd;
      p[i].events = POLLIN | POLLERR | POLLHUP;
      if (c->write_len - c->write_off || c->SSL_rd_w_wr)
        p[i].events |= POLLOUT;
      p[i].revents = 0;
      c = c->next;
      i++;
    }

    poll(p, conn_cur, 100);

    c = conn;

    for (i=0;i<conn_cur;i++) {

      struct conn_entry* next = c->next;

      /* Connection closed: see if we have any pending data to write. If yes,
         fail. If not, try parse_response() to see if we have all the data.
         Clean up. */

      if (p[i].revents & (POLLERR|POLLHUP)) {

        u8 keep;

network_error:

        keep = 0;

        /* Retry requests that were sent on old keep-alive connections
           and failed instantly with no data read; might be just that
           the server got bored. */

        if (c->q && !c->q->retrying && c->reused && !c->read_len) {

          c->q->res->state = STATE_NOTINIT;
          c->q->retrying   = 1;
          c->q->c          = 0;
          c->q             = 0;

          req_retried++;

        } else if (c->q) {

          if (c->write_len - c->write_off || !c->read_len) {
            c->q->res->state = STATE_CONNERR;
            keep = c->q->req->callback(c->q->req, c->q->res);
            req_errors_net++;
            req_errors_cur++;
          } else {
            if (parse_response(c->q->req, c->q->res, c->read_buf,
                               c->read_len, 0) != 2) {
              c->q->res->state = STATE_OK;
              keep = c->q->req->callback(c->q->req, c->q->res);
              if (req_errors_cur <= max_fail)
                req_errors_cur = 0;
            } else {
              c->q->res->state = STATE_CONNERR;
              keep = c->q->req->callback(c->q->req, c->q->res);
              req_errors_net++;
              req_errors_cur++;
            }
          }

        }

        destroy_unlink_conn(c, keep);

      } else

      /* Incoming data (when SSL_write() did not request a read) or
         continuation of SSL_read() possible (if SSL_read() wanted to write).
         Process data, call parse_response() to see if w have all we wanted.
         Update event timers. */

      if (((p[i].revents & POLLIN) && !c->SSL_wr_w_rd) ||
          ((p[i].revents & POLLOUT) && c->SSL_rd_w_wr)) {

        if (c->q) {
          s32 read_res;
          u8 p_ret;

SSL_read_more:

          c->read_buf = ck_realloc(c->read_buf, c->read_len + READ_CHUNK + 1);

          if (c->proto == PROTO_HTTPS) {
            s32 ssl_err;

            c->SSL_rd_w_wr = 0;

            read_res = SSL_read(c->srv_ssl, c->read_buf + c->read_len,
                                READ_CHUNK);

            if (!read_res) goto network_error;

            if (read_res < 0) {
              ssl_err = SSL_get_error(c->srv_ssl, read_res);
              if (ssl_err == SSL_ERROR_WANT_WRITE) c->SSL_rd_w_wr = 1;
              else if (ssl_err != SSL_ERROR_WANT_READ) goto network_error;
              read_res = 0;
            }

          } else {
            read_res = read(c->fd, c->read_buf + c->read_len, READ_CHUNK);
            if (read_res <= 0) goto network_error;
          }

          bytes_recv += read_res;

          c->read_len += read_res;
          c->read_buf = ck_realloc(c->read_buf, c->read_len + 1);

          /* Retry reading until SSL_ERROR_WANT_READ. */

          if (c->proto == PROTO_HTTPS &&
              read_res && c->read_len < size_limit) goto SSL_read_more;

          c->read_buf[c->read_len] = 0; /* NUL-terminate for sanity. */

          /* We force final parse_response() if response length exceeded
             size_limit by more than 4 kB. The assumption here is that
             it is less expensive to redo the connection than it is
             to continue receiving an unknown amount of extra data. */

          p_ret = parse_response(c->q->req, c->q->res, c->read_buf, c->read_len,
            (c->read_len > (size_limit + READ_CHUNK)) ? 0 : 1);

          if (!p_ret || p_ret == 3) {

            u8 keep;

            c->q->res->state = STATE_OK;
            keep = c->q->req->callback(c->q->req, c->q->res);

            /* If we got all data without hitting the limit, and if
               "Connection: close" is not indicated, we might want
               to keep the connection for future use. */

            if (c->read_len > (size_limit + READ_CHUNK) || p_ret)
              destroy_unlink_conn(c, keep); else reuse_conn(c, keep);

            if (req_errors_cur <= max_fail)
              req_errors_cur = 0;

          } else if (p_ret == 2) {
            c->q->res->state = STATE_RESPERR;
            destroy_unlink_conn(c, c->q->req->callback(c->q->req, c->q->res));
            req_errors_http++;
            req_errors_cur++;
          } else {
            c->last_rw = cur_time;
            c->q->res->state = STATE_RECEIVE;
          }

        } else destroy_unlink_conn(c, 0); /* Unsolicited response! */

      } else

      /* Write possible (if SSL_read() did not request a write), or
         continuation of SSL_write() possible (if SSL_write() wanted to
         read). Send data, update timers, etc. */

      if (((p[i].revents & POLLOUT) && !c->SSL_rd_w_wr) ||
          ((p[i].revents & POLLIN) && c->SSL_wr_w_rd)) {

        if (c->write_len - c->write_off) {
          s32 write_res;

          if (c->proto == PROTO_HTTPS) {
            s32 ssl_err;

            c->SSL_wr_w_rd = 0;

            write_res = SSL_write(c->srv_ssl, c->write_buf + c->write_off,
                                 c->write_len - c->write_off);

            if (!write_res) goto network_error;

            if (write_res < 0) {
              ssl_err = SSL_get_error(c->srv_ssl, write_res);
              if (ssl_err == SSL_ERROR_WANT_READ) c->SSL_wr_w_rd = 1;
              else if (ssl_err != SSL_ERROR_WANT_WRITE) goto network_error;
              write_res = 0;
            } else if (!c->ssl_checked) check_ssl(c);

          } else {
            write_res = write(c->fd, c->write_buf + c->write_off,
                              c->write_len - c->write_off);
            if (write_res <= 0) goto network_error;
          }

          bytes_sent += write_res;

          c->write_off += write_res;

          c->q->res->state = STATE_SEND;

          c->last_rw = cur_time;

        }

      } else

      /* Nothing happened. Check timeouts, kill stale connections.
         Active (c->q) connections get checked for total and last I/O
         timeouts. Non-active connections must just not exceed
         idle_tmout. */

      if (!p[i].revents) {

        u8 keep = 0;

        if ((c->q && (cur_time - c->last_rw > rw_tmout ||
            cur_time - c->req_start > resp_tmout)) ||
            (!c->q && (cur_time - c->last_rw > idle_tmout)) ||
            (!c->q && tear_down_idle)) {

          if (c->q) {
            c->q->res->state = STATE_CONNERR;
            keep = c->q->req->callback(c->q->req, c->q->res);
            req_errors_net++;
            req_errors_cur++;
            conn_busy_tmout++;
          } else {
            conn_idle_tmout++;
            tear_down_idle = 0;
          }

          destroy_unlink_conn(c, keep);

        }

      }

      c = next;

    }

  }

  /* OK, connection-handling affairs taken care of! Next, let's go through all
     queue entries NOT currently associated with a connection, and try to
     pair them up with something. */

  if (queue_cur) {
    struct queue_entry *q = queue;

    while (q) {
      u32 to_host = 0;

      // enforce the max requests per seconds requirement
      if (max_requests_sec && req_sec > max_requests_sec) {
        u32 diff = req_sec - max_requests_sec;

        DEBUG("req_sec=%f max=%f diff=%u\n", req_sec, max_requests_sec, diff);
        if ((iterations_cnt++)%(diff + 1) != 0) {
            idle = 1;
            return queue_cur;
        }
      }
      idle = 0;

      struct queue_entry* next = q->next;

      if (!q->c) {

        struct conn_entry* c = conn;

        /* Let's try to find a matching, idle connection first. */

        while (c) {
          struct conn_entry* cnext = c->next;

          if (c->addr == q->req->addr   && (++to_host) &&
              c->port == q->req->port   &&
              c->proto == q->req->proto && !c->q) {
            conn_associate(c, q);
            goto next_q_entry;
          }

          c = cnext;
        }

        /* No match. If we are out of slots, request some other idle
           connection to be nuked soon. */

        if (to_host < max_conn_host && conn_cur < max_connections) {
          conn_associate(0, q);
          goto next_q_entry;
        } else tear_down_idle = 1;

      }

next_q_entry:

      q = next;

    }

  }

  return queue_cur;
}


/* Helper function for request / response dumpers: */
static void dump_params(struct param_array* par) {
  u32 i;

  for (i=0;i<par->c;i++) {

    switch (par->t[i]) {
      case PARAM_NONE:     SAY("  <<<<"); break;
      case PARAM_PATH:     SAY("  PATH"); break;
      case PARAM_PATH_S:   SAY("  PT_S"); break;
      case PARAM_PATH_C:   SAY("  PT_C"); break;
      case PARAM_PATH_E:   SAY("  PT_E"); break;
      case PARAM_PATH_D:   SAY("  PT_D"); break;
      case PARAM_QUERY:    SAY("  QUER"); break;
      case PARAM_QUERY_S:  SAY("  QR_S"); break;
      case PARAM_QUERY_C:  SAY("  QR_C"); break;
      case PARAM_QUERY_E:  SAY("  QR_E"); break;
      case PARAM_QUERY_D:  SAY("  QR_D"); break;
      case PARAM_POST:     SAY("  POST"); break;
      case PARAM_POST_F:   SAY("  FILE"); break;
      case PARAM_POST_O:   SAY("  OPAQ"); break;
      case PARAM_HEADER:   SAY("  head"); break;
      case PARAM_COOKIE:   SAY("  cook"); break;
      default:             SAY("  ????");
    }

    SAY(":%-20s = '%s'\n",
        par->n[i] ? par->n[i] : (u8*)"-",
        par->v[i] ? par->v[i] : (u8*)"-");

  }
}


/* Creates a working copy of a request. If all is 0, does not copy
   path, query parameters, or POST data (but still copies headers). */

struct http_request* req_copy(struct http_request* req, struct pivot_desc* pv,
                              u8 all) {
  struct http_request* ret;
  u32 i;

  if (!req) return NULL;

  ret = ck_alloc(sizeof(struct http_request));

  ret->proto  = req->proto;

  if (all)
    ret->method = ck_strdup(req->method);
  else
    ret->method = ck_strdup((u8*)"GET");

  ret->host     = ck_strdup(req->host);
  ret->addr     = req->addr;
  ret->port     = req->port;
  ret->pivot    = pv;
  ret->user_val = req->user_val;

  /* Copy all the requested data. */

  for (i=0;i<req->par.c;i++)
    if (all || HEADER_SUBTYPE(req->par.t[i]))
      set_value(req->par.t[i], req->par.n[i], req->par.v[i], -1,
                &ret->par);

  memcpy(&ret->same_sig, &req->same_sig, sizeof(struct http_sig));

  return ret;

}


/* Creates a copy of a response. */

struct http_response* res_copy(struct http_response* res) {
  struct http_response* ret;
  u32 i;

  if (!res) return NULL;

  ret = ck_alloc(sizeof(struct http_response));

  ret->state = res->state;
  ret->code  = res->code;
  ret->msg   = res->msg ? ck_strdup(res->msg) : NULL;
  ret->warn  = res->warn;

  for (i=0;i<res->hdr.c;i++)
    set_value(res->hdr.t[i], res->hdr.n[i], res->hdr.v[i], -1, &ret->hdr);

  ret->pay_len = res->pay_len;

  if (res->pay_len) {
    ret->payload = ck_alloc(res->pay_len);
    memcpy(ret->payload, res->payload, res->pay_len);
  }

  memcpy(&ret->sig, &res->sig, sizeof(struct http_sig));

  ret->sniff_mime_id = res->sniff_mime_id;
  ret->decl_mime_id  = res->decl_mime_id;
  ret->doc_type      = res->doc_type;
  ret->css_type      = res->css_type;
  ret->js_type       = res->js_type;
  ret->json_safe     = res->json_safe;
  ret->stuff_checked = res->stuff_checked;
  ret->scraped       = res->scraped;

  if (res->meta_charset)
    ret->meta_charset = ck_strdup(res->meta_charset);

  if (res->header_charset)
    ret->header_charset = ck_strdup(res->header_charset);

  if (res->header_mime)
    ret->header_mime = ck_strdup(res->header_mime);

  ret->sniffed_mime = res->sniffed_mime;

  return ret;

}

/* Dumps HTTP request data, for diagnostic purposes: */

void dump_http_request(struct http_request* r) {

  u8 *new_url, *tmp;

  SAY("\n== HTTP REQUEST %p ==\n\nBasic values:\n", r);

  SAY("  Proto   = %u\n", r->proto);
  SAY("  Method  = %s\n", r->method ? r->method : (u8*)"(GET)");
  SAY("  Host    = %s\n", r->host);
  SAY("  Addr    = %u.%u.%u.%u\n", ((u8*)&r->addr)[0], ((u8*)&r->addr)[1],
                                      ((u8*)&r->addr)[2], ((u8*)&r->addr)[3]);
  SAY("  Port    = %d\n", r->port);
  SAY("  Xrefs   = pivot %p, handler %p, user %d\n", r->pivot,
      r->callback, r->user_val);

  new_url = serialize_path(r, 1, 0);

  SAY("\nURLs:\n  Original  = %s\n"
      "  Synthetic = %s\n", r->orig_url ? r->orig_url : (u8*)"[none]",
      new_url);

  ck_free(new_url);

  SAY("\nParameter array:\n");

  dump_params(&r->par);

  SAY("\nRaw request data:\n\n");

  tmp = build_request_data(r);
  SAY("%s\n",tmp);
  ck_free(tmp);

  SAY("\n== END OF REQUEST ==\n");

}


/* Dumps HTTP response data, likewise: */

void dump_http_response(struct http_response* r) {

  SAY("\n== HTTP RESPONSE %p ==\n\nBasic values:\n", r);

  SAY("  State    = %u\n", r->state);
  SAY("  Response = %u ('%s')\n", r->code, r->msg);
  SAY("  Flags    = %08x\n", r->warn);
  SAY("  Data len = %u\n", r->pay_len);

  SAY("\nParameter array:\n");

  dump_params(&r->hdr);

  if (r->payload) SAY("\nPayload data (%u):\n\n%s\n", r->pay_len, r->payload);

  SAY("\n== END OF RESPONSE ==\n");

}

/* Destroys http state information, for memory profiling. */

void destroy_http() {
  u32 i;
  struct dns_entry* cur;

  for (i=0;i<global_http_par.c;i++) {
    ck_free(global_http_par.n[i]);
    ck_free(global_http_par.v[i]);
  }

  ck_free(global_http_par.t);
  ck_free(global_http_par.n);
  ck_free(global_http_par.v);

  while (conn) destroy_unlink_conn(conn,0 );
  while (queue) destroy_unlink_queue(queue,0 );

  cur = dns;

  while (cur) {
   struct dns_entry* next = cur->next;
   ck_free(cur->name);
   ck_free(cur);
   cur = next;
  }

}


/* Shows some pretty statistics. */

void http_stats(u64 st_time) {
  u64 en_time;
  struct timeval tv;

  gettimeofday(&tv, NULL);
  en_time = tv.tv_sec * 1000LL + tv.tv_usec / 1000;

  SAY(cLBL "Scan statistics:\n\n"
      cGRA "      Scan time : " cNOR "%u:%02u:%02u.%03u\n"
      cGRA "  HTTP requests : " cNOR "%u (%.01f/s), %llu kB in, "
                                      "%llu kB out (%.01f kB/s)  \n"
      cGRA "    Compression : " cNOR "%llu kB in, %llu kB out "
                               "(%.01f%% gain)    \n"
      cGRA "    HTTP faults : " cNOR "%u net errors, %u proto errors, "
                               "%u retried, %u drops\n"
      cGRA " TCP handshakes : " cNOR "%u total (%.01f req/conn)  \n"
      cGRA "     TCP faults : " cNOR "%u failures, %u timeouts, %u purged\n"
      cGRA " External links : " cNOR "%u skipped\n"
      cGRA "   Reqs pending : " cNOR "%u        \n",

      /* hrs */ (u32)((en_time - st_time) / 1000 / 60 / 60),
      /* min */ (u32)((en_time - st_time) / 1000 / 60) % 60,
      /* sec */ (u32)((en_time - st_time) / 1000) % 60,
      /* ms  */ (u32)((en_time - st_time) % 1000),

      req_count - queue_cur,
      (float) (req_count - queue_cur / 1.15) * 1000 / (en_time - st_time + 1),
      (unsigned long long int) bytes_recv / 1024,
      (unsigned long long int) bytes_sent / 1024,
      (float) (bytes_recv + bytes_sent) / 1.024 / (en_time - st_time + 1),

      (unsigned long long int) bytes_deflated / 1024,
      (unsigned long long int) bytes_inflated / 1024,
      ((float) bytes_inflated - bytes_deflated) / (bytes_inflated +
      bytes_deflated + 1) * 100,

      req_errors_net, req_errors_http, req_retried, req_dropped,

      conn_count, (float) req_count / conn_count,
      conn_failed, conn_busy_tmout, conn_idle_tmout,
      url_scope, queue_cur);
}


/* Show currently handled requests. */

#define SP70 \
  "                                                                      "

void http_req_list(void) {
  u32 i;
  struct conn_entry* c = conn;

  SAY(cLBL "In-flight requests (max 15 shown):\n\n");

  for (i=0;i<15;i++) {

    SAY("  " cGRA "[" cBLU "%02d" cGRA "] " cBRI, i + 1);

    if (c && c->q) {
      u8* p = serialize_path(c->q->req, 1, 0);
      u32 l = strlen((char*)p);

      if (l > 70) {
        SAY("%.30s" cGRA "..." cBRI "%.37s\n", p, p + l - 37);
      } else {
        SAY("%s%s\n", p, SP70 + l);
      }

      ck_free(p);

    } else SAY(cLGN "<slot idle>%s\n", SP70 + 11);

    if (c) c = c->next;

  }

}
