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

#ifndef _HAVE_HTTP_CLIENT_H
#define _HAVE_HTTP_CLIENT_H

#include <openssl/ssl.h>

#include "config.h"
#include "types.h"
#include "alloc-inl.h"
#include "string-inl.h"

/* Generic type-name-value array, used for HTTP headers, etc: */

struct param_array {
  u8*  t;                       /* Type  */
  u8** n;                       /* Name  */
  u8** v;                       /* Value */
  u32  c;                       /* Count */
};

/* Flags for http_request protocol: */

#define PROTO_NONE      0       /* Illegal value                */
#define PROTO_HTTP      1       /* Plain-text HTTP              */
#define PROTO_HTTPS     2       /* TLS/SSL wrapper              */

/* Flags for http_request parameter list entries: */

#define PARAM_NONE      0       /* Empty parameter slot         */

#define PARAM_PATH      10      /* Path or parametrized path    */
#define PARAM_PATH_S    11      /* - Semicolon element          */
#define PARAM_PATH_C    12      /* - Comma element              */
#define PARAM_PATH_E    13      /* - Exclamation mark element   */
#define PARAM_PATH_D    14      /* - Dollar sign element        */

#define PATH_SUBTYPE(_x) ((_x) >= PARAM_PATH && (_x) < PARAM_QUERY)

#define PARAM_QUERY     20      /* Query parameter              */
#define PARAM_QUERY_S   21      /* - Semicolon element          */
#define PARAM_QUERY_C   22      /* - Comma element              */
#define PARAM_QUERY_E   23      /* - Exclamation mark element   */
#define PARAM_QUERY_D   24      /* - Dollar sign element        */

#define QUERY_SUBTYPE(_x) ((_x) >= PARAM_QUERY && (_x) < PARAM_POST)

#define PARAM_POST      50      /* Post parameter               */
#define PARAM_POST_F    51      /* - File field                 */
#define PARAM_POST_O    52      /* - Non-standard (e.g., JSON)  */

#define POST_SUBTYPE(_x) ((_x) >= PARAM_POST && (_x) < PARAM_HEADER)

#define PARAM_HEADER    100     /* Generic HTTP header          */
#define PARAM_COOKIE    101     /* - HTTP cookie                */

#define HEADER_SUBTYPE(_x) ((_x) >= PARAM_HEADER)

/* Different character sets to feed the encoding function  */

#define ENC_DEFAULT "#&=+;,!$?%"                /* Default encoding          */
#define ENC_PATH    "#&=+;,!$?%/"               /* Path encoding with slash  */
#define ENC_NULL    "#&=+;,!$?"                 /* Encoding without %        */

/* SSL Cipher strengths */

#define SSL_MEDIUM 0x00000040L
#define SSL_HIGH   0x00000080L


struct http_response;
struct queue_entry;

/* HTTP response signature. */

struct http_sig {
  u32 code;                     /* HTTP response code           */
  u32 data[FP_SIZE];            /* Response fingerprint data    */
  u8 has_text;                  /* Does the page have text      */
};

/* HTTP request descriptor: */

struct http_request {

  u8  proto;                    /* Protocol (PROTO_*)           */
  u8* method;                   /* HTTP method (GET, POST, ...) */
  u8* host;                     /* Host name                    */
  u32 addr;                     /* Resolved IP address          */
  u16 port;                     /* Port number to connect to    */

  u8* orig_url;                 /* Copy of the original URL     */
  struct param_array par;       /* Parameters, headers, cookies */

  struct pivot_desc *pivot;     /* Pivot descriptor             */

  u32 user_val;                 /* Can be used freely           */

  u8 (*callback)(struct http_request*, struct http_response*);
                                /* Callback to invoke when done */

  struct http_sig same_sig;     /* Used by secondary ext fuzz.  */

  /* Used by directory brute-force: */

  u8* trying_key;               /* Current keyword ptr          */
  u8  trying_spec;              /* Keyword specificity info     */

  u8* fuzz_par_enc;             /* Fuzz target encoding         */

};

/* Flags for http_response completion state: */

#define STATE_NOTINIT   0       /* Request not sent             */
#define STATE_CONNECT   1       /* Connecting...                */
#define STATE_SEND      2       /* Sending request              */
#define STATE_RECEIVE   3       /* Waiting for response         */

#define STATE_OK        100     /* Proper fetch                 */
#define STATE_DNSERR    101     /* DNS error                    */
#define STATE_LOCALERR  102     /* Socket or routing error      */
#define STATE_CONNERR   103     /* Connection failed            */
#define STATE_RESPERR   104     /* Response not valid           */
#define STATE_SUPPRESS  200     /* Dropped (limits / errors)    */

/* Flags for http_response warnings: */

#define WARN_NONE       0       /* No warnings                  */
#define WARN_PARTIAL    1       /* Incomplete read              */
#define WARN_TRAIL      2       /* Trailing request garbage     */
#define WARN_CFL_HDR    4       /* Conflicting headers          */

/* HTTP response descriptor: */

struct http_response {

  u32 state;                    /* HTTP convo state (STATE_*)   */
  u32 code;                     /* HTTP response code           */
  u8* msg;                      /* HTTP response message        */
  u32 warn;                     /* Warning flags                */

  u8  cookies_set;              /* Sets cookies?                */

  struct param_array hdr;       /* Server header, cookie list   */

  u32 pay_len;                  /* Response payload length      */
  u8* payload;                  /* Response payload data        */

  struct http_sig sig;          /* Response signature data      */

  /* Various information populated by content checks: */

  u8  sniff_mime_id;            /* Sniffed MIME (MIME_*)        */
  u8  decl_mime_id;             /* Declared MIME (MIME_*)       */

  u8* meta_charset;             /* META tag charset value       */
  u8* header_charset;           /* Content-Type charset value   */
  u8* header_mime;              /* Content-Type MIME type       */
  u8* sniffed_mime;             /* Detected MIME type (ref)     */

  /* Everything below is of interest to scrape_response() only: */

  u8  doc_type;                 /* 0 - tbd, 1 - bin, 2 - ascii  */
  u8  css_type;                 /* 0 - tbd, 1 - other, 2 - css  */
  u8  js_type;                  /* 0 - tbd, 1 - other, 2 - js   */
  u8  json_safe;                /* 0 - no, 1 - yes              */
  u8  stuff_checked;            /* check_stuff() called?        */
  u8  scraped;                  /* scrape_response() called?    */

};

/* Open keep-alive connection descriptor: */

struct conn_entry {

  s32 fd;                       /* The actual file descriptor   */

  u8  proto;                    /* Protocol (PROTO_*)           */
  u32 addr;                     /* Destination IP               */
  u32 port;                     /* Destination port             */

  u8  reused;                   /* Used for earier requests?    */

  u32 req_start;                /* Unix time: request start     */
  u32 last_rw;                  /* Unix time: last read / write */

  SSL_CTX *srv_ctx;             /* SSL context                  */
  SSL     *srv_ssl;
  u8  SSL_rd_w_wr;              /* SSL_read() wants to write?   */
  u8  SSL_wr_w_rd;              /* SSL_write() wants to read?   */
  u8  ssl_checked;              /* SSL state checked?           */

  u8* read_buf;                 /* Current read buffer          */
  u32 read_len;
  u8* write_buf;                /* Pending write buffer         */
  u32 write_off;                /* Current write offset         */
  u32 write_len;

  struct queue_entry* q;        /* Current queue entry          */

  struct conn_entry*  prev;     /* Previous connection entry    */
  struct conn_entry*  next;     /* Next connection entry        */

};

/* Request queue descriptor: */

struct queue_entry {
  struct http_request*  req;    /* Request descriptor           */
  struct http_response* res;    /* Response descriptor          */
  struct conn_entry*    c;      /* Connection currently used    */
  struct queue_entry*   prev;   /* Previous queue entry         */
  struct queue_entry*   next;   /* Next queue entry             */
  u8 retrying;                  /* Request being retried?       */
};

/* DNS cache item: */

struct dns_entry {
  u8* name;                     /* Name requested               */
  u32 addr;                     /* IP address (0 = bad host)    */
  struct dns_entry* next;       /* Next cache entry             */
};


/* Simplified macros to manipulate param_arrays: */

#define ADD(_ar,_t,_n,_v) do { \
    u32 _cur = (_ar)->c++; \
    (_ar)->t = ck_realloc((_ar)->t, (_ar)->c); \
    (_ar)->n = ck_realloc((_ar)->n, (_ar)->c * sizeof(u8*)); \
    (_ar)->v = ck_realloc((_ar)->v, (_ar)->c * sizeof(u8*)); \
    (_ar)->t[cur] = _t; \
    (_ar)->n[cur] = (_n) ? ck_strdup(_n) : 0; \
    (_ar)->v[cur] = (_v) ? ck_strdup(_v) : 0; \
  } while (0)

#define FREE(_ar) do { \
    while ((_ar)->c--) { \
      ck_free((_ar)->n[(_ar)->c]); \
      ck_free((_ar)->v[(_ar)->c]); \
    } \
    ck_free((_ar)->t); \
    ck_free((_ar)->n); \
    ck_free((_ar)->v); \
  } while (0)


/* Extracts parameter value from param_array. Name is matched if
   non-NULL. Returns pointer to value data, not a duplicate string;
   NULL if no match found. */

u8* get_value(u8 type, u8* name, u32 offset, struct param_array* par);

/* Inserts or overwrites parameter value in param_array. If offset
   == -1, will append parameter to list. Duplicates strings,
   name and val can be NULL. */

void set_value(u8 type, u8* name, u8* val, s32 offset, struct param_array* par);

/* Simplified macros for value table access: */

#define GET_CK(_name, _p)         get_value(PARAM_COOKIE, _name, 0, _p)
#define SET_CK(_name, _val, _p)   set_value(PARAM_COOKIE, _name, _val, 0, _p)
#define GET_PAR(_name, _p)        get_value(PARAM_QUERY, _name, 0, _p)
#define SET_PAR(_name, _val, _p)  set_value(PARAM_QUERY, _name, _val, -1, _p)
#define GET_HDR(_name, _p)        get_value(PARAM_HEADER, _name, 0, _p)
#define SET_HDR(_name, _val, _p)  set_value(PARAM_HEADER, _name, _val, -1, _p)
#define GET_HDR_OFF(_name, _p, _o) get_value(PARAM_HEADER, _name, _o, _p)

void tokenize_path(u8* str, struct http_request* req, u8 add_slash);

/* Convert a fully-qualified or relative URL string to a proper http_request
   representation. Returns 0 on success, 1 on format error. */

u8 parse_url(u8* url, struct http_request* req, struct http_request* ref);

/* URL-decodes a string. 'Plus' parameter governs the behavior on +
   signs (as they have a special meaning only in query params, not in path). */

u8* url_decode_token(u8* str, u32 len, u8 plus);

/* URL-encodes a string according to custom rules. The assumption here is that
   the data is already tokenized as "special" boundaries such as ?, =, &, /,
   ;, so these characters must always be escaped if present in tokens. We
   otherwise let pretty much everything else go through, as it may help with
   the exploitation of certain vulnerabilities. */

u8* url_encode_token(u8* str, u32 len, u8* enc_set);

/* Reconstructs URI from http_request data. Includes protocol and host
   if with_host is non-zero. */

u8* serialize_path(struct http_request* req, u8 with_host, u8 with_post);

/* Looks up IP for a particular host, returns data in network order.
   Uses standard resolver, so it is slow and blocking, but we only
   expect to call it a couple of times. */

u32 maybe_lookup_host(u8* name);

/* Creates an ad hoc DNS cache entry, to override NS lookups. */

void fake_host(u8* name, u32 addr);

/* Schedules a new asynchronous request; req->callback() will be invoked when
   the request is completed. */

void async_request(struct http_request* req);

/* Prepares a serialized HTTP buffer to be sent over the network. */

u8* build_request_data(struct http_request* req);

/* Parses a network buffer containing raw HTTP response received over the
   network ('more' == the socket is still available for reading). Returns 0
   if response parses OK, 1 if more data should be read from the socket,
   2 if the response seems invalid. */

u8 parse_response(struct http_request* req, struct http_response* res, u8* data,
                  u32 data_len, u8 more);

/* Processes the queue. Returns the number of queue entries remaining,
   0 if none. Will do a blocking select() to wait for socket state changes
   (or timeouts) if no data available to process. This is the main
   routine for the scanning loop. */

u32 next_from_queue(void);

/* Dumps HTTP request stats, for debugging purposes: */

void dump_http_request(struct http_request* r);

/* Dumps HTTP response stats, for debugging purposes: */

void dump_http_response(struct http_response* r);

/* Fingerprints a response: */

void fprint_response(struct http_response* res);

/* Performs a deep free() of sturct http_request */

void destroy_request(struct http_request* req);

/* Performs a deep free() of sturct http_response */

void destroy_response(struct http_response* res);

/* Creates a working copy of a request. If all is 0, does not copy
   path, query parameters, or POST data (but still copies headers). */

struct http_request* req_copy(struct http_request* req, struct pivot_desc* pv,
                              u8 all);

/* Creates a copy of a response. */

struct http_response* res_copy(struct http_response* res);

/* Various settings and counters exported to other modules: */

extern u32 max_connections,
           max_conn_host,
           max_requests,
           max_fail,
           idle_tmout,
           resp_tmout,
           rw_tmout,
           size_limit,
           req_errors_net,
           req_errors_http,
           req_errors_cur,
           req_count,
           req_dropped,
           req_retried,
           url_scope,
           conn_count,
           conn_idle_tmout,
           conn_busy_tmout,
           conn_failed,
           queue_cur;

extern float req_sec,
             max_requests_sec;

extern u64 bytes_sent,
           bytes_recv,
           bytes_deflated,
           bytes_inflated,
           iterations_cnt;

extern u8  ignore_cookies,
           idle;

/* Flags for browser type: */

#define BROWSER_FAST    0       /* Minimimal HTTP headers       */
#define BROWSER_MSIE    1       /* Try to mimic MSIE            */
#define BROWSER_FFOX    2       /* Try to mimic Firefox         */
#define BROWSER_PHONE   3       /* Try to mimic iPhone          */

extern u8 browser_type;

/* Flags for authentication type: */

#define AUTH_NONE       0       /* No authentication            */
#define AUTH_BASIC      1       /* 'Basic' HTTP auth            */

extern u8 auth_type;

extern u8 *auth_user,
          *auth_pass;

#ifdef PROXY_SUPPORT
extern u8* use_proxy;
extern u32 use_proxy_addr;
extern u16 use_proxy_port;
#endif /* PROXY_SUPPORT */

/* Global HTTP cookies, extra headers: */

extern struct param_array global_http_par;

/* Destroys http state information, for memory profiling. */

void destroy_http();

/* Shows some pretty statistics. */

void http_stats(u64 st_time);
void http_req_list(void);

#endif /* !_HAVE_HTTP_CLIENT_H */
