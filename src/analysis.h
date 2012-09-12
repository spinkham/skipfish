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

#ifndef _HAVE_ANALYSIS_C

#include "types.h"
#include "http_client.h"
#include "database.h"

extern u8  no_parse,            /* Disable HTML link detection */
           warn_mixed,          /* Warn on mixed content       */
           log_ext_urls,        /* Log all external URLs       */
           no_forms,            /* Do not submit forms         */
           pedantic_cache;      /* Match HTTP/1.0 and HTTP/1.1 */

/* Helper macros to group various useful checks: */

#define PIVOT_CHECKS(_req, _res) do { \
    pivot_header_checks(_req, _res); \
    content_checks(_req, _res); \
    scrape_response(_req, _res); \
  } while (0)


#define RESP_CHECKS(_req, _res) do { \
    content_checks(_req, _res); \
    scrape_response(_req, _res); \
  } while (0)

/* Form autofill hints: */

extern u8** addl_form_name;
extern u8** addl_form_value;
extern u32  addl_form_cnt;


/* Runs some rudimentary checks on top-level pivot HTTP responses. */

void pivot_header_checks(struct http_request* req,
                         struct http_response* res);

/* Adds a new item to the form hint system. */

void add_form_hint(u8* name, u8* value);

/* Analyzes response headers (Location, etc), body to extract new links,
   keyword guesses, examine forms, mixed content issues, etc. */

void scrape_response(struct http_request* req, struct http_response* res);

/* Analyzes response headers and body to detect stored XSS, redirection,
   401, 500 codes, exception messages, source code, offensive comments, etc. */

u8 content_checks(struct http_request* req, struct http_response* res);

/* Deletes payload of binary responses if requested. */

void maybe_delete_payload(struct pivot_desc* pv);



/* Examines all <input> tags up until </form>, then adds them as
   parameters to current request. */

void collect_form_data(struct http_request* req,
                       struct http_request* orig_req,
                       struct http_response* orig_res,
                       u8* cur_str, u8 is_post);


/* Create a http_request from an HTML form structure */

struct http_request* make_form_req(struct http_request *req,
                                   struct http_request *base,
                                   u8* cur_str, u8* target);

/* MIME detector output codes: */

#define MIME_NONE               0       /* Checks missing or failed       */

#define MIME_ASC_GENERIC        1       /* Unknown, but mostly 7bit       */
#define MIME_ASC_HTML           2       /* Plain, non-XML HTML            */
#define MIME_ASC_JAVASCRIPT     3       /* JavaScript or JSON             */
#define MIME_ASC_CSS            4       /* Cascading Style Sheets         */
#define MIME_ASC_POSTSCRIPT     5       /* PostScript                     */
#define MIME_ASC_RTF            6       /* Rich Text Format               */

#define MIME_XML_GENERIC        7       /* XML not recognized otherwise   */
#define MIME_XML_OPENSEARCH     8       /* OpenSearch specification       */
#define MIME_XML_RSS            9       /* Real Simple Syndication        */
#define MIME_XML_ATOM           10      /* Atom feeds                     */
#define MIME_XML_WML            11      /* WAP WML                        */
#define MIME_XML_CROSSDOMAIN    12      /* crossdomain.xml (Flash)        */
#define MIME_XML_SVG            13      /* Scalable Vector Graphics       */
#define MIME_XML_XHTML          14      /* XML-based XHTML                */

#define MIME_IMG_JPEG           15      /* JPEG                           */
#define MIME_IMG_GIF            16      /* GIF                            */
#define MIME_IMG_PNG            17      /* PNG                            */
#define MIME_IMG_BMP            18      /* Windows BMP (including ICO)    */
#define MIME_IMG_TIFF           19      /* TIFF                           */
#define MIME_IMG_ANI            20      /* RIFF: ANI animated cursor      */

#define MIME_AV_WAV             21      /* RIFF: WAV sound file           */
#define MIME_AV_MP3             22      /* MPEG audio (commonly MP3)      */
#define MIME_AV_OGG             23      /* Ogg Vorbis                     */
#define MIME_AV_RA              24      /* Real audio                     */

#define MIME_AV_AVI             25      /* RIFF: AVI container            */
#define MIME_AV_MPEG            26      /* MPEG video                     */
#define MIME_AV_QT              27      /* QuickTime                      */
#define MIME_AV_FLV             28      /* Flash video                    */
#define MIME_AV_RV              29      /* Real video                     */

#define MIME_AV_WMEDIA          30      /* Windows Media audio            */

#define MIME_EXT_FLASH          31      /* Adobe Flash                    */
#define MIME_EXT_PDF            32      /* Adobe PDF                      */
#define MIME_EXT_JAR            33      /* Sun Java archive               */
#define MIME_EXT_CLASS          34      /* Sun Java class                 */
#define MIME_EXT_WORD           35      /* Microsoft Word                 */
#define MIME_EXT_EXCEL          36      /* Microsoft Excel                */
#define MIME_EXT_PPNT           37      /* Microsoft Powerpoint           */

#define MIME_BIN_ZIP            38      /* ZIP not recognized otherwise   */
#define MIME_BIN_GZIP           39      /* GZIP                           */
#define MIME_BIN_CAB            40      /* CAB                            */

#define MIME_BIN_GENERIC        41      /* Binary, unknown type           */

#define MIME_COUNT (MIME_BIN_GENERIC + 1)

/* NULL-terminated MIME mapping sets. Canonical name should go first; do not
   put misspelled or made up entries here. This is used to match server intent
   with the outcome of MIME sniffing. */

#ifdef _VIA_ANALYSIS_C

static char* mime_map[MIME_COUNT][8] = {

/* MIME_NONE            */ { 0 },

/* MIME_ASC_GENERIC     */ { "text/plain", "?text/x-", "?text/vnd.",
                             "?application/x-httpd-", "text/csv", 0 },
/* MIME_ASC_HTML        */ { "text/html", 0 },
/* MIME_ASC_JAVASCRIPT  */ { "application/javascript",
                             "application/x-javascript",
                             "application/json", "text/javascript", 0 },
/* MIME_ASC_CSS         */ { "text/css", 0 },
/* MIME_ASC_POSTSCRIPT  */ { "application/postscript", 0 },
/* MIME_ASC_RTF         */ { "text/rtf", "application/rtf", 0 },

/* MIME_XML_GENERIC     */ { "text/xml", "application/xml", 0 },
/* MIME_XML_OPENSEARCH  */ { "application/opensearchdescription+xml", 0 },
/* MIME_XML_RSS         */ { "application/rss+xml", 0 },
/* MIME_XML_ATOM        */ { "application/atom+xml", 0 },
/* MIME_XML_WML         */ { "text/vnd.wap.wml", 0 },
/* MIME_XML_CROSSDOMAIN */ { "text/x-cross-domain-policy", 0 },
/* MIME_XML_SVG         */ { "image/svg+xml", 0 },
/* MIME_XML_XHTML       */ { "application/xhtml+xml", 0 },

/* MIME_IMG_JPEG        */ { "image/jpeg", 0 },
/* MIME_IMG_GIF         */ { "image/gif", 0 },
/* MIME_IMG_PNG         */ { "image/png", 0 },
/* MIME_IMG_BMP         */ { "image/x-ms-bmp", "image/bmp", "image/x-icon", 0 },
/* MIME_IMG_TIFF        */ { "image/tiff", 0 },
/* MIME_IMG_ANI         */ { "application/x-navi-animation", 0 },

/* MIME_AV_WAV          */ { "audio/x-wav", "audio/wav", 0 },
/* MIME_AV_MP3          */ { "audio/mpeg", 0 },
/* MIME_AV_OGG          */ { "application/ogg", 0 },
/* MIME_AV_RA           */ { "audio/vnd.rn-realaudio",
                             "audio/x-pn-realaudio", "audio/x-realaudio", 0 },

/* MIME_AV_AVI          */ { "video/avi", 0 },
/* MIME_AV_MPEG         */ { "video/mpeg", "video/mp4", 0 },
/* MIME_AV_QT           */ { "video/quicktime", 0 },
/* MIME_AV_FLV          */ { "video/flv", "video/x-flv", 0 },
/* MIME_AV_RV           */ { "video/vnd.rn-realvideo", 0 },

/* MIME_AV_WMEDIA       */ { "video/x-ms-wmv", "audio/x-ms-wma",
                             "video/x-ms-asf", 0 },

/* MIME_EXT_FLASH       */ { "application/x-shockwave-flash", 0 },
/* MIME_EXT_PDF         */ { "application/pdf", 0 },
/* MIME_EXT_JAR         */ { "application/java-archive", 0 },
/* MIME_EXT_CLASS       */ { "application/java-vm", 0 },
/* MIME_EXT_WORD        */ { "application/msword", 0 },
/* MIME_EXT_EXCEL       */ { "application/vnd.ms-excel", 0 },
/* MIME_EXT_PPNT        */ { "application/vnd.ms-powerpoint", 0 },

/* MIME_BIN_ZIP         */ { "application/zip", "application/x-zip-compressed", 0 },
/* MIME_BIN_GZIP        */ { "application/x-gzip", "application/x-gunzip",
                             "application/x-tar-gz", 0 },
/* MIME_BIN_CAB         */ { "application/vnd.ms-cab-compressed", 0 },

/* MIME_BIN_GENERIC     */ { "application/binary", "application/octet-stream",
                             0 }

};

/* A set of headers that we check to see if our injection string ended
   up in their value. This list should only contain headers where control
   over the value could potentially be exploited. */

static const char* injection_headers[] = {
  "Set-Cookie",
  "Set-Cookie2",
  "Content-Type",
  0,
};

#endif /* _VIA_ANALYSIS_C */

#endif /* !_HAVE_ANALYSIS_H */
