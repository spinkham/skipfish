
/*
   skipfish - signature matching
   ----------------------------------------

   Author: Niels Heinen <heinenn@google.com>

   Copyright 2011 - 2012 by Google Inc. All Rights Reserved.

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

#include "pcre.h"

#ifndef _SIGNATURE_H
#define _SIGNATURE_H

#define MAX_CONTENT 10
#define PCRE_VECTOR 30

struct content_struct {
  u8* match_str;                   /* The content string to find     */
  u32 match_str_len;               /* Length of the content string   */
  pcre* pcre_sig;                  /* Regex: compiled                */
  pcre_extra* pcre_extra_sig;      /* Regex: extra                   */

  u8 no;                           /* 1 = string should not be there */
  u8 nocase;                       /* 1 = case insensitive matching  */
  u8 type;                         /* regex or static string         */
  u32 depth;                       /* Depth of bytes to search       */
  u32 distance;                    /* Relative distance to search    */
  u32 offset;                      /* Search starts after offset     */
};

struct signature {
  u32 id;                          /* Unique ID for documentation    */
  u8* memo;                        /* Message displayed when found   */
  u8 severity;                     /* Severity                       */
  u32 prob;                        /* Problem ID from analysis.h     */
  u8* mime;                        /* Match with this mime type      */
  u32 rcode;                       /* Match with HTTP resp code      */
  u32 content_cnt;                 /* Amount of contenrt structs     */
  u32 check;                       /* The check ID                   */
  struct content_struct* content[MAX_CONTENT];
};


/* The signature matching function */

u8 match_signatures(struct http_request *req, struct http_response *res);


/* Load the passwords from a file */

void load_signatures(u8* fname);

/* Destroy the wordlists and free all memory */

void destroy_signature_lists(void);

/* Wrapper for reporting a signature problem */

void signature_problem(struct signature *sig, struct http_request *req, struct http_response *res);


struct signature** sig_list;       /* The one and only: signature list       */

extern u32 slist_max_cnt;          /* Allocated space in the signature lists */
u32 slist_cnt;                     /* Actual elements in the signature lists */

#define TYPE_PLAIN 0               /* Content type: static string            */
#define TYPE_REGEX 1               /* Content type: regular expression       */

#define MAX_SIG_LEN 2048           /* Signature line length                  */
#define MAX_SIG_CNT 1024           /* Max amount of signatures to load       */
#define MAX_SIG_FNAME 512          /* Maximum signature filename             */
#define MAX_SIG_INCS 64            /* Maximum files to include.              */

#ifdef _VIA_SIGNATURE_C

u32 sig_serv[] = {
  PROB_SIG_DETECT,       /* Default: info level */
  PROB_SIG_DETECT_H,     /* High risk           */
  PROB_SIG_DETECT_M,     /* Medium risk         */
  PROB_SIG_DETECT_L,     /* Low risk            */
  PROB_SIG_DETECT        /* info risk           */
};


/* Destroy an individual signature */

void destroy_signature(struct signature *sig);

#define SIG_ID      1
#define SIG_CONTENT 2
#define SIG_MEMO    3
#define SIG_TYPE    4
#define SIG_SEV     5
#define SIG_CONST   6
#define SIG_PROB    7
#define SIG_TAG     8
#define SIG_MIME    9
#define SIG_CODE    10
#define SIG_CASE    11
#define SIG_DEPTH   12
#define SIG_OFFSET  13
#define SIG_DIST    14
#define SIG_CHK     15

/* The structs below are to for helping the signature parser */

struct sig_key {
  u32 id;
  const char *name;
};


struct sig_key lookuptable[] = {
  { SIG_ID,      "id" },
  { SIG_CONTENT, "content" },
  { SIG_MEMO,    "memo" },
  { SIG_TYPE,    "type" },
  { SIG_SEV,     "sev" },
  { SIG_PROB,    "prob" },
  { SIG_TAG,     "tag" },
  { SIG_MIME,    "mime" },
  { SIG_CODE,    "code" },
  { SIG_CASE,    "case" },
  { SIG_DEPTH,   "depth" },
  { SIG_OFFSET,  "offset" },
  { SIG_DIST,    "distance" },
  { SIG_CHK,     "check" },
  { 0, 0}
};

#endif /* !_VIA_SIGNATURE_C */
#endif /* !_SIGNATURE_H */
