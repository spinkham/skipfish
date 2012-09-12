
/*
   skipfish - Signature Matching
   ----------------------------------------

   Author: Niels Heinen <heinenn@google.com>,
           Sebastian Roschke <s.roschke@gmail.com>

   Copyright 2011, 2012 by Google Inc. All Rights Reserved.

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
#include "pcre.h"

#define _VIA_SIGNATURE_C

#include "types.h"
#include "config.h"
#include "debug.h"
#include "alloc-inl.h"
#include "database.h"
#include "signatures.h"

struct signature** sig_list;
u32 slist_max_cnt = 0, slist_cnt = 0;

void dump_sig(struct signature *sig);

/* Helper function to lookup a signature keyword. This makes it easier
  switch() signature keywords for, for example, storing their values in
  a struct */

static s32 lookup(u8* key) {

  u32 i;
  for (i=0; lookuptable[i].name; i++) {
    if (!strcmp((char*)key, lookuptable[i].name))
      return lookuptable[i].id;
  }
  return -1;
}

/* Helper function for parse_sig which takes a string where some
  characters might be escaped. It returns a copy with the \'s
  removed so \"aa\" becomes "aa" */

static u8* unescape_str(u8* str) {

  u32 k = 0, i = 0;
  u32 len = strlen((char*)str) + 1;
  u8* ret = ck_alloc(len);

  for (i=0; i<len; i++) {
    if(str[i] == '\\')
      continue;

    ret[k++] = str[i];
  }

  return ret;
}

/* Checks the signature and returns 1 if there is an error. This function is
 * expected to give warnings that help to resolve the signature error */

static u8 check_signature(struct signature *sig) {

  u8 ret = 0;
  if (sig->severity < 0 || sig->severity > 4) {
    WARN("Signature %d has an invalid severity: %d\n", sig->id, sig->severity);
    ret = 1;
  }

  if (!sig->content_cnt && !sig->mime) {
    WARN("Signature %d has no \"content\" nor \"mime\" string\n", sig->id);
    ret = 1;
  }

  if (!sig->memo) {
    WARN("Signature %d has no memo string\n", sig->id);
    ret = 1;
  }

  return ret;
}

static u8 compile_content(struct content_struct *content) {
  const char* pcre_err;
  int pcre_err_offset;

  u32 options = PCRE_MULTILINE;

  if (content->type != TYPE_REGEX)
    return 1;

  if (content->nocase) options |= PCRE_CASELESS;

  content->pcre_sig = pcre_compile((char*)content->match_str, options,
                               &pcre_err, &pcre_err_offset, 0);

  if (!content->pcre_sig)
    return 1;

  /* This is extra */
  content->pcre_extra_sig = pcre_study(content->pcre_sig, 0, &pcre_err);

  return 0;

}

/* Parses the signature string that is given as the first parameter and returns
   a signature struct */

struct signature* parse_sig(u8* tline) {

  u8 *val, *name, *line;
  u8 in_quot = 0;
  u8 no = 0;
  struct content_struct *lcontent = NULL;

  line = tline = ck_strdup(tline);

  struct signature* sig = ck_alloc(sizeof(struct signature));
  while (line) {

    /* Skip spaces */
    name = line;
    no = 0;

    while (name && isspace(*name))
      name++;

    /* Split on the value and, for now, return NULL when there is no
       value. Later we should add value-less keywords, like 'nocase' */
    val = (u8*)index((char*)name, ':');

    if(!val) {
      ck_free(sig);
      ck_free(tline);
      return 0;
    }
    *val = 0;

    /* Check if ! is present and set 'not' */
    if (++val && *val == '!') {
     no = 1;
     val++;
    }

    /* Move to value and check if quoted */
    if (val && (*val == '\'' || *val == '"')) {
      in_quot = *val;
      val++;
    }

    /* Find the end of the value string */
    line = val;
    while (++line) {
      if(*line == '\\') {
        line++;
        continue;
      }

      /* End of quotation? */
      if (in_quot && *line == in_quot) {
        in_quot = 0;
        *line = 0;
        continue;
      }

      /* End of the value? */
      if (!in_quot && *line == ';') {
        *line = 0;
        break;
      }
    }

    switch (lookup(name)) {
      case SIG_ID:
        sig->id = atoi((char*)val);
        break;
      case SIG_CHK:
        sig->check = atoi((char*)val);
        break;
      case SIG_CONTENT:

        /* If we already have a content struct, try to compile it (when
           regex) and create a new content struct */

        if (lcontent) {

          /* Compile and bail out on failure */
          if (lcontent->type == TYPE_REGEX &&
              compile_content(lcontent))
              FATAL("Unable to compile regex in: %s", tline);

        }

        if (sig->content_cnt > MAX_CONTENT)
          FATAL("Too many content's in line: %s", tline);

        sig->content[sig->content_cnt] = ck_alloc(sizeof(struct content_struct));
        lcontent = sig->content[sig->content_cnt];
        lcontent->match_str = unescape_str(val);
        lcontent->match_str_len = strlen((char*)lcontent->match_str);
        lcontent->no = no;
        sig->content_cnt++;
        break;
      case SIG_MEMO:
        sig->memo = unescape_str(val);
        break;
      case SIG_TYPE:
        if (!lcontent) {
          WARN("Found 'type' before 'content', skipping..");
          break;
        }
        /* 0 is plain to which we default so this only checks if the
           rule wants a regex */
        if (!strcmp((char*)val, "regex"))
          lcontent->type = (u8)TYPE_REGEX;
        break;
      case SIG_DIST:
        if (!lcontent) {
          WARN("Found 'distance' before 'content', skipping..");
          break;
        }
        lcontent->distance = atoi((char*)val);
        break;
      case SIG_OFFSET:
        if (!lcontent) {
          WARN("Found 'offset' before 'content', skipping..");
          break;
        }
        lcontent->offset = atoi((char*)val);
        break;
      case SIG_SEV:
        sig->severity = atoi((char*)val);
        break;
      case SIG_PROB:
        sig->prob = atoi((char*)val);
        break;
      case SIG_DEPTH:
        if (!lcontent) {
          WARN("Found 'depth' before 'content', skipping..");
          break;
        }
          lcontent->depth = atoi((char*)val);
        break;
      case SIG_CASE:
        if (!lcontent) {
          WARN("Found 'case' before 'content', skipping..");
          break;
        }
        if (!strcmp((char*)val, "no"))
          lcontent->nocase = 1;
        break;
      case SIG_MIME:
        sig->mime = unescape_str(val);
        break;
      case SIG_CODE:
        sig->rcode = atoi((char*)val);
        break;

      default:
        FATAL("Unknown keyword: %s", name);
    }

    /* Proceed, or stop when we're at the end of the line. Since 'line'
       still points to ; , we'll increase it first */
    if(line) line++;

    /* Now if we're at EOF or EOL, we'll stop */
    if (!line || (*line == '\r' || *line == '\n'))
        break;
  }

  ck_free(tline);

  /* Compile the last content entry */
  if (lcontent) compile_content(lcontent);

  /* Done parsing! Now validate the signature before returning it */
  if (check_signature(sig)) {
    DEBUG("Skipping signature (didn't validate)\n");
    destroy_signature(sig);
    return NULL;
  }

  /* Dump the signature when debugging */

#ifdef LOG_STDERR
  dump_sig(sig);
#endif /* !LOG_STDERR */
  return sig;
}

/* Loads the signature list from file 'fname' and parses each line. Whenever a
 * line starts with #include , the file will be parsed as well to make signature
 * management really easy. */

void load_signatures(u8* fname) {
  FILE* in;
  u8 tmp[MAX_SIG_LEN];
  u8 include[MAX_SIG_FNAME + 1];
  u32 in_cnt = 0;
  u8 fmt[20];

  struct signature *sig;

  in = fopen((char*)fname, "r");
  if (!in) {
    PFATAL("Unable to open signature list '%s'", fname);
    return;
  }

  /* Create a signature list */
  if (!sig_list)
    sig_list = ck_alloc(sizeof(struct signature*) * MAX_SIG_CNT);

  while (fgets((char*)tmp, MAX_SIG_LEN, in)) {
    if (tmp[0] == '#')
      continue;

    /* When the include directive is present, we'll follow it */
    if (!strncmp((char*)tmp, "include ", 8)) {

      /* Check the amount of files included already. This is mostly to protect
       * against include loops */

      if (in_cnt++ > MAX_SIG_INCS)
        FATAL("Too many signature includes (max: %d)\n", MAX_SIG_INCS);

      sprintf((char*)fmt, "%%%u[^\x01-\x1f]", MAX_SIG_FNAME);
      sscanf((char*)tmp + 8,(char*)fmt, (char*)&include);

      DEBUG("- Including signature file: %s\n", include);
      load_signatures(include);

    }

    sig = parse_sig(tmp);

    if(sig == NULL)
      continue;

    if (slist_cnt >= MAX_SIG_CNT)
      FATAL("* Signature list is too large (max = %d)\n", MAX_SIG_CNT);

    sig_list[slist_cnt++] = sig;
  }

  DEBUG("*- Signatures processed: %s (total sigs %d)\n", fname, slist_cnt);

  fclose(in);
}

u8 match_signatures(struct http_request *req, struct http_response *res) {

  u8 pcre_ret, matches = 0;
  u8 *payload, *match = NULL;
  u32 ovector[PCRE_VECTOR];
  u32 pay_len, j = 0, i = 0;

  struct content_struct *content = NULL;

  for ( j = 0; j < slist_cnt; j++ ) {

    /* Check if the signature is only intended for one of the active tests. */
    if (sig_list[j]->check && (req->pivot->check_id > 0 &&
        req->pivot->check_id != sig_list[j]->check)) {
      continue;
    }

    /* Compare response code */
    if (sig_list[j]->rcode && sig_list[j]->rcode != res->code)
      continue;
    /* Compare the mime types */
    if (sig_list[j]->mime && res->header_mime) {
      /* Skip if the mime doesn't match */
      if (strncmp((char*)res->header_mime, (char*)sig_list[j]->mime,
                  strlen((char*)sig_list[j]->mime))) continue;

      /* We've got a signature match with the mime is the same and no content
       * string exists. This is useful for reporting interesting mime types,
       * such as application/x-httpd-php-source */

      if (!sig_list[j]->content_cnt) {
        signature_problem(sig_list[j], req, res);
        continue;
      }
    }


    /* Nice, so here the matching will start! Unless...  there are not content
     * strings, or when the response is mainly binary data.  */
    if (res->doc_type == 1 || !sig_list[j]->content_cnt)
      continue;

    payload = res->payload;
    pay_len = res->pay_len;
    matches = 0;

    for (i=0; pay_len > 0 && i<sig_list[j]->content_cnt; i++) {

      content = sig_list[j]->content[i];

      /* If there is an offset, we will apply it to the current payload
         pointer */

      if (content->offset) {
        if (pay_len < content->offset) break;

        payload = payload + content->offset;
      }

      /* Use the specified maximum depth to search the string. If no depth
      is specified, we search the entire buffer. Note that this is relative
      to the beginning of the buffer _or_ the previous content match */

      if (content->depth)
        pay_len = content->depth;

      if (content->distance && pay_len > content->distance) {
        payload += content->distance;
        pay_len -= content->distance;
      }

      match = 0;
      if (content->type == TYPE_PLAIN) {
        if (content->nocase) {
          match = inl_findstrcase(payload, content->match_str, pay_len);
        } else {
          match = inl_findstr(payload, content->match_str, pay_len);
        }

        if (match && !content->no) {
          /* Move the match pointer to allow offset to be applied relative
             to the previous content-match */

          payload = match + content->match_str_len;
          pay_len -= content->match_str_len;
          matches++;
        } else if(!match && content->no) {
          matches++;
        } else break;

      } else if(content->type == TYPE_REGEX) {
        /* Lets do the pcre matching */
        pcre_ret = (pcre_exec(content->pcre_sig, content->pcre_extra_sig,
            (char*)payload, pay_len, 0, 0, (int*)ovector, PCRE_VECTOR) >= 0);

        if (!content->no && pcre_ret) {
            /* We care about the first match and update the match pointer
              to the first byte that follows the matching string */

            payload = payload + ovector[1];
            pay_len -= (ovector[1] - ovector[0]);
            /* pay_len is checked in the next match */

            matches++;
        } else if(!pcre_ret && content->no) {
            matches++;
        } else break;
      }
    } /* for i loop */

    if (matches == sig_list[j]->content_cnt)
      signature_problem(sig_list[j], req, res);

  } /* for j loop */

  return 0;
}


/* Wrapper for reporting a signature problem */
void signature_problem(struct signature *sig,
                       struct http_request *req,
                       struct http_response *res) {

#ifdef _SIGNATURE_TEST
  DEBUG("signature_problem() called for %d (%s)\n", sig->id, sig->memo);
#else

  /* Register the problem, together with the sid */
  register_problem((sig->prob ? sig->prob : sig_serv[sig->severity]), sig->id,
                    req, res, (sig->memo ? sig->memo : (u8*)""), req->pivot, 0);

#endif
}

void destroy_signature(struct signature *sig) {
  u32 i;

  if (sig->memo) ck_free(sig->memo);
  if (sig->mime) ck_free(sig->mime);

  for (i=0; i<sig->content_cnt; i++) {
    ck_free(sig->content[i]->match_str);

    if (sig->content[i]->pcre_sig)
      free(sig->content[i]->pcre_sig);
    if (sig->content[i]->pcre_extra_sig)
      free(sig->content[i]->pcre_extra_sig);

    ck_free(sig->content[i]);
  }

  ck_free(sig);

}
void destroy_signature_lists() {

  u32 i;
  for (i = 0; i < slist_cnt; i++)
    destroy_signature(sig_list[i]);

  ck_free(sig_list);
}

/* For debugging: dump a signature */
void dump_sig(struct signature *sig) {

  u32 i;

  DEBUG("\n=== New signature loaded ===\n");
  DEBUG("  id        = %d\n", sig->id);
  DEBUG("  severity  = %d\n", sig->severity);
  DEBUG("  content # = %d\n", sig->content_cnt);

  for (i=0; i<sig->content_cnt; i++) {
    DEBUG("  %d. match_str     = %s\n", i, sig->content[i]->match_str);
    DEBUG("  %d. type          = %s\n", i, sig->content[i]->type ? "REGEX" : "STRING");
    DEBUG("  %d. offset        = %d\n", i, sig->content[i]->offset);
    DEBUG("  %d. depth         = %d\n", i, sig->content[i]->depth);
    DEBUG("  %d. position      = %d\n", i, sig->content[i]->distance);
    DEBUG("  %d. no            = %d\n", i, sig->content[i]->no);

  }
  /* And now the optional fields */
  if (sig->memo)
    DEBUG("  memo     = %s\n", sig->memo);
  if (sig->mime)
    DEBUG("  mime     = %s\n", sig->mime);
  if (sig->rcode)
    DEBUG("  code     = %d\n", sig->rcode);
}
