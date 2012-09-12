/*
   skipfish - post-processing and reporting
   ----------------------------------------

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

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <dirent.h>
#include <sys/fcntl.h>

#include "debug.h"
#include "config.h"
#include "types.h"
#include "http_client.h"
#include "database.h"
#include "crawler.h"
#include "checks.h"
#include "analysis.h"

/* Pivot and issue signature data. */

struct p_sig_desc {
  u8 type;                               /* Pivot type             */
  struct http_sig* res_sig;              /* Response signature     */
  u32 issue_sig;                         /* Issues fingerprint     */
  u32 child_sig;                         /* Children fingerprint   */
};


static struct p_sig_desc* p_sig;
static u32 p_sig_cnt;
u8 suppress_dupes;
u32 verbosity = 0;


/* Response, issue sample data. */

struct mime_sample_desc {
  u8* det_mime;
  struct http_request** req;
  struct http_response** res;
  u32 sample_cnt;
};


struct issue_sample_desc {
  u32 type;
  struct issue_desc** i;
  u32 sample_cnt;
};

static struct mime_sample_desc* m_samp;
static struct issue_sample_desc* i_samp;
static u32 m_samp_cnt, i_samp_cnt;


/* qsort() helper for sort_annotate_pivot(). */

static int pivot_compar(const void* par1, const void* par2) {
  const struct pivot_desc *p1 = *(struct pivot_desc**)par1,
                          *p2 = *(struct pivot_desc**)par2;

  /* Force directories to appear before files, etc. */

  if (p1->type < p2->type) return -1;
  if (p1->type > p2->type) return 1;

  return strcasecmp((char*)p1->name, (char*)p2->name);
}

static int issue_compar(const void* par1, const void* par2) {
  const struct issue_desc *i1 = par1, *i2 = par2;
  return i2->type - i1->type;
}


/* Recursively annotates and sorts pivots. */

static void sort_annotate_pivot(struct pivot_desc* pv) {
  u32 i, path_child = 0;
  static u32 proc_cnt;
  u8 *q1, *q2;

  /* Add notes to all non-dir nodes with dir or file children... */

  for (i=0;i<pv->child_cnt;i++) {
    if (pv->child[i]->type == PIVOT_FILE || pv->child[i]->type == PIVOT_DIR) path_child = 1;
    sort_annotate_pivot(pv->child[i]); 
  }

  if (pv->type != PIVOT_DIR && pv->type != PIVOT_SERV &&
      pv->type != PIVOT_ROOT && path_child)
    problem(PROB_NOT_DIR, pv->req, pv->res, 0, pv, 0);

  /* Non-parametric nodes with digits in the name were not brute-forced,
     but the user might be interested in doing so. Skip images here. */

  if (pv->fuzz_par == -1 && pv->res &&
      (pv->res->sniff_mime_id < MIME_IMG_JPEG ||
      pv->res->sniff_mime_id > MIME_AV_WMEDIA) && 
      (pv->type == PIVOT_DIR || pv->type == PIVOT_FILE ||
      pv->type == PIVOT_PATHINFO) && !pv->missing) {
    i = strlen((char*)pv->name);
    while (i--)
      if (isdigit(pv->name[i])) {
        problem(PROB_FUZZ_DIGIT, pv->req, pv->res, 0, pv, 0);
        break;
      }
  }

  /* Parametric nodes that seem to contain queries in parameters, and are not
     marked as bogus_par, should be marked as dangerous. */

  if (pv->fuzz_par != -1 && !pv->bogus_par &&
      (((q1 = (u8*)strchr((char*)pv->req->par.v[pv->fuzz_par], '(')) &&
        (q2 = (u8*)strchr((char*)pv->req->par.v[pv->fuzz_par], ')')) && q1 < q2 &&
         !isdigit(q1[1])) ||
      ((inl_strcasestr(pv->req->par.v[pv->fuzz_par], (u8*)"SELECT ") || 
        inl_strcasestr(pv->req->par.v[pv->fuzz_par], (u8*)"DELETE ") ) &&
        inl_strcasestr(pv->req->par.v[pv->fuzz_par], (u8*)" FROM ")) ||
      (inl_strcasestr(pv->req->par.v[pv->fuzz_par], (u8*)"UPDATE ") || 
      inl_strcasestr(pv->req->par.v[pv->fuzz_par], (u8*)" WHERE ")) ||
      inl_strcasestr(pv->req->par.v[pv->fuzz_par], (u8*)"DROP TABLE ") ||
      inl_strcasestr(pv->req->par.v[pv->fuzz_par], (u8*)" ORDER BY ")))
    problem(PROB_SQL_PARAM, pv->req, pv->res, 0, pv, 0);

  /* Sort children nodes and issues as appropriate. */

  if (pv->child_cnt > 1)
    qsort(pv->child, pv->child_cnt, sizeof(struct pivot_desc*), pivot_compar);

  if (pv->issue_cnt > 1)
    qsort(pv->issue, pv->issue_cnt, sizeof(struct issue_desc), issue_compar);

  if ((!(proc_cnt++ % 50)) || pv->type == PIVOT_ROOT) {
    SAY(cLGN "\r[+] " cNOR "Sorting and annotating crawl nodes: %u", proc_cnt);
    fflush(0);
  }

}


/* Issue extra hashing helper. */

static inline u32 hash_extra(u8* str) {
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

  return ret;
}



/* Registers a new pivot signature, or updates an existing one. */

static void maybe_add_sig(struct pivot_desc* pv) {
  u32 i, issue_sig = ~(pv->issue_cnt | (pv->desc_issue_cnt << 16)), 
         child_sig = ~(pv->desc_cnt | (pv->child_cnt << 16));

  if (!pv->res) return;

  /* Compute a rough children node signature based on children types. */

  for (i=0;i<pv->child_cnt;i++)
    child_sig ^= (hash_extra(pv->child[i]->name) ^ 
                  pv->child[i]->type) << (i % 16);

  /* Do the same for all recorded issues. */

  for (i=0;i<pv->issue_cnt;i++)
    issue_sig ^= (hash_extra(pv->issue[i].extra) ^ 
                 pv->issue[i].type) << (i % 16);

  /* Assign a simplified signature to the pivot. */

  pv->pv_sig = (pv->type << 16) ^ ~child_sig ^ issue_sig;

  /* See if a matching signature already exists. */

  for (i=0;i<p_sig_cnt;i++)
    if (p_sig[i].type == pv->type && p_sig[i].issue_sig == issue_sig &&
        p_sig[i].child_sig == child_sig &&
        same_page(p_sig[i].res_sig, &pv->res->sig)) {

      /* We don't mark parameters as dupes: different parameters for the
      same page will get the same signature. If we mark them as duplicate,
      some issues, like XSS' will only be reported once while that might
      be present in two or more parameters. */

      if (pv->type != PIVOT_PARAM && !pv->bogus_par)
        pv->dupe = 1;
      return;

    }

  /* No match - create a new one. */

  p_sig = ck_realloc(p_sig, (p_sig_cnt + 1) * sizeof(struct p_sig_desc));

  p_sig[p_sig_cnt].type      = pv->type;
  p_sig[p_sig_cnt].res_sig   = &pv->res->sig;
  p_sig[p_sig_cnt].issue_sig = issue_sig;
  p_sig[p_sig_cnt].child_sig = child_sig;
  p_sig_cnt++;

}




/* Recursively collects unique signatures for pivots. */

static void collect_signatures(struct pivot_desc* pv) {
  u32 i;
  static u32 proc_cnt;

  maybe_add_sig(pv);
  for (i=0;i<pv->child_cnt;i++) collect_signatures(pv->child[i]);

  if ((!(proc_cnt++ % 50)) || pv->type == PIVOT_ROOT) {
    SAY(cLGN "\r[+] " cNOR "Looking for duplicate entries: %u", proc_cnt);
    fflush(0);
  }

}


/* Destroys signature data (for memory profiling purposes). */

void destroy_signatures(void) {
  u32 i;

  ck_free(p_sig);

  for (i=0;i<m_samp_cnt;i++) {
    ck_free(m_samp[i].req);
    ck_free(m_samp[i].res);
  }

  for (i=0;i<i_samp_cnt;i++) 
    ck_free(i_samp[i].i);

  ck_free(m_samp);
  ck_free(i_samp);
}


/* Prepares issue, pivot stats, backtracing through all children.
   Do not count nodes that seem duplicate. */

static void compute_counts(struct pivot_desc* pv) {
  u32 i;
  struct pivot_desc* tmp = pv->parent;
  static u32 proc_cnt;

  for (i=0;i<pv->child_cnt;i++) compute_counts(pv->child[i]);

  if (pv->dupe) return;

  while (tmp) {
    tmp->total_child_cnt++;
    tmp = tmp->parent;
  }

  for (i=0;i<pv->issue_cnt;i++) {
    u8 sev = PSEV(pv->issue[i].type);
    tmp = pv;
    while (tmp) {
      tmp->total_issues[sev]++;
      tmp = tmp->parent;
    }
  }

  if ((!(proc_cnt++ % 50)) || pv->type == PIVOT_ROOT) {
    SAY(cLGN "\r[+] " cNOR "Counting unique nodes: %u", proc_cnt);
    fflush(0);
  }

}


/* Helper to JS-escape data. Static buffer, will be destroyed on
   subsequent calls. */

static inline u8* js_escape(u8* str, u8 sp) {
  u32 len;
  static u8* ret;
  u8* opos;

  if (!str) return (u8*)"[none]";

  len = strlen((char*)str);

  if (ret) __DFL_ck_free(ret);
  opos = ret = __DFL_ck_alloc(len * 4 + 1);

  while (len--) {
    if (*str > (sp ? 0x20 : 0x1f) && *str < 0x80 && !strchr("<>\\'\"", *str)) {
      *(opos++) = *(str++);
    } else {
      sprintf((char*)opos, "\\x%02x", *(str++));
      opos += 4;
    }
  }

  *opos = 0;

  return ret;

}


static void output_scan_info(u64 scan_time, u32 seed) {
  FILE* f;
  time_t t = time(NULL);
  u8* ct = (u8*)ctime(&t);

  if (isspace(ct[strlen((char*)ct)-1]))
    ct[strlen((char*)ct)-1] = 0;

  f = fopen("summary.js", "w");
  if (!f) PFATAL("Cannot open 'summary.js'");

  fprintf(f, "var sf_version = '%s';\n", VERSION);
  fprintf(f, "var scan_date  = '%s';\n", js_escape(ct, 0));
  fprintf(f, "var scan_seed  = '0x%08x';\n", seed);
  fprintf(f, "var scan_ms    = %llu;\n", (long long)scan_time);

  fclose(f);

}


/* Helper to save request, response data. */

static void describe_res(FILE* f, struct http_response* res) {

  if (!res) {
    fprintf(f, "'fetched': false, 'error': 'Content not fetched'");
    return;
  }
  
  switch (res->state) {

    case 0 ... STATE_OK - 1:
      fprintf(f, "'fetched': false, 'error': '(Reported while fetch in progress)'");
      break;

    case STATE_OK:
      fprintf(f, "'fetched': true, 'code': %u, 'len': %u, 'decl_mime': '%s', ",
                 res->code, res->pay_len,
                 js_escape(res->header_mime, 0));

      fprintf(f, "'sniff_mime': '%s', 'cset': '%s'", 
                 res->sniffed_mime ? res->sniffed_mime : (u8*)"[none]",
                 js_escape(res->header_charset ? res->header_charset 
                 : res->meta_charset, 0));
      break;

    case STATE_DNSERR:
      fprintf(f, "'fetched': false, 'error': 'DNS error'");
      break;

    case STATE_LOCALERR:
      fprintf(f, "'fetched': false, 'error': 'Local network error'");
      break;

    case STATE_CONNERR:
      fprintf(f, "'fetched': false, 'error': 'Connection error'");
      break;

    case STATE_RESPERR:
      fprintf(f, "'fetched': false, 'error': 'Malformed HTTP response'");
      break;

    case STATE_SUPPRESS:
      fprintf(f, "'fetched': false, 'error': 'Limits exceeded'");
      break;


    default:
      fprintf(f, "'fetched': false, 'error': 'Unknown error'");

  }

}


/* Helper to save request, response data. */

static void save_req_res(struct http_request* req, struct http_response* res, u8 sample) {
  FILE* f;

  if (req) {
    u8* rd = build_request_data(req);
    f = fopen("request.dat", "w");
    if (!f) PFATAL("Cannot create 'request.dat'");
    if (fwrite(rd, strlen((char*)rd), 1, f)) {};
    fclose(f);

    /* Write .js file with base64 encoded json data. */
    u32 size = 0;
    u8* rd_js;
    NEW_STR(rd_js, size);
    ADD_STR_DATA(rd_js, size, "var req = {'data':'");
    ADD_STR_DATA(rd_js, size, js_escape(rd, 0));
    ADD_STR_DATA(rd_js, size, "'}");

    f = fopen("request.js", "w");
    if (!f) PFATAL("Cannot create 'request.js'");
    if (fwrite(rd_js, strlen((char*)rd_js), 1, f)) {};
    fclose(f);

    ck_free(rd_js);
    ck_free(rd);
  }

  if (res && req && res->state == STATE_OK) {
    u32 i;
    f = fopen("response.dat", "w");
    if (!f) PFATAL("Cannot create 'response.dat'");

    u64 msg_size = strlen((char*)res->msg);
    u64 rs_size = msg_size + strlen("HTTP/1.1 1000 \n") + 1;
    u8* rs = ck_alloc(rs_size);
    snprintf((char*)rs, rs_size -1, "HTTP/1.1 %u %s\n", res->code, res->msg);

    u32 s = strlen((char*)rs);
    for (i=0;i<res->hdr.c;i++)
      if (res->hdr.t[i] == PARAM_HEADER) {
        ADD_STR_DATA(rs, s, res->hdr.n[i]);
        ADD_STR_DATA(rs, s, ": ");
        ADD_STR_DATA(rs, s, res->hdr.v[i]);
        ADD_STR_DATA(rs, s, "\n");
      }


    if(res->payload) {
      ADD_STR_DATA(rs, s, "\n");
      ADD_STR_DATA(rs, s, res->payload);
    }

    if (fwrite(rs, strlen((char*)rs), 1, f)) {};
    fclose(f);

    /* Write .js file with base64 encoded json data. */
    u8* rs_js;
    NEW_STR(rs_js, s);
    ADD_STR_DATA(rs_js, s, "var res = {'data':'");
    ADD_STR_DATA(rs_js, s, js_escape(rs, 0));
    ADD_STR_DATA(rs_js, s, "'}");

    f = fopen("response.js", "w");
    if (!f) PFATAL("Cannot create 'response.js'");
    if (fwrite(rs_js, strlen((char*)rs_js), 1, f)) {};
    fclose(f);

    ck_free(rs_js);
    ck_free(rs);

    /* Also collect MIME samples at this point. */

    if (!req->pivot->dupe && res->sniffed_mime && sample) {

      for (i=0;i<m_samp_cnt;i++) 
        if (!strcmp((char*)m_samp[i].det_mime, (char*)res->sniffed_mime)) break;

      if (i == m_samp_cnt) {
        m_samp = ck_realloc(m_samp, (i + 1) * sizeof(struct mime_sample_desc));
        m_samp[i].det_mime = res->sniffed_mime;
        m_samp_cnt++;
      } else {
        u32 c;

        /* If we already have something that looks very much the same on the
           list, don't bother reporting it again. */

        for (c=0;c<m_samp[i].sample_cnt;c++)
          if (same_page(&m_samp[i].res[c]->sig, &res->sig)) return;
      }

      m_samp[i].req = ck_realloc(m_samp[i].req, (m_samp[i].sample_cnt + 1) *
                                 sizeof(struct http_request*));
      m_samp[i].res = ck_realloc(m_samp[i].res, (m_samp[i].sample_cnt + 1) *
                                 sizeof(struct http_response*));
      m_samp[i].req[m_samp[i].sample_cnt] = req;
      m_samp[i].res[m_samp[i].sample_cnt] = res;
      m_samp[i].sample_cnt++;

    }

  }

}


/* Dumps the actual crawl data. */

static void output_crawl_tree(struct pivot_desc* pv) {
  u32 i;
  FILE* f;
  static u32 proc_cnt;

  /* Save request, response. */

  save_req_res(pv->req, pv->res, 1);

  /* Write children information. Don't crawl children just yet,
     because we could run out of file descriptors on a particularly
     deep tree if we keep one open and recurse. */

  f = fopen("child_index.js", "w");
  if (!f) PFATAL("Cannot create 'child_index.js'.");

  fprintf(f, "var child = [\n");

  for (i=0;i<pv->child_cnt;i++) {
    u8 tmp[32];
    u8* p;

    if (suppress_dupes && pv->child[i]->dupe && 
        !pv->child[i]->total_child_cnt) continue;

    /* Also completely suppress nodes that seem identical to the
       previous one, and have a common prefix (as this implies
       a mod_rewrite or htaccess filter). */

    if (i && pv->child[i-1]->pv_sig == pv->child[i]->pv_sig) {
      u8 *pn = pv->child[i-1]->name, *cn = pv->child[i]->name;
      u32 pnd = strcspn((char*)pn, ".");
      if (!strncasecmp((char*)pn, (char*)cn, pnd)) continue;
    }

    sprintf((char*)tmp, "c%u", i);

    fprintf(f, "  { 'dupe': %s, 'type': %u, 'name': '%s%s",
            pv->child[i]->dupe ? "true" : "false",
            pv->child[i]->type, js_escape(pv->child[i]->name, 0),
            (pv->child[i]->fuzz_par == -1 || pv->child[i]->type == PIVOT_VALUE)
            ? (u8*)"" : (u8*)"=");

    fprintf(f, "%s', 'dir': '%s', 'linked': %d, ",
            (pv->child[i]->fuzz_par == -1 || pv->child[i]->type == PIVOT_VALUE)
            ? (u8*)"" :
            js_escape(pv->child[i]->req->par.v[pv->child[i]->fuzz_par], 0),
            tmp, pv->child[i]->linked);

    p = serialize_path(pv->child[i]->req, 1, 1);
    fprintf(f, "'url': '%s', ", js_escape(p, 0));
    ck_free(p);

    describe_res(f, pv->child[i]->res);

    fprintf(f,", 'missing': %s, 'csens': %s, 'child_cnt': %u, "
            "'issue_cnt': [ %u, %u, %u, %u, %u ], 'sig': 0x%x }%s\n", 
            pv->child[i]->missing ? "true" : "false",
            pv->child[i]->csens ? "true" : "false",
            pv->child[i]->total_child_cnt, pv->child[i]->total_issues[1],
            pv->child[i]->total_issues[2], pv->child[i]->total_issues[3],
            pv->child[i]->total_issues[4], pv->child[i]->total_issues[5],
            pv->child[i]->pv_sig,
            (i == pv->child_cnt - 1) ? "" : ",");
  }

  fprintf(f, "];\n");
  fclose(f);

  /* Write issue index, issue dumps. */

  f = fopen("issue_index.js", "w");
  if (!f) PFATAL("Cannot create 'issue_index.js'.");

  fprintf(f, "var issue = [\n");

  for (i=0;i<pv->issue_cnt;i++) {
    u8 tmp[32];
    sprintf((char*)tmp, "i%u", i);

    fprintf(f, "  { 'severity': %u, 'type': %u, 'sid': '%d', 'extra': '%s', ",
            PSEV(pv->issue[i].type) - 1, pv->issue[i].type, pv->issue[i].sid,
            pv->issue[i].extra ? js_escape(pv->issue[i].extra, 0) : (u8*)"");

    describe_res(f, pv->issue[i].res);

    fprintf(f, ", 'dir': '%s' }%s\n",
            tmp, (i == pv->issue_cnt - 1) ? "" : ",");

    if (mkdir((char*)tmp, 0755)) PFATAL("Cannot create '%s'.", tmp);
    if (chdir((char*)tmp)) PFATAL("chdir unexpectedly fails!");
    save_req_res(pv->issue[i].req, pv->issue[i].res, 1);
    if (chdir((char*)"..")) PFATAL("chdir unexpectedly fails!");

    /* Issue samples next! */

    if (!pv->dupe) {
      u32 c;
      for (c=0;c<i_samp_cnt;c++)
        if (i_samp[c].type == pv->issue[i].type) break;

      if (c == i_samp_cnt) {
        i_samp = ck_realloc(i_samp, (c + 1) * sizeof(struct issue_sample_desc));
        i_samp_cnt++;
        i_samp[c].type = pv->issue[i].type;
      }

      i_samp[c].i = ck_realloc(i_samp[c].i, (i_samp[c].sample_cnt + 1) *
                               sizeof(struct issue_desc*));
      i_samp[c].i[i_samp[c].sample_cnt] = &pv->issue[i];
      i_samp[c].sample_cnt++;
    }

  }

  fprintf(f, "];\n");
  fclose(f);

  /* Actually crawl children. */

  for (i=0;i<pv->child_cnt;i++) {
    u8 tmp[32];
    sprintf((char*)tmp, "c%u", i);
    if (mkdir((char*)tmp, 0755)) PFATAL("Cannot create '%s'.", tmp);
    if (chdir((char*)tmp)) PFATAL("chdir unexpectedly fails!");
    output_crawl_tree(pv->child[i]);
    if (chdir((char*)"..")) PFATAL("chdir unexpectedly fails!");
  }

  if ((!(proc_cnt++ % 50)) || pv->type == PIVOT_ROOT) {
    SAY(cLGN "\r[+] " cNOR "Writing crawl tree: %u", proc_cnt);
    fflush(0);
  }

}


/* Writes previews of MIME types, issues. */

static int m_samp_qsort(const void* ptr1, const void* ptr2) {
  const struct mime_sample_desc *p1 = ptr1, *p2 = ptr2;
  return strcasecmp((char*)p1->det_mime, (char*)p2->det_mime);
}

static int i_samp_qsort(const void* ptr1, const void* ptr2) {
  const struct issue_sample_desc *p1 = ptr1, *p2 = ptr2;
  return p2->type - p1->type;
}


static void output_summary_views() {
  u32 i;
  FILE* f;

  f = fopen("samples.js", "w");
  if (!f) PFATAL("Cannot create 'samples.js'.");

  qsort(m_samp, m_samp_cnt, sizeof(struct mime_sample_desc), m_samp_qsort);
  qsort(i_samp, i_samp_cnt, sizeof(struct issue_sample_desc), i_samp_qsort);

  fprintf(f, "var mime_samples = [\n");

  for (i=0;i<m_samp_cnt;i++) {
    u32 c;
    u8 tmp[32];
    u32 use_samp = (m_samp[i].sample_cnt > MAX_SAMPLES ? MAX_SAMPLES :
         m_samp[i].sample_cnt);

    sprintf((char*)tmp, "_m%u", i);
    if (mkdir((char*)tmp, 0755)) PFATAL("Cannot create '%s'.", tmp);
    if (chdir((char*)tmp)) PFATAL("chdir unexpectedly fails!");

    fprintf(f, "  { 'mime': '%s', 'samples': [\n", m_samp[i].det_mime);

    for (c=0;c<use_samp;c++) {
      u8 tmp2[32];
      u8* p = serialize_path(m_samp[i].req[c], 1, 0);
      sprintf((char*)tmp2, "%u", c);
      if (mkdir((char*)tmp2, 0755)) PFATAL("Cannot create '%s'.", tmp2);
      if (chdir((char*)tmp2)) PFATAL("chdir unexpectedly fails!");
      save_req_res(m_samp[i].req[c], m_samp[i].res[c], 0);
      if (chdir("..")) PFATAL("chdir unexpectedly fails!");
      fprintf(f, "    { 'url': '%s', 'dir': '%s/%s', 'linked': %d, 'len': %d"
              " }%s\n", js_escape(p, 0), tmp, tmp2,
              m_samp[i].req[c]->pivot->linked, m_samp[i].res[c]->pay_len,
              (c == use_samp - 1) ? " ]" : ",");
      ck_free(p);
    }

    fprintf(f, "  }%s\n", (i == m_samp_cnt - 1) ? "" : ",");
    if (chdir("..")) PFATAL("chdir unexpectedly fails!");
  }

  fprintf(f, "];\n\n");

  fprintf(f, "var issue_samples = [\n");

  for (i=0;i<i_samp_cnt;i++) {
    u32 c;
    u8 tmp[32];
    u32 use_samp = (i_samp[i].sample_cnt > MAX_SAMPLES ? MAX_SAMPLES :
         i_samp[i].sample_cnt);

    sprintf((char*)tmp, "_i%u", i);
    if (mkdir((char*)tmp, 0755)) PFATAL("Cannot create '%s'.", tmp);
    if (chdir((char*)tmp)) PFATAL("chdir unexpectedly fails!");

    fprintf(f, "  { 'severity': %d, 'type': %d, 'samples': [\n", 
            PSEV(i_samp[i].type) - 1, i_samp[i].type);

    for (c=0;c<use_samp;c++) {
      u8 tmp2[32];
      u8* p = serialize_path(i_samp[i].i[c]->req, 1, 0);
      sprintf((char*)tmp2, "%u", c);
      if (mkdir((char*)tmp2, 0755)) PFATAL("Cannot create '%s'.", tmp2);
      if (chdir((char*)tmp2)) PFATAL("chdir unexpectedly fails!");
      save_req_res(i_samp[i].i[c]->req, i_samp[i].i[c]->res, 0);
      if (chdir("..")) PFATAL("chdir unexpectedly fails!");
      fprintf(f, "    { 'url': '%s', ", js_escape(p, 0));
      fprintf(f, "'extra': '%s', 'sid': '%d', 'dir': '%s/%s' }%s\n", 
              i_samp[i].i[c]->extra ? js_escape(i_samp[i].i[c]->extra, 0) : 
              (u8*)"", i_samp[i].i[c]->sid, tmp, tmp2, 
              (c == use_samp - 1) ? " ]" : ",");
      ck_free(p);
    }

    fprintf(f, "  }%s\n", (i == i_samp_cnt - 1) ? "" : ",");
    if (chdir("..")) PFATAL("chdir unexpectedly fails!");
  }

  fprintf(f, "];\n\n");
  fclose(f);

}


/* Copies over assets to target directory. */

static u8* ca_out_dir;

static int copy_asset(const struct dirent* d) {
  u8 *itmp, *otmp, buf[1024];
  s32 i, o;

  if (d->d_name[0] == '.' || !strcmp(d->d_name, "COPYING")) return 0;

  itmp = ck_alloc(strlen(ASSETS_DIR) + strlen(d->d_name) + 2);
  sprintf((char*)itmp, "%s/%s", ASSETS_DIR, d->d_name);
  i = open((char*)itmp, O_RDONLY);

  otmp = ck_alloc(strlen((char*)ca_out_dir) + strlen(d->d_name) + 2);
  sprintf((char*)otmp, "%s/%s", ca_out_dir, d->d_name);
  o = open((char*)otmp, O_WRONLY | O_CREAT | O_EXCL, 0644);

  if (i >= 0 && o >= 0) {
    s32 c;
    while ((c = read(i, buf, 1024)) > 0) 
      if (write(o, buf, c) != c) break;
  } 

  close(i);
  close(o);

  ck_free(itmp);
  ck_free(otmp);

  return 0;

}


static void copy_static_code(u8* out_dir) {
  struct dirent** d;
  ca_out_dir = out_dir;
  scandir(ASSETS_DIR, &d, copy_asset, NULL);
}


/* Saves all pivots for use by third-party tools. */

static void save_pivots(FILE* f, struct pivot_desc* cur) {

  u32 i;

  if (cur->req) {
    u8* url = serialize_path(cur->req, 1, 1);

    fprintf(f, "%s %s ", cur->req->method ? cur->req->method : (u8*)"GET",
           js_escape(url, 0));

    ck_free(url);

    fprintf(f, "name=%s ", js_escape(cur->name, 1));

    switch (cur->type) {
      case PIVOT_SERV:     fprintf(f, "type=serv "); break;
      case PIVOT_DIR:      fprintf(f, "type=dir "); break;
      case PIVOT_FILE:     fprintf(f, "type=file "); break;
      case PIVOT_PATHINFO: fprintf(f, "type=pathinfo "); break;
      case PIVOT_VALUE:    fprintf(f, "type=value "); break;
      case PIVOT_UNKNOWN:  fprintf(f, "type=unknown "); break;
      case PIVOT_PARAM:    fprintf(f, "type=param "); break;
      default:             fprintf(f, "type=??? ");
    }

    switch (cur->linked) {
      case 0:  fprintf(f, "linked=no "); break;
      case 1:  fprintf(f, "linked=maybe "); break;
      default: fprintf(f, "linked=yes ");
    }


    /* When in no_checks mode, we'll report all the detected files and
       directories. We don't do this when crawling is disabled.. */
    if(!cur->linked && no_checks && !no_parse)
      problem(PROB_HIDDEN_NODE, cur->req, cur->res, 0, cur, 0);

    if (cur->res)
      fprintf(f, "dup=%u %s%scode=%u len=%u notes=%u sig=0x%x\n", cur->dupe,
             cur->bogus_par ? "bogus " : "",
             cur->missing ? "returns_404 " : "",
             cur->res->code, cur->res->pay_len, 
             cur->issue_cnt, cur->pv_sig);
    else
      fprintf(f, "not_fetched\n");

  }

  for (i=0;i<cur->child_cnt;i++) save_pivots(f, cur->child[i]);

}


static void save_all_pivots(void) {
  FILE *f = fopen("pivots.txt", "w");

  if (!f) PFATAL("Cannot create 'pivots.txt'.");

  save_pivots(f, &root_pivot);

  fclose(f);
}



/* Writes report to index.html in the current directory. Will create
   subdirectories, helper files, etc. */

void write_report(u8* out_dir, u64 scan_time, u32 seed) {

  SAY(cLGN "[+] " cNOR "Copying static resources...\n");
  copy_static_code(out_dir);

  if (chdir((char*)out_dir)) PFATAL("Cannot chdir to '%s'", out_dir);

  sort_annotate_pivot(&root_pivot);
  SAY("\n");

  collect_signatures(&root_pivot);
  SAY("\n");

  compute_counts(&root_pivot);
  SAY("\n");

  SAY(cLGN "[+] " cNOR "Saving pivot data for third-party tools...\n");
  save_all_pivots();

  SAY(cLGN "[+] " cNOR "Writing scan description...\n");
  output_scan_info(scan_time, seed);

  output_crawl_tree(&root_pivot);
  SAY("\n");

  SAY(cLGN "[+] " cNOR "Generating summary views...\n");
  output_summary_views();

  SAY(cLGN "[+] " cNOR "Report saved to '" cLBL "%s/index.html" cNOR "' ["
      cLBL "0x%08x" cNOR "].\n", out_dir, seed);

}
