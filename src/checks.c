/*
   skipfish - injection tests
   ---------------------------

   Author: Niels Heinen <heinenn@google.com>,
           Michal Zalewski <lcamtuf@google.com>

   Copyright 2009 - 2012 by Google Inc. All Rights Reserved.

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


#define _VIA_CHECKS_C

#include "crawler.h"
#include "analysis.h"
#include "http_client.h"
#include "checks.h"
#include "auth.h"



static u8 inject_prologue_tests(struct pivot_desc* pivot);
static u8 inject_prologue_check(struct http_request*, struct http_response*);

static u8 dir_ips_tests(struct pivot_desc* pivot);
static u8 dir_ips_check(struct http_request*, struct http_response*);

static u8 inject_xml_tests(struct pivot_desc* pivot);
static u8 inject_xml_check(struct http_request*, struct http_response*);

static u8 inject_xss_tests(struct pivot_desc* pivot);
static u8 inject_xss_check(struct http_request*, struct http_response*);

static u8 inject_shell_tests(struct pivot_desc* pivot);
static u8 inject_shell_check(struct http_request*, struct http_response*);

static u8 inject_diff_shell_tests(struct pivot_desc* pivot);
static u8 inject_diff_shell_check(struct http_request*, struct http_response*);

static u8 inject_dir_listing_tests(struct pivot_desc* pivot);
static u8 inject_dir_listing_check(struct http_request*, struct http_response*);

static u8 inject_inclusion_tests(struct pivot_desc* pivot);
static u8 inject_inclusion_check(struct http_request*, struct http_response*);

static u8 inject_split_tests(struct pivot_desc* pivot);
static u8 inject_split_check(struct http_request*, struct http_response*);

static u8 inject_redir_tests(struct pivot_desc* pivot);
static u8 inject_redir_check(struct http_request*, struct http_response*);

static u8 inject_sql_tests(struct pivot_desc* pivot);
static u8 inject_sql_check(struct http_request*, struct http_response*);

static u8 inject_format_tests(struct pivot_desc* pivot);
static u8 inject_format_check(struct http_request*, struct http_response*);

static u8 inject_integer_tests(struct pivot_desc* pivot);
static u8 inject_integer_check(struct http_request*, struct http_response*);

static u8 put_upload_tests(struct pivot_desc* pivot);
static u8 put_upload_check(struct http_request*, struct http_response*);

static u8 inject_behavior_tests(struct pivot_desc* pivot);
static u8 inject_behavior_check(struct http_request*, struct http_response*);

static u8 param_behavior_tests(struct pivot_desc* pivot);
static u8 param_behavior_check(struct http_request*, struct http_response*);

static u8 param_ognl_tests(struct pivot_desc* pivot);
static u8 param_ognl_check(struct http_request*, struct http_response*);

static u8 xssi_tests(struct pivot_desc* pivot);
static u8 xssi_check(struct http_request*, struct http_response*);



/* The crawl structure defines the tests by combining function pointers and
   flags. The values given indicate the following:

   1- Amount of responses expected
   2- Whether to keep requests and responses before calling the check
   3- Whether the check accepted pivots with res_varies set
   4- Whether the check is time sensitive
   5- Whether we should scrape the response for links.
   6- The type of PIVOT that the test/check accepts
   7- Pointer to the function that scheduled the test(s) requests
   8- Pointer to the function that checks the result
   9- Whether to skip this test

   At the end, inject_done() is called:
     - we move on with additional tests (e.g. parameter)
     - or continue with the next pivot

   Point 8 allows command-line flags to toggle enabled/disabled
   tests. For example, shell injection tests are not so relevant on
   Windows environments so this allow them to be disabled.

*/

u32 cb_handle_cnt = 19;  /* Total of checks                      */
u32 cb_handle_off = 4;   /* Checks after the offset are optional */

static struct cb_handle cb_handles[] = {
  /* Authentication check */
  { 2, 0, 0, 0, 0, 0,
    CHK_SESSION, (u8*)"session check",
    auth_verify_tests, auth_verify_checks, 0 },

  /* Behavior checks for dirs/params */
  { BH_CHECKS, 1, 0, 0, 2, PIVOT_PARAM,
    CHK_BEHAVE, (u8*)"param behavior",
    param_behavior_tests, param_behavior_check, 0 },

  { 2, 1, 0, 0, 2, PIVOT_PARAM,
    CHK_OGNL, (u8*)"param OGNL",
    param_ognl_tests, param_ognl_check, 0 },

  { BH_CHECKS, 1, 0, 0, 2, PIVOT_DIR|PIVOT_FILE,
    CHK_BEHAVE, (u8*)"inject behavior",
    inject_behavior_tests, inject_behavior_check, 0 },

  /* All the injection tests */
  { 2, 1, 0, 0, 2, PIVOT_DIR,
    CHK_IPS, (u8*)"IPS check",
    dir_ips_tests, dir_ips_check, 0 },

  { 2, 1, 0, 0, 0, PIVOT_DIR|PIVOT_SERV,
    CHK_PUT, (u8*)"PUT upload",
    put_upload_tests, put_upload_check, 0 },

  { 4, 1, 0, 0, 1, PIVOT_DIR|PIVOT_PARAM,
    CHK_DIR_LIST, (u8*)"dir traversal",
    inject_dir_listing_tests, inject_dir_listing_check, 0 },

#ifdef RFI_SUPPORT
  { 12, 1, 1, 0, 1, 0,
    CHK_FI, (u8*)"file inclusion",
    inject_inclusion_tests, inject_inclusion_check, 0 },
#else
  { 11, 1, 1, 0, 1, 0,
    CHK_FI, (u8*)"file inclusion",
    inject_inclusion_tests, inject_inclusion_check, 0 },
#endif

  { 4, 0, 1, 0, 1, 0,
    CHK_XSS, (u8*)"XSS injection",
    inject_xss_tests, inject_xss_check, 0 },

  { 1, 1, 1, 0, 1, 0,
    CHK_XSSI, (u8*)"XSSI protection",
    xssi_tests, xssi_check, 0 },

  { 0, 0, 1, 0, 1, 0,
    CHK_PROLOG, (u8*)"prologue injection",
    inject_prologue_tests, inject_prologue_check, 0 },

  { 2, 1, 1, 0, 1, 0,
    CHK_RSPLIT, (u8*)"Header injection",
    inject_split_tests, inject_split_check, 0 },

  { 5, 1, 1, 0, 1, PIVOT_PARAM,
    CHK_REDIR, (u8*)"Redirect injection",
    inject_redir_tests, inject_redir_check, 0 },

  { 10, 1, 0, 0, 1, 0,
    CHK_SQL, (u8*)"SQL injection",
    inject_sql_tests, inject_sql_check, 0 },

  { 2, 1, 0, 0, 1, 0,
    CHK_XML, (u8*)"XML injection",
    inject_xml_tests, inject_xml_check, 0 },

  { 12, 1, 0, 0, 1, 0,
    CHK_SHELL_DIFF, (u8*)"Shell injection (diff)",
    inject_diff_shell_tests, inject_diff_shell_check, 0 },

  { 12, 1, 1, 1, 1, 0,
    CHK_SHELL_SPEC, (u8*)"Shell injection (spec)",
    inject_shell_tests, inject_shell_check, 0 },

  { 2, 1, 0, 0, 1, 0,
    CHK_FORMAT, (u8*)"format string",
    inject_format_tests, inject_format_check, 1 },

  { 9, 1, 0, 0, 1, 0,
    CHK_INTEGER, (u8*)"integer handling",
    inject_integer_tests, inject_integer_check, 1 }

};

/* Dump the checks to stdout */

void display_injection_checks(void) {
  u32 i;

  SAY("\n[*] Available injection tests:\n\n");
  for (i=cb_handle_off; i<cb_handle_cnt; i++) {
    SAY("  -- [%2d] %-25s %s\n", i-cb_handle_off, cb_handles[i].name,
           cb_handles[i].skip ? "(disabled)" : "");
  }
  SAY("\n");
}

/* Disable tests by parsing a comma separated list which we received
   from the command-line.  */

void toggle_injection_checks(u8* str, u32 enable, u8 user) {

  u32 tnr;
  u8* ptr;

  /* If this is user input, we only allow check manipulation. Else,
     we also allow other tests, such as for stability to be toggled */

  u32 offset = user ? cb_handle_off : 0;

  /* Copy the string for manipulation */
  u8* ids = ck_strdup(str);

  ptr = (u8*)strtok((char*)ids, ",");

  for (; ptr != NULL ;){
    tnr = atoi((char*)ptr);

    if (tnr > cb_handle_cnt)
      FATAL("Unable to parse checks toggle string");

    tnr += offset;
    /* User values are array index nr + 1 */
    if (enable && cb_handles[tnr].skip) {
      cb_handles[tnr].skip = 0;
      DEBUG(" Enabled test: %d : %s\n", tnr, cb_handles[tnr].name);
    } else {
      cb_handles[tnr].skip = 1;
      DEBUG(" Disabled test: %d : %s\n", tnr, cb_handles[tnr].name);
    }

    ptr = (u8*)strtok(NULL, ",");
  }

  ck_free(ids);
}

/* The inject state manager which uses the list ot check structs to
   decide what test to schedule next */

u8 inject_state_manager(struct http_request* req, struct http_response* res) {

  u32 i;
  s32 check = req->pivot->check_idx;

  DEBUG_CALLBACK(req, res);

  /* If we are in crawler only more, jump to inject_done to effectively
     disable all checks for the pivot */

  if(no_checks) goto inject_done;

  /* First test that gets us in the loop? This means we'll immediately go and
     schedule some tests */

  if (check == -1) goto schedule_tests;

  /* Safety check */
  if (check > cb_handle_cnt)
    FATAL("Check number %d exceeds handle count %d!",check,cb_handle_cnt);

  /* If requests failed for a test than we might have chosen to not
     proceed with it by adding the check to i_skip.  Here we check if this
     is the case. */

  if (req->pivot->i_skip[check])
    return 0;

  /* For simple injection tests, we do not abort at 503, 504's. But for
     differential tests, we have to. */

  if (res->state != STATE_OK || (!cb_handles[check].allow_varies &&
      (res->code == 503 || res->code == 504))) {
    handle_error(req, res, (u8*)cb_handles[check].name, 0);

    content_checks(req, res);
    req->pivot->i_skip[check] = 1;
    return 0;
  }


  /* Store req/res which is used by checks that like to have multiple req/res
     pairs before getting called. */

  if (cb_handles[check].res_keep) {
    req->pivot->misc_req[req->user_val] = req;
    req->pivot->misc_res[req->user_val] = res;
    req->pivot->misc_cnt++;

    /* Check and return if we need more responses. */
    if (cb_handles[check].res_num &&
        req->pivot->misc_cnt != cb_handles[check].res_num)
         return 1;
  }

  /* Check the results of previously scheduled tests and, if that goes
     well, schedule new tests. When the callback returns 1, this means
     more requests are needed before we can can do the final checks. */


  DEBUG_STATE_CALLBACK(req, cb_handles[check].name, 1);

  /* Check if we got all responses to avoid handing over NULL poiners to the
   * checks() functions */

  if (cb_handles[check].res_keep) {
    for (i=0; i<req->pivot->misc_cnt; i++) {
      if (!MREQ(i) || !MRES(i)) {
        problem(PROB_FETCH_FAIL, req, res, (u8*)"During injection testing", req->pivot, 0);

        /* Today, we'll give up on this test. In the next release: reschedule */
        goto content_checks;
      }

    }
  }

  if (cb_handles[check].checks(req,res))
    return 1;

  if (!cb_handles[check].res_keep &&
     (cb_handles[check].res_num && ++req->pivot->misc_cnt != cb_handles[check].res_num))
    return 0;

content_checks:

  /* If we get here, we're done and can move on. First make sure that
     all responses have been checked. Than free memory and schedule the
     next test */

  if (cb_handles[check].res_keep && req->pivot->misc_cnt) {
    for (i=0; i<req->pivot->misc_cnt; i++) {

      /* Only check content once */
      if (!MRES(i) || !MREQ(i) || MRES(i)->stuff_checked)
        continue;

      /* Only scrape for checks that want it
           0 = don't scrape
           1 = check content
           2 = check content and extract links */
      if (cb_handles[check].scrape > 0) {
        content_checks(MREQ(i), MRES(i));
        if (cb_handles[check].scrape == 2)
          scrape_response(MREQ(i), MRES(i));
      }
    }
  }

schedule_tests:

  destroy_misc_data(req->pivot, req);

  check = ++req->pivot->check_idx;
  if (check < cb_handle_cnt) {

    /* Move to the next test in case it's marked... */
    if (cb_handles[check].skip) goto schedule_tests;

    /* Move to the next test in case the page is unstable and the test doesn't want it. */
    if ((req->pivot->res_varies && !cb_handles[check].allow_varies) ||
        (req->pivot->res_time_exceeds && cb_handles[check].time_sensitive))
      goto schedule_tests;

    /* Move to the next test in case of pivot type mismatch */
    if (cb_handles[check].pv_flag > 0 && !(cb_handles[check].pv_flag & req->pivot->type))
      goto schedule_tests;

    DEBUG_STATE_CALLBACK(req, cb_handles[check].name, 0);

    /* Do the tests and return upon success or move on to the next upon
      a return value of 1. We store the ID of the check in the pivot to
      allow other functions, that use the pivot, to find out the current
      injection test */
    req->pivot->check_id = cb_handles[check].id;
    if (cb_handles[check].tests(req->pivot) == 1)
      goto schedule_tests;

    return 0;
  }

inject_done:

  /* All injection tests done. Reset the counter and call inject_done()
     to finish (or proceed with param tests */


  DEBUG_STATE_CALLBACK(req, "inject_done", 1);

  req->pivot->check_idx = -1;
  inject_done(req->pivot);

  return 0;
}


static u8 xssi_tests(struct pivot_desc* pv) {
  struct http_request* n;

  DEBUG_HELPER(pv);

  /* We only want Javascript that does not have inclusion protection. This
   * test, should be moved to the injection manager whenever we have more
   * content specific tests (e.g. css ones) */

  if(pv->res->js_type != 2 || pv->res->json_safe)
    return 1;

  n = req_copy(pv->req, pv, 1);
  n->callback = inject_state_manager;
  n->no_cookies = 1;
  async_request(n);

  return 0;

}

static u8 xssi_check(struct http_request* req,
                     struct http_response* res) {

  DEBUG_MISC_CALLBACK(req, res);

  /* When the response with cookie is different from the cookie-less response,
   * than the content is session depended. In case of Javascript without XSSI
   * protection, this is more than likely an issue. */


  if (!same_page(&RPRES(req)->sig, &MRES(0)->sig)) {

  /* Responses that do not contain the term "function", "if", "for", "while", etc,
     are much more likely to be dynamic JSON than just static scripts. Let's
     try to highlight these. */

    if ((!req->method || !strcmp((char*)req->method, "GET")) &&
      !inl_findstr(res->payload, (u8*)"if (", 2048) &&
      !inl_findstr(res->payload, (u8*)"if(", 2048) &&
      !inl_findstr(res->payload, (u8*)"for (", 2048) &&
      !inl_findstr(res->payload, (u8*)"for(", 2048) &&
      !inl_findstr(res->payload, (u8*)"while (", 2048) &&
      !inl_findstr(res->payload, (u8*)"while(", 2048) &&
      !inl_findstr(res->payload, (u8*)"function ", 2048) &&
      !inl_findstr(res->payload, (u8*)"function(", 2048)) {

      problem(PROB_JS_XSSI, req, res, (u8*)"Cookie-less JSON is different", req->pivot, 0);

    } else {
      problem(PROB_JS_XSSI, req, res, (u8*)"Cookie-less Javascript response is different", req->pivot, 0);
    }
  }

 /* Now this is interesting.  We can lookup the issues in the pivot and if
  * analysis.c thinks this page has an XSSI, we can kill that assumption */

  remove_issue(req->pivot, PROB_JS_XSSI);

  return 0;
}

static u8 inject_behavior_tests(struct pivot_desc* pv) {
  struct http_request* n;
  u32 i;

  DEBUG_HELPER(pv);

  for (i=0;i<BH_CHECKS;i++) {
    n = req_copy(pv->req, pv, 1);
    n->callback = inject_state_manager;
    n->user_val = i;
    async_request(n);
  }

  return 0;
}

static u8 inject_behavior_check(struct http_request* req,
                                struct http_response* res) {

  u32 i;

  /* pv->state may change after async_request() calls in
     insta-fail mode, so we should cache accordingly. */

  DEBUG_CALLBACK(req, res);

  for (i=0; i<req->pivot->misc_cnt; i++) {
    if (!same_page(&RPRES(req)->sig, &MRES(i)->sig)) {
      problem(PROB_VARIES, MREQ(i), MRES(i), 0, MREQ(i)->pivot, 0);
      return 0;
    }
  }

  return 0;
}

static u8 put_upload_tests(struct pivot_desc* pv) {

  struct http_request* n;
  DEBUG_HELPER(pv);

  /* First a PUT request */
  n = req_copy(pv->req, pv, 1);
  if (n->method) ck_free(n->method);
  n->method   = ck_strdup((u8*)"PUT");
  n->user_val = 0;
  n->callback = inject_state_manager;
  replace_slash(n, (u8*)("PUT-" BOGUS_FILE));
  async_request(n);

  /* Second a FOO for false positives */
  n = req_copy(pv->req, pv, 1);
  if (n->method) ck_free(n->method);
  n->method   = ck_strdup((u8*)"FOO");
  n->user_val = 1;
  n->callback = inject_state_manager;
  replace_slash(n, (u8*)("FOO-" BOGUS_FILE));
  async_request(n);

  return 0;
}

static u8 put_upload_check(struct http_request* req,
                           struct http_response* res) {

  DEBUG_MISC_CALLBACK(req, res);

  /* If PUT and FOO of the page does not give the same result. And if
  additionally we get a 2xx code, than we'll mark the issue as detected */
  if (!same_page(&MRES(0)->sig, &MRES(1)->sig) &&
     MRES(0)->code >= 200 && MRES(1)->code < 300)
    problem(PROB_PUT_DIR, MREQ(0), MRES(0), 0, req->pivot, 0);

  return 0;
}


/* The prologue test checks whether it is possible to inject a string in the
   first bytes of the response because this can lead to utf-7 or third party
   browser plugin attacks */

static u8 inject_prologue_tests(struct pivot_desc* pivot) {

  u32 orig_state = pivot->state;
  struct http_request* n;

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, (u8*)"+/skipfish-bom");
  n->callback = inject_state_manager;
  async_request(n);

  return 0;
}

static u8 inject_prologue_check(struct http_request* req,
                                struct http_response* res) {

  DEBUG_CALLBACK(req, res);

  if (res->pay_len && !prefix(res->payload, (u8*)"+/skipfish-bom") &&
      !GET_HDR((u8*)"Content-Disposition", &res->hdr))
    problem(PROB_PROLOGUE, req, res, NULL, req->pivot, 0);

  return 0;
}


/* XML injection checks evaluates multiple server responses and determined
   whether the injected string caused a difference in behavior/reponse */

static u8 inject_xml_tests(struct pivot_desc* pivot) {

  /* Backend XML injection - 2 requests. */
  u32 orig_state = pivot->state;
  struct http_request* n;

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, "sfish>'>\"><sfish></sfish>");
  n->callback = inject_state_manager;
  n->user_val = 0;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, "sfish>'>\"></sfish><sfish>");
  n->callback = inject_state_manager;
  n->user_val = 1;
  async_request(n);

  return 0;
}

static u8 inject_xml_check(struct http_request* req,
                           struct http_response* res) {

  DEBUG_MISC_CALLBACK(req, res);

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

  return 0;
}


static u8 inject_shell_tests(struct pivot_desc* pivot) {

  /* Shell command injection - 12 requests. */

  u32 orig_state = pivot->state;
  u8* tmp;
  struct http_request* n;

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, (u8*)"`echo skip12``echo 34fish`");
  n->callback = inject_state_manager;
  n->user_val = 0;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  APPEND_VECTOR(orig_state, n, (u8*)"`echo skip12``echo 34fish`");
  n->callback = inject_state_manager;
  n->user_val = 1;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, (u8*)"`echo${IFS}skip12``echo${IFS}34fish`");
  n->callback = inject_state_manager;
  n->user_val = 2;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  APPEND_VECTOR(orig_state, n, (u8*)"`echo${IFS}skip12``echo${IFS}34fish`");
  n->callback = inject_state_manager;
  n->user_val = 3;
  async_request(n);

  /* We use the measured time_base as an offset for the sleep test. The
     value is limited to MAX_RES_DURATION and the result is < 10 */

  tmp = ck_alloc(10);
  sprintf((char*)tmp, (char*)"`sleep %d`", pivot->res_time_base + SLEEP_TEST_ONE);

  n = req_copy(pivot->req, pivot, 1);
  APPEND_VECTOR(orig_state, n,tmp );
  n->callback = inject_state_manager;
  n->user_val = 4;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, tmp);
  n->callback = inject_state_manager;
  n->user_val = 5;
  async_request(n);

  sprintf((char*)tmp, (char*)"`sleep %d`", pivot->res_time_base + SLEEP_TEST_TWO);

  n = req_copy(pivot->req, pivot, 1);
  APPEND_VECTOR(orig_state, n, tmp);
  n->callback = inject_state_manager;
  n->user_val = 6;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, tmp);
  n->callback = inject_state_manager;
  n->user_val = 7;
  async_request(n);

  tmp = ck_realloc(tmp, 15);
  sprintf((char*)tmp, (char*)"`sleep${IFS}%d`", pivot->res_time_base + SLEEP_TEST_ONE);


  n = req_copy(pivot->req, pivot, 1);
  APPEND_VECTOR(orig_state, n, tmp);
  n->callback = inject_state_manager;
  n->user_val = 8;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, tmp);
  n->callback = inject_state_manager;
  n->user_val = 9;
  async_request(n);

  sprintf((char*)tmp, (char*)"`sleep${IFS}%d`", pivot->res_time_base + SLEEP_TEST_TWO);

  n = req_copy(pivot->req, pivot, 1);
  APPEND_VECTOR(orig_state, n, tmp);
  n->callback = inject_state_manager;
  n->user_val = 10;
  async_request(n);


  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, tmp);
  n->callback = inject_state_manager;
  n->user_val = 11;
  async_request(n);

  ck_free(tmp);

  return 0;
}

static u8 inject_shell_check(struct http_request* req,
                             struct http_response* res) {
  u32 i;

  DEBUG_MISC_CALLBACK(req, res);

  /* Look in the first 4 requests to find our concatenated string */

  for (i = 0; i < 3; i++) {
    if (inl_findstr(MRES(i)->payload, (u8*)"skip1234fish", 1024))
        problem(PROB_SH_INJECT, MREQ(i), MRES(i),
                (u8*)"Confirmed shell injection (echo test)", req->pivot, 0);
  }

  /* Check that the request was delayed by our sleep. The sleep delay is
     calculated by using the time_base in order to avoid FPs */

  u32 test_one = req->pivot->res_time_base + SLEEP_TEST_ONE;
  u32 test_two = req->pivot->res_time_base + SLEEP_TEST_TWO;

  /* Now we check if the request duration was influenced by the sleep. We
     do this by testing if the total request time was longer (or equal)
     to: the average request time + the sleep time (3 or 5 seconds).

     We allow the `sleep` request to take 1 second longer than
     expected which is the final measure to reduce FPs.

  */

  if ((RTIME(4) >= test_one && RTIME(4) < test_one + 1) &&
      (RTIME(6) >= test_two && RTIME(6) < test_two + 1)) {
        problem(PROB_SH_INJECT, MREQ(4), MRES(4),
                (u8*)"Confirmed shell injection (sleep test)", req->pivot, 0);
  }

  if ((RTIME(5) >= test_one && RTIME(5) < test_one + 1) &&
      (RTIME(7) >= test_two && RTIME(7) < test_two + 1)) {
        problem(PROB_SH_INJECT, MREQ(5), MRES(5),
                (u8*)"Confirmed shell injection (sleep test)", req->pivot, 0);
  }

  if ((RTIME(8) >= test_one && RTIME(8) < test_one + 1) &&
      (RTIME(10) >= test_two && RTIME(10) < test_two + 1)) {
        problem(PROB_SH_INJECT, MREQ(8), MRES(8),
                (u8*)"Confirmed shell injection (sleep test)", req->pivot, 0);
  }

  if ((RTIME(9) >= test_one && RTIME(9) < test_one + 1) &&
      (RTIME(11) >= test_two && RTIME(11) < test_two + 1)) {
        problem(PROB_SH_INJECT, MREQ(9), MRES(9),
                (u8*)"Confirmed shell injection (sleep test)", req->pivot, 0);
  }

  return 0;
}


static u8 inject_diff_shell_tests(struct pivot_desc* pivot) {

  /* Shell command injection - 12 requests. */

  u32 orig_state = pivot->state;
  struct http_request* n;

  n = req_copy(pivot->req, pivot, 1);
  APPEND_VECTOR(orig_state, n, "`true`");
  n->callback = inject_state_manager;
  n->user_val = 0;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  APPEND_VECTOR(orig_state, n, "`false`");
  n->callback = inject_state_manager;
  n->user_val = 1;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  APPEND_VECTOR(orig_state, n, "`uname`");
  n->callback = inject_state_manager;
  n->user_val = 2;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  APPEND_VECTOR(orig_state, n, "\"`true`\"");
  n->callback = inject_state_manager;
  n->user_val = 3;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  APPEND_VECTOR(orig_state, n, "\"`false`\"");
  n->callback = inject_state_manager;
  n->user_val = 4;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  APPEND_VECTOR(orig_state, n, "\"`uname`\"");
  n->callback = inject_state_manager;
  n->user_val = 5;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  APPEND_VECTOR(orig_state, n, "'`true`'");
  n->callback = inject_state_manager;
  n->user_val = 6;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  APPEND_VECTOR(orig_state, n, "'`false`'");
  n->callback = inject_state_manager;
  n->user_val = 7;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  APPEND_VECTOR(orig_state, n, "'`uname`'");
  n->callback = inject_state_manager;
  n->user_val = 8;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, "`true`");
  n->callback = inject_state_manager;
  n->user_val = 9;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, "`false`");
  n->callback = inject_state_manager;
  n->user_val = 10;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, "`uname`");
  n->callback = inject_state_manager;
  n->user_val = 11;
  async_request(n);

  return 0;
}


static u8 inject_diff_shell_check(struct http_request* req,
                             struct http_response* res) {

  DEBUG_MISC_CALLBACK(req, res);

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

     And a variant that replaces the original values (instead of appending)

       misc[9] = `true`
       misc[10] = `false`
       misc[11] = `uname`

     If misc[0] == misc[1], but misc[0] != misc[2], we probably have shell
     injection. Ditto for the remaining triplets. We use the `false` case
     to avoid errors on search fields, etc. */

  if (same_page(&MRES(0)->sig, &MRES(1)->sig) &&
      !same_page(&MRES(1)->sig, &MRES(2)->sig)) {
    problem(PROB_SH_INJECT, MREQ(1), MRES(1), 
      (u8*)"responses to `true` and `false` different than to `uname`",
      req->pivot, 0);
  }

  if (same_page(&MRES(3)->sig, &MRES(4)->sig) &&
      !same_page(&MRES(4)->sig, &MRES(5)->sig)) {
    problem(PROB_SH_INJECT, MREQ(3), MRES(3),
      (u8*)"responses to `true` and `false` different than to `uname`",
      req->pivot, 0);
  }

  if (same_page(&MRES(6)->sig, &MRES(7)->sig) &&
      !same_page(&MRES(6)->sig, &MRES(8)->sig)) {
    problem(PROB_SH_INJECT, MREQ(6), MRES(6),
      (u8*)"responses to `true` and `false` different than to `uname`",
      req->pivot, 0);
  }

  if (same_page(&MRES(9)->sig, &MRES(10)->sig) &&
      !same_page(&MRES(10)->sig, &MRES(11)->sig)) {
    problem(PROB_SH_INJECT, MREQ(9), MRES(9),
      (u8*)"responses to `true` and `false` different than to `uname`",
      req->pivot, 0);
  }

  return 0;
}



static u8 inject_xss_tests(struct pivot_desc* pivot) {

  /* Cross-site scripting - three requests (also test common
     "special" error pages). */

  struct http_request* n;
  u32 orig_state = pivot->state;
  u32 i, uval;

  n = req_copy(pivot->req, pivot, 1);
  APPEND_VECTOR(orig_state, n, new_xss_tag(NULL));
  set_value(PARAM_HEADER, (u8*)"Referer", new_xss_tag(NULL), 0, &n->par);
  register_xss_tag(n);
  n->callback = inject_state_manager;
  n->user_val = 0;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, new_xss_tag((u8*)".htaccess.aspx"));
  register_xss_tag(n);
  n->callback = inject_state_manager;
  n->user_val = 1;
  async_request(n);

  /* A last ones with only header injections. The User-Agent injection
    doesn't seems to be very useful for reflective XSS scenario's
    but could reveal persistant XSS problems (i.e. in log / backend
    interfaces) */

  n = req_copy(pivot->req, pivot, 1);
  set_value(PARAM_HEADER, (u8*)"Referer", new_xss_tag(NULL), 0, &n->par);
  set_value(PARAM_HEADER, (u8*)"User-Agent", new_xss_tag(NULL), 0, &n->par);
  register_xss_tag(n);
  n->callback = inject_state_manager;
  n->user_val = 2;
  async_request(n);

  /* One for testing HTTP_HOST XSS types which are somewhat unlikely
     but still have abuse potential (e.g. stored XSS') */
  n = req_copy(pivot->req, pivot, 1);
  set_value(PARAM_HEADER, (u8*)"Host", new_xss_tag(NULL), 0, &n->par);
  register_xss_tag(n);
  n->callback = inject_state_manager;
  n->user_val = 3;
  async_request(n);


  /* Finally we tests the cookies, one by one to avoid breaking the
     session */

  uval = 3;
  for (i=0;i<global_http_par.c;i++) {

    if (global_http_par.t[i] != PARAM_COOKIE)
      continue;

    n = req_copy(pivot->req, pivot, 1);
    set_value(PARAM_COOKIE, global_http_par.n[i],
            new_xss_tag(NULL), 0, &n->par);
    register_xss_tag(n);
    n->callback = inject_xss_check;
    n->user_val = ++uval;
    async_request(n);
  }

  return 0;
}


static u8 inject_xss_check(struct http_request* req,
                           struct http_response* res) {

  DEBUG_CALLBACK(req, res);

  if (!req || !res || FETCH_FAIL(res))
    return 0;

  /* Content checks do automatic HTML parsing and XSS detection.
  scrape_page() is generally not advisable here. This is not a very
  exiting check and we'll be able to get rid of it in future updated. */

  content_checks(req, res);
  return 0;
}

static u8 inject_dir_listing_tests(struct pivot_desc* pivot) {

  struct http_request* n;
  u8* tmp = NULL;
  u32 orig_state = pivot->state;

  /* Directory listing - 4 requests. The logic here is a bit
     different for parametric targets (which are easy to examine with 
     a ./ trick) and directories (which require a more complex 
     comparison). */

  pivot->misc_cnt = 0;

  n = req_copy(pivot->req, pivot, 1);

  if (orig_state == PSTATE_CHILD_INJECT) {
    replace_slash(n, (u8*)".");
    set_value(PARAM_PATH, NULL, (u8*)"", -1, &n->par);
  } else {
    tmp = ck_alloc(strlen((char*)TPAR(n)) + 5);
    sprintf((char*)tmp, ".../%s", TPAR(n));
    ck_free(TPAR(n));
    TPAR(n) = ck_strdup(tmp);
  }

  n->callback = inject_state_manager;
  n->user_val = 0;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);

  if (orig_state == PSTATE_CHILD_INJECT) {
    replace_slash(n, (u8*)".sf");
    set_value(PARAM_PATH, NULL, (u8*)"", -1, &n->par);
  } else {
    ck_free(TPAR(n));
    TPAR(n) = ck_strdup(tmp + 2);
  }

  n->callback = inject_state_manager;
  n->user_val = 1;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);

  if (orig_state == PSTATE_CHILD_INJECT) {
    replace_slash(n, (u8*)"\\.\\");
  } else {
    tmp[3] = '\\';
    ck_free(TPAR(n));
    TPAR(n) = ck_strdup(tmp);
  }
  n->callback = inject_state_manager;
  n->user_val = 2;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);

  if (orig_state == PSTATE_CHILD_INJECT) {
    replace_slash(n, (u8*)"\\.sf\\");
  } else {
    ck_free(TPAR(n));
    TPAR(n) = ck_strdup(tmp + 2);
    ck_free(tmp);
  }

  n->callback = inject_state_manager;
  n->user_val = 3;
  async_request(n);

  return 0;
}


static u8 inject_dir_listing_check(struct http_request* req,
                                   struct http_response* res) {
  u32 orig_state = req->pivot->state;

  DEBUG_MISC_CALLBACK(req, res);

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

     Here, the test is simpler: if misc[1] != misc[0], or misc[3] !=
     misc[2], we probably have a bug. The same if misc[4] or misc[5]
     contain magic strings, but misc[0] doesn't.

 */

  if (orig_state == PSTATE_CHILD_INJECT) {

    if (MRES(0)->code < 300 &&
        !same_page(&MRES(0)->sig, &RPRES(req)->sig) &&
        !same_page(&MRES(0)->sig, &MRES(1)->sig)) {
      problem(PROB_DIR_LIST_BYPASS, MREQ(0), MRES(0),
        (u8*)"unique response for /./", 
        req->pivot, 0);

      /* Use pivot's request, rather than MREQ(0), for link scraping;
         MREQ(0) contains an "illegal" manually constructed path. */

      RESP_CHECKS(RPREQ(req), MRES(0));
    }

    if (MRES(2)->code < 300 &&
        !same_page(&MRES(2)->sig, &RPRES(req)->sig) &&
        !same_page(&MRES(2)->sig, &MRES(3)->sig)) {
      problem(PROB_DIR_LIST_BYPASS, MREQ(2), MRES(2), 
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

  }

  return 0;
}


static u8 inject_inclusion_tests(struct pivot_desc* pivot) {

  struct http_request* n;
  u32 i;

  /* Perhaps do this in state manager ?*/
  if (pivot->state == PSTATE_CHILD_INJECT)
    return 1;

  /* We combine the traversal and file disclosure attacks here since
     the checks are almost identical */

  i = 0;
  while (disclosure_tests[i]) {
    n = req_copy(pivot->req, pivot, 1);

    /* No % encoding for these requests */
    n->fuzz_par_enc = (u8*)ENC_NULL;

    ck_free(TPAR(n));
    TPAR(n) = ck_strdup((u8*)disclosure_tests[i]);

    n->callback = inject_state_manager;
    n->user_val = i;
    async_request(n);
    i++;
  }

#ifdef RFI_SUPPORT
  /* Optionally try RFI */
  n = req_copy(pivot->req, pivot, 1);

  ck_free(TPAR(n));
  TPAR(n) = ck_strdup((u8*)RFI_HOST);

  n->callback = inject_state_manager;
  n->user_val = i;
  async_request(n);
#endif

  return 0;
}


static u8 inject_inclusion_check(struct http_request* req,
                                   struct http_response* res) {

  DEBUG_MISC_CALLBACK(req, res);

  u32 not_found = 0;

  /*
     Perform directory traveral and file inclusion tests.

       misc[1] = ../../../../../../../../etc/hosts
       misc[2] = ../../../../../../../../etc/hosts\0
       misc[3] = ../../../../../../../../etc/passwd
       misc[4] = ../../../../../../../../etc/passwd\0
       misc[5] = ..\..\..\..\..\..\..\..\boot.ini
       misc[6] = ..\..\..\..\..\..\..\..\boot.ini\0
       misc[7] = ../../../../../../../../WEB-INF/web.xml
       misc[8] = ../../../../../../../../WEB-INF/web.xml\0
       misc[9] = file:///etc/hosts
       misc[10] = file:///etc/passwd
       misc[11] = file:///boot.ini
       misc[12] = RFI (optional)

 */

  /* Check on the /etc/hosts file disclosure */
  if (!inl_findstr(RPRES(req)->payload, (u8*)"127.0.0.1", 1024)) {
    if (inl_findstr(MRES(0)->payload, (u8*)"127.0.0.1", 1024)) {
      problem(PROB_FI_LOCAL, MREQ(0), MRES(0),
              (u8*)"response resembles /etc/hosts (traversal)", req->pivot, 0);
    } else if (inl_findstr(MRES(1)->payload, (u8*)"127.0.0.1", 1024)) {
          problem(PROB_FI_LOCAL, MREQ(1), MRES(1),
                  (u8*)"response resembles /etc/hosts (traversal with NULL byte)", req->pivot, 0);
    } else if (inl_findstr(MRES(4)->payload, (u8*)"127.0.0.1", 1024)) {
          problem(PROB_FI_LOCAL, MREQ(4), MRES(4),
                  (u8*)"response resembles /etc/hosts (via file://)", req->pivot, 0);
    } else not_found++;
  }

  /* Check on the /etc/passwd file disclosure */
  if (!inl_findstr(RPRES(req)->payload, (u8*)"root:x:0:0:root", 1024)) {
    if (inl_findstr(MRES(2)->payload, (u8*)"root:x:0:0:root", 1024)) {
          problem(PROB_FI_LOCAL, MREQ(2), MRES(2),
                  (u8*)"response resembles /etc/passwd (via traversal)", req->pivot, 0);
    } else if (inl_findstr(MRES(3)->payload, (u8*)"root:x:0:0:root", 1024)) {
          problem(PROB_FI_LOCAL, MREQ(3), MRES(3),
                  (u8*)"response resembles /etc/passwd (via traversal)", req->pivot, 0);
    } else if (inl_findstr(MRES(9)->payload, (u8*)"root:x:0:0:root", 1024)) {
          problem(PROB_FI_LOCAL, MREQ(9), MRES(9),
                  (u8*)"response resembles /etc/passwd (via file://)", req->pivot, 0);
    } else not_found++;
  }

  /* Windows boot.ini disclosure */
  if (!inl_findstr(RPRES(req)->payload, (u8*)"[boot loader]", 1024)) {
    if (inl_findstr(MRES(4)->payload, (u8*)"[boot loader]", 1024)) {
        problem(PROB_FI_LOCAL, MREQ(4), MRES(4),
                (u8*)"response resembles c:\\boot.ini (via traversal)", req->pivot, 0);
    } else if (inl_findstr(MRES(5)->payload, (u8*)"[boot loader]", 1024)) {
        problem(PROB_FI_LOCAL, MREQ(5), MRES(5),
                (u8*)"response resembles c:\\boot.ini (via traversal)", req->pivot, 0);
    } else if (inl_findstr(MRES(10)->payload, (u8*)"[boot loader]", 1024)) {
        problem(PROB_FI_LOCAL, MREQ(10), MRES(10),
                (u8*)"response resembles c:\\boot.ini (via file://)", req->pivot, 0);
    } else not_found++;
  }

  /* Check the web.xml disclosure */
  if (!inl_findstr(RPRES(req)->payload, (u8*)"<servlet-mapping>", 1024)) {
    if (inl_findstr(MRES(6)->payload, (u8*)"<servlet-mapping>", 1024)) {
      problem(PROB_FI_LOCAL, MREQ(6), MRES(10),
              (u8*)"response resembles ./WEB-INF/web.xml (via traversal)", req->pivot, 0);
    } else if (inl_findstr(MRES(7)->payload, (u8*)"<servlet-mapping>", 1024)){ 
      problem(PROB_FI_LOCAL, MREQ(7), MRES(7),
              (u8*)"response resembles ./WEB-INF/web.xml (via traversal)", req->pivot, 0);
    } else not_found++;
  }

  /* If we disclosed a file, than we can remove any present traversal
     warnings, which in that case are just duplicate/noise */
  if (not_found != 4)
    remove_issue(req->pivot, PROB_DIR_TRAVERSAL);

#ifdef RFI_SUPPORT
  if (!inl_findstr(RPRES(req)->payload, (u8*)RFI_STRING, 1024) && 
      inl_findstr(MRES(11)->payload, (u8*)RFI_STRING, 1024)) {
    problem(PROB_FI_REMOTE, MREQ(11), MRES(11),
      (u8*)"remote file inclusion", req->pivot, 0);
  }
#endif

  return 0;
}




static u8 inject_redir_tests(struct pivot_desc* pivot) {

  struct http_request* n;
  u32 orig_state = pivot->state;

  /* XSS checks - 5 requests */

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, "http://skipfish.invalid/;?");
  n->callback = inject_state_manager;
  n->user_val = 0;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, "//skipfish.invalid/;?");
  n->callback = inject_state_manager;
  n->user_val = 1;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, "skipfish://invalid/;?");
  n->callback = inject_state_manager;
  n->user_val = 2;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, "'skip'''\"fish\"\"\"");
  n->callback = inject_state_manager;
  n->user_val = 3;
  async_request(n);

  /* Finally an encoded version which is aimed to detect injection
     problems in JS handlers, such as onclick, which executes HTML encoded
     strings. */

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, "&apos;skip&apos;&apos;&apos;&quot;fish&quot;&quot;&quot;");
  n->callback = inject_state_manager;
  n->user_val = 4;
  async_request(n);

  return 0;
}


static u8 inject_redir_check(struct http_request* req,
                             struct http_response* res) {
  u8* val;
  u32 i;

  DEBUG_MISC_CALLBACK(req, res);

  /* Check Location, Refresh headers. */

  for (i=0; i < req->pivot->misc_cnt; i++) {

    val = GET_HDR((u8*)"Location", &MRES(i)->hdr);

    if (val) {

      if (!case_prefix(val, "http://skipfish.invalid/") ||
          !case_prefix(val, "//skipfish.invalid/"))
        problem(PROB_URL_REDIR, MREQ(i), MRES(i), (u8*)"injected URL in 'Location' header",
                req->pivot, 0);

      if (!case_prefix(val, "skipfish:"))
        problem(PROB_URL_XSS, MREQ(i), MRES(i), (u8*)"injected URL in 'Location' header",
                req->pivot, 0);

    }

    val = GET_HDR((u8*)"Refresh", &MRES(i)->hdr);

    if (val && (val = (u8*)strchr((char*)val, '=')) && val++) {
      u8 semi_safe = 0;

      if (*val == '\'' || *val == '"') { val++; semi_safe++; }

      if (!case_prefix(val, "http://skipfish.invalid/") ||
          !case_prefix(val, "//skipfish.invalid/"))
        problem(PROB_URL_REDIR, MREQ(i), MRES(i), (u8*)"injected URL in 'Refresh' header",
                req->pivot, 0);

      /* Unescaped semicolon in Refresh headers is unsafe with MSIE6. */

      if (!case_prefix(val, "skipfish:") ||
          (!semi_safe && strchr((char*)val, ';')))
        problem(PROB_URL_XSS, MREQ(i), MRES(i), (u8*)"injected URL in 'Refresh' header",
                req->pivot, 0);

    }

    /* META tags and JS will be checked by content_checks(). We're not
       calling scrape_page(), because we don't want to accumulate bogus,
       injected links. */

    content_checks(MREQ(i), MRES(i));

  }

  return 0;
}


static u8 inject_split_tests(struct pivot_desc* pivot) {

  struct http_request* n;
  u32 orig_state = pivot->state;

  /* Header splitting - 2 requests */

  n = req_copy(pivot->req, pivot, 1);
  APPEND_VECTOR(orig_state, n, "bogus\nSkipfish-Inject:bogus");
  n->callback = inject_state_manager;
  n->user_val = 0;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  APPEND_VECTOR(orig_state, n, "bogus\rSkipfish-Inject:bogus");
  n->callback = inject_state_manager;
  n->user_val = 1;
  async_request(n);

  return 0;

}


static u8 inject_split_check(struct http_request* req,
                             struct http_response* res) {

  DEBUG_MISC_CALLBACK(req, res);

  /* Not differential. */

  if (res->state != STATE_OK) {
    handle_error(req, res, (u8*)"during header injection attacks", 0);
    return 0;
  }

  /* Check headers - that's all! */

  if (GET_HDR((u8*)"Skipfish-Inject", &MRES(0)->hdr))
    problem(PROB_HTTP_INJECT, MREQ(0), MRES(0), 
      (u8*)"successfully injected 'Skipfish-Inject' header into response",
      req->pivot, 0);

  if (GET_HDR((u8*)"Skipfish-Inject", &MRES(1)->hdr))
    problem(PROB_HTTP_INJECT, MREQ(1), MRES(1), 
      (u8*)"successfully injected 'Skipfish-Inject' header into response",
      req->pivot, 0);

  return 0;
}


static u8 inject_sql_tests(struct pivot_desc* pivot) {

  struct http_request* n;
  u32 orig_state = pivot->state;
  u8 is_num = 0;

  /* SQL injection - 10 requests */

  if (orig_state != PSTATE_CHILD_INJECT) {
    u8* pstr = TPAR(pivot->req);
    u32 c = strspn((char*)pstr, "01234567890.+-");
    if (pstr[0] && !pstr[c]) is_num = 1;
  }

  n = req_copy(pivot->req, pivot, 1);
  if (!is_num) SET_VECTOR(orig_state, n, "9-8");
  else APPEND_VECTOR(orig_state, n, "-0");
  n->callback = inject_state_manager;
  n->user_val = 0;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  if (!is_num) SET_VECTOR(orig_state, n, "8-7");
  else APPEND_VECTOR(orig_state, n, "-0-0");
  n->callback = inject_state_manager;
  n->user_val = 1;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  if (!is_num) SET_VECTOR(orig_state, n, "9-1");
  else APPEND_VECTOR(orig_state, n, "-0-9");
  n->callback = inject_state_manager;
  n->user_val = 2;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  APPEND_VECTOR(orig_state, n, "\\\'\\\"");
  set_value(PARAM_HEADER, (u8*)"User-Agent", (u8*)"sfish\\\'\\\"", 0, &n->par);
  set_value(PARAM_HEADER, (u8*)"Referer", (u8*)"sfish\\\'\\\"", 0, &n->par);
  set_value(PARAM_HEADER, (u8*)"Accept-Language", (u8*)"sfish\\\'\\\",en", 0,
            &n->par);
  n->callback = inject_state_manager;
  n->user_val = 3;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  APPEND_VECTOR(orig_state, n, "\'\"");
  set_value(PARAM_HEADER, (u8*)"User-Agent", (u8*)"sfish\'\"", 0, &n->par);
  set_value(PARAM_HEADER, (u8*)"Referer", (u8*)"sfish\'\"", 0, &n->par);
  set_value(PARAM_HEADER, (u8*)"Accept-Language", (u8*)"sfish\'\",en", 0,
            &n->par);
  n->callback = inject_state_manager;
  n->user_val = 4;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  APPEND_VECTOR(orig_state, n, "\\\\\'\\\\\"");
  set_value(PARAM_HEADER, (u8*)"User-Agent", (u8*)"sfish\\\\\'\\\\\"", 0, &n->par);
  set_value(PARAM_HEADER, (u8*)"Referer", (u8*)"sfish\\\\\'\\\\\"", 0, &n->par);
  set_value(PARAM_HEADER, (u8*)"Accept-Language", (u8*)"sfish\\\\\'\\\\\",en", 0,
            &n->par);
  n->callback = inject_state_manager;
  n->user_val = 5;
  async_request(n);

  /* This is a special case to trigger fault on blind numerical injection. */

  n = req_copy(pivot->req, pivot, 1);
  if (!is_num) SET_VECTOR(orig_state, n, "9 - 1");
  else APPEND_VECTOR(orig_state, n, " - 0 - 0");
  n->callback = inject_state_manager;
  n->user_val = 6;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  if (!is_num) SET_VECTOR(orig_state, n, "9 1 -");
  else APPEND_VECTOR(orig_state, n, " 0 0 - -");
  n->callback = inject_state_manager;
  n->user_val = 7;
  async_request(n);

  /* Another round of SQL injection checks for a different escaping style. */

  n = req_copy(pivot->req, pivot, 1);
  APPEND_VECTOR(orig_state, n, "''''\"\"\"\"");
  set_value(PARAM_HEADER, (u8*)"User-Agent", (u8*)"sfish''''\"\"\"\"", 0, 
            &n->par);
  set_value(PARAM_HEADER, (u8*)"Referer", (u8*)"sfish''''\"\"\"\"", 0, &n->par);
  set_value(PARAM_HEADER, (u8*)"Accept-Language", (u8*)"sfish''''\"\"\"\",en",
            0, &n->par);
  n->callback = inject_state_manager;
  n->user_val = 8;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  APPEND_VECTOR(orig_state, n, "'\"'\"'\"'\"");
  set_value(PARAM_HEADER, (u8*)"User-Agent", (u8*)"sfish'\"'\"'\"'\"", 0,
            &n->par);
  set_value(PARAM_HEADER, (u8*)"Referer", (u8*)"sfish'\"'\"'\"'\"", 0,
            &n->par);
  set_value(PARAM_HEADER, (u8*)"Accept-Language", 
            (u8*)"sfish'\"'\"'\"'\",en", 0, &n->par);
  n->callback = inject_state_manager;
  n->user_val = 9;
  async_request(n);

  /* Todo: cookies */

  return 0;
}


static u8 inject_sql_check(struct http_request* req,
                           struct http_response* res) {

  DEBUG_MISC_CALLBACK(req, res);

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
      !same_page(&MRES(1)->sig, &MRES(2)->sig)) {
    problem(PROB_SQL_INJECT, MREQ(0), MRES(0),
      (u8*)"response suggests arithmetic evaluation on server side (type 1)",
      req->pivot, 0);
  }

  if (same_page(&MRES(1)->sig, &MRES(6)->sig) &&
      !same_page(&MRES(6)->sig, &MRES(7)->sig)) {
    problem(PROB_SQL_INJECT, MREQ(7), MRES(7),
      (u8*)"response suggests arithmetic evaluation on server side (type 2)",
      req->pivot, 0);
  }

  if (same_page(&MRES(3)->sig, &MRES(4)->sig) &&
      !same_page(&MRES(4)->sig, &MRES(5)->sig)) {
    problem(PROB_SQL_INJECT, MREQ(4), MRES(4),
      (u8*)"response to '\" different than to \\'\\\"", req->pivot, 0);
  }

  if (same_page(&MRES(4)->sig, &MRES(9)->sig) &&
      !same_page(&MRES(8)->sig, &MRES(9)->sig)) {
    problem(PROB_SQL_INJECT, MREQ(4), MRES(4),
      (u8*)"response to ''''\"\"\"\" different than to '\"'\"'\"'\"", req->pivot, 0);
  }

  return 0;
}


static u8 inject_format_tests(struct pivot_desc* pivot) {

  struct http_request* n;
  u32 orig_state = pivot->state;

  /* Format string attacks - 2 requests. */

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, "sfish%dn%dn%dn%dn%dn%dn%dn%dn");
  n->callback = inject_state_manager;
  n->user_val = 0;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, "sfish%nd%nd%nd%nd%nd%nd%nd%nd");
  n->callback = inject_state_manager;
  n->user_val = 1;
  async_request(n);

  return 0;
}


static u8 inject_format_check(struct http_request* req,
                              struct http_response* res) {
  DEBUG_MISC_CALLBACK(req, res);

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

  return 0;
}

static u8 inject_integer_tests(struct pivot_desc* pivot) {

  struct http_request* n;
  u32 orig_state = pivot->state;

  /* Integer overflow bugs - 9 requests. */

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, "-0000012345");
  n->callback = inject_state_manager;
  n->user_val = 0;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, "-2147483649");
  n->callback = inject_state_manager;
  n->user_val = 1;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, "-2147483648");
  n->callback = inject_state_manager;
  n->user_val = 2;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, "0000012345");
  n->callback = inject_state_manager;
  n->user_val = 3;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, "2147483647");
  n->callback = inject_state_manager;
  n->user_val = 4;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, "2147483648");
  n->callback = inject_state_manager;
  n->user_val = 5;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, "4294967295");
  n->callback = inject_state_manager;
  n->user_val = 6;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, "4294967296");
  n->callback = inject_state_manager;
  n->user_val = 7;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  SET_VECTOR(orig_state, n, "0000023456");
  n->callback = inject_state_manager;
  n->user_val = 8;
  async_request(n);

  return 0;
}


static u8 inject_integer_check(struct http_request* req,
                               struct http_response* res) {

  DEBUG_MISC_CALLBACK(req, res);

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
    return 0;

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

  return 0;
}


static u8 param_behavior_tests(struct pivot_desc* pivot) {

  struct http_request* n;
  u32 i;

  if (pivot->fuzz_par < 0 || !url_allowed(pivot->req) || !param_allowed(pivot->name)) {
    pivot->state = PSTATE_DONE;
    if (delete_bin) maybe_delete_payload(pivot);
    return 0;
  }

  DEBUG_HELPER(pivot);


  /* Parameter behavior. */

  for (i=0;i<BH_CHECKS;i++) {
    n = req_copy(pivot->req, pivot, 1);
    ck_free(TPAR(n));
    TPAR(n) = ck_strdup((u8*)BOGUS_PARAM);
    n->callback = inject_state_manager;
    n->user_val = i;
    async_request(n);
  }
  return 0;
}


static u8 param_behavior_check(struct http_request* req,
                               struct http_response* res) {

  u32 i;
  u32 res_diff;
  u32 page_diff = 0;

  DEBUG_MISC_CALLBACK(req, res);

  for (i=0; i<req->pivot->misc_cnt; i++) {

    /* Store the biggest response time */
    res_diff = MREQ(i)->end_time - MREQ(i)->start_time;
    if(res_diff > req->pivot->res_time_base)
      req->pivot->res_time_base = res_diff;

    /* Compare the page responses */
    if (!page_diff && !same_page(&MRES(i)->sig, &RPRES(req)->sig))
      page_diff = i;
  }

  /* If the largest response time exceeded our threshold, we'll skip
     the timing related tests */

  if(req->pivot->res_time_base > MAX_RES_DURATION) {
    problem(PROB_VARIES, req, res, (u8*)"Responses too slow for time sensitive tests", req->pivot, 0);
    req->pivot->res_time_exceeds = 1;
  }


  if (page_diff == req->pivot->misc_cnt) {
    DEBUG("* Parameter seems to have no effect.\n");
    req->pivot->bogus_par = 1;
    return 0;
  }

  DEBUG("* Parameter seems to have some effect:\n");
  debug_same_page(&res->sig, &RPRES(req)->sig);

  if (req->pivot->bogus_par) {
    DEBUG("* We already classified it as having no effect, whoops.\n");
    req->pivot->res_varies = 1;
    problem(PROB_VARIES, req, res, 0, req->pivot, 0);
    return 0;
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
    }
    return 0;
  }
  req->pivot->state = PSTATE_PAR_CHECK;

  return 0;
}


static u8 param_ognl_tests(struct pivot_desc* pivot) {

  struct http_request* n;
  u32 ret = 1;
  u8* tmp;

  /* All probes failed? Assume bogus parameter, what else to do... */

  if (!pivot->r404_cnt)
    pivot->bogus_par = 1;

  /* If the parameter has an effect, schedule OGNL checks. */

  if (!pivot->bogus_par && !pivot->res_varies &&
       pivot->req->par.n[pivot->fuzz_par]) {

    n = req_copy(pivot->req, pivot, 1);
    tmp = ck_alloc(strlen((char*)n->par.n[pivot->fuzz_par]) + 8);
    sprintf((char*)tmp, "[0]['%s']", n->par.n[pivot->fuzz_par]);
    ck_free(n->par.n[pivot->fuzz_par]);
    n->par.n[pivot->fuzz_par] = tmp;
    n->callback = inject_state_manager;
    n->user_val = 0;
    async_request(n);

    n = req_copy(pivot->req, pivot, 1);
    ck_free(n->par.n[pivot->fuzz_par]);
    n->par.n[pivot->fuzz_par] = ck_strdup((u8*)"[0]['sfish']");
    n->callback = inject_state_manager;
    n->user_val = 1;
    async_request(n);

    ret = 0;
  }

  /* Injection attacks should be carried out even if we think this
     parameter has no visible effect; but injection checks will not proceed
     to dictionary fuzzing if bogus_par or res_varies is set. */

  pivot->state = PSTATE_PAR_INJECT;

  return ret;

}

static u8 param_ognl_check(struct http_request* req,
                           struct http_response* res) {

  DEBUG_MISC_CALLBACK(req, res);

  /* First response is meant to give the same result. Second
     is meant to give a different one. */

  if (same_page(&MREQ(0)->pivot->res->sig, &MRES(0)->sig) &&
      !same_page(&MREQ(1)->pivot->res->sig, &MRES(1)->sig)) {

    problem(PROB_OGNL, req, res,
      (u8*)"response to [0]['name']=... identical to name=...", 
      req->pivot, 0);
  }

  return 0;
}


static u8 dir_ips_tests(struct pivot_desc* pivot) {

  struct http_request* n;

  pivot->state = PSTATE_IPS_CHECK;

  n = req_copy(pivot->req, pivot, 1);
  tokenize_path((u8*)IPS_TEST, n, 0);
  n->callback = inject_state_manager;
  n->user_val = 0;
  async_request(n);

  n = req_copy(pivot->req, pivot, 1);
  tokenize_path((u8*)IPS_SAFE, n, 0);
  n->callback = inject_state_manager;
  n->user_val = 1;
  async_request(n);

  return 0;

}

static u8 dir_ips_check(struct http_request* req,
                        struct http_response* res) {
  struct pivot_desc* par;

  DEBUG_MISC_CALLBACK(req, res);

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

  destroy_misc_data(req->pivot, req);
  req->pivot->state = PSTATE_CHILD_INJECT;
  return 0;
}
