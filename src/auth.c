/*
   skipfish - form authentication
   ------------------------------

   Author: Niels Heinen <heinenn@google.com>

   Copyright 2012 by Google Inc. All Rights Reserved.

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

#include <string.h>

#define _VIA_AUTH_C

#include "debug.h"
#include "config.h"
#include "types.h"
#include "http_client.h"
#include "database.h"
#include "crawler.h"
#include "analysis.h"
#include "auth.h"

u8 *auth_form;                          /* Auth form location           */
u8 *auth_form_target;                   /* Auth form submit target      */
u8 *auth_user;                          /* User name                    */
u8 *auth_user_field;                    /* Username field id            */
u8 *auth_pass;                          /* Password                     */
u8 *auth_pass_field;                    /* Password input field id      */
u8 *auth_verify_url;                    /* Auth verify URL              */
u8 auth_state;                          /* Stores the auth state        */

void authenticate() {

  struct http_request* req;

  DEBUGC(L1, "*- Authentication starts\n");

  if (!auth_form || !auth_user || !auth_pass)
    return;

  struct pivot_desc *fake = ck_alloc(sizeof(struct pivot_desc));
  fake->type     = PIVOT_FILE;
  fake->state    = PSTATE_FETCH;

  /* When in session, do nothing */
  if (auth_state != ASTATE_NONE)
    return;

  auth_state = ASTATE_START;
  req = ck_alloc(sizeof(struct http_request));

  /* Create a request struct. Note that in this case, we don't care about
   * whether the URL is whitelisted or not */
  if (parse_url(auth_form, req, NULL))
    FATAL("Auth form URL could not be parsed\n");

  req->pivot = fake;
  req->callback = submit_auth_form;

  async_request(req);

}

/* Main function to submit the authentication, login form. This function
   will try find the right form and , unless form fields are specified on
   command-line, try to find the right fields in order to store the username
   and password. */

u8 submit_auth_form(struct http_request* req,
                    struct http_response* res) {

  u8* form;
  u8 *vurl = NULL;
  u8 is_post = 1;
  u8 par_type = PARAM_POST;
  u32 i = 0, k = 0;
  struct http_request* n = NULL;

  DEBUG_CALLBACK(req, res);

  /* Loop over the forms till we get our password form */

  do {

    form = inl_strcasestr(res->payload, (u8*)"<form");
    if (!form) break;

    if (auth_form_target)
      vurl = ck_strdup(auth_form_target);

    n = make_form_req(req, NULL, form, vurl);
    if (!n)
      FATAL("No auth form found\n");

    is_post = (n->method && !strcmp((char*)n->method, "POST"));
    par_type = is_post ? PARAM_POST : PARAM_QUERY;

    n->pivot = req->pivot;
    collect_form_data(n, req, res, form, is_post);

    /* If the form field was specified per command-line, we'll check if
       it's present. When it's not present: move on to next form.

       Now when no form field was specified via command-line: try
       to find one by using the strings from the "user_fields" array
       (defined in auth.h).
     */
    if (auth_user_field)
      if(!get_value(par_type, auth_user_field, 0, &n->par))
        continue;

    if (auth_pass_field)
      if(!get_value(par_type, auth_pass_field, 0, &n->par))
        continue;

    /* Try to find a user name-like field */
    for (i=0; i<n->par.c; i++) {
      if (!n->par.n[i] || n->par.t[i] != par_type) continue;

      /* Find and set the user field */
      for (k=0; !auth_user_field && user_fields[k]; k++) {
        if (inl_strcasestr(n->par.n[i], (u8*)user_fields[k])) {
          DEBUGC(L1, "*-- Authentication - using user field: %s\n", n->par.n[i]);
          if (n->par.v[i]) ck_free(n->par.v[i]);
          n->par.v[i] = ck_strdup(auth_user);
          auth_user_field = n->par.n[i];
          break;
        }
      }
      /* Find and set the password field */
      for (k=0; !auth_pass_field && pass_fields[k]; k++) {
        if (inl_strcasestr(n->par.n[i], (u8*)pass_fields[k])) {
          DEBUGC(L1, "*-- Authentication - using pass field: %s\n", n->par.n[i]);
          if (n->par.v[i]) ck_free(n->par.v[i]);
          n->par.v[i] = ck_strdup(auth_pass);
          auth_pass_field = n->par.n[i];
          break;
        }
      }
    }

    /* If one of both fields is not set, there is no point in submitting
       so we'll look for another form in the page */
    if (!auth_pass_field || !auth_user_field)
      continue;

    n->callback = auth_form_callback;
    DEBUGC(L1, "*-- Submitting authentication form\n");
#ifdef LOG_STDERR
    dump_http_request(n);
#endif
    async_request(n);
    auth_state = ASTATE_SEND;
    break;
  } while (form);

  if (auth_state != ASTATE_SEND)
    DEBUGC(L1, "*-- Could not login. Please check the URL and form fields\n");

  return 0;
}

/* After submitting the form and receiving a response, this is called */

u8 auth_form_callback(struct http_request* req,
                      struct http_response* res) {

  DEBUG_CALLBACK(req, res);
  DEBUGC(L1, "*-- Received form response\n");

  /* Parse the payload which will make sure cookies are stored. */
  content_checks(req, res);

  /* Compare an authenticated and anonymous request to the verification URL. The
   * response should be different in order to determine that we are indeed
   * authenticated */

  if (!auth_verify_url) {
    auth_state = ASTATE_DONE;
    return 0;
  }

  auth_state = ASTATE_VERIFY;
  auth_verify_tests(req->pivot);

  return 0;
}

/* Sends two requests to the verification URL. The first request is
   authenticated (or should be) while the second request is anonymous */

u8 auth_verify_tests(struct pivot_desc* pivot) {

  /* When we have no verification URL or the scan is no authenticated:
     return */

  DEBUG("In auth verify\n");

  if (!auth_verify_url || (auth_state != ASTATE_DONE &&
                           auth_state != ASTATE_VERIFY))
    return 1;

  u8* vurl = ck_strdup(auth_verify_url);
  struct http_request *n = ck_alloc(sizeof(struct http_request));

  n->pivot = pivot;
  if (parse_url(vurl, n, NULL))
    FATAL("Unable to parse verification URL: %s\n", vurl);

  /* One: authenticated request  */
  n->callback = auth_verify_checks;
  n->user_val = 0;
  async_request(n);

  /* Two: anonymous request */
  n = req_copy(n, pivot, 1);
  n->no_cookies = 1;
  n->user_val = 1;
  n->callback = auth_verify_checks;
  async_request(n);

  return 0;
}

/* Receives two requests to the verification URL. If there is a difference, than
   we'll trust that it's because one request was authenticated while the other
   wasn't */

u8 auth_verify_checks(struct http_request* req, struct http_response* res) {
  DEBUG_CALLBACK(req, res);

  if (FETCH_FAIL(res)) {
    handle_error(req, res, (u8*)"during auth verification tests", 0);
    return 0;
  }

  req->pivot->misc_req[req->user_val] = req;
  req->pivot->misc_res[req->user_val] = res;

  /* We need two responses */
  if ((++req->pivot->misc_cnt) != 2) return 1;

  /* Compare the two response. The authenticates response should be
     different to the anonymous request */

  if (same_page(&MRES(0)->sig, &MRES(1)->sig)) {
    DEBUGC(L1, "*- Unable to verify authentication using provided URL.\n");
    dump_signature(&MRES(0)->sig);
    dump_signature(&MRES(1)->sig);
    auth_state = ASTATE_FAIL;
  }


  destroy_misc_data(req->pivot, req);

  /* Re-authenticate upon failure */
  if (auth_state == ASTATE_FAIL) {
    authenticate();
    DEBUG("* Going to re-authenticate\n");
  } else {
    auth_state = ASTATE_DONE;
    DEBUGC(L1, "*- Authenticated\n");
  }

  return 0;
}
