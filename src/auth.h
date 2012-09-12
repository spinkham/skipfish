/*
   skipfish - form authentication matching
   ----------------------------------------

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

#ifndef _HAVE_AUTH_H

void authenticate();

u8 submit_auth_form(struct http_request* req,
                    struct http_response* res);

u8 auth_form_callback(struct http_request* req,
                      struct http_response* res);

u8 auth_verify_tests(struct pivot_desc* pivot);
u8 auth_verify_checks(struct http_request* req, struct http_response* res);

extern u8 *auth_form,           /* Auth form location           */
          *auth_form_target,    /* Auth form submit target      */
          *auth_user,           /* User name                    */
          *auth_pass,           /* Password                     */
          *auth_user_field,     /* Username field id            */
          *auth_pass_field,     /* Password input field id      */
          *auth_verify_url;     /* Auth verify URL              */

extern u8 auth_state;

#define ASTATE_NONE   0
#define ASTATE_START  1
#define ASTATE_SEND   2
#define ASTATE_VERIFY 3
#define ASTATE_DONE   4
#define ASTATE_FAIL   5

#ifdef _VIA_AUTH_C

/* These strings are used to find the username field */

static const char* user_fields[] = {
  "user",
  "name",
  "email",
  0
};

/* These strings are used to find the password field */

static const char* pass_fields[] = {
  "pass",
  "secret",
  "pin",
  0
};

#endif /* !_VIA_AUTH_C  */
#endif /* !_HAVE_AUTH_H */
