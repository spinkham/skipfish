#ifndef _HAVE_CHECKS_H
#include "types.h"
#include "http_client.h"
#include "database.h"

/* The init crawler structure which loads the test/check combos */

void init_injection_checks(void);

/* The crawler structure helper functions */

void display_injection_checks(void);
void release_injection_checks(void);
void toggle_injection_checks(u8* str, u32 enable, u8 user);

extern u8 no_checks;

/* The inject state manager callback function is used in crawler.c to
   direct the flow to the state manager where all the injection tests are
   performed. */

u8 inject_state_manager(struct http_request* req, struct http_response* res);

/* Check identifiers which can be used by other parts of code to
   see what the current *check* is. One specific location where this is
   used is the signature matching code, */

#define CHK_GENERIC 0
#define CHK_XML 1
#define CHK_XSS 2
#define CHK_SHELL_DIFF 3
#define CHK_SHELL_SPEC 4
#define CHK_SESSION 5
#define CHK_DIR_LIST 6
#define CHK_PUT 7
#define CHK_FI 8
#define CHK_RFI 9
#define CHK_XSSI 10
#define CHK_PROLOG 11
#define CHK_REDIR 12
#define CHK_SQL 13
#define CHK_FORMAT 14
#define CHK_INTEGER 15
#define CHK_OGNL 16
#define CHK_BEHAVE 17
#define CHK_IPS 18
#define CHK_RSPLIT 19

#ifdef _VIA_CHECKS_C

/* Time attack knobs */

#define MAX_RES_DURATION 3
#define SLEEP_TEST_ONE   3
#define SLEEP_TEST_TWO   5

/* Helper for calculating the request time */

#define RTIME(_r) (MREQ(_r)->end_time - MREQ(_r)->start_time)

/* The test/check struct with pointers to callback functions */

struct cb_handle {
  u32  res_num;              /* Amount of expected responses          */
  u32  res_keep;             /* Bool for keeping req/res              */
  u8   allow_varies;         /* Bool to accept pivots with res_varies */
  u8   time_sensitive;       /* Bool for time sensitive tests         */
  u8   scrape;               /* Scrape links, or not..                */
  u32  pv_flag;              /* Flag to match pivot type              */
  u32  id;                   /* Flag to match pivot type              */
  u8*  name;                 /* Name or title of the check            */

  u8 (*tests)(struct pivot_desc* pivot);
  u8 (*checks)(struct http_request*, struct http_response*);

  u32  skip;                 /* Bool to disable the check             */
};

/* Strings for traversal and file disclosure tests. The order should
   not be changed  */

static const char* disclosure_tests[] = {
  "../../../../../../../../etc/hosts",
  "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fhosts%00.js",
  "../../../../../../../../etc/passwd",
  "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00.js",
  "..\\..\\..\\..\\..\\..\\..\\..\\boot.ini",
  "..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cboot.ini%00.js",
  "../../../../../../../../WEB-INF/web.xml",
  "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fWEB-INF%2fweb.xml%3f.js",
  "file:///etc/hosts",
  "file:///etc/passwd",
  "file:///boot.ini",
  0
};

#endif /* _VIA_CHECKS_C */
#endif /* _HAVE_CHECKS_H */
