#ifndef _HAVE_CHECKS_H
#include "types.h"
#include "http_client.h"
#include "database.h"

/* The init crawler structure which loads the test/check combos */

void init_injection_checks(void); 

/* The crawler structure helper functions */

void display_injection_checks(void);
void release_injection_checks(void);
void toggle_injection_checks(u8* str, u32 enable);

extern u8 no_checks;

/* The inject state manager callback function is used in crawler.c to
   direct the flow to the state manager where all the injection tests are
   performed. */

u8 inject_state_manager(struct http_request* req, struct http_response* res);

#ifdef _VIA_CHECKS_C

/* The test/check struct with pointers to callback functions */

struct cb_handle {
  u32  res_num;              /* Amount of expected responses          */
  u32  res_keep;             /* Bool for keeping req/res              */
  u8   allow_varies;         /* Bool to accept pivots with res_varies */
  u8   scrape;               /* Scrape links, or not..                */
  u32  pv_flag;              /* Flag to match pivot type              */
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
