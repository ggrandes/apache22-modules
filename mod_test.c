/* 
**  Apache 2.2/2.4 mod_test -- Author: G.Grandes
**
**  To play with this module first compile it into a
**  DSO file and install it into Apache's modules directory 
**  by running:
**
**    $ apxs2 -c -i mod_test.c
**
**  This module always response with a text/plain "OK\n"
**
**  Usage:
**
**  LoadModule test_module /usr/lib/apache2/modules/mod_test.so
**
**  <LocationMatch ^/test$>
**    # Require all granted
**    order deny,allow
**    allow from all
**    SetEnv dontlog
**    SetHandler test
**  </LocationMatch>
*/ 

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"

static int test_handler(request_rec *r)
{
    if (strcmp(r->handler, "test")) {
        return DECLINED;
    }
                   
    r->content_type = "text/plain";
    if (!r->header_only)
        ap_rputs("OK\n", r);

    return OK;
}

static void test_register_hooks(apr_pool_t *p)
{
    ap_hook_handler(test_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA test_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    NULL,                  /* table of config file commands       */
    test_register_hooks    /* register hooks                      */
};
