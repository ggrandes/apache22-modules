/* 
**  mod_header_remote_addr.c -- Apache mod_header_remote_addr module
**
**  To play with this module first compile it into a
**  DSO file and install it into Apache's modules directory 
**  by running:
**
**    $ apxs2 -c -i mod_header_remote_addr.c
**
**  This module add header "Client-IP: X" (where X is the remote client ip)
*/ 

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "apr_strings.h"
#include "ap_config.h"

// Apache 2.4 or 2.2
#if AP_SERVER_MINORVERSION_NUMBER > 3
#define _USERAGENT_IP   r->useragent_ip
#else
#define _USERAGENT_IP   c->remote_ip
#endif

static int post_read_handler(request_rec *r)
{
    conn_rec *c = r->connection;
    // Response header with visible IP
    apr_table_set(r->err_headers_out, "Client-IP", _USERAGENT_IP);

    return DECLINED;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_read_request(post_read_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA header_remote_addr_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    NULL,                  /* table of config file commands       */
    register_hooks         /* register hooks                      */
};
