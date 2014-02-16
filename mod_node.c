/* 
**  mod_node.c -- Apache mod_node module
**
**  To play with this module first compile it into a
**  DSO file and install it into Apache's modules directory 
**  by running:
**
**    $ apxs2 -c -i mod_node.c
**
**  This module add header "Node: X" (where X is the hostname)
*/ 

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "apr_strings.h"
#include "ap_config.h"

#include <sys/utsname.h>

static const char *name = NULL;

static int node_handler(request_rec *r)
{
    if (name == NULL) {
        return DECLINED;
    }
    apr_table_setn(r->headers_in, "Node", name);
    apr_table_setn(r->err_headers_out, "Node", name);
                   
    return DECLINED;
}

// Set up startup-time initialization
static int post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    struct utsname buf;
    uname(&buf);
    name = apr_pstrdup(pconf, buf.nodename);
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "node=%s", buf.nodename);
    return OK;
}

static void node_register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(node_handler, NULL, NULL, APR_HOOK_REALLY_FIRST);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA node_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    NULL,                  /* table of config file commands       */
    node_register_hooks    /* register hooks                      */
};
