/* 
**  mod_random_header.c -- Apache mod_random_header module
**
**  To play with this module first compile it into a
**  DSO file and install it into Apache's modules directory 
**  by running:
**
**    $ apxs2 -c -i mod_random_header.c
**
*/ 

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "apr_strings.h"
#include "ap_config.h"
#include <apr_general.h>
#include <apr_base64.h>


static int hdr_handler(request_rec *r)
{
    unsigned char rlen;
    unsigned int len;
    unsigned char brand[0x100];
    char b64rand[sizeof(brand)*2];

    /* variable length 16-255 */
    apr_generate_random_bytes(&rlen, 1);
    len = rlen;
    if (len < 16) {
        len += 16;
    }
    /* generate random data */
    apr_generate_random_bytes(brand, len);

    /* encode in base64 */
    len = apr_base64_encode_binary(b64rand, brand, len);
    /* remove base64 padding */
    len = len - 4 + strlen(b64rand + len - 4);
    while ((len > 2) && (b64rand[--len] == 0x3d)) {
        b64rand[len] = 0;
    }

    /* set header in response */
    const char *hrand = apr_pstrdup(r->pool, b64rand); 
    apr_table_setn(r->err_headers_out, "X-Random", hrand);

    return DECLINED;
}

static void hdr_register_hooks(apr_pool_t *p)
{
    ap_hook_post_read_request(hdr_handler, NULL, NULL, APR_HOOK_REALLY_FIRST);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA random_header_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    NULL,                  /* table of config file commands       */
    hdr_register_hooks     /* register hooks                      */
};
