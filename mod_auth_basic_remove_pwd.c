/* 
**  Apache 2.2/2.4 mod_auth_basic_remove_pwd -- Author: G.Grandes
**
**  To play with this module first compile it into a
**  DSO file and install it into Apache's modules directory 
**  by running:
**
**    $ apxs2 -c -i mod_auth_basic_remove_pwd.c
**
**  This module remove password sended in basic auth headers
**  "Proxy-Authorization" / "Authorization"
**
**  Usage and default values:
**
**  LoadModule auth_basic_remove_pwd_module mod_auth_basic_remove_pwd.so
**
**  <Location />
**      AuthBasicRemovePwdEnabled Off
**  </Location>
*/

#include "apr_strings.h"
#include "apr_lib.h"            /* for apr_isspace */
#define APR_WANT_STRFUNC        /* for strcasecmp */
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#define DEFAULT_ENABLED 0

#define MAP_DEFAULT(n, d) (n >= 0 ? n : d)

typedef struct {
    char *dir;
    int enabled;
} auth_basic_remove_pwd_config_rec;

static void *create_auth_basic_remove_pwd_dir_config(apr_pool_t *p, char *d)
{
    auth_basic_remove_pwd_config_rec *conf = apr_pcalloc(p, sizeof(*conf));

    conf->dir = d;
    conf->enabled = -1;

    return conf;
}

static void *merge_auth_basic_remove_pwd_dir_config(apr_pool_t *p,
                    void *parent_conf, void *newloc_conf)
{
    auth_basic_remove_pwd_config_rec *conf = apr_pcalloc(p, sizeof(*conf));
    auth_basic_remove_pwd_config_rec *pconf = parent_conf;
    auth_basic_remove_pwd_config_rec *nconf = newloc_conf;

    conf->dir = nconf->dir;
    conf->enabled = MAP_DEFAULT(nconf->enabled, pconf->enabled);

    return conf;
}

module AP_MODULE_DECLARE_DATA auth_basic_remove_pwd_module;

static int fixup_auth_basic_remove_pwd(request_rec *r)
{
    auth_basic_remove_pwd_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                                  &auth_basic_remove_pwd_module);
    if (!MAP_DEFAULT(conf->enabled, DEFAULT_ENABLED))
        return DECLINED;

    const char *auth_line;

    // Get the appropriate header
    auth_line = apr_table_get(r->headers_in, ((PROXYREQ_PROXY == r->proxyreq)
                                               ? "Proxy-Authorization"
                                               : "Authorization"));

    if (!auth_line) {
        return DECLINED;
    }

    // Only Basic Auth is supported
    if (strcasecmp(ap_getword(r->pool, &auth_line, ' '), "Basic")) {
        return DECLINED;
    }

    // Skip leading spaces
    while (apr_isspace(*auth_line)) {
        auth_line++;
    }

    char *decoded_line;

    decoded_line = ap_pbase64decode(r->pool, auth_line);

    const char **user;

    *user = ap_getword_nulls(r->pool, (const char**)&decoded_line, ':');

    auth_line = apr_pstrcat(r->pool, "Basic ",
                            ap_pbase64encode(r->pool,
                                             apr_pstrcat(r->pool, *user,
                                                         ":", "*", NULL)),
                            NULL);
    // Set the appropriate header
    apr_table_setn(r->headers_in, ((PROXYREQ_PROXY == r->proxyreq)
                                   ? "Proxy-Authorization"
                                   : "Authorization"), auth_line);

    return DECLINED;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_fixups(fixup_auth_basic_remove_pwd, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec auth_basic_remove_pwd_cmds[] =
{
    AP_INIT_FLAG("AuthBasicRemovePwdEnabled", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(auth_basic_remove_pwd_config_rec, enabled),
                 OR_AUTHCFG,
                 "Set to 'Off' to disable auth basic password removal"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA auth_basic_remove_pwd_module =
{
    STANDARD20_MODULE_STUFF,
    create_auth_basic_remove_pwd_dir_config,  /* dir config creater */
    merge_auth_basic_remove_pwd_dir_config,   /* dir merger */
    NULL,                                     /* server config */
    NULL,                                     /* merge server config */
    auth_basic_remove_pwd_cmds,               /* command apr_table_t */
    register_hooks                            /* register hooks */
};
