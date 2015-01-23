/* 
**  Apache 2.2/2.4 mod_auth_basic_check -- Author: G.Grandes
**
**  To play with this module first compile it into a
**  DSO file and install it into Apache's modules directory 
**  by running:
**
**    $ apxs2 -c -i mod_auth_basic_check.c
**
**  This module response with a 403 if auth basic password sended 
**  in "Proxy-Authorization" / "Authorization" header is weak.
**
**  Usage and default values:
**
**  LoadModule auth_basic_check_module mod_auth_basic_check.so
**
**  <Location />
**      AuthBasicCheckEnabled Off
**      AuthBasicCheckMaxLength 255
**      AuthBasicCheckMinLength 8
**      AuthBasicCheckMinUpper 1
**      AuthBasicCheckMinLower 1
**      AuthBasicCheckMinNumber 1
**      AuthBasicCheckMinSpecial 1
**      AuthBasicCheckSpecialChars "<[{(#$%&*?!:.,=+-_~^)}]>"
**  </Location>
*/

#include "apr_strings.h"
#include "apr_md5.h"            /* for apr_password_validate */
#include "apr_lib.h"            /* for apr_isspace */
#include "apr_base64.h"         /* for apr_base64_decode et al */
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
#define DEFAULT_MAX_LENGTH 255
#define DEFAULT_MIN_LENGTH 8
#define DEFAULT_MIN_UPPER 1
#define DEFAULT_MIN_LOWER 1
#define DEFAULT_MIN_NUMBER 1
#define DEFAULT_MIN_SPECIAL 1

#define MAP_DEFAULT(n, d) (n >= 0 ? n : d)
#define MAP_DEFAULT_STR(n, d) (n != NULL ? n : d)
#define MAP_DEFAULT_STR_LEN(n, v, d) (n != NULL ? v : d)

typedef struct {
    char *dir;
    int enabled;
    int maxLength;
    int minLength;
    int minUpper;
    int minLower;
    int minNumber;
    int minSpecial;
    const char *special_chars;
    int special_chars_len;
} auth_basic_check_config_rec;

// US-ASCII printable special chars
static const char DEFAULT_SPECIAL_CHARS[] = "<[{(#$%&*?!:.,=+-_~^)}]>";
#define DEFAULT_SPECIAL_CHARS_LEN sizeof(DEFAULT_SPECIAL_CHARS)

static const char *set_special_chars(cmd_parms *cmd,
                               void *pconf,
                               const char *arg)
{
    auth_basic_check_config_rec *conf = pconf;
    conf->special_chars = arg;
    conf->special_chars_len = strlen(arg);
    return NULL;
}

static void *create_auth_basic_check_dir_config(apr_pool_t *p, char *d)
{
    auth_basic_check_config_rec *conf = apr_pcalloc(p, sizeof(*conf));

    conf->dir = d;
    conf->enabled = -1;
    conf->maxLength = -1;
    conf->minLength = -1;
    conf->minUpper = -1;
    conf->minLower = -1;
    conf->minNumber = -1;
    conf->minSpecial = -1;
    conf->special_chars = NULL;
    conf->special_chars_len = 0;

    return conf;
}

static void *merge_auth_basic_check_dir_config(apr_pool_t *p,
                    void *parent_conf, void *newloc_conf)
{
    auth_basic_check_config_rec *conf = apr_pcalloc(p, sizeof(*conf));
    auth_basic_check_config_rec *pconf = parent_conf;
    auth_basic_check_config_rec *nconf = newloc_conf;

    conf->dir = nconf->dir;
    conf->enabled = MAP_DEFAULT(nconf->enabled, pconf->enabled);
    conf->maxLength = MAP_DEFAULT(nconf->maxLength, pconf->maxLength);
    conf->minLength = MAP_DEFAULT(nconf->minLength, pconf->minLength);
    conf->minUpper = MAP_DEFAULT(nconf->minUpper, pconf->minUpper);
    conf->minLower = MAP_DEFAULT(nconf->minLower, pconf->minLower);
    conf->minNumber = MAP_DEFAULT(nconf->minNumber, pconf->minNumber);
    conf->minSpecial = MAP_DEFAULT(nconf->minSpecial, pconf->minSpecial);
    conf->special_chars = MAP_DEFAULT_STR(nconf->special_chars, pconf->special_chars);
    conf->special_chars_len = MAP_DEFAULT_STR_LEN(nconf->special_chars, 
                                                  strlen(nconf->special_chars), 0);

    return conf;
}

module AP_MODULE_DECLARE_DATA auth_basic_check_module;

static int get_basic_auth(request_rec *r, const char **user, const char **pw)
{
    const char *auth_line;
    char *decoded_line;
    int length;

    /* Get the appropriate header */
    auth_line = apr_table_get(r->headers_in, (PROXYREQ_PROXY == r->proxyreq)
                                              ? "Proxy-Authorization"
                                              : "Authorization");

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

    decoded_line = apr_palloc(r->pool, apr_base64_decode_len(auth_line) + 1);
    length = apr_base64_decode(decoded_line, auth_line);
    // Null-terminate the string
    decoded_line[length] = '\0';

    *user = ap_getword_nulls(r->pool, (const char**)&decoded_line, ':');
    *pw = decoded_line;

    return OK;
}

static int isspecial(const char c, const char *special_chars, int len)
{
    int i = 0;
    while (i < len) {
        if (c == special_chars[i++])
            return 1;
    }
    return 0;
}

static int check_strong(request_rec *r, auth_basic_check_config_rec *conf,
                        const char *user, const char *pw)
{
    int maxLength = MAP_DEFAULT(conf->maxLength, DEFAULT_MAX_LENGTH);
    int minLength = MAP_DEFAULT(conf->minLength, DEFAULT_MIN_LENGTH);
    int minUpper = MAP_DEFAULT(conf->minUpper, DEFAULT_MIN_UPPER);
    int minLower = MAP_DEFAULT(conf->minLower, DEFAULT_MIN_LOWER);
    int minNumber = MAP_DEFAULT(conf->minNumber, DEFAULT_MIN_NUMBER);
    int minSpecial = MAP_DEFAULT(conf->minSpecial, DEFAULT_MIN_SPECIAL);
    const char *specialChars = MAP_DEFAULT_STR(conf->special_chars, 
                                               DEFAULT_SPECIAL_CHARS);
    int specialCharsLen = MAP_DEFAULT_STR_LEN(conf->special_chars, 
                                              conf->special_chars_len, 
                                              DEFAULT_SPECIAL_CHARS_LEN);
    int countUpper = 0; // Uppers
    int countLower = 0; // Lowers
    int countNum = 0; // Numbers
    int countSpe = 0; // Specials
    int countInv = 0; // Invalids
    int isok = 0;
    //
    int len = 0;
    char c;
    while ((c = pw[len]) != 0) {
        if ((c >= 'A') && (c <= 'Z')) {
            countUpper++;
        } else if ((c >= 'a') && (c <= 'z')) {
            countLower++;
        } else if ((c >= '0') && (c <= '9')) {
            countNum++;
        } else if (isspecial(c, specialChars, specialCharsLen)) {
            countSpe++;
        } else {
            countInv++;
        }
        len++;
    }

    if ((len >= minLength) && (len <= maxLength) &&
        (countUpper >= minUpper) && (countLower >= minLower) &&
        (countNum >= minNumber) &&
        (countSpe >= minSpecial) && (countInv == 0)) {
        isok = 1;
    }

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "checking: user=%s password len=%d/%d/%d " 
            "upper=%d/%d lower=%d/%d number=%d/%d "
            "special=%d/%d invalids=%d isok=%s",
            user,
            len, minLength, maxLength,
            countUpper, minUpper,
            countLower, minLower,
            countNum, minNumber,
            countSpe, minSpecial,
            countInv, isok ? "YES" : "NO");

    return isok;
}

/* Determine user ID, and check if password is good, for HTTP
 * basic authentication...
 */
static int authenticate_basic_user(request_rec *r)
{
    auth_basic_check_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                       &auth_basic_check_module);
    const char *sent_user, *sent_pw;
    int res;

    if (!MAP_DEFAULT(conf->enabled, DEFAULT_ENABLED))
        return DECLINED;

    res = get_basic_auth(r, &sent_user, &sent_pw);
    if (res) {
        return res;
    }

    res = check_strong(r, conf, sent_user, sent_pw);
    return (res ? DECLINED : HTTP_FORBIDDEN);
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_header_parser(authenticate_basic_user,NULL,NULL,APR_HOOK_MIDDLE);
}

static const command_rec auth_basic_check_cmds[] =
{
    AP_INIT_FLAG("AuthBasicCheckEnabled", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(auth_basic_check_config_rec, enabled),
                 OR_AUTHCFG,
                 "Set to 'Off' to disable password strength checks"),
    AP_INIT_TAKE1("AuthBasicCheckMaxLength", ap_set_int_slot,
                  (void*)APR_OFFSETOF(auth_basic_check_config_rec, maxLength),
                 OR_AUTHCFG,
                 "Maximum length of password"),
    AP_INIT_TAKE1("AuthBasicCheckMinLength", ap_set_int_slot,
                  (void*)APR_OFFSETOF(auth_basic_check_config_rec, minLength),
                 OR_AUTHCFG,
                 "Minimum length of password"),
    AP_INIT_TAKE1("AuthBasicCheckMinUpper", ap_set_int_slot,
                  (void*)APR_OFFSETOF(auth_basic_check_config_rec, minUpper),
                 OR_AUTHCFG,
                 "Minimum occurrences of upper letters"),
    AP_INIT_TAKE1("AuthBasicCheckMinLower", ap_set_int_slot,
                  (void*)APR_OFFSETOF(auth_basic_check_config_rec, minLower),
                 OR_AUTHCFG,
                 "Minimum occurrences of lower letters"),
    AP_INIT_TAKE1("AuthBasicCheckMinNumber", ap_set_int_slot,
                  (void*)APR_OFFSETOF(auth_basic_check_config_rec, minNumber),
                 OR_AUTHCFG,
                 "Minimum occurrences of numbers"),
    AP_INIT_TAKE1("AuthBasicCheckMinSpecial", ap_set_int_slot,
                  (void*)APR_OFFSETOF(auth_basic_check_config_rec, minSpecial),
                 OR_AUTHCFG,
                 "Minimum occurrences of special characters"),
    AP_INIT_TAKE1("AuthBasicCheckSpecialChars", set_special_chars,
                  (void*)APR_OFFSETOF(auth_basic_check_config_rec, special_chars),
                 OR_AUTHCFG,
                 "String with the allowed special characters"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA auth_basic_check_module =
{
    STANDARD20_MODULE_STUFF,
    create_auth_basic_check_dir_config,  /* dir config creater */
    merge_auth_basic_check_dir_config,   /* dir merger */
    NULL,                                /* server config */
    NULL,                                /* merge server config */
    auth_basic_check_cmds,               /* command apr_table_t */
    register_hooks                       /* register hooks */
};
