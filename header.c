/*
  +----------------------------------------------------------------------+
  | Suhosin Version 1                                                    |
  +----------------------------------------------------------------------+
  | Copyright (c) 2006 The Hardened-PHP Project                          |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Stefan Esser <sesser@hardened-php.net>                       |
  +----------------------------------------------------------------------+
*/
/*
  $Id: header.c,v 1.6 2006-08-26 19:56:20 sesser Exp $ 
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "ext/standard/url.h"
#include "php_suhosin.h"
#include "SAPI.h"
#include "php_variables.h"

static int (*orig_header_handler)(sapi_header_struct *sapi_header, sapi_headers_struct *sapi_headers TSRMLS_DC) = NULL;

/* {{{ suhosin_cookie_decryptor
 */
char *suhosin_cookie_decryptor(TSRMLS_D)
{
	char *raw_cookie = SG(request_info).cookie_data;
	char *decrypted, *var, *val, *tmp, *d;
	int j, l;
	char cryptkey[33];

	/*
	if (...deactivated...) {
		return estrdup(raw_cookie);
	}
	*/

	suhosin_generate_key(SUHOSIN_G(cookie_cryptkey), SUHOSIN_G(cookie_cryptua), SUHOSIN_G(cookie_cryptdocroot), SUHOSIN_G(cookie_cryptraddr), (char *)&cryptkey TSRMLS_CC);

	decrypted = emalloc(strlen(raw_cookie)*3+1);
	
	j = 0; tmp = raw_cookie;
	while (*tmp) {
		int vlen; char old;char *d_url;int varlen;
		while (*tmp == '\t' || *tmp == ' ') tmp++;
		var = tmp;
		while (*tmp && *tmp != ';' && *tmp != '=') tmp++;
		
		varlen = tmp-var;
		memcpy(decrypted + j, var, varlen);
		
		j += varlen;
		if (*tmp == 0) break;
		
		if (*tmp++ == ';') {
			decrypted[j++] = ';';
			continue;
		}
		
		decrypted[j++] = '=';
		
		val = tmp;
		while (*tmp && *tmp != ';') tmp++;

		old = *tmp;
		vlen = php_url_decode(val, tmp-val);
		*tmp = old;

		d = suhosin_decrypt_string(val, vlen, var, varlen, (char *)&cryptkey, &l TSRMLS_CC);
		d_url = php_url_encode(d, l, &l);
		efree(d);
		
		memcpy(decrypted + j, d_url, l);
		j += l;
		if (old == ';') {
			decrypted[j++] = ';';
		}
		
		efree(d_url);

		if (*tmp == 0) break;
		tmp++;
	}
	decrypted[j] = 0;
	decrypted = erealloc(decrypted, j+1);
	
	SUHOSIN_G(decrypted_cookie) = decrypted;
		
	return decrypted;
}
/* }}} */

/* {{{ suhosin_header_handler
 */
int suhosin_header_handler(sapi_header_struct *sapi_header, sapi_headers_struct *sapi_headers TSRMLS_DC)
{
        int retval = SAPI_HEADER_ADD, i;
        char *tmp;
        
        if (!SUHOSIN_G(allow_multiheader) && sapi_header && sapi_header->header) {
                
                tmp = sapi_header->header;
                for (i=0; i<sapi_header->header_len; i++, tmp++) {
                        if (tmp[0] == 0) {
                                char *fname = get_active_function_name(TSRMLS_C);
                                
                                if (!fname) {
                                        fname = "unknown";
                                }
                                
                                suhosin_log(S_MISC, "%s() - wanted to send a HTTP header with an ASCII NUL in it", fname);
				if (!SUHOSIN_G(simulation)) {
                            		sapi_header->header_len = i;
				}
                        } else if (tmp[0] == '\n' && (i == sapi_header->header_len-1 || (tmp[1] != ' ' && tmp[1] != '\t'))) {
                                char *fname = get_active_function_name(TSRMLS_C);
                                
                                if (!fname) {
                                        fname = "unknown";
                                }
                                
                                suhosin_log(S_MISC, "%s() - wanted to send multiple HTTP headers at once", fname);
				if (!SUHOSIN_G(simulation)) {
                            		sapi_header->header_len = i;
                            		tmp[0] = 0;
				}
                        }
                }
        }

		/* Handle a potential cookie */
	
	if (SUHOSIN_G(cookie_encrypt) && (strncasecmp("Set-Cookie:", sapi_header->header, sizeof("Set-Cookie:")-1) == 0)) {
                
		char *start, *end, *rend, *tmp;
    		char *name, *value;
    		int nlen, vlen, len, tlen;
		char cryptkey[33];
				
		suhosin_generate_key(SUHOSIN_G(cookie_cryptkey), SUHOSIN_G(cookie_cryptua), SUHOSIN_G(cookie_cryptdocroot), SUHOSIN_G(cookie_cryptraddr), (char *)&cryptkey TSRMLS_CC);
				
		
                start = estrndup(sapi_header->header, sapi_header->header_len);
                rend = end = start + sapi_header->header_len;
                
                tmp = memchr(start, ';', end-start);
                if (tmp != NULL) {
                        end = tmp;
                }
                
                tmp = start + sizeof("Set-Cookie:") - 1;
                while (tmp < end && tmp[0]==' ') {
                        tmp++;
                }
                name = tmp;
                nlen = end-name;
                tmp = memchr(name, '=', nlen);
                if (tmp == NULL) {
                        value = end;
                } else {
                        value = tmp+1;
                        nlen = tmp-name;
                }
                vlen = end-value;
                
                /* decode the name & value */
                nlen = php_url_decode(name, nlen);
                vlen = php_url_decode(value, vlen);
		
		if (end != rend) {
			*end = ';';
		}
                
                value = suhosin_encrypt_string(value, vlen, name, nlen, (char *)&cryptkey TSRMLS_CC); vlen = strlen(value);
                
                name = php_url_encode(name, nlen, &nlen);
                value = php_url_encode(value, vlen, &vlen);
                
                len = sizeof("Set-Cookie: ")-1 + nlen + 1 + vlen + rend-end;
                tmp = emalloc(len + 1);
                tlen = sprintf(tmp, "Set-Cookie: %s=%s", name, value);
                memcpy(tmp + tlen, end, rend-end);
                tmp[len] = 0;

                efree(sapi_header->header);
                efree(name);
                efree(value);
                efree(start);
                
                sapi_header->header = tmp;
                sapi_header->header_len = len;
        }


	/* If existing call the sapi header handler */
        if (orig_header_handler) {
                retval = orig_header_handler(sapi_header, sapi_headers TSRMLS_CC);
        }
        
        return retval;
}
/* }}} */


/* {{{ suhosin_hook_header_handler
 */
void suhosin_hook_header_handler()
{
	if (orig_header_handler == NULL) {
		orig_header_handler = sapi_module.header_handler;
		sapi_module.header_handler = suhosin_header_handler;
	}
}
/* }}} */

/* {{{ suhosin_unhook_header_handler
 */
void suhosin_unhook_header_handler()
{
	sapi_module.header_handler = orig_header_handler;
	orig_header_handler = NULL;
}
/* }}} */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */


