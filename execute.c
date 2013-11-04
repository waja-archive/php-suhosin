/*
  +----------------------------------------------------------------------+
  | Suhosin Version 1                                                    |
  +----------------------------------------------------------------------+
  | Copyright (c) 2006-2007 The Hardened-PHP Project                     |
  | Copyright (c) 2007-2012 SektionEins GmbH                             |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Stefan Esser <sesser@sektioneins.de>                         |
  +----------------------------------------------------------------------+
*/

/* $Id: execute.c,v 1.1.1.1 2007-11-28 01:15:35 sesser Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <fcntl.h>
#include "php.h"
#include "php_ini.h"
#include "zend_hash.h"
#include "zend_extensions.h"
#include "ext/standard/info.h"
#include "ext/standard/php_rand.h"
#include "ext/standard/php_lcg.h"
#include "php_suhosin.h"
#include "zend_compile.h"
#include "zend_llist.h"
#include "SAPI.h"

#include "sha256.h"


static void (*old_execute)(zend_op_array *op_array TSRMLS_DC);
static void suhosin_execute(zend_op_array *op_array TSRMLS_DC);
static void (*old_execute_ZO)(zend_op_array *op_array, long dummy TSRMLS_DC);
static void suhosin_execute_ZO(zend_op_array *op_array, long dummy TSRMLS_DC);
static void *(*zo_set_oe_ex)(void *ptr) = NULL;

/*STATIC zend_op_array* (*old_compile_file)(zend_file_handle* file_handle, int type TSRMLS_DC);
  STATIC zend_op_array* suhosin_compile_file(zend_file_handle*, int TSRMLS_DC);*/

static void suhosin_execute_internal(zend_execute_data *execute_data_ptr, int return_value_used TSRMLS_DC);
static void (*old_execute_internal)(zend_execute_data *execute_data_ptr, int return_value_used TSRMLS_DC);

extern zend_extension suhosin_zend_extension_entry;

/* {{{ suhosin_strcasestr */
static char *suhosin_strcasestr(char *haystack, char *needle)
{
	unsigned char *t, *h, *n;
	h = (unsigned char *) haystack;
conts:
	while (*h) {
		n = (unsigned char *) needle;
		if (toupper(*h++) == toupper(*n++)) {
			for (t=h; *n; t++, n++) {
				if (toupper(*t) != toupper(*n)) goto conts;
			}
    		return ((char*)h-1);
		}
	}

	return (NULL);
}
/* }}} */


#define SUHOSIN_CODE_TYPE_UNKNOWN	0
#define SUHOSIN_CODE_TYPE_COMMANDLINE	1
#define SUHOSIN_CODE_TYPE_EVAL		2
#define SUHOSIN_CODE_TYPE_REGEXP	3
#define SUHOSIN_CODE_TYPE_ASSERT	4
#define SUHOSIN_CODE_TYPE_CFUNC		5
#define SUHOSIN_CODE_TYPE_SUHOSIN	6
#define SUHOSIN_CODE_TYPE_UPLOADED	7
#define SUHOSIN_CODE_TYPE_0FILE		8
#define SUHOSIN_CODE_TYPE_BLACKURL	9
#define SUHOSIN_CODE_TYPE_BADURL	10
#define SUHOSIN_CODE_TYPE_GOODFILE	11
#define SUHOSIN_CODE_TYPE_BADFILE	12
#define SUHOSIN_CODE_TYPE_LONGNAME	13
#define SUHOSIN_CODE_TYPE_MANYDOTS	14
#define SUHOSIN_CODE_TYPE_WRITABLE      15

static int suhosin_check_filename(char *s, int len TSRMLS_DC)
{
	char fname[MAXPATHLEN+1];
	char *t, *h, *h2, *index, *e;
	int tlen, i, count=0;
	uint indexlen;
	ulong numindex;
	zend_bool isOk;

	/* check if filename is too long */
	if (len > MAXPATHLEN) {
		return SUHOSIN_CODE_TYPE_LONGNAME;
	}
	memcpy(fname, s, len);
	fname[len] = 0; 
	s = (char *)&fname;
	e = s + len;

	/* check if ASCIIZ attack -> not working yet (and cannot work in PHP4 + ZO) */
	if (len != strlen(s)) {
		return SUHOSIN_CODE_TYPE_0FILE;
	}
	
	/* disallow uploaded files */
	if (SG(rfc1867_uploaded_files)) {
		if (zend_hash_exists(SG(rfc1867_uploaded_files), (char *) s, e-s+1)) {
			return SUHOSIN_CODE_TYPE_UPLOADED;
		}
	}
		
	/* count number of directory traversals */
	for (i=0; i < len-3; i++) {
		if (s[i] == '.' && s[i+1] == '.' && (s[i+2] == '/' || s[i+2] == '\\')) {
			count++;
			i+=2;
		}
	}
	if (SUHOSIN_G(executor_include_max_traversal) && SUHOSIN_G(executor_include_max_traversal)<=count) {
		return SUHOSIN_CODE_TYPE_MANYDOTS;
	}
	
SDEBUG("xxx %08x %08x",SUHOSIN_G(include_whitelist),SUHOSIN_G(include_blacklist));
	/* no black or whitelist then disallow all */
	if (SUHOSIN_G(include_whitelist)==NULL && SUHOSIN_G(include_blacklist)==NULL) {
		/* disallow all URLs */
		if (strstr(s, "://") != NULL || suhosin_strcasestr(s, "data:") != NULL) {
			return SUHOSIN_CODE_TYPE_BADURL;
		}
	} else 
	/* whitelist is stronger than blacklist */
	if (SUHOSIN_G(include_whitelist)) {
		
		do {
			isOk = 0;
			
			h = strstr(s, "://");
			h2 = suhosin_strcasestr(s, "data:");
			h2 = h2 == NULL ? NULL : h2 + 4;
			t = h = (h == NULL) ? h2 : ( (h2 == NULL) ? h : ( (h < h2) ? h : h2 ) );
			if (h == NULL) break;
							
			while (t > s && (isalnum(t[-1]) || t[-1]=='_')) {
				t--;
			}
			
			tlen = e-t;
			
			zend_hash_internal_pointer_reset(SUHOSIN_G(include_whitelist));
			do {
				int r = zend_hash_get_current_key_ex(SUHOSIN_G(include_whitelist), &index, &indexlen, &numindex, 0, NULL);
				
				if (r==HASH_KEY_NON_EXISTANT) {
					break;
				}
				if (r==HASH_KEY_IS_STRING) {
					if (h-t <= indexlen-1 && tlen>=indexlen-1) {
						if (strncasecmp(t, index, indexlen-1)==0) {
							isOk = 1;
							break;
						}
					}
				}
				
				zend_hash_move_forward(SUHOSIN_G(include_whitelist));
			} while (1);
			
			/* not found in whitelist */
			if (!isOk) {
				return SUHOSIN_CODE_TYPE_BADURL;
			}
			
			s = h + 1;
		} while (1);
	} else {
		
		do {
			int tlen;
			
			h = strstr(s, "://");
			h2 = suhosin_strcasestr(s, "data:");
			h2 = h2 == NULL ? NULL : h2 + 4;
			t = h = (h == NULL) ? h2 : ( (h2 == NULL) ? h : ( (h < h2) ? h : h2 ) );
			if (h == NULL) break;
							
			while (t > s && (isalnum(t[-1]) || t[-1]=='_')) {
				t--;
			}

			tlen = e-t;

			zend_hash_internal_pointer_reset(SUHOSIN_G(include_blacklist));
			do {
				int r = zend_hash_get_current_key_ex(SUHOSIN_G(include_blacklist), &index, &indexlen, &numindex, 0, NULL);

				if (r==HASH_KEY_NON_EXISTANT) {
					break;
				}
				if (r==HASH_KEY_IS_STRING) {
					if (h-t <= indexlen-1 && tlen>=indexlen-1) {
						if (strncasecmp(t, index, indexlen-1)==0) {
							return SUHOSIN_CODE_TYPE_BLACKURL;
						}
					}
				}
				
				zend_hash_move_forward(SUHOSIN_G(include_blacklist));
			} while (1);
			
			s = h + 1;
		} while (1);
	}

	/* disallow writable files */
	if (!SUHOSIN_G(executor_include_allow_writable_files)) {
	        /* protection against *REMOTE* attacks, potential
	           race condition of access() is irrelevant */
	        if (access(s, W_OK) == 0) {
                        return SUHOSIN_CODE_TYPE_WRITABLE;
	        }
	}

	return SUHOSIN_CODE_TYPE_GOODFILE;
}


#ifdef ZEND_ENGINE_2
static int (*old_zend_stream_open)(const char *filename, zend_file_handle *fh TSRMLS_DC);
#else
static zend_bool (*old_zend_open)(const char *filename, zend_file_handle *fh);
#endif

#ifdef ZEND_ENGINE_2
static int suhosin_zend_stream_open(const char *filename, zend_file_handle *fh TSRMLS_DC)
{
	zend_execute_data *exd;
#else
static zend_bool suhosin_zend_open(const char *filename, zend_file_handle *fh)
{
	zend_execute_data *exd;
	TSRMLS_FETCH();
#endif
	exd=EG(current_execute_data);
	if (EG(in_execution) && (exd!=NULL) && (exd->opline != NULL) && (exd->opline->opcode == ZEND_INCLUDE_OR_EVAL)) {
		int filetype = suhosin_check_filename((char *)filename, strlen(filename) TSRMLS_CC);
		
		switch (filetype) {
		    case SUHOSIN_CODE_TYPE_LONGNAME:
			suhosin_log(S_INCLUDE, "Include filename ('%s') is too long", filename);
			suhosin_bailout(TSRMLS_C);
			break;

		    case SUHOSIN_CODE_TYPE_UPLOADED:
			suhosin_log(S_INCLUDE, "Include filename is an uploaded file");
			suhosin_bailout(TSRMLS_C);
			break;
		    
		    case SUHOSIN_CODE_TYPE_0FILE:
			suhosin_log(S_INCLUDE, "Include filename contains an ASCIIZ character");
			suhosin_bailout(TSRMLS_C);
			break;
		
		    case SUHOSIN_CODE_TYPE_WRITABLE:
			suhosin_log(S_INCLUDE, "Include filename ('%s') is writable by PHP process", filename);
			suhosin_bailout(TSRMLS_C);
			break;		    	

		    case SUHOSIN_CODE_TYPE_BLACKURL:
			suhosin_log(S_INCLUDE, "Include filename ('%s') is an URL that is forbidden by the blacklist", filename);
			suhosin_bailout(TSRMLS_C);
			break;
			
		    case SUHOSIN_CODE_TYPE_BADURL:
			suhosin_log(S_INCLUDE, "Include filename ('%s') is an URL that is not allowed", filename);
			suhosin_bailout(TSRMLS_C);
			break;

		    case SUHOSIN_CODE_TYPE_MANYDOTS:
			suhosin_log(S_INCLUDE, "Include filename ('%s') contains too many '../'", filename);
			suhosin_bailout(TSRMLS_C);
			break;
		}
	}
#ifdef ZEND_ENGINE_2
	return old_zend_stream_open(filename, fh TSRMLS_CC);
#else
	return old_zend_open(filename, fh);
#endif
}


static int suhosin_detect_codetype(zend_op_array *op_array TSRMLS_DC)
{
	char *s;
	int r;

	s = op_array->filename;
	
	/* eval, assert, create_function, preg_replace  */
	if (op_array->type == ZEND_EVAL_CODE) {
	
		if (s == NULL) {
			return SUHOSIN_CODE_TYPE_UNKNOWN;
		}
	
		if (strstr(s, "eval()'d code") != NULL) {
			return SUHOSIN_CODE_TYPE_EVAL;
		}

		if (strstr(s, "regexp code") != NULL) {
			return SUHOSIN_CODE_TYPE_REGEXP;
		}

		if (strstr(s, "assert code") != NULL) {
			return SUHOSIN_CODE_TYPE_ASSERT;
		}

		if (strstr(s, "runtime-created function") != NULL) {
			return SUHOSIN_CODE_TYPE_CFUNC;
		}
		
		if (strstr(s, "Command line code") != NULL) {
			return SUHOSIN_CODE_TYPE_COMMANDLINE;
		}
		
		if (strstr(s, "suhosin internal code") != NULL) {
			return SUHOSIN_CODE_TYPE_SUHOSIN;
		}
		
	} else {

		r = suhosin_check_filename(s, strlen(s) TSRMLS_CC);
/*		switch (r) {
			case SUHOSIN_CODE_TYPE_GOODFILE:
				break;
		} */
		return r;

	}
	
	return SUHOSIN_CODE_TYPE_UNKNOWN;
}

/* {{{ void suhosin_execute_ex(zend_op_array *op_array TSRMLS_DC)
 *    This function provides a hook for execution */
static void suhosin_execute_ex(zend_op_array *op_array, int zo, long dummy TSRMLS_DC)
{
	zend_op_array *new_op_array;
	int op_array_type, len;
	char *fn;
	zval cs;
	zend_uint orig_code_type;
	unsigned long *suhosin_flags = NULL;
	
	if (SUHOSIN_G(abort_request) && !SUHOSIN_G(simulation) && SUHOSIN_G(filter_action)) {
	
		char *action = SUHOSIN_G(filter_action);
		long code = -1;
		
		SUHOSIN_G(abort_request) = 0; /* we do not want to endlessloop */
		
		while (*action == ' ' || *action == '\t') action++;
		
		if (*action >= '0' && *action <= '9') {
			char *end = action;
			while (*end && *end != ',' && *end != ';') end++;
			code = zend_atoi(action, end-action);
			action = end;
		}
		
		while (*action == ' ' || *action == '\t' || *action == ',' || *action == ';') action++;
		
		if (*action) {
			
			if (strncmp("http://", action, sizeof("http://")-1)==0) {
				sapi_header_line ctr = {0};
				
				if (code == -1) {
					code = 302;
				}
				
				ctr.line_len = spprintf(&ctr.line, 0, "Location: %s", action);
				ctr.response_code = code;
				sapi_header_op(SAPI_HEADER_REPLACE, &ctr TSRMLS_CC);
				efree(ctr.line);
			} else {
				zend_file_handle file_handle;
				zend_op_array *new_op_array;
				zval *result = NULL;
				
				if (code == -1) {
					code = 200;
				}
				
#ifdef ZEND_ENGINE_2
				if (zend_stream_open(action, &file_handle TSRMLS_CC) == SUCCESS) {
#else
				if (zend_open(action, &file_handle) == SUCCESS && ZEND_IS_VALID_FILE_HANDLE(&file_handle)) {
					file_handle.filename = action;
					file_handle.free_filename = 0;
#endif		
					if (!file_handle.opened_path) {
						file_handle.opened_path = estrndup(action, strlen(action));
					}
					new_op_array = zend_compile_file(&file_handle, ZEND_REQUIRE TSRMLS_CC);
					zend_destroy_file_handle(&file_handle TSRMLS_CC);
					if (new_op_array) {
						EG(return_value_ptr_ptr) = &result;
						EG(active_op_array) = new_op_array;
						zend_execute(new_op_array TSRMLS_CC);
#ifdef ZEND_ENGINE_2
						destroy_op_array(new_op_array TSRMLS_CC);
#else
						destroy_op_array(new_op_array);
#endif
						efree(new_op_array);
#ifdef ZEND_ENGINE_2
						if (!EG(exception))
#endif
						{
							if (EG(return_value_ptr_ptr)) {
								zval_ptr_dtor(EG(return_value_ptr_ptr));
								EG(return_value_ptr_ptr) = NULL;
							}
						}
					} else {
						code = 500;
					}
				} else {
					code = 500;
				}
			}
		}
		
		sapi_header_op(SAPI_HEADER_SET_STATUS, (void *)code TSRMLS_CC);
		zend_bailout();
	}
	
	SDEBUG("%s %s", op_array->filename, op_array->function_name);
	
	SUHOSIN_G(execution_depth)++;
	
	if (SUHOSIN_G(max_execution_depth) && SUHOSIN_G(execution_depth) > SUHOSIN_G(max_execution_depth)) {
		suhosin_log(S_EXECUTOR, "maximum execution depth reached - script terminated");
		suhosin_bailout(TSRMLS_C);
	}
	
	fn = op_array->filename;
	len = strlen(fn);
	
	orig_code_type = SUHOSIN_G(in_code_type);
	if (op_array->type == ZEND_EVAL_CODE) {
		SUHOSIN_G(in_code_type) = SUHOSIN_EVAL;
	} else {
		if (suhosin_zend_extension_entry.resource_number != -1) {
			suhosin_flags = (unsigned long *) &op_array->reserved[suhosin_zend_extension_entry.resource_number];
			SDEBUG("suhosin flags: %08x", *suhosin_flags);
			
			if (*suhosin_flags & SUHOSIN_FLAG_CREATED_BY_EVAL) {
				SUHOSIN_G(in_code_type) = SUHOSIN_EVAL;
			}
			if (*suhosin_flags & SUHOSIN_FLAG_NOT_EVALED_CODE) {
				goto not_evaled_code;
			}
		}
		
		if (strstr(op_array->filename, "eval()'d code")) {
			SUHOSIN_G(in_code_type) = SUHOSIN_EVAL;
		} else {
			if (suhosin_flags) {
				*suhosin_flags |= SUHOSIN_FLAG_NOT_EVALED_CODE;
			}
		}
	}
not_evaled_code:
	SDEBUG("code type %u", SUHOSIN_G(in_code_type));
	if (op_array->function_name) {
		goto continue_execution;
	}

/*	if (SUHOSIN_G(deactivate)) {
		goto continue_execution;
	}
*/	

	op_array_type = suhosin_detect_codetype(op_array TSRMLS_CC);
	
	switch (op_array_type) {
	    case SUHOSIN_CODE_TYPE_EVAL:
		    if (SUHOSIN_G(executor_disable_eval)) {
			    suhosin_log(S_EXECUTOR, "use of eval is forbidden by configuration");
			    if (!SUHOSIN_G(simulation)) {
				    zend_error(E_ERROR, "SUHOSIN - Use of eval is forbidden by configuration");
			    }
		    }
		    break;
		    
	    case SUHOSIN_CODE_TYPE_REGEXP:
		    if (SUHOSIN_G(executor_disable_emod)) {
			    suhosin_log(S_EXECUTOR, "use of preg_replace() with /e modifier is forbidden by configuration");
			    if (!SUHOSIN_G(simulation)) {
				    zend_error(E_ERROR, "SUHOSIN - Use of preg_replace() with /e modifier is forbidden by configuration");
			    }
		    }
		    break;
		    
	    case SUHOSIN_CODE_TYPE_ASSERT:
		    break;
		    
	    case SUHOSIN_CODE_TYPE_CFUNC:
		    break;
		    
		case SUHOSIN_CODE_TYPE_LONGNAME:
			suhosin_log(S_INCLUDE, "Include filename ('%s') is too long", op_array->filename);
			suhosin_bailout(TSRMLS_C);
			break;

		case SUHOSIN_CODE_TYPE_MANYDOTS:
			suhosin_log(S_INCLUDE, "Include filename ('%s') contains too many '../'", op_array->filename);
			suhosin_bailout(TSRMLS_C);
			break;
	    
		case SUHOSIN_CODE_TYPE_UPLOADED:
		    suhosin_log(S_INCLUDE, "Include filename is an uploaded file");
		    suhosin_bailout(TSRMLS_C);
		    break;
		    
	    case SUHOSIN_CODE_TYPE_0FILE:
			suhosin_log(S_INCLUDE, "Include filename contains an ASCIIZ character");
			suhosin_bailout(TSRMLS_C);
			break;
			
    		case SUHOSIN_CODE_TYPE_WRITABLE:
    		        suhosin_log(S_INCLUDE, "Include filename ('%s') is writable by PHP process", op_array->filename);
    			suhosin_bailout(TSRMLS_C);
    			break;		    	

	    case SUHOSIN_CODE_TYPE_BLACKURL:
			suhosin_log(S_INCLUDE, "Include filename ('%s') is an URL that is forbidden by the blacklist", op_array->filename);
			suhosin_bailout(TSRMLS_C);
			break;
			
	    case SUHOSIN_CODE_TYPE_BADURL:
			suhosin_log(S_INCLUDE, "Include filename ('%s') is an URL that is not allowed", op_array->filename);
		    suhosin_bailout(TSRMLS_C);
			break;

	    case SUHOSIN_CODE_TYPE_BADFILE:
		    cs.type = IS_STRING;
#define DIE_WITH_MSG "die('disallowed_file'.chr(10).chr(10));"
		    cs.value.str.val = estrndup(DIE_WITH_MSG, sizeof(DIE_WITH_MSG)-1);
		    cs.value.str.len = sizeof(DIE_WITH_MSG)-1;
		    new_op_array = compile_string(&cs, "suhosin internal code" TSRMLS_CC);
		    if (new_op_array) {
				op_array = new_op_array;
				goto continue_execution;
		    }
		    suhosin_bailout(TSRMLS_C);
		    break;

	    case SUHOSIN_CODE_TYPE_COMMANDLINE:
	    case SUHOSIN_CODE_TYPE_SUHOSIN:
	    case SUHOSIN_CODE_TYPE_UNKNOWN:
	    case SUHOSIN_CODE_TYPE_GOODFILE:
			goto continue_execution;
		    break;
	}

continue_execution:
	if (zo) {
		old_execute_ZO (op_array, dummy TSRMLS_CC);
	} else {
		old_execute (op_array TSRMLS_CC);
	}
	/* nothing to do */
	SUHOSIN_G(in_code_type) = orig_code_type;
	SUHOSIN_G(execution_depth)--;
}
/* }}} */

/* {{{ void suhosin_execute(zend_op_array *op_array TSRMLS_DC)
 *    This function provides a hook for execution */
static void suhosin_execute(zend_op_array *op_array TSRMLS_DC)
{
	suhosin_execute_ex(op_array, 0, 0 TSRMLS_CC);
}

/* {{{ void suhosin_execute(zend_op_array *op_array, long dummy TSRMLS_DC)
 *    This function provides a hook for execution */
static void suhosin_execute_ZO(zend_op_array *op_array, long dummy TSRMLS_DC)
{
	suhosin_execute_ex(op_array, 1, dummy TSRMLS_CC);
}	
/* }}} */


#define IH_HANDLER_PARAMS_REST zend_execute_data *execute_data_ptr, int return_value_used, int ht, zval *return_value TSRMLS_DC
#define IH_HANDLER_PARAMS internal_function_handler *ih, IH_HANDLER_PARAMS_REST
#define IH_HANDLER_PARAM_PASSTHRU ih, execute_data_ptr, return_value_used, ht, return_value TSRMLS_CC

HashTable ihandler_table;

typedef struct _internal_function_handler {

	char *name;
	int (*handler)(struct _internal_function_handler *ih, IH_HANDLER_PARAMS_REST);
	void *arg1;
	void *arg2;
	void *arg3;

} internal_function_handler;

int ih_preg_replace(IH_HANDLER_PARAMS)
{
	zval **regex,
	     **replace,
	     **subject,
	     **limit;

	if (ZEND_NUM_ARGS() < 3 || zend_get_parameters_ex(3, &regex, &replace, &subject, &limit) == FAILURE) {
		return (0);
	}
		
	if (Z_TYPE_PP(regex) == IS_ARRAY) {
		zval	**regex_entry;
		
		zend_hash_internal_pointer_reset(Z_ARRVAL_PP(regex));
		/* For each entry in the regex array, get the entry */
		while (zend_hash_get_current_data(Z_ARRVAL_PP(regex), (void **)&regex_entry) == SUCCESS) {
			
			if (Z_TYPE_PP(regex_entry) == IS_STRING) {
				if (strlen(Z_STRVAL_PP(regex_entry)) != Z_STRLEN_PP(regex_entry)) {
					suhosin_log(S_EXECUTOR, "string termination attack on first preg_replace parameter detected");
	    				if (!SUHOSIN_G(simulation)) {
						RETVAL_FALSE;
						return (1);
					}
				}
			}
				
			zend_hash_move_forward(Z_ARRVAL_PP(regex));
			
		}
			
	} else if (Z_TYPE_PP(regex) == IS_STRING) {
		if (strlen(Z_STRVAL_PP(regex)) != Z_STRLEN_PP(regex)) {
			suhosin_log(S_EXECUTOR, "string termination attack on first preg_replace parameter detected");
			if (!SUHOSIN_G(simulation)) {
				RETVAL_FALSE;
				return (1);
			}
		}
	}
	
	return (0);
}

int ih_symlink(IH_HANDLER_PARAMS)
{
	if (SUHOSIN_G(executor_allow_symlink)) {
		return (0);
	}
	
	if (PG(open_basedir) && PG(open_basedir)[0]) {
		suhosin_log(S_EXECUTOR, "symlink called during open_basedir");
		if (!SUHOSIN_G(simulation)) {
			RETVAL_FALSE;
			return (1);
		}
	}
	
	return (0);
}

int ih_mail(IH_HANDLER_PARAMS)
{
	char *to=NULL, *message=NULL, *headers=NULL;
	char *subject=NULL, *extra_cmd=NULL;
	char *tmp;
	int to_len, message_len, headers_len;
	int subject_len, extra_cmd_len;

	if (SUHOSIN_G(mailprotect) == 0) {
		return (0);
	}

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss|ss",
						  &to, &to_len,
						  &subject, &subject_len,
						  &message, &message_len,
						  &headers, &headers_len,
						  &extra_cmd, &extra_cmd_len
						  ) == FAILURE) {
		RETVAL_FALSE;
		return (1);
	}

	if (headers_len > 0 && headers && (strstr(headers,"\n\n") || strstr(headers,"\r\n\r\n")) ) {
		suhosin_log(S_MAIL, "mail() - double newline in headers, possible injection, mail dropped");
		if (!SUHOSIN_G(simulation)) {
			RETVAL_FALSE;
			return (1);
		}
	}

	/* check for spam attempts with buggy webforms */
	if (to_len > 0 && to) {
		do {
			tmp = strchr(to, '\n');
			tmp = tmp == NULL ? strchr(to, '\r') : tmp;
			if (tmp == NULL) break;
			to = tmp+1;
			if (isspace(*to)) continue;
		} while (1);
		if (tmp != NULL) {
			suhosin_log(S_MAIL, "mail() - newline in to header, possible injection, mail dropped");
			if (!SUHOSIN_G(simulation)) {
				RETVAL_FALSE;
				return (1);
			}
		}
	}

	if (subject_len > 0 && subject) {
		do {
			tmp = strchr(subject, '\n');
			tmp = tmp == NULL ? strchr(subject, '\r') : tmp;
			if (tmp == NULL) break;
			subject = tmp+1;
			if (isspace(*subject)) continue;
		} while (1);
		if (tmp != NULL) {
			suhosin_log(S_MAIL, "mail() - newline in subject header, possible injection, mail dropped");
			if (!SUHOSIN_G(simulation)) {
				RETVAL_FALSE;
				return (1);
			}
		}
	}
		
	if (SUHOSIN_G(mailprotect) > 1) {
		/* search for to, cc or bcc headers */
		if (headers_len > 0 && headers != NULL) {
			if (strncasecmp(headers, "to:", sizeof("to:") - 1) == 0 || suhosin_strcasestr(headers, "\nto:")) {
				suhosin_log(S_MAIL, "mail() - To: headers aren't allowed in the headers parameter.");
				if (!SUHOSIN_G(simulation)) {
					RETVAL_FALSE;
					return (1);
				}
			}
			
			if (strncasecmp(headers, "cc:", sizeof("cc:") - 1) == 0 || suhosin_strcasestr(headers, "\ncc:")) {
				suhosin_log(S_MAIL, "mail() - CC: headers aren't allowed in the headers parameter.");
				if (!SUHOSIN_G(simulation)) {
					RETVAL_FALSE;
					return (1);
				}
			}

			if (strncasecmp(headers, "bcc:", sizeof("bcc:") - 1) == 0 || suhosin_strcasestr(headers, "\nbcc:")) {
				suhosin_log(S_MAIL, "mail() - BCC: headers aren't allowed in the headers parameter.");
				if (!SUHOSIN_G(simulation)) {
					RETVAL_FALSE;
					return (1);
				}
			}
		}
	}

	return (0);
}

#define SQLSTATE_SQL        0
#define SQLSTATE_IDENTIFIER 1
#define SQLSTATE_STRING     2
#define SQLSTATE_COMMENT    3
#define SQLSTATE_MLCOMMENT  4

int ih_querycheck(IH_HANDLER_PARAMS)
{
#ifdef PHP_ATLEAST_5_3
    void **p = zend_vm_stack_top(TSRMLS_C) - 1;
#else
	void **p = EG(argument_stack).top_element-2;
#endif
	unsigned long arg_count;
	zval **arg;
	char *query, *s, *e;
	zval *backup;
	int len;
	char quote;
	int state = SQLSTATE_SQL;
	int cnt_union = 0, cnt_select = 0, cnt_comment = 0, cnt_opencomment = 0;
	int mysql_extension = 0;

	
	SDEBUG("function: %s", ih->name);
	arg_count = (unsigned long) *p;

	if (ht < (long) ih->arg1) {
		return (0);
	}
    
	if ((long) ih->arg1) {
    	    mysql_extension = 1;
	}
	
	arg = (zval **) p - (arg_count - (long) ih->arg1 + 1); /* count from 0 */

	backup = *arg;
	if (Z_TYPE_P(backup) != IS_STRING) {
		return (0);
	}
	len = Z_STRLEN_P(backup);
	query = Z_STRVAL_P(backup);
	
	s = query;
	e = s+len;
	
	while (s < e) {
	    switch (state)
	    {
    		case SQLSTATE_SQL:
    		    switch (s[0])
    		    {
        		case '`':
        		    state = SQLSTATE_IDENTIFIER;
        		    quote = '`';
        		    break;
        		case '\'':
        		case '"':
        		    state = SQLSTATE_STRING;
        		    quote = *s;
        		    break;
        		case '/':
        		    if (s[1]=='*') {
                        if (mysql_extension == 1 && s[2] == '!') {
                            s += 2;
                            break;
                        }
            			s++;
            			state = SQLSTATE_MLCOMMENT;
        			    cnt_comment++;
        		    }
        		    break;
    			case '-':
        		    if (s[1]=='-') {
        			s++;
        			state = SQLSTATE_COMMENT;
        			cnt_comment++;
        		    }
        		    break;
    			case '#':
        		    state = SQLSTATE_COMMENT;
        		    cnt_comment++;
        		    break;
        		case 'u':
    			case 'U':
        		    if (strncasecmp("union", s, 5)==0) {
            			s += 4;
        			cnt_union++;
        		    }
        		    break;
    			case 's':
    			case 'S':
        		    if (strncasecmp("select", s, 6)==0) {
            			s += 5;
        			cnt_select++;
        		    }
        		    break;
    		    }
    		    break;
    		case SQLSTATE_STRING:
		case SQLSTATE_IDENTIFIER:
    		    if (s[0] == quote) {
        		if (s[1] == quote) {
        		    s++;
    			} else {
        		    state = SQLSTATE_SQL;
    			}
    		    }
    		    if (s[0] == '\\') {
    			s++;
    		    }
    		    break;
		case SQLSTATE_COMMENT:
    		    while (s[0] && s[0] != '\n') {
    			s++;        
    		    }
    		    state = SQLSTATE_SQL;
    		    break;
    		case SQLSTATE_MLCOMMENT:
    		    while (s[0] && (s[0] != '*' || s[1] != '/')) {
    			s++;
    		    }
    		    if (s[0]) {
    			state = SQLSTATE_SQL;
    		    }
    		    break;
	    }
	    s++;
	}
	if (state == SQLSTATE_MLCOMMENT) {
	    cnt_opencomment = 1;
	}
	
	if (cnt_opencomment && SUHOSIN_G(sql_opencomment)>0) {
	    suhosin_log(S_SQL, "Open comment in SQL query: '%*s'", len, query);
	    if (SUHOSIN_G(sql_opencomment)>1) {
		suhosin_bailout(TSRMLS_C);
	    }
	}
	
	if (cnt_comment && SUHOSIN_G(sql_comment)>0) {
	    suhosin_log(S_SQL, "Comment in SQL query: '%*s'", len, query);
	    if (SUHOSIN_G(sql_comment)>1) {
		suhosin_bailout(TSRMLS_C);
	    }
	}

	if (cnt_union && SUHOSIN_G(sql_union)>0) {
	    suhosin_log(S_SQL, "UNION in SQL query: '%*s'", len, query);
	    if (SUHOSIN_G(sql_union)>1) {
		suhosin_bailout(TSRMLS_C);
	    }
	}

	if (cnt_select>1 && SUHOSIN_G(sql_mselect)>0) {
	    suhosin_log(S_SQL, "Multiple SELECT in SQL query: '%*s'", len, query);
	    if (SUHOSIN_G(sql_mselect)>1) {
		suhosin_bailout(TSRMLS_C);
	    }
	}
    
	return (0);
}


int ih_fixusername(IH_HANDLER_PARAMS)
{
#ifdef PHP_ATLEAST_5_3
    void **p = zend_vm_stack_top(TSRMLS_C) - 1;
#else
	void **p = EG(argument_stack).top_element-2;
#endif
	unsigned long arg_count;
	zval **arg;char *prefix, *postfix, *user;
	zval *backup, *my_user;
	int prefix_len, postfix_len, len;
	
	SDEBUG("function: %s", ih->name);
	
	prefix = SUHOSIN_G(sql_user_prefix);
	postfix = SUHOSIN_G(sql_user_postfix);
	
	if ((prefix == NULL || prefix[0] == 0)&& 
		(postfix == NULL || postfix[0] == 0)) {
		return (0);
	}
	
	if (prefix == NULL) {
		prefix = "";
	}
	if (postfix == NULL) {
		postfix = "";
	}
	
	prefix_len = strlen(prefix);
	postfix_len = strlen(postfix);
	
	arg_count = (unsigned long) *p;

	if (ht < (long) ih->arg1) {
		return (0);
	}
	
	arg = (zval **) p - (arg_count - (long) ih->arg1 + 1); /* count from 0 */

	backup = *arg;
	if (Z_TYPE_P(backup) != IS_STRING) {
		user = "";
		len = 0;
	} else {
		len = Z_STRLEN_P(backup);
		user = Z_STRVAL_P(backup);
	}

	if (prefix_len && prefix_len <= len) {
		if (strncmp(prefix, user, prefix_len)==0) {
			prefix = "";
			len -= prefix_len;
		}
	}
	
	if (postfix_len && postfix_len <= len) {
		if (strncmp(postfix, user+len-postfix_len, postfix_len)==0) {
			postfix = "";
		}
	}
	
	MAKE_STD_ZVAL(my_user);
	my_user->type = IS_STRING;
	my_user->value.str.len = spprintf(&my_user->value.str.val, 0, "%s%s%s", prefix, user, postfix);
	
	/* XXX: memory_leak? */
	*arg = my_user;	
	 
	SDEBUG("function: %s - user: %s", ih->name, user);

	return (0);
}

static int suhosin_php_body_write(const char *str, uint str_length TSRMLS_DC)
{
#define P_META_ROBOTS "<meta name=\"ROBOTS\" content=\"NOINDEX,NOFOLLOW,NOARCHIVE\" />"
#define S_META_ROBOTS "<meta name=\"ROBOTS\" content=\"NOINDEX,FOLLOW,NOARCHIVE\" />"

    SDEBUG("bw: %s", str);

	if ((str_length == sizeof("</head>\n")-1) && (strcmp(str, "</head>\n")==0)) {
		SUHOSIN_G(old_php_body_write)(S_META_ROBOTS, sizeof(S_META_ROBOTS)-1 TSRMLS_CC);
		OG(php_body_write) = SUHOSIN_G(old_php_body_write);
		return SUHOSIN_G(old_php_body_write)(str, str_length TSRMLS_CC);
	} else if ((str_length == sizeof(P_META_ROBOTS)-1) && (strcmp(str, P_META_ROBOTS)==0)) {
		return str_length;
	}
	return SUHOSIN_G(old_php_body_write)(str, str_length TSRMLS_CC);	
}

static int ih_phpinfo(IH_HANDLER_PARAMS)
{
    int argc = ZEND_NUM_ARGS();
	long flag;

	if (zend_parse_parameters(argc TSRMLS_CC, "|l", &flag) == FAILURE) {
        RETVAL_FALSE;
		return (1);
	}

	if(!argc) {
		flag = PHP_INFO_ALL;
	}

	/* Andale!  Andale!  Yee-Hah! */
	php_start_ob_buffer(NULL, 4096, 0 TSRMLS_CC);
	if (!sapi_module.phpinfo_as_text) {
		SUHOSIN_G(old_php_body_write) = OG(php_body_write);
		OG(php_body_write) = suhosin_php_body_write;
	}
	php_print_info(flag TSRMLS_CC);
	php_end_ob_buffer(1, 0 TSRMLS_CC);

	RETVAL_TRUE;
	return (1);
}


static int ih_function_exists(IH_HANDLER_PARAMS)
{
#ifndef PHP_ATLEAST_5_3
	zval **function_name;
#endif
	zend_function *func;
	char *lcname;
	zend_bool retval;
	int func_name_len;
	
#ifndef PHP_ATLEAST_5_3
	if (ZEND_NUM_ARGS()!=1 || zend_get_parameters_ex(1, &function_name)==FAILURE) {
		ZEND_WRONG_PARAM_COUNT_WITH_RETVAL(1);
	}
	convert_to_string_ex(function_name);
	func_name_len = Z_STRLEN_PP(function_name);
	lcname = estrndup(Z_STRVAL_PP(function_name), func_name_len);	
	zend_str_tolower(lcname, func_name_len);
#else
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &lcname, &func_name_len) == FAILURE) {
		return;
	}

	/* Ignore leading "\" */
	if (lcname[0] == '\\') {
		lcname = &lcname[1];
		func_name_len--;
	}
	lcname = zend_str_tolower_dup(lcname, func_name_len);	
#endif

	retval = (zend_hash_find(EG(function_table), lcname, func_name_len+1, (void **)&func) == SUCCESS);
	
	efree(lcname);

	/*
	 * A bit of a hack, but not a bad one: we see if the handler of the function
	 * is actually one that displays "function is disabled" message.
	 */
	if (retval && func->type == ZEND_INTERNAL_FUNCTION &&
		func->internal_function.handler == zif_display_disabled_function) {
		retval = 0;
	}

	/* Now check if function is forbidden by Suhosin */
	if (SUHOSIN_G(in_code_type) == SUHOSIN_EVAL) {
		if (SUHOSIN_G(eval_whitelist) != NULL) {
			if (!zend_hash_exists(SUHOSIN_G(eval_whitelist), lcname, func_name_len+1)) {
			    retval = 0;
			}
		} else if (SUHOSIN_G(eval_blacklist) != NULL) {
			if (zend_hash_exists(SUHOSIN_G(eval_blacklist), lcname, func_name_len+1)) {
			    retval = 0;
			}
		}
	}
	
	if (SUHOSIN_G(func_whitelist) != NULL) {
		if (!zend_hash_exists(SUHOSIN_G(func_whitelist), lcname, func_name_len+1)) {
		    retval = 0;
		}
	} else if (SUHOSIN_G(func_blacklist) != NULL) {
		if (zend_hash_exists(SUHOSIN_G(func_blacklist), lcname, func_name_len+1)) {
		    retval = 0;
		}
	}

	RETVAL_BOOL(retval);
	return (1);
}

/* MT RAND FUNCTIONS */

/*
	The following php_mt_...() functions are based on a C++ class MTRand by
	Richard J. Wagner. For more information see the web page at
	http://www-personal.engin.umich.edu/~wagnerr/MersenneTwister.html

	Mersenne Twister random number generator -- a C++ class MTRand
	Based on code by Makoto Matsumoto, Takuji Nishimura, and Shawn Cokus
	Richard J. Wagner  v1.0  15 May 2003  rjwagner@writeme.com

	The Mersenne Twister is an algorithm for generating random numbers.  It
	was designed with consideration of the flaws in various other generators.
	The period, 2^19937-1, and the order of equidistribution, 623 dimensions,
	are far greater.  The generator is also fast; it avoids multiplication and
	division, and it benefits from caches and pipelines.  For more information
	see the inventors' web page at http://www.math.keio.ac.jp/~matumoto/emt.html

	Reference
	M. Matsumoto and T. Nishimura, "Mersenne Twister: A 623-Dimensionally
	Equidistributed Uniform Pseudo-Random Number Generator", ACM Transactions on
	Modeling and Computer Simulation, Vol. 8, No. 1, January 1998, pp 3-30.

	Copyright (C) 1997 - 2002, Makoto Matsumoto and Takuji Nishimura,
	Copyright (C) 2000 - 2003, Richard J. Wagner
	All rights reserved.                          

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions
	are met:

	1. Redistributions of source code must retain the above copyright
	   notice, this list of conditions and the following disclaimer.

	2. Redistributions in binary form must reproduce the above copyright
	   notice, this list of conditions and the following disclaimer in the
	   documentation and/or other materials provided with the distribution.

	3. The names of its contributors may not be used to endorse or promote 
	   products derived from this software without specific prior written 
	   permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
	"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
	LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
	A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
	CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
	EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
	PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
	PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
	LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
	NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

	The original code included the following notice:

	When you use this, send an email to: matumoto@math.keio.ac.jp
    with an appropriate reference to your work.

	It would be nice to CC: rjwagner@writeme.com and Cokus@math.washington.edu
	when you write.
*/

#define N             624                 /* length of state vector */
#define M             (397)                /* a period parameter */
#define hiBit(u)      ((u) & 0x80000000U)  /* mask all but highest   bit of u */
#define loBit(u)      ((u) & 0x00000001U)  /* mask all but lowest    bit of u */
#define loBits(u)     ((u) & 0x7FFFFFFFU)  /* mask     the highest   bit of u */
#define mixBits(u, v) (hiBit(u)|loBits(v)) /* move hi bit of u to hi bit of v */

#define twist(m,u,v)  (m ^ (mixBits(u,v)>>1) ^ ((php_uint32)(-(php_int32)(loBit(u))) & 0x9908b0dfU))

/* {{{ php_mt_initialize
 */
static inline void suhosin_mt_initialize(php_uint32 seed, php_uint32 *state)
{
	/* Initialize generator state with seed
	   See Knuth TAOCP Vol 2, 3rd Ed, p.106 for multiplier.
	   In previous versions, most significant bits (MSBs) of the seed affect
	   only MSBs of the state array.  Modified 9 Jan 2002 by Makoto Matsumoto. */

	register php_uint32 *s = state;
	register php_uint32 *r = state;
	register int i = 1;

	*s++ = seed & 0xffffffffU;
	for( ; i < N; ++i ) {
		*s++ = ( 1812433253U * ( *r ^ (*r >> 30) ) + i ) & 0xffffffffU;
		r++;
	}
}
/* }}} */

static inline void suhosin_mt_init_by_array(php_uint32 *key, int keylen, php_uint32 *state)
{
    int i, j, k;
    suhosin_mt_initialize(19650218U, state);
    i = 1; j = 0;
    k = (N > keylen ? N : keylen);
    for (; k; k--) {
        state[i] = (state[i] ^ ((state[i-1] ^ (state[i-1] >> 30)) * 1664525U)) + key[j] + j;
        i++; j = (j+1) % keylen;
        if (i >= N) { state[0] = state[N-1]; i=1; }
    }
    for (k=N-1; k; k--) {
        state[i] = (state[i] ^ ((state[i-1] ^ (state[i-1] >> 30)) * 1566083941U)) - i;
        i++;
        if (i >= N) { state[0] = state[N-1]; i=1; }
    }
    state[0] = 0x80000000U;
}
/* }}} */


/* {{{ suhosin_mt_reload
 */
static inline void suhosin_mt_reload(php_uint32 *state, php_uint32 **next, int *left)
{
	/* Generate N new values in state
	   Made clearer and faster by Matthew Bellew (matthew.bellew@home.com) */

	register php_uint32 *p = state;
	register int i;

	for (i = N - M; i--; ++p)
		*p = twist(p[M], p[0], p[1]);
	for (i = M; --i; ++p)
		*p = twist(p[M-N], p[0], p[1]);
	*p = twist(p[M-N], p[0], state[0]);
	*left = N;
	*next = state;
}
/* }}} */

/* {{{ suhosin_mt_srand
 */
static void suhosin_mt_srand(php_uint32 seed TSRMLS_DC)
{
	/* Seed the generator with a simple uint32 */
	suhosin_mt_initialize(seed, SUHOSIN_G(mt_state));
	suhosin_mt_reload(SUHOSIN_G(mt_state), &SUHOSIN_G(mt_next), &SUHOSIN_G(mt_left));

	/* Seed only once */
	SUHOSIN_G(mt_is_seeded) = 1;
}
/* }}} */

/* {{{ suhosin_mt_rand
 */
static php_uint32 suhosin_mt_rand(TSRMLS_D)
{
	/* Pull a 32-bit integer from the generator state
	   Every other access function simply transforms the numbers extracted here */
	
	register php_uint32 s1;

	if (SUHOSIN_G(mt_left) == 0) {
    	suhosin_mt_reload(SUHOSIN_G(mt_state), &SUHOSIN_G(mt_next), &SUHOSIN_G(mt_left));
	}
	--SUHOSIN_G(mt_left);
		
	s1 = *SUHOSIN_G(mt_next)++;
	s1 ^= (s1 >> 11);
	s1 ^= (s1 <<  7) & 0x9d2c5680U;
	s1 ^= (s1 << 15) & 0xefc60000U;
	return ( s1 ^ (s1 >> 18) );
}
/* }}} */

/* {{{ suhosin_gen_entropy
 */
static void suhosin_gen_entropy(php_uint32 *seedbuf TSRMLS_DC)
{
    /* On a modern OS code, stack and heap base are randomized */
    unsigned long code_value  = (unsigned long)suhosin_gen_entropy;
    unsigned long stack_value = (unsigned long)&code_value;
    unsigned long heap_value  = (unsigned long)SUHOSIN_G(r_state);
    suhosin_SHA256_CTX   context;
    int fd;
    
    code_value ^= code_value >> 32;
    stack_value ^= stack_value >> 32;
    heap_value ^= heap_value >> 32;
    
    seedbuf[0] = code_value;
    seedbuf[1] = stack_value;
    seedbuf[2] = heap_value;
    seedbuf[3] = time(0);
#ifdef PHP_WIN32
    seedbuf[4] = GetCurrentProcessId();
#else
    seedbuf[4] = getpid();
#endif
    seedbuf[5] = (php_uint32) 0x7fffffff * php_combined_lcg(TSRMLS_C);

#ifndef PHP_WIN32
    fd = VCWD_OPEN("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        /* ignore error case - if urandom doesn't give us any/enough random bytes */
        read(fd, &seedbuf[6], 2 * sizeof(php_uint32));
        close(fd);
    }
#endif

    suhosin_SHA256Init(&context);
	suhosin_SHA256Update(&context, (void *) seedbuf, sizeof(php_uint32) * 8);
	suhosin_SHA256Final(seedbuf, &context);
}
/* }}} */


/* {{{ suhosin_srand_auto
 */
static void suhosin_srand_auto(TSRMLS_D)
{
    php_uint32 seed[8];    
    suhosin_gen_entropy(&seed[0] TSRMLS_CC);

	suhosin_mt_init_by_array(seed, 8, SUHOSIN_G(r_state));
	suhosin_mt_reload(SUHOSIN_G(r_state), &SUHOSIN_G(r_next), &SUHOSIN_G(r_left));

	/* Seed only once */
	SUHOSIN_G(r_is_seeded) = 1;
}
/* }}} */

/* {{{ suhosin_mt_srand_auto
 */
static void suhosin_mt_srand_auto(TSRMLS_D)
{
    php_uint32 seed[8];    
    suhosin_gen_entropy(&seed[0] TSRMLS_CC);

	suhosin_mt_init_by_array(seed, 8, SUHOSIN_G(mt_state));
	suhosin_mt_reload(SUHOSIN_G(mt_state), &SUHOSIN_G(mt_next), &SUHOSIN_G(mt_left));

	/* Seed only once */
	SUHOSIN_G(mt_is_seeded) = 1;
}
/* }}} */


/* {{{ suhosin_srand
 */
static void suhosin_srand(php_uint32 seed TSRMLS_DC)
{
	/* Seed the generator with a simple uint32 */
	suhosin_mt_initialize(seed+0x12345, SUHOSIN_G(r_state));
	suhosin_mt_reload(SUHOSIN_G(r_state), &SUHOSIN_G(r_next), &SUHOSIN_G(r_left));

	/* Seed only once */
	SUHOSIN_G(r_is_seeded) = 1;
}
/* }}} */

/* {{{ suhosin_mt_rand
 */
static php_uint32 suhosin_rand(TSRMLS_D)
{
	/* Pull a 32-bit integer from the generator state
	   Every other access function simply transforms the numbers extracted here */
	
	register php_uint32 s1;

	if (SUHOSIN_G(r_left) == 0) {
    	suhosin_mt_reload(SUHOSIN_G(r_state), &SUHOSIN_G(r_next), &SUHOSIN_G(r_left));
	}
	--SUHOSIN_G(r_left);
		
	s1 = *SUHOSIN_G(r_next)++;
	s1 ^= (s1 >> 11);
	s1 ^= (s1 <<  7) & 0x9d2c5680U;
	s1 ^= (s1 << 15) & 0xefc60000U;
	return ( s1 ^ (s1 >> 18) );
}
/* }}} */

static int ih_srand(IH_HANDLER_PARAMS)
{
    int argc = ZEND_NUM_ARGS();
	long seed;

	if (zend_parse_parameters(argc TSRMLS_CC, "|l", &seed) == FAILURE || SUHOSIN_G(srand_ignore)) {
    	return (1);
    }

    if (argc == 0) {
        suhosin_srand_auto(TSRMLS_C);
    } else {
        suhosin_srand(seed TSRMLS_CC);
    }
	return (1);
}

static int ih_mt_srand(IH_HANDLER_PARAMS)
{
    int argc = ZEND_NUM_ARGS();
	long seed;

	if (zend_parse_parameters(argc TSRMLS_CC, "|l", &seed) == FAILURE || SUHOSIN_G(mt_srand_ignore)) {
    	return (1);
    }
    
    if (argc == 0) {
        suhosin_mt_srand_auto(TSRMLS_C);
    } else {
        suhosin_mt_srand(seed TSRMLS_CC);
    }
	return (1);
}

static int ih_mt_rand(IH_HANDLER_PARAMS)
{
    int argc = ZEND_NUM_ARGS();
    long min;
	long max;
	long number;

	if (argc != 0 && zend_parse_parameters(argc TSRMLS_CC, "ll", &min, &max) == FAILURE) {
	    return (1);        
	}

	if (!SUHOSIN_G(mt_is_seeded)) {
		suhosin_mt_srand_auto(TSRMLS_C);
	}

	number = (long) (suhosin_mt_rand(TSRMLS_C) >> 1);
	if (argc == 2) {
		RAND_RANGE(number, min, max, PHP_MT_RAND_MAX);
	}

	RETVAL_LONG(number);
        return (1);
}

static int ih_rand(IH_HANDLER_PARAMS)
{
    int argc = ZEND_NUM_ARGS();
    long min;
	long max;
	long number;

	if (argc != 0 && zend_parse_parameters(argc TSRMLS_CC, "ll", &min, &max) == FAILURE) {
	    return (1);        
	}

	if (!SUHOSIN_G(r_is_seeded)) {
		suhosin_srand_auto(TSRMLS_C);
	}

	number = (long) (suhosin_rand(TSRMLS_C) >> 1);
	if (argc == 2) {
		RAND_RANGE(number, min, max, PHP_MT_RAND_MAX);
	}

	RETVAL_LONG(number);
        return (1);
}

static int ih_getrandmax(IH_HANDLER_PARAMS)
{
#ifdef PHP_ATLEAST_5_3
	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}
#else
        int argc = ZEND_NUM_ARGS();

        if (argc != 0) {
		ZEND_WRONG_PARAM_COUNT_WITH_RETVAL(1);
        }
#endif    
	RETVAL_LONG(PHP_MT_RAND_MAX);
	return (1);
}

internal_function_handler ihandlers[] = {
    { "preg_replace", ih_preg_replace, NULL, NULL, NULL },
    { "mail", ih_mail, NULL, NULL, NULL },
    { "symlink", ih_symlink, NULL, NULL, NULL },
    { "phpinfo", ih_phpinfo, NULL, NULL, NULL },
	
	{ "srand", ih_srand, NULL, NULL, NULL },
	{ "mt_srand", ih_mt_srand, NULL, NULL, NULL },
	{ "rand", ih_rand, NULL, NULL, NULL },
	{ "mt_rand", ih_mt_rand, NULL, NULL, NULL },
	{ "getrandmax", ih_getrandmax, NULL, NULL, NULL },
	{ "mt_getrandmax", ih_getrandmax, NULL, NULL, NULL },
	
    { "ocilogon", ih_fixusername, (void *)1, NULL, NULL },
    { "ociplogon", ih_fixusername, (void *)1, NULL, NULL },
    { "ocinlogon", ih_fixusername, (void *)1, NULL, NULL },
    { "oci_connect", ih_fixusername, (void *)1, NULL, NULL },
    { "oci_pconnect", ih_fixusername, (void *)1, NULL, NULL },
    { "oci_new_connect", ih_fixusername, (void *)1, NULL, NULL },
	
    { "fbsql_change_user", ih_fixusername, (void *)1, NULL, NULL },
    { "fbsql_connect", ih_fixusername, (void *)2, NULL, NULL },
    { "fbsql_pconnect", ih_fixusername, (void *)2, NULL, NULL },
    
    { "function_exists", ih_function_exists, NULL, NULL, NULL },
	
    { "ifx_connect", ih_fixusername, (void *)2, NULL, NULL },
    { "ifx_pconnect", ih_fixusername, (void *)2, NULL, NULL },

    { "ibase_connect", ih_fixusername, (void *)2, NULL, NULL },
    { "ibase_pconnect", ih_fixusername, (void *)2, NULL, NULL },

    { "maxdb", ih_fixusername, (void *)2, NULL, NULL },
    { "maxdb_change_user", ih_fixusername, (void *)2, NULL, NULL },
    { "maxdb_connect", ih_fixusername, (void *)2, NULL, NULL },
    { "maxdb_pconnect", ih_fixusername, (void *)2, NULL, NULL },
    { "maxdb_real_connect", ih_fixusername, (void *)3, NULL, NULL },

    { "mssql_connect", ih_fixusername, (void *)2, NULL, NULL },
    { "mssql_pconnect", ih_fixusername, (void *)2, NULL, NULL },

    { "mysql_query", ih_querycheck, (void *)1, (void *)1, NULL },
    { "mysql_db_query", ih_querycheck, (void *)2, (void *)1, NULL },
    { "mysql_unbuffered_query", ih_querycheck, (void *)1, (void *)1, NULL },
    { "mysqli_query", ih_querycheck, (void *)2, (void *)1, NULL },
    { "mysqli_real_query", ih_querycheck, (void *)2, (void *)1, NULL },
    { "mysqli_send_query", ih_querycheck, (void *)2, (void *)1, NULL },
    { "mysqli_master_query", ih_querycheck, (void *)2, (void *)1, NULL },
    { "mysqli_slave_query", ih_querycheck, (void *)2, (void *)1, NULL },

    { "mysqli", ih_fixusername, (void *)2, NULL, NULL },
    { "mysql_connect", ih_fixusername, (void *)2, NULL, NULL },
    { "mysql_pconnect", ih_fixusername, (void *)2, NULL, NULL },
    { "mysqli_change_user", ih_fixusername, (void *)2, NULL, NULL },
    { "mysql_real_connect", ih_fixusername, (void *)3, NULL, NULL },
    { NULL, NULL, NULL, NULL, NULL }
};

#define FUNCTION_WARNING() zend_error(E_WARNING, "%s() has been disabled for security reasons", get_active_function_name(TSRMLS_C));
#define FUNCTION_SIMULATE_WARNING() zend_error(E_WARNING, "SIMULATION - %s() has been disabled for security reasons", get_active_function_name(TSRMLS_C));

/* {{{ void suhosin_execute_internal(zend_execute_data *execute_data_ptr, int return_value_used TSRMLS_DC)
 *    This function provides a hook for internal execution */
static void suhosin_execute_internal(zend_execute_data *execute_data_ptr, int return_value_used TSRMLS_DC)
{
	char *lcname;
	int function_name_strlen, free_lcname = 0;
	zval *return_value;
	zend_class_entry *ce = NULL;
	int ht;
	internal_function_handler *ih;

#ifdef ZEND_ENGINE_2
	ce = ((zend_internal_function *) execute_data_ptr->function_state.function)->scope;
#endif
	lcname = ((zend_internal_function *) execute_data_ptr->function_state.function)->function_name;
	function_name_strlen = strlen(lcname);
	
	/* handle methodcalls correctly */
	if (ce != NULL) {
		char *tmp = (char *) emalloc(function_name_strlen + 2 + ce->name_length + 1);
		memcpy(tmp, ce->name, ce->name_length);
		memcpy(tmp+ce->name_length, "::", 2);
		memcpy(tmp+ce->name_length+2, lcname, function_name_strlen);
		lcname = tmp;
		free_lcname = 1;
		function_name_strlen += ce->name_length + 2;
		lcname[function_name_strlen] = 0;
		zend_str_tolower(lcname, function_name_strlen);
	}
	
#ifdef ZEND_ENGINE_2  
	return_value = (*(temp_variable *)((char *) execute_data_ptr->Ts + execute_data_ptr->opline->result.u.var)).var.ptr;
#else
        return_value = execute_data_ptr->Ts[execute_data_ptr->opline->result.u.var].var.ptr;
#endif
	ht = execute_data_ptr->opline->extended_value;

	SDEBUG("function: %s", lcname);

	if (SUHOSIN_G(in_code_type) == SUHOSIN_EVAL) {
	
		if (SUHOSIN_G(eval_whitelist) != NULL) {
			if (!zend_hash_exists(SUHOSIN_G(eval_whitelist), lcname, function_name_strlen+1)) {
				suhosin_log(S_EXECUTOR, "function outside of eval whitelist called: %s()", lcname);
				if (!SUHOSIN_G(simulation)) {
				        goto execute_internal_bailout;
        			} else {
        			        FUNCTION_SIMULATE_WARNING()
				}
			}
		} else if (SUHOSIN_G(eval_blacklist) != NULL) {
			if (zend_hash_exists(SUHOSIN_G(eval_blacklist), lcname, function_name_strlen+1)) {
				suhosin_log(S_EXECUTOR, "function within eval blacklist called: %s()", lcname);
				if (!SUHOSIN_G(simulation)) {
				        goto execute_internal_bailout;
        			} else {
        			        FUNCTION_SIMULATE_WARNING()
				}
			}
		}
	}
	
	if (SUHOSIN_G(func_whitelist) != NULL) {
		if (!zend_hash_exists(SUHOSIN_G(func_whitelist), lcname, function_name_strlen+1)) {
			suhosin_log(S_EXECUTOR, "function outside of whitelist called: %s()", lcname);
			if (!SUHOSIN_G(simulation)) {
			        goto execute_internal_bailout;
			} else {
			        FUNCTION_SIMULATE_WARNING()
			}
		}
	} else if (SUHOSIN_G(func_blacklist) != NULL) {
		if (zend_hash_exists(SUHOSIN_G(func_blacklist), lcname, function_name_strlen+1)) {
			suhosin_log(S_EXECUTOR, "function within blacklist called: %s()", lcname);
			if (!SUHOSIN_G(simulation)) {
			        goto execute_internal_bailout;
			} else {
			        FUNCTION_SIMULATE_WARNING()
			}
		}
	}
	
	if (zend_hash_find(&ihandler_table, lcname, function_name_strlen+1, (void **)&ih) == SUCCESS) {
	
		int retval = 0;
		void *handler = ((zend_internal_function *) execute_data_ptr->function_state.function)->handler;
		
		if (handler != ZEND_FN(display_disabled_function)) {
		    retval = ih->handler(IH_HANDLER_PARAM_PASSTHRU);
		}
		
		if (retval == 0) {
			old_execute_internal(execute_data_ptr, return_value_used TSRMLS_CC);
		}
	} else {
		old_execute_internal(execute_data_ptr, return_value_used TSRMLS_CC);
	}
	if (free_lcname == 1) {
		efree(lcname);
	}
	return;
execute_internal_bailout:
	if (free_lcname == 1) {
		efree(lcname);
	}
	FUNCTION_WARNING()
	suhosin_bailout(TSRMLS_C);
}
/* }}} */


/* {{{ int function_lookup(zend_extension *extension)
 */
static int function_lookup(zend_extension *extension)
{
	if (zo_set_oe_ex != NULL) {
		return ZEND_HASH_APPLY_STOP;
	}
    
    if (extension->handle != NULL) {

	    zo_set_oe_ex = (void *)DL_FETCH_SYMBOL(extension->handle, "zend_optimizer_set_oe_ex");
    
    }

	return 0;
}
/* }}} */


/* {{{ void suhosin_hook_execute()
 */
void suhosin_hook_execute(TSRMLS_D)
{
	internal_function_handler *ih;
	
	old_execute = zend_execute;
	zend_execute = suhosin_execute;
	
/*	old_compile_file = zend_compile_file;
	zend_compile_file = suhosin_compile_file; */

	if (zo_set_oe_ex == NULL) {	
		zo_set_oe_ex = (void *)DL_FETCH_SYMBOL(NULL, "zend_optimizer_set_oe_ex");
	}
	if (zo_set_oe_ex == NULL) {	
		zend_llist_apply(&zend_extensions, (llist_apply_func_t)function_lookup TSRMLS_CC);
	}

	if (zo_set_oe_ex != NULL) {
		old_execute_ZO = zo_set_oe_ex(suhosin_execute_ZO);
	}
	
	old_execute_internal = zend_execute_internal;
	if (old_execute_internal == NULL) {
		old_execute_internal = execute_internal;
	}
	zend_execute_internal = suhosin_execute_internal;
	/* register internal function handlers */
	zend_hash_init(&ihandler_table, 16, NULL, NULL, 1);
	ih = &ihandlers[0];
	while (ih->name) {
		zend_hash_add(&ihandler_table, ih->name, strlen(ih->name)+1, ih, sizeof(internal_function_handler), NULL);
		ih++;
	}
		
	
	/* Add additional protection layer, that SHOULD
	   catch ZEND_INCLUDE_OR_EVAL *before* the engine tries
	   to execute */
#ifdef ZEND_ENGINE_2
	old_zend_stream_open = zend_stream_open_function;
	zend_stream_open_function = suhosin_zend_stream_open;
#else
	old_zend_open = zend_open;
	zend_open = suhosin_zend_open;
#endif
	
}
/* }}} */


/* {{{ void suhosin_unhook_execute()
 */
void suhosin_unhook_execute()
{
	if (zo_set_oe_ex) {
		zo_set_oe_ex(old_execute_ZO);
	}
	
	zend_execute = old_execute;
	
/*	zend_compile_file = old_compile_file; */

	if (old_execute_internal == execute_internal) {
		old_execute_internal = NULL;
	}
	zend_execute_internal = old_execute_internal;
	zend_hash_clean(&ihandler_table);
	
	/* remove zend_open protection */
#ifdef ZEND_ENGINE_2
	zend_stream_open_function = old_zend_stream_open;
#else
	zend_open = old_zend_open;
#endif
	
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
