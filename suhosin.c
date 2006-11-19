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

/* $Id: suhosin.c,v 1.28 2006-10-08 10:00:31 sesser Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "zend_extensions.h"
#include "ext/standard/info.h"
#include "php_syslog.h"
#include "php_suhosin.h"
#include "zend_llist.h"
#include "zend_operators.h"
#include "SAPI.h"
#include "php_logos.h"
#include "suhosin_logo.h"

ZEND_DECLARE_MODULE_GLOBALS(suhosin)

static zend_llist_position lp = NULL;
static int (*old_startup)(zend_extension *extension) = NULL;
static zend_extension *ze = NULL;

static int suhosin_module_startup(zend_extension *extension);
static void suhosin_shutdown(zend_extension *extension);


static void suhosin_op_array_ctor(zend_op_array *op_array);
static void suhosin_op_array_dtor(zend_op_array *op_array);

STATIC zend_extension suhosin_zend_extension_entry = {
	"Suhosin",
	SUHOSIN_EXT_VERSION,
	"Hardened-PHP Project",
	"http://suhosin.hardened-php.net",
	"(C) Copyright 2006",
	
	suhosin_module_startup,
	suhosin_shutdown,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	suhosin_op_array_ctor,
	suhosin_op_array_dtor,
	
	STANDARD_ZEND_EXTENSION_PROPERTIES
};

static void suhosin_op_array_ctor(zend_op_array *op_array)
{
	TSRMLS_FETCH();

	if (suhosin_zend_extension_entry.resource_number != -1) {
	
		unsigned long suhosin_flags = 0;
		
		if (SUHOSIN_G(in_code_type) == SUHOSIN_EVAL) {
			suhosin_flags |= SUHOSIN_FLAG_CREATED_BY_EVAL;
		}
		
		op_array->reserved[suhosin_zend_extension_entry.resource_number] = (void *)suhosin_flags;
		
	}
}

static void suhosin_op_array_dtor(zend_op_array *op_array)
{
	if (suhosin_zend_extension_entry.resource_number != -1) {
		op_array->reserved[suhosin_zend_extension_entry.resource_number] = NULL;
	}
}

static int suhosin_module_startup(zend_extension *extension)
{
	zend_module_entry *module_entry_ptr;
	int resid;
	TSRMLS_FETCH();
	
/*	zend_register_module(&suhosin_module_entry TSRMLS_CC); */
	
	if (zend_hash_find(&module_registry, "suhosin", sizeof("suhosin"), (void **)&module_entry_ptr)==SUCCESS) {
		
		if (extension) {
		    extension->handle = module_entry_ptr->handle;
		} else {
		    zend_extension ext;
		    ext = suhosin_zend_extension_entry;
		    ext.handle = module_entry_ptr->handle;
		    zend_llist_add_element(&zend_extensions, &ext);
		    extension = zend_llist_get_last(&zend_extensions);
		}
		module_entry_ptr->handle = NULL;

	} else {
		return FAILURE;
	}

	if (SUHOSIN_G(apc_bug_workaround)) {
		resid = zend_get_resource_handle(extension);
	}
	resid = zend_get_resource_handle(extension);
	suhosin_zend_extension_entry.resource_number = resid;

	suhosin_hook_treat_data();
	suhosin_hook_post_handlers(TSRMLS_C);
	suhosin_aes_gentables();
	suhosin_hook_register_server_variables();
	suhosin_hook_header_handler();
	suhosin_hook_execute(TSRMLS_C);
	suhosin_hook_session(TSRMLS_C);


	return SUCCESS;
}


static void suhosin_shutdown(zend_extension *extension)
{
	suhosin_unhook_execute();
	suhosin_unhook_header_handler();
}



static int suhosin_startup_wrapper(zend_extension *ext)
{
	int res;
	
	ze->startup = old_startup;
	res = old_startup(ext);
	suhosin_module_startup(NULL);
	
	return res;
}

/*static zend_extension_version_info extension_version_info = { ZEND_EXTENSION_API_NO, ZEND_VERSION, ZTS_V, ZEND_DEBUG };*/


static ZEND_INI_MH(OnUpdateSuhosin_log_syslog)
{
	if (!new_value) {
		SUHOSIN_G(log_syslog) = (S_ALL & ~S_SQL) | S_MEMORY;
	} else {
		SUHOSIN_G(log_syslog) = atoi(new_value) | S_MEMORY;
	}
	return SUCCESS;
}
static ZEND_INI_MH(OnUpdateSuhosin_log_syslog_facility)
{
	if (!new_value) {
		SUHOSIN_G(log_syslog_facility) = LOG_USER;
	} else {
		SUHOSIN_G(log_syslog_facility) = atoi(new_value);
	}
	return SUCCESS;
}
static ZEND_INI_MH(OnUpdateSuhosin_log_syslog_priority)
{
	if (!new_value) {
		SUHOSIN_G(log_syslog_priority) = LOG_ALERT;
	} else {
		SUHOSIN_G(log_syslog_priority) = atoi(new_value);
	}
	return SUCCESS;
}
static ZEND_INI_MH(OnUpdateSuhosin_log_sapi)
{
	SDEBUG("(OnUpdateSuhosin_log_sapi) new_value: %s - stage: %u", new_value, stage);

	if (!new_value) {
		SUHOSIN_G(log_sapi) = (S_ALL & ~S_SQL);
	} else {
		SUHOSIN_G(log_sapi) = atoi(new_value);
	}
	return SUCCESS;
}
static ZEND_INI_MH(OnUpdateSuhosin_log_script)
{
	if (!new_value) {
		SUHOSIN_G(log_script) = S_ALL & ~S_MEMORY;
	} else {
		SUHOSIN_G(log_script) = atoi(new_value) & (~S_MEMORY) & (~S_INTERNAL);
	}
	return SUCCESS;
}
static ZEND_INI_MH(OnUpdateSuhosin_log_scriptname)
{
	if (SUHOSIN_G(log_scriptname)) {
		pefree(SUHOSIN_G(log_scriptname),1);
	}
        SUHOSIN_G(log_scriptname) = NULL;
	if (new_value) {
		SUHOSIN_G(log_scriptname) = pestrdup(new_value,1);
	}
	return SUCCESS;
}
static ZEND_INI_MH(OnUpdateSuhosin_log_phpscript)
{
	if (!new_value) {
		SUHOSIN_G(log_phpscript) = S_ALL & ~S_MEMORY;
	} else {
		SUHOSIN_G(log_phpscript) = atoi(new_value) & (~S_MEMORY) & (~S_INTERNAL);
	}
	return SUCCESS;
}

static ZEND_INI_MH(OnUpdate_include_whitelist)
{
	char *s = NULL, *e, *val;
	unsigned long dummy = 1;

	if (!new_value) {
include_whitelist_destroy:
		if (SUHOSIN_G(include_whitelist)) {
			zend_hash_destroy(SUHOSIN_G(include_whitelist));
			pefree(SUHOSIN_G(include_whitelist),1);
		}
		SUHOSIN_G(include_whitelist) = NULL;
		return SUCCESS;
	}
	if (!(*new_value)) {
		goto include_whitelist_destroy;
	}
	
	SUHOSIN_G(include_whitelist) = pemalloc(sizeof(HashTable), 1);
	zend_hash_init(SUHOSIN_G(include_whitelist), 5, NULL, NULL, 1);
	
	val = suhosin_str_tolower_dup(new_value, strlen(new_value));
	e = val;

	while (*e) {
		switch (*e) {
			case ' ':
			case ',':
				if (s) {
					*e = '\0';
					zend_hash_add(SUHOSIN_G(include_whitelist), s, e-s+1, &dummy, sizeof(unsigned long), NULL);
					s = NULL;
				}
				break;
			default:
				if (!s) {
					s = e;
				}
				break;
		}
		e++;
	}
	if (s) {
		zend_hash_add(SUHOSIN_G(include_whitelist), s, e-s+1, &dummy, sizeof(unsigned long), NULL);
	}
	efree(val);
	
	return SUCCESS;
}

static ZEND_INI_MH(OnUpdate_include_blacklist)
{
	char *s = NULL, *e, *val;
	unsigned long dummy = 1;

	if (!new_value) {
include_blacklist_destroy:
		if (SUHOSIN_G(include_blacklist)) {
			zend_hash_destroy(SUHOSIN_G(include_blacklist));
			pefree(SUHOSIN_G(include_blacklist),1);
		}
		SUHOSIN_G(include_blacklist) = NULL;
		return SUCCESS;
	}
	if (!(*new_value)) {
		goto include_blacklist_destroy;
	}
	
	SUHOSIN_G(include_blacklist) = pemalloc(sizeof(HashTable), 1);
	zend_hash_init(SUHOSIN_G(include_blacklist), 5, NULL, NULL, 1);
	
	val = suhosin_str_tolower_dup(new_value, strlen(new_value));
	e = val;

	while (*e) {
		switch (*e) {
			case ' ':
			case ',':
				if (s) {
					*e = '\0';
					zend_hash_add(SUHOSIN_G(include_blacklist), s, e-s+1, &dummy, sizeof(unsigned long), NULL);
					s = NULL;
				}
				break;
			default:
				if (!s) {
					s = e;
				}
				break;
		}
		e++;
	}
	if (s) {
		zend_hash_add(SUHOSIN_G(include_blacklist), s, e-s+1, &dummy, sizeof(unsigned long), NULL);
	}
	efree(val);
	
	return SUCCESS;
}

static ZEND_INI_MH(OnUpdate_eval_whitelist)
{
	char *s = NULL, *e, *val;
	unsigned long dummy = 1;

	if (!new_value) {
eval_whitelist_destroy:
		if (SUHOSIN_G(eval_whitelist)) {
			zend_hash_destroy(SUHOSIN_G(eval_whitelist));
			pefree(SUHOSIN_G(eval_whitelist),1);
		}
		SUHOSIN_G(eval_whitelist) = NULL;
		return SUCCESS;
	}
	if (!(*new_value)) {
		goto eval_whitelist_destroy;
	}
	
	SUHOSIN_G(eval_whitelist) = pemalloc(sizeof(HashTable), 1);
	zend_hash_init(SUHOSIN_G(eval_whitelist), 5, NULL, NULL, 1);
	
	val = suhosin_str_tolower_dup(new_value, strlen(new_value));
	e = val;

	while (*e) {
		switch (*e) {
			case ' ':
			case ',':
				if (s) {
					*e = '\0';
					zend_hash_add(SUHOSIN_G(eval_whitelist), s, e-s+1, &dummy, sizeof(unsigned long), NULL);
					s = NULL;
				}
				break;
			default:
				if (!s) {
					s = e;
				}
				break;
		}
		e++;
	}
	if (s) {
		zend_hash_add(SUHOSIN_G(eval_whitelist), s, e-s+1, &dummy, sizeof(unsigned long), NULL);
	}
	efree(val);
	
	return SUCCESS;
}

static ZEND_INI_MH(OnUpdate_eval_blacklist)
{
	char *s = NULL, *e, *val;
	unsigned long dummy = 1;

	if (!new_value) {
eval_blacklist_destroy:
		if (SUHOSIN_G(eval_blacklist)) {
			zend_hash_destroy(SUHOSIN_G(eval_blacklist));
			pefree(SUHOSIN_G(eval_blacklist), 1);
		}
		SUHOSIN_G(eval_blacklist) = NULL;
		return SUCCESS;
	}
	if (!(*new_value)) {
		goto eval_blacklist_destroy;
	}
	
	SUHOSIN_G(eval_blacklist) = pemalloc(sizeof(HashTable), 1);
	zend_hash_init(SUHOSIN_G(eval_blacklist), 5, NULL, NULL, 1);
	
	val = suhosin_str_tolower_dup(new_value, strlen(new_value));
	e = val;

	while (*e) {
		switch (*e) {
			case ' ':
			case ',':
				if (s) {
					*e = '\0';
					zend_hash_add(SUHOSIN_G(eval_blacklist), s, e-s+1, &dummy, sizeof(unsigned long), NULL);
					s = NULL;
				}
				break;
			default:
				if (!s) {
					s = e;
				}
				break;
		}
		e++;
	}
	if (s) {
		zend_hash_add(SUHOSIN_G(eval_blacklist), s, e-s+1, &dummy, sizeof(unsigned long), NULL);
	}
	efree(val);
	
	
	return SUCCESS;
}

static ZEND_INI_MH(OnUpdate_func_whitelist)
{
	char *s = NULL, *e, *val;
	unsigned long dummy = 1;

	if (!new_value) {
func_whitelist_destroy:
		if (SUHOSIN_G(func_whitelist)) {
			zend_hash_destroy(SUHOSIN_G(func_whitelist));
			pefree(SUHOSIN_G(func_whitelist),1);
		}
		SUHOSIN_G(func_whitelist) = NULL;
		return SUCCESS;
	}
	if (!(*new_value)) {
		goto func_whitelist_destroy;
	}
	
	SUHOSIN_G(func_whitelist) = pemalloc(sizeof(HashTable), 1);
	zend_hash_init(SUHOSIN_G(func_whitelist), 5, NULL, NULL, 1);
	
	val = suhosin_str_tolower_dup(new_value, strlen(new_value));
	e = val;

	while (*e) {
		switch (*e) {
			case ' ':
			case ',':
				if (s) {
					*e = '\0';
					zend_hash_add(SUHOSIN_G(func_whitelist), s, e-s+1, &dummy, sizeof(unsigned long), NULL);
					s = NULL;
				}
				break;
			default:
				if (!s) {
					s = e;
				}
				break;
		}
		e++;
	}
	if (s) {
		zend_hash_add(SUHOSIN_G(func_whitelist), s, e-s+1, &dummy, sizeof(unsigned long), NULL);
	}
	efree(val);
	
	return SUCCESS;
}

static ZEND_INI_MH(OnUpdate_func_blacklist)
{
	char *s = NULL, *e, *val;
	unsigned long dummy = 1;

	if (!new_value) {
func_blacklist_destroy:
		if (SUHOSIN_G(func_blacklist)) {
			zend_hash_destroy(SUHOSIN_G(func_blacklist));
			pefree(SUHOSIN_G(func_blacklist),1);
		}
		SUHOSIN_G(func_blacklist) = NULL;
		return SUCCESS;
	}
	if (!(*new_value)) {
		goto func_blacklist_destroy;
	}
	
	SUHOSIN_G(func_blacklist) = pemalloc(sizeof(HashTable), 1);
	zend_hash_init(SUHOSIN_G(func_blacklist), 5, NULL, NULL, 1);
	
	val = suhosin_str_tolower_dup(new_value, strlen(new_value));
	e = val;

	while (*e) {
		switch (*e) {
			case ' ':
			case ',':
				if (s) {
					*e = '\0';
					zend_hash_add(SUHOSIN_G(func_blacklist), s, e-s+1, &dummy, sizeof(unsigned long), NULL);
					s = NULL;
				}
				break;
			default:
				if (!s) {
					s = e;
				}
				break;
		}
		e++;
	}
	if (s) {
		zend_hash_add(SUHOSIN_G(func_blacklist), s, e-s+1, &dummy, sizeof(unsigned long), NULL);
	}
	efree(val);
	
	
	return SUCCESS;
}


/* {{{ suhosin_functions[]
 */
zend_function_entry suhosin_functions[] = {
	{NULL, NULL, NULL}	/* Must be the last line in suhosin_functions[] */
};
/* }}} */

/* {{{ suhosin_module_entry
 */
zend_module_entry suhosin_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"suhosin",
	suhosin_functions,
	PHP_MINIT(suhosin),
	PHP_MSHUTDOWN(suhosin),
	PHP_RINIT(suhosin),
	PHP_RSHUTDOWN(suhosin),
	PHP_MINFO(suhosin),
#if ZEND_MODULE_API_NO >= 20010901
	SUHOSIN_EXT_VERSION, /* Replace with version number for your extension */
#endif
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_SUHOSIN
ZEND_GET_MODULE(suhosin)
#endif

/* {{{ PHP_INI
 */
static zend_ini_entry shared_ini_entries[] = {
	ZEND_INI_ENTRY("suhosin.log.syslog",			NULL,		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateSuhosin_log_syslog)
	ZEND_INI_ENTRY("suhosin.log.syslog.facility",		NULL,		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateSuhosin_log_syslog_facility)
	ZEND_INI_ENTRY("suhosin.log.syslog.priority",		NULL,		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateSuhosin_log_syslog_priority)
	ZEND_INI_ENTRY("suhosin.log.sapi",				"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateSuhosin_log_sapi)
	ZEND_INI_ENTRY("suhosin.log.script",			"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateSuhosin_log_script)
	ZEND_INI_ENTRY("suhosin.log.script.name",			NULL,		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateSuhosin_log_scriptname)
	STD_ZEND_INI_BOOLEAN("suhosin.log.use-x-forwarded-for",	"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateBool, log_use_x_forwarded_for,	zend_suhosin_globals,	suhosin_globals)
	ZEND_INI_ENTRY("suhosin.log.phpscript",			"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateSuhosin_log_phpscript)
	STD_ZEND_INI_ENTRY("suhosin.log.phpscript.name",			NULL,		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateString, log_phpscriptname, zend_suhosin_globals, suhosin_globals)
	STD_ZEND_INI_BOOLEAN("suhosin.log.phpscript.is_safe",			"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateBool, log_phpscript_is_safe,	zend_suhosin_globals,	suhosin_globals)
ZEND_INI_END()
 
PHP_INI_BEGIN()

	STD_ZEND_INI_ENTRY("suhosin.executor.include.max_traversal",		"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateLong, executor_include_max_traversal,	zend_suhosin_globals,	suhosin_globals)
	ZEND_INI_ENTRY("suhosin.executor.include.whitelist",	NULL,		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdate_include_whitelist)
	ZEND_INI_ENTRY("suhosin.executor.include.blacklist",	NULL,		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdate_include_blacklist)
	ZEND_INI_ENTRY("suhosin.executor.eval.whitelist",	NULL,		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdate_eval_whitelist)
	ZEND_INI_ENTRY("suhosin.executor.eval.blacklist",	NULL,		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdate_eval_blacklist)
	ZEND_INI_ENTRY("suhosin.executor.func.whitelist",	NULL,		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdate_func_whitelist)
	ZEND_INI_ENTRY("suhosin.executor.func.blacklist",	NULL,		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdate_func_blacklist)
	STD_ZEND_INI_BOOLEAN("suhosin.executor.disable_eval",	"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateBool, executor_disable_eval,	zend_suhosin_globals,	suhosin_globals)
	STD_ZEND_INI_BOOLEAN("suhosin.executor.disable_emodifier",	"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateBool, executor_disable_emod,	zend_suhosin_globals,	suhosin_globals)

	STD_ZEND_INI_BOOLEAN("suhosin.executor.allow_symlink",	"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateBool, executor_allow_symlink,	zend_suhosin_globals,	suhosin_globals)
	STD_ZEND_INI_ENTRY("suhosin.executor.max_depth",		"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateLong, max_execution_depth,	zend_suhosin_globals,	suhosin_globals)
	STD_ZEND_INI_BOOLEAN("suhosin.sql.bailout_on_error",	"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateBool, sql_bailout_on_error,	zend_suhosin_globals,	suhosin_globals)
	STD_ZEND_INI_BOOLEAN("suhosin.multiheader",		"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateBool, allow_multiheader,	zend_suhosin_globals,	suhosin_globals)
	
	STD_ZEND_INI_BOOLEAN("suhosin.simulation",		"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateBool, simulation,	zend_suhosin_globals,	suhosin_globals)
	STD_ZEND_INI_BOOLEAN("suhosin.coredump",		"0",		ZEND_INI_SYSTEM,	OnUpdateBool, coredump,	zend_suhosin_globals,	suhosin_globals)
	STD_ZEND_INI_BOOLEAN("suhosin.apc_bug_workaround",		"0",		ZEND_INI_SYSTEM,	OnUpdateBool, apc_bug_workaround,	zend_suhosin_globals,	suhosin_globals)
	
	STD_ZEND_INI_ENTRY("suhosin.mail.protect",		"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateLong, mailprotect,	zend_suhosin_globals,	suhosin_globals)
	STD_ZEND_INI_ENTRY("suhosin.memory_limit",		"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateLong, memory_limit,	zend_suhosin_globals,	suhosin_globals)
	

        STD_PHP_INI_ENTRY("suhosin.request.max_vars", "200", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, max_request_variables, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.request.max_varname_length", "64", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, max_varname_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.request.max_value_length", "65000", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, max_value_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.request.max_array_depth", "100", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, max_array_depth, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.request.max_totalname_length", "256", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, max_totalname_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.request.max_array_index_length", "64", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, max_array_index_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.request.disallow_nul", "1", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateBool, disallow_nul, zend_suhosin_globals, suhosin_globals)
    
        STD_PHP_INI_ENTRY("suhosin.cookie.max_vars", "100", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, max_cookie_vars, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.cookie.max_name_length", "64", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, max_cookie_name_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.cookie.max_totalname_length", "256", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, max_cookie_totalname_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.cookie.max_value_length", "10000", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, max_cookie_value_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.cookie.max_array_depth", "100", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, max_cookie_array_depth, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.cookie.max_array_index_length", "64", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, max_cookie_array_index_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.cookie.disallow_nul", "1", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateBool, disallow_cookie_nul, zend_suhosin_globals, suhosin_globals)

        STD_PHP_INI_ENTRY("suhosin.get.max_vars", "100", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, max_get_vars, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.get.max_name_length", "64", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, max_get_name_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.get.max_totalname_length", "256", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, max_get_totalname_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.get.max_value_length", "512", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, max_get_value_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.get.max_array_depth", "50", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, max_get_array_depth, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.get.max_array_index_length", "64", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, max_get_array_index_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.get.disallow_nul", "1", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateBool, disallow_get_nul, zend_suhosin_globals, suhosin_globals)

        STD_PHP_INI_ENTRY("suhosin.post.max_vars", "200", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, max_post_vars, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.post.max_name_length", "64", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, max_post_name_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.post.max_totalname_length", "256", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, max_post_totalname_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.post.max_value_length", "65000", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, max_post_value_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.post.max_array_depth", "100", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, max_post_array_depth, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.post.max_array_index_length", "64", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, max_post_array_index_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.post.disallow_nul", "1", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateBool, disallow_post_nul, zend_suhosin_globals, suhosin_globals)

        STD_PHP_INI_ENTRY("suhosin.upload.max_uploads", "25", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, upload_limit, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.upload.disallow_elf", "1", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateBool, upload_disallow_elf, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.upload.disallow_binary", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateBool, upload_disallow_binary, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.upload.remove_binary", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateBool, upload_remove_binary, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.upload.verification_script", NULL, PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateString, upload_verification_script, zend_suhosin_globals, suhosin_globals)

        STD_PHP_INI_ENTRY("suhosin.filter.action", NULL, PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateString, filter_action, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.sql.user_prefix", NULL, PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateString, sql_user_prefix, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.sql.user_postfix", NULL, PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateString, sql_user_postfix, zend_suhosin_globals, suhosin_globals)
    
	STD_ZEND_INI_BOOLEAN("suhosin.session.encrypt",		"1",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateBool, session_encrypt,	zend_suhosin_globals,	suhosin_globals)
	STD_PHP_INI_ENTRY("suhosin.session.cryptkey", "", PHP_INI_ALL, OnUpdateString, session_cryptkey, zend_suhosin_globals, suhosin_globals)
	STD_ZEND_INI_BOOLEAN("suhosin.session.cryptua",		"1",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateBool, session_cryptua,	zend_suhosin_globals,	suhosin_globals)
	STD_ZEND_INI_BOOLEAN("suhosin.session.cryptdocroot",		"1",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateBool, session_cryptdocroot,	zend_suhosin_globals,	suhosin_globals)
	STD_PHP_INI_ENTRY("suhosin.session.cryptraddr", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, session_cryptraddr, zend_suhosin_globals, suhosin_globals)	
	STD_PHP_INI_ENTRY("suhosin.session.max_id_length", "128", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, session_max_id_length, zend_suhosin_globals, suhosin_globals)
	

	STD_ZEND_INI_BOOLEAN("suhosin.cookie.encrypt",		"1",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateBool, cookie_encrypt,	zend_suhosin_globals,	suhosin_globals)
	STD_PHP_INI_ENTRY("suhosin.cookie.cryptkey", "", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateString, cookie_cryptkey, zend_suhosin_globals, suhosin_globals)
	STD_ZEND_INI_BOOLEAN("suhosin.cookie.cryptua",		"1",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateBool, cookie_cryptua,	zend_suhosin_globals,	suhosin_globals)
	STD_ZEND_INI_BOOLEAN("suhosin.cookie.cryptdocroot",		"1",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateBool, cookie_cryptdocroot,	zend_suhosin_globals,	suhosin_globals)
	STD_PHP_INI_ENTRY("suhosin.cookie.cryptraddr", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, cookie_cryptraddr, zend_suhosin_globals, suhosin_globals)	

PHP_INI_END()
/* }}} */


/* {{{ php_suhosin_init_globals
 */
void suhosin_bailout(TSRMLS_D)
{
	if (!SUHOSIN_G(simulation)) {
		zend_bailout();
	}
}
/* }}} */

/* {{{ php_suhosin_init_globals
 */
STATIC void php_suhosin_init_globals(zend_suhosin_globals *suhosin_globals)
{
	memset(suhosin_globals, 0, sizeof(zend_suhosin_globals));
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(suhosin)
{
	SDEBUG("(MINIT)");
	ZEND_INIT_MODULE_GLOBALS(suhosin, php_suhosin_init_globals, NULL);

	/* only register constants if they have not previously been registered by a possible patched PHP */
	
	if (zend_hash_exists(EG(zend_constants), "S_MEMORY", sizeof("S_MEMORY"))==0) {
		REGISTER_MAIN_LONG_CONSTANT("S_MEMORY", S_MEMORY, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_VARS", S_VARS, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_FILES", S_FILES, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_INCLUDE", S_INCLUDE, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_SQL", S_SQL, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_EXECUTOR", S_EXECUTOR, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_MAIL", S_MAIL, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_SESSION", S_SESSION, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_MISC", S_MISC, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_INTERNAL", S_INTERNAL, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_ALL", S_ALL, CONST_PERSISTENT | CONST_CS);
	}
	
	/* check if shared ini directives are already known (maybe a patched PHP) */
	if (zend_hash_exists(EG(ini_directives), "suhosin.log.syslog", sizeof("suhosin.log.syslog"))) {
	
		/* and update them */
		zend_ini_entry *p = (zend_ini_entry *)&shared_ini_entries;
		
		while (p->name) {
		
			zend_ini_entry *i;
			
			if (zend_hash_find(EG(ini_directives), p->name, p->name_length, (void **) &i)==FAILURE) {
				/* continue registering them */
				zend_register_ini_entries(p, module_number TSRMLS_CC);
				break;
			}
			
			SDEBUG("updating ini %s=%s", i->name, i->value);
			
#ifdef ZEND_ENGINE_2
			i->modifiable = p->modifiable;
#else
			i->modifyable = p->modifyable;
#endif
			i->module_number = module_number;
			i->on_modify = p->on_modify;
			i->mh_arg1 = p->mh_arg1;
			i->mh_arg2 = p->mh_arg2;
			i->mh_arg3 = p->mh_arg3;
			i->on_modify(i, i->value, i->value_length, i->mh_arg1, i->mh_arg2, i->mh_arg3, ZEND_INI_STAGE_ACTIVATE TSRMLS_CC);
			p++;
		}
	} else {
	
		/* not registered yet, then simply use the API */
		zend_register_ini_entries((zend_ini_entry *)&shared_ini_entries, module_number TSRMLS_CC);
		
	}

	/* and register the rest of the ini entries */
	REGISTER_INI_ENTRIES();
	
	/* Load invisible to other Zend Extensions */
	if (zend_llist_count(&zend_extensions)==0) {
		zend_extension extension;
		extension = suhosin_zend_extension_entry;
		extension.handle = NULL;
		zend_llist_add_element(&zend_extensions, &extension);
	} else {
		ze = (zend_extension *)zend_llist_get_last_ex(&zend_extensions, &lp);
		old_startup = ze->startup;
		ze->startup = suhosin_startup_wrapper;
	}

	/* now hook a bunch of stuff */
	suhosin_hook_memory_limit();
	suhosin_hook_crypt();
	suhosin_hook_sha256();
	suhosin_hook_ex_imp();

	/* register the logo for phpinfo */
	php_register_info_logo(SUHOSIN_LOGO_GUID, "image/jpeg", suhosin_logo, sizeof(suhosin_logo));

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(suhosin)
{
	SDEBUG("(MSHUTDOWN)");
	UNREGISTER_INI_ENTRIES();
	return SUCCESS;
}
/* }}} */


/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(suhosin)
{
	SDEBUG("(RINIT)");
	SUHOSIN_G(in_code_type) = SUHOSIN_NORMAL;
	SUHOSIN_G(execution_depth) = 0;

	return SUCCESS;
}
/* }}} */


/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(suhosin)
{
	SDEBUG("(RSHUTDOWN)");
	
	/* We need to clear the input filtering 
	   variables in the request shutdown
	   because input filtering is done before 
	   RINIT */
	   
	SUHOSIN_G(cur_request_variables) = 0;
	SUHOSIN_G(cur_cookie_vars) = 0;
	SUHOSIN_G(cur_get_vars) = 0;
	SUHOSIN_G(cur_post_vars) = 0;
	SUHOSIN_G(num_uploads) = 0;

        SUHOSIN_G(no_more_variables) = 0;
        SUHOSIN_G(no_more_get_variables) = 0;
        SUHOSIN_G(no_more_post_variables) = 0;
        SUHOSIN_G(no_more_cookie_variables) = 0;
        SUHOSIN_G(no_more_uploads) = 0;
	
	SUHOSIN_G(abort_request) = 0;
	
	if (SUHOSIN_G(decrypted_cookie)) {
		efree(SUHOSIN_G(decrypted_cookie));
		SUHOSIN_G(decrypted_cookie)=NULL;
	}
	
	return SUCCESS;
}
/* }}} */


/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(suhosin)
{
	php_info_print_box_start(0);
	if (PG(expose_php) && !sapi_module.phpinfo_as_text) {
		PUTS("<a href=\"http://www.hardened-php.net/suhosin/index.html\"><img border=\"0\" src=\"");
		if (SG(request_info).request_uri) {
			char *elem_esc = php_info_html_esc(SG(request_info).request_uri TSRMLS_CC);
			PUTS(elem_esc);
			efree(elem_esc);
		}
		PUTS("?="SUHOSIN_LOGO_GUID"\" alt=\"Suhosin logo\" /></a>\n");
	}
	PUTS("This server is protected with the Suhosin Extension " SUHOSIN_EXT_VERSION);
	PUTS(!sapi_module.phpinfo_as_text?"<br /><br />":"\n\n");
	if (sapi_module.phpinfo_as_text) {
		PUTS("Copyright (c) 2006 Hardened-PHP Project\n");
	} else {
		PUTS("Copyright (c) 2006 <a href=\"http://www.hardened-php.net/\">Hardened-PHP Project</a>\n");
	}
	php_info_print_box_end();


	DISPLAY_INI_ENTRIES();
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
