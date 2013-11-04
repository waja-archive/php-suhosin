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

/* $Id: sha256.h,v 1.3 2006-08-24 22:40:16 sesser Exp $ */

#ifndef SHA256_H
#define SHA256_H

#include "ext/standard/basic_functions.h"

/* SHA1 context. */
typedef struct {
	php_uint32 state[8];		/* state (ABCD) */
	php_uint32 count[2];		/* number of bits, modulo 2^64 (lsb first) */
	unsigned char buffer[64];	/* input buffer */
} suhosin_SHA256_CTX;

void suhosin_SHA256Init(suhosin_SHA256_CTX *);
void suhosin_SHA256Update(suhosin_SHA256_CTX *, const unsigned char *, unsigned int);
void suhosin_SHA256Final(unsigned char[32], suhosin_SHA256_CTX *);

#endif
