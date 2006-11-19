dnl $Id: config.m4,v 1.2 2006-08-17 08:07:15 sesser Exp $
dnl config.m4 for extension suhosin

PHP_ARG_ENABLE(suhosin, whether to enable suhosin support,
[  --enable-suhosin        Enable suhosin support])

if test "$PHP_SUHOSIN" != "no"; then
  PHP_NEW_EXTENSION(suhosin, suhosin.c crypt.c crypt_blowfish.c sha256.c memory_limit.c treat_data.c ifilter.c post_handler.c ufilter.c rfc1867.c log.c header.c execute.c ex_imp.c session.c aes.c, $ext_shared)
fi
