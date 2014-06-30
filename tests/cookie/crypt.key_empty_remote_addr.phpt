--TEST--
cookie encryption with empty key and REMOTE_ADDR set
--SKIPIF--
<?php include "../skipif.inc"; ?>
--INI--
suhosin.cookie.encrypt=1
suhosin.cookie.cryptkey=
suhosin.cookie.cryptua=0
suhosin.cookie.cryptdocroot=0
suhosin.cookie.cryptraddr=0
suhosin.cookie.checkraddr=0
;suhosin.cookie.cryptlist=
;suhosin.cookie.plainlist=
--ENV--
return <<<END
REMOTE_ADDR=127.0.0.1
END;
--COOKIE--
a=b
--FILE--
<?php
setcookie('foo', 'bar');
$ch = preg_grep("/^Set-Cookie:/", headers_list());
echo join("\n", array_values($ch));
?>
--EXPECTF--
Set-Cookie: foo=EgJxlQxzPwoAcVFj395vssv3hy1rAem1lH9qZYUvRi8.