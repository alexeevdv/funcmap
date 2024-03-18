--TEST--
Checks if the method call is logged
--INI--
funcmap.enabled=on
funcmap.log_format="%message%"
--FILE--
<?php
class Test {
    function test() {
        echo "code works\n";
    }
}

for ($i = 0; $i < 5; ++ $i) {
    (new Test)->test();
}

?>
--EXPECT--
code works
code works
code works
code works
code works
Test::test
