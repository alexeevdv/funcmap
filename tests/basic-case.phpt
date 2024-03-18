--TEST--
Checks if the method call is logged
--INI--
funcmap.enabled=on
funcmap.log_format="%s"
--FILE--
<?php
funcmap_enable(true);

class Test {
    function test() {
        echo "code works\n";
    }
}

for ($i = 0; $i < 5; ++ $i) {
    (new Test)->test();
}

funcmap_enable(false);
funcmap_flush();
?>
--EXPECT--
code works
code works
code works
code works
code works
Test::test
