<?php
class ExampleTest {
    public function test_something() {
        dd('test'); // should NOT fire
        dump('test'); // should NOT fire
    }
}
