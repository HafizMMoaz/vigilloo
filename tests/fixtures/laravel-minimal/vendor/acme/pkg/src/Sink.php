<?php
namespace Acme\Pkg;

class Sink
{
    public static function execute($cmd)
    {
        system($cmd);
    }
}
