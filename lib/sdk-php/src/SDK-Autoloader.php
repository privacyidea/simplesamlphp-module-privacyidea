<?php

/**
 * Include all files you need to authenticate against privacyIDEA
 * All that files are placed in privacyIDEA-PHP-SDK direction
 */

spl_autoload_register('autoLoader');

function autoLoader($className)
{
    $fullPath = dirname(__FILE__) . "/" . $className . ".php";
    if (file_exists($fullPath)) {
        require_once $fullPath;
        return true;
    } else {
        return false;
    }
}