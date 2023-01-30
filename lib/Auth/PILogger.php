<?php

require_once((dirname(__FILE__, 2)) . '/php-client/src/Client-Autoloader.php');

class PILogger implements PILog
{
    /**
     * This function allows to show the debug messages from privacyIDEA server
     * @param $message
     */
    public function piDebug($message)
    {
        SimpleSAML_Logger::debug($message);
    }

    /**
     * This function allows to show the debug messages from privacyIDEA server
     * @param $message
     */
    public function piError($message)
    {
        SimpleSAML_Logger::error($message);
    }
}