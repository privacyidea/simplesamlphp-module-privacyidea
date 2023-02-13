<?php

namespace SimpleSAML\Module\privacyidea\Auth;

use PILog;
use SimpleSAML\Logger;

class PILogger implements PILog
{
    /**
     * This function allows to show the debug messages from privacyIDEA server
     * @param $message
     */
    public function piDebug($message)
    {
        Logger::debug($message);
    }

    /**
     * This function allows to show the debug messages from privacyIDEA server
     * @param $message
     */
    public function piError($message)
    {
        Logger::error($message);
    }
}