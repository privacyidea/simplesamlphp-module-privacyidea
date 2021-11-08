<?php

/**
 * Interface PILog
 * Call the functions that collect debug and error messages
 */
interface PILog
{
    public function piDebug($message);

    public function piError($message);
}