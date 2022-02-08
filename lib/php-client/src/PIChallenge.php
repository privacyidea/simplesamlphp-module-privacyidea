<?php

namespace PrivacyIdea\PHPClient;

class PIChallenge
{
    /* @var string Token's type. */
    public $type = "";
    /* @var string Message from single challenge. */
    public $message = "";
    /* @var string */
    public $transactionID = "";
    /* @var string Token's serial. */
    public $serial = "";
    /* @var string */
    public $attributes = "";
    /* @var string JSON format */
    public $webAuthnSignRequest = "";
    /* @var string JSON format */
    public $u2fSignRequest = "";
}