<?php

namespace PrivacyIdea\PHPClient;

class PIResponse
{
    /* @var string All tokens messages which are sent by PI and can be used in UI to help user interact with service. */
    public $messages = "";
    /* @var string Transaction ID which is needed by some PI API requests. */
    public $transactionID = "";
    /* @var string This is the raw PI response in JSON format. */
    public $raw = "";
    /* @var array Here are all triggered challenges delivered as object of PIChallenge class. */
    public $multiChallenge = array();
    /* @var bool The status indicates if the request was processed correctly by the server. */
    public $status = false;
    /* @var bool The value tell us if authentication was successful. */
    public $value = false;
    /* @var array All interesting details about user which can be shown in the UI at the end of the authentication. */
    public $detailAndAttributes = array();
    /* @var string PI error code will be delivered here. */
    public $errorCode;
    /* @var string PI error message will be delivered here. */
    public $errorMessage;

    /**
     * Prepare a good readable PI response and return it as an object
     * @param $json
     * @param PrivacyIDEA $privacyIDEA
     * @return PIResponse|null
     */
    public static function fromJSON($json, PrivacyIDEA $privacyIDEA)
    {
        assert('string' === gettype($json));

        if ($json == null || $json == "")
        {
            $privacyIDEA->errorLog("PrivacyIDEA - PIResponse: No response from PI.");
            return null;
        }

        // Build an PIResponse object and decode the response from JSON to PHP
        $ret = new PIResponse();
        $map = json_decode($json, true);

        // If wrong response format - throw error
        if ($map == null)
        {
            $privacyIDEA->errorLog("PrivacyIDEA - PIResponse: Response from PI was in wrong format. JSON expected.");
            return null;
        }

        // Prepare raw JSON Response if needed
        $ret->raw = $json;

        // Possibility to show an error message from PI server if no value
        if (!isset($map['result']['value']))
        {
            $ret->errorCode = $map['result']['error']['code'];
            $ret->errorMessage = $map['result']['error']['message'];
            return $ret;
        }

        // Set information from PI response to property
        if (isset($map['detail']['messages']))
        {
            $ret->messages = implode(", ", array_unique($map['detail']['messages'])) ?: "";
        }
        if (isset($map['detail']['transaction_id']))
        {
            $ret->transactionID = $map['detail']['transaction_id'];
        }
        $ret->status = $map['result']['status'] ?: false;
        $ret->value = $map['result']['value'] ?: false;

        // Prepare attributes and detail
        if (!empty($map['detail']['user']))
        {
            $attributes = $map['detail']['user'];
            $detail = $map['detail'];

            if (isset($attributes['username']))
            {
                $attributes['realm'] = $map['detail']['user-realm'] ?: "";
                $attributes['resolver'] = $map['detail']['user-resolver'] ?: "";
            }
            $ret->detailAndAttributes = array("detail" => $detail, "attributes" => $attributes);
        }

        // Set all challenges to objects and set it all to one array
        if (isset($map['detail']['multi_challenge']))
        {
            $mc = $map['detail']['multi_challenge'];
            foreach ($mc as $challenge)
            {
                $tmp = new PIChallenge();
                $tmp->transactionID = $challenge['transaction_id'];
                $tmp->message = $challenge['message'];
                $tmp->serial = $challenge['serial'];
                $tmp->type = $challenge['type'];
                if (isset($challenge['attributes']))
                {
                    $tmp->attributes = $challenge['attributes'];
                }

                if ($tmp->type === "webauthn")
                {
                    $t = $challenge['attributes']['webAuthnSignRequest'];
                    $tmp->webAuthnSignRequest = json_encode($t);
                }

                if ($tmp->type === "u2f")
                {
                    $t = $challenge['attributes']['u2fSignRequest'];
                    $tmp->u2fSignRequest = json_encode($t);
                }

                array_push($ret->multiChallenge, $tmp);
            }
        }
        return $ret;
    }

    /**
     * Get array with all triggered token types.
     * @return array
     */
    public function triggeredTokenTypes()
    {
        $ret = array();
        foreach ($this->multiChallenge as $challenge)
        {
            array_push($ret, $challenge->type);
        }
        return array_unique($ret);
    }

    /**
     * Get OTP message if OTP token(s) triggered.
     * @return string
     */
    public function otpMessage()
    {
        foreach ($this->multiChallenge as $challenge)
        {
            if ($challenge->type !== "push" && $challenge->type !== "webauthn")
            {
                return $challenge->message;
            }
        }
        return false;
    }

    /**
     * Get push message if push token triggered.
     * @return string
     */
    public function pushMessage()
    {
        foreach ($this->multiChallenge as $challenge)
        {
            if ($challenge->type === "push")
            {
                return $challenge->message;
            }
        }
        return "";
    }

    /**
     * Get WebAuthn message if that kind of token triggered.
     * @return string
     */
    public function webauthnMessage()
    {
        foreach ($this->multiChallenge as $challenge)
        {
            if ($challenge->type === "webauthn")
            {
                return $challenge->message;
            }
        }
        return "";
    }

    /**
     * Get WebAuthn Sign Request which comes in PIResponse if WebAuthn token is triggered.
     * @return string
     */
    public function webAuthnSignRequest()
    {
        $arr = [];
        $webauthn = "";
        foreach ($this->multiChallenge as $challenge)
        {
            if ($challenge->type === "webauthn")
            {
                $t = json_decode($challenge->webAuthnSignRequest);
                if (empty($webauthn))
                {
                    $webauthn = $t;
                }
                $arr[] = $challenge->attributes['webAuthnSignRequest']['allowCredentials'][0];
            }
        }
        $webauthn->allowCredentials = $arr;

        return json_encode($webauthn);
    }

    public function u2fSignRequest()
    {
        $ret = "";
        foreach ($this->multiChallenge as $challenge)
        {
            if ($challenge->type === "u2f")
            {
                $ret = $challenge->u2fSignRequest;
                break;
            }
        }
        return $ret;
    }
}
