<?php

require_once((dirname(__FILE__, 2)) . '/php-client/src/Client-Autoloader.php');

class sspmod_privacyidea_Auth_utils
{
    /**
     * Perform 2FA given the current state and the inputs from the form.
     *
     * @param array $state state
     * @param array $formParams inputs from the form
     * @param array $serverConfig
     * @return PIResponse|null An array containing attributes and detail, or NULL.
     * @throws PIBadRequestException
     */
    public static function authenticatePI(array &$state, array $formParams, array $serverConfig)
    {
        assert('array' === gettype($state));
        assert('array' === gettype($formParams));
        assert('array' === gettype($serverConfig));

        SimpleSAML_Logger::debug("utils::authenticatePI...");
        SimpleSAML_Logger::debug("Form data: " . http_build_query($formParams, '', ', '));
        SimpleSAML_Logger::debug("Server config: " . http_build_query($serverConfig, '', ', '));

        $state['privacyidea:privacyidea:ui']['mode'] = $formParams['mode'];

        if ($formParams["modeChanged"] == "1")
        {
            $state['privacyidea:privacyidea:ui']['loadCounter'] = 1;
            return null;
        }

        if (empty($formParams['username']))
        {

            if ($state['privacyidea:privacyidea']['authenticationMethod'] === "authsource")
            {
                $username = $state['privacyidea:privacyidea']['username'];
            }
            else
            {
                $username = $state["Attributes"][$serverConfig['uidKey']][0];
            }
        }
        else
        {
            $username = $formParams['username'];
        }

        $pi = new PrivacyIDEA("simpleSAMLphp", $serverConfig['privacyideaServerURL']);
        $pi->sslVerifyHost = $serverConfig['sslVerifyHost'];
        $pi->sslVerifyPeer = $serverConfig['sslVerifyPeer'];
        $pi->realm = @$serverConfig['realm'] ?: "";

        $response = null;
        $transactionID = $state['privacyidea:privacyidea']['transactionID'];

        // Send a request according to the mode
        if ($formParams['mode'] == "push")
        {
            if ($pi->pollTransaction($transactionID))
            {
                // If the authentication has been confirmed on the phone, the authentication has to be finalized with a
                // call to /validate/check with an empty pass
                // https://privacyidea.readthedocs.io/en/latest/tokens/authentication_modes.html#outofband-mode
                $response = $pi->validateCheck($username, "", $transactionID);
            }
            else
            {
                SimpleSAML_Logger::debug("privacyIDEA: PUSH not confirmed yet");
            }

        }
        elseif ($formParams['mode'] == "u2f")
        {
            $u2fSignResponse = $formParams['u2fSignResponse'];

            if (empty($u2fSignResponse))
            {
                SimpleSAML_Logger::error("Incomplete data for U2F authentication: u2fSignResponse is missing!");
            }
            else
            {
                $response = $pi->validateCheckU2F($username, $transactionID, $u2fSignResponse);
            }
        }
        elseif ($formParams['mode'] == "webauthn")
        {
            $origin = $formParams['origin'];
            $webAuthnSignResponse = $formParams['webAuthnSignResponse'];

            if (empty($origin) || empty($webAuthnSignResponse))
            {
                SimpleSAML_Logger::error("Incomplete data for WebAuthn authentication: WebAuthnSignResponse or Origin is missing!");
            }
            else
            {
                $response = $pi->validateCheckWebAuthn($username, $transactionID, $webAuthnSignResponse, $origin);
            }
        }
        else
        {
            $response = $pi->validateCheck($username, $formParams["otp"], $transactionID);
        }
        $counter = $formParams['loadCounter'];
        $state['privacyidea:privacyidea:ui']['loadCounter'] = $counter + 1;
        return $response;
    }

    /**
     * Write SSO specific data to the session and register a logout handler. The logout handler has to be attached to an
     * authority which is also obtained from the session. If there are no valid authorities, this function does nothing.
     * The first authority returned by SSP is used. Authorities are validated before they are returned so the authority
     * that is used can be considered valid.
     *
     * @param $state
     * @return void
     */
    public static function tryWriteSSO($state)
    {
        SimpleSAML_Logger::debug("privacyIDEA: tryWriteSSO");

        $session = SimpleSAML_Session::getSessionFromRequest();
        // First get the authority to register the logout handler for
        $authorities = $session->getAuthorities();
        if (empty($authorities))
        {
            SimpleSAML_Logger::error("privacyIDEA: Cannot use SSO because there is no authority configured to register the logout handler for!");
            return;
        }

        $authority = $authorities[0];
        SimpleSAML_Logger::debug("privacyIDEA: Registering logout handler for authority " .  $authority);

        $session->registerLogoutHandler(
            $authority,
            \sspmod_privacyidea_Auth_utils::class,
            'handleLogout'
        );
        $session->setData('privacyidea:privacyidea:sso', "2FA-success", true);
        SimpleSAML_Logger::debug("privacyIDEA: SSO data written and logout handler registered.");
    }

    /**
     * Check the state for data indicating an active login. If such data is present, check if SSO data of our
     * module is present, indicating that 2FA was completed before.
     * A boolean is returned to indicate if the login/2FA can be skipped.
     *
     * @param $state
     * @return boolean true if login/2FA can be skipped, false if not
     */
    public static function checkForValidSSO($state)
    {
        SimpleSAML_Logger::debug("privacyIDEA: checkForValidSSO");

        // For SSO to be valid, we check 2 things:
        // 1. Valid login of SSP which is not expired
        // 2. Completed 2FA with this module
        if(is_array($state) && array_key_exists('Expire', $state) && $state['Expire'] > time())
        {
            SimpleSAML_Logger::debug("privacyIDEA: Valid login found. Checking for valid 2FA..");
            $session = SimpleSAML_Session::getSessionFromRequest();
            $success = $ssoData = $session->getData('privacyidea:privacyidea:sso', '2FA-success');
            return $success;
        }
        else
        {
            SimpleSAML_Logger::debug("privacyIDEA: No valid login found or state is not an array.");
        }
        return false;
    }

    /**
     * This function is registered as a logout handler when writing the SSO specific data to the session.
     * When called, it removes SSO data on logout.
     *
     * @return void
     * @throws Exception
     */
    public static function handleLogout()
    {
        SimpleSAML_Logger::debug("privacyIDEA: Logout handler called. Removing SSO data.");
        SimpleSAML_Session::getSessionFromRequest()->deleteData('privacyidea:privacyidea:sso', "2FA-success");
    }

    /**
     * Process the response from privacyIDEA and write information for the next step to the state.
     * If the response from privacyIDEA indicates success and this module is used as AuthProcFilter,
     * this function will resume the processing chain and not return.
     *
     * @param string $stateID to load the state
     * @param mixed $response from privacyIDEA
     * @return string stateID of the modified state
     * @throws Exception
     */
    public static function processPIResponse($stateID, PIResponse $response, $config = null)
    {
        assert('string' === gettype($stateID));

        $state = SimpleSAML_Auth_State::loadState($stateID, 'privacyidea:privacyidea');
        $state['privacyidea:privacyidea:ui']['mode'] = "otp";

        if (!empty($response->multiChallenge))
        {
            // Preferred token type
            if ($config !== null)
            {
                $preferred = $config['preferredTokenType'];
                if (!empty($preferred))
                {
                    if (in_array($preferred, $response->triggeredTokenTypes()))
                    {
                        SimpleSAML_Logger::debug("Found preferred token type: " . $preferred);
                        $state['privacyidea:privacyidea:ui']['mode'] = $preferred;
                    }
                }
            }

            $state['privacyidea:privacyidea:ui']['pushAvailable'] = in_array("push", $triggeredTokens);
            $state['privacyidea:privacyidea:ui']['otpAvailable'] = true; // Always show otp field
            $state['privacyidea:privacyidea:ui']['message'] = $response->messages;

            if(in_array("webauthn", $triggeredTokens))
            {
                $state['privacyidea:privacyidea:ui']['webAuthnSignRequest'] = $response->webAuthnSignRequest();
            }

            if(in_array("u2f", $triggeredTokens))
            {
                $state['privacyidea:privacyidea:ui']['u2fSignRequest'] = $response->u2fSignRequest();
            }

            $state['privacyidea:privacyidea']['transactionID'] = $response->transactionID;
        }
        elseif ($response->value)
        {
            SimpleSAML_Logger::debug("privacyIDEA: User authenticated successfully!");

            // Write data for SSO if enabled
            if(array_key_exists('SSO', $state['privacyidea:serverconfig']) &&
                $state['privacyidea:serverconfig']['SSO'] == true)
            {
                sspmod_privacyidea_Auth_utils::tryWriteSSO($state);
            }

            // If called from AuthProcFilter, the authentication ends here
            if ($state['privacyidea:privacyidea']['authenticationMethod'] === "authprocess")
            {
                SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea');
                SimpleSAML_Auth_ProcessingChain::resumeProcessing($state);
            }
        }
        elseif (!empty($response->errorCode))
        {
            SimpleSAML_Logger::error("PrivacyIDEA server: Error code: " . $response->errorCode . ", Error message: " . $response->errorMessage);
            $state['privacyidea:privacyidea']['errorCode'] = $response->errorCode;
            $state['privacyidea:privacyidea']['errorMessage'] = $response->errorMessage;
        }
        else
        {
            SimpleSAML_Logger::error("privacyIDEA: " . $response->message);
            $state['privacyidea:privacyidea']['errorMessage'] = $response->message;
        }
        return SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea');
    }

    /**
     * Determine the clients IP-Address.
     * @return string|null The IP-Address of the client.
     */
    public static function getClientIP()
    {
        $result = @$_SERVER['HTTP_X_FORWARDED_FOR'] ?: @$_SERVER['REMOTE_ADDR'] ?: @$_SERVER['HTTP_CLIENT_IP'];
        SimpleSAML_Logger::debug('privacyIDEA: client ip: ' . $result);
        return $result;
    }

    /**
     * Find the first usable uid key.
     * If the administrator has configured multiple uidKeys,
     * this will find the first one that exists as an Attribute in
     * the $state and update the $config to use that key.
     * @param array $config The authproc configuration to use
     * @param array $state The global state to check the keys against
     * @return array The updated config
     */
    public static function checkUidKey(array $config, array $state)
    {
        assert('array' === gettype($config));
        assert('array' === gettype($state));

        if (gettype($config['uidKey']) === "array" && !empty($config['uidKey']))
        {
            foreach ($config['uidKey'] as $i)
            {
                if (isset($state['Attributes'][$i][0]))
                {
                    $config['uidKey'] = $i;
                }
            }
        }
        return $config;
    }

    /**
     * Check if PrivacyIDEA was disabled by a filter.
     * @param array $state The global state of simpleSAMLphp.
     * @param array $config The config for the PrivacyIDEA server.
     * @return boolean Whether PrivacyIDEA is disabled.
     */
    public static function isPrivacyIDEADisabled(array $state, array $config)
    {
        if (isset($config['enabledPath']) || isset($state['enabledPath']))
        {
            if ($config['enabledKey'] === false || $state['enabledKey'] === false)
            {
                return true;
            }
        }
        return false;
    }
}
