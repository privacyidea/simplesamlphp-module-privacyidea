<?php

require_once((dirname(__FILE__, 2)) . '/php-client/src/Client-Autoloader.php');
require_once('PILogger.php');

class sspmod_privacyidea_Auth_Utils
{
    /**
     * Perform 2FA given the current state and the inputs from the form.
     *
     * @param array $state state
     * @param array $formParams inputs from the form
     * @return PIResponse|null An array containing attributes and detail, or NULL.
     * @throws Exception
     */
    public static function authenticatePI(array &$state, array $formParams)
    {
        assert('array' === gettype($state));
        assert('array' === gettype($formParams));

        SimpleSAML_Logger::debug("privacyIDEA: Utils::authenticatePI with form data:\n" . http_build_query($formParams, '', ', '));

        // If the mode was changed, do not make any requests
        if ($formParams["modeChanged"] == "1")
        {
            $state['privacyidea:privacyidea:ui']['loadCounter'] = 1;
            return null;
        }

        $state['privacyidea:privacyidea:ui']['mode'] = $formParams['mode'];
        $serverConfig = $state['privacyidea:privacyidea'];

        // Get the username from elsewhere if it is not in the form
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

        $pi = self::createPrivacyIDEAInstance($serverConfig);
        if ($pi == null)
        {
            throw new Exception("Unable to initialize privacyIDEA");
        }

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
        }
        elseif ($formParams['mode'] == "u2f")
        {
            $u2fSignResponse = $formParams['u2fSignResponse'];

            if (empty($u2fSignResponse))
            {
                SimpleSAML_Logger::error("privacyIDEA: Incomplete data for U2F authentication: u2fSignResponse is missing!");
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
                SimpleSAML_Logger::error("privacyIDEA: Incomplete data for WebAuthn authentication: WebAuthnSignResponse or Origin is missing!");
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
     * @return void
     */
    public static function tryWriteSSO()
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
        SimpleSAML_Logger::debug("privacyIDEA: Registering logout handler for authority " . $authority);

        $session->registerLogoutHandler(
            $authority,
            sspmod_privacyidea_Auth_Utils::class,
            'handleLogout'
        );
        $session->setData('privacyidea:privacyidea', "2FA-success", true);
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
        if (is_array($state) && array_key_exists('Expire', $state) && $state['Expire'] > time())
        {
            SimpleSAML_Logger::debug("privacyIDEA: Valid login found. Checking for valid 2FA..");
            $session = SimpleSAML_Session::getSessionFromRequest();
            return $session->getData('privacyidea:privacyidea', '2FA-success');
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
     * Create a new privacyIDEA object with the given configuration
     *
     * @param array $config
     * @return PrivacyIDEA|null privacyIDEA object or null on error
     */
    public static function createPrivacyIDEAInstance($config)
    {
        if (!empty($config['privacyideaServerURL']))
        {
            $pi = new PrivacyIDEA("simpleSAMLphp", $config['privacyideaServerURL']);
            $pi->logger = new PILogger();

            if (array_key_exists('sslVerifyHost', $config) && !empty($config['sslVerifyHost']))
            {
                $pi->sslVerifyHost = $config['sslVerifyHost'] !== "false";
            }

            if (array_key_exists('sslVerifyPeer', $config) && !empty($config['sslVerifyPeer']))
            {
                $pi->sslVerifyPeer = $config['sslVerifyPeer'] !== "false";
            }

            if (array_key_exists('serviceAccount', $config) && !empty($config['serviceAccount']))
            {
                $pi->serviceAccountName = $config['serviceAccount'];
            }

            if (array_key_exists('servicePass', $config) && !empty($config['servicePass']))
            {
                $pi->serviceAccountPass = $config['servicePass'];
            }

            if (array_key_exists('serviceRealm', $config) && !empty($config['serviceRealm']))
            {
                $pi->serviceAccountRealm = $config['serviceRealm'];
            }

            if (array_key_exists('realm', $config) && !empty($config['realm']))
            {
                $pi->realm = $config['realm'];
            }

            return $pi;
        }
        else
        {
            SimpleSAML_Logger::error("privacyIDEA: Cannot create privacyIDEA instance: server url missing in configuration!");
        }
        return null;
    }

    /**
     * Process the response from privacyIDEA and write information for the next step to the state.
     * If the response from privacyIDEA indicates success and this module is used as AuthProcFilter,
     * this function will resume the processing chain and not return.
     *
     * @param string $stateId to load the state
     * @param mixed $response from privacyIDEA
     * @return string stateId of the modified state
     * @throws Exception
     */
    public static function processPIResponse($stateId, PIResponse $response)
    {
        assert('string' === gettype($stateId));
        $state = SimpleSAML_Auth_State::loadState($stateId, 'privacyidea:privacyidea');

        $config = $state['privacyidea:privacyidea'];
        $state['privacyidea:privacyidea:ui']['mode'] = "otp";

        if (!empty($response->multiChallenge))
        {
            // Authentication not complete, new challenges where triggered. Prepare the state for the next step
            $triggeredToken = $response->triggeredTokenTypes();
            // Preferred token type
            if ($config !== null && array_key_exists("preferredTokenType", $config))
            {
                $preferred = $config['preferredTokenType'];
                if (!empty($preferred))
                {
                    if (in_array($preferred, $triggeredToken))
                    {
                        $state['privacyidea:privacyidea:ui']['mode'] = $preferred;
                    }
                }
            }

            $state['privacyidea:privacyidea:ui']['pushAvailable'] = in_array("push", $triggeredToken);
            $state['privacyidea:privacyidea:ui']['otpAvailable'] = true; // Always show otp field
            $state['privacyidea:privacyidea:ui']['message'] = $response->messages;

            if (in_array("webauthn", $triggeredToken))
            {
                $state['privacyidea:privacyidea:ui']['webAuthnSignRequest'] = $response->webAuthnSignRequest();
            }

            if (in_array("u2f", $triggeredToken))
            {
                $state['privacyidea:privacyidea:ui']['u2fSignRequest'] = $response->u2fSignRequest();
            }

            $state['privacyidea:privacyidea']['transactionID'] = $response->transactionID;
        }
        elseif ($response->value)
        {
            // Authentication successful. Finalize the authentication depending on method (AuthProc or AuthSource) and
            // write SSO specific data if enabled.
            SimpleSAML_Logger::debug("privacyIDEA: User authenticated successfully!");

            // Complete the authentication depending on method
            if ($state['privacyidea:privacyidea']['authenticationMethod'] === "authprocess")
            {
                // Write data for SSO if enabled
                if (array_key_exists('SSO', $config) && $config['SSO'] == true)
                {
                    sspmod_privacyidea_Auth_Utils::tryWriteSSO();
                }

                SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea');
                SimpleSAML_Auth_ProcessingChain::resumeProcessing($state);
            }
            else if ($state['privacyidea:privacyidea']['authenticationMethod'] === "authsource")
            {
                // For AuthSource, the attributes required by saml need to be present, so check for that before completing
                sspmod_privacyidea_Auth_Source_PrivacyideaAuthSource::checkAuthenticationComplete($state, $response, $config);
            }
        }
        elseif (!empty($response->errorCode))
        {
            // privacyIDEA returned an error, prepare to display it
            SimpleSAML_Logger::error("privacyIDEA: Error code: " . $response->errorCode . ", Error message: " . $response->errorMessage);
            $state['privacyidea:privacyidea']['errorCode'] = $response->errorCode;
            $state['privacyidea:privacyidea']['errorMessage'] = $response->errorMessage;
        }
        else
        {
            // Unexpected response
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
