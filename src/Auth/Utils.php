<?php

namespace SimpleSAML\Module\privacyidea\Auth;

use PIResponse;
use PrivacyIDEA;
use SimpleSAML\Auth\ProcessingChain;
use SimpleSAML\Auth\State;
use SimpleSAML\Error\Exception;
use SimpleSAML\Logger;
use SimpleSAML\Module\privacyidea\Auth\Source\PrivacyideaAuthSource;
use SimpleSAML\Session;

class Utils
{
    /**
     * Perform 2FA given the current state and the inputs from the form.
     *
     * @param array $state state
     * @param array $formParams inputs from the form
     * @return PIResponse|null An array containing attributes and detail, or NULL.
     * @throws Exception
     */
    public static function authenticatePI(array &$state, array $formParams, array $headers): ?PIResponse
    {
        Logger::debug("privacyIDEA: Utils::authenticatePI with form data:\n" . http_build_query($formParams, '', ', '));

        $state['privacyidea:privacyidea:ui']['mode'] = $formParams['mode'];

        // If the mode was changed, do not make any requests
        if ($formParams["modeChanged"] == "1")
        {
            $state['privacyidea:privacyidea:ui']['loadCounter'] = 1;
            return null;
        }

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
        $transactionID = "";
        if (isset($state['privacyidea:privacyidea']['transactionID']))
        {
            $transactionID = $state['privacyidea:privacyidea']['transactionID'];
        }

        // Send a request according to the mode
        if ($formParams['mode'] == "push")
        {
            try
            {
                if ($pi->pollTransaction($transactionID))
                {
                    // If the authentication has been confirmed on the phone, the authentication has to be finalized with a
                    // call to /validate/check with an empty pass
                    // https://privacyidea.readthedocs.io/en/latest/tokens/authentication_modes.html#outofband-mode
                    $response = $pi->validateCheck($username, "", $transactionID, $headers);
                }
            }
            catch (\PIBadRequestException $e)
            {
                Utils::handlePrivacyIDEAException($e, $state);
            }
        }
        elseif ($formParams['mode'] == "u2f")
        {
            $u2fSignResponse = $formParams['u2fSignResponse'];

            if (empty($u2fSignResponse))
            {
                Logger::error("privacyIDEA: Incomplete data for U2F authentication: u2fSignResponse is missing!");
            }
            else
            {
                try
                {
                    $response = $pi->validateCheckU2F($username, $transactionID, $u2fSignResponse, $headers);
                }
                catch (\PIBadRequestException $e)
                {
                    Utils::handlePrivacyIDEAException($e, $state);
                }
            }
        }
        elseif ($formParams['mode'] == "webauthn")
        {
            $origin = $formParams['origin'];
            $webAuthnSignResponse = $formParams['webAuthnSignResponse'];

            if (empty($origin) || empty($webAuthnSignResponse))
            {
                Logger::error("privacyIDEA: Incomplete data for WebAuthn authentication: WebAuthnSignResponse or Origin is missing!");
            }
            else
            {
                try
                {
                    $response = $pi->validateCheckWebAuthn($username, $transactionID, $webAuthnSignResponse, $origin, $headers);
                }
                catch (\PIBadRequestException $e)
                {
                    self::handlePrivacyIDEAException($e, $state);
                }
            }
        }
        else
        {
            try
            {
                $response = $pi->validateCheck($username, $formParams["otp"], $transactionID, $headers);
            }
            catch (\PIBadRequestException $e)
            {
                self::handlePrivacyIDEAException($e, $state);
            }
        }
        $counter = $formParams['loadCounter'];
        $state['privacyidea:privacyidea:ui']['loadCounter'] = $counter + 1;
        return $response;
    }

    /**
     * @param $exception
     * @param $state
     */
    public static function handlePrivacyIDEAException($exception, &$state): void
    {
        Logger::error("Exception: " . $exception->getMessage());
        $state['privacyidea:privacyidea']['errorCode'] = $exception->getCode();
        $state['privacyidea:privacyidea']['errorMessage'] = $exception->getMessage();
    }

    /**
     * Write SSO specific data to the session and register a logout handler. The logout handler has to be attached to an
     * authority which is also obtained from the session. If there are no valid authorities, this function does nothing.
     * The first authority returned by SSP is used. Authorities are validated before they are returned so the authority
     * that is used can be considered valid.
     *
     * @return void
     * @throws \Exception
     */
    public static function tryWriteSSO(): void
    {
        Logger::debug("privacyIDEA: tryWriteSSO");

        $session = Session::getSessionFromRequest();
        // First get the authority to register the logout handler for
        $authorities = $session->getAuthorities();
        if (empty($authorities))
        {
            Logger::error("privacyIDEA: Cannot use SSO because there is no authority configured to register the logout handler for!");
            return;
        }

        $authority = $authorities[0];
        Logger::debug("privacyIDEA: Registering logout handler for authority " . $authority);

        $session->registerLogoutHandler(
            $authority,
            Utils::class,
            'handleLogout'
        );
        $session->setData('privacyidea:privacyidea', "2FA-success", true);
        Logger::debug("privacyIDEA: SSO data written and logout handler registered.");
    }

    /**
     * Check the state for data indicating an active login. If such data is present, check if SSO data of our
     * module is present, indicating that 2FA was completed before.
     * A boolean is returned to indicate if the login/2FA can be skipped.
     *
     * @param array $state
     * @return boolean true if login/2FA can be skipped, false if not
     * @throws \Exception
     */
    public static function checkForValidSSO(array $state): bool
    {
        Logger::debug("privacyIDEA: checkForValidSSO");

        // For SSO to be valid, we check 2 things:
        // 1. Valid login of SSP which is not expired
        // 2. Completed 2FA with this module
        if (array_key_exists('Expire', $state) && $state['Expire'] > time())
        {
            Logger::debug("privacyIDEA: Valid login found. Checking for valid 2FA..");
            $session = Session::getSessionFromRequest();
            $ret = $session->getData('privacyidea:privacyidea', '2FA-success');
            return empty($ret) ? false : $ret;
        }
        else
        {
            Logger::debug("privacyIDEA: No valid login found or state is not an array.");
        }
        return false;
    }

    /**
     * This function is registered as a logout handler when writing the SSO specific data to the session.
     * When called, it removes SSO data on logout.
     *
     * @return void
     * @throws Exception|\Exception
     */
    public static function handleLogout(): void
    {
        Logger::debug("privacyIDEA: Logout handler called. Removing SSO data.");
        Session::getSessionFromRequest()->deleteData('privacyidea:privacyidea:sso', "2FA-success");
    }

    /**
     * Create a new privacyIDEA object with the given configuration
     *
     * @param array $config
     * @return PrivacyIDEA|null privacyIDEA object or null on error
     */
    public static function createPrivacyIDEAInstance(array $config): ?PrivacyIDEA
    {
        if (!empty($config['privacyideaServerURL']))
        {
            $pi = new PrivacyIDEA("simpleSAMLphp", $config['privacyideaServerURL']);
            $pi->setLogger(new PILogger());

            if (array_key_exists('sslVerifyHost', $config) && !empty($config['sslVerifyHost']))
            {
                $pi->setSSLVerifyHost($config['sslVerifyHost'] !== "false");
            }

            if (array_key_exists('sslVerifyPeer', $config) && !empty($config['sslVerifyPeer']))
            {
                $pi->setSSLVerifyPeer($config['sslVerifyPeer'] !== "false");
            }

            if (array_key_exists('serviceAccount', $config) && !empty($config['serviceAccount']))
            {
                $pi->setServiceAccountName($config['serviceAccount']);
            }

            if (array_key_exists('servicePass', $config) && !empty($config['servicePass']))
            {
                $pi->setServiceAccountPass($config['servicePass']);
            }

            if (array_key_exists('serviceRealm', $config) && !empty($config['serviceRealm']))
            {
                $pi->setServiceAccountRealm($config['serviceRealm']);
            }

            if (array_key_exists('realm', $config) && !empty($config['realm']))
            {
                $pi->setRealm($config['realm']);
            }

            return $pi;
        }
        else
        {
            Logger::error("privacyIDEA: Cannot create privacyIDEA instance: server url missing in configuration!");
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
     * @throws Exception|\Exception
     */
    public static function processPIResponse(string $stateId, PIResponse $response): string
    {
        $state = State::loadState($stateId, 'privacyidea:privacyidea', true);

        $config = $state['privacyidea:privacyidea'];
        $state['privacyidea:privacyidea:ui']['mode'] = "otp";

        if (!empty($response->getMultiChallenge()))
        {
            // Authentication not complete, new challenges were triggered. Prepare the state for the next step.
            $triggeredTokens = $response->triggeredTokenTypes();
            if (!empty($response->getPreferredClientMode()))
            {
                if ($response->getPreferredClientMode() === "interactive")
                {
                    $state['privacyidea:privacyidea:ui']['mode'] = "otp";
                }
                elseif ($response->getPreferredClientMode() === "poll")
                {
                    $state['privacyidea:privacyidea:ui']['mode'] = "push";
                }
                else
                {
                    $state['privacyidea:privacyidea:ui']['mode'] = $response->getPreferredClientMode();
                }
                Logger::debug("privacyIDEA: Preferred client mode: " . $state['privacyidea:privacyidea:ui']['mode']);
            }

            $state['privacyidea:privacyidea:ui']['pushAvailable'] = in_array("push", $triggeredTokens);
            $state['privacyidea:privacyidea:ui']['otpAvailable'] = true;

            $state['privacyidea:privacyidea:ui']['message'] = $response->getMessages();

            if (in_array("webauthn", $triggeredTokens))
            {
                $state['privacyidea:privacyidea:ui']['webAuthnSignRequest'] = $response->webAuthnSignRequest();
            }

            if (in_array("u2f", $triggeredTokens))
            {
                $state['privacyidea:privacyidea:ui']['u2fSignRequest'] = $response->u2fSignRequest();
            }

            $state['privacyidea:privacyidea']['transactionID'] = $response->getTransactionID();

            // Search for the image
            foreach ($response->MultiChallenge() as $challenge)
            {
                if (!empty($challenge->image))
                {
                    if (!empty($challenge->clientMode) && $challenge->clientMode === "interactive")
                    {
                        $state['privacyidea:privacyidea:ui']['imageOTP'] = $challenge->image;
                    }
                    elseif (!empty($challenge->clientMode) && $challenge->clientMode === "poll")
                    {
                        $state['privacyidea:privacyidea:ui']['imagePush'] = $challenge->image;
                    }
                    elseif (!empty($challenge->clientMode) && $challenge->clientMode === "u2f")
                    {
                        $state['privacyidea:privacyidea:ui']['imageU2F'] = $challenge->image;
                    }
                    elseif (!empty($challenge->clientMode) && $challenge->clientMode === "webauthn")
                    {
                        $state['privacyidea:privacyidea:ui']['imageWebauthn'] = $challenge->image;
                    }
                }
            }
        }
        elseif ($response->getValue())
        {
            // Authentication successful. Finalize the authentication depending on method (AuthProc or AuthSource) and
            // write SSO specific data if enabled.
            Logger::debug("privacyIDEA: User authenticated successfully!");

            // Complete the authentication depending on method
            if ($state['privacyidea:privacyidea']['authenticationMethod'] === "authprocess")
            {
                // Write data for SSO if enabled
                if (array_key_exists('SSO', $config) && $config['SSO'])
                {
                    Utils::tryWriteSSO();
                }

                State::saveState($state, 'privacyidea:privacyidea');
                ProcessingChain::resumeProcessing($state);
            }
            else if ($state['privacyidea:privacyidea']['authenticationMethod'] === "authsource")
            {
                // For AuthSource, the attributes required by saml need to be present, so check for that before completing
                PrivacyideaAuthSource::checkAuthenticationComplete($state, $response, $config);
            }
        }
        elseif (!empty($response->getErrorCode()))
        {
            // privacyIDEA returned an error, prepare to display it
            Logger::error("privacyIDEA: Error code: " . $response->getErrorCode() . ", Error message: " . $response->getErrorMessage());
            $state['privacyidea:privacyidea']['errorCode'] = $response->getErrorCode();
            $state['privacyidea:privacyidea']['errorMessage'] = $response->getErrorMessage();
        }
        else
        {
            // Unexpected response
            Logger::error("privacyIDEA: " . $response->getMessage());
            $state['privacyidea:privacyidea']['errorMessage'] = $response->getMessage();
        }
        return State::saveState($state, 'privacyidea:privacyidea');
    }

    /**
     * Determine the clients IP-Address.
     * @return string|null The IP-Address of the client.
     */
    public static function getClientIP(): ?string
    {
        $result = @$_SERVER['HTTP_X_FORWARDED_FOR'] ?: @$_SERVER['REMOTE_ADDR'] ?: @$_SERVER['HTTP_CLIENT_IP'];
        Logger::debug('privacyIDEA: client ip: ' . $result);
        return $result;
    }

    /**
     * Search for the configured headers in $_SERVER and return all found with their values.
     *
     * @param array $headers List of headers to forward.
     * @return array Headers to forward with their values.
     */
    public static function getHeadersToForward(array $headers): array
    {
        $cleanHeaders = str_replace(' ', '', $headers);
        $arrHeaders = explode(',', $cleanHeaders);

        $headersToForward = array();
        foreach ($arrHeaders as $header)
        {
            if (array_key_exists($header, $_SERVER))
            {
                Logger::debug("Found matching header: " . $header);
                $value = $_SERVER[$header];
                if (is_array($_SERVER[$header]))
                {
                    $value = implode(',', $_SERVER[$header]);
                }
                $header = array($header => $value);
                $headersToForward = array_push($headersToForward, $header);
            }
            else
            {
                Logger::debug("No values for header: " . $header . " found.");
            }
        }
        return $headersToForward;
    }
}
