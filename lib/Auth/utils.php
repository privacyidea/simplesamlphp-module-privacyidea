<?php

use PrivacyIdea\PHPClient\PIResponse;
use PrivacyIdea\PHPClient\PrivacyIDEA;

class sspmod_privacyidea_Auth_utils
{
    /**
     * Perform 2FA authentication given the current state and an OTP from a token managed by privacyIDEA
     * The otp is sent to the privacyidea_url.
     *
     * @param array $state state
     * @param array $formParams An array containing: user, realm, pass, transactionID, signaturedata, clientdata, regdata
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

        $formParams['realm'] = in_array('realm', $formParams) ? $formParams['realm'] : "";
        $formParams['client'] = self::getClientIP();

        $pi = new PrivacyIDEA("simpleSAMLphp", $serverConfig['privacyideaServerURL']);
        $pi->sslVerifyHost = $serverConfig['sslVerifyHost'];
        $pi->sslVerifyPeer = $serverConfig['sslVerifyPeer'];
        $pi->realm = @$serverConfig['realm'] ?: "";
//        $pi->logger = new Logger;

        $result = null;
        $transactionID = $state['privacyidea:privacyidea']['transactionID'];

        // Send a request according to the mode
        if ($formParams['mode'] == "push")
        {
//            SimpleSAML_Logger::info("PUSH MODE.");

            if ($pi->pollTransaction($transactionID))
            {
                $result = $pi->validateCheck($username, "", $transactionID);
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
//                SimpleSAML_Logger::info("U2F MODE.");
                $result = $pi->validateCheckU2F($username, $transactionID, $u2fSignResponse);
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
//                SimpleSAML_Logger::info("WEBAUTHN MODE.");
                $result = $pi->validateCheckWebAuthn($username, $transactionID, $webAuthnSignResponse, $origin);
            }
        }
        else
        {
//            SimpleSAML_Logger::info("OTP MODE.");
            // Call validate/check endpoint adding parameters and eventually transaction ID
            $result = $pi->validateCheck($username, $formParams["otp"], $transactionID);
        }
        $counter = $formParams['loadCounter'];
        $state['privacyidea:privacyidea:ui']['loadCounter'] = $counter + 1;
        return $result;
    }

    /**
     * This function can edit the state to enter all needle info from PIResponse
     * and to transport it easy to formbuilder.php
     * @param string $stateID The state is needed to be changed in this function
     * @param mixed $result The result contains the multi_challenge which will be used to check which token types are used.
     * @return string The modified state ID will be returned. It now contains the token types for the user.
     * @throws Exception
     */
    public static function processPIResponse($stateID, PIResponse $result)
    {
        assert('string' === gettype($stateID));

        $state = SimpleSAML_Auth_State::loadState($stateID, 'privacyidea:privacyidea');

        if (($result->multiChallenge) !== array())
        {
            $triggeredTokens = $result->triggeredTokenTypes();
            $state['privacyidea:privacyidea:ui']['pushAvailable'] = in_array("push", $triggeredTokens);
            $state['privacyidea:privacyidea:ui']['otpAvailable'] = true; // Always show otp field
            $state['privacyidea:privacyidea']['transactionID'] = $result->transactionID;
            $state['privacyidea:privacyidea:ui']['message'] = $result->messages;
            $state['privacyidea:privacyidea:ui']['webAuthnSignRequest'] = $result->webAuthnSignRequest();
            $state['privacyidea:privacyidea:ui']['u2fSignRequest'] = $result->u2fSignRequest();
        }
        elseif ($result->value)
        {
            SimpleSAML_Logger::debug("privacyIDEA: User authenticated successfully!");

            if ($state['privacyidea:privacyidea']['authenticationMethod'] === "authprocess")
            {
                SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea');
                SimpleSAML_Auth_ProcessingChain::resumeProcessing($state);
            }
        }
        elseif (!empty($result->errorCode))
        {
            SimpleSAML_Logger::error("PrivacyIDEA server: Error code: " . $result->errorCode . ", Error message: " . $result->errorMessage);
            $state['privacyidea:privacyidea']['errorCode'] = $result->errorCode;
            $state['privacyidea:privacyidea']['errorMessage'] = $result->errorMessage;
        }
        else
        {
            SimpleSAML_Logger::error("privacyIDEA: Wrong OTP.");
            $state['privacyidea:privacyidea']['errorMessage'] = "You have entered incorrect OTP. Please try again or use another token.";
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
     * If the administrator has configured multiple uidKeys, this will find the first one that exists as an Attribute in
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
    public static function checkPIAbility(array $state, array $config)
    {
        if (isset($config['enabledPath']) || isset($state['enabledPath']))
        {
            if ($config['enabledKey'] === false || $state['enabledKey'] === false)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        else
        {
            return false;
        }
    }
}
