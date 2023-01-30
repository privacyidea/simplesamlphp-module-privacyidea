<?php

require_once((dirname(__FILE__, 2)) . '/PILogger.php');
require_once((dirname(__FILE__, 3)) . '/php-client/src/Client-Autoloader.php');

/**
 * This authentication processing filter allows you to add a second step
 * authentication against privacyIDEA
 *
 * @author Cornelius Kölbel <cornelius.koelbel@netknights.it>
 * @author Jean-Pierre Höhmann <jean-pierre.hoehmann@netknights.it>
 * @author Lukas Matusiewicz <lukas.matusiewicz@netknights.it>
 */
class sspmod_privacyidea_Auth_Process_PrivacyideaAuthProc extends SimpleSAML_Auth_ProcessingFilter
{
    /* @var array This contains the authproc configuration which is set in metadata */
    private $authProcConfig;
    /* @var PrivacyIDEA This is an object from privacyIDEA class */
    private $pi;

    /**
     * @param array $config Authproc configuration.
     * @param mixed $reserved
     */
    public function __construct(array $config, $reserved)
    {
        assert('array' === gettype($config));
        parent::__construct($config, $reserved);
        $this->authProcConfig = $config;
        $this->pi = sspmod_privacyidea_Auth_Utils::createPrivacyIDEAInstance($config);
        if ($this->pi == null)
        {
            throw new SimpleSAML_Error_ConfigurationError("privacyIDEA: Initialization failed.");
        }
    }

    /**
     * Run the filter.
     *
     * @param array $state
     * @throws Exception if authentication fails
     */
    public function process(&$state)
    {
        SimpleSAML_Logger::info("privacyIDEA: Auth Proc Filter - Entering process function.");
        assert('array' === gettype($state));

        // Update state before starting the authentication process
        $state['privacyidea:privacyidea'] = $this->authProcConfig;
        $state['privacyidea:privacyidea']['authenticationMethod'] = "authprocess";

        // If set in config, allow to check the IP of the client and to control the 2FA depending on the client IP.
        // It can be used to configure that a user does not need to provide a second factor when logging in from the local network.
        if (!empty($this->authProcConfig['excludeClientIPs']))
        {
            $ip = sspmod_privacyidea_Auth_Utils::getClientIP();
            if ($this->matchIP($ip, $this->authProcConfig['excludeClientIPs']))
            {
                SimpleSAML_Logger::debug("privacyIDEA: privacyIDEA is disabled because ip " . $ip . " is excluded.");
                SimpleSAML_Auth_ProcessingChain::resumeProcessing($state);
            }
        }

        // If set to "true" in config, selectively disable the privacyIDEA authentication using the entityID and/or SAML attributes.
        // The skipping will be done in self::isPrivacyIDEADisabled
        if (!empty($this->authProcConfig['checkEntityID']) && $this->authProcConfig['checkEntityID'] === 'true')
        {
            $stateId = SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea');
            $stateId = $this->checkEntityID($this->authProcConfig, $stateId);
            $state = SimpleSAML_Auth_State::loadState($stateId, 'privacyidea:privacyidea');
        }

        // Check if privacyIDEA is disabled by configuration setting
        if (self::isPrivacyIDEADisabled($state, $this->authProcConfig))
        {
            SimpleSAML_Logger::debug("privacyIDEA: privacyIDEA is disabled by a filter");
            SimpleSAML_Auth_ProcessingChain::resumeProcessing($state);
        }

        // SSO check if authentication should be skipped
        if (array_key_exists('SSO', $this->authProcConfig)
            && $this->authProcConfig['SSO'] === 'true')
        {
            if (sspmod_privacyidea_Auth_Utils::checkForValidSSO($state))
            {
                SimpleSAML_Logger::debug("privacyIDEA: SSO data valid - logging in..");
                SimpleSAML_Auth_ProcessingChain::resumeProcessing($state);
            }
            else
            {
                SimpleSAML_Logger::debug("privacyIDEA: No valid SSO data found.");
            }
        }

        $username = $state["Attributes"][$this->authProcConfig['uidKey']][0];
        $stateId = SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea');

        // Check if triggerChallenge call should be done
        $triggered = false;
        if (!empty($this->authProcConfig['authenticationFlow']))
        {
            if ($this->authProcConfig['authenticationFlow'] === 'triggerChallenge')
            {
                // Call /validate/triggerchallenge with the service account from the configuration to trigger all token of the user
                $stateId = SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea');
                if (!$this->pi->serviceAccountAvailable())
                {
                    SimpleSAML_Logger::error('privacyIDEA: service account or password is not set in config. Cannot to do trigger challenge.');
                }
                else
                {
                    $response = null;
                    try
                    {
                        $response = $this->pi->triggerChallenge($username);
                    }
                    catch (Exception $e)
                    {
                        sspmod_privacyidea_Auth_Utils::handlePrivacyIDEAException($e, $state);
                    }

                    if ($response != null)
                    {
                        $triggered = !empty($response->multiChallenge);
                        $stateId = sspmod_privacyidea_Auth_Utils::processPIResponse($stateId, $response);
                    }
                }
            }
        }
        else
        {
            SimpleSAML_Logger::error("privacyidea: Authentication flow is not set in config. Processing default one...");
        }

        // Check if it should be controlled that user has no tokens and a new token should be enrolled.
        if (!$triggered && !empty($this->authProcConfig['doEnrollToken']) && $this->authProcConfig['doEnrollToken'] === 'true')
        {
            $stateId = $this->enrollToken($stateId, $username);
        }

        // Check if call with a static pass to /validate/check should be done
        if (!$triggered && !empty($this->authProcConfig['tryFirstAuthentication'])
            && $this->authProcConfig['tryFirstAuthentication'] === 'true')
        {
            // Call /validate/check with a static pass from the configuration
            // This could already end the authentication with the "passOnNoToken" policy, or it could trigger challenges
            $response = sspmod_privacyidea_Auth_Utils::authenticatePI($state, array('otp' => $this->authProcConfig['tryFirstAuthPass']));
            if (empty($response->multiChallenge) && $response->value)
            {
                SimpleSAML_Auth_ProcessingChain::resumeProcessing($state);
            }
            elseif (!empty($response->multiChallenge))
            {
                $stateId = sspmod_privacyidea_Auth_Utils::processPIResponse($stateId, $response);
            }
        }

        $state = SimpleSAML_Auth_State::loadState($stateId, 'privacyidea:privacyidea');

        // This is AuthProcFilter, so step 1 (username+password) is already done. Set the step to 2
        $state['privacyidea:privacyidea:ui']['step'] = 2;
        if (!empty($this->authProcConfig['otpFieldHint']))
        {
            $state['privacyidea:privacyidea:ui']['otpFieldHint'] = $this->authProcConfig['otpFieldHint'] ?: "";
        }
        $stateId = SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea');

        $url = SimpleSAML_Module::getModuleURL('privacyidea/FormBuilder.php');
        SimpleSAML_Utilities::redirectTrustedURL($url, array('stateId' => $stateId));
    }

    /**
     * This function check if user has a token and if not - help to enroll a new one in UI.
     * @param string $stateId
     * @param string $username
     * @return string
     * @throws PIBadRequestException
     */
    private function enrollToken($stateId, $username)
    {
        assert('string' === gettype($username));
        assert('string' === gettype($stateId));

        $state = SimpleSAML_Auth_State::loadState($stateId, 'privacyidea:privacyidea');

        // Error if no serviceAccount or servicePass
        if ($this->pi->serviceAccountAvailable() === false)
        {
            SimpleSAML_Logger::error("privacyIDEA: service account for token enrollment is not set!");
        }
        else
        {
            $genkey = "1";
            $type = $this->authProcConfig['tokenType'];
            $description = "Enrolled with simpleSAMLphp";

            $response = $this->pi->enrollToken($username, $genkey, $type, $description);

            if (!empty($response->errorMessage))
            {
                SimpleSAML_Logger::error("privacyIDEA: Error code: " . $response->errorCode . ", Error message: " . $response->errorMessage);
                $state['privacyidea:privacyidea']['errorCode'] = $response->errorCode;
                $state['privacyidea:privacyidea']['errorMessage'] = $response->errorMessage;
            }

            // If we have a response from PI - save QR Code into state to show it soon
            // and enroll a new token for the user
            if (!empty($response->detail->googleurl->img))
            {
                $state['privacyidea:tokenEnrollment']['tokenQR'] = $response->detail->googleurl->img;
            }
            return SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea');
        }
        return "";
    }

    /**
     * This is the help function to exclude some IP from 2FA. Only if is set in config.
     * @param $clientIP
     * @param $excludeClientIPs
     * @return bool|void
     */
    private function matchIP($clientIP, $excludeClientIPs)
    {
        assert('string' === gettype($clientIP));
        $clientIP = ip2long($clientIP);

        $match = false;
        foreach ($excludeClientIPs as $ipAddress)
        {
            if (strpos($ipAddress, '-'))
            {
                $range = explode('-', $ipAddress);
                $startIP = ip2long($range[0]);
                $endIP = ip2long($range[1]);
                $match = $clientIP >= $startIP && $clientIP <= $endIP;
            }
            else
            {
                $match = $clientIP === ip2long($ipAddress);
            }
            if ($match)
            {
                break;
            }
        }
        return $match;
    }

    /**
     * This function allows the selective deactivation of privacyIDEA for a list of regular expressions
     * which match SAML service provider entityIDs.
     * The filter checks the entityID in the SAML request against a list of regular expressions and sets the state variable
     * $state[enabledPath][enabledKey][0] to false on match, which can be used to disable privacyIDEA.
     * For any value in excludeEntityIDs, the config parameter includeAttributes may be used to enable privacyIDEA for a subset
     * of users which have these attribute values (e.g. memberOf).
     * @param array $authProcConfig
     * @param string $stateId
     * @return string
     */
    private function checkEntityID($authProcConfig, $stateId)
    {
        SimpleSAML_Logger::debug("Checking requesting entity ID for privacyIDEA");
        $state = SimpleSAML_Auth_State::loadState($stateId, 'privacyidea:privacyidea');

        $excludeEntityIDs = $authProcConfig['excludeEntityIDs'] ?: array();
        $includeAttributes = $authProcConfig['includeAttributes'] ?: array();
        $setPath = $authProcConfig['setPath'] ?: "";
        $setKey = $authProcConfig['setKey'] ?: '';

        // the default return value is true, privacyIDEA should be enabled by default.
        $ret = true;
        $requestEntityID = $state["Destination"]["entityid"];

        // if the requesting entityID matches the given list set the return parameter to false
        SimpleSAML_Logger::debug("privacyidea:checkEntityID: Requesting entityID is " . $requestEntityID);
        $matchedEntityIDs = $this->strMatchesRegArr($requestEntityID, $excludeEntityIDs);
        if ($matchedEntityIDs)
        {
            $ret = false;
            $entityIDKey = $matchedEntityIDs[0];
            SimpleSAML_Logger::debug("privacyidea:checkEntityID: Matched entityID is " . $entityIDKey);

            // if there is also a match for any attribute value in the includeAttributes
            // fall back to the default return value: true
            if (isset($includeAttributes[$entityIDKey]))
            {
                foreach ($includeAttributes[$entityIDKey] as $attrKey => $attrRegExpArr)
                {
                    if (isset($state["Attributes"][$attrKey]))
                    {
                        foreach ($state["Attributes"][$attrKey] as $attrVal)
                        {
                            $matchedAttrs = $this->strMatchesRegArr($attrVal, $attrRegExpArr);

                            if (!empty($matchedAttrs))
                            {
                                $ret = true;
                                SimpleSAML_Logger::debug("privacyidea:checkEntityID: Requesting entityID in " .
                                                         "list, but excluded by at least one attribute regexp \"" . $attrKey .
                                                         "\" = \"" . $matchedAttrs[0] . "\".");
                                break;
                            }
                        }
                    }
                    else
                    {
                        SimpleSAML_Logger::debug("privacyidea:checkEntityID: attribute key " .
                                                 $attrKey . " not contained in request");
                    }
                }
            }
        }
        else
        {
            SimpleSAML_Logger::debug("privacyidea:checkEntityID: Requesting entityID " .
                                     $requestEntityID . " not matched by any regexp.");
        }

        $state[$setPath][$setKey][0] = $ret;

        $stateId = SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea');

        if ($ret)
        {
            $retStr = "true";
        }
        else
        {
            $retStr = "false";
        }
        SimpleSAML_Logger::debug("Setting \$state[" . $setPath . "][" . $setKey . "][0] = " . $retStr . ".");

        return $stateId;
    }

    /**
     * This is the help function for checkEntityID() and checks a given string against an array with regular expressions.
     * It will return an array with matches.
     * @param string $str
     * @param array $reg_arr
     * @return array
     */
    private function strMatchesRegArr($str, array $reg_arr)
    {
        $retArr = array();

        foreach ($reg_arr as $reg)
        {
            if ($reg[0] != "/")
            {
                $reg = "/" . $reg . "/";
            }
            SimpleSAML_Logger::debug("privacyidea:checkEntityID: test regexp " . $reg . " against the string " . $str);

            if (preg_match($reg, $str))
            {
                $retArr[] = $reg;
            }
        }
        return $retArr;
    }

    /**
     * Check if PrivacyIDEA was disabled by a filter.
     * @param array $state The global state of simpleSAMLphp.
     * @param array $config The config for the PrivacyIDEA server.
     * @return boolean Whether PrivacyIDEA is disabled.
     */
    public static function isPrivacyIDEADisabled(array $state, array $config)
    {
        if (isset($config['enabledPath']) && isset($config['enabledKey']))
        {
            return isset($state[$config['enabledPath']][$config['enabledKey']][0])
                && !$state[$config['enabledPath']][$config['enabledKey']][0];
        }
        return false;
    }

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
