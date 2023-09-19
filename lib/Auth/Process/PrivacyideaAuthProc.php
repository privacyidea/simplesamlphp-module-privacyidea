<?php

namespace SimpleSAML\Module\privacyidea\Auth\Process;

use PIBadRequestException;
use PrivacyIDEA;
use SimpleSAML\Auth\ProcessingChain;
use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Auth\State;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Error\Exception;
use SimpleSAML\Error\NoState;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\privacyidea\Auth\Utils;
use SimpleSAML\Utils\HTTP;

/**
 * This authentication processing filter allows you to add a second step
 * authentication against privacyIDEA
 *
 * @author Cornelius Kölbel <cornelius.koelbel@netknights.it>
 * @author Jean-Pierre Höhmann <jean-pierre.hoehmann@netknights.it>
 * @author Lukas Matusiewicz <lukas.matusiewicz@netknights.it>
 */
class PrivacyideaAuthProc extends ProcessingFilter
{
    /* @var array This contains the authproc configuration which is set in metadata */
    private $authProcConfig;
    /* @var PrivacyIDEA This is an object from privacyIDEA class */
    private $pi;

    /**
     * @param array $config Authproc configuration.
     * @param mixed $reserved
     * @throws ConfigurationError
     * @throws \Exception
     */
    public function __construct(array $config, $reserved)
    {
        parent::__construct($config, $reserved);
        $this->authProcConfig = $config;
        $this->pi = Utils::createPrivacyIDEAInstance($config);
        if ($this->pi == null)
        {
            throw new ConfigurationError("privacyIDEA: Initialization failed.");
        }
    }

    /**
     * Run the filter.
     *
     * @param array $request The request state
     * @throws Exception|PIBadRequestException if authentication fails
     * @throws \Exception
     */
    public function process(&$request): void
    {
        Logger::info("privacyIDEA: Auth Proc Filter - Entering process function.");
        assert('array' === gettype($request));

        $state = $request;
        // Update state before starting the authentication process
        $state['privacyidea:privacyidea'] = $this->authProcConfig;
        $state['privacyidea:privacyidea']['authenticationMethod'] = "authprocess";

        // If set in config, allow to check the IP of the client and to control the 2FA depending on the client IP.
        // It can be used to configure that a user does not need to provide a second factor when logging in from the local network.
        if (!empty($this->authProcConfig['excludeClientIPs']))
        {
            $ip = Utils::getClientIP();
            if ($this->matchIP($ip, $this->authProcConfig['excludeClientIPs']))
            {
                Logger::debug("privacyIDEA: privacyIDEA is disabled because ip " . $ip . " is excluded.");
                ProcessingChain::resumeProcessing($state);
            }
        }

        // If set to "true" in config, selectively disable the privacyIDEA authentication using the entityID and/or SAML attributes.
        // The skipping will be done in self::isPrivacyIDEADisabled
        if (!empty($this->authProcConfig['checkEntityID']) && $this->authProcConfig['checkEntityID'] === 'true')
        {
            $stateId = State::saveState($state, 'privacyidea:privacyidea');
            $stateId = $this->checkEntityID($this->authProcConfig, $stateId);
            $state = State::loadState($stateId, 'privacyidea:privacyidea', true);
        }

        // Check if privacyIDEA is disabled by configuration setting
        if (self::isPrivacyIDEADisabled($state, $this->authProcConfig))
        {
            Logger::debug("privacyIDEA: privacyIDEA is disabled by a filter");
            ProcessingChain::resumeProcessing($state);
        }

        // SSO check if authentication should be skipped
        if (array_key_exists('SSO', $this->authProcConfig)
            && $this->authProcConfig['SSO'] === 'true')
        {
            if (Utils::checkForValidSSO($state))
            {
                Logger::debug("privacyIDEA: SSO data valid - logging in..");
                ProcessingChain::resumeProcessing($state);
            }
            else
            {
                Logger::debug("privacyIDEA: No valid SSO data found.");
            }
        }

        $username = $state["Attributes"][$this->authProcConfig['uidKey']][0];
        $stateId = State::saveState($state, 'privacyidea:privacyidea');

        // Check if triggerChallenge call should be done
        $triggered = false;
        if (!empty($this->authProcConfig['authenticationFlow']))
        {
            if ($this->authProcConfig['authenticationFlow'] === 'triggerChallenge')
            {
                // Call /validate/triggerchallenge with the service account from the configuration to trigger all token of the user
                $stateId = State::saveState($state, 'privacyidea:privacyidea');
                if (!$this->pi->serviceAccountAvailable())
                {
                    Logger::error('privacyIDEA: service account or password is not set in config. Cannot to do trigger challenge.');
                }
                else
                {
                    $response = null;
                    try
                    {
                        $response = $this->pi->triggerChallenge($username);
                    }
                    catch (\Exception $e)
                    {
                        Utils::handlePrivacyIDEAException($e, $state);
                    }

                    if ($response != null)
                    {
                        $triggered = !empty($response->multiChallenge);
                        $stateId = Utils::processPIResponse($stateId, $response);
                    }
                }
            }
            elseif ($this->authProcConfig['authenticationFlow'] === 'sendStaticPass')
            {
                // Call /validate/check with a static pass from the configuration
                // This could already end up the authentication if the "passOnNoToken" policy is set.
                // Otherwise, it triggers the challenges.
                $response = Utils::authenticatePI($state, array('otp' => $this->authProcConfig['staticPass']));
                if (empty($response->multiChallenge) && $response->value)
                {
                    ProcessingChain::resumeProcessing($state);
                }
                elseif (!empty($response->multiChallenge))
                {
                    $stateId = Utils::processPIResponse($stateId, $response);
                }
            }
            else
            {
                Logger::error("privacyidea: Authentication flow is not set in the config. Fallback to default...");
            }
        }

        $state = State::loadState($stateId, 'privacyidea:privacyidea', true);

        // This is AuthProcFilter, so step 1 (username+password) is already done. Set the step to 2
        $state['privacyidea:privacyidea:ui']['step'] = 2;
        if (!empty($this->authProcConfig['otpFieldHint']))
        {
            $state['privacyidea:privacyidea:ui']['otpFieldHint'] = $this->authProcConfig['otpFieldHint'] ?: "";
        }
        $stateId = State::saveState($state, 'privacyidea:privacyidea');

        $url = Module::getModuleURL('privacyidea/FormBuilder.php');
        HTTP::redirectTrustedURL($url, array('stateId' => $stateId));
    }

    /**
     * This is the help function to exclude some IP from 2FA. Only if is set in config.
     * @param string $clientIP
     * @param array $excludeClientIPs
     * @return bool
     */
    private function matchIP(string $clientIP, array $excludeClientIPs): bool
    {
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
     * @throws NoState
     */
    private function checkEntityID(array $authProcConfig, string $stateId): string
    {
        Logger::debug("Checking requesting entity ID for privacyIDEA");
        $state = State::loadState($stateId, 'privacyidea:privacyidea', true);

        $excludeEntityIDs = $authProcConfig['excludeEntityIDs'] ?: array();
        $includeAttributes = $authProcConfig['includeAttributes'] ?: array();
        $setPath = $authProcConfig['setPath'] ?: "";
        $setKey = $authProcConfig['setKey'] ?: '';

        // the default return value is true, privacyIDEA should be enabled by default.
        $ret = true;
        $requestEntityID = $state["Destination"]["entityid"];

        // if the requesting entityID matches the given list set the return parameter to false
        Logger::debug("privacyidea:checkEntityID: Requesting entityID is " . $requestEntityID);
        $matchedEntityIDs = $this->strMatchesRegArr($requestEntityID, $excludeEntityIDs);
        if ($matchedEntityIDs)
        {
            $ret = false;
            $entityIDKey = $matchedEntityIDs[0];
            Logger::debug("privacyidea:checkEntityID: Matched entityID is " . $entityIDKey);

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
                                Logger::debug("privacyidea:checkEntityID: Requesting entityID in " .
                                              "list, but excluded by at least one attribute regexp \"" . $attrKey .
                                              "\" = \"" . $matchedAttrs[0] . "\".");
                                break;
                            }
                        }
                    }
                    else
                    {
                        Logger::debug("privacyidea:checkEntityID: attribute key " .
                                      $attrKey . " not contained in request");
                    }
                }
            }
        }
        else
        {
            Logger::debug("privacyidea:checkEntityID: Requesting entityID " .
                          $requestEntityID . " not matched by any regexp.");
        }

        $state[$setPath][$setKey][0] = $ret;

        $stateId = State::saveState($state, 'privacyidea:privacyidea');

        if ($ret)
        {
            $retStr = "true";
        }
        else
        {
            $retStr = "false";
        }
        Logger::debug("Setting \$state[" . $setPath . "][" . $setKey . "][0] = " . $retStr . ".");
        return $stateId;
    }

    /**
     * This is the help function for checkEntityID() and checks a given string against an array with regular expressions.
     * It will return an array with matches.
     * @param string $str
     * @param array $reg_arr
     * @return array
     */
    private function strMatchesRegArr(string $str, array $reg_arr): array
    {
        $retArr = array();

        foreach ($reg_arr as $reg)
        {
            if ($reg[0] != "/")
            {
                $reg = "/" . $reg . "/";
            }
            Logger::debug("privacyidea:checkEntityID: test regexp " . $reg . " against the string " . $str);

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
    public static function isPrivacyIDEADisabled(array $state, array $config): bool
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
     * @param string $message
     */
    public function piDebug(string $message): void
    {
        Logger::debug($message);
    }

    /**
     * This function allows to show the debug messages from privacyIDEA server
     * @param string $message
     */
    public function piError(string $message): void
    {
        Logger::error($message);
    }
}
