<?php

require_once((dirname(__FILE__, 3)) . '/php-client/src/Client-Autoloader.php');
require_once((dirname(__FILE__, 2)) . '/PILogger.php');

const DEFAULT_UID_KEYS = array("username", "surname", "email", "givenname", "mobile", "phone", "realm", "resolver");

/**
 * privacyidea authentication module.
 * 2021-08-21 Lukas Matusiewicz <lukas.matusiewicz@netknights.it>
 *            Major refactor.
 * 2019-11-30 Jean-Pierre Hömann <jean-pierre.hoehmann@netknights.it>
 *            Major refactor.
 * 2018-03-16 Cornelius Kölbel <cornelius.koelbel@netknights.it>
 *            Replace [] with array()
 * 2017-08-17 Cornelius Kölbel <cornelius.koelbel@netknights.it>
 *            Change POST params to array and
 *            only add REALM if necessary
 * 2017-02-13 Cornelius Kölbel <cornelius.koelbel@netknights.it>
 *            Forward the client IP to privacyIDEA
 * 2016-12-30 Andreas Böhler <dev@rnb-consulting.at>
 *            Add support for passing additional attributes to SAML
 * 2015-11-21 Cornelius Kölbel <cornelius.koelbel@netknights.it>
 *            Add support for U2F authentication requests
 * 2015-11-19 Cornelius Kölbel <cornelius.koelbel@netknights.it>
 *            Add authenticate method to call our own template.
 *            Add handleLogin method to be able to handle challenge response.
 * 2015-11-05 Cornelius Kölbel <cornelius.koelbel@netknights.it>
 *            Revert the authentication logic to avoid false logins
 * 2015-09-23 Cornelius Kölbel <cornelius.koelbel@netknights.it>
 *            Adapt for better usability with
 *            Univention Corporate Server
 *            Change Auth Request to POST
 * 2015-04-11 Cornelius Kölbel <cornelius.koelbel@netknights.it>
 *            minor changes by code climate
 * 2014-09-29 Cornelius Kölbel, cornelius@privacyidea.org
 *
 * This is forked from simplesamlphp-linotp,
 * (https://github.com/lsexperts/simplesamlphp-linotp)
 * which is based on Radius.php
 *
 */
class sspmod_privacyidea_Auth_Source_PrivacyideaAuthSource extends sspmod_core_Auth_UserPassBase
{
    /* @var array The serverconfig is listed in this array */
    public $authSourceConfig;

    /* @var PrivacyIDEA object representing the privacyIDEA authentication server */
    public $pi;

    /**
     * Constructor for this authentication source.
     * @param array $info Information about this authentication source.
     * @param array $config Configuration set in authsources.php
     */
    public function __construct(array $info, array $config)
    {
        assert('array' === gettype($info));
        assert('array' === gettype($config));

        parent::__construct($info, $config);

        if (!in_array('attributemap', $config))
        {
            $config['attributemap'] = array();
        }
        if (!in_array('detailmap', $config))
        {
            $config['detailmap'] = array();
        }
        if (!in_array('concatenationmap', $config))
        {
            $config['concatenationmap'] = array();
        }

        $this->authSourceConfig = $config;
        $this->pi = sspmod_privacyidea_Auth_Utils::createPrivacyIDEAInstance($this->authSourceConfig);
        if ($this->pi == null)
        {
            throw new SimpleSAML_Error_ConfigurationError("privacyIDEA: Initialization failed.");
        }
    }

    /**
     * Initialize login.
     * This function saves the information about the login, and redirects to the login page.
     *
     * @override
     * @param array &$state Information about the current authentication.
     */
    public function authenticate(&$state)
    {
        assert('array' === gettype($state));
        SimpleSAML_Logger::debug("privacyIDEA AuthSource authenticate");

        // SSO check if authentication should be skipped
        if (array_key_exists('SSO', $this->authSourceConfig) &&
            $this->authSourceConfig['SSO'] == true &&
            sspmod_privacyidea_Auth_Utils::checkForValidSSO($state))
        {
            $session = SimpleSAML_Session::getSessionFromRequest();
            $attributes = $session->getData('privacyidea:privacyidea', 'attributes');
            SimpleSAML_Logger("privacyIDEA: SSO retrieved attributes from session: " . print_r($attributes, true));
            $state['Attributes'] = $attributes;
            SimpleSAML_Auth_Source::completeAuth($state);
        }

        $state['privacyidea:privacyidea'] = $this->authSourceConfig;

        // We are going to need the authID in order to retrieve this authentication source later.
        $state['privacyidea:privacyidea']['AuthId'] = self::getAuthId();
        SimpleSAML_Logger::debug("privacyIDEA AuthSource authId: " . $state['privacyidea:privacyidea']['AuthId']);
        $state['privacyidea:privacyidea']['transactionID'] = "";
        $state['privacyidea:privacyidea']['authenticationMethod'] = "authsource";

        $state['privacyidea:privacyidea:ui']['step'] = "1";
        $state['privacyidea:privacyidea:ui']['pushAvailable'] = "0";
        $state['privacyidea:privacyidea:ui']['otpAvailable'] = "1";
        $state['privacyidea:privacyidea:ui']['message'] = "";
        $state['privacyidea:privacyidea:ui']['webAuthnSignRequest'] = "";
        $state['privacyidea:privacyidea:ui']['u2fSignRequest'] = "";
        $state['privacyidea:privacyidea:ui']['mode'] = "otp";
        $state['privacyidea:privacyidea:ui']['otpFieldHint'] = @$this->authSourceConfig['otpFieldHint'] ?: "";
        $state['privacyidea:privacyidea:ui']['passFieldHint'] = @$this->authSourceConfig['passFieldHint'] ?: "";
        $state['privacyidea:privacyidea:ui']['loadCounter'] = "1";

        $stateId = SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea');

        $url = SimpleSAML_Module::getModuleURL('privacyidea/FormBuilder.php');
        SimpleSAML_Utilities::redirectTrustedURL($url, array('stateId' => $stateId));
    }

    /**
     * Attempt to log in using the given username and password.
     * @override
     * @param string $username The username the user wrote.
     * @param string $password The password the user wrote.
     */
    protected function login($username, $password)
    {
        // Stub.
        SimpleSAML_Logger::debug("privacyIDEA AuthSource login stub");
    }

    /**
     * This function process the login for auth source.
     *
     * @param string $stateId
     * @param array $formParams
     * @throws Exception
     */
    public static function authSourceLogin($stateId, $formParams)
    {
        assert('array' === gettype($stateId));
        assert('array' === gettype($formParams));

        $state = SimpleSAML_Auth_State::loadState($stateId, 'privacyidea:privacyidea');
        $step = $state['privacyidea:privacyidea:ui']['step'];

        $source = SimpleSAML_Auth_Source::getById($state['privacyidea:privacyidea']["AuthId"]);
        if (!$source)
        {
            throw new Exception('Could not find authentication source with ID ' . $state["AuthId"]);
        }

        // If it is the first step, trigger challenges or send the password if configured
        $username = $formParams['username'];
        $password = "";
        if (!empty($formParams['pass']))
        {
            $password = $formParams['pass'];
        }

        $response = null;
        if ($step == 1)
        {
            $state['privacyidea:privacyidea']['username'] = $username;
            $stateId = SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea');

            if (array_key_exists("doTriggerChallenge", $source->authSourceConfig)
                && $source->authSourceConfig["doTriggerChallenge"] === 'true')
            {
                if (!empty($username) && $source->pi->serviceAccountAvailable())
                {
                    $response = $source->pi->triggerChallenge($username);
                }
            }
            elseif (array_key_exists("doSendPassword", $source->authSourceConfig)
                && $source->authSourceConfig['doSendPassword'] === 'true')
            {
                if (!empty($username))
                {
                    $response = $source->pi->validateCheck($username, $password);
                }
            }
        }
        elseif ($step > 1)
        {
            $response = sspmod_privacyidea_Auth_Utils::authenticatePI($state, $formParams);
            $stateId = SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea');
        }
        else
        {
            SimpleSAML_Logger::error("privacyIDEA: UNDEFINED STEP: " . $step);
        }

        if ($response != null)
        {
            $stateId = sspmod_privacyidea_Auth_Utils::processPIResponse($stateId, $response, $source->authSourceConfig);
        }

        $state = SimpleSAML_Auth_State::loadState($stateId, 'privacyidea:privacyidea');

        // Increase steps counter
        if (empty($state['privacyidea:privacyidea']['errorMessage']))
        {
            $state['privacyidea:privacyidea:ui']['step'] = $step + 1;
        }

        //SimpleSAML_Logger::error("NEW STEP: " . $state['privacyidea:privacyidea:ui']['step']);
        $stateId = SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea');
        $url = SimpleSAML_Module::getModuleURL('privacyidea/FormBuilder.php');
        SimpleSAML_Utilities::redirectTrustedURL($url, array('stateId' => $stateId));
    }

    /**
     * Check if the attributes that are required by SSP are contained in the response of privacyIDEA. They are then merged
     * with the attributes specified in the configuration before returning control to SSP.
     * If the authentication is complete, this function does not return.
     * If SSO is enabled, this will also register the loginCompletedHandler that will write the necessary data.
     *
     * @param array $state
     * @param PIResponse $piResponse
     * @param $authSourceConfig
     */
    public static function checkAuthenticationComplete($state, PIResponse $piResponse, $authSourceConfig)
    {
        $attributes = $piResponse->detailAndAttributes;

        if (!empty($attributes))
        {
            $userAttributes = $attributes['attributes'];
            $detailAttributes = $attributes['detail'];

            $completeAttributes = self::mergeAttributes($userAttributes, $detailAttributes, $authSourceConfig);
            $state['Attributes'] = $completeAttributes;

            if (array_key_exists('SSO', $authSourceConfig) && $authSourceConfig['SSO'] == true)
            {
                /*
                 * In order to be able to register a logout handler for the session (mandatory for SSO to work),
                 * the authority is required in the session's authData.
                 * The authority can be put there by invoking Session::doLogin, which should be done by the LoginCompletedHandler.
                 * To be able to do something after Session::doLogin, the LoginCompletedHandler has to be replaced with
                 * an implementation that writes the SSO data and attributes in this case (AuthSource) to the session.
                 */
                $state['LoginCompletedHandler'] = ['sspmod_privacyidea_Auth_Source_PrivacyideaAuthSource', 'loginCompletedWriteSSO'];
            }

            // Return control to simpleSAMLphp after successful authentication.
            SimpleSAML_Auth_Source::completeAuth($state);
        }
    }

    /**
     * This function merge all attributes and detail which SimpleSAMLphp needs.
     *
     * @param $userAttributes
     * @param $detailAttributes
     * @param $authSourceConfig
     * @return array
     */
    protected static function mergeAttributes($userAttributes, $detailAttributes, $authSourceConfig)
    {
        // Prepare attributes array to return
        $attributes = array();

        // attributemap is set in config/authsources.php
        $keys = array_merge(array_keys($authSourceConfig['attributemap']), DEFAULT_UID_KEYS);
        $keys = array_unique($keys);

        // Keep all reservations from attributemap to translate PI attributes names to SAML attributes names.
        foreach ($keys as $key)
        {
            //SimpleSAML_Logger::debug("privacyidea key: " . $key);
            $attributeValue = $userAttributes[$key];

            if ($attributeValue)
            {
                $attributeKey = @$authSourceConfig['attributemap'][$key] ?: $key;
                $attributes[$attributeKey] = is_array($attributeValue) ? $attributeValue : array($attributeValue);

                //SimpleSAML_Logger::debug("privacyidea key: " . $attributeKey);
                //SimpleSAML_Logger::debug("privacyidea value: " . print_r($attributeValue, TRUE));
            }
        }

        // Keep all reservations from detailmap to know which attributes are set to show in UI.
        // Detailmap was set in config/authsources.php
        foreach ($authSourceConfig['detailmap'] as $key => $mappedKey)
        {
            //SimpleSAML_Logger::debug("privacyIDEA:        key: " . print_r($key, TRUE));
            //SimpleSAML_Logger::debug("privacyIDEA: mapped key: " . print_r($mappedKey, TRUE));

            $attributeValue = $detailAttributes->$key;
            $attributes[$mappedKey] = is_array($attributeValue) ? $attributeValue : array($attributeValue);
        }

        // Keep all reservations from concatenationmap to fuse some attributes together.
        // Concatenationmap was set in config/authsources.php
        foreach ($authSourceConfig['concatenationmap'] as $key => $mappedKey)
        {
            //SimpleSAML_Logger::debug("privacyIDEA:        key: " . print_r($key, TRUE));
            //SimpleSAML_Logger::debug("privacyIDEA: mapped key: " . print_r($mappedKey, TRUE));

            $concatenationArr = explode(",", $key);
            $concatenationValues = array();

            foreach ($concatenationArr as $item)
            {
                $concatenationValues[] = $userAttributes->$item;
            }

            $concatenationString = implode(" ", $concatenationValues);
            $attributes[$mappedKey] = array($concatenationString);
        }

        SimpleSAML_Logger::debug("privacyIDEA: Attributes returned: " . print_r($attributes, True));
        return $attributes;
    }

    /**
     * Copy of the original loginCompletedHandler that will additionally write the SSO data and user attributes to
     * the session after performing the standard login.
     *
     * @param array $state The state after the login has completed.
     */
    public static function loginCompletedWriteSSO(array $state)
    {
        SimpleSAML_Logger::debug("privacyIDEA: loginCompletedWriteSSO");
        assert(array_key_exists('\SimpleSAML\Auth\Source.Return', $state));
        assert(array_key_exists('\SimpleSAML\Auth\Source.id', $state));
        assert(array_key_exists('Attributes', $state));
        assert(!array_key_exists('LogoutState', $state) || is_array($state['LogoutState']));

        $return = $state['\SimpleSAML\Auth\Source.Return'];

        // save session state
        $session = SimpleSAML_Session::getSessionFromRequest();
        $authId = $state['\SimpleSAML\Auth\Source.id'];
        $session->doLogin($authId, SimpleSAML_Auth_State::getPersistentAuthData($state));

        // In addition to the SSO data, the attributes have to be written to the session so that they can be retrieved
        // and used on the next login
        sspmod_privacyidea_Auth_Utils::tryWriteSSO();
        $session->setData('privacyidea:privacyidea', "attributes", $state['Attributes']);

        if (is_string($return))
        {
            // redirect...
            $httpUtils = new SimpleSAML_Utils_HTTP();
            $httpUtils->redirectTrustedURL($return);
        }
        else
        {
            call_user_func($return, $state);
        }
        assert(false);
    }

    /**
     * Check if url is allowed.
     * @param $id
     */
    private static function checkIdLegality($id)
    {
        $sid = SimpleSAML_Utilities::parseStateID($id);
        if (!is_null($sid['url']))
        {
            SimpleSAML_Utilities::checkURLAllowed($sid['url']);
        }
    }
}