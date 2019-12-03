<?php

const DEFAULT_UID_KEYS = array("username", "surname", "email", "givenname", "mobile", "phone", "realm", "resolver");

/**
 * privacyidea authentication module.
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
class sspmod_privacyidea_Auth_Source_privacyidea extends sspmod_core_Auth_UserPassBase
{
    /**
     * The serverconfig is listed in this array
     * @var array
     */
    private $serverconfig;

    /**
     * Check whether the OTP should be in its own field.
     *
     * @return 0|1 Whether the OTP is in an extra field.
     */
    public function getOtpExtra()
    {
        return $this->serverconfig['otpextra'] ?: 0;
    }

    /**
     * Constructor for this authentication source.
     *
     * @param array $info Information about this authentication source.
     * @param array $config Configuration.
     */
    public function __construct($info, $config)
    {
        assert('array' === gettype($info));
        assert('array' === gettype($config));

        parent::__construct($info, $config);
        foreach (array('attributemap', 'detailmap', 'concatenationmap') as $i) {
            $config[$i] = $config[$i] ?: array();
        }
        $this->serverconfig = $config;
    }

    /**
     * Attempt to log in using the given username and password.
     *
     * @param string $username The username the user wrote.
     * @param string $password The password the user wrote.
     * @return array  Associative array with the users attributes.
     * Each attribute needs to contain a list:
     * {"uid" => {0 => "Administrator},
     *  "givenName" => {0 => "Hans",
     *                  1 => "Dampf"}
     * }
     */
    protected function login($username, $password)
    {
        // Stub.
        return;
    }

    protected function login_chal_resp($state, $username, $password, $transaction_id, $signaturedata, $clientdata)
    {
        assert('string' === gettype($username));
        assert('string' === gettype($password));
        assert('string' === gettype($transaction_id));

        if (!$auth = sspmod_privacyidea_Auth_utils::authenticate(
            $state,
            array(
                "user" => $username,
                "pass" => $password,
                "realm" => @$this->serverconfig['realm'],
                "transaction_id" => $transaction_id,
                "signaturedata" => $signaturedata,
                "clientdata" => $clientdata
            ),
            $this->serverconfig
        )) {throw new SimpleSAML_Error_Error("WRONGUSERPASS");}

        /* If we get this far, we have a valid login. */
        $user_attributes = $auth['attributes'];
        $detailAttributes = $auth['detail'];
        $attributes = array();
        $keys = array_merge(array_keys($this->serverconfig['attributemap']), DEFAULT_UID_KEYS);
        foreach ($keys as $key) {
            SimpleSAML_Logger::debug("privacyidea        key: " . $key);
            $attribute_value = $user_attributes->$key;
            if ($attribute_value) {
                $attribute_key = @$this->serverconfig['attributemap'][$key] ?: $key;
                $attributes[$attribute_key] = is_array($attribute_value) ? $attribute_value : array($attribute_value);
                SimpleSAML_Logger::debug("privacyidea key: " . $attribute_key);
                SimpleSAML_Logger::debug("privacyidea value: " . print_r($attribute_value, TRUE));
            }
        }
        foreach ($this->serverconfig['detailmap'] as $key => $mapped_key) {
            SimpleSAML_Logger::debug("privacyidea        key: " . print_r($key, TRUE));
            SimpleSAML_Logger::debug("privacyidea mapped key: " . print_r($mapped_key, TRUE));
            $attribute_value = $detailAttributes->$key;
            $attributes[$mapped_key] = is_array($attribute_value) ? $attribute_value : array($attribute_value);
        }
        foreach ($this->serverconfig['concatenationmap'] as $key => $mapped_key) {
            SimpleSAML_Logger::debug("privacyidea        key: " . print_r($key, TRUE));
            SimpleSAML_Logger::debug("privacyidea mapped key: " . print_r($mapped_key, TRUE));
            $concatenationArr = explode(",", $key);
            $concatenationValues = array();
            foreach ($concatenationArr as $item) {
                $concatenationValues[] = $user_attributes->$item;
            }
            $concatenationString = implode(" ", $concatenationValues);
            $attributes[$mapped_key] = array($concatenationString);
        }
        SimpleSAML_Logger::debug("privacyidea Array returned: " . print_r($attributes, True));
        return $attributes;
    }

    /**
     * Initialize login.
     *
     * This function saves the information about the login, and redirects to a
     * login page.
     *
     * @param array &$state Information about the current authentication.
     */
    public function authenticate(&$state)
    {
        assert('array' === gettype($state));

        /* We are going to need the authId in order to retrieve this authentication source later. */
        $state[self::AUTHID] = $this->authId;
        $state['privacyidea:privacyidea:authenticationMethod'] = "authsource";
        SimpleSAML_Logger::debug("privacyIDEA authId: " . $this->authId);

        $id = SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea:init');
        SimpleSAML_Logger::debug("Saved state privacyidea:privacyidea:init from Source/privacyidea.php");

        $url = SimpleSAML_Module::getModuleURL('privacyidea/otpform.php');
        SimpleSAML_Utilities::redirectTrustedURL($url, array('StateId' => $id));
    }

    /**
     * Handle login request.
     *
     * This function is used by the login form (core/www/loginuserpass.php) when the user
     * enters a username and password. On success, it will not return. On wrong
     * username/password failure, and other errors, it will throw an exception.
     *
     * @param string $authStateId The identifier of the authentication state.
     * @param string $username The username the user wrote.
     * @param string $password The password the user wrote.
     * @param $transaction_id
     * @param $signaturedata
     * @param $clientdata
     * @throws Exception
     */
    public static function handleLogin($authStateId, $username, $password, $transaction_id = NULL, $signaturedata = NULL, $clientdata = NULL)
    {
        assert('string' === gettype($authStateId));
        assert('string' === gettype($username));
        assert('string' === gettype($password));
        assert('string' === gettype($transaction_id));

        SimpleSAML_Logger::debug("calling privacyIDEA handleLogin with authState: " . $authStateId . " for user " . $username);
        if (array_key_exists("OTP", $_REQUEST)) {
            $otp = $_REQUEST["OTP"];
            $password = $password . $otp;
            SimpleSAML_Logger::stats('Found OTP in Auth request. Concatenating passwords.');
        }

        // sanitize the input
        $sid = SimpleSAML_Utilities::parseStateID($authStateId);
        if (!is_null($sid['url'])) {
            SimpleSAML_Utilities::checkURLAllowed($sid['url']);
        }

        /* Here we retrieve the state array we saved in the authenticate-function. */
        $state = SimpleSAML_Auth_State::loadState($authStateId, "privacyidea:privacyidea:init");
        SimpleSAML_Logger::debug("Loaded state privacyidea:privacyidea:init from Source/privacyidea.php");

        /* Retrieve the authentication source we are executing. */
        $source = SimpleSAML_Auth_Source::getById($state[self::AUTHID]);
        if ($source === NULL) {
            throw new Exception('Could not find authentication source with id ' . $state[self::AUTHID]);
        }

        /*
         * $source now contains the authentication source on which authenticate()
         * was called. We should call login() on the same authentication source.
         */

        /* Attempt to log in. */
        try {
            $attributes = $source->login_chal_resp($state, $username, $password, $transaction_id, $signaturedata, $clientdata);
        } catch (Exception $e) {
            SimpleSAML_Logger::stats('Unsuccessful login attempt from ' . $_SERVER['REMOTE_ADDR'] . '.');
            throw $e;
        }

        SimpleSAML_Logger::stats('User \'' . $username . '\' has been successfully authenticated.');

        /* Save the attributes we received from the login-function in the $state-array. */
        $state['Attributes'] = $attributes;

        /* Return control to simpleSAMLphp after successful authentication. */
        SimpleSAML_Auth_Source::completeAuth($state);
    }

}
