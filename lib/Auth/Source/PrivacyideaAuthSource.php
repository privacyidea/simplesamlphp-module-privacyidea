<?php

namespace SimpleSAML\Module\privacyidea\Auth\Source;

use PrivacyIdea\PHPClient\PILog;
use PrivacyIdea\PHPClient\PrivacyIDEA;
use SimpleSAML\Auth\State;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\core\Auth\UserPassBase;
use SimpleSAML\Utils\HTTP;

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
class PrivacyideaAuthSource extends UserPassBase implements PILog
{
    /* @var array The serverconfig is listed in this array */
    public $authSourceConfig;
    /* @var PrivacyIDEA PrivacyIDEA object */
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

        // Build a pi object
        if (!empty($this->authSourceConfig['privacyideaServerURL']))
        {
            $this->pi = new PrivacyIDEA("simpleSAMLphp", $this->authSourceConfig['privacyideaServerURL']);
        }
        if (!empty($this->authSourceConfig['sslVerifyHost']))
        {
            $this->pi->sslVerifyHost = $this->authSourceConfig['sslVerifyHost'] !== "false";
        }
        if (!empty($this->authSourceConfig['sslVerifyPeer']))
        {
            $this->pi->sslVerifyPeer = $this->authSourceConfig['sslVerifyPeer'] !== "false";
        }
        if (!empty($this->authSourceConfig['serviceAccount']))
        {
            $this->pi->serviceAccountName = $this->authSourceConfig['serviceAccount'];
        }
        if (!empty($this->authSourceConfig['servicePass']))
        {
            $this->pi->serviceAccountPass = $this->authSourceConfig['servicePass'];
        }
        if (!empty($this->authSourceConfig['serviceRealm']))
        {
            $this->pi->serviceAccountRealm = $this->authSourceConfig['serviceRealm'];
        }
        if (!empty($this->authSourceConfig['privacyideaServerURL']))
        {
            $this->pi->logger = $this;
        }
    }

    /**
     * Initialize login.
     * This function saves the information about the login, and redirects to the login page.
     * @override
     * @param array &$state Information about the current authentication.
     */
    public function authenticate(&$state)
    {
        assert('array' === gettype($state));
        Logger::debug("privacyIDEA AUTH SOURCE authenticate...");

        // We are going to need the authID in order to retrieve this authentication source later.
        $state['privacyidea:privacyidea']['AuthId'] = self::getAuthId();
        Logger::debug("privacyIDEA AUTH SOURCE stateID: " . $state['privacyidea:privacyidea']['AuthId']);
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

        $stateID = State::saveState($state, 'privacyidea:privacyidea');
        Logger::debug("Saved state privacyidea:privacyidea from Source/privacyidea.php");

        $url = Module::getModuleURL('privacyidea/formbuilder.php');
        HTTP::redirectTrustedURL($url, array('StateId' => $stateID));
    }

    public function piDebug($message)
    {
        Logger::debug("PrivacyIDEA AUTHSOURCE: " . $message);
    }

    public function piError($message)
    {
        Logger::error("PrivacyIDEA AUTHSOURCE: " . $message);
    }

    /**
     * Attempt to log in using the given username and password.
     * @override
     * @param string $username The username the user wrote.
     * @param string $password The password the user wrote.
     * @return array  Associative array with the users attributes.
     */
    protected function login($username, $password)
    {
        // Stub.
        Logger::debug("privacyIDEA AUTHSOURCE LOGIN");
        return;
    }
}