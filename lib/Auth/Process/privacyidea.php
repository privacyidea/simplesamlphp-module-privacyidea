<?php
/**
 * This authentication processing filter allows you to add a second step
 * authentication against privacyIDEA
 *
 * @author Cornelius Kölbel <cornelius.koelbel@netknights.it>
 * @author Jean-Pierre Höhmann <jean-pierre.hoehmann@netknights.it>
 */


class sspmod_privacyidea_Auth_Process_privacyidea extends SimpleSAML_Auth_ProcessingFilter
{
    /**
     * This contains the server configuration
     * @var array
     */
    private $serverconfig;

    /**
     * privacyidea constructor.
     *
     * @param array $config The configuration of this authproc.
     * @param mixed $reserved
     *
     * @throws \SimpleSAML\Error\CriticalConfigurationError in case the configuration is wrong.
     */
    public function __construct(array $config, $reserved)
    {
        assert('array' === gettype($config));

        parent::__construct($config, $reserved);
        $this->serverconfig = $config;
        // set defaults
        if (!isset($this->serverconfig['tryFirstAuthentication'])) { $this->serverconfig['tryFirstAuthentication'] = false; }
        if (!isset($this->serverconfig['doTriggerChallenge'])) { $this->serverconfig['doTriggerChallenge'] = false; }
        if (!isset($this->serverconfig['SSO'])) { $this->serverconfig['SSO'] = true; }
    }

    /**
     * Run the filter.
     *
     * @param array $state
     *
     * @throws \Exception if authentication fails
     */
    public function process(&$state)
    {
        assert('array' === gettype($state));

        SimpleSAML_Logger::info("privacyIDEA Auth Proc Filter: Entering process function");

        $this->serverconfig = sspmod_privacyidea_Auth_utils::buildServerconfig(
            $state['privacyidea:serverconfig'],
            $this->serverconfig,
            $state
        );
        $state['privacyidea:privacyidea'] = $this->serverconfig;

        if (sspmod_privacyidea_Auth_utils::privacyIdeaIsDisabled($state, $this->serverconfig)) {
            SimpleSAML_Logger::debug(
                "privacyIDEA: "
                . $this->serverconfig['enabledPath']
                . " -> "
                . $this->serverconfig['enabledKey']
                . " is not set to true -> privacyIDEA is disabled"
            );
            return;
        }

        // skip 2FA for authenticated users in passive requests and if SSO is enabled
        if (isset($state['isPassive']) && $state['isPassive'] === true) {
            if (SimpleSAML_Session::getSessionFromRequest()->getData('privacyidea:privacyidea', 'authenticated')) {
                SimpleSAML_Logger::debug("privacyIDEA: ignore passive SAML request for already logged in user");
                return;
            }
            throw new \SimpleSAML\Module\saml\Error\NoPassive('Passive authentication (OTP) not supported.');
        } elseif ($this->serverconfig['SSO'] === true) {
            if (SimpleSAML_Session::getSessionFromRequest()->getData('privacyidea:privacyidea', 'authenticated')) {
                SimpleSAML_Logger::debug("privacyIDEA: SAML request for already logged in user. Disabling privacyIDEA, since SSO is enabled.");
                return;
            }
        }

        if (!$this->serverconfig['privacyideaserver']) {SimpleSAML_Logger::error("privacyIDEA url is not set!");}
        if ($this->maybeTryFirstAuthentication($state)) {return;}
        if ($this->serverconfig['doTriggerChallenge']) {$state = $this->triggerChallenge($state);}

        self::openOtpform($state);
    }

    private function maybeTryFirstAuthentication($state) {
        return $this->serverconfig['tryFirstAuthentication']
            && sspmod_privacyidea_Auth_utils::authenticate(
                $state,
                array('pass' => $this->serverconfig['tryFirstAuthPass'])
            );
    }

    private function triggerChallenge($state) {
        assert('array' === gettype($state));

        $authToken = sspmod_privacyidea_Auth_utils::fetchAuthToken($this->serverconfig);
        $body = sspmod_privacyidea_Auth_utils::curl(
            array("user" => $state["Attributes"][$this->serverconfig['uidKey']][0]),
            array("authorization:" . $authToken),
            $this->serverconfig,
            "/validate/triggerchallenge",
            "POST");
        return sspmod_privacyidea_Auth_utils::checkTokenType($state, $body);
    }

    private static function openOtpform($state) {
        assert('array' === gettype($state));

        SimpleSAML_Logger::debug("privacyIDEA: privacyIDEA is enabled, so we use 2FA");
        $state['privacyidea:privacyidea:authenticationMethod'] = "authprocess";
        $id = SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea:init');
        $url = SimpleSAML_Module::getModuleURL('privacyidea/otpform.php');
        SimpleSAML_Utilities::redirectTrustedURL($url, array('StateId' => $id));
    }
}
