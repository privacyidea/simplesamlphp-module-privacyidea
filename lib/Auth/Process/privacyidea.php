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

        SimpleSAML_Logger::info("Create the Auth Proc Filter privacyidea");
        parent::__construct($config, $reserved);
        $this->serverconfig = $config;
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

        if (!isset($state[$this->serverconfig['enabledPath']][$this->serverconfig['enabledKey']][0])) {
            SimpleSAML_Logger::debug(
                "privacyIDEA: "
                . $this->serverconfig['enabledPath']
                . " -> "
                . $this->serverconfig['enabledKey']
                . " is not set to true -> privacyIDEA is disabled"
            );
            return;
        }
        if ($this->serverconfig['privacyideaserver'] === '') {
            $piEnabled = False;
            SimpleSAML_Logger::error("privacyIDEA url is not set!");
        }

        if (
            $this->serverconfig['tryFirstAuthentication']
            && sspmod_privacyidea_Auth_utils::authenticate(
                $state,
                array('pass' => $this->serverconfig['tryFirstAuthPass'])
            )
        ) {return;}
        if ($this->serverconfig['doTriggerChallenge']) {
            $authToken = sspmod_privacyidea_Auth_utils::fetchAuthToken($this->serverconfig);
            $params = array(
                "user" => $state["Attributes"][$this->serverconfig['uidKey']][0],
            );
            $headers = array(
                "authorization:" . $authToken,
            );
            $body = sspmod_privacyidea_Auth_utils::curl($params, $headers, $this->serverconfig, "/validate/triggerchallenge", "POST");
            $state = sspmod_privacyidea_Auth_utils::checkTokenType($state, $body);
        }
        SimpleSAML_Logger::debug("privacyIDEA: privacyIDEA is enabled, so we use 2FA");
        $state['privacyidea:privacyidea:authenticationMethod'] = "authprocess";
        $id = SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea:init');
        SimpleSAML_Logger::debug("Saved state privacyidea:privacyidea:init from Process/privacyidea.php");
        $url = SimpleSAML_Module::getModuleURL('privacyidea/otpform.php');
        SimpleSAML_Utilities::redirectTrustedURL($url, array('StateId' => $id));
    }

}
