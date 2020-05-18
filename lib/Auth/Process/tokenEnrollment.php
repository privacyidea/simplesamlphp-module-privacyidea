<?php
/**
 * If a user does not have a token, a new one could be enrolled.
 * This one will be generated with a QR-code, which can be scanned with a mobile device.
 * For that you'll need an application like 'privacyIDEA Authenticator' or 'Google Authenticator'
 * @author Micha Preußer <micha.preusser@netknights.it>
 */

class sspmod_privacyIDEA_Auth_Process_tokenEnrollment extends SimpleSAML_Auth_ProcessingFilter
{

    /**
     * This is the token, which will be fetched by the service account.
     * It is needed to get the number of tokens and to enroll one.
     * @var String
     */
    private $auth_token;

    /**
     * This contains the server configuration
     * @var array
     */
    private $serverconfig;

    public function __construct(array $config, $reserved)
    {
        assert('array' === gettype($config));

        parent::__construct($config, $reserved);
        $this->serverconfig = $config;
    }

    /**
     * Perform token enrollment, if necessary.
     *
     * @param array &$state The global state of simpleSAMLphp
     */
    public function process(&$state)
    {
        assert('array' === gettype($state));

        $this->serverconfig = sspmod_privacyidea_Auth_utils::buildServerconfig(
            $state['privacyidea:serverconfig'],
            $this->serverconfig,
            $state
        );

        if (sspmod_privacyidea_Auth_utils::privacyIdeaIsDisabled($state, $this->serverconfig)) {return;}
        if ($this->doesNotHaveServiceAccount()) {
            SimpleSAML_Logger::error("privacyIDEA service account for token enrollment is not set!");
            return;
        }
        if (!$this->serverconfig['privacyideaserver']) {
            SimpleSAML_Logger::error("privacyIDEA url is not set!");
            return;
        }

        $this->auth_token = sspmod_privacyidea_Auth_utils::fetchAuthToken($this->serverconfig);
        if (!$this->userHasToken($state)) {
            $body = $this->enrollToken($state);
            if ($this->serverconfig['tokenType'] === "u2f") {
                $state['privacyidea:tokenEnrollment']['enrollU2F'] = true;
                $state['privacyidea:tokenEnrollment']['authToken'] = $this->auth_token;
                $state['privacyidea:tokenEnrollment']['serial']
                    = sspmod_privacyidea_Auth_utils::nullCheck(@$body->detail->serial);
            } else {
                $state['privacyidea:tokenEnrollment']['tokenQR']
                    = sspmod_privacyidea_Auth_utils::nullCheck(@$body->detail->googleurl->img);
            }
        }
    }

    /**
     * Perform an api-request to enroll the actual token.
     *
     * @param array &$state The global state of simpleSAMLphp
     * @return array The response from the privacyIDEA-server.
     */
    public function enrollToken(&$state)
    {
        assert('array' === gettype($state));

        $params = array(
            "user" => $state["Attributes"][$this->serverconfig['uidKey']][0],
            "genkey" => 1,
            "type" => $this->serverconfig['tokenType'],
            "description" => "Enrolled with simpleSAMLphp",
        );
        $headers = array(
            "authorization: " . $this->auth_token,
        );

        return sspmod_privacyidea_Auth_utils::curl($params, $headers, $this->serverconfig, "/token/init", "POST");
    }

    /**
     * Check whether the user already has a token.
     *
     * @param array &$state The global state of simpleSAMLphp
     * @return bool Whether the user already has a token enrolled.
     */
    public function userHasToken(&$state)
    {
        assert('array' === gettype($state));

        return !!sspmod_privacyidea_Auth_utils::nullCheck(
            @sspmod_privacyidea_Auth_utils::curl(
                array("user" => $state["Attributes"][$this->serverconfig['uidKey']][0]),
                array("authorization: " . $this->auth_token),
                $this->serverconfig,
                "/token/",
                "GET"
            )->result->value->count
        );
    }

    private function doesNotHaveServiceAccount() {
        return !$this->serverconfig['serviceAccount'] || !$this->serverconfig['servicePass'];
    }
}