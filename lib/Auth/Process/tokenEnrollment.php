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

        foreach ($state['privacyidea:serverconfig'] as $key => $value) {
            if (!isset($this->serverconfig[$key])) {$this->serverconfig[$key] = $value;}
        }

        // Find the first usable uidKey.
        if (gettype($this->serverconfig['uidKey']) === "array" && !empty($this->serverconfig['uidKey'])) {
            foreach ($this->serverconfig['uidKey'] as $uidKey) {
                if (isset($state['Attributes'][$uidKey][0])) {
                    $this->serverconfig['uidKey'] = $uidKey;
                    break;
                }
            }
        }

        if (isset($state[$this->serverconfig['enabledPath']][$this->serverconfig['enabledKey']][0])) {
            $piEnabled = $state[$this->serverconfig['enabledPath']][$this->serverconfig['enabledKey']][0];
        } else {
            $piEnabled = True;
        }

        if ($this->serverconfig['serviceAccount'] === null or $this->serverconfig['servicePass'] === null) {
            $piEnabled = False;
            SimpleSAML_Logger::error("privacyIDEA service account for token enrollment is not set!");
        }

        if ($this->serverconfig['privacyideaserver'] === null) {
            $piEnabled = False;
            SimpleSAML_Logger::error("privacyIDEA url is not set!");
        }

        if ($piEnabled) {
            $this->auth_token = sspmod_privacyidea_Auth_utils::fetchAuthToken($this->serverconfig);
            if (!$this->userHasToken($state)) {
                $body = $this->enrollToken($state);
                if ($this->serverconfig['tokenType'] === "u2f") {
                    try {
                        $detail = $body->detail;
                        $serial = $detail->serial;
                        $state['privacyidea:tokenEnrollment']['enrollU2F'] = true;
                        $state['privacyidea:tokenEnrollment']['serial'] = $serial;
                        $state['privacyidea:tokenEnrollment']['authToken'] = $this->auth_token;
                    } catch (Exception $e) {
                        throw new SimpleSAML_Error_BadRequest("privacyIDEA: We were not able to read the response from the PI server");
                    }
                } else {
                    try {
                        $detail = $body->detail;
                        $googleurl = $detail->googleurl;
                        $img = $googleurl->img;
                        $state['privacyidea:tokenEnrollment']['tokenQR'] = $img;
                    } catch (Exception $e) {
                        throw new SimpleSAML_Error_BadRequest("privacyIDEA: We were not able to read the response from the PI server");
                    }
                }
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

        $params = array(
            "user" => $state["Attributes"][$this->serverconfig['uidKey']][0],
        );
        $headers = array(
            "authorization: " . $this->auth_token,
        );

        $body = sspmod_privacyidea_Auth_utils::curl($params, $headers, $this->serverconfig, "/token/", "GET");
        try {
            $result = $body->result;
            $value = $result->value;
            $count = $value->count;
        } catch (Exception $e) {
            throw new SimpleSAML_Error_BadRequest("privacyIDEA: We were not able to read the response from the PI server");
        }
        if ($count == 0) {
            return false;
        } else {
            return true;
        }
    }
}