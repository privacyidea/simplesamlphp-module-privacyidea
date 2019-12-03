<?php

const USERAGENT =  "simpleSAMLphp";

/**
 * The functions, which are needed in more than one class, are listed below.
 * @author Micha Preußer <micha.preusser@netknights.it>
 * @author Jean-Pierre Höhmann <jean-pierre.hoehmann@netknights.it>
 */
class sspmod_privacyidea_Auth_utils
{

    /**
     * Perform a request against privacyIDEA.
     *
     * @param array $params All params, which are needed for the http request (e.g. user, pass, realm, etc.)
     * @param array $headers The headers for the http request (e.g. authentication token)
     * @param array $serverconfig The whole configuation for the server (e.g. url, verify host, verify peer)
     * @param string $api_endpoint This is the path for the request (e.g. /validate/samlcheck)
     * @param string $http_method Some requests need POST or GET method. This can be entered here.
     * @return object We will return the JSON decoded body, because all the requests need different data.
     * @throws SimpleSAML_Error_BadRequest
     */
    public static function curl($params, $headers, $serverconfig, $api_endpoint, $http_method)
    {
        assert('array' === gettype($params));
        assert('array' === gettype($headers));
        assert('array' === gettype($serverconfig));
        assert('string' === gettype($api_endpoint));
        assert('string' === gettype($http_method));

        $curl_instance = curl_init();
        $url = $serverconfig['privacyideaserver'] . $api_endpoint;

        curl_setopt($curl_instance, CURLOPT_URL, $url);
        curl_setopt($curl_instance, CURLOPT_HEADER, true);
        if ($headers) {curl_setopt($curl_instance, CURLOPT_HTTPHEADER, $headers);}
        curl_setopt($curl_instance, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl_instance, CURLOPT_USERAGENT, USERAGENT);
        if ($http_method === "POST") {
            curl_setopt($curl_instance, CURLOPT_POST, true);
            curl_setopt($curl_instance, CURLOPT_POSTFIELDS, $params);
        } elseif ($http_method === "GET") {
            $params_str = '?';
            foreach ($params as $key => $value) {
                $params_str .= $key . "=" . $value . "&";
            }
            curl_setopt($curl_instance, CURLOPT_URL, $url . $params_str);
        }
        if (!$serverconfig['sslverifyhost']) {
            curl_setopt($curl_instance, CURLOPT_SSL_VERIFYHOST, 0);
        }
        curl_setopt($curl_instance, CURLOPT_SSL_VERIFYPEER, $serverconfig['sslverifypeer']);

        SimpleSAML_Logger::debug("privacyIDEA: " . $http_method . " " . $url);
        $response = curl_exec($curl_instance);
        if (!$response) {
            throw new SimpleSAML_Error_BadRequest(
                "privacyIDEA: Bad request to PI server: " . curl_error($curl_instance)
            );
        }
        $header_size = curl_getinfo($curl_instance, CURLINFO_HEADER_SIZE);
        $body = json_decode(substr($response, $header_size));
        return $body;
    }

    /**
     * Null check.
     *
     * This function will null-check a value and throw a BadRequest error with a generic response if necessary.
     *
     * @param mixed $x Variable to perform the null-check on.
     * @return mixed The input.
     * @throws SimpleSAML_Error_BadRequest
     */
    public static function nullCheck($x) {
        if (gettype($x) === "NULL") {
            throw new SimpleSAML_Error_BadRequest(
                "privacyIDEA: We were not able to read the response from the PI server");
        }
        return $x;
    }

    /**
     * With this function you can get the authorization token with a service account.
     *
     * The keys serviceAccount and servicePass must be set in the $serverconfig. It can be done in the config or in the
     * metadata. The service account must have the correct rights. You can edit them in the policies in privacyIDEA
     *
     * @param array $serverconfig The whole configuation for the server.
     * @return String This is the authorization header, which is needed for some API requests.
     */
    public static function fetchAuthToken($serverconfig)
    {
        assert('array' === gettype($serverconfig));

        return self::nullCheck(
            @self::curl(
                array(
                    "username" => $serverconfig['serviceAccount'],
                    "password" => $serverconfig['servicePass'],
                ),
                null,
                $serverconfig,
                "/auth",
                "POST"
            )->result->value->token
        );
    }

    /**
     * This function can edit the state to enter the needed token types for a user.
     *
     * The booleans 'use_u2f', 'use_otp' and 'use_push' will be added.
     *
     * @param array $state The state is needed to be changed in this function
     * @param object $body The body contains the multi_challenge which will be used to check which token types are used.
     * @return mixed The modified state will be returned. It now contains the token types for the user.
     */
    public static function checkTokenType($state, $body)
    {
        assert('array' === gettype($state));
        assert('object' === gettype($body));

        $detail = $body->detail;
        $multi_challenge = $detail->multi_challenge;
        $use_u2f = false;
        $use_otp = false;
        $use_push = false;
        for ($i = 0; $i < count($multi_challenge); $i++) {
            switch ($multi_challenge[$i]->type) {
                case "u2f":
                    $use_u2f = true;
                    break;
                case "push":
                    $use_push = true;
                    break;
                default:
                    $use_otp = true;
            }
        }
        $state['privacyidea:privacyidea:checkTokenType'] = array(
            "transaction_id" => $detail->transaction_id,
            "multi_challenge" => $multi_challenge,
        );
        if ($use_u2f) {SimpleSAML_Logger::debug("privacyIDEA: The user has u2f token");}
        if ($use_push) {SimpleSAML_Logger::debug("privacyIDEA: The user has push token");}
        if ($use_otp) {SimpleSAML_Logger::debug("privacyIDEA: The user has otp token");}
        $state['privacyidea:privacyidea:checkTokenType']['use_u2f'] = $use_u2f;
        $state['privacyidea:privacyidea:checkTokenType']['use_push'] = $use_push;
        $state['privacyidea:privacyidea:checkTokenType']['use_otp'] = $use_otp;
        return $state;
    }

    /**
     * Determine the clients IP-Address.
     *
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
     *
     * If the administrator has configured multiple uidKeys, this will find the first one the exists as an Attribute in
     * the $state and update the $config to use that key.
     *
     * @param array $config The serverconfig to use
     * @param array $state The global state to check the keys against
     * @return array The updated config
     */
    public static function determineUidKey($config, $state) {
        assert('array' === gettype($config));
        assert('array' === gettype($state));

        if (self::isNonEmptyArray($config['uidKey'])) {
            foreach ($config['uidKey'] as $i) {
                if (isset($state['Attributes'][$i][0])) {$config['uidKey'] = $i;}
            }
        }
        return $config;
    }

    /**
     * Build the serverconfig.
     *
     * This will take a serverconfig, merge in overrides and determine the uidKey if necessary.
     *
     * @param array $config The serverconfig
     * @param array $overrides THe config overrides
     * @param array $state The global state of simpleSAMLphp
     * @return array The new serverconfig.
     */
    public static function buildServerconfig($config, $overrides, $state) {
        assert('array' === gettype($config));
        assert('array' === gettype($overrides));
        assert('array' === gettype($state));

        return self::determineUidKey(array_merge($config, $overrides), $state);
    }

    /**
     * Perform 2FA authentication given the current state and an OTP from a token managed by privacyIDEA
     * The otp is sent to the privacyidea_url.
     *
     * @param array $state The state array in the "privacyidea:privacyidea:init" stage.
     * @param array $params An array containing: user, realm, pass, transaction_id, signaturedata, clientdata, regdata
     * @param array $serverconfig The configuration for the PrivacyIDEA-server. Optional, if contained in $state.
     * @return array|null An array containing attributes and detail, or NULL.
     * @throws \InvalidArgumentException if the state array is not in a valid stage or the OTP has incorrect length.
     */
    public static function authenticate($state, $params, $serverconfig = NULL)
    {
        assert('array' === gettype($state));
        assert('array' === gettype($params));
        assert('array' === gettype($serverconfig) || NULL === $serverconfig);
        $serverconfig = $serverconfig ?: $state['privacyidea:privacyidea'];

        $params['user'] = @$params['user'] ?: $state["Attributes"][$serverconfig['uidKey']][0];
        $params['realm'] = @$params['realm'] ?: $serverconfig['realm'];
        $params['client'] = self::getClientIP();

        if (self::shouldEnrollToken($state, @$params['transaction_id'])) {
            return self::enrollToken($state, $serverconfig, $params);
        }
        $body = sspmod_privacyidea_Auth_utils::curl($params, null, $serverconfig, "/validate/samlcheck", "POST");
        $auth = sspmod_privacyidea_Auth_utils::nullCheck(@$body->result->value->auth);
        $status = @$body->result->status;
        $detail = @$body->detail;
        $multi_challenge = @$detail->multi_challenge;

        // Fallback for legacy compatibility.
        $attributes = @$body->result->value->attributes ?: @$body->result->value;

        if (!$status) {
            throw new SimpleSAML_Error_BadRequest("privacyIDEA: Valid JSON response, but some internal error occured in PI server");
        }
        if ($auth) {
            SimpleSAML_Logger::debug("privacyIDEA: User authenticated successfully");
        } else {
            if ($multi_challenge) {
                $state = sspmod_privacyidea_Auth_utils::checkTokenType($state, $body);
                $serverconfig['username'] = $params['user'];

                SimpleSAML_Logger::debug("privacyIDEA: privacyIDEA is enabled, so we use 2FA");
                $id = SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea:init');
                SimpleSAML_Logger::debug("Saved state privacyidea:privacyidea:init from Process/privacyidea.php");
                $url = SimpleSAML_Module::getModuleURL('privacyidea/otpform.php');
                SimpleSAML_Utilities::redirectTrustedURL($url, array('StateId' => $id));
            } else {
                SimpleSAML_Logger::error("privacyIDEA WRONG USER PASSWORD");
                return NULL;
            }
        }

        return array(
            "detail" => $detail,
            "attributes" => $attributes
        );
    }

    /**
     * Check if the given parameter is a non empty array.
     *
     * @param mixed $x The parameter to check.
     * @return boolean Whether the parameter is a non-empty array.
     */
    public static function isNonEmptyArray($x) {
        return gettype($x) === "array" && !empty($x);
    }

    /**
     * Check if a token should be enrolled.
     *
     * @param array $state The global state of simpleSAMLphp.
     * @param string $transaction_id The id of the current transaction.
     * @return boolean Whether a token should be enrolled.
     */
    public static function shouldEnrollToken($state, $transaction_id) {
        assert('array' === gettype($state));
        assert('string' === gettype($transaction_id));

        return @$state['privacyidea:tokenEnrollment']['enrollU2F'] && $transaction_id;
    }

    /**
     * Enroll a u2f token.
     *
     * @param array $state The global state of simpleSAMLphp.
     * @param array $config The configuration for the PrivacyIDEA-server.
     * @param array $params Array with: client, user, realm, pass, transaction_id, signaturedata, clientdata, regdata
     */
    public static function enrollToken($state, $config, $params) {
        assert('array' === gettype($state));
        assert('array' === gettype($config));
        assert('array' === gettype($params));

        $params['type'] = "u2f";
        $params['description'] = "Enrolled with simpleSAMLphp";
        $params['serial'] = $state['privacyidea:tokenEnrollment']['serial'];
        $authToken = $state['privacyidea:tokenEnrollment']['authToken'];
        $headers = array("authorization: " . $authToken);
        sspmod_privacyidea_Auth_utils::curl($params, $headers, $config, "/token/init", "POST");
    }

    /**
     * Check if PrivacyIDEA was disabled by a filter.
     *
     * @param array $state The global state of simpleSAMLphp.
     * @param array $config The config for the PrivacyIDEA server.
     * @return boolean Whether PrivacyIDEA is disabled.
     */
    public static function privacyIdeaIsDisabled($state, $config) {
        return isset($state[$config['enabledPath']][$config['enabledKey']][0])
            && !$state[$config['enabledPath']][$config['enabledKey']][0];
    }
}
