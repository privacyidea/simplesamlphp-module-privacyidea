<?php

require_once((dirname(__FILE__, 3)) . '/php-client/src/Client-Autoloader.php');

/**
 * This is the helper class for PrivacyideaAuthSource.php
 */
class sspmod_privacyidea_Auth_Source_AuthSourceLoginHandler
{
    /**
     * This function process the login for auth source.
     *
     * @param string $stateID
     * @param array $formParams
     * @throws Exception
     */
    public static function authSourceLogin($stateID, $formParams)
    {
        assert('array' === gettype($stateID));
        assert('array' === gettype($formParams));

        SimpleSAML_Logger::debug("auth source login..."
                                 . "\nFormParams:\n"
                                 . print_r($formParams, true));

        $state = SimpleSAML_Auth_State::loadState($stateID, 'privacyidea:privacyidea');

        $source = SimpleSAML_Auth_Source::getById($state['privacyidea:privacyidea']["AuthId"]);
        if (!$source)
        {
            throw new Exception('Could not find authentication source with ID ' . $state["AuthId"]);
        }

        // SSO
        if (array_key_exists('SSO', $source->authSourceConfig)
            && $source->authSourceConfig['SSO'] === 'true')
        {
            sspmod_privacyidea_Auth_utils::writeSSODataToSession($state);
//            SimpleSAML_Logger::debug("state: " . print_r($state, true));

            sspmod_privacyidea_Auth_utils::checkSSO($state);
        }

        // If it is the first step, trigger challenges or send the password if configured
        $username = $formParams['username'];
        $password = "";
        if (!empty($formParams['pass']))
        {
            $password = $formParams['pass'];
        }

        $step = $state['privacyidea:privacyidea:ui']['step'];
        //SimpleSAML_Logger::debug("STEP: " . $step);
        $response = null;
        if ($step == 1)
        {
            $state['privacyidea:privacyidea']['username'] = $username;
            $stateID = SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea');

            if (array_key_exists("doTriggerChallenge", $source->authSourceConfig)
                && $source->authSourceConfig["doTriggerChallenge"] === 'true')
            {
                if (!empty($username) && $source->pi->serviceAccountAvailable() === true)
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
            $response = sspmod_privacyidea_Auth_utils::authenticatePI($state, $formParams, $source->authSourceConfig);
            $stateID = SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea');
        }
        else
        {
            SimpleSAML_Logger::error("UNDEFINED STEP: " . $step);
        }

        if ($response != null)
        {
            self::checkAuthenticationComplete($state, $response, $source->authSourceConfig);
            $stateID = sspmod_privacyidea_Auth_utils::processPIResponse($stateID, $response);
        }

        $state = SimpleSAML_Auth_State::loadState($stateID, 'privacyidea:privacyidea');

        // Increase steps counter
        if (empty($state['privacyidea:privacyidea']['errorMessage']))
        {
            $state['privacyidea:privacyidea:ui']['step'] = $step + 1;
        }

        //SimpleSAML_Logger::error("NEW STEP: " . $state['privacyidea:privacyidea:ui']['step']);
        $stateID = SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea');
        $url = SimpleSAML_Module::getModuleURL('privacyidea/formbuilder.php');
        SimpleSAML_Utilities::redirectTrustedURL($url, array('StateId' => $stateID));
    }

    /**
     * @param array $state
     * @param PIResponse $piResponse
     * @param $authSourceConfig
     */
    protected static function checkAuthenticationComplete($state, PIResponse $piResponse, $authSourceConfig)
    {
        $attributes = $piResponse->detailAndAttributes;

        if (!empty($attributes))
        {
            $userAttributes = $attributes['attributes'];
            $detailAttributes = $attributes['detail'];

            $completeAttributes = self::mergeAttributes($userAttributes, $detailAttributes, $authSourceConfig);
            $state['Attributes'] = $completeAttributes;

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

        // attributemap was set in config/authsources.php
        $keys = array_merge(array_keys($authSourceConfig['attributemap']), DEFAULT_UID_KEYS);
        $keys = array_unique($keys);

        // Keep all reservations from attributemap to translate PI attributes names to SAML attributes names.
        foreach ($keys as $key)
        {

            SimpleSAML_Logger::debug("privacyidea        key: " . $key);
            $attributeValue = $userAttributes[$key];

            if ($attributeValue)
            {

                $attributeKey = @$authSourceConfig['attributemap'][$key] ?: $key;
                $attributes[$attributeKey] = is_array($attributeValue) ? $attributeValue : array($attributeValue);

                SimpleSAML_Logger::debug("privacyidea key: " . $attributeKey);
                SimpleSAML_Logger::debug("privacyidea value: " . print_r($attributeValue, TRUE));
            }
        }

        // Keep all reservations from detailmap to know which attributes are set to show in UI.
        // Detailmap was set in config/authsources.php
        foreach ($authSourceConfig['detailmap'] as $key => $mappedKey)
        {

            SimpleSAML_Logger::debug("privacyidea        key: " . print_r($key, TRUE));
            SimpleSAML_Logger::debug("privacyidea mapped key: " . print_r($mappedKey, TRUE));

            $attributeValue = $detailAttributes->$key;
            $attributes[$mappedKey] = is_array($attributeValue) ? $attributeValue : array($attributeValue);
        }

        // Keep all reservations from concatenationmap to fuse some attributes together.
        // Concatenationmap was set in config/authsources.php
        foreach ($authSourceConfig['concatenationmap'] as $key => $mappedKey)
        {

            SimpleSAML_Logger::debug("privacyidea        key: " . print_r($key, TRUE));
            SimpleSAML_Logger::debug("privacyidea mapped key: " . print_r($mappedKey, TRUE));

            $concatenationArr = explode(",", $key);
            $concatenationValues = array();

            foreach ($concatenationArr as $item)
            {
                $concatenationValues[] = $userAttributes->$item;
            }

            $concatenationString = implode(" ", $concatenationValues);
            $attributes[$mappedKey] = array($concatenationString);
        }

        SimpleSAML_Logger::debug("privacyidea Array returned: " . print_r($attributes, True));
        return $attributes;
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

