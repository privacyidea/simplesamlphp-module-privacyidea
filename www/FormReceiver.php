<?php
$stateId = SimpleSAML_Session::getSessionFromRequest()->getData("privacyidea:privacyidea", "stateId");
SimpleSAML_Session::getSessionFromRequest()->deleteData("privacyidea:privacyidea", "stateId");
if (empty($stateId))
{
    SimpleSAML_Logger::error("stateId empty in FormReceiver.");
    throw new \Exception("State information lost!");
}
$state = SimpleSAML_Auth_State::loadState($stateId, 'privacyidea:privacyidea');

// Find the username
if (isset($state['privacyidea:privacyidea']['uidKey']))
{
    $uidKey = $state['privacyidea:privacyidea']['uidKey'];
    $username = $state['Attributes'][$uidKey][0];
}
elseif (isset($state['privacyidea:privacyidea']['username']))
{
    $username = $state['privacyidea:privacyidea']['username'];
}
elseif (array_key_exists('username', $_REQUEST))
{
    $username = (string)$_REQUEST['username'];
}
elseif (isset($state['core:username']))
{
    $username = (string)$state['core:username'];
}
else
{
    $username = '';
}

$formParams = array(
    "username" => $username,
    "pass" => array_key_exists('password', $_REQUEST) ? $_REQUEST['password'] : "",
    "otp" => array_key_exists('otp', $_REQUEST) ? $_REQUEST['otp'] : "",
    "mode" => array_key_exists('mode', $_REQUEST) ? $_REQUEST['mode'] : "otp",
    "pushAvailable" => array_key_exists('pushAvailable', $_REQUEST) ? $_REQUEST['pushAvailable'] : "false",
    "otpAvailable" => array_key_exists('otpAvailable', $_REQUEST) ? $_REQUEST['otpAvailable'] : "true",
    "modeChanged" => array_key_exists('modeChanged', $_REQUEST) ? $_REQUEST['modeChanged'] : "false",
    "webAuthnSignResponse" => array_key_exists('webAuthnSignResponse', $_REQUEST) ? $_REQUEST['webAuthnSignResponse'] : "",
    "webAuthnSignRequest" => array_key_exists('webAuthnSignRequest', $_REQUEST) ? $_REQUEST['webAuthnSignRequest'] : "",
    "origin" => array_key_exists('origin', $_REQUEST) ? $_REQUEST['origin'] : "",
    "u2fSignRequest" => array_key_exists('u2fSignRequest', $_REQUEST) ? $_REQUEST['u2fSignRequest'] : "",
    "u2fSignResponse" => array_key_exists('u2fSignResponse', $_REQUEST) ? $_REQUEST['u2fSignResponse'] : "",
    "message" => array_key_exists('message', $_REQUEST) ? $_REQUEST['message'] : "",
    "loadCounter" => array_key_exists('loadCounter', $_REQUEST) ? $_REQUEST['loadCounter'] : 1
);

if ($state['privacyidea:privacyidea']['authenticationMethod'] === "authprocess")
{
    // Auth Proc
    try
    {
        $response = sspmod_privacyidea_Auth_Utils::authenticatePI($state, $formParams);
        $stateId = SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea');

        // If the authentication is successful processPIResponse will not return!
        if (!empty($response))
        {
            $stateId = sspmod_privacyidea_Auth_Utils::processPIResponse($stateId, $response);
        }
        $url = SimpleSAML_Module::getModuleURL('privacyidea/FormBuilder.php');
        SimpleSAML_Utilities::redirectTrustedURL($url, array('stateId' => $stateId));
    }
    catch (Exception $e)
    {
        SimpleSAML_Logger::error($e->getMessage());
    }
}
else
{
    // Auth Source
    $source = SimpleSAML_Auth_Source::getById($state["privacyidea:privacyidea"]["AuthId"]);
    if ($source->getRememberUsernameEnabled())
    {
        $sessionHandler = SimpleSAML_SessionHandler::getSessionHandler();
        $params = $sessionHandler->getCookieParams();

        $params['expire'] = time();
        $params['expire'] += (isset($_REQUEST['rememberUsername']) && $_REQUEST['rememberUsername'] === 'Yes' ? 31536000 : -300);
        SimpleSAML_Utilities::setCookie($source->getAuthId() . '-username', $username, $params, FALSE);
    }

    if ($source->isRememberMeEnabled())
    {
        if (array_key_exists('rememberMe', $_REQUEST) && $_REQUEST['rememberMe'] === 'Yes')
        {
            $state['RememberMe'] = TRUE;
            $stateId = SimpleSAML_Auth_State::saveState($state, sspmod_core_Auth_UserPassBase::STAGEID);
        }
    }

    try
    {
        sspmod_privacyidea_Auth_Source_PrivacyideaAuthSource::authSourceLogin($stateId, $formParams);
    }
    catch (Exception $e)
    {
        SimpleSAML_Logger::error($e->getMessage());
        $state = SimpleSAML_Auth_State::loadState($stateId, 'privacyidea:privacyidea');
        $state['privacyidea:privacyidea']['errorCode'] = $e->getCode();
        $state['privacyidea:privacyidea']['errorMessage'] = $e->getMessage();
        $stateId = SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea');
    }
}
