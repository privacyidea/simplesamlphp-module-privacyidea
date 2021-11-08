<?php
require_once(dirname(__FILE__, 2) . '/lib/sdk-php/src/SDK-Autoloader.php');

SimpleSAML_Logger::info("Calling formbuilder...");

// Load $state from the earlier position
$stateID = $_REQUEST['StateId'];
$state = SimpleSAML_Auth_State::loadState($stateID, 'privacyidea:privacyidea');

// Find the username and set it to the variable
if (isset($state['privacyidea:privacyidea']['uidKey']))
{
    $uidKey = $state['privacyidea:privacyidea']['uidKey'];
    $username = $state['Attributes'][$uidKey][0];
} elseif (isset($state['privacyidea:privacyidea']['username']))
{
    $username = $state['privacyidea:privacyidea']['username'];
} elseif (array_key_exists('username', $_REQUEST))
{
    $username = (string)$_REQUEST['username'];
} elseif (isset($state['core:username']))
{
    $username = (string)$state['core:username'];
} else
{
    $username = '';
}

// Find and set the inputs to the variables
if (!empty($_REQUEST['password']) || !empty($_REQUEST['username'])
    || !empty($_REQUEST['otp']) || !empty($_REQUEST['modeChanged'])
    || (!empty($_REQUEST['mode']) && $_REQUEST['mode'] == "push")
    || (!empty($_REQUEST['mode']) && $_REQUEST['mode'] == "u2f")
    || (!empty($_REQUEST['mode']) && $_REQUEST['mode'] == "webauthn"))
{

    // Collect the inputs from the form in an array
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
        //    "loadCounter" => $_REQUEST['loadCounter'] ?: 1
        "loadCounter" => $_REQUEST['loadCounter']
    );
//    array_push($formParams, "loadCounter");
//    if(!empty($_REQUEST['loadCounter'])){
//        $formParams['loadCounter'] = $_REQUEST['loadCounter'];
//    } else {
//        $formParams['loadCounter'] = 1;
//    }

    if ($state['privacyidea:privacyidea']['authenticationMethod'] === "authprocess")
    {
        try
        {
            $response = sspmod_privacyidea_Auth_utils::authenticatePI($state, $formParams, $state['privacyidea:serverconfig']);
            $stateID = SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea');

            // If the authentication is successful processPIResponse will not return!
            if (!empty($response))
            {
                $stateID = sspmod_privacyidea_Auth_utils::processPIResponse($stateID, $response);
            }
            $url = SimpleSAML_Module::getModuleURL('privacyidea/formbuilder.php');
            SimpleSAML_Utilities::redirectTrustedURL($url, array('StateId' => $stateID));
        } catch (Exception $e)
        {
            SimpleSAML_Logger::error($e->getMessage());
        }
    } else
    {
        try
        {
            sspmod_privacyidea_Auth_Source_AuthSourceLoginHandler::authSourceLogin($stateID, $formParams);
        } catch (Exception $e)
        {
            SimpleSAML_Logger::error($e->getMessage());
            $state = SimpleSAML_Auth_State::loadState($stateID, 'privacyidea:privacyidea');
            $state['privacyidea:privacyidea']['errorCode'] = $e->getCode();
            $state['privacyidea:privacyidea']['errorMessage'] = $e->getMessage();
            $stateID = SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea');

        }
    }
}

// Config needs a new login form
$cfg = SimpleSAML_Configuration::getInstance();

// Open new login form using the right State ID
$tpl = new SimpleSAML_XHTML_Template($cfg, 'privacyidea:loginform.php');

// Prepare error to show in UI
$tpl->data['errorCode'] = null;
$tpl->data['errorMessage'] = null;

if (!empty($state['privacyidea:privacyidea']['errorCode']) || !empty($state['privacyidea:privacyidea']['errorMessage']))
{
    if (!empty($state['privacyidea:privacyidea']['errorCode']))
    {
        $tpl->data['errorCode'] = $state['privacyidea:privacyidea']['errorCode'];
        $state['privacyidea:privacyidea']['errorCode'] = "";
    } else
    {
        $tpl->data['errorCode'] = "";
    }
    $tpl->data['errorMessage'] = $state['privacyidea:privacyidea']['errorMessage'];
    $state['privacyidea:privacyidea']['errorMessage'] = "";
    $stateID = SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea');
}

// Authprocess step 1
if ($state['privacyidea:privacyidea']['authenticationMethod'] === "authprocess")
{

    $tpl->data['authProcFilterScenario'] = true;
    $tpl->data['rememberUsernameEnabled'] = true;
    $tpl->data['rememberUsernameChecked'] = true;
    $tpl->data['forceUsername'] = true;

    // Enroll token's QR
    if (isset($state['privacyidea:tokenEnrollment']['tokenQR']))
    {
        $tpl->data['tokenQR'] = $state['privacyidea:tokenEnrollment']['tokenQR'];
    } else
    {
        $tpl->data['tokenQR'] = null;
    }

// Authsource step 1
} elseif ($state['privacyidea:privacyidea']['authenticationMethod'] === "authsource")
{
    $authConfig = SimpleSAML_Configuration::getOptionalConfig("authsources.php");

    $privacyideaConfig = array();
    $keys = $authConfig->getOptions();

    foreach ($keys as $key)
    {
        $config = $authConfig->getValue($key);
        if ($config[0] == "privacyidea:privacyidea")
        {
            $privacyideaConfig = $config;
        }
    }

    $pi = new sspmod_privacyidea_Auth_Source_PrivacyideaAuthSource(array(), $privacyideaConfig);

    $source = SimpleSAML_Auth_Source::getById($state["privacyidea:privacyidea"]["AuthId"]);

    if ($source == NULL)
    {
        SimpleSAML_Logger::error('Could not find authentication source with ID ' . $state[sspmod_core_Auth_UserPassBase::AUTHID]);
    }

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
            $stateID = SimpleSAML_Auth_State::saveState($state, sspmod_core_Auth_UserPassBase::STAGEID);
        }
    }

    $tpl->data['username'] = $username;
    $tpl->data['rememberMeEnabled'] = $source->isRememberMeEnabled();
    $tpl->data['rememberMeChecked'] = $source->isRememberMeChecked();
    $tpl->data['links'] = $source->getLoginLinks();

    if (array_key_exists('forcedUsername', $state))
    {
        $tpl->data['forceUsername'] = true;
        $tpl->data['rememberUsernameEnabled'] = false;
        $tpl->data['rememberUsernameChecked'] = false;
    } else
    {
        $tpl->data['forceUsername'] = false;
        $tpl->data['rememberUsernameEnabled'] = $source->getRememberUsernameEnabled();
        $tpl->data['rememberUsernameChecked'] = $source->getRememberUsernameChecked();
    }

    if (!empty($state['SPMetadata']))
    {
        $tpl->data['SPMetadata'] = $state['SPMetadata'];
    } else
    {
        $tpl->data['SPMetadata'] = NULL;
    }
}

if (empty($_REQUEST['loadCounter']))
{
    $tpl->data['loadCounter'] = 1;
}

// Get all the ui data placed in state and set it to $tpl->data for future use in loginform.php
if (!empty($state['privacyidea:privacyidea:ui']))
{
    foreach ($state['privacyidea:privacyidea:ui'] as $key => $value)
    {
        $tpl->data[$key] = $value;
    }
}

if ($state['privacyidea:privacyidea']['authenticationMethod'] === "authprocess")
{
    $tpl->data['LogoutURL'] = SimpleSAML_Module::getModuleURL('core/authenticate.php', array('as' => $state['Source']['auth'])) . "&logout";
}

$tpl->show();