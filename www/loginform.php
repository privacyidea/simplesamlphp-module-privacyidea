<?php

/**
 * This page shows a username/password login form, and passes information from it
 * to the sspmod_core_Auth_UserPassBase class, which is a generic class for
 * username/password authentication.
 *
 * This was modified from ./core/www/loginuserpass.php 

 * @author Olav Morken, UNINETT AS.
 * @package simpleSAMLphp
 */

if (!array_key_exists('AuthState', $_REQUEST)) {
	throw new SimpleSAML_Error_BadRequest('Missing AuthState parameter.');
}
$authStateId = $_REQUEST['AuthState'];

// sanitize the input
$sid = SimpleSAML_Utilities::parseStateID($authStateId);
if (!is_null($sid['url'])) {
	SimpleSAML_Utilities::checkURLAllowed($sid['url']);
}

/* Retrieve the authentication state. */
$state = SimpleSAML_Auth_State::loadState($authStateId, sspmod_core_Auth_UserPassBase::STAGEID);


$source = SimpleSAML_Auth_Source::getById($state[sspmod_core_Auth_UserPassBase::AUTHID]);
if ($source === NULL) {
	throw new Exception('Could not find authentication source with id ' . $state[sspmod_core_Auth_UserPassBase::AUTHID]);
}


if (array_key_exists('username', $_REQUEST)) {
	$username = $_REQUEST['username'];
} elseif ($source->getRememberUsernameEnabled() && array_key_exists($source->getAuthId() . '-username', $_COOKIE)) {
	$username = $_COOKIE[$source->getAuthId() . '-username'];
} elseif (isset($state['core:username'])) {
	$username = (string)$state['core:username'];
} else {
	$username = '';
}

if (array_key_exists('password', $_REQUEST)) {
	$password = $_REQUEST['password'];
} else {
	$password = '';
}

if (array_key_exists('transaction_id', $_REQUEST)) {
	$transaction_id = $_REQUEST['transaction_id'];
} else {
	$transaction_id = '';
}

$signatureData = '';
if (array_key_exists('signatureData', $_REQUEST)){
	$signatureData = $_REQUEST['signatureData'];
	SimpleSAML_Logger::debug("signaturedata: " . $signatureData);
}
$clientData = '';
if (array_key_exists('clientData', $_REQUEST)) {
	$clientData = $_REQUEST['clientData'];
	SimpleSAML_Logger::debug("clientdata: " . $clientData);
}

$errorCode = NULL;
$errorParams = NULL;
$message = '';
$attributes = NULL;

if (!empty($_REQUEST['username']) || !empty($password)) {
	/* Either username or password set - attempt to log in. */

	if (array_key_exists('forcedUsername', $state)) {
		$username = $state['forcedUsername'];
	}

	if ($source->getRememberUsernameEnabled()) {
		$sessionHandler = SimpleSAML_SessionHandler::getSessionHandler();
		$params = $sessionHandler->getCookieParams();
		$params['expire'] = time();
		$params['expire'] += (isset($_REQUEST['remember_username']) && $_REQUEST['remember_username'] == 'Yes' ? 31536000 : -300);
		SimpleSAML_Utilities::setCookie($source->getAuthId() . '-username', $username, $params, FALSE);
	}

    if ($source->isRememberMeEnabled()) {
        if (array_key_exists('remember_me', $_REQUEST) && $_REQUEST['remember_me'] === 'Yes') {
            $state['RememberMe'] = TRUE;
            $authStateId = SimpleSAML_Auth_State::saveState($state, sspmod_core_Auth_UserPassBase::STAGEID);
        }
    }

	try {
		// Here we catch the challenge response
		SimpleSAML_Logger::debug("Calling handleLogin for " . $username);
		SimpleSAML_Logger::debug("with transaction_id " . $transaction_id);
		SimpleSAML_Logger::debug("with signatureData " . $signatureData);
		SimpleSAML_Logger::debug("with clientData " . $clientData);
		sspmod_privacyidea_Auth_Source_privacyidea::handleLogin($authStateId, $username, $password,
								$transaction_id, $signatureData, $clientData);
	} catch (SimpleSAML_Error_Error $e) {
		/* Login failed. Extract error code and parameters, to display the error. */
		$errorCode = $e->getErrorCode();
		$errorParams = $e->getParameters();
		SimpleSAML_Logger::debug("Login failed. Catching errorCode: ". $errorCode);
		if ($errorCode === "CHALLENGERESPONSE" ) {
			/* In case of challenge response we do not change the username */
			$state['forcedUsername'] = $username;
			$transaction_id = $errorParams[1];
			$message = $errorParams[2];
			$attributes = $errorParams[3];
			SimpleSAML_Logger::debug("Challenge Response transaction_id: ". $errorParams[1]);
			SimpleSAML_Logger::debug("Challenge Response message: ". $errorParams[2]);
			SimpleSAML_Logger::debug("CHallenge Response attributes: ". print_r($attributes, TRUE));
		}
	}
}

$globalConfig = SimpleSAML_Configuration::getInstance();
$t = new SimpleSAML_XHTML_Template($globalConfig, 'privacyidea:loginform.php');
$t->data['stateparams'] = array('AuthState' => $authStateId);
if (array_key_exists('forcedUsername', $state)) {
	$t->data['username'] = $state['forcedUsername'];
	$t->data['transaction_id'] = $transaction_id;
	$t->data['chal_resp_message'] = $message;
	$t->data['chal_resp_attributes'] = $attributes;
	$t->data['forceUsername'] = TRUE;
	$t->data['rememberUsernameEnabled'] = FALSE;
	$t->data['rememberUsernameChecked'] = FALSE;
	$t->data['rememberMeEnabled'] = $source->isRememberMeEnabled();
	$t->data['rememberMeChecked'] = $source->isRememberMeChecked();
} else {
	$t->data['username'] = $username;
	$t->data['forceUsername'] = FALSE;
	$t->data['rememberUsernameEnabled'] = $source->getRememberUsernameEnabled();
	$t->data['rememberUsernameChecked'] = $source->getRememberUsernameChecked();
	$t->data['rememberMeEnabled'] = $source->isRememberMeEnabled();
	$t->data['rememberMeChecked'] = $source->isRememberMeChecked();
	if (isset($_COOKIE[$source->getAuthId() . '-username'])) $t->data['rememberUsernameChecked'] = TRUE;
}
$t->data['links'] = $source->getLoginLinks();
$t->data['errorcode'] = $errorCode;
$t->data['errorparams'] = $errorParams;

if (isset($state['SPMetadata'])) {
	$t->data['SPMetadata'] = $state['SPMetadata'];
} else {
	$t->data['SPMetadata'] = NULL;
}

$t->show();
exit();

