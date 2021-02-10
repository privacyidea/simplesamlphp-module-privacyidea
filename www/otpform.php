<?php
	try{
		$authStateId = $_REQUEST['StateId'];
		$state = SimpleSAML_Auth_State::loadState($authStateId, 'privacyidea:privacyidea:init');
	} catch (Exception $e){
	}

	$errorCode = null;
	$errorParams = null;

	if (isset($state['privacyidea:privacyidea']['uidKey'])) {
		$uidKey = $state['privacyidea:privacyidea']['uidKey'];
		$username = $state['Attributes'][$uidKey][0];
	} elseif (isset($state['privacyidea:privacyidea']['username'])){
		$username = $state['privacyidea:privacyidea']['username'];
	} elseif (array_key_exists('username', $_REQUEST)) {
		$username = (string)$_REQUEST['username'];
	} elseif (isset($state['core:username'])) {
		$username = (string)$state['core:username'];
	} else {
		$username = '';
	}

	if(isset($_REQUEST['password']) || isset($_REQUEST['username'])) {
		if (array_key_exists('transaction_id', $_REQUEST)) {
            $transaction_id = (string)$_REQUEST['transaction_id'];
		} else {
            $transaction_id = '';
		}
		$signatureData = '';
		if (array_key_exists('signatureData', $_REQUEST)){
            $signatureData = (string)$_REQUEST['signatureData'];
            SimpleSAML_Logger::debug("signaturedata: " . $signatureData);
		}
		$clientData = '';
		if (array_key_exists('clientData', $_REQUEST)) {
            $clientData = (string)$_REQUEST['clientData'];
            SimpleSAML_Logger::debug("clientdata: " . $clientData);
		}
		$registrationData = '';
		if (array_key_exists('registrationData', $_REQUEST)) {
			$registrationData = (string)$_REQUEST['registrationData'];
			SimpleSAML_Logger::debug("registrationdata: " . $registrationData);
		}
		if (isset($_REQUEST['password'])) {
			$password = $_REQUEST['password'];
		} else {
			$password = NULL;
		}

	    try {
			if($state['privacyidea:privacyidea:authenticationMethod'] === "authprocess") {
				if (sspmod_privacyidea_Auth_Process_privacyidea::authenticate($state, $password, $transaction_id, $signatureData, $clientData, $registrationData)) {
					SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea:init');
					SimpleSAML_Auth_ProcessingChain::resumeProcessing($state);
				} else {
					SimpleSAML_Logger::debug("privacyIDEA: User entered wrong OTP");
				}
			} elseif ($state['privacyidea:privacyidea:authenticationMethod'] === "authsource") {
				sspmod_privacyidea_Auth_Source_privacyidea::handleLogin($authStateId, $username, $password, $transaction_id, $signatureData, $clientData);
			}
        } catch (SimpleSAML_Error_Error $e) {
            /* Login failed. Extract error code and parameters, to display the error. */
            $errorCode = $e->getErrorCode();
            $errorParams = $e->getParameters();
            SimpleSAML_Logger::debug("Login failed. Catching errorCode: ". $errorCode);
		}
	}
	$doChallengeResponse = false;
	if (isset($state['privacyidea:privacyidea:checkTokenType'])) {
		$triggerChallenge = $state['privacyidea:privacyidea:checkTokenType'];
		if ($triggerChallenge['use_u2f']) {
			$doChallengeResponse = true;
		}
		if ($triggerChallenge['use_otp']) {
			$use_otp = true;
		}
		$transaction_id = $triggerChallenge['transaction_id'];
		$message = '';
		$multi_challenge = $triggerChallenge['multi_challenge'];
		SimpleSAML_Logger::debug("Challenge Response transaction_id: ". $transaction_id);
		SimpleSAML_Logger::debug("Challenge Response multi_challenge: " . print_r($multi_challenge, TRUE));
		for ($i = 0; $i < count($multi_challenge); $i++) {
			SimpleSAML_Logger::debug("Token serial " . $i . ": " . print_r($multi_challenge[$i]->serial, TRUE));
			$message = $message . ' ' . $multi_challenge[$i]->serial;
		}
	}

	$cfg = SimpleSAML_Configuration::getInstance();
	$tpl = new SimpleSAML_XHTML_Template($cfg, 'privacyidea:loginform.php');
	$tpl->data['stateparams'] = array('StateId' => $authStateId);

	if ($state['privacyidea:privacyidea:authenticationMethod'] === "authprocess") {
		$tpl->data['auth_proc_filter_scenario'] = true;
		$tpl->data['rememberUsernameEnabled'] = true;
		$tpl->data['rememberUsernameChecked'] = true;
		$tpl->data['forceUsername'] = true;
		if (isset($state['privacyidea:tokenEnrollment']['enrollU2F'])) {
			$tpl->data['serial'] = $state['privacyidea:tokenEnrollment']['serial'];
			$tpl->data['enrollU2F'] = true;
		}
		if (isset($state['privacyidea:tokenEnrollment']['tokenQR'])) {
			$tpl->data['tokenQR'] = $state['privacyidea:tokenEnrollment']['tokenQR'];
		} else {
			$tpl->data['tokenQR'] = null;
		}
	} elseif ($state['privacyidea:privacyidea:authenticationMethod'] === "authsource") {

		$authConfig = SimpleSAML_Configuration::getOptionalConfig("authsources.php");
		$privacyideaConfig = Array();
		$keys = $authConfig->getOptions();
		foreach ($keys as $key) {
			$config = $authConfig->getValue($key);
			if ($config[0] == "privacyidea:privacyidea") {
				$privacyideaConfig = $config;
			}
		}
		$pi = new sspmod_privacyidea_Auth_Source_privacyidea(Array(), $privacyideaConfig);
		$tpl->data['otp_extra'] = $pi->getOtpExtra();

		$source = SimpleSAML_Auth_Source::getById($state[sspmod_core_Auth_UserPassBase::AUTHID]);
		if ($source === NULL) {
			throw new Exception('Could not find authentication source with id ' . $state[sspmod_core_Auth_UserPassBase::AUTHID]);
		}
		if ($source->getRememberUsernameEnabled()) {
			$sessionHandler = SimpleSAML_SessionHandler::getSessionHandler();
			$params = $sessionHandler->getCookieParams();
			$params['expire'] = time();
			$params['expire'] += (isset($_REQUEST['remember_username']) && $_REQUEST['remember_username'] === 'Yes' ? 31536000 : -300);
			SimpleSAML_Utilities::setCookie($source->getAuthId() . '-username', $username, $params, FALSE);
		}

		if ($source->isRememberMeEnabled()) {
			if (array_key_exists('remember_me', $_REQUEST) && $_REQUEST['remember_me'] === 'Yes') {
				$state['RememberMe'] = TRUE;
				$authStateId = SimpleSAML_Auth_State::saveState($state, sspmod_core_Auth_UserPassBase::STAGEID);
			}
		}
		$tpl->data['username'] = $username;
		$tpl->data['rememberMeEnabled'] = $source->isRememberMeEnabled();
		$tpl->data['rememberMeChecked'] = $source->isRememberMeChecked();
		$tpl->data['links'] = $source->getLoginLinks();
		if (array_key_exists('forcedUsername', $state)) {
			$tpl->data['forceUsername'] = true;
			$tpl->data['rememberUsernameEnabled'] = false;
			$tpl->data['rememberUsernameChecked'] = false;
		} else {
			$tpl->data['forceUsername'] = false;
			$tpl->data['rememberUsernameEnabled'] = $source->getRememberUsernameEnabled();
			$tpl->data['rememberUsernameChecked'] = $source->getRememberUsernameChecked();
		}
		if (isset($state['SPMetadata'])) {
			$tpl->data['SPMetadata'] = $state['SPMetadata'];
		} else {
			$tpl->data['SPMetadata'] = NULL;
		}
	}

	$tpl->data['doChallengeResponse'] = $doChallengeResponse;
	$tpl->data['errorcode'] = $errorCode;
	$tpl->data['errorparams'] = $errorParams;
	if (isset($use_otp)){
		$tpl->data['use_otp'] = true;
	} else {
		$tpl->data['use_otp'] = false;
	}
	if (isset($state['privacyidea:privacyidea:checkTokenType'])) {
		$tpl->data['transaction_id'] = $transaction_id;
		$tpl->data['chal_resp_message'] = $message;
		$tpl->data['multi_challenge'] = $multi_challenge;
	}

    if ($state['privacyidea:privacyidea:authenticationMethod'] === "authprocess") {
        $tpl->data['LogoutURL'] = \SimpleSAML\Module::getModuleURL('core/authenticate.php', array('as' => $state['Source']['auth']))."&logout";
    }

	$tpl->show();

?>
