<?php
	try{
		$authStateId = $_REQUEST['StateId'];
		$state = SimpleSAML_Auth_State::loadState($authStateId, 'privacyidea:privacyidea:init');
	} catch (Exception $e){
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
		    if(sspmod_privacyidea_Auth_Process_privacyidea::authenticate($state, $password, $transaction_id, $signatureData, $clientData, $registrationData)) {
			    SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea:init');
			    SimpleSAML_Auth_ProcessingChain::resumeProcessing($state);
		    } else {
			    SimpleSAML_Logger::debug("privacyIDEA: User entered wrong OTP");
		    }
        } catch (SimpleSAML_Error_Error $e) {
            /* Login failed. Extract error code and parameters, to display the error. */
            $errorCode = $e->getErrorCode();
            $errorParams = $e->getParameters();
            SimpleSAML_Logger::debug("Login failed. Catching errorCode: ". $errorCode);
            if ($errorCode === "CHALLENGERESPONSE" ) {
	            /* In case of challenge response we do not change the username */
	            $uidKey = $state['privacyidea:privacyidea']['uidKey'];
	            $username = $state['Attributes'][$uidKey][0];
	            $transaction_id = $errorParams[1];
	            $message = '';
	            $multi_challenge = $errorParams[2];
	            SimpleSAML_Logger::debug("Challenge Response transaction_id: ". $errorParams[1]);
	            SimpleSAML_Logger::debug("Challenge Response multi_challenge: " . print_r($multi_challenge, TRUE));
	            for ($i = 0; $i < count($multi_challenge); $i++) {
	            	SimpleSAML_Logger::debug("Token serial " . $i . ": " . print_r($multi_challenge[$i]->serial, TRUE));
	            	$message = $message . ' ' . $multi_challenge[$i]->serial;
	            }
	            SimpleSAML_Logger::debug("Challenge Response message: " . $message);
	        }
		}
	}
	$doChallengeResponse = false;
	if (isset($state['privacyidea:privacyidea:doTriggerChallenge'])) {
		$triggerChallenge = $state['privacyidea:privacyidea:doTriggerChallenge'];
		if ($triggerChallenge['use_u2f']) {
			$doChallengeResponse = true;
			$uidKey = $state['privacyidea:privacyidea']['uidKey'];
			$username = $state['Attributes'][$uidKey][0];
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
		if ($triggerChallenge['use_otp']) {
			$use_otp = true;
		}
	}

	$cfg = SimpleSAML_Configuration::getInstance();
	$tpl = new SimpleSAML_XHTML_Template($cfg, 'privacyidea:loginform.php');
	$tpl->data['auth_proc_filter_scenario'] = true;
	if (isset($state['privacyidea:tokenEnrollment']['tokenQR'])) {
		$tpl->data['tokenQR'] = $state['privacyidea:tokenEnrollment']['tokenQR'];
	} else {
		$tpl->data['tokenQR'] = null;
	}
	if (isset($state['privacyidea:tokenEnrollment']['enrollU2F'])) {
		$tpl->data['serial'] = $state['privacyidea:tokenEnrollment']['serial'];
		$tpl->data['enrollU2F'] = true;
	}
	$tpl->data['params'] = array('StateId' => $authStateId);


	if (isset($username)) {
        $tpl->data['transaction_id'] = $transaction_id;
        $tpl->data['chal_resp_message'] = $message;
        $tpl->data['multi_challenge'] = $multi_challenge;
	}
	if (isset($errorCode)) {
		$tpl->data['errorcode'] = $errorCode;
		$tpl->data['errorparams'] = $errorParams;
	}
	if (isset($use_otp)) {
		$tpl->data['use_otp'] = TRUE;
	} else {
		$tpl->data['use_otp'] = FALSE;
	}
	$tpl->data['forceUsername'] = TRUE;
	$tpl->data['rememberUsernameEnabled'] = TRUE;
	$tpl->data['rememberUsernameChecked'] = TRUE;
	$tpl->data['doChallengeResponse'] = $doChallengeResponse;

	$tpl->show();

	?>