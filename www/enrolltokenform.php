<?php
	try{
		$authStateId = $_REQUEST['StateId'];
		$state = SimpleSAML_Auth_State::loadState($authStateId, 'privacyidea:tokenEnrollment:init');
	} catch (Exception $e){
	}

	if(isset($_POST['OTP'])) {
	    try {
		    if(sspmod_privacyidea_Auth_Process_privacyidea::authenticate($state, $_POST['OTP'])) {
			    SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea:init');
			    SimpleSAML_Auth_ProcessingChain::resumeProcessing($state);
		    } else {
			    SimpleSAML_Logger::debug("privacyIDEA: User entered wrong OTP");
		    }
        } catch (Exception $e){
	        echo $e;
        }
	}

	$cfg = SimpleSAML_Configuration::getInstance();
	$tpl = new SimpleSAML_XHTML_Template($cfg, 'privacyidea:loginform.php');
	$tpl->data['auth_proc_filter_scenario'] = true;
	$tpl->data['params'] = array('StateId' => $authStateId);
	$tpl->show();

	?>