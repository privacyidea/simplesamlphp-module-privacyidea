<?php
	try{
		$authStateId = $_REQUEST['StateId'];
		$state = SimpleSAML_Auth_State::loadState($authStateId, 'privacyidea:privacyidea:init');
	} catch (Exception $e){
	}

	if(isset($_POST['OTP'])) {
	    try {
		    if(SimpleSAML\Module\privacyidea\Auth\Process\privacyidea::authenticate($state, $_POST['OTP'])) {
			    SimpleSAML_Auth_State::saveState($state, 'privacyidea:privacyidea:init');
			    SimpleSAML_Auth_ProcessingChain::resumeProcessing($state);
		    } else {
			    echo "Wrong OTP";
		    }
        } catch (Exception $e){
	        echo $e;
        }
	}

	$cfg = SimpleSAML_Configuration::getInstance();
	$tpl = new SimpleSAML_XHTML_Template($cfg, 'privacyidea:loginform.php');
	$trans = $tpl->getTranslator();
	$tpl->data['auth_proc_filter_scenario'] = true;
	$tpl->data['params'] = array('StateId' => $authStateId);
	$tpl->data['error'] = ($error) ? $trans->t($error) : false;
	$tpl->show();

	?>