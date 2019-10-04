<?php

/*
 * Poll for the response to an out-of-band challenge.
 *
 * This is called from AJAX, if the user has an out-of-band token. It acts as a proxy for the
 * `/validate/polltransaction`-endpoint of PrivacyIDEA.
 */

try{
    $authStateId = $_REQUEST['StateId'];
    $state = SimpleSAML_Auth_State::loadState($authStateId, 'privacyidea:privacyidea:init');
    SimpleSAML_Logger::debug("Loaded state privacyidea:privacyidea:init from checktokenchallenges.php");
} catch (Exception $e){
}

$serverconfig = $state['privacyidea:serverconfig'];
$authToken = sspmod_privacyidea_Auth_utils::fetchAuthToken($serverconfig);

// Stub.
echo "false";

?>
