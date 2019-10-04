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
    SimpleSAML_Logger::debug("Loaded state privacyidea:privacyidea:init from polltransaction.php");
} catch (Exception $e){
}

if (isset($state)) {
    $serverconfig = $state['privacyidea:serverconfig'];
    $authToken = sspmod_privacyidea_Auth_utils::fetchAuthToken($serverconfig);
    $transaction_id = strval($state['privacyidea:privacyidea:checkTokenType']['transaction_id']);
    SimpleSAML_Logger::debug("Polling for transaction_id: " . $transaction_id);

    $result = sspmod_privacyidea_Auth_utils::curl(
        array(),
        array("authorization:" . $authToken),
        $serverconfig,
        "/validate/polltransaction/" . $transaction_id,
        "GET")
        ->result
        ->value;
}

echo isset($result) && $result ? "true" : "false";

?>
