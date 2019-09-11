<?php

    try{
        $authStateId = $_REQUEST['StateId'];
        $state = SimpleSAML_Auth_State::loadState($authStateId, 'privacyidea:privacyidea:init');
    } catch (Exception $e){
    }

    $serverconfig = $state['privacyidea:serverconfig'];
    $pushToken = $_GET['token'];
    $authToken = sspmod_privacyidea_Auth_utils::fetchAuthToken($serverconfig);

    $result = false;

    foreach (
        // The $pushToken is sanitized using urlencode() here. Any legal token ID should not be altered by this, as of
        // PrivacyIDEA 3.2. If the token ID does however contain any characters that would need to be urlencoded, this
        // will hang indefinitely, since the server will not decode the token ID and the ID checked will thus be wrong.
        sspmod_privacyidea_Auth_utils::curl(
            array(),
            array("authorization:" . $authToken),
            $serverconfig,
            "/token/challenges/" . urlencode($pushToken),
            "GET")
            ->result
            ->value
            ->challenges
        as $i => $e
    ) {
        if ($e->otp_valid) {
            $result = true;
        }
    }

    echo $result ? "true" : "false";

?>