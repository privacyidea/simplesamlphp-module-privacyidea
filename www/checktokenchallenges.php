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
        sspmod_privacyidea_Auth_utils::curl(
            array(),
            array("authorization:" . $authToken),
            $serverconfig,
            "/token/challenges/" . $pushToken,
            "GET")
            ->result
            ->value
            ->challenges
        as $i => $e
    ) {
        if (strtotime($e->expiration) - time() > 0 && $e->otp_valid) {
            $result = true;
        }
    }

    echo $result ? "true" : "false";

?>