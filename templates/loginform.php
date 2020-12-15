<?php
if(isset($this->data['auth_proc_filter_scenario'])) {
	if (!isset($this->data['username'])) {
		$this->data['username'] = null;
	}
	$this->data['otp_extra'] = NULL;
} else {
    $this->data['auth_proc_filter_scenario'] = 0;
}
// First of all we determine how we were called
$multi_challenge = NULL;
if (isset($this->data['chal_resp_message'])) {
	$chal_resp_message = $this->t('{privacyidea:privacyidea:chal_resp_message}') . $this->data['chal_resp_message'];
} else {
    $chal_resp_message = "";
}
$hideResponseInput = FALSE;
$u2fSignRequest = NULL;
if ($this->data['otp_extra'] == 1){
    $password_text = $this->t('{privacyidea:privacyidea:password}');
} elseif ($this->data['use_otp']) {
    $password_text = $this->t('{privacyidea:privacyidea:otp}');
} else {
    $password_text = $this->t('{privacyidea:privacyidea:password_otp}');
}

if ($this->data['errorcode'] === "CHALLENGERESPONSE" || $this->data['doChallengeResponse']) {
    $password_text = $this->t('{privacyidea:privacyidea:otp}');
    SimpleSAML_Logger::debug("multi_challenge: " . print_r($this->data["multi_challenge"], TRUE));
    $multi_challenge = $this->data['multi_challenge'];
    // check if this is U2F
    SimpleSAML_Logger::debug("u2fSignRequest: " . print_r($u2fSignRequest, TRUE));
    $hideResponseInput = true;
    $u2fSignRequest = false;
    for ($i = 0; $i < count($multi_challenge); $i++) {
        if ($multi_challenge[$i]->type === "u2f") {
	        SimpleSAML_Logger::debug( "multi_challenge " . $i . " hide: " . print_r( $multi_challenge[ $i ]->attributes->hideResponseInput, true ) );
	        // not all challenges have hideResponseInput true
	        if ( ! $multi_challenge[ $i ]->attributes->hideResponseInput ) {
		        $hideResponseInput = false;
	        }
	        // we have at least one U2F token
	        if ( $multi_challenge[ $i ]->attributes->u2fSignRequest ) {
		        $u2fSignRequest = true;
	        }
        }
    }
}

$this->data['head'] = '';
if ($u2fSignRequest) {
    // Add javascript for U2F support before including the header.
    $this->data['head'] .= '<script type="text/javascript" src="'. htmlspecialchars(SimpleSAML_Module::getModuleUrl('privacyidea/js/u2f-api.js'), ENT_QUOTES) . '"></script>';
    $this->data['head'] .= '<script type="text/javascript" src="' . htmlspecialchars(SimpleSAML_Module::getModuleUrl('privacyidea/js/u2f.js'), ENT_QUOTES) . '"></script>';
}
if ($this->data['doPolling']) {
    // Add JavaScript for polling /token/challenges before including the header.
    $this->data['head'] .= '<script type="text/javascript" src="' . htmlspecialchars(SimpleSAML_Module::getModuleUrl('privacyidea/js/poll.js'), ENT_QUOTES) . '"></script>';
}

$this->data['header'] = $this->t('{privacyidea:privacyidea:header}');
if (strlen($this->data['username']) > 0) {
    $this->data['autofocus'] = 'password';
} else {
    $this->data['autofocus'] = 'username';
}
$this->includeAtTemplateBase('includes/header.php');

?>

<?php
// If there is an error, which is NOT the challenge response
if ($this->data['errorcode'] !== NULL && $this->data['errorcode'] !== "CHALLENGERESPONSE") {
    ?>

    <div style="border-left: 1px solid #e8e8e8; border-bottom: 1px solid #e8e8e8; background: #f5f5f5">
        <img src="/<?php echo htmlspecialchars($this->data['baseurlpath'], ENT_QUOTES); ?>resources/icons/experience/gtk-dialog-error.48x48.png"
             class="float-l erroricon" style="margin: 15px "/>
        <h2><?php echo $this->t('{login:error_header}'); ?></h2>
        <p>
            <b><?php echo htmlspecialchars($this->t('{errors:title_' . $this->data['errorcode'] . '}', $this->data['errorparams'])); ?></b>
        </p>
        <p><?php echo htmlspecialchars($this->t('{errors:descr_' . $this->data['errorcode'] . '}', $this->data['errorparams'])); ?></p>
    </div>

    <?php
}  // end of errorcode
?>


<div class="container">
    <div class="login">
        <div class="loginlogo"></div>
        <?php
        if ($this->data['errorcode'] === "CHALLENGERESPONSE" ||
            $this->data['auth_proc_filter_scenario']) {
            echo '<h2>' . htmlspecialchars($this->t('{privacyidea:privacyidea:login_title_challenge}')) . '</h2>';
            echo '<p class="logintext">' . htmlspecialchars($this->t('{privacyidea:privacyidea:login_text_challenge}')) . '</p>';
        } elseif ($this->data['otp_extra'] == 1) {
            echo '<h2>' . htmlspecialchars($this->t('{privacyidea:privacyidea:otp}')) . '</h2>';
            echo '<p class="logintext">' . htmlspecialchars($this->t('{privacyidea:privacyidea:otp_extra_text}')) . '</p>';
        } else {
            echo '<h2>' . htmlspecialchars($this->t('{privacyidea:privacyidea:login_title}')) . '</h2>';
            echo '<p class="logintext">' . htmlspecialchars($this->t('{privacyidea:privacyidea:login_text}')) . '</p>';
        } // end of !CHALLENGERESPONSE
        if (isset($this->data['enrollU2F'])) {
			echo '<p class="logintext">' . htmlspecialchars($this->t('{privacyidea:privacyidea:enroll_u2f}')) . '</p>';
        }
        ?>
        <form action="" method="post" id="piLoginForm" name="piLoginForm" class="loginform">
            <div class="form-panel first valid" id="gaia_firstform">
                <div class="slide-out ">
                    <div class="input-wrapper focused">
                        <!-- per line we have an identifier-shown -->
                        <div class="identifier-shown">
                            <?php
                            if ($this->data['forceUsername']) {
                                echo '<strong style="font-size: medium">' . htmlspecialchars($this->data['username']) . '</strong>';
                                echo '<input type="hidden" id="username" name="username" value="' . htmlspecialchars($this->data['username'], ENT_QUOTES) . '" />';
                                echo '<input type="hidden" id="clientData" name="clientData" value="" />';
                                echo '<input type="hidden" id="signatureData" name="signatureData" value="" />';
                                echo '<input type="hidden" id="registrationData" name="registrationData" value="" />';
                            } else {
                                echo '<label for="username">';
                                echo '<input type="text" id="username" tabindex="1" name="username" value="' . htmlspecialchars($this->data['username'], ENT_QUOTES) . '"';
                                echo ' placeholder="' . htmlspecialchars($this->t('{login:username}'), ENT_QUOTES) . '" />';
                                echo '</label>';
                            }
                            ?>
                            <?php
                            if(!$this->data['auth_proc_filter_scenario']) {
	                            if ( $this->data['rememberUsernameEnabled'] || $this->data['rememberMeEnabled'] ) {
		                            $rowspan = 1;
	                            } elseif ( array_key_exists( 'organizations', $this->data ) ) {
		                            $rowspan = 3;
	                            } else {
		                            $rowspan = 2;
	                            }
	                            ?>

	                            <?php
	                            if ( $this->data['rememberUsernameEnabled'] || $this->data['rememberMeEnabled'] ) {
		                            if ( $this->data['rememberUsernameEnabled'] ) {
			                            echo str_repeat( "\t", 4 );
			                            echo '<input type="checkbox" id="remember_username" tabindex="4" name="remember_username" value="Yes" ';
			                            echo $this->data['rememberUsernameChecked'] ? 'checked="Yes" /> ' : '/> ';
			                            echo htmlspecialchars( $this->t( '{login:remember_username}' ) );
		                            }
		                            if ( $this->data['rememberMeEnabled'] ) {
			                            echo str_repeat( "\t", 4 );
			                            echo '<input type="checkbox" id="remember_me" tabindex="4" name="remember_me" value="Yes" ';
			                            echo $this->data['rememberMeChecked'] ? 'checked="Yes" /> ' : '/> ';
			                            echo htmlspecialchars( $this->t( '{login:remember_me}' ) );
		                            }
	                            }
                            }
                            ?>


                        </div>
                        <div class="identifier-shown">
                            <!--
                            In case of challenge response with the U2F, we hide the password.
                            -->
                            <?php
                            echo '<td style="padding: .3em;" colspan="2">' . htmlspecialchars($chal_resp_message) . '</td>';
                            if (!$hideResponseInput || $this->data['use_otp']){
                                // normal login
	                            if (isset($this->data['tokenQR'])) {
		                            echo htmlspecialchars($this->t('{privacyidea:privacyidea:scanTokenQR}'));
		                            ?>
                                    <div class="tokenQR">
			                            <?php echo '<img src="' . $this->data['tokenQR'] . '" />';?>
                                    </div>
		                            <?php
	                            }
                                echo '<td><label for="password">';
                                echo '<input id="password" type="password" tabindex="2" name="password" placeholder="' . htmlspecialchars($password_text, ENT_QUOTES) . '" />';
                                echo '</label></td>';
                            }
                            echo '<p id="u2fTryAgain" name="u2fTryAgain" style="display: none">' . htmlspecialchars($this->t('{privacyidea:privacyidea:u2fNotWorking}'));
                            echo '<input class="rc-button" type="button" id="u2fTryAgain" name="u2fTryAgain" value="' . $this->t('{privacyidea:privacyidea:tryAgain}') . '" onClick="window.location.reload()" />';
                            echo '</p>'
                            ?>

                        </div>
                        <div class="identifier-shown">
                            <?php
                                // otp_extra == 1
                                if ($this->data["otp_extra"] == 1) {
                                    echo '<label for="OTP">';
                                    echo '<input type="password" id="OTP" tabindex="2" name="OTP" ';
                                    echo ' placeholder="' . htmlspecialchars($this->t('{privacyidea:privacyidea:otp}'), ENT_QUOTES) . '" />';
                                    echo '</label>';
                                }
                            ?>
                        </div>

                <?php
                if (array_key_exists('organizations', $this->data)) {
                    ?>
                    <div class="identifier-shown">
                        <?php echo htmlspecialchars($this->t('{login:organization}')); ?>
                        <select name="organization" tabindex="3">
                                <?php
                                if (array_key_exists('selectedOrg', $this->data)) {
                                    $selectedOrg = $this->data['selectedOrg'];
                                } else {
                                    $selectedOrg = NULL;
                                }

                                foreach ($this->data['organizations'] as $orgId => $orgDesc) {
                                    if (is_array($orgDesc)) {
                                        $orgDesc = $this->t($orgDesc);
                                    }

                                    if ($orgId === $selectedOrg) {
                                        $selected = 'selected="selected" ';
                                    } else {
                                        $selected = '';
                                    }

                                    echo '<option ' . $selected . 'value="' . htmlspecialchars($orgId, ENT_QUOTES) . '">' . htmlspecialchars($orgDesc) . '</option>';
                                }
                                ?>
                        </select>
                    </div>
                    <?php
                        }
                    ?>

                    <div class="identifier-captcha">
                        <?php
                            $text = $this->t('{login:login_button}');
                            if ($u2fSignRequest === NULL || $this->data['use_otp']) {
                                printf('<input class="rc-button rc-button-submit" type="submit" tabindex="4" id="regularsubmit" value="%s" />', htmlspecialchars($text, ENT_QUOTES));
                            }
                            ?>
                    </div>
                    </div> <!-- focused -->
                </div> <!-- slide-out-->
            </div> <!-- form-panel -->

            <?php
            if ($this->data['stateparams'] !== NULL) {
	            foreach ($this->data['stateparams'] as $name => $value) {
		            echo('<input type="hidden" name="' . htmlspecialchars($name, ENT_QUOTES) . '" value="' . htmlspecialchars($value, ENT_QUOTES) . '" />');
	            }
            }
            ?>
        </form>
<?php if (isset($this->data['LogoutURL'])) { ?>
        <p><a href="<?php echo htmlspecialchars($this->data['LogoutURL']); ?>"><?php echo $this->t('{status:logout}'); ?></a></p>
<?php } ?>
    </div>  <!-- End of login -->
</div>  <!-- End of container -->


<?php

if (!empty($this->data['links'])) {
    echo '<ul class="links" style="margin-top: 2em">';
    foreach ($this->data['links'] AS $l) {
        echo '<li><a href="' . htmlspecialchars($l['href'], ENT_QUOTES) . '">' . htmlspecialchars($this->t($l['text'])) . '</a></li>';
    }
    echo '</ul>';
}

$this->includeAtTemplateBase('includes/footer.php');

if ($u2fSignRequest) {
    // We call the U2F signing function
    SimpleSAML_Logger::debug("Calling Javascript with u2fSignRequest: " . print_r($u2fSignRequest, TRUE));
    SimpleSAML_Logger::debug("Calling Javascript with multi_challenge: " . print_r($multi_challenge, TRUE));
    for ($i = 0; $i < count($multi_challenge); $i++) {
        if ($multi_challenge[$i]->type === "u2f") {
	        SimpleSAML_Logger::debug( "multi_challenge u2fSignRequest: " . print_r( $multi_challenge[ $i ]->attributes->u2fSignRequest, true ) );
	        $signRequests[] = $multi_challenge[ $i ]->attributes->u2fSignRequest;
        }
    }
    SimpleSAML_Logger::debug("signRequests: " . print_r($signRequests, TRUE));
    SimpleSAML_Logger::debug("signRequests json: " . json_encode($signRequests, TRUE));
    echo '<script type="text/javascript">';
    if (isset($this->data['enrollU2F'])) {
        for ($i = 0; $i < count($multi_challenge); $i++) {
            if ($multi_challenge[$i]->serial = $this->data['serial']) {
                $attributes = $multi_challenge[$i]->attributes;
                $u2fSignRequest = $attributes->u2fSignRequest;
            }
        }
        echo 'register_u2f_request(';
        echo json_encode($u2fSignRequest->appId) . ", ";
        echo json_encode($u2fSignRequest->challenge) . ", ";
        echo json_encode($u2fSignRequest->keyHandle);
	    echo ');';
    } else {
	    echo 'sign_u2f_request(';
        echo json_encode($signRequests);
        echo ');';
    }
    echo '</script>';
}
if ($this->data['doPolling']) {
    echo '<script type="text/javascript">';
    foreach ($this->data['pollTokens'] as $i => $e) {
        SimpleSAML_Logger::debug("Asking client to poll challenges for " . $e . ".");
        echo 'poll_token_challenges(' . json_encode($e) . ');';
    }
    echo '</script>';
}
?>
