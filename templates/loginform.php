<?php
// First of all we determine how we were called
$chal_resp_attributes = NULL;
$chal_resp_message = '';
$hideResponseInput = FALSE;
$u2fSignRequest = NULL;
if ($this->data['otp_extra'] == 1){
    $password_text = $this->t('{privacyidea:privacyidea:password}');
} else {
    $password_text = $this->t('{privacyidea:privacyidea:password_otp}');
}

if ($this->data['errorcode'] === "CHALLENGERESPONSE") {
    $password_text = $this->t('{privacyidea:privacyidea:otp}');
    SimpleSAML_Logger::debug("Attributes: " . print_r($this->data["chal_resp_attributes"], TRUE));
    $chal_resp_attributes = $this->data['chal_resp_attributes'];
    $hideResponseInput = $chal_resp_attributes->hideResponseInput;
    $chal_resp_message = $this->data['chal_resp_message'];
    // check if this is U2F
    $u2fSignRequest = $chal_resp_attributes->u2fSignRequest;
    SimpleSAML_Logger::debug("u2fSignRequest: " . print_r($u2fSignRequest, TRUE));
}

if ($u2fSignRequest) {
    // Add javascript for U2F support before including the header.
    $this->data['head'] = '<script type="text/javascript" src="' . htmlspecialchars(SimpleSAML_Module::getModuleUrl('privacyidea/js/u2f-api.js')) . '"></script>\n';
    $this->data['head'] .= '<script type="text/javascript" src="' . htmlspecialchars(SimpleSAML_Module::getModuleUrl('privacyidea/js/u2f.js')) . '"></script>';
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
        <img src="/<?php echo htmlspecialchars($this->data['baseurlpath']); ?>resources/icons/experience/gtk-dialog-error.48x48.png"
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
        if ($this->data['errorcode'] === "CHALLENGERESPONSE") {
            echo '<h2>' . htmlspecialchars($this->t('{privacyidea:privacyidea:login_title_challenge}')) . '</h2>';
            echo '<p class="logintext">' . htmlspecialchars($this->t('{privacyidea:privacyidea:login_text_challenge}')) . '</p>';
        } elseif ($this->data['otp_extra'] == 1) {
            echo '<h2>' . htmlspecialchars($this->t('{privacyidea:privacyidea:otp}')) . '</h2>';
            echo '<p class="logintext">' . htmlspecialchars($this->t('{privacyidea:privacyidea:otp_extra_text}')) . '</p>';
        } else {
            echo '<h2>' . htmlspecialchars($this->t('{privacyidea:privacyidea:login_title}')) . '</h2>';
            echo '<p class="logintext">' . htmlspecialchars($this->t('{privacyidea:privacyidea:login_text}')) . '</p>';
        } // end of !CHALLENGERESPONSE
        ?>
        <form action="?" method="post" id="piLoginForm" name="piLoginForm" class="loginform">
            <div class="form-panel first valid" id="gaia_firstform">
                <div class="slide-out ">
                    <div class="input-wrapper focused">
                        <!-- per line we have an identifier-shown -->
                        <div class="identifier-shown">
                            <?php
                            if ($this->data['forceUsername']) {
                                echo '<strong style="font-size: medium">' . htmlspecialchars($this->data['username']) . '</strong>';
                                echo '<input type="hidden" id="username" name="username" value="' . htmlspecialchars($this->data['username']) . '" />';
                                echo '<input type="hidden" id="transaction_id" name="transaction_id" value="' . htmlspecialchars($this->data['transaction_id']) . '" />';
                                echo '<input type="hidden" id="clientData" name="clientData" value="" />';
                                echo '<input type="hidden" id="signatureData" name="signatureData" value="" />';
                            } else {
                                echo '<label for="username">';
                                echo '<input type="text" id="username" tabindex="1" name="username" value="' . htmlspecialchars($this->data['username']) . '"';
                                echo ' placeholder="' . htmlspecialchars($this->t('{login:username}')) . '" />';
                                echo '</label>';
                            }
                            ?>

                            <?php
                            if ($this->data['rememberUsernameEnabled'] || $this->data['rememberMeEnabled']) {
                                $rowspan = 1;
                            } elseif (array_key_exists('organizations', $this->data)) {
                                $rowspan = 3;
                            } else {
                                $rowspan = 2;
                            }
                            ?>

                            <?php
                            if ($this->data['rememberUsernameEnabled'] || $this->data['rememberMeEnabled']) {
                                if ($this->data['rememberUsernameEnabled']) {
                                    echo str_repeat("\t", 4);
                                    echo '<input type="checkbox" id="remember_username" tabindex="4" name="remember_username" value="Yes" ';
                                    echo $this->data['rememberUsernameChecked'] ? 'checked="Yes" /> ' : '/> ';
                                    echo htmlspecialchars($this->t('{login:remember_username}'));
                                }
                                if ($this->data['rememberMeEnabled']) {
                                    echo str_repeat("\t", 4);
                                    echo '<input type="checkbox" id="remember_me" tabindex="4" name="remember_me" value="Yes" ';
                                    echo $this->data['rememberMeChecked'] ? 'checked="Yes" /> ' : '/> ';
                                    echo htmlspecialchars($this->t('{login:remember_me}'));
                                }
                            }
                            ?>

                        </div>
                        <div class="identifier-shown">
                            <!--
                            In case of challenge response with the U2F, we hide the password.
                            -->
                            <?php
                            if ($hideResponseInput) {
                                // challenge response without OTP
                                echo '<td style="padding: .3em;" colspan="2">' . htmlspecialchars($chal_resp_message) . '</td>';
                            } else {
                                // normal login
                                echo '<td><label for="password">';
                                echo '<input id="password" type="password" tabindex="2" name="password" placeholder="' . htmlspecialchars($password_text) . '" />';
                                echo '</label></td>';
                            }
                            ?>

                        </div>
                        <div class="identifier-shown">
                            <?php
                                // otp_extra == 1
                                if ($this->data["otp_extra"] == 1) {
                                    echo '<label for="OTP">';
                                    echo '<input type="text" id="OTP" tabindex="2" name="OTP" ';
                                    echo ' placeholder="' . htmlspecialchars($this->t('{privacyidea:privacyidea:otp}')) . '" />';
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

                                    echo '<option ' . $selected . 'value="' . htmlspecialchars($orgId) . '">' . htmlspecialchars($orgDesc) . '</option>';
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
                            if ($u2fSignRequest === NULL) {
                                printf('<input class="rc-button rc-button-submit" type="submit" tabindex="4" id="regularsubmit" value="%s" />', htmlspecialchars($text));
                            }
                            ?>
                    </div>
                    </div> <!-- focused -->
                </div> <!-- slide-out-->
            </div> <!-- form-panel -->

            <?php
            foreach ($this->data['stateparams'] as $name => $value) {
                echo('<input type="hidden" name="' . htmlspecialchars($name) . '" value="' . htmlspecialchars($value) . '" />');
            }
            ?>
        </form>

    </div>  <!-- End of login -->
</div>  <!-- End of container -->


<?php

if (!empty($this->data['links'])) {
    echo '<ul class="links" style="margin-top: 2em">';
    foreach ($this->data['links'] AS $l) {
        echo '<li><a href="' . htmlspecialchars($l['href']) . '">' . htmlspecialchars($this->t($l['text'])) . '</a></li>';
    }
    echo '</ul>';
}

$this->includeAtTemplateBase('includes/footer.php');

if ($u2fSignRequest) {
    // We call the U2F signing function
    SimpleSAML_Logger::debug("Calling Javascript with u2fSignRequest: " . print_r($u2fSignRequest, TRUE));
    echo '<script type="text/javascript">';
    echo 'sign_u2f_request(';
    echo json_encode($u2fSignRequest->challenge) . ',';
    echo json_encode($u2fSignRequest->keyHandle) . ',';
    echo json_encode($u2fSignRequest->appId) . ');';
    echo '</script>';
}
?>
