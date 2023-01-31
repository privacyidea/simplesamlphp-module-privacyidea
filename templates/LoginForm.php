<?php

// Set default scenario if isn't set
if (!empty($this->data['authProcFilterScenario']))
{
    if (empty($this->data['username']))
    {
        $this->data['username'] = null;
    }
}
else
{
    $this->data['authProcFilterScenario'] = 0;
}

// Set the right text shown in otp/pass field(s)
if (!empty($this->data['otpFieldHint']))
{
    $otpHint = $this->data['otpFieldHint'];
}
else
{
    $otpHint = $this->t('{privacyidea:privacyidea:otp}');
}
if (!empty($this->data['passFieldHint']))
{
    $passHint = $this->data['passFieldHint'];
}
else
{
    $passHint = $this->t('{privacyidea:privacyidea:password}');
}

$this->data['header'] = $this->t('{privacyidea:privacyidea:header}');

// Prepare next settings
if (strlen($this->data['username']) > 0)
{
    $this->data['autofocus'] = 'password';
}
else
{
    $this->data['autofocus'] = 'username';
}

$this->data['head'] .= '<link rel="stylesheet" href="'
    . htmlspecialchars(SimpleSAML_Module::getModuleUrl('privacyidea/css/loginform.css'), ENT_QUOTES)
    . '" media="screen" />';

$this->includeAtTemplateBase('includes/header.php');

// Prepare error case to show it in UI if needed
if ($this->data['errorCode'] !== NULL)
{
    ?>

    <div class="error-dialog">
        <img src="/<?php echo htmlspecialchars($this->data['baseurlpath'], ENT_QUOTES); ?>resources/icons/experience/gtk-dialog-error.48x48.png"
             class="float-l erroricon" alt="gtk-dialog-error"/>
        <h2><?php echo $this->t('{login:error_header}'); ?></h2>
        <p>
            <strong><?php echo htmlspecialchars("Error " . $this->data['errorCode'] . ": " . $this->data['errorMessage']); ?></strong>
        </p>
    </div>

    <?php
}  // end of errorcode
?>

    <div class="container">
        <div class="login">
            <div class="loginlogo"></div>

            <?php
            if ($this->data['authProcFilterScenario'])
            {
                echo '<h2>' . htmlspecialchars($this->t('{privacyidea:privacyidea:login_title_challenge}')) . '</h2>';
            }
            else
            {
                if ($this->data['step'] < 2)
                {
                    echo '<h2>' . htmlspecialchars($this->t('{privacyidea:privacyidea:login_title}')) . '</h2>';
                }
            }
            ?>

            <form action="FormReceiver.php" method="POST" id="piLoginForm" name="piLoginForm" class="loginForm">
                <div class="form-panel first valid" id="gaia_firstform">
                    <div class="slide-out ">
                        <div class="input-wrapper focused">
                            <div class="identifier-shown">
                                <?php
                                if ($this->data['forceUsername'])
                                {
                                    ?>
                                    <h3><?php echo htmlspecialchars($this->data['username']) ?></h3>
                                    <input type="hidden" id="username" name="username"
                                           value="<?php echo htmlspecialchars($this->data['username'], ENT_QUOTES) ?>"/>
                                    <?php
                                }
                                else
                                {
                                    ?>
                                    <label for="username" class="sr-only">
                                        <?php echo $this->t('{login:username}'); ?>
                                    </label>
                                    <input type="text" id="username" tabindex="1" name="username" autofocus
                                           value="<?php echo htmlspecialchars($this->data['username'], ENT_QUOTES) ?>"
                                           placeholder="<?php echo htmlspecialchars($this->t('{login:username}'), ENT_QUOTES) ?>"
                                    />
                                    <br>
                                    <?php
                                }

                                // Remember username in authproc
                                if (!$this->data['authProcFilterScenario'])
                                {
                                    if ($this->data['rememberUsernameEnabled'] || $this->data['rememberMeEnabled'])
                                    {
                                        $rowspan = 1;
                                    }
                                    elseif (array_key_exists('organizations', $this->data))
                                    {
                                        $rowspan = 3;
                                    }
                                    else
                                    {
                                        $rowspan = 2;
                                    }
                                    if ($this->data['rememberUsernameEnabled'] || $this->data['rememberMeEnabled'])
                                    {
                                        if ($this->data['rememberUsernameEnabled'])
                                        {
                                            echo str_repeat("\t", 4);
                                            echo '<input type="checkbox" id="rememberUsername" tabindex="5" name="rememberUsername"
                                         value="Yes" ';
                                            echo $this->data['rememberUsernameChecked'] ? 'checked="Yes" /> ' : '/> ';
                                            echo htmlspecialchars($this->t('{login:remember_username}'));
                                        }
                                        if ($this->data['rememberMeEnabled'])
                                        {
                                            echo str_repeat("\t", 4);
                                            echo '<input type="checkbox" id="rememberMe" tabindex="6" name="rememberMe" value="Yes" ';
                                            echo $this->data['rememberMeChecked'] ? 'checked="Yes" /> ' : '/> ';
                                            echo htmlspecialchars($this->t('{login:remember_me}'));
                                        }
                                    }
                                } ?>

                                <!-- Show the image if available -->
                                <?php
                                if ($this->data['mode'] === "otp" && !empty($this->data['imageOTP']))
                                {?>
                                    <br><img class="images" alt="challenge_img" src=<?php echo $this->data['imageOTP'] ?>><br><br><?php
                                }
                                elseif ($this->data['mode'] === "push" && !empty($this->data['imagePush']))
                                {?>
                                    <br><img class="images" alt="challenge_img" src="<?php echo $this->data['imagePush'] ?>"><br><br><?php
                                }
                                elseif ($this->data['mode'] === "u2f" && !empty($this->data['imageU2F']))
                                {?>
                                    <br><img class="images" alt="challenge_img" src="<?php echo $this->data['imageU2F'] ?>"><br><br><?php
                                }
                                elseif ($this->data['mode'] === "webauthn" && !empty($this->data['imageWebauthn']))
                                {?>
                                    <br><img class="images" alt="challenge_img" src="<?php echo $this->data['imageWebauthn'] ?>"><br><br><?php
                                }
                                ?>

                                <!-- Show the messages -->
                                <strong id="message"><?php echo htmlspecialchars(@$this->data['message'] ?: "", ENT_QUOTES) ?></strong>
                                <br>

                                <!-- Pass and OTP fields -->
                                <label for="password" class="sr-only">
                                    <?php echo $this->t('{privacyidea:privacyidea:password}'); ?>
                                </label>
                                <input id="password" name="password" tabindex="2" type="password" value="" class="text"
                                       placeholder="<?php echo htmlspecialchars($passHint, ENT_QUOTES) ?>"/>

                                <label for="otp" class="sr-only">
                                    <?php echo $this->t('{privacyidea:privacyidea:otp}'); ?>
                                </label>
                                <input id="otp" name="otp" tabindex="3" type="password" value="" class="text" placeholder="<?php echo htmlspecialchars($otpHint, ENT_QUOTES) ?>">

                                <br><br>
                                <input id="submitButton" tabindex="7" class="rc-button rc-button-submit" type="submit"
                                       name="Submit"
                                       value="<?php echo htmlspecialchars($this->t('{login:login_button}'), ENT_QUOTES) ?>"/>
                                <br><br>

                                <!-- Undefined index is suppressed and the default is used for these values -->
                                <input id="mode" type="hidden" name="mode"
                                       value="<?php echo htmlspecialchars(@$this->data['mode'] ?: "otp", ENT_QUOTES) ?>"/>

                                <input id="pushAvailable" type="hidden" name="pushAvailable"
                                       value="<?php echo htmlspecialchars(@$this->data['pushAvailable'] ?: "0", ENT_QUOTES) ?>"/>

                                <input id="otpAvailable" type="hidden" name="otpAvailable"
                                       value="<?php echo htmlspecialchars(@$this->data['otpAvailable'] ?: "1", ENT_QUOTES) ?>"/>

                                <input id="webAuthnSignRequest" type="hidden" name="webAuthnSignRequest"
                                       value='<?php echo htmlspecialchars(@$this->data['webAuthnSignRequest'] ?: "", ENT_QUOTES) ?>'/>

                                <input id="u2fSignRequest" type="hidden" name="u2fSignRequest"
                                       value='<?php echo htmlspecialchars(@$this->data['u2fSignRequest'] ?: "", ENT_QUOTES) ?>'/>

                                <input id="modeChanged" type="hidden" name="modeChanged" value="0"/>
                                <input id="step" type="hidden" name="step"
                                       value="<?php echo htmlspecialchars(@$this->data['step'] ?: 2, ENT_QUOTES) ?>"/>

                                <input id="webAuthnSignResponse" type="hidden" name="webAuthnSignResponse" value=""/>
                                <input id="u2fSignResponse" type="hidden" name="u2fSignResponse" value=""/>
                                <input id="origin" type="hidden" name="origin" value=""/>
                                <input id="loadCounter" type="hidden" name="loadCounter"
                                       value="<?php echo htmlspecialchars(@$this->data['loadCounter'] ?: 1, ENT_QUOTES) ?>"/>

                                <!-- Additional input to persist the message and images -->
                                <input type="hidden" name="message"
                                       value="<?php echo htmlspecialchars(@$this->data['message'] ?: "", ENT_QUOTES) ?>"/>
                                <input type="hidden" name="imageOTP"
                                       value="<?php echo htmlspecialchars(@$this->data['imageOTP'] ?: "", ENT_QUOTES) ?>"/>
                                <input type="hidden" name="imagePush"
                                       value="<?php echo htmlspecialchars(@$this->data['imagePush'] ?: "", ENT_QUOTES) ?>"/>
                                <input type="hidden" name="imageU2F"
                                       value="<?php echo htmlspecialchars(@$this->data['imageU2F'] ?: "", ENT_QUOTES) ?>"/>
                                <input type="hidden" name="imageWebauthn"
                                       value="<?php echo htmlspecialchars(@$this->data['imageWebauthn'] ?: "", ENT_QUOTES) ?>"/>

                                <?php
                                // If enrollToken load QR Code
                                if (isset($this->data['tokenQR']))
                                {
                                    echo htmlspecialchars($this->t('{privacyidea:privacyidea:scanTokenQR}'));
                                    ?>
                                    <br><br>
                                    <div class="tokenQR">
                                        <?php echo '<img src="' . $this->data['tokenQR'] . '" />'; ?>
                                    </div>
                                    <?php
                                }
                                ?>
                            </div>

                            <?php
                            // Organizations
                            if (array_key_exists('organizations', $this->data))
                            {
                                ?>
                                <div class="identifier-shown">
                                    <label for="organization"><?php echo htmlspecialchars($this->t('{login:organization}')); ?></label>
                                    <select id="organization" name="organization" tabindex="4">
                                        <?php
                                        if (array_key_exists('selectedOrg', $this->data))
                                        {
                                            $selectedOrg = $this->data['selectedOrg'];
                                        }
                                        else
                                        {
                                            $selectedOrg = NULL;
                                        }

                                        foreach ($this->data['organizations'] as $orgId => $orgDesc)
                                        {
                                            if (is_array($orgDesc))
                                            {
                                                $orgDesc = $this->t($orgDesc);
                                            }

                                            if ($orgId === $selectedOrg)
                                            {
                                                $selected = 'selected="selected" ';
                                            }
                                            else
                                            {
                                                $selected = '';
                                            }

                                            echo '<option ' . $selected . 'value="' . htmlspecialchars($orgId, ENT_QUOTES) . '">' . htmlspecialchars($orgDesc) . '</option>';
                                        } ?>
                                    </select>
                                </div>
                            <?php } ?>
                        </div> <!-- focused -->
                    </div> <!-- slide-out-->
                </div> <!-- form-panel -->

                <div id="AlternateLoginOptions" class="groupMargin">

                    <h3><label><?php echo $this->t('{privacyidea:privacyidea:alternate_login_options}'); ?></label></h3>
                    <br>

                    <!-- Alternate Login Options-->
                    <input id="useWebAuthnButton" name="useWebAuthnButton" type="button" value="WebAuthn"/>
                    <input id="usePushButton" name="usePushButton" type="button" value="Push"/>
                    <input id="useOTPButton" name="useOTPButton" type="button" value="OTP"/>
                    <input id="useU2FButton" name="useU2FButton" type="button" value="U2F"/>
                </div>
                <br>
            </form>

            <?php
            // Logout
            if (isset($this->data['LogoutURL']))
            { ?>
                <p>
                    <a href="<?php echo htmlspecialchars($this->data['LogoutURL']); ?>"><?php echo $this->t('{status:logout}'); ?></a>
                </p>
            <?php } ?>
        </div>  <!-- End of login -->
    </div>  <!-- End of container -->

<?php
if (!empty($this->data['links']))
{
    echo '<ul class="links">';
    foreach ($this->data['links'] as $l)
    {
        echo '<li><a href="' . htmlspecialchars($l['href'], ENT_QUOTES) . '">' . htmlspecialchars($this->t($l['text'])) . '</a></li>';
    }
    echo '</ul>';
}
?>

    <script src="<?php echo htmlspecialchars(SimpleSAML_Module::getModuleUrl('privacyidea/js/pi-webauthn.js'), ENT_QUOTES) ?>">
    </script>

    <script src="<?php echo htmlspecialchars(SimpleSAML_Module::getModuleUrl('privacyidea/js/u2f-api.js'), ENT_QUOTES) ?>">
    </script>

    <meta id="privacyidea-step" name="privacyidea-step" content="<?php echo $this->data['step'] ?>">

    <meta id="privacyidea-separate-otp" name="privacyidea-separate-otp" content="<?php if (isset($this->data['authenticationFlow']) && $this->data['authenticationFlow'] === "separateOTP") {echo "true";} ?>">
    <meta id="privacyidea-hide-pass-field" name="privacyidea-hide-pass-field" content="<?php if (isset($this->data['authenticationFlow']) && $this->data['authenticationFlow'] === "triggerChallenge") {echo "true";} ?>">

    <meta id="privacyidea-hide-alternate" name="privacyidea-hide-alternate" content="
        <?php
        if(!empty($this->data['pushAvailable']))
        {echo (!$this->data['pushAvailable'] && empty($this->data['u2fSignRequest']) && empty($this->data['webAuthnSignRequest'])) ? 'true' : 'false';}
        ?>
    ">

    <meta id="privacyidea-translations" name="privacyidea-translations" content="<?php
    $translations = [];
    $translation_keys = [
        'alert_webauthn_insecure_context', 'alert_webauthn_unavailable', 'alert_webAuthnSignRequest_error',
        'alert_u2f_insecure_context', 'alert_u2f_unavailable', 'alert_U2FSignRequest_error',
    ];
    foreach ($translation_keys as $translation_key)
    {
        $translations[$translation_key] = $this->t(sprintf('{privacyidea:privacyidea:%s}', $translation_key));
    }
    echo htmlspecialchars(json_encode($translations));
    ?>">

    <script src="<?php echo htmlspecialchars(SimpleSAML_Module::getModuleUrl('privacyidea/js/loginform.js'), ENT_QUOTES) ?>">
    </script>

<?php
$this->includeAtTemplateBase('includes/footer.php');
?>