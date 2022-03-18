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
if (isset($this->data['otpFieldHint']))
{
    $otpHint = $this->data['otpFieldHint'];
}
else
{
    $otpHint = $this->t('{privacyidea:privacyidea:otp}');
}
if (isset($this->data['passFieldHint']))
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
                                            echo '<input type="checkbox" id="rememberUsername" tabindex="4" name="rememberUsername"
                                         value="Yes" ';
                                            echo $this->data['rememberUsernameChecked'] ? 'checked="Yes" /> ' : '/> ';
                                            echo htmlspecialchars($this->t('{login:remember_username}'));
                                        }
                                        if ($this->data['rememberMeEnabled'])
                                        {
                                            echo str_repeat("\t", 4);
                                            echo '<input type="checkbox" id="rememberMe" tabindex="4" name="rememberMe" value="Yes" ';
                                            echo $this->data['rememberMeChecked'] ? 'checked="Yes" /> ' : '/> ';
                                            echo htmlspecialchars($this->t('{login:remember_me}'));
                                        }
                                    }
                                } ?>

                                <!-- Pass and OTP fields -->
                                <label for="password" class="sr-only">
                                    <?php echo $this->t('{privacyidea:privacyidea:password}'); ?>
                                </label>
                                <input id="password" name="password" tabindex="1" type="password" value="" class="text"
                                       placeholder="<?php echo htmlspecialchars($passHint, ENT_QUOTES) ?>"/>

                                <strong id="message"><?php echo @$this->data['message'] ?: "" ?></strong>
                                <br>
                                <input id="otp" name="otp" type="password"
                                       placeholder="<?php echo htmlspecialchars($otpHint, ENT_QUOTES) ?>">
                                <br><br>
                                <input id="submitButton" tabindex="1" class="rc-button rc-button-submit" type="submit"
                                       name="Submit"
                                       value="<?php echo htmlspecialchars($this->t('{login:login_button}'), ENT_QUOTES) ?>"/>
                                <br><br>

                                <!-- Undefined index is suppressed and the default is used for these values -->
                                <input id="mode" type="hidden" name="mode"
                                       value="<?php echo @$this->data['mode'] ?: "otp" ?>"/>

                                <input id="pushAvailable" type="hidden" name="pushAvailable"
                                       value="<?php echo @$this->data['pushAvailable'] ?: false ?>"/>

                                <input id="otpAvailable" type="hidden" name="otpAvailable"
                                       value="<?php echo @$this->data['otpAvailable'] ?: true ?>"/>

                                <input id="webAuthnSignRequest" type="hidden" name="webAuthnSignRequest"
                                       value='<?php echo @$this->data['webAuthnSignRequest'] ?: "" ?>'/>

                                <input id="u2fSignRequest" type="hidden" name="u2fSignRequest"
                                       value='<?php echo @$this->data['u2fSignRequest'] ?: "" ?>'/>

                                <input id="modeChanged" type="hidden" name="modeChanged" value="0"/>
                                <input id="step" type="hidden" name="step"
                                       value="<?php echo @$this->data['step'] ?: 2 ?>"/>

                                <input id="webAuthnSignResponse" type="hidden" name="webAuthnSignResponse" value=""/>
                                <input id="u2fSignResponse" type="hidden" name="u2fSignResponse" value=""/>
                                <input id="origin" type="hidden" name="origin" value=""/>
                                <input id="loadCounter" type="hidden" name="loadCounter"
                                       value="<?php echo @$this->data['loadCounter'] ?: 1 ?>"/>

                                <!-- Additional input to persist the message -->
                                <input type="hidden" name="message"
                                       value="<?php echo @$this->data['message'] ?: "" ?>"/>

                                <?php
                                // If enrollToken load QR Code
                                if (isset($this->data['tokenQR']))
                                {
                                    echo htmlspecialchars($this->t('{privacyidea:privacyidea:scanTokenQR}'));
                                    ?>
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
                                    <select id="organization" name="organization" tabindex="3">
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
    <meta id="privacyidea-hide-alternate" name="privacyidea-hide-alternate" content="<?php echo (
        !$this->data['pushAvailable']
        && (!isset($this->data['u2fSignRequest']) || ($this->data['u2fSignRequest']) == "")
        && (!isset($this->data['webAuthnSignRequest']) || ($this->data['webAuthnSignRequest']) == "")
    ) ? 'true' : 'false'; ?>">

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