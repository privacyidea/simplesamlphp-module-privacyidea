<?php

// Set default scenario if isn't set
if (!empty($this->data['authProcFilterScenario'])) {
    if (empty($this->data['username'])) {
        $this->data['username'] = null;
    }
} else {
    $this->data['authProcFilterScenario'] = 0;
}

// Set the right text shown in otp/pass field(s)
if(!empty($this->data['otpFieldHint'])) {
    $otpHint = $this->data['otpFieldHint'];
} else {
    $otpHint = $this->t('{privacyidea:privacyidea:otp}');
}
if(!empty($this->data['passFieldHint'])) {
    $passHint = $this->data['passFieldHint'];
} else {
    $passHint = $this->t('{privacyidea:privacyidea:password}');
}

// Call u2f.js and u2f-api.js if u2f token is triggered
/*$head = '';
if ($this->data['u2fSignRequest']) {
    // Add javascript for U2F support before including the header.
    $head .= '<script type="text/javascript" src="' . htmlspecialchars(SimpleSAML_Module::getModuleUrl('privacyidea/js/u2f-api.js'), ENT_QUOTES) . '"></script>';
}*/

$this->data['header'] = $this->t('{privacyidea:privacyidea:header}');

// Prepare next settings
if (strlen($this->data['username']) > 0) {
    $this->data['autofocus'] = 'password';
} else {
    $this->data['autofocus'] = 'username';
}

$this->includeAtTemplateBase('includes/header.php');

// Prepare error case to show it in UI if needed
if ($this->data['errorCode'] !== NULL) {
    ?>

    <div style="border-left: 1px solid #e8e8e8; border-bottom: 1px solid #e8e8e8; background: #f5f5f5">
        <img src="/<?php echo htmlspecialchars($this->data['baseurlpath'], ENT_QUOTES); ?>resources/icons/experience/gtk-dialog-error.48x48.png"
             class="float-l erroricon" style="margin: 15px " alt="gtk-dialog-error"/>
        <h2><?php echo $this->t('{login:error_header}'); ?></h2>
        <p>
            <strong><?php echo htmlspecialchars("Error ". $this->data['errorCode']. ": " . $this->data['errorMessage']); ?></strong>
        </p>
    </div>

    <?php
}  // end of errorcode
?>

<div class="container">
    <div class="login">
        <div class="loginlogo"></div>

        <?php
        if ($this->data['authProcFilterScenario']) {
            echo '<h2>' . htmlspecialchars($this->t('{privacyidea:privacyidea:login_title_challenge}')) . '</h2>';
        } else {
            if ($this->data['step'] < 2) {
                echo '<h2>' . htmlspecialchars($this->t('{privacyidea:privacyidea:login_title}')) . '</h2>';
            }
        }
        ?>

        <form action="" method="POST" id="piLoginForm" name="piLoginForm" class="loginForm">
            <div class="form-panel first valid" id="gaia_firstform">
                <div class="slide-out ">
                    <div class="input-wrapper focused">
                        <div class="identifier-shown">
                            <?php
                            if ($this->data['forceUsername']) {
                                ?>
                                <strong style="font-size: medium"><?php echo htmlspecialchars($this->data['username']) ?></strong>
                                <input type="hidden" id="username" name="username"
                                       value="<?php echo htmlspecialchars($this->data['username'], ENT_QUOTES) ?>"/>
                                <?php
                            } else {
                                ?>
                                <label for="username"></label>
                                <input type="text" id="username" tabindex="1" name="username"
                                       style="width:322px; margin:25px 15px 15px"
                                       value="<?php echo htmlspecialchars($this->data['username'], ENT_QUOTES) ?>"
                                       placeholder="<?php echo htmlspecialchars($this->t('{login:username}'), ENT_QUOTES) ?>"
                                />
                                <br>
                                <?php
                            }

                            // Remember username in authproc
                            if (!$this->data['authProcFilterScenario']) {
                                if ($this->data['rememberUsernameEnabled'] || $this->data['rememberMeEnabled']) {
                                    $rowspan = 1;
                                } elseif (array_key_exists('organizations', $this->data)) {
                                    $rowspan = 3;
                                } else {
                                    $rowspan = 2;
                                }
                                if ($this->data['rememberUsernameEnabled'] || $this->data['rememberMeEnabled']) {
                                    if ($this->data['rememberUsernameEnabled']) {
                                        echo str_repeat("\t", 4);
                                        echo '<input type="checkbox" id="rememberUsername" tabindex="4" name="rememberUsername"
                                         value="Yes" ';
                                        echo $this->data['rememberUsernameChecked'] ? 'checked="Yes" /> ' : '/> ';
                                        echo htmlspecialchars($this->t('{login:remember_username}'));
                                    }
                                    if ($this->data['rememberMeEnabled']) {
                                        echo str_repeat("\t", 4);
                                        echo '<input type="checkbox" id="rememberMe" tabindex="4" name="rememberMe" value="Yes" ';
                                        echo $this->data['rememberMeChecked'] ? 'checked="Yes" /> ' : '/> ';
                                        echo htmlspecialchars($this->t('{login:remember_me}'));
                                    }
                                }
                            } ?>

                            <!-- Pass and OTP fields -->
                            <label for="password"></label>
                            <input id="password" name="password" tabindex="1" type="password" value="" class="text"
                                   placeholder="<?php echo htmlspecialchars($passHint, ENT_QUOTES) ?>"
                                   style="width:322px; margin:15px"/>

                            <label for="otp" class="block"><strong
                                        id="message"><?php echo $this->data['message'] ?></strong></label>
                            <br>
                            <input id="otp" name="otp" tabindex="1" type="password" value="" class="text"
                                   placeholder="<?php echo htmlspecialchars($otpHint, ENT_QUOTES) ?>"
                                   style="width:322px; margin: 25px 15px 7px"/>
                            <br>
                            <input id="submitButton" tabindex="1" class="rc-button rc-button-submit" type="submit"
                                   name="Submit" style="width:210px; margin:0 15px 7px"
                                   value="<?php echo htmlspecialchars($this->t('{login:login_button}'), ENT_QUOTES) ?>"/>

                            <!-- Hidden input which store the info about changes for future use in backend-->
                            <input id="mode" type="hidden" name="mode" value="<?php echo $this->data['mode'] ?>"/>
                            <input id="pushAvailable" type="hidden" name="pushAvailable"
                                   value="<?php echo $this->data['pushAvailable'] ?>"/>
                            <input id="otpAvailable" type="hidden" name="otpAvailable"
                                   value="<?php echo $this->data['otpAvailable'] ?>"/>
                            <input id="webAuthnSignRequest" type="hidden" name="webAuthnSignRequest"
                                   value='<?php echo $this->data['webAuthnSignRequest'] ?>'/>
                            <input id="u2fSignRequest" type="hidden" name="u2fSignRequest"
                                   value='<?php echo $this->data['u2fSignRequest'] ?>'/>
                            <input id="modeChanged" type="hidden" name="modeChanged" value="0"/>
                            <input id="step" type="hidden" name="step"
                                   value="<?php echo $this->data['step'] ?>"/>
                            <input id="webAuthnSignResponse" type="hidden" name="webAuthnSignResponse" value=""/>
                            <input id="u2fSignResponse" type="hidden" name="u2fSignResponse" value=""/>
                            <input id="origin" type="hidden" name="origin" value=""/>
                            <input id="loadCounter" type="hidden" name="loadCounter"
                                   value="<?php echo $this->data['loadCounter'] ?>"/>

                            <!-- Additional input to persist the message -->
                            <input id="message" type="hidden" name="message"
                                   value="<?php echo $this->data['message'] ?>"/>

                            <script>
                                // Helper functions
                                function value(id) {
                                    const element = document.getElementById(id);
                                    if (element != null) {
                                        return element.value;
                                    } else {
                                        console.log(id + " is null!");
                                    }
                                    return "";
                                }

                                function set(id, value) {
                                    const element = document.getElementById(id);
                                    if (element != null) {
                                        element.value = value;
                                    } else {
                                        console.log(id + " is null!");
                                    }
                                }

                                function disable(id) {
                                    const element = document.getElementById(id);
                                    if (element != null) {
                                        element.style.display = "none";
                                    } else {
                                        console.log(id + " is null!");
                                    }
                                }

                                function enable(id) {
                                    const element = document.getElementById(id);
                                    if (element != null) {
                                        element.style.display = "initial";
                                    } else {
                                        console.log(id + " is null!");
                                    }
                                }

                                function changeMode(newMode) {
                                    document.getElementById("mode").value = newMode;
                                    document.getElementById("modeChanged").value = "1";
                                    document.forms["piLoginForm"].submit();
                                }
                            </script>

                            <?php
                            // If enrollToken load QR Code
                            if (isset($this->data['tokenQR'])) {
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
                        if (array_key_exists('organizations', $this->data)) {
                            ?>
                            <div class="identifier-shown">
                                <?php echo htmlspecialchars($this->t('{login:organization}')); ?>
                                <label>
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
                                        } ?>
                                    </select>
                                </label>
                            </div>
                        <?php } ?>
                    </div> <!-- focused -->
                </div> <!-- slide-out-->
            </div> <!-- form-panel -->

            <div id="AlternateLoginOptions" style="margin-top:35px" class="groupMargin">
                <label><strong>Alternate login options:</strong></label>
                <br>
                <!-- Alternate Login Options-->
                <input id="useWebAuthnButton" name="useWebAuthnButton" type="button" value="WebAuthn"
                       onclick="doWebAuthn()" style="width:140px; margin:15px 10px 7px"/>
                <input id="usePushButton" name="usePushButton" type="button" value="Push"
                       onclick="changeMode('push')" style="width:140px; margin:15px 10px 7px"/>
                <input id="useOTPButton" name="useOTPButton" style="width:140px; margin:15px 15px 7px" type="button"
                       value="OTP" onclick="changeMode('otp')"/>
                <input id="useU2FButton" name="useU2FButton" type="button" value="U2F" onclick="doU2F()"
                       style="width:140px; margin:15px 10px 7px"/>
            </div>
        </form>

        <?php
        // Logout
        if (isset($this->data['LogoutURL'])) { ?>
            <p>
                <a href="<?php echo htmlspecialchars($this->data['LogoutURL']); ?>"><?php echo $this->t('{status:logout}'); ?></a>
            </p>
        <?php } ?>
    </div>  <!-- End of login -->
</div>  <!-- End of container -->

<?php
if (!empty($this->data['links'])) {
    echo '<ul class="links" style="margin-top: 2em">';
    foreach ($this->data['links'] as $l) {
        echo '<li><a href="' . htmlspecialchars($l['href'], ENT_QUOTES) . '">' . htmlspecialchars($this->t($l['text'])) . '</a></li>';
    }
    echo '</ul>';
}

$this->includeAtTemplateBase('includes/footer.php');
?>

<script src="<?php echo htmlspecialchars(SimpleSAML_Module::getModuleUrl('privacyidea/js/webauthn.js'), ENT_QUOTES) ?>">
</script>

<script src="<?php echo htmlspecialchars(SimpleSAML_Module::getModuleUrl('privacyidea/js/u2f-api.js'), ENT_QUOTES) ?>">
</script>

<!--We need to open a new script tag up here-->
<script>
    const step = '<?php echo $this->data['step'] ?>';

    if (step > "1") {
        disable("username");
        disable("password");
    } else {
        disable("otp");
        disable("message");
        disable("AlternateLoginOptions");
    }

    // Set alternate token button visibility
    if (value("webAuthnSignRequest") === "") {
        disable("useWebAuthnButton");
    }

    if (value("u2fSignRequest") === "") {
        disable("useU2FButton");
    }

    if (value("pushAvailable") !== "1") {
        disable("usePushButton");
    }

    if (value("otpAvailable") !== "1") {
        disable("useOTPButton");
    }

    if (value("pushAvailable") === "0" && value("webAuthnSignRequest") === "" && value("u2fSignRequest") === "") {
        disable("alternateTokenDiv");
    }

    if (value("mode") === "otp") {
        disable("useOTPButton");
    }

    if (value("mode") === "webauthn") {
        doWebAuthn();
    }

    if (value("mode") === "u2f") {
        doU2F();
    }

    if (value("mode") === "push") {
        const pollingIntervals = [4, 3, 2, 1];

        disable("otp");
        disable("usePushButton");
        disable("submitButton");

        if (value("loadCounter") > (pollingIntervals.length - 1)) {
            refreshTime = pollingIntervals[(pollingIntervals.length - 1)];
        } else {
            refreshTime = pollingIntervals[Number(value("loadCounter") - 1)];
        }

        refreshTime *= 1000;
        setTimeout(() => {
            document.forms["piLoginForm"].submit();
        }, refreshTime);
    }

    function doWebAuthn() {
        // If mode is push, we have to change it, otherwise the site will refresh while doing webauthn
        if (value("mode") === "push") {
            changeMode("webauthn");
        }

        if (!window.isSecureContext) {
            alert("Unable to proceed with Web Authn because the context is insecure!");
            console.log("Insecure context detected: Aborting Web Authn authentication!")
            changeMode("otp");
            return;
        }

        if (!window.pi_webauthn) {
            alert("Could not load WebAuthn library. Please try again or use other token.");
            changeMode("otp");
            return;
        }

        const requestStr = value("webAuthnSignRequest");

        // Set origin
        if (!window.location.origin) {
            window.location.origin = window.location.protocol + "//" + window.location.hostname + (window.location.port ? ':' + window.location.port : '');
        }
        set("origin", window.origin);

        try {
            const requestjson = JSON.parse(requestStr);

            const webAuthnSignResponse = window.pi_webauthn.sign(requestjson);
            webAuthnSignResponse.then((webauthnresponse) => {
                const response = JSON.stringify(webauthnresponse);
                set("webAuthnSignResponse", response);
                set("mode", "webauthn");
                document.forms["piLoginForm"].submit();
            });

        } catch (err) {
            console.log("Error while signing WebAuthnSignRequest: " + err);
            alert("Error while signing WebAuthnSignRequest: " + err);
        }
    }

    function doU2F() {
        // If mode is push, we have to change it, otherwise the site will refresh while doing webauthn
        if (value("mode") === "push") {
            changeMode("u2f");
        }

        if (!window.isSecureContext) {
            alert("Unable to proceed with U2F because the context is insecure!");
            console.log("Insecure context detected: Aborting U2F authentication!")
            changeMode("otp");
            return;
        }

        const requestStr = value("u2fSignRequest");

        if (requestStr === null) {
            alert("Could not load U2F library. Please try again or use other token.");
            changeMode("otp");
            return;
        }

        try {
            const requestjson = JSON.parse(requestStr);
            sign_u2f_request(requestjson);
        } catch (err) {
            console.log("Error while signing U2FSignRequest: " + err);
            alert("Error while signing U2FSignRequest: " + err);
        }
    }

    function sign_u2f_request(signRequest) {

        let appId = signRequest["appId"];
        let challenge = signRequest["challenge"];
        let registeredKeys = [];

        registeredKeys.push({
            version: "U2F_V2",
            keyHandle: signRequest["keyHandle"]
        });

        u2f.sign(appId, challenge, registeredKeys, function (result) {
            const stringResult = JSON.stringify(result);
            if(stringResult.includes("clientData") && stringResult.includes("signatureData")) {
                set("u2fSignResponse", stringResult);
                set("mode", "u2f");
                document.forms["piLoginForm"].submit();
            }
        })

    }
</script>
