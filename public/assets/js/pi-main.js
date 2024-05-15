/**
 * Process the WebAuthn authentication
 */
function doWebAuthn()
{
    // If mode is push, we have to change it, otherwise the site will refresh while doing webauthn
    if (piGetValue("mode") === "push")
    {
        piChangeMode("webauthn");
    }

    if (!window.isSecureContext)
    {
        alert(piGetValue("alertWebauthnInsecureContext"));
        console.log("Insecure context detected: Aborting WebAuthn authentication!")
        piChangeMode("otp");
        return;
    }

    if (!window.pi_webauthn)
    {
        alert(piGetValue("alertWebauthnUnavailable"));
        piChangeMode("otp");
        return;
    }

    const requestStr = piGetValue("webAuthnSignRequest");

    // Set origin
    if (!window.location.origin)
    {
        window.location.origin = window.location.protocol + "//" + window.location.hostname + (window.location.port ? ':' + window.location.port : '');
    }
    piSetValue("origin", window.origin);

    try
    {
        const requestjson = JSON.parse(requestStr);
        const webAuthnSignResponse = window.pi_webauthn.sign(requestjson);

        webAuthnSignResponse.then((webauthnresponse) =>
        {
            const response = JSON.stringify(webauthnresponse);
            piSetValue("webAuthnSignResponse", response);
            piSetValue("mode", "webauthn");
            piSubmit()
        });

    }
    catch (err)
    {
        alert(piGetValue("alertWebAuthnSignRequestError") + " " + err);
        console.log("Error while signing WebAuthnSignRequest: " + err);
    }
}

/**
 * Main function to handle the different states of the authentication process
 */
function piMain()
{
    // Handle step
    if (piGetValue("step") > "1")
    {
        piDisableElement("username");
        piDisableElement("password");
    }
    else
    {
        piDisableElement("otp");
        piDisableElement("message");
        piDisableElement("AlternateLoginOptions");
    }

    // Add separate OTP field if needed
    if (piGetValue("authenticationFlow") === "separateOTP")
    {
        piEnableElement("otp");
    }

    // Hide pass field if redundant
    if (piGetValue("authenticationFlow") === "triggerChallenge")
    {
        piDisableElement("password");
    }

    if (!piGetValue("pushAvailable") && piGetValue("webAuthnSignRequest") === "")
    {
        piDisableElement("AlternateLoginOptions");
    }

    // Set alternate token button visibility
    if (piGetValue("webAuthnSignRequest") === "")
    {
        piDisableElement("useWebAuthnButton");
    }

    if (piGetValue("pushAvailable") !== "1")
    {
        piDisableElement("usePushButton");
    }

    if (piGetValue("otpAvailable") !== "1")
    {
        piDisableElement("useOTPButton");
    }

    if (!piGetValue("pushAvailable") && piGetValue("webAuthnSignRequest") === "")
    {
        piDisableElement("AlternateLoginOptions");
    }

    if (piGetValue("mode") === "otp")
    {
        piDisableElement("useOTPButton");
    }

    if (piGetValue("mode") === "webauthn")
    {
        piDisableElement("otp");
        piDisableElement("submitButton");
        doWebAuthn();
    }

    if (piGetValue("mode") === "push")
    {
        let refreshTime;
        const pollingIntervals = [4, 3, 2, 1];

        piDisableElement("otp");
        piDisableElement("usePushButton");
        piDisableElement("submitButton");

        if (piGetValue("loadCounter") > (pollingIntervals.length - 1))
        {
            refreshTime = pollingIntervals[(pollingIntervals.length - 1)];
        }
        else
        {
            refreshTime = pollingIntervals[Number(piGetValue("loadCounter") - 1)];
        }

        refreshTime *= 1000;
        setTimeout(() =>
        {
            piSubmit();
        }, refreshTime);
    }
}

// Wait until the document is ready
document.addEventListener("DOMContentLoaded", function ()
{
    piMain();
});