function t(key)
{
    return JSON.parse(document.getElementById("privacyidea-translations").content)[key];
}

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
        console.log("Insecure context detected: Aborting Web Authn authentication!")
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
 * Sign the U2F request
 * @param signRequest
 */
function signU2FRequest(signRequest)
{

    let appId = signRequest["appId"];
    let challenge = signRequest["challenge"];
    let registeredKeys = [];

    registeredKeys.push({
        version: "U2F_V2",
        keyHandle: signRequest["keyHandle"]
    });

    u2f.sign(appId, challenge, registeredKeys, function (result)
    {
        const stringResult = JSON.stringify(result);
        if (stringResult.includes("clientData") && stringResult.includes("signatureData"))
        {
            piSetValue("u2fSignResponse", stringResult);
            piSetValue("mode", "u2f");
            piSubmit();
        }
    })
}

/**
 * Process the U2F authentication
 */
function doU2F()
{
    // If mode is push, we have to change it, otherwise the site will refresh while doing webauthn
    if (piGetValue("mode") === "push")
    {
        piChangeMode("u2f");
    }

    if (!window.isSecureContext)
    {
        alert(piGetValue("alertU2FInsecureContext"));
        console.log("Insecure context detected: Aborting U2F authentication!")
        piChangeMode("otp");
        return;
    }

    const requestStr = piGetValue("u2fSignRequest");

    if (requestStr === null)
    {
        alert(piGetValue("alertU2FUnavailable"));
        piChangeMode("otp");
        return;
    }

    try
    {
        const requestjson = JSON.parse(requestStr);
        signU2FRequest(requestjson);
    }
    catch (err)
    {
        alert(piGetValue("alertU2FSignRequestError") + " " + err);
        console.log("Error while signing U2FSignRequest: " + err);
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

    // Set alternate token button visibility
    if (piGetValue("webAuthnSignRequest") === "")
    {
        piDisableElement("useWebAuthnButton");
    }

    if (piGetValue("u2fSignRequest") === "")
    {
        piDisableElement("useU2FButton");
    }

    if (piGetValue("pushAvailable") !== "1")
    {
        piDisableElement("usePushButton");
    }

    if (piGetValue("otpAvailable") !== "1")
    {
        piDisableElement("useOTPButton");
    }

    if (!piGetValue("pushAvailable") && piGetValue("webAuthnSignRequest") === "" && piGetValue("u2fSignRequest") === "")
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

    if (piGetValue("mode") === "u2f")
    {
        piDisableElement("otp");
        piDisableElement("submitButton");
        doU2F();
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
    if (!piGetValue("pushAvailable") && piGetValue("webAuthnSignRequest") === "" && piGetValue("u2fSignRequest") === "")
    {
        piDisableElement("AlternateLoginOptions");
    }
}

// Wait until the document is ready
document.addEventListener("DOMContentLoaded", function ()
{
    piMain();
});