// Helper functions
function value(id)
{
    const element = document.getElementById(id);
    if (element != null)
    {
        return element.value;
    } else
    {
        console.log(id + " is null!");
    }
    return "";
}

function set(id, value)
{
    const element = document.getElementById(id);
    if (element != null)
    {
        element.value = value;
    } else
    {
        console.log(id + " is null!");
    }
}

function disable(id)
{
    const element = document.getElementById(id);
    if (element != null)
    {
        element.classList.add("hidden");
    } else
    {
        console.log(id + " is null!");
    }
}

function enable(id)
{
    const element = document.getElementById(id);
    if (element != null)
    {
        element.classList.remove("hidden");
    } else
    {
        console.log(id + " is null!");
    }
}

function changeMode(newMode)
{
    document.getElementById("mode").value = newMode;
    document.getElementById("modeChanged").value = "1";
    document.forms["piLoginForm"].submit();
}

function t(key) {
    return JSON.parse(document.getElementById("privacyidea-translations").content)[key];
}

// Handle step
const step = document.getElementById("privacyidea-step").content;

if (step > "1")
{
    disable("username");
    disable("password");
} else
{
    disable("otp");
    disable("message");
    disable("AlternateLoginOptions");
}

// Handle separate OTP field
if (document.getElementById("privacyidea-separate-otp").content === "true")
{
    enable("otp");
}

// Hide pass field if redundant
if (document.getElementById("privacyidea-hide-pass-field").content === "true")
{
    disable("password");
}

// Set alternate token button visibility
if (value("webAuthnSignRequest") === "")
{
    disable("useWebAuthnButton");
}

if (value("u2fSignRequest") === "")
{
    disable("useU2FButton");
}

if (value("pushAvailable") !== "1")
{
    disable("usePushButton");
}

if (value("otpAvailable") !== "1")
{
    disable("useOTPButton");
}

if (value("pushAvailable") === "0" && value("webAuthnSignRequest") === "" && value("u2fSignRequest") === "")
{
    disable("AlternateLoginOptions");
}

if (value("mode") === "otp")
{
    disable("useOTPButton");
}

if (value("mode") === "webauthn")
{
    disable("otp");
    disable("submitButton");
    doWebAuthn();
}

if (value("mode") === "u2f")
{
    disable("otp");
    disable("submitButton");
    doU2F();
}

if (value("mode") === "push")
{
    const pollingIntervals = [4, 3, 2, 1];

    disable("otp");
    disable("usePushButton");
    disable("submitButton");

    if (value("loadCounter") > (pollingIntervals.length - 1))
    {
        refreshTime = pollingIntervals[(pollingIntervals.length - 1)];
    } else
    {
        refreshTime = pollingIntervals[Number(value("loadCounter") - 1)];
    }

    refreshTime *= 1000;
    setTimeout(() =>
    {
        document.forms["piLoginForm"].submit();
    }, refreshTime);
}

function doWebAuthn()
{
    // If mode is push, we have to change it, otherwise the site will refresh while doing webauthn
    if (value("mode") === "push")
    {
        changeMode("webauthn");
    }

    if (!window.isSecureContext)
    {
        alert(t("alert_webauthn_insecure_context"));
        console.log("Insecure context detected: Aborting Web Authn authentication!")
        changeMode("otp");
        return;
    }

    if (!window.pi_webauthn)
    {
        alert(t("alert_webauthn_unavailable"));
        changeMode("otp");
        return;
    }

    const requestStr = value("webAuthnSignRequest");

    // Set origin
    if (!window.location.origin)
    {
        window.location.origin = window.location.protocol + "//" + window.location.hostname + (window.location.port ? ':' + window.location.port : '');
    }
    set("origin", window.origin);

    try
    {
        const requestjson = JSON.parse(requestStr);
        const webAuthnSignResponse = window.pi_webauthn.sign(requestjson);

        webAuthnSignResponse.then((webauthnresponse) =>
        {
            const response = JSON.stringify(webauthnresponse);
            set("webAuthnSignResponse", response);
            set("mode", "webauthn");
            document.forms["piLoginForm"].submit();
        });

    } catch (err)
    {
        console.log("Error while signing WebAuthnSignRequest: " + err);
        alert(t("alert_webAuthnSignRequest_error") + " " + err);
    }
}

function doU2F()
{
    // If mode is push, we have to change it, otherwise the site will refresh while doing webauthn
    if (value("mode") === "push")
    {
        changeMode("u2f");
    }

    if (!window.isSecureContext)
    {
        alert(t("alert_u2f_insecure_context"));
        console.log("Insecure context detected: Aborting U2F authentication!")
        changeMode("otp");
        return;
    }

    const requestStr = value("u2fSignRequest");

    if (requestStr === null)
    {
        alert(t("alert_u2f_unavailable"));
        changeMode("otp");
        return;
    }

    try
    {
        const requestjson = JSON.parse(requestStr);
        sign_u2f_request(requestjson);
    } catch (err)
    {
        console.log("Error while signing U2FSignRequest: " + err);
        alert(t("alert_U2FSignRequest_error") + " " + err);
    }
}

function sign_u2f_request(signRequest)
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
            set("u2fSignResponse", stringResult);
            set("mode", "u2f");
            document.forms["piLoginForm"].submit();
        }
    })
}

if (document.getElementById("privacyidea-hide-alternate").content === "true") {
    disable("AlternateLoginOptions");
}

document.addEventListener("DOMContentLoaded", (event) => {
    document.getElementById("useWebAuthnButton").addEventListener("click", doWebAuthn);
    document.getElementById("usePushButton").addEventListener("click", function(){changeMode("push");});
    document.getElementById("useOTPButton").addEventListener("click", function(){changeMode("otp");});
    document.getElementById("useU2FButton").addEventListener("click", doU2F);
});
