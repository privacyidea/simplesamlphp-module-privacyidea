function autoSubmitByLength()
{
    if (piGetValue("otpLength") !== "")
    {
        if (piGetValue("otp").length === parseInt(piGetValue("otpLength")))
        {
            piSubmit();
        }
    }
}

document.addEventListener("DOMContentLoaded", (event) =>
{
    document.getElementById("otp").addEventListener("keyup", autoSubmitByLength);

    document.getElementById("useWebAuthnButton").addEventListener("click", doWebAuthn);
    document.getElementById("usePushButton").addEventListener("click", function ()
    {
        piChangeMode("push");
    });
    document.getElementById("useOTPButton").addEventListener("click", function ()
    {
        piChangeMode("otp");
    });
});