document.addEventListener("DOMContentLoaded", (event) =>
{
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