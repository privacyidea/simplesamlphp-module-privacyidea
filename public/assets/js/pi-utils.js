window.piGetValue = function getValue(id)
{
    const element = document.getElementById(id);
    if (element === null)
    {
        console.log(id + " is null!");
        return "";
    }
    else
    {
        return element.value;
    }
}

window.piSetValue = function setValue(id, value)
{
    const element = document.getElementById(id);
    if (element !== null)
    {
        element.value = value;
    }
    else
    {
        console.log(id + " is null!");
    }
}

window.piDisableElement = function disableElement(id)
{
    const element = document.getElementById(id);
    if (element !== null)
    {
        element.style.display = "none";
    }
}

window.piEnableElement = function enableElement(id)
{
    const element = document.getElementById(id);
    if (element !== null)
    {
        element.style.display = "initial";
    }
    else
    {
        console.log(id + " is null!");
    }
}

window.piChangeMode = function changeMode(newMode)
{
    piSetValue("mode", newMode);
    piSetValue("modeChanged", "1");
    piSubmit();
}

window.piSubmit = function submitForm()
{
    document.forms["piLoginForm"].submit();
}