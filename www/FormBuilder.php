<?php

use SimpleSAML\Auth\Source;
use SimpleSAML\Auth\State;
use SimpleSAML\Configuration;
use SimpleSAML\Error\NoState;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Session;
use SimpleSAML\XHTML\Template;

Logger::debug("Loading privacyIDEA form...");
// Load $state from the earlier position
$stateId = $_REQUEST['stateId'];
try
{
    $state = State::loadState($stateId, 'privacyidea:privacyidea', true);
}
catch (NoState $e)
{
    Logger::error("Unable to load state information because stateId is lost");
    throw $e;
}
catch (Exception $e)
{
    Logger::error("Unable to load state information. " . $e->getMessage());
    throw $e;
}

// Find the username
if (isset($state['privacyidea:privacyidea']['uidKey']))
{
    $uidKey = $state['privacyidea:privacyidea']['uidKey'];
    $username = $state['Attributes'][$uidKey][0];
}
elseif (isset($state['privacyidea:privacyidea']['username']))
{
    $username = $state['privacyidea:privacyidea']['username'];
}
elseif (isset($state['core:username']))
{
    $username = (string)$state['core:username'];
}
else
{
    $username = '';
}

// Prepare the form to show
try
{
    $tpl = new Template(Configuration::getInstance(), 'privacyidea:LoginForm.php');
}
catch (Exception $e)
{
    Logger::error("Unable to prepare the login form. " . $e->getMessage());
    throw $e;
}

// Prepare error to show in UI
$tpl->data['errorCode'] = null;
$tpl->data['errorMessage'] = null;

if (!empty($state['privacyidea:privacyidea']['errorCode']) || !empty($state['privacyidea:privacyidea']['errorMessage']))
{
    if (!empty($state['privacyidea:privacyidea']['errorCode']))
    {
        $tpl->data['errorCode'] = $state['privacyidea:privacyidea']['errorCode'];
        $state['privacyidea:privacyidea']['errorCode'] = "";
    }
    else
    {
        $tpl->data['errorCode'] = "";
    }
    $tpl->data['errorMessage'] = $state['privacyidea:privacyidea']['errorMessage'];
    $state['privacyidea:privacyidea']['errorMessage'] = "";
    $stateId = State::saveState($state, 'privacyidea:privacyidea');
}

// AuthProc
if ($state['privacyidea:privacyidea']['authenticationMethod'] === "authprocess")
{
    $tpl->data['authProcFilterScenario'] = true;
    $tpl->data['rememberUsernameEnabled'] = true;
    $tpl->data['rememberUsernameChecked'] = true;
    $tpl->data['forceUsername'] = true;
    $tpl->data['username'] = $username;
}
elseif ($state['privacyidea:privacyidea']['authenticationMethod'] === "authsource")
{
    // AuthSource
    try
    {
        $source = Source::getById($state["privacyidea:privacyidea"]["AuthId"]);

        $tpl->data['username'] = $username;

        assert(method_exists($source, "isRememberMeEnabled"));
        $tpl->data['rememberMeEnabled'] = $source->isRememberMeEnabled();

        assert(method_exists($source, "isRememberMeChecked"));
        $tpl->data['rememberMeChecked'] = $source->isRememberMeChecked();

        if (method_exists($source, "getLoginLinks"))
        {
            $tpl->data['links'] = $source->getLoginLinks();
        }
        if (array_key_exists('forcedUsername', $state))
        {
            $tpl->data['forceUsername'] = true;
            $tpl->data['rememberUsernameEnabled'] = false;
            $tpl->data['rememberUsernameChecked'] = false;
        }
        else
        {
            $tpl->data['forceUsername'] = false;

            assert(method_exists($source, "getRememberUsernameEnabled"));
            $tpl->data['rememberUsernameEnabled'] = $source->getRememberUsernameEnabled();

            assert(method_exists($source, "getRememberUsernameChecked"));
            $tpl->data['rememberUsernameChecked'] = $source->getRememberUsernameChecked();
        }
        if (!empty($state['SPMetadata']))
        {
            $tpl->data['SPMetadata'] = $state['SPMetadata'];
        }
    }
    catch (\SimpleSAML\Error\Exception $e)
    {
        Logger::error("Could not find authentication source with ID: " . $state["privacyidea:privacyidea"]["AuthId"] . $e->getMessage());
    }
}

// Get all the ui data placed in state and set it to $tpl->data for future use in LoginForm.php
if (!empty($state['privacyidea:privacyidea:ui']))
{
    foreach ($state['privacyidea:privacyidea:ui'] as $key => $value)
    {
        $tpl->data[$key] = $value;
    }
}

// Make sure every required key exists, even with just default values
if (!array_key_exists('head', $tpl->data))
{
    $tpl->data['head'] = "";
}

if (empty($_REQUEST['loadCounter']))
{
    $tpl->data['loadCounter'] = 1;
}

if ($state['privacyidea:privacyidea']['authenticationMethod'] === "authprocess")
{
    $tpl->data['LogoutURL'] = Module::getModuleURL('core/authenticate.php', array('as' => $state['Source']['auth'])) . "&logout";
}

try
{
    Session::getSessionFromRequest()->setData("privacyidea:privacyidea", "stateId", $stateId);
}
catch (Exception $e)
{
    Logger::error("No access to request session. " . $e->getMessage());
}
$tpl->show();
