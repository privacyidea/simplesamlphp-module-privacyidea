privacyIDEA module
==================

This module is an authentication module for simpleSAMLphp to use with the privacyIDEA authentication server.

You can use this plugin in two different ways:
<ol>
    <li> AuthSource: This module does the complete authentication process against privacyIDEA.
    <li> AuthProc: This module does just one step of the authentication, the second factor against privacyIDEA.
</ol>

NOTE: This plugin is enabled by default when installed, you do not need to enable it manually. Just add the
configuration to the corresponding file as explained in the following:

AuthSource
==========

Add the configuration to `config/authsources.php`.

In an absolute basic configuration, the following config options will be required to set:
`privacyideaServerURL`, `authenticationFlow`(set to default), `attributemap`.

NOTE: `example-privacyidea` is the name used to identify this module, it can be changed at your discretion.

The following is a template configuration:

```PHP
'example-privacyidea' => array(
    'privacyidea:PrivacyideaAuthSource',

    /**
     * The URL of the privacyidea server.
     * Required.
     */
    'privacyideaServerURL' => 'https://your.server.com',

    /**
     * Disable SSL verification.
     * Values should be 'true' or 'false'. Default is 'true'.
     * 
     * NOTE: This should always be enabled in a productive environment!
     * 
     * Optional.
     */
    'sslVerifyHost' => 'true',
    'sslVerifyPeer' => 'true',
        
    /**
     * Set the privacyidea realm.
     * Optional.
     */
    'realm' => '',
    
    /**
     * Specify the username and password of your service account from privacyIDEA server.
     * Required by the 'triggerChallenge' authentication flow.
     */
    'serviceAccount' => '',
    'servicePass' => '',
    
    /**
     * Specify the realm for your service account.
     * Optional (by the 'triggerChallenge' authentication flow).
     */
    'serviceRealm' => '',
    
    /**
     * Choose one of the following authentication flows:
     * 
     * 'sendPassword' - (default) Login interface will contain the username input and a single password/OTP input.
     * 
     * 'triggerChallenge' - Login interface will contain only the username input. This mode triggers
     * challenges prior to the login using the configured service account (required).
     * 
     * 'separateOTP' - Login interface will contain 3 inputs for username, password and OTP.
     *
     * Required.
     */
    'authenticationFlow' => 'sendPassword',
    
    /**
     * Set custom hints for the OTP and password fields.
     */
    'otpFieldHint' => 'OTP',
    'passFieldHint' => 'Password',
    
    /**
     * Set SSO to 'true' if you want to use single sign on.
     * All information required for SSO will be saved in the session.
     * After logging out, the SSO data will be removed from the session.
     * The value has to be 'true' or 'false', default is 'false'.
     * 
     * Optional.
     */
    'SSO' => 'false',
    
    /**
     * If you want to turn on the form-auto-submit function after x number of characters are entered into the OTP input
     * field, set this option to expected OTP length here.
     * Note: Only digits as the parameter's value are allowed here.
     *
     * Optional.
     */
    'autoSubmitOtpLength' => '',
    
    /**
     * If 'pollInBrowser' option should use a deviating URL, set it here. Otherwise, the general URL will be used.
     * Required only by 'pollInBrowser'.
     */
     //'pollInBrowserUrl' => 'https://your.privacyidea.server',
    
    /**
     * Enable this to do the polling for accepted push requests in the user's browser.
     * When enabled, the login page does not refresh to confirm the push authentication.
     * CORS settings for privacyidea can be adjusted in etc/apache2/sites-available/privacyidea.conf.
     * 
     * Note: You'll also need to set the connect-src header in your CSP policy to allow connecting to the privacyIDEA
     * server. This can be done in server or in the simplesamlphp configuration:
     * /var/simplesamlphp/config/conf.php -> SECURITY CONFIGURATION OPTIONS -> -> headers.security ->
     * -> Content-Security-Policy -> add: "connect-src 'self' https://your.privacyidea.server"
     * 
     * Optional.
     */
     'pollInBrowser' => 'false',

    /**
     * Configure which headers should be forwarded to the privacyIDEA server.
     * Multiple headers should be separated by a comma (see example).
     * 
     * Optional.
     */
    'forwardHeaders' => 'header1,header2,header3',

    /**
     * Translation from privacyIDEA attribute names to the SAML attribute names.
     * Required.
     */
    'attributemap' => array(
        'username' => 'samlLoginName',
        'surname' => 'surName',
        'givenname' => 'givenName',
        'email' => 'emailAddress',
        'phone' => 'telePhone',
        'mobile' => 'mobilePhone'
    ),
    
    /**
     * To concatenate or edit the attributes mentioned above, you can use next 2 options.
     * If they should not be used, feel free to remove them.
     */

    /**
     * You are able to concatenate attributes like the given and surname.
     * Optional.
     */
    'concatenationmap' => array(
        'givenname,surname' => 'fullName'
    ),

    /**
     * Here the detail attributes can be edited.
     * Optional.
     */
    'detailmap' => array(
        'message' => 'message',
        'type' => 'otpType',
        'serial' => 'otpSerial',
        'otplen' => 'otpLength'
    ),
),
```

User Attributes
---------------
To complete the authentication with SAML in AuthSource mode, SAML expects user attributes to be returned.
These attributes will be received from privacyIDEA upon completing the authentication.
However, this has to be enabled by creating a policy in privacyIDEA with the following values:
Scope: authorization,
Actions from section "setting_actions": "add_resolver_in_response", "add_user_in_response".

The attributes can then be mapped to SAML attributes using the "attributemap" setting described in the config template above.
Examples for those attributes are:

- username: The login name
- surname: The real world name of the user as it is retrieved from the user source
- givenname: The real world name of the user as it is retrieved from the user source
- mobile: The mobile phone number of the user as it is retrieved from the user source
- phone: The phone number of the user as it is retrieved from the user source
- email: The email address of the user as it is retrieved from the user source

The list can be extended by including custom attributes in the attributemap. If the privacyIDEA server returns an
attribute 'groups', you can map that to 'groups' if you include it in the attributemap. Otherwise, it is discarded.


AuthProc
========

If you want to use privacyIDEA as an auth process filter, add the configuration to the metadata file,
e.g. `simplesaml/metadata/saml20-idp-hosted.php`.

In an absolute basic configuration, the following config options will be required to set:
`class`, `privacyideaServerURL`, `authenticationFlow`(set to default), `uidKey`.

The following is a template configuration:

```PHP
'authproc' => array(

    /**
     * Configuration for the privacyIDEA.
     */
    20 => array(
        'class'             => 'privacyidea:PrivacyideaAuthProc',

        /**
         * The URL of the privacyidea server.
         * Required.
         */
        'privacyideaServerURL' => 'https://your.privacyidea.server',
        
        /**
         * Set the privacyidea realm.
         * Optional.
         */
        'realm' => '',

        /**
         * The uidKey is the username's attribute key.
         * You can choose a single one or multiple ones. The first set will be used.
         * Example: 'uidKey' => array('uid', 'userName', 'uName').
         * 
         * Required.
         */
        'uidKey' => 'uid',

        /**
         * Disable SSL verification.
         * Values should be 'true' or 'false'. Default is 'true'.
         * NOTE: This should always be enabled in a productive environment!
         * 
         * Optional.
         */
        'sslVerifyHost' => 'true',
        'sslVerifyPeer' => 'true',
               
        /**
         * Specify the static password for the 'sendStaticPass' authentication flow.
         * Required by the 'sendStaticPass' authentication flow.
         */
        'staticPass' => '',
        
        /**
         * Specify the username and password of your service account from privacyIDEA server.
         * Required by the 'triggerChallenge' authentication flow.
         */
        'serviceAccount' => '',
        'servicePass' => '',
        
        /**
         * Choose one of the following authentication flows:
         * 
         * 'default' - Default authentication flow.
         * 
         * 'sendStaticPass' - If you want to use the passOnNoToken or passOnNoUser policy in privacyidea,
         * you can use this flow, and specify a static pass which will be sent before the actual
         * authentication to trigger the policies in privacyidea.
         * NOTE: This 'sendStaticPass'.
         * NOTE: This won't be processed if the user has a challenge-response token that were triggered before.
         * 
         * 'triggerChallenge' - Before the login interface is shown, the filter will attempt to trigger challenge-response
         * token with the specified serviceAccount.
         * 
         * Required.
         */
        'authenticationFlow' => 'default',
        
        /**
         * Set the realm for your service account.
         * Optional (by the 'triggerChallenge' authentication flow).
         */
        'serviceRealm' => '',
        
        /**
         * Set this to 'true' if you want to use single sign on.
         * All information required for SSO will be saved in the session.
         * After logging out, the SSO data will be removed from the session.
         * 
         * Optional.
         */
        'SSO' => 'false',

        /**
         * Configure which headers should be forwarded to the privacyIDEA server.
         * Multiple headers should be separated by a comma (see example).
         * 
         * Optional.
         */
        'forwardHeaders' => 'header1,header2,header3',
        
        /**
         * Custom hint for the OTP field.
         * Optional.
         */
        'otpFieldHint' => 'Please enter the OTP!',

        /**
         * Other authproc filters can disable this filter.
         * If privacyIDEA should consider the setting, you have to enter the path and key of the state.
         * The value of this key has to be set by a previous auth proc filter.
         * privacyIDEA will only be disabled, if the value of the key is set to false,
         * in any other situation (e.g. the key is not set or does not exist), privacyIDEA will be enabled.
         * 
         * Optional.
         */
        'enabledPath' => '',
        'enabledKey' => '',

        /**
         * You can exclude clients with specified ip addresses.
         * Enter a range like "10.0.0.0-10.2.0.0" or a single ip like "192.168.178.2"
         * The selected ip addresses do not need 2FA.
         * 
         * Optional.
         */
        'excludeClientIPs' => array("10.0.0.0-10.2.0.0", "192.168.178.2"),


        /**
         * If you want to selectively disable the privacyIDEA authentication using
         * the entityID and/or SAML attributes, you may enable this.
         * Value has to be a 'true' or 'false'.
         * 
         * Optional.
         */
        'checkEntityID' => 'true',
     
        /**
         * Depending on excludeEntityIDs and includeAttributes this will set the state variable 
         * $state[$setPath][$setPath] to true or false.
         * To selectively enable or disable privacyIDEA, make sure that you specify setPath and setKey such
         * that they equal enabledPath and enabledKey from privacyidea:privacyidea.
         * 
         * Optional.
         */
        'setPath' => 'privacyIDEA',
        'setKey' => 'enabled',
        
        /**
         * The requesting SAML provider's entityID will be tested against this list of regular expressions.
         * If there is a match, the filter will set the specified state variable to false and thereby disables 
         * privacyIDEA for this entityID The first matching expression will take precedence.
         * 
         * Optional.
         */
        'excludeEntityIDs' => array(
            '/http(s)\/\/conditional-no2fa-provider.de\/(.*)/',
            '/http(.*)no2fa-provider.de/'
        ),
        
        /**
         * Per value in excludeEntityIDs, you may specify another set of regular expressions to match the 
         * attributes in the SAML request. If there is a match in any attribute value, this filter will 
         * set the state variable to true and thereby enable privacyIDEA where it would be normally disabled
         * due to the matching entityID. This may be used to enable 2FA at this entityID only for privileged
         * accounts.
         * The key in includeAttributes must be identical to a value in excludeEntityIDs to have an effect!
         * 
         * Optional.
         */
        'includeAttributes' => array(
            '/http(s)\/\/conditional-no2fa-provider.de\/(.*)/' => array(
                'memberOf' => array(
                    '/cn=2fa-required([-_])regexmatch(.*),cn=groups,(.*)/',
                    'cn=2fa-required-exactmatch,ou=section,dc=privacyidea,dc=org'
                ),
                'myAttribute' => array(
                    '/(.*)2fa-required/', '2fa-required',
                )
            )
        ),
    ),
)
```
