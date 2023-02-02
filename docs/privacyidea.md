privacyIDEA module
==================

This module is an authentication module for simpleSAMLphp to use with the privacyIDEA authentication server.

You can use this plugin in two different ways:
<ol>
    <li> AuthSource: This module does the complete authentication process against privacyIDEA
    <li> AuthProc: This module does just one step of the authentication, the second factor against privacyIDEA
</ol>

NOTE: This plugin is enabled by default when installed, you do not need to enable it manually. Just add the
configuration to the corresponding file as explained in the following:

AuthSource
==========

Add the configuration to `config/authsources.php`.
*example-privacyidea* is the name used to identify this module, it can be changed to your liking. The following is a
template configuration:

```PHP
'example-privacyidea' => array(
    'privacyidea:PrivacyideaAuthSource',

    /**
     * The URL of the privacyidea server. Required.
     */
    'privacyideaServerURL' => 'https://your.server.com',

    /**
     * Optionally disable SSL verification. This should always be enabled in a productive environment!
     * Values should be 'true' or 'false'. Default is 'true'.      
     */
    'sslVerifyHost' => 'true',
    'sslVerifyPeer' => 'true',
        
    /**
     * Optionally set the privacyidea realm.
     */
    'realm' => '',
    
    /**
     * Specify the username and password of your service account from privacyIDEA server.
     * Only required if 'authSourceMode' => 'triggerChallenge'.
     */
    'serviceAccount'    => 'service',
    'servicePass'       => 'service',
    
    /**
     * Optionally set the realm for your service account.
     */
    'serviceRealm'      => '',
    
    /**
     * Required. Set one of the following authentication flows:
     * 'sendPassword' - (default) Login interface will contain the username input and a single password/OTP input.
     * 'triggerChallenge' - Login interface will contain only the username input. This mode triggers
     * challenges prior to the login using the configured service account (required).
     * 'separateOTP' - Login interface will contain 3 inputs for username, password and OTP.
     */
    'authenticationFlow'      => 'sendPassword',
    
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
     * Optional.
     */
    'SSO' => 'false',
    
    /**
     * Optionally set a preferred token type.
     * If the chosen token is triggered, it will be used to authenticate directly
     * without having to press the button for the type.
     * Possible values are: 'otp', 'push', 'webauthn' or 'u2f'. Default is 'otp'.
     * 
     * NOTE: If the 'preferred_client_mode' is set on the server side, this option will be ignored.
     */
    'preferredTokenType' => '',

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

User attributes
---------------
To complete the authentication with SAML in AuthSource mode, SAML expects user attributes to be returned.
These attributes will be received from privacyIDEA upon completing the authentication.
However, this has to be enabled by creating a policy in privacyIDEA with the following values:
Scope:  authorization
Actions from section "setting_actions": "add_resolver_in_response", "add_user_in_response"
Actions from section "miscellaneous": "application_tokentype

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

```PHP
'authproc' => array(

    /**
     * Configuration for the privacyIDEA server.
     */
    20 => array(
        'class'             => 'privacyidea:PrivacyideaAuthProc',

       /**
        * The URL of the privacyidea server. Required.
        */
        'privacyideaServerURL' => 'https://your.privacyidea.server',
        
       /**
        * Optionally set the privacyidea realm.
        */
        'realm' => '',

        /**
         * The uidKey is the username's attribute key.
         * You can choose a single one or multiple ones. The first set will be used.
         * Example: 'uidKey' => array('uid', 'userName', 'uName').
         * Required.
         */
        'uidKey' => 'uid',

        /**
         * Optionally disable SSL verification. This should always be enabled in a productive environment!
         * Values should be 'true' or 'false'. Default is 'true'.      
         */
        'sslVerifyHost' => 'true',
        'sslVerifyPeer' => 'true',
        
        /**
         * Choose one of the authentication flows:
         * 'default' - Default authentication flow.
         * 'triggerChallenge' - Before the login interface is shown, the filter will attempt to trigger challenge-response
         * token with the specified serviceAccount
         * Required.
         */
        'authenticationFlow' => 'default',
        
        /**
         * Specify the username and password of your service account from privacyIDEA server.
         * Only required if 'authSourceMode' => 'triggerChallenge'.
         */
        'serviceAccount' => 'service',
        'servicePass' => 'service',
        
        /**
         * Optionally set the realm for your service account.
         */
        'serviceRealm' => '',
        
        /**
         * If you want to use the passOnNoToken or passOnNoUser policy in privacyidea, you can set this to 'true' and specify
         * a static pass which will be sent before the actual authentication to trigger the policies in privacyidea. 
         * NOTE: Not compatible it with 'doEnrollToken'.
         * NOTE: This won't be processed if the user has challenge-response token that were triggered before.
         * Optional.
         */
        'tryFirstAuthentication' => 'false',
        'tryFirstAuthPass' => 'secret',
        
        /**
         * Set this to 'true' if you want to use single sign on.
         * All information required for SSO will be saved in the session.
         * After logging out, the SSO data will be removed from the session.
         * Optional.
         */
        'SSO' => 'false',
        
        /**
         * Optionally set a preferred token type.
         * If the chosen token is triggered, it will be used to authenticate directly
         * without having to press the button for the type.
         * Possible values are: 'otp', 'push', 'webauthn' or 'u2f'. Default is 'otp'.
         *
         * NOTE: If the 'preferred_client_mode' is set on the server side, this option will be ignored.
         */
        'preferredTokenType' => '',
        
        /**
         * Custom hint for the OTP field.
         */
        'otpFieldHint' => 'OTP',
        
        /**
         * Enable this if a token should be enrolled for users that do not have one.
         * The value has to be 'true' or 'false'.
         * Possible token types are 'hotp', 'totp' or 'u2f'
         * Optional.
         * 
         * NOTE: Up from privacyIDEA v3.8.1, we recommend using the 'enroll via challenge'
         * policy instead of this feature.
         */
        'doEnrollToken' => 'false',
        'tokenType' => 'totp',

        /**
         * Other authproc filters can disable this filter.
         * If privacyIDEA should consider the setting, you have to enter the path and key of the state.
         * The value of this key has to be set by a previous auth proc filter.
         * privacyIDEA will only be disabled, if the value of the key is set to false,
         * in any other situation (e.g. the key is not set or does not exist), privacyIDEA will be enabled.
         * Optional.
         */
        'enabledPath' => '',
        'enabledKey' => '',

        /**
         * You can exclude clients with specified ip addresses.
         * Enter a range like "10.0.0.0-10.2.0.0" or a single ip like "192.168.178.2"
         * The selected ip addresses do not need 2FA.
         * Optional.
         */
        'excludeClientIPs' => array("10.0.0.0-10.2.0.0", "192.168.178.2"),


        /**
         * If you want to selectively disable the privacyIDEA authentication using
         * the entityID and/or SAML attributes, you may enable this.
         * Value has to be a 'true' or 'false'.
         * Optional.
         */
        'checkEntityID' => 'true',
     
        /**
         * Depending on excludeEntityIDs and includeAttributes this will set the state variable 
         * $state[$setPath][$setPath] to true or false.
         * To selectively enable or disable privacyIDEA, make sure that you specify setPath and setKey such
         * that they equal enabledPath and enabledKey from privacyidea:privacyidea.
         * Optional.
         */
        'setPath' => 'privacyIDEA',
        'setKey' => 'enabled',
        
        /**
         * The requesting SAML provider's entityID will be tested against this list of regular expressions.
         * If there is a match, the filter will set the specified state variable to false and thereby disables 
         * privacyIDEA for this entityID The first matching expression will take precedence.
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
