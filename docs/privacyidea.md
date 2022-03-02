privacyIDEA module
==================

This module is an authentication module for simpleSAMLphp to use with the privacyIDEA authentication server.

You can use this plugin in two different ways:
<ol>
    <li> AuthSource: This module does the complete authentication process against privacyIDEA
    <li> AuthProc: This module does just one step of the authentication, the second factor against privacyIDEA
</ol>

NOTE: This plugin is enabled by default when installed, you do not need to enable it manually.

AuthSource
==========

You need to add the authentication source 'privacyidea' to
`config/authsources.php`. *example-privacyidea* is the name used to identify this module, it can be changed to your liking. The following is a template configuration:

```PHP
'example-privacyidea' => array(
    'privacyidea:PrivacyideaAuthSource',

    /* 
     * The URI (including protocol and port) of the privacyidea server
     * Required.
     */
    'privacyideaServerURL' => 'https://your.server.com',

    /*
     * Check if the hostname matches the name in the certificate.
     * The value have to be a string.
     * Optional.
     */
    'sslVerifyHost' => 'false',

    /*
     * Check if the certificate is valid, signed by a trusted CA.
     * The value have to be a string.
     * Optional.
     */
    'sslVerifyPeer' => 'false',
        
    /*
     * The realm where the user is located in.
     * Optional.
     */
    'realm' => '',
    
    /**
     *  Here you need to enter the username of your service account
     */
    'serviceAccount'    => 'service',

    /**
     *  Enter here the password for your service account
     */
    'servicePass'       => 'service',
    
    /**
     *  Set doTriggerChallenge to 'true' to trigger challenges prior to the login 
     *  using the configured service account. 
     *  This setting takes precedence over 'doSendPassword'.
     *  The value have to be a string.
     */
    'doTriggerChallenge' => 'true',
    
    /**
     *  Set doSendPassword to 'true' to send a request to validate/check with the username
     *  and an empty pass prior to the login. 
     *  This can be used to trigger challenges depending on the configuration in privacyIDEA 
     *  and requires no service account. If 'doTriggerChallenge' is enabled, this setting has no effect.
     *  The value have to be a string.
     */
    'doSendPassword' => 'true',
    
    /**
     * Set custom hints for the OTP and password fields
     */
    'otpFieldHint' => 'OTP',
    'passFieldHint' => 'Password',
    
    /**
     * Set SSO to 'true' if you want to use single sign on.
     * All information required for SSO will be saved in the session.
     * After logging out, the SSO data will be removed from the session.
     */
    'SSO' => 'false',
    
    /**
     * Set preferredTokenType to your favourite token type.
     * If the choosen token is triggered, it will be used to authenticate directly
     * without having to press the button for the type.
     * Possible values are: push, webauthn or u2f.
     * When left empty, defaults to showing an input field for OTPs.
     */
    'preferredTokenType' => '',

    /*
     * This is the translation from privacyIDEA attribute names to 
     * SAML attribute names.
     * Optional.
     */
    'attributemap' => array(
        'username' => 'samlLoginName',
        'surname' => 'surName',
        'givenname' => 'givenName',
        'email' => 'emailAddress',
        'phone' => 'telePhone',
        'mobile' => 'mobilePhone'
    ),

    /*
     * You are able to concatenate attributes like the given and surname.
     * Optional.
     */
    'concatenationmap' => array(
        'givenname,surname' => 'fullName',
    ),

    /*
     * Here the detail attributes can be edited.
     * If they should not be listed, just remove them.
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
At the moment privacyIDEA will know and return the following attributes by default, that can be mapped to SAML
attributes:

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


If you want to use privacyIDEA as an auth process filter, add the configuration to the metadata file (e.g. `simplesaml/metadata/saml20-idp-hosted.php`. 

```PHP
'authproc' => array(

    /**
     *  Configuration for the privacyIDEA server.
     */
    20 => array(
        'class'             => 'privacyidea:PrivacyideaAuthProc',

        /**
         *  Enter the URL to your privacyIDEA instance
         */
        'privacyideaServerURL' => 'https://your.privacyidea.server',
        
        /**
         *  Enter the realm, where your users are stored (remove it or set it to '' to use default)
         */
        'realm'             => 'realm1',

        /**
         *  The uidKey is the username's attribute key.
         *  You can choose a single one or multiple ones. The first set will be used.
         */
        'uidKey'            => 'uid',
        //  'uidKey'        => array('uid', 'userName', 'uName'),

        /**
         *  Check if the hostname matches the name in the certificate.
         *  The value have to be a string.
         */
        'sslVerifyHost'     => 'true',

        /**
         *  Check if the certificate is valid, signed by a trusted CA
         *  The value have to be a string.
         */
        'sslVerifyPeer'     => 'true',

        /**
         *  Here you need to enter the username of your service account
         */
        'serviceAccount'    => 'service',

        /**
         *  Enter here the password for your service account
         */
        'servicePass'       => 'service',
        
        /**
         *  You can add this option, if you want to enroll tokens for users, who do not have one yet.
         *  The value have to be a string.
         */
        'doEnrollToken'     => 'true',
        
        /**
         *  You can select a time based otp (totp), an event based otp (hotp) or an u2f (u2f)
         */
        'tokenType'         => 'totp',
         
        /**
         *  You can enable or disable trigger challenge.
         *  The value have to be a string.
         */
        'doTriggerChallenge' => 'true',
        
        /**
         * Set this to 'true' if you want to use single sign on.
         * All information required for SSO will be saved in the session.
         * After logging out, the SSO data will be removed from the session.
         */
        'SSO' => 'false',
        
        /**
         * Set preferredTokenType to your favourite token type.
         * If the choosen token is triggered, it will be used to authenticate directly
         * without having to press the button for the type.
         * Possible values are: push, webauthn or u2f.
         * When left empty, defaults to showing an input field for OTPs.
         */
        'preferredTokenType' => '',
        
        /**
         * Set custom hints for the OTP and password fields
         */
        'otpFieldHint' => 'OTP'
        'passFieldHint' => 'Password'

        /**
         *  Other authproc filters can disable 2FA if you want to.
         *  If privacyIDEA should listen to the setting, you have to enter the state's path and key.
         *  The value of this key will be set by a previous auth proc filter.
         *  privacyIDEA will only be disabled, if the value of the key is set to false,
         *  in any other situation (e.g. the key is not set or does not exist), privacyIDEA will be enabled.
         */
        'enabledPath'       => '',
        'enabledKey'        => '',

        /**
         *  If you want to use passOnNoToken or passOnNoUser, you can decide, if this module should send a password to
         *  privacyIDEA. If passOnNoToken is activated and the user does not have a token, he will be passed by privacyIDEA.
         *  NOTE: Do not use it with privacyidea:tokenEnrollment.
         */
        'tryFirstAuthentication' => 'true',

        /**
         *  You can decide, which password should be used for tryFirstAuthentication
         */
        'tryFirstAuthPass' => 'simpleSAMLphp'

        /**
         *  
         *  You can exclude clients with specified ip addresses.
         *  Enter a range like "10.0.0.0-10.2.0.0" or a single ip like "192.168.178.2"
         *  The selected ip addresses do not need 2FA
         */
        'excludeClientIPs'  => array("10.0.0.0-10.2.0.0", "192.168.178.2"),


        /**
         *  Check Entity ID is optional. If you want to selectively disable the privacyIDEA authentication using
         *  the entityID and/or SAML attributes, you may enable this filter.
         *  Value have to be string.
         */
        'checkEntityID'        => 'true',
     
        /**
         *  Depending on excludeEntityIDs and includeAttributes the filter will set the state variable 
         *  $state[$setPath][$setPath] to true or false.
         *  To selectively enable or disable privacyIDEA, make sure that you specify setPath and setKey such
         *  that they equal enabledPath and enabledKey from privacyidea:privacyidea.
         */
        'setPath'              => 'privacyIDEA',
        'setKey'               => 'enabled',
        /**
         *  The requesting SAML provider's entityID will be tested against this list of regular expressions.
         *  If there is a match, the filter will set the specified state variable to false and thereby disables 
         *  privacyIDEA for this entityID The first matching expression will take precedence.
         */
        'excludeEntityIDs' => array(
            '/http(s)\/\/conditional-no2fa-provider.de\/(.*)/',
            '/http(.*)no2fa-provider.de/'
        ),
        /**
         *  Per value in excludeEntityIDs, you may specify another set of regular expressions to match the 
         *  attributes in the SAML request. If there is a match in any attribute value, this filter will 
         *  set the state variable to true and thereby enable privacyIDEA where it would be normally disabled
         *  due to the matching entityID. This may be used to enable 2FA at this entityID only for privileged
         *  accounts.
         *  The key in includeAttributes must be identical to a value in excludeEntityIDs to have an effect!
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
