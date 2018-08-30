# privacyIDEA simpleSAMLphp Plugin

This plugin adds flexible, enterprise-grade two factor authentication 
to simplesSAMLphp. 

It enables simpleSAMLphp to do two factor authentication against 
a [privacyIDEA server](https://github.com/privacyidea/privacyidea), 
that runs in your network. Users can authenticate with normal OTP tokens, 
Challenge Response tokens like EMail and SMS or with U2F devices.
TiQR is currently not supported.

### Packagist and Composer

The package is listed at packagist.
https://packagist.org/packages/privacyidea/simplesamlphp-module-privacyidea

simpleSAMLphp recommends to use composer to install plugins. For 
more information about setting up composer see 
https://getcomposer.org/doc/00-intro.md

You can install this plugin into simpleSAMLphp like this:

    php composer.phar require privacyidea/simplesamlphp-module-privacyidea:v1.5.1

Check for the latest version of the plugin. It might be higher than 1.5.1.