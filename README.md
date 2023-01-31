# privacyIDEA simpleSAMLphp Plugin

This plugin adds flexible, enterprise-grade two-factor authentication 
to simplesSAMLphp. 

It enables simpleSAMLphp to do two-factor authentication against 
a [privacyIDEA server](https://github.com/privacyidea/privacyidea), 
that runs in your network. Users can authenticate with normal OTP tokens, 
Challenge Response tokens like EMail and SMS or using WebAuthn and U2F devices.
TiQR is currently not supported.

## Installation
It is recommended to install this package using [composer](https://getcomposer.org/). In your saml root dir, execute the following command in a terminal:

`composer require privacyidea/simplesamlphp-module-privacyidea`

## Configuration
Please check the [documentation](https://github.com/privacyidea/simplesamlphp-module-privacyidea/blob/master/docs/privacyidea.md)

## Customization (Themes)
Please check the [documentation](https://github.com/privacyidea/simplesamlphp-module-privacyidea/blob/master/docs/pi-themes.md)

## Logfiles
The saml log can be read with `journalctl -f`. If you encounter any problems that are not logged as errors, set the logging level of saml to debug by editing `{samlDir}/config/config.php`. Search for `logging.level` and set it so `SimpleSAML\Logger::DEBUG`. Alternatively, the apache error log can be checked for errors. It is located at `/var/log/apache2/error.log`
