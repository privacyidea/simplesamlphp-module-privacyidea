# privacyIDEA simpleSAMLphp Module

This module adds flexible, enterprise grade Multi-Factor Authentication 
to simplesSAMLphp.

It enables simpleSAMLphp to perform MFA against the [privacyIDEA server](https://github.com/privacyidea/privacyidea), 
that runs in your network. Users can authenticate with normal OTP tokens, 
Challenge Response tokens like EMail, SMS and PUSH or using WebAuthn devices.
TiQR is currently not supported.

## Installation
It is recommended to install this package using [composer](https://getcomposer.org/). In your saml root dir, execute the following command in the terminal:

`composer require privacyidea/simplesamlphp-module-privacyidea`

## Configuration
Please check the [documentation](https://github.com/privacyidea/simplesamlphp-module-privacyidea/blob/master/docs/privacyidea.md)

## Customization
To customize the module, you can edit ´public/assets/css/pi-main.css´.

## Logging
The saml log can be read with `journalctl -f`. 
If you encounter any problems that are not logged as errors, 
set the logging level of simpleSAMLphp to debug by 
editing `{samlDir}/config/config.php`. 
Search for `logging.level` and set it 
to `SimpleSAML\Logger::DEBUG`. Alternatively, 
the apache error log can be checked for the errors. 
It is located at `/var/log/apache2/error.log`.
