# wordpress-onelogin. OneLogin SAML plugin for Wordpress. #

Uses the new Onelogin PHP-SAML Toolkit. Review its [dependences](https://github.com/onelogin/php-saml#dependences)

In order to install it, move the onelogin-saml-sso inside the wp-content/plugins folder.
Once moved, activate the plugin and configure it.

### Using the SAML Plugin in WPengine or similar ###

This kind of WP hosting used to cache plugins and protect the wp-login.php view.
You will need to contact them in order to disable the cache for this SAML plugin and also allow external HTTP POST to
wp-login.php


### PHP Compatibility on 3.6.0 ###

Version 3.6.0 is compatible with PHP 8.X (php-saml 4.3.1)

### Security Improvements on 3.5.0 ###

Version 3.5.0 includes a security patch for xmlseclibs (CVE-2025-66475) . Updated to version 3.1.4

### Security Improvements on 3.2.0 and 3.2.1 ###

Version 3.2.0 includes a security patch that prevent RelayState redirection attacks

### Security Improvements on 3.0.0 ###

Version 3.0.0 includes a security patch that will prevent DDOS by expansion of internally defined entities (XEE)
That version also includes the use of php-saml 3.X so will be compatible with PHP 5.X and 7.X

### Security Improvements on 2.4.3 ###

Version 2.4.3 includes a security patch that contains extra validations that will prevent some kind of elaborated signature wrapping attacks and other security improvements. Previous versions are vulnerable so we highly recommended to upgrade to >= 2.4.3.


### If you used this plugin before 2.2.0 with just-in-time provision active ###
Read: https://wpvulndb.com/vulnerabilities/8508

To mitigate that, place the script at the root of WordPress and execute it (later remove it)
https://gist.github.com/pitbulk/a8223c90a3534e9a7d5e0a93009a094f
