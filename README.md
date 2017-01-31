# wordpress-onelogin. OneLogin SAML plugin for Wordpress. #

Uses the new Onelogin PHP-SAML Toolkit. Review its [dependences](https://github.com/onelogin/php-saml#dependences)

In order to install it, move the onelogin-saml-sso inside the wp-content/plugins folder.
Once moved, activate the plugin and configure it.


P.S This plugin will be available at wordpress site soon.

### Using the SAML Plugin in WPengine or similar ###

This kind of WP hosting used to cache plugins and protect the wp-login.php view.
You will need to contact them in order to disable the cache for this SAML plugin and also allow external HTTP POST to
wp-login.php

### Security Improvements on 2.4.3 ###

Version 2.4.3 includes a security patch that contains extra validations that will prevent some kind of elaborated signature wrapping attacks and other security improvements. Previous versions are vulnerable so we highly recommended to upgrade to >= 2.4.3.


### If you used this plugin before 2.2.0 with just-in-time provision active ###
Read: https://wpvulndb.com/vulnerabilities/8508

To mitigate that, place the script at the root of WordPress and execute it (later remove it)
https://gist.github.com/pitbulk/a8223c90a3534e9a7d5e0a93009a094f
