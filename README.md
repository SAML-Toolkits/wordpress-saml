# wordpress-onelogin. OneLogin SAML plugin for Wordpress. #

Uses the new Onelogin PHP-SAML Toolkit. Review its [dependences](https://github.com/onelogin/php-saml#dependences)

In order to install it, move the onelogin-saml-sso inside the wp-content/plugins folder.
Once moved, activate the plugin and configure it.


P.S This plugin will be available at wordpress site soon.

### Using the SAML Plugin in WPengine or similar ###

This kind of WP hosting used to cache plugins and protect the wp-login.php view.
You will need to contact them in order to disable the cache for this SAML plugin and also allow external HTTP POST to
wp-login.php
