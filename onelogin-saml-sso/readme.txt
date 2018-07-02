=== Plugin Name ===
Contributors: onelogin
Tags: sso, saml, single sign on, password, active directory, ldap, identity, onelogin, yubico, yubikey, vip access, otp
Requires at least: 2.1.2
Tested up to: 4.9.6
Stable tag: trunk

This plugin provides single sign-on via SAML and gives users one-click access to their WordPress accounts from identity providers like OneLogin.

== Description ==

This SAML plugin eliminates passwords and allows you to authenticate WordPress users (typically editors) against your existing Active Directory or LDAP server as well increase security using YubiKeys or VeriSign VIP Access via OneLogin. OneLogin is pre-integrated with thousands of apps and handles all of your SSO needs in the cloud and behind the firewall.

* Eliminate passwords in WordPress
* Allow users to sign into WordPress with their *Active Directory* or *LDAP* credentials
* Give users one-click access from your intranet
* Increase security using browser PKI certificates or two-factor authentication from *Yubico* or *VeriSign*
* Easily prevent access from former employees and contractors

If you used this plugin before 2.2.0 with just-in-time provision active, Read: https://wpvulndb.com/vulnerabilities/8508
To mitigate that bug, place the script at the root of wordpress and execute it (later remove it) https://gist.github.com/pitbulk/a8223c90a3534e9a7d5e0a93009a094f

== Changelog ==

= 2.8.0 =
* Update php-saml to 2.14.0
* Remove the use of screen_icon method

= 2.7.1 =
* Fix is_saml_enabled method

= 2.7.0 =
* Make NameID optional

= 2.6.0 =
* Update php-saml to 2.13.0
* Add Status setting in order to enable or disable the plugin (Required on multi-sites environment since the plugin is enabled globally for the network)
* Add 'Remember Me' Login option to Settings
* Fix bug on escaping value for customize_links_saml_login
* If password is disabled.. turn field readonly.. not disable it
* Add ability to expose attributes that come from saml via a WordPress
* On multi-site environment, provision users on specific site if JIT enabled on that site.

= 2.5.0 =
* Update php-saml library to 2.11.0
* Allow WP-CLI to work
* Sanitize SAML settings input
* Add support to SAML NameId Format

= 2.4.7 =
* Fix Signature & Digest algorithm support

= 2.4.6 =
* Fix validate page (debug/strict values were showed wrong)
* Avoid error 500 when accesing ACS URL directly, instead print error.

= 2.4.5 =
* Update php-saml library to 2.10.5
* Fixes some grammatical error
* Use WP to determine wp-content path
* Avoid double site URL concatenation
* Replace deprecated add_contextual_help method
* Signature & Digest algorithm support
* On SP metadata publication validate only SP part.

= 2.4.4 =
* Relax Destination check.
*  On SLS, Print errors, not lastError (it will be printed if debug enabled)

= 2.4.3 =
 * Update php-saml library to [2.10.0](https://github.com/onelogin/php-saml/releases/tag/v2.10.0) (it includes SAML Signature Wrapping attack prevention and other security improvements).
* Fix Idp initiated sign out issue (WP session not closed) [#25](https://github.com/onelogin/wordpress-saml/issues/25)
* Fix Ordering issue with Auth Check for SAML Validation  [#23](https://github.com/onelogin/wordpress-saml/issues/23) 
* Be able to enable lowercase URL encoding (Compatibility issue with ADFS when validating Signatures

= 2.4.2 =
 * Update php-saml library to 2.9.0 (it includes SAML Signature Wrapping attack prevention).

= 2.4.1 =
 * Update php-saml library to 2.8.0

= 2.4.0 =
 * Use the worpress roles API to generate the options for the mappings a nd use these mappings to set the user role. Add Role precedence support.
 * Add alternative ACS URL (WPEngine compatible)
 * Update php-saml library to 2.7.0

= 2.3.1 =
 * Fix SAML link

= 2.3.0 =
 * Uncomment out filter based custom role code
 * Add 'Keep Local login' functionality in order to prompt the normal login form + a SAML link instead of directly execute the SP-initiaited SSO flow
 * Fix changelog
 * Update php-saml library to 2.6.1

= 2.2.0 =
 * Password security issue
 * Add alternative solution/documentation about custom roles (php/functions.php L167)
 * Call exit after any error message or redirection

= 2.1.8 =
 * Improve the role/group support when multiple values on a single attribute statement.
 * Prevent to auto-update the role of the superuser

= 2.1.7 =
 * Add NameIDFormat support.
 * Add requestedAuthnContext support.
 * SessionIndex and nameID is now passed to the IdP
 * Now retrieveParametersFromServer can be activated

= 2.1.6 =
 * Update php-saml library to 2.5.0
 * Remove deprecated method wp_login
 * SLS inprovement

= 2.1.5 =
 * Refactor sso/slo flow

= 2.1.4 =
 * Added stay when slo and forced logn

= 2.1.3 =
 * Updated the php-saml toolkit (now 2.2.0)
 * Added more Customization related to change password, reset password, change mail

= 2.1.2 =
 * Fix minor bugs. Add customRole support (editing php/functions.php file, review commented code)


= 2.1.1 =
 * Fix bug introduced in the reimplementation

= 2.1.0 =
 * Reimplement the plugin architecture (was an independent plugin, now depends on wordpress).
 * Update the php-saml toolkit
 * Improve the i18n support
 * Improve base url and pase path
 * Override user registration or reset password links to link 3rd party (like IdP) urls.
 * Fix bug when role attribute carry a space as attribute

= 2.0.0 =
 * Based on the new php toolkit, added many functionalities: JIT, SLO.

= 1.0.1 =
 * Fixed installation issue.


= 1.0.0 =
 * First version.
