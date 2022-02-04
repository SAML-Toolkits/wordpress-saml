=== Plugin Name ===
Contributors: onelogin
Tags: sso, saml, single sign on, password, active directory, ldap, identity, onelogin, yubico, yubikey, vip access, otp
Requires at least: 2.1.2
Tested up to: 5.9
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
= 3.4.0 =
* Update php-saml to 3.6.1 and xmlseclibs to 3.1.1
* Support Passive mode and don't raise error when passive authentication failed
* Allow set desired target on saml_sso endpoint by the use of a 'target' GET parameter
* Add new parameter to determine if the account was created or already existed
* Add Support for WPS Hide Login
* Use add_query_arg to better adjust login URLs
* Login always returned to frontend page, now if redirect_to is set, redirects there

= 3.3.1 =
* wp_login was triggered with wrong arguments, user object was not initializated
* Minor refactor

= 3.3.0 =
* Add support for Nickname user field
* Fix redirect protection. Absolute URLs failed and only relatives were accepted
* Add support for saml_nameid_name_qualifier and saml_nameid_name_sp_qualifier which fixes detected issues on SLO process with ADFS
* Add to setcookie method the cookie domain, secure flag and httponly
* [#101](https://github.com/onelogin/wordpress-saml/issues/101) SAML request was improperly generated when requestedAuthNContext was empty.
* Replace deprecated method (sanitize_url --> esc_url_raw )
* Support triggering wp_login hook controller by a setting
* Update php-saml to 3.5.0

= 3.2.1 =
* Sanitize inputs
* Update php-saml to 3.4.1
* Fix nameidformat field

= 3.2.0 =
* Avoid untrusted redirections
* Disable SAML on CLI/Cron on ACS and SLS endpoints. Allow custom filter to disable SAML
* Support multi-role
* Fix variable assignment during conditional check
* Swap to `manage_options` for the cap check on the validate page.
* Fix unintentional variable assignment
* Set 1000 as the limit of sites to be managed by SAML network settings

= 3.1.2 =
* Minor fix to extract all sites for the multi-site features

= 3.1.1 =
* Multisites: Add the option to automatically enroll users on sites when a SAML Network setting enabled
* Fix #86. Set default role when not provided only on create action
* Detect Ajax and cron tasks

= 3.1.0 =
* Multisite improvement. Now when multisite is enabled, on the "Network Admin" dashboard appears a "Network SAML Settings" where you can define a SAML template setting, and then inject it in sites. Also will allow you enable/disable multiple sites on a unique view.
* Now the onelogin_saml_keep_local_login will also hide the login form on wp-login.php view. So when on a logout action, we can notify the user with the typical message of 'You are now logged out.' without showing the local login form.
* Update php-saml to 3.3.1
* Update xmlseclibs to 3.0.4

= 3.0.0 =
* Update php-saml to 3.1.0 to make the plugin compatible with PHP7.3
* Overriding user_register will prevent admins to register users, so deactivating that override
* Stop using $blog_id at the is_user_member_of_blog call

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
