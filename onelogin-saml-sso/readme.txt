=== Plugin Name ===
Contributors: onelogin
Tags: sso, saml, single sign on, password, active directory, ldap, identity, onelogin, yubico, yubikey, vip access, otp
Requires at least: 2.1.2
Tested up to: 3.5.1
Stable tag: trunk

This plugin provides single sign-on via SAML and gives users one-click access to their WordPress accounts from identity providers like OneLogin.

== Description ==

This SAML plugin eliminates passwords and allows you to authenticate WordPress users (typically editors) against your existing Active Directory or LDAP server as well increase security using YubiKeys or VeriSign VIP Access via OneLogin. OneLogin is pre-integrated with thousands of apps and handles all of your SSO needs in the cloud and behind the firewall.

* Eliminate passwords in WordPress
* Allow users to sign into WordPress with their *Active Directory* or *LDAP* credentials
* Give users one-click access from your intranet
* Increase security using browser PKI certificates or two-factor authentication from *Yubico* or *VeriSign*
* Easily prevent access from former employees and contractors

== Changelog ==

= 1.0.0 =
* First version.

= 1.0.1 =
* Fixed installation issue.

= 2.0.0 =
* Based on the new php toolkit, added many functionalities: JIT, SLO.

= 2.1.0 =
 * Reimplement the plugin architecture (was an independent plugin, now depends on wordpress).
 * Update the php-saml toolkit
 * Improve the i18n support
 * Improve base url and pase path
 * Override user registration or reset password links to link 3rd party (like IdP) urls.
 * Fix bug when role attribute carry a space as attribute

= 2.1.1 =
 * Fix bug introduced in the reimplementation

= 2.1.2 =
 * Fix minor bugs. Add customRole support (editing php/functions.php file, review commented code)

= 2.1.3 =
 * Updated the php-saml toolkit (now 2.2.0)
 * Added more Customization related to change password, reset password, change mail

= 2.1.4 =
 * Added stay when slo and forced logn

= 2.1.5 =
 * Refactor sso/slo flow
