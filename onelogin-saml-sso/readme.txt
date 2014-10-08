=== Plugin Name ===
Contributors: onelogin
Tags: sso, saml, single sign on, password, active directory, ldap, identity, onelogin, yubico, yubikey, vip access, otp
Requires at least: 2.0.2
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

= 2.0.1 b =
 * Update the php-saml toolkit (now 2.2.0)
 * Improve the i18n support
 * Override user registration or reset password links to link 3rd party (like IdP) urls.
 * Added more Customization related to change password, reset password, change mail
 * Fix bug when role attribute carry a space as attribute
 * Fix minor bugs. Add customRole support (editing php/functions.php file, review commented code)

= 2.0.2 b =
 * Refactor sso logic. Bugfix password reset bug