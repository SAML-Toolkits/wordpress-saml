<?php
/*
Plugin Name: OneLogin SAML SSO
Plugin URI: http://support.onelogin.com/entries/383540
Description: Give users secure one-click access to WordPress from OneLogin. This SAML integration eliminates passwords and allows you to authenticate users against your existing Active Directory or LDAP server as well increase security using YubiKeys or VeriSign VIP Access, browser PKI certificates and OneLogin's flexible security policies. OneLogin is pre-integrated with thousands of apps and handles all of your SSO needs in the cloud and behind the firewall.
Author: OneLogin, Inc.
Version: 2.0.0
Author URI: http://www.onelogin.com
*/

require_once dirname(dirname(dirname(dirname(__FILE__)))) . '/wp-load.php';
require_once plugin_dir_path(__FILE__)."php/functions.php";

$domain = 'onelogin-saml-sso';
$mo_file = plugin_dir_path(__FILE__) . 'lang/'.get_locale() . '/' . $domain . '.mo';
load_textdomain($domain, $mo_file );
load_plugin_textdomain($domain, false, dirname( plugin_basename( __FILE__ ) ) . '/lang/'. get_locale() . '/' );

if (isset($_GET['acs'])) {
	saml_acs();
}
else if (isset($_GET['sls'])) {
	saml_sls();
}

// add menu option for configuration
require_once plugin_dir_path(__FILE__)."php/configuration.php";
add_action('admin_menu', 'onelogin_saml_configuration');

// plugin hooks into authenticator system
if (!isset($_GET['normal']) || !isset($_POST['wp-submit']) || strpos($_SERVER['SCRIPT_NAME'], 'php/metadata.php') === FALSE) {
	if (get_option('onelogin_saml_forcelogin')) {
		add_action('init', 'saml_sso');
	}
	else if (!isset($_GET['loggedout'])){
		add_action('wp_authenticate', 'saml_sso', 1);
	}
}

if (isset($_COOKIE['saml_login'])) {
    if (get_option('onelogin_saml_slo')) { 
		add_action('wp_logout', 'saml_slo', 1);
    }
}

add_action('lost_password', 'saml_lostpassword', 1);
add_action('retrieve_password', 'saml_lostpassword' , 1);
add_action('password_reset', 'saml_lostpassword', 1);
add_action('user_register', 'saml_user_register', 1);
add_action('register_form', 'saml_user_register', 1);
