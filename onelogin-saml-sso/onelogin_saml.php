<?php
/*
Plugin Name: OneLogin SAML SSO
Plugin URI: http://support.onelogin.com/entries/383540
Description: Give users secure one-click access to WordPress from OneLogin. This SAML integration eliminates passwords and allows you to authenticate users against your existing Active Directory or LDAP server as well increase security using YubiKeys or VeriSign VIP Access, browser PKI certificates and OneLogin's flexible security policies. OneLogin is pre-integrated with thousands of apps and handles all of your SSO needs in the cloud and behind the firewall.
Author: OneLogin, Inc.
Version: 2.1.2
Author URI: http://www.onelogin.com
*/

// Make sure we don't expose any info if called directly
if ( !function_exists( 'add_action' ) ) {
	echo 'Hi there!  I\'m just a plugin, not much I can do when called directly.';
	exit;
}

require_once plugin_dir_path(__FILE__)."php/functions.php";
require_once plugin_dir_path(__FILE__)."php/configuration.php";

// Localization
add_action( 'init', 'saml_load_translations');

// Check if exists SAML Messages
add_action('init', 'saml_checker', 1);

// add menu option for configuration
add_action('admin_menu', 'onelogin_saml_configuration');

// plugin hooks into authenticator system
if ((!isset($_GET['normal']) && !isset($_GET['saml_metadata']) && !isset($_GET['saml_validate_config'])) && !isset($_POST['wp-submit'])) {
	if (get_option('onelogin_saml_forcelogin')) {
		add_action('init', 'saml_sso', 1);
	}
	else if (!isset($_GET['loggedout'])) {
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
