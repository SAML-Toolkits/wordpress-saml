<?php
/*
Plugin Name: OneLogin SAML SSO
Plugin URI: https://github.com/onelogin/wordpress-saml
Description: Give users secure one-click access to WordPress from OneLogin. This SAML integration eliminates passwords and allows you to authenticate users against your existing Active Directory or LDAP server as well increase security using YubiKeys or VeriSign VIP Access, browser PKI certificates and OneLogin's flexible security policies. OneLogin is pre-integrated with thousands of apps and handles all of your SSO needs in the cloud and behind the firewall.
Author: OneLogin, Inc.
Version: 3.0.0-composer
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

$prevent_reset_password = get_option('onelogin_saml_customize_action_prevent_reset_password', false);
if ($prevent_reset_password) {
	add_filter ('allow_password_reset', 'disable_password_reset' );
	function disable_password_reset() { return false; }
} else {
	add_action('lost_password', 'saml_lostpassword', 1);
	add_action('retrieve_password', 'saml_lostpassword' , 1);
	add_action('password_reset', 'saml_lostpassword', 1);
}

$action = isset($_REQUEST['action']) ? $_REQUEST['action'] : 'login';

// Handle SLO
if (isset($_COOKIE['saml_login']) && get_option('onelogin_saml_slo')) { 
	add_action('init', 'saml_slo', 1);
}

// Handle SSO
if (isset($_GET['saml_sso'])) {
	add_action('init', 'saml_sso', 1);
} else {
	$execute_sso = false;
	$saml_actions = isset($_GET['saml_metadata']) || (strpos($_SERVER['SCRIPT_NAME'], 'alternative_acs.php') !== FALSE);

	$wp_login_page = (strpos($_SERVER['SCRIPT_NAME'], 'wp-login.php') !== FALSE) && $action == 'login' && !isset($_GET['loggedout']);

	$want_to_local_login = isset($_GET['normal']) || (isset($_POST['log']) && isset($_POST['pwd']));
	$want_to_reset = $action == 'lostpassword' || $action == 'rp' || $action == 'resetpass' || (isset($_GET['checkemail']) &&  $_GET['checkemail'] == 'confirm');

	$local_wp_actions = $want_to_local_login || $want_to_reset;

	// plugin hooks into authenticator system
	if (!$local_wp_actions) {
		if ($wp_login_page) {
			$execute_sso = True;
		} else if (!$saml_actions && !isset($_GET['loggedout'])) {
			if (get_option('onelogin_saml_forcelogin')) {
				add_action('init', 'saml_sso', 1);
			}
		}
	} else if ($local_wp_actions) {
		$prevent_local_login = get_option('onelogin_saml_customize_action_prevent_local_login', false);

		if (($want_to_local_login && $prevent_local_login) || ($want_to_reset && $prevent_reset_password)) {		
			$execute_sso = True;
		}
	}


	$keep_local_login_form = get_option('onelogin_saml_keep_local_login', false);
	if ($execute_sso && !$keep_local_login_form) {
		add_action('init', 'saml_sso', 1);
	} else {
		add_filter('login_message', 'saml_custom_login_footer');
	}
}

add_action('user_register', 'saml_user_register', 1);
add_action('register_form', 'saml_user_register', 1);
