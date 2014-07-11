<?php

function saml_lostpassword() {
	$target = get_option('onelogin_saml_customize_links_lost_password');
	if (!empty($target)) {
		wp_redirect($target);
		return false;
	}
}

function saml_user_register() {
	$target = get_option('onelogin_saml_customize_links_user_registration');
	if (!empty($target)) {
    	wp_redirect($target);
    	return false;
    }
}

function saml_sso() {
        $slo = get_option('onelogin_saml_slo');	

	if (!$slo) {
		if (isset($_GET['action']) && $_GET['action']  == 'logout') {
			wp_logout();
			return false;
		} else if (isset($_GET['loggedout']) && $_GET['loggedout']) {
			setcookie('saml_login', 0, time() - 3600, SITECOOKIEPATH );
			return false;
		}
	}

	if (is_user_logged_in()) {
		return true;
	}
	$auth = initialize_saml();
	if (isset($_SERVER['REQUEST_URI'])) {
		$auth->login($_SERVER['REQUEST_URI']);
	} else {
		$auth->login();
	}
	exit();
}

function saml_slo() {
	setcookie('saml_login', 0, time() - 3600, SITECOOKIEPATH );
	$auth = initialize_saml();
	$auth->logout(plugins_url('onelogin_saml.php?sls', dirname(__FILE__)));
}


function saml_acs() {
	$auth = initialize_saml();

	$auth->processResponse();

	$errors = $auth->getErrors();
	if (!empty($errors)) {
		echo __("<br>There was at least one error processing the SAML Response").': ';
		echo implode("<br>", $errors);
		echo '<br>'.__("Contact the administrator");
		exit();
	}

	$attrs = $auth->getAttributes();

	if (empty($attrs)) {
		$username = $auth->getNameId();
		$email = $username;
	} else {
		$usernameMapping = get_option('onelogin_saml_attr_mapping_username');
		$mailMapping =  get_option('onelogin_saml_attr_mapping_mail'); 

		if (!empty($usernameMapping) && isset($attrs[$usernameMapping]) && !empty($attrs[$usernameMapping][0])){
			$username = $attrs[$usernameMapping][0];
		}
		if (!empty($mailMapping) && isset($attrs[$mailMapping])  && !empty($attrs[$mailMapping][0])){
			$email = $attrs[$mailMapping][0];
		}
	}

	if (empty($username)) {
		echo __("The username could not be retrieved from the IdP and is required");
		exit();
	}
	else if (empty($email)) {
		echo __("The email could not be retrieved from the IdP and is required");
		exit();	
	} else {
		$userdata = array();
		$userdata['user_login'] = wp_slash($username);
		$userdata['user_email'] = wp_slash($email);
	}

	if (!empty($attrs)) {
		$firstNameMapping = get_option('onelogin_saml_attr_mapping_firstname');
		$lastNameMapping = get_option('onelogin_saml_attr_mapping_lastname');
		$roleMapping = get_option('onelogin_saml_attr_mapping_role');

		if (!empty($firstNameMapping) && isset($attrs[$firstNameMapping]) && !empty($attrs[$firstNameMapping][0])){
			$userdata['first_name'] = $attrs[$firstNameMapping][0];
		}

		if (!empty($lastNameMapping) && isset($attrs[$lastNameMapping])  && !empty($attrs[$lastNameMapping][0])){
			$userdata['last_name'] = $attrs[$lastNameMapping][0];
		}

		if (!empty($roleMapping) && isset($attrs[$roleMapping])){
			$adminsRole = explode(',', get_option('onelogin_saml_role_mapping_administrator'));
			$editorsRole = explode(',', get_option('onelogin_saml_role_mapping_editor'));
			$authorsRole = explode(',', get_option('onelogin_saml_role_mapping_author'));
			$contributorsRole = explode(',', get_option('onelogin_saml_role_mapping_contributor'));
			$subscribersRole = explode(',', get_option('onelogin_saml_role_mapping_subscriber'));

			$role = 0;

			foreach ($attrs[$roleMapping] as $samlRole) {
				$samlRole = trim($samlRole);
				if (empty($samlRole)) {
					break;	
				}
				else if (in_array($samlRole, $adminsRole)) {
					if ($role < 5) {
						$role = 5;
					}
					break;
				} else if (in_array($samlRole, $editorsRole)) {
					if ($role < 4) {
						$role = 4;
					}
					break;
				} else if (in_array($samlRole, $authorsRole)) {
					if ($role < 3) {
						$role = 3;
					}
					break;
				} else if (in_array($samlRole, $contributorsRole)) {
					if ($role < 2) {
						$role = 2;
					}
					break;
				} else if (in_array($samlRole, $subscribersRole)) {
					if ($role < 1) {
						$role = 1;
					}
					break;
				}
			}

			switch ($role) {
				case 5:
					$userdata['role'] = 'administrator';
					break;
				case 4:
					$userdata['role'] = 'editor';
					break;
				case 3:
					$userdata['role'] = 'author';
					break;
				case 2:
					$userdata['role'] = 'contributor';
					break;
				case 1:
				case 0:
				default:
					$userdata['role'] = 'subscriber';		
					break;

			}
		}
	}

	require_once ABSPATH . WPINC . '/registration.php';
	require_once ABSPATH . WPINC . '/pluggable.php';

	$matcher = get_option('onelogin_saml_account_matcher');

	if (empty($matcher) || $matcher == 'username') {
		$matcherValue = $userdata['user_login'];
		$user_id = username_exists($matcherValue);		
	} else {
		$matcherValue = $userdata['user_email'];
		$user_id = email_exists($matcherValue);
	}

	if ($user_id) {
		if (get_option('onelogin_saml_updateuser')) {
			$userdata['ID'] = $user_id;
			unset($userdata['$user_pass']);
			$user_id = wp_update_user($userdata);
		}
	} else if (get_option('onelogin_saml_autocreate')) {
		if (!validate_username($username)) {
			echo __("The username provided by the IdP"). ' "'. $username. '" '. __("is not valid and can't create the user at wordpress");
			return false;			
		}
		$userdata['user_pass'] = '@@@nopass@@@';
		$user_id = wp_insert_user($userdata);
	} else {
		echo __("User provided by the IdP "). ' "'. $matcherValue. '" '. __("not exists in wordpress and auto-provisioning is disabled.");
		return false;
	}

	if (is_a($user_id, 'WP_Error')) {
		$error = $user_id->get_error_messages();
		echo implode('<br>', $error);
		exit();
	} else if ($user_id) {
		wp_set_current_user($user_id);
		wp_set_auth_cookie($user_id);
		setcookie('saml_login', 1, time() + YEAR_IN_SECONDS, SITECOOKIEPATH );
		do_action('wp_login', $user_id);
	}

	$forcelogin = get_option('onelogin_saml_forcelogin');
	$slo = get_option('onelogin_saml_slo');

	if (isset($_REQUEST['RelayState'])) {
		if (!empty($_REQUEST['RelayState']) && !$slo && !$forcelogin && $_REQUEST['RelayState'] == '/wp-login.php') {
			wp_redirect(home_url());
		} else {
			if (strpos($_REQUEST['RelayState'], 'redirect_to') !== false) {
				$urlinfo = parse_url($_REQUEST['RelayState']);
				$parameters = array();
				parse_str($urlinfo['query'], $parameters);
				$target = urldecode($parameters['redirect_to']);
				wp_redirect(urldecode($parameters['redirect_to']));
			}  else {
				wp_redirect($_REQUEST['RelayState']);
			}
		}
	} else {
		wp_redirect(home_url());
	}
}

function saml_sls() {
	$auth = initialize_saml();
	$auth->processSLO();
	wp_redirect(home_url());
}

function initialize_saml() {
	require_once plugin_dir_path(__FILE__).'_toolkit_loader.php';
	require plugin_dir_path(__FILE__).'settings.php';

	try {
		$auth = new Onelogin_Saml2_Auth($settings);
	} catch (Exception $e) {
		echo '<br>'.__("The Onelogin SSO/SAML plugin is not correctly configured.").'<br>';
		print_r($e->getMessage());
		echo '<br>'.__("If you are the administrator").', <a href="'.get_site_url().'/wp-login.php?normal">'.__("access using your wordpress credentials").'</a> '.__("and fix the problem");
		exit();
	}

	return $auth;
}

// Prevent that the user change the email when the 'email' field is used as 'matcher'
class preventEmailChange
{
    function __construct()
    {
	$matcher = get_option('onelogin_saml_account_matcher');
	if ($matcher == 'email') {
        	add_action('admin_footer', array($this, 'disable_userprofile_fields'));
        }
    }

    function disable_userprofile_fields()
    {
        global $pagenow;
        if ($pagenow == 'profile.php' && !current_user_can( 'manage_options' )) {

            ?>
            <script>
                jQuery(document).ready(function ($) {
                    if ($('input[name=email]').length) {
                        $('input[name=email]').attr("disabled", "disabled");
                    }

                });
            </script>
        <?php
        }
    }
}

$preventEmailChange = new preventEmailChange();
