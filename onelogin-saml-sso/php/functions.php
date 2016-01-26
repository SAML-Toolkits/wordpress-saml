<?php

// Make sure we don't expose any info if called directly
if ( !function_exists( 'add_action' ) ) {
	echo 'Hi there!  I\'m just a plugin, not much I can do when called directly.';
	exit;
}

function saml_checker() {
	if (isset($_GET['saml_acs'])) {
		saml_acs();
	}
	else if (isset($_GET['saml_sls'])) {
		saml_sls();
	} else if (isset($_GET['saml_metadata'])) {
		saml_metadata();
	} else if (isset($_GET['saml_validate_config'])) {
		saml_validate_config();
	}
}

function saml_load_translations() {
	$domain = 'onelogin-saml-sso';
	$mo_file = plugin_dir_path(dirname(__FILE__)) . 'lang/'.get_locale() . '/' . $domain  . '.mo';

	load_textdomain($domain, $mo_file ); 
	load_plugin_textdomain($domain, false, dirname( plugin_basename( __FILE__ ) ) . '/lang/'. get_locale() . '/' );
}

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
	$slo = get_option('onelogin_saml_slo');

	if (isset($_GET['action']) && $_GET['action']  == 'logout') {
		if (!$slo) {
			wp_logout();
			return false;
		} else {
			$nameId = null;
			$sessionIndex = null;
			if (isset($_COOKIE['saml_nameid'])) {
				$nameId = $_COOKIE['saml_nameid']; 
			}
			if (isset($_COOKIE['saml_sessionindex'])) {
				$sessionIndex = $_COOKIE['saml_sessionindex'];
			}
			
			$auth = initialize_saml();
			$auth->logout(home_url(), array(), $nameId, $sessionIndex);
			return false;
		}
	}
}


function saml_acs() {
	$auth = initialize_saml();

	$auth->processResponse();

	$errors = $auth->getErrors();
	if (!empty($errors)) {
		echo '<br>'.__("There was at least one error processing the SAML Response").': ';
		echo implode("<br>", $errors);
		echo '<br>'.__("Contact the administrator");
		exit();
	}

	setcookie('saml_nameid', $auth->getNameId(), time() + YEAR_IN_SECONDS, SITECOOKIEPATH );
	setcookie('saml_sessionindex', $auth->getSessionIndex(), time() + YEAR_IN_SECONDS, SITECOOKIEPATH );

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
			$multiValued = get_option('onelogin_saml_role_mapping_multivalued_in_one_attribute_value', false);
			if ($multiValued && count($attrs[$roleMapping]) == 1) {
				$roleValues = array();
				$pattern = get_option('onelogin_saml_role_mapping_multivalued_pattern');
				if (!empty($pattern)) {
					preg_match_all($pattern, $attrs[$roleMapping][0], $roleValues);
					if (!empty($roleValues)) {
    					$attrs[$roleMapping] = $roleValues[1];
					}
				} else {
					$roleValues = explode(';', $attrs[$roleMapping][0]);
					$attrs[$roleMapping] = $roleValues;
				}
			}

			$adminsRole = explode(',', get_option('onelogin_saml_role_mapping_administrator'));
			$editorsRole = explode(',', get_option('onelogin_saml_role_mapping_editor'));
			$authorsRole = explode(',', get_option('onelogin_saml_role_mapping_author'));
			$contributorsRole = explode(',', get_option('onelogin_saml_role_mapping_contributor'));
			$subscribersRole = explode(',', get_option('onelogin_saml_role_mapping_subscriber'));

			$foundCustomizedRole = false;

			/*  In order to use custom roles, you have 2 alternatives */

			/*  Alternative 1 
			 *  =============
			 *
			 *	Uncomment the wollowing lines and replace the values:
			 *   - First we assign possible OneLogin roles that we want to map with Wordpress Roles
			 *   - Then we asigned to the $userdata['role'] the name of the Wordpress role
			 */

			/*
				$customRole1 = array('value1', 'value2');  // value1 and value2 are roles of OneLogin platform that will be mapped to customRole1
				$customRole2 = array('value3');  // value3 is a role of OneLogin platformthat will be mapped to customRole2

				foreach ($attrs[$roleMapping] as $samlRole) {
					if (in_array($samlRole, $customRole1)) {
						$userdata['role'] = 'customrole1'; // Name of the role -> customrole1
						$foundCustomized = true;
						break;
					} else if (in_array($samlRole, $customRole2)) {
						$userdata['role'] = 'customrole2'; // Name of the role -> customrole2
						$foundCustomized = true;
						break;
					}
				}
			*/

			/*  Alternative 2
			 *  =============
			 *
			 *  - Add the following commented block to a plugin or a themes functions file 
			 *    replacing CUSTOM_ROLE_NAME with the role name, not the display name the actual unique role name. 
			 */

			/*
				function add_custom_rolemapping($custom_roles) { 
				   
					$extra_custom_roles = array('CUSTOM_ROLE_NAME1','CUSTOM_ROLE_NAME2'); 

					// combine the two arrays 
					$custom_roles = array_merge($extra_custom_roles, $custom_roles); 

					return $custom_roles; 
				}

				add_filter('onelogin_custom_roles', 'add_custom_rolemapping'); 
			*/


			if (has_filter('onelogin_custom_roles')) {
				$customRoles = array();
				$customRoles = apply_filters('onelogin_custom_roles', $customRoles);
				$customRoles = array_unique($customRoles);
				foreach ($attrs[$roleMapping] as $samlRole) {
					if (in_array($samlRole, $customRoles) && $GLOBALS['wp_roles']->is_role( $samlRole)) {
						$userdata['role'] = $samlRole;
						$foundCustomizedRole = true; 
						break; 						}
				}
    			}
			

			if (!$foundCustomizedRole) {
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
						$userdata['role'] = 'subscriber';
						break;
					case 0:
					default:
						$userdata['role'] = get_option('default_role');
						break;
				}
			}
		}
	}
	
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

			// Prevent to change the role to the superuser (id=1)
			if ($user_id == 1 && isset($userdata['role'])) {
				unset($userdata['role']);
			}

			$user_id = wp_update_user($userdata);
		}
	} else if (get_option('onelogin_saml_autocreate')) {
		if (!validate_username($username)) {
			echo __("The username provided by the IdP"). ' "'. $username. '" '. __("is not valid and can't create the user at wordpress");
			exit();
		}
		$userdata['user_pass'] = wp_generate_password();
		$user_id = wp_insert_user($userdata);
	} else {
		echo __("User provided by the IdP "). ' "'. $matcherValue. '" '. __("does not exist in wordpress and auto-provisioning is disabled.");
		exit();
	}

	if (is_a($user_id, 'WP_Error')) {
		$error = $user_id->get_error_messages();
		echo implode('<br>', $error);
		exit();
	} else if ($user_id) {
		wp_set_current_user($user_id);
		wp_set_auth_cookie($user_id);
		setcookie('saml_login', 1, time() + YEAR_IN_SECONDS, SITECOOKIEPATH );
				#do_action('wp_login', $user_id);
		#wp_signon($user_id);
	}

	if (isset($_REQUEST['RelayState'])) {
		if (!empty($_REQUEST['RelayState']) && (substr($_REQUEST['RelayState'], -strlen('/wp-login.php')) === '/wp-login.php')) {
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
	exit();
}

function saml_sls() {
	$auth = initialize_saml();
	$retrieve_parameters_from_server = get_option('onelogin_saml_advanced_settings_retrieve_parameters_from_server', false);
	$auth->processSLO(false, null, $retrieve_parameters_from_server);
		$errors = $auth->getErrors();
	if (empty($errors)) {
		wp_logout();
		setcookie('saml_login', 0, time() - 3600, SITECOOKIEPATH );
		setcookie('saml_nameid', null, time() - 3600, SITECOOKIEPATH );
		setcookie('saml_sessionindex', null, time() - 3600, SITECOOKIEPATH );

		if (get_option('onelogin_saml_forcelogin') && get_option('onelogin_saml_customize_stay_in_wordpress_after_slo')) {
			wp_redirect(home_url().'/wp-login.php?loggedout=true');
		} else {
			if (isset($_REQUEST['RelayState'])) {
				wp_redirect($_REQUEST['RelayState']);
			} else {
				wp_redirect(home_url());
			}
		}
		exit();
	} else {
		echo __("SLS endpoint found an error.").$auth->getLastErrorReason();
		exit();
	}
}

function saml_metadata() {
	$auth = initialize_saml();
	$settings = $auth->getSettings();
	$metadata = $settings->getSPMetadata();
	
	header('Content-Type: text/xml');
	echo $metadata;
	exit();
}


function saml_validate_config() {
	saml_load_translations();
	require_once plugin_dir_path(__FILE__).'_toolkit_loader.php';
	require plugin_dir_path(__FILE__).'settings.php';
	require_once plugin_dir_path(__FILE__)."validate.php";
	exit();
}

function initialize_saml() {
	require_once plugin_dir_path(__FILE__).'_toolkit_loader.php';
	require plugin_dir_path(__FILE__).'settings.php';

	try {
		$auth = new Onelogin_Saml2_Auth($settings);
	} catch (Exception $e) {
		echo '<br>'.__("The Onelogin SSO/SAML plugin is not correctly configured.", 'onelogin-saml-sso').'<br>';
		print_r($e->getMessage());
		echo '<br>'.__("If you are the administrator", 'onelogin-saml-sso').', <a href="'.get_site_url().'/wp-login.php?normal">'.__("access using your wordpress credentials", 'onelogin-saml-sso').'</a> '.__("and fix the problem", 'onelogin-saml-sso');
		exit();
	}

	return $auth;
}

// Prevent that the user change important fields
class preventLocalChanges
{
	function __construct()
	{
		if (get_option('onelogin_saml_customize_action_prevent_change_mail', false)) {
			add_action('admin_footer', array($this, 'disable_email'));
		}
		if (get_option('onelogin_saml_customize_action_prevent_change_password', false)) {
			add_action('admin_footer', array($this, 'disable_password'));
		}
	}

	function disable_email()
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

	function disable_password()
	{
		global $pagenow;
		if ($pagenow == 'profile.php' && !current_user_can( 'manage_options' )) {

			?>
			<script>
				jQuery(document).ready(function ($) {
					$('tr[id=password]').hide();
					$('tr[id=password]').next().hide();
				});
			</script>
		<?php
		}
	}

}

$preventLocalChanges = new preventLocalChanges();
