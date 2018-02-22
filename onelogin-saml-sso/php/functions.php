<?php

// Make sure we don't expose any info if called directly
if ( !function_exists( 'add_action' ) ) {
	echo 'Hi there!  I\'m just a plugin, not much I can do when called directly.';
	exit;
}

require_once "compatibility.php";


function saml_checker() {
	if (isset($_GET['saml_acs'])) {
		if (empty($_POST['SAMLResponse'])) {
			echo "That ACS endpoint expects a SAMLResponse value sent using HTTP-POST binding. Nothing was found";
			exit();
		}
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

function saml_custom_login_footer() {
	$saml_login_message = get_option('onelogin_saml_customize_links_saml_login');
	if (empty($saml_login_message)) {
		$saml_login_message = "SAML Login";
	}

    echo '<div style="font-size: 110%;padding:8px;background: #fff;text-align: center;"><a href="'.esc_url( get_site_url().'/wp-login.php?saml_sso') .'">'.esc_html($saml_login_message).'</a></div>';
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
		exit;
	}
}

function saml_user_register() {
	$target = get_option('onelogin_saml_customize_links_user_registration');
	if (!empty($target)) {
		wp_redirect($target);
		exit;
	}
}

function saml_sso() {
	if ( defined( 'WP_CLI' ) && WP_CLI ) {
		return true;
	}
	
	if (is_user_logged_in()) {
		return true;
	}
	$auth = initialize_saml();
	if (isset($_SERVER['REQUEST_URI']) && !isset($_GET['saml_sso'])) {
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
			$nameIdFormat = null;

			if (isset($_COOKIE[SAML_NAMEID_COOKIE])) {
				$nameId = $_COOKIE[SAML_NAMEID_COOKIE];
			}
			if (isset($_COOKIE[SAML_SESSIONINDEX_COOKIE])) {
				$sessionIndex = $_COOKIE[SAML_SESSIONINDEX_COOKIE];
			}
			if (isset($_COOKIE[SAML_NAMEID_FORMAT_COOKIE])) {
				$nameIdFormat = $_COOKIE[SAML_NAMEID_FORMAT_COOKIE];
			}

			$auth = initialize_saml();
			$auth->logout(home_url(), array(), $nameId, $sessionIndex, false, $nameIdFormat);
			return false;
		}
	}
}

function saml_role_order_get($role) {
	static $role_defaults = array(
		'administrator' => 1,
		'editor'        => 2,
		'author'        => 3,
		'contributor'   => 4,
		'subscriber'    => 5);
	$rv = get_option('onelogin_saml_role_order_'.$role);
	if (empty($rv))
		if (isset($role_defaults[$role])) {
			return $role_defaults[$role];
		} else {
			return PHP_INT_MAX;
		}
	else {
		return (int)$rv;
	}
}

function saml_role_order_compare($role1, $role2) {
	$r1 = saml_role_order_get($role1);
	$r2 = saml_role_order_get($role2);
	if ($r1 > $r2)
		return 1;
	else if ($r1 < $r2)
		return -1;
	else return 0;
}

function saml_acs() {
	$auth = initialize_saml();

	$auth->processResponse();

	$errors = $auth->getErrors();
	if (!empty($errors)) {
		echo '<br>'.__("There was at least one error processing the SAML Response").': ';
		foreach($errors as $error) {
			echo esc_html($error).'<br>';
		}
		echo __("Contact the administrator");
		exit();
	}

	setcookie(SAML_NAMEID_COOKIE, $auth->getNameId(), time() + YEAR_IN_SECONDS, SITECOOKIEPATH );
	setcookie(SAML_SESSIONINDEX_COOKIE, $auth->getSessionIndex(), time() + YEAR_IN_SECONDS, SITECOOKIEPATH );
	setcookie(SAML_NAMEID_FORMAT_COOKIE, $auth->getNameIdFormat(), time() + YEAR_IN_SECONDS, SITECOOKIEPATH );

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

			$all_roles = wp_roles()->get_names();
			$roles_found = array();

			foreach ($attrs[$roleMapping] as $samlRole) {
				$samlRole = trim($samlRole);
				if (empty($samlRole)) {
					continue;
				}

				foreach ($all_roles as $role_value => $role_name) {
					$matchList = explode(',', get_option('onelogin_saml_role_mapping_'.$role_value));
					if (in_array($samlRole, $matchList)) {
						$roles_found[$role_value] = true;
					}
				}
			}

			$userdata['role'] = get_option('default_role');
			uksort($roles_found, 'saml_role_order_compare');
			foreach ($roles_found as $role_value => $__role_found) {
				$userdata['role'] = $role_value;
				break;
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
			echo __("The username provided by the IdP"). ' "'. esc_attr($username). '" '. __("is not valid and can't create the user at wordpress");
			exit();
		}
		$userdata['user_pass'] = wp_generate_password();
		$user_id = wp_insert_user($userdata);
	} else {
		echo __("User provided by the IdP "). ' "'. esc_attr($matcherValue). '" '. __("does not exist in wordpress and auto-provisioning is disabled.");
		exit();
	}

	if (is_a($user_id, 'WP_Error')) {
		$errors = $user_id->get_error_messages();
		foreach($errors as $error) {
			echo esc_html($error).'<br>';
		}
		exit();
	} else if ($user_id) {
		wp_set_current_user($user_id);
		
		$rememberme = false;
		$remembermeMapping = get_option('onelogin_saml_attr_mapping_rememberme');
		if (!empty($remembermeMapping) && isset($attrs[$remembermeMapping]) && !empty($attrs[$remembermeMapping][0])) {
    			$rememberme = in_array($attrs[$remembermeMapping][0], array(1, true, '1', 'yes', 'on')) ? true : false;
		}
		wp_set_auth_cookie($user_id, $rememberme);

		setcookie(SAML_LOGIN_COOKIE, 1, time() + YEAR_IN_SECONDS, SITECOOKIEPATH );
	}

	do_action( 'onelogin_saml_attrs', $attrs, get_current_user(), get_current_user_id() );

	if (isset($_REQUEST['RelayState'])) {
		if (!empty($_REQUEST['RelayState']) && ((substr($_REQUEST['RelayState'], -strlen('/wp-login.php')) === '/wp-login.php') || (substr($_REQUEST['RelayState'], -strlen('/alternative_acs.php')) === '/alternative_acs.php'))) {
			wp_redirect(home_url());
		} else {
			if (strpos($_REQUEST['RelayState'], 'redirect_to') !== false) {
				$query = wp_parse_url($_REQUEST['RelayState'], PHP_URL_QUERY);
				parse_str( $query, $parameters );
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
	if (isset($_GET) && isset($_GET['SAMLRequest'])) {
		// Close session before send the LogoutResponse to the IdP
		$auth->processSLO(false, null, $retrieve_parameters_from_server, 'wp_logout');
	} else {
		$auth->processSLO(false, null, $retrieve_parameters_from_server);
	}
	$errors = $auth->getErrors();
	if (empty($errors)) {
		wp_logout();
		setcookie(SAML_LOGIN_COOKIE, 0, time() - 3600, SITECOOKIEPATH );
		setcookie(SAML_NAMEID_COOKIE, null, time() - 3600, SITECOOKIEPATH );
		setcookie(SAML_SESSIONINDEX_COOKIE, null, time() - 3600, SITECOOKIEPATH );
		setcookie(SAML_NAMEID_FORMAT_COOKIE, null, time() - 3600, SITECOOKIEPATH );

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
		echo __("SLS endpoint found an error.");
		foreach($errors as $error) {
			echo esc_html($error).'<br>';
		}
		exit();
	}
}

function saml_metadata() {
	require_once plugin_dir_path(__FILE__).'_toolkit_loader.php';
	require plugin_dir_path(__FILE__).'settings.php';

	$samlSettings = new OneLogin_Saml2_Settings($settings, true);
	$metadata = $samlSettings->getSPMetadata();

	header('Content-Type: text/xml');
	echo ent2ncr($metadata);
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
		echo esc_html($e->getMessage());
		echo '<br>'.__("If you are the administrator", 'onelogin-saml-sso').', <a href="'.esc_url( get_site_url().'/wp-login.php?normal').'">'.__("access using your wordpress credentials", 'onelogin-saml-sso').'</a> '.__("and fix the problem", 'onelogin-saml-sso');
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
						$('input[name=email]').attr("readonly", "readonly");
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
