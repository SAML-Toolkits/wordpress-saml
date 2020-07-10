<?php
// Make sure we don't expose any info if called directly
if ( !function_exists( 'add_action' ) ) {
	echo 'Hi there!  I\'m just a plugin, not much I can do when called directly.';
	exit;
}


require_once "_toolkit_loader.php";
require_once "compatibility.php";

use OneLogin\Saml2\Constants;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

function sanitize_array_int($integers) {
	$sanitized_array = array_map( 'intval', $integers );
	return $sanitized_array;
}

function onelogin_saml_configuration_render() {
	$config_title = __("SSO/SAML Settings", 'onelogin-saml-sso');
	?>
		<div class="wrap">
			<div class="alignleft">
				<a href="http://www.onelogin.com"><img src="<?php echo esc_url( plugins_url('onelogin.png', dirname(__FILE__)) );?>"></a>
			</div>
			<div class="alignright">
				<a href="<?php echo esc_url( get_site_url().'/wp-login.php?saml_metadata' ); ?>" target="blank"><?php echo __("Go to the metadata of this SP", 'onelogin-saml-sso');?></a><br>
				<a href="<?php echo esc_url( get_site_url().'/wp-login.php?saml_validate_config' ); ?>" target="blank"><?php echo __("Once configured, validate here your OneLogin SSO/SAML Settings", 'onelogin-saml-sso');?></a>
			</div>
			<div style="clear:both"></div>
			<h2><?php echo esc_html( $config_title ); ?></h2>
			<form action="options.php" method="post">

				<?php settings_fields('onelogin_saml_configuration'); ?>
				<?php do_settings_sections('onelogin_saml_configuration'); ?>

				<p class="submit">
					<input type="submit" name="Submit" class="button-primary" value="<?php esc_attr_e('Save Changes') ?>" />
				</p>

			</form>
		</div>
	<?php
}

function onelogin_saml_configuration() {
	$current_screen = add_submenu_page( 'options-general.php', 'SSO/SAML Settings', 'SSO/SAML Settings', 'manage_options', 'onelogin_saml_configuration', 'onelogin_saml_configuration_render');

	$helpText = '<p>' . __('This plugin provides single sign-on via SAML and gives users one-click access to their WordPress accounts from identity providers like OneLogin', 'onelogin-saml-sso') . '</p>' .
		'<p><strong>' . __('For more information', 'onelogin-saml-sso') . '</strong> '.__("access to the", 'onelogin-saml-sso').' <a href="https://onelogin.zendesk.com/hc/en-us/articles/201173454-Configuring-SAML-for-WordPress" target="_blank">'.__("Plugin Info", 'onelogin-saml-sso').'</a> ' .
		__("or visit", 'onelogin-saml-sso') . ' <a href="http://onelogin.com/" target="_blank">OneLogin, Inc.</a>' . '</p>';

	$current_screen = convert_to_screen($current_screen);
	WP_Screen::add_old_compat_help($current_screen, $helpText);

	$option_group = 'onelogin_saml_configuration';

	$sections = get_sections();
	foreach ($sections as $name => $description) {
		add_settings_section($name, $description, 'plugin_section_'.$name.'_text', $option_group);
	}

	$fields = get_onelogin_saml_settings();

	$special_fields = array(
		'onelogin_saml_role_mapping_multivalued_in_one_attribute_value',
		'onelogin_saml_role_mapping_multivalued_pattern'
	);

	foreach ($fields as $section => $settings) {
		foreach ($settings as $name => $data) {
			$description = $data[0];
			$field_type = $data[1];
			register_setting($option_group, $name);
			if ($section === 'role_mapping' && !in_array($name, $special_fields, true)) {
				$role_value = str_replace('onelogin_saml_role_mapping_', '', $name);
				add_settings_field($name, $description, "plugin_setting_".$field_type."_onelogin_saml_role_mapping", $option_group, 'role_mapping', $role_value);
			} else if ($section === 'role_precedence') {
				$role_value = str_replace('onelogin_saml_role_order_', '', $name);
				add_settings_field($name, $description, "plugin_setting_".$field_type."_onelogin_saml_role_order", $option_group, 'role_precedence', $role_value);
			} else {
				add_settings_field($name, $description, "plugin_setting_".$field_type."_$name", $option_group, $section);
			}
		}
	}

	wp_create_nonce('onelogin_saml_configuration');
}

function plugin_setting_boolean_onelogin_saml_enabled($network = false) {
	$value = $network ? get_site_option('onelogin_saml_enabled') : get_option('onelogin_saml_enabled');
	echo '<input type="checkbox" name="onelogin_saml_enabled" id="onelogin_saml_enabled"
		  '.($value ? 'checked="checked"': '').'>'.
		  '<p class="description">'.__("Check it in order to enable the SAML plugin.", 'onelogin-saml-sso').'</p>';
}

function plugin_setting_string_onelogin_saml_idp_entityid($network = false) {
	echo '<input type="text" name="onelogin_saml_idp_entityid" id="onelogin_saml_idp_entityid"
		  value= "'.esc_attr($network ? get_site_option('onelogin_saml_idp_entityid') : get_option('onelogin_saml_idp_entityid')).'" size="80">'.
		  '<p class="description">'.__('Identifier of the IdP entity. ("Issuer URL")', 'onelogin-saml-sso').'</p>';
}

function plugin_setting_string_onelogin_saml_idp_sso($network = false) {
	echo '<input type="text" name="onelogin_saml_idp_sso" id="onelogin_saml_idp_sso"
		  value= "'.esc_url($network ? get_site_option('onelogin_saml_idp_sso') : get_option('onelogin_saml_idp_sso')).'" size="80">'.
		  '<p class="description">'.__('SSO endpoint info of the IdP. URL target of the IdP where the SP will send the Authentication Request. ("SAML 2.0 Endpoint (HTTP)")', 'onelogin-saml-sso').'</p>';
}

function plugin_setting_string_onelogin_saml_idp_slo($network = false) {
	echo '<input type="text" name="onelogin_saml_idp_slo" id="onelogin_saml_idp_slo"
		  value= "'.esc_url($network ? get_site_option('onelogin_saml_idp_slo') : get_option('onelogin_saml_idp_slo')).'" size="80">'.
		  '<p class="description">'.__('SLO endpoint info of the IdP. URL target of the IdP where the SP will send the SLO Request. ("SLO Endpoint (HTTP)")', 'onelogin-saml-sso').'</p>';
}

function plugin_setting_textarea_onelogin_saml_idp_x509cert($network = false) {
	echo '<textarea name="onelogin_saml_idp_x509cert" id="onelogin_saml_idp_x509cert" style="width:600px; height:220px; font-size:12px; font-family:courier,arial,sans-serif;">';
	echo esc_textarea($network ? get_site_option('onelogin_saml_idp_x509cert') : get_option('onelogin_saml_idp_x509cert'));
	echo '</textarea>';
	echo '<p class="description">'.__('Public x509 certificate of the IdP.  ("X.509 certificate")', 'onelogin-saml-sso');
}

function plugin_setting_boolean_onelogin_saml_advanced_idp_lowercase_url_encoding($network = false) {
	$value = $network ? get_site_option('onelogin_saml_advanced_idp_lowercase_url_encoding') : get_option('onelogin_saml_advanced_idp_lowercase_url_encoding');

	echo '<input type="checkbox" name="onelogin_saml_advanced_idp_lowercase_url_encoding" id="onelogin_saml_advanced_idp_lowercase_url_encoding"
		  '.($value ? 'checked="checked"': '').'>'.
		  '<p class="description">'.__('Some IdPs like ADFS can use lowercase URL encoding, but the plugin expects uppercase URL encoding, enable it to fix incompatibility issues.', 'onelogin-saml-sso').'</p>';
}

function plugin_setting_boolean_onelogin_saml_autocreate($network = false) {
	$value = $network ? get_site_option('onelogin_saml_autocreate') : get_option('onelogin_saml_autocreate');
	echo '<input type="checkbox" name="onelogin_saml_autocreate" id="onelogin_saml_autocreate"
		  '.($value ? 'checked="checked"': '').'>'.
		  '<p class="description">'.__('Auto-provisioning. If user not exists,  WordPress will create a new user with the data provided by the IdP.<br>Review the Mapping section.', 'onelogin-saml-sso').'</p>';
}

function plugin_setting_boolean_onelogin_saml_updateuser($network = false) {
	$value = $network ? get_site_option('onelogin_saml_updateuser') : get_option('onelogin_saml_updateuser');
	echo '<input type="checkbox" name="onelogin_saml_updateuser" id="onelogin_saml_updateuser"
		  '.($value ? 'checked="checked"': '').'>'.
		  '<p class="description">'.__('Auto-update. WordPress will update the account of the user with the data provided by the IdP.<br>Review the Mapping section.', 'onelogin-saml-sso').'</p>';
}

function plugin_setting_boolean_onelogin_saml_forcelogin($network = false) {
	$value = $network ? get_site_option('onelogin_saml_forcelogin') : get_option('onelogin_saml_forcelogin');
	echo '<input type="checkbox" name="onelogin_saml_forcelogin" id="onelogin_saml_forcelogin"
		  '.($value ? 'checked="checked"': '').'>'.
		  '<p class="description">'.__('Protect WordPress and force the user to authenticate at the IdP in order to access when any WordPress page is loaded and no active session.', 'onelogin-saml-sso').'</p>';
}

function plugin_setting_boolean_onelogin_saml_slo($network = false) {
	$value = $network ? get_site_option('onelogin_saml_slo') : get_option('onelogin_saml_slo');
	echo '<input type="checkbox" name="onelogin_saml_slo" id="onelogin_saml_slo"
		  '.($value ? 'checked="checked"': '').'>'.
		  '<p class="description">'.__('Enable/disable Single Log Out. SLO  is a complex functionality, the most common SLO implementation is based on front-channel (redirections), sometimes if the SLO workflow fails a user can be blocked in an unhandled view. If the admin does not control the set of apps involved in the SLO process, you may want to disable this functionality to avoid more problems than benefits.', 'onelogin-saml-sso').'</p>';
}

function plugin_setting_boolean_onelogin_saml_keep_local_login($network = false) {
	$value = $network ? get_site_option('onelogin_saml_keep_local_login') : get_option('onelogin_saml_keep_local_login');
	echo '<input type="checkbox" name="onelogin_saml_keep_local_login" id="onelogin_saml_keep_local_login"
		  '.($value ? 'checked="checked"': '').'>'.
		  '<p class="description">'.__('Enable/disable the normal login form. If disabled, instead of the WordPress login form, WordPress will excecute the SP-initiated SSO flow. If enabled the normal login form is displayed and a link to initiate that flow is displayed.', 'onelogin-saml-sso').'</p>';
}

function plugin_setting_select_onelogin_saml_account_matcher($network = false) {
	$value = $network ? get_site_option('onelogin_saml_account_matcher') : get_option('onelogin_saml_account_matcher');
	echo '<select name="onelogin_saml_account_matcher" id="onelogin_saml_account_matcher">
		  <option value="username" '.($value === 'username'?'selected="selected"':'').'>'.__("Username", 'onelogin-saml-sso').'</option>
		  <option value="email" '.($value === 'email'? 'selected="selected"':'').'>'.__("E-mail", 'onelogin-saml-sso').'</option>
		</select>'.
		'<p class="description">'.__('Select what field will be used in order to find the user account. If "email", the plugin will prevent the user from changing their email address in their user profile.', 'onelogin-saml-sso').'</p>';
}

function plugin_setting_boolean_onelogin_saml_multirole($network = false) {
    $value = $network ? get_site_option('onelogin_saml_multirole') : get_option('onelogin_saml_multirole');
    echo '<input type="checkbox" name="onelogin_saml_multirole" id="onelogin_saml_multirole"
          '.($value ? 'checked="checked"': '').'>'.
          '<p class="description">'.__('Enable/disable the support of multiple roles. Not available in multi-site wordpress', 'onelogin-saml-sso').'</p>';
}

function plugin_setting_boolean_onelogin_saml_alternative_acs($network = false) {
	$value = $network ? get_site_option('onelogin_saml_alternative_acs') : get_option('onelogin_saml_alternative_acs');
	echo '<input type="checkbox" name="onelogin_saml_alternative_acs" id="onelogin_saml_alternative_acs"
		  '.($value ? 'checked="checked"': '').'>'.
		  '<p class="description">'.__('Enable if you want to use a different Assertion Consumer Endpoint than <code>/wp-login.php?saml_acs</code> (Required if using WPEngine or any similar hosting service that prevents POST on <code>wp-login.php</code>). You must update the IdP with the new value after enabling/disabling this setting.', 'onelogin-saml-sso').'</p>';
}

function plugin_setting_textarea_onelogin_saml_trusted_url_domains($network = false) {
	echo '<textarea name="onelogin_saml_trusted_url_domains" id="onelogin_saml_trusted_url_domains" style="width:600px; height:220px; font-size:12px; font-family:courier,arial,sans-serif;">';
	echo esc_textarea($network ? get_site_option('onelogin_saml_trusted_url_domains') : get_option('onelogin_saml_trusted_url_domains'));
	echo '</textarea>';
	echo '<p class="description">'.__("List here any domain (comma- separated) that you want to be trusted in the RelayState parameter, otherwise the parameter will be ignored. You don't need to include the domain of the wordpress instance", 'onelogin-saml-sso');
}

function plugin_setting_string_onelogin_saml_attr_mapping_username($network = false) {
	$value = $network ? get_site_option('onelogin_saml_attr_mapping_username') : get_option('onelogin_saml_attr_mapping_username');
	echo '<input type="text" name="onelogin_saml_attr_mapping_username" id="onelogin_saml_attr_mapping_username"
		  value= "'.esc_html($value).'" size="30">';
}

function plugin_setting_string_onelogin_saml_attr_mapping_mail($network = false) {
	$value = $network ? get_site_option('onelogin_saml_attr_mapping_mail') : get_option('onelogin_saml_attr_mapping_mail');
	echo '<input type="text" name="onelogin_saml_attr_mapping_mail" id="onelogin_saml_attr_mapping_mail"
		  value= "'.esc_attr($value).'" size="30">';
}

function plugin_setting_string_onelogin_saml_attr_mapping_firstname($network = false) {
	$value = $network ? get_site_option('onelogin_saml_attr_mapping_firstname') : get_option('onelogin_saml_attr_mapping_firstname');
	echo '<input type="text" name="onelogin_saml_attr_mapping_firstname" id="onelogin_saml_attr_mapping_firstname"
		  value= "'.esc_attr($value).'" size="30">';
}

function plugin_setting_string_onelogin_saml_attr_mapping_lastname($network = false) {
	$value = $network ? get_site_option('onelogin_saml_attr_mapping_lastname') : get_option('onelogin_saml_attr_mapping_lastname');
	echo '<input type="text" name="onelogin_saml_attr_mapping_lastname" id="onelogin_saml_attr_mapping_lastname"
		  value= "'.esc_attr($value).'" size="30">';
}

function plugin_setting_string_onelogin_saml_attr_mapping_rememberme($network = false) {
	$value = $network ? get_site_option('onelogin_saml_attr_mapping_rememberme') : get_option('onelogin_saml_attr_mapping_rememberme');
	echo '<input type="text" name="onelogin_saml_attr_mapping_rememberme" id="onelogin_saml_attr_mapping_rememberme"
		  value= "'.esc_html($value).'" size="30">';
}

function plugin_setting_string_onelogin_saml_attr_mapping_role($network = false) {
	$value = $network ? get_site_option('onelogin_saml_attr_mapping_role') : get_option('onelogin_saml_attr_mapping_role');
	echo '<input type="text" name="onelogin_saml_attr_mapping_role" id="onelogin_saml_attr_mapping_role"
		  value= "'.esc_attr($value).'" size="30">'.
		  '<p class="description">'.__("The attribute that contains the role of the user, For example 'memberOf'. If WordPress can't figure what role assign to the user, it will assign the default role defined at the general settings.", 'onelogin-saml-sso').'</p>';
}

function plugin_setting_string_onelogin_saml_role_mapping($role_value, $network = false) {
	$value = $network ? get_site_option('onelogin_saml_role_mapping_'.$role_value) : get_option('onelogin_saml_role_mapping_'.$role_value);
	if ($network) {
		$value = get_site_option('onelogin_saml_role_mapping_'.$role_value);
	} else {
		$value = get_option('onelogin_saml_role_mapping_'.$role_value);
	}
	echo '<input type="text" name="onelogin_saml_role_mapping_'.esc_attr($role_value).'" id="onelogin_saml_role_mapping_'.esc_attr($role_value).'"
		  value= "'.esc_attr($value).'" size="30">';
}

function plugin_setting_string_onelogin_saml_role_order($role_value, $network = false) {
	$value = $network ? get_site_option('onelogin_saml_role_order_'.$role_value) : get_option('onelogin_saml_role_order_'.$role_value);
	echo '<input type="text" name="onelogin_saml_role_order_'.esc_attr($role_value).'" id="onelogin_saml_role_order_'.esc_attr($role_value).'"
		  value= "'.esc_attr($value).'" size="3">';
}

function plugin_setting_boolean_onelogin_saml_role_mapping_multivalued_in_one_attribute_value($network = false) {
	$value = $network ? get_site_option('onelogin_saml_role_mapping_multivalued_in_one_attribute_value') : get_option('onelogin_saml_role_mapping_multivalued_in_one_attribute_value');
	echo '<input type="checkbox" name="onelogin_saml_role_mapping_multivalued_in_one_attribute_value" id="onelogin_saml_role_mapping_multivalued_in_one_attribute_value"
		  '.($value ? 'checked="checked"': '').'>
		  <p class="description">'.__("Sometimes role values are provided in an unique attribute statement (instead multiple attribute statements). If that is the case, activate this and the plugin will try to split those values by ;<br>Use a regular expression pattern in order to extract complex data.", 'onelogin-saml-sso').'</p>';
}

function plugin_setting_string_onelogin_saml_role_mapping_multivalued_pattern($network = false) {
	$value = $network ? get_site_option('onelogin_saml_role_mapping_multivalued_pattern') : get_option('onelogin_saml_role_mapping_multivalued_pattern');
	echo '<input type="text" name="onelogin_saml_role_mapping_multivalued_pattern" id="onelogin_saml_role_mapping_multivalued_pattern"
		  value= "'.esc_attr($value).'" size="70">
		  <p class="description">'.__("Regular expression that extract roles from complex multivalued data (required to active the previous option).<br> E.g. If the SAMLResponse has a role attribute like: CN=admin;CN=superuser;CN=europe-admin; , use the regular expression <code>/CN=([A-Z0-9\s _-]*);/i</code> to retrieve the values. Or use <code>/CN=([^,;]*)/</code>", 'onelogin-saml-sso').'</p>';
}

function plugin_setting_boolean_onelogin_saml_customize_action_prevent_local_login($network = false) {
	$value = $network ? get_site_option('onelogin_saml_customize_action_prevent_local_login') : get_option('onelogin_saml_customize_action_prevent_local_login');
	echo '<input type="checkbox" name="onelogin_saml_customize_action_prevent_local_login" id="onelogin_saml_customize_action_prevent_local_login"
		  '.($value ? 'checked="checked"': '').'>
		  <p class="description">'.__("Check to disable the <code>?normal</code> option and offer the local login when it is not enabled.", 'onelogin-saml-sso').'</p>';
}

function plugin_setting_boolean_onelogin_saml_customize_action_prevent_reset_password($network = false) {
	$value = $network ? get_site_option('onelogin_saml_customize_action_prevent_reset_password') : get_option('onelogin_saml_customize_action_prevent_reset_password');
	echo '<input type="checkbox" name="onelogin_saml_customize_action_prevent_reset_password" id="onelogin_saml_customize_action_prevent_reset_password"
		  '.($value ? 'checked="checked"': '').'>
		  <p class="description">'.__("Check to disable resetting passwords in WordPress.", 'onelogin-saml-sso').'</p>';
}

function plugin_setting_boolean_onelogin_saml_customize_action_prevent_change_password($network = false) {
	$value = $network ? get_site_option('onelogin_saml_customize_action_prevent_change_password') : get_option('onelogin_saml_customize_action_prevent_change_password');
	echo '<input type="checkbox" name="onelogin_saml_customize_action_prevent_change_password" id="onelogin_saml_customize_action_prevent_change_password"
		  '.($value ? 'checked="checked"': '').'>
		  <p class="description">'.__("Check to disable changing passwords in WordPress.", 'onelogin-saml-sso').'</p>';
}

function plugin_setting_boolean_onelogin_saml_customize_action_prevent_change_mail($network = false) {
	$value = $network ? get_site_option('onelogin_saml_customize_action_prevent_change_mail') : get_option('onelogin_saml_customize_action_prevent_change_mail');
	echo '<input type="checkbox" name="onelogin_saml_customize_action_prevent_change_mail" id="onelogin_saml_customize_action_prevent_change_mail"
		  '.($value ? 'checked="checked"': '').'>
		  <p class="description">'.__("Check to disable changing the email addresses in WordPress (recommended if you are using email to match accounts).", 'onelogin-saml-sso').'</p>';
}

function plugin_setting_boolean_onelogin_saml_customize_stay_in_wordpress_after_slo($network = false) {
	$value = $network ? get_site_option('onelogin_saml_customize_stay_in_wordpress_after_slo') : get_option('onelogin_saml_customize_stay_in_wordpress_after_slo');
	echo '<input type="checkbox" name="onelogin_saml_customize_stay_in_wordpress_after_slo" id="onelogin_saml_customize_stay_in_wordpress_after_slo"
		  '.($value ? 'checked="checked"': '').'>
		  <p class="description">'.__("If SLO and Force SAML login are enabled, after the SLO process you will be redirected to the WordPress main page and a SAML SSO process will start. Check this to prevent that and stay at the WordPress login form. ", 'onelogin-saml-sso').'</p>';
}

function plugin_setting_string_onelogin_saml_customize_links_user_registration($network = false) {
	$value = $network ? get_site_option('onelogin_saml_customize_links_user_registration') : get_option('onelogin_saml_customize_links_user_registration');
	echo '<input type="text" name="onelogin_saml_customize_links_user_registration" id="onelogin_saml_customize_links_user_registration"
		  value= "'.esc_url($value).'" size="80">
		  <p class="description">'.__("Override the user registration link. ", 'onelogin-saml-sso').'</p>';
}

function plugin_setting_string_onelogin_saml_customize_links_lost_password($network = false) {
	$value = $network ? get_site_option('onelogin_saml_customize_links_lost_password') : get_option('onelogin_saml_customize_links_lost_password');
	echo '<input type="text" name="onelogin_saml_customize_links_lost_password" id="onelogin_saml_customize_links_lost_password"
		  value= "'.esc_url($value).'" size="80">
			  <p class="description">'.__("Override the lost password link. (Prevent reset password must be deactivated or the SAML SSO will be used.)", 'onelogin-saml-sso').'</p>';
}

function plugin_setting_string_onelogin_saml_customize_links_saml_login($network = false) {
	$value = $network ? get_site_option('onelogin_saml_customize_links_saml_login') : get_option('onelogin_saml_customize_links_saml_login');
	echo '<input type="text" name="onelogin_saml_customize_links_saml_login" id="onelogin_saml_customize_links_saml_login"
		  value= "'.esc_attr($value).'" size="80">
			  <p class="description">'.__("If 'Keep Local login' enabled, this will be showed as message at the SAML link.", 'onelogin-saml-sso').'</p>';
}

function plugin_setting_boolean_onelogin_saml_advanced_settings_debug($network = false) {
	$value = $network ? get_site_option('onelogin_saml_advanced_settings_debug') : get_option('onelogin_saml_advanced_settings_debug');
	echo '<input type="checkbox" name="onelogin_saml_advanced_settings_debug" id="onelogin_saml_advanced_settings_debug"
		  '.($value ? 'checked="checked"': '').'>'.
		  '<p class="description">'.__('Enable for debugging the SAML workflow. Errors and Warnings will be shown.', 'onelogin-saml-sso').'</p>';
}

function plugin_setting_boolean_onelogin_saml_advanced_settings_strict_mode($network = false) {
	$value = $network ? get_site_option('onelogin_saml_advanced_settings_strict_mode') : get_option('onelogin_saml_advanced_settings_strict_mode');
	echo '<input type="checkbox" name="onelogin_saml_advanced_settings_strict_mode" id="onelogin_saml_advanced_settings_strict_mode"
		  '.($value ? 'checked="checked"': '').'>'.
		  '<p class="description">'.__("If Strict Mode is enabled, WordPress will reject unsigned or unencrypted messages if it expects them signed or encrypted.
		   It will also reject messages if not strictly following the SAML standard: Destination, NameId, Conditions ... are also validated.", 'onelogin-saml-sso').'</p>';
}

function plugin_setting_string_onelogin_saml_advanced_settings_sp_entity_id($network = false) {
	$value = $network ? get_site_option('onelogin_saml_advanced_settings_sp_entity_id') : get_option('onelogin_saml_advanced_settings_sp_entity_id');
	echo '<input type="text" name="onelogin_saml_advanced_settings_sp_entity_id" id="onelogin_saml_advanced_settings_sp_entity_id"
		  value= "'.esc_html($value).'" size="80">'.
		  '<p class="description">'.__("Set the Entity ID for the Service Provider. If not provided, 'php-saml' will be used.", 'onelogin-saml-sso').'</p>';
}


function plugin_setting_boolean_onelogin_saml_advanced_settings_nameid_encrypted($network = false) {
	$value = $network ? get_site_option('onelogin_saml_advanced_settings_nameid_encrypted') : get_option('onelogin_saml_advanced_settings_nameid_encrypted');
	echo '<input type="checkbox" name="onelogin_saml_advanced_settings_nameid_encrypted" id="onelogin_saml_advanced_settings_nameid_encrypted"
		  '.($value ? 'checked="checked"': '').'>'.
		  '<p class="description">'.__('The nameID sent by this SP will be encrypted.', 'onelogin-saml-sso').'</p>';
}

function plugin_setting_boolean_onelogin_saml_advanced_settings_authn_request_signed($network = false) {
	$value = $network ? get_site_option('onelogin_saml_advanced_settings_authn_request_signed') : get_option('onelogin_saml_advanced_settings_authn_request_signed');
	echo '<input type="checkbox" name="onelogin_saml_advanced_settings_authn_request_signed" id="onelogin_saml_advanced_settings_authn_request_signed"
		  '.($value ? 'checked="checked"': '').'>'.
		  '<p class="description">'.__('The samlp:AuthnRequest messages sent by this SP will be signed.', 'onelogin-saml-sso').'</p>';
}

function plugin_setting_boolean_onelogin_saml_advanced_settings_logout_request_signed($network = false) {
	$value = $network ? get_site_option('onelogin_saml_advanced_settings_logout_request_signed') : get_option('onelogin_saml_advanced_settings_logout_request_signed');
	echo '<input type="checkbox" name="onelogin_saml_advanced_settings_logout_request_signed" id="onelogin_saml_advanced_settings_logout_request_signed"
		  '.($value ? 'checked="checked"': '').'>'.
		  '<p class="description">'.__('The samlp:logoutRequest messages sent by this SP will be signed.', 'onelogin-saml-sso').'</p>';
}

function plugin_setting_boolean_onelogin_saml_advanced_settings_logout_response_signed($network = false) {
	$value = $network ? get_site_option('onelogin_saml_advanced_settings_logout_response_signed') : get_option('onelogin_saml_advanced_settings_logout_response_signed');
	echo '<input type="checkbox" name="onelogin_saml_advanced_settings_logout_response_signed" id="onelogin_saml_advanced_settings_logout_response_signed"
		  '.($value ? 'checked="checked"': '').'>'.
		  '<p class="description">'.__('The samlp:logoutResponse messages sent by this SP will be signed.', 'onelogin-saml-sso').'</p>';
}

function plugin_setting_boolean_onelogin_saml_advanced_settings_want_message_signed($network = false) {
	$value = $network ? get_site_option('onelogin_saml_advanced_settings_want_message_signed') : get_option('onelogin_saml_advanced_settings_want_message_signed');
	echo '<input type="checkbox" name="onelogin_saml_advanced_settings_want_message_signed" id="onelogin_saml_advanced_settings_want_message_signed"
		  '.($value ? 'checked="checked"': '').'>'.
		  '<p class="description">'.__('Reject unsigned samlp:Response, samlp:LogoutRequest and samlp:LogoutResponse received', 'onelogin-saml-sso').'</p>';
}

function plugin_setting_boolean_onelogin_saml_advanced_settings_want_assertion_signed($network = false) {
	$value = $network ? get_site_option('onelogin_saml_advanced_settings_want_assertion_signed') : get_option('onelogin_saml_advanced_settings_want_assertion_signed');
	echo '<input type="checkbox" name="onelogin_saml_advanced_settings_want_assertion_signed" id="onelogin_saml_advanced_settings_want_assertion_signed"
		  '.($value ? 'checked="checked"': '').'>'.
		  '<p class="description">'.__('Reject unsigned saml:Assertion received', 'onelogin-saml-sso').'</p>';
}

function plugin_setting_boolean_onelogin_saml_advanced_settings_want_assertion_encrypted($network = false) {
	$value = $network ? get_site_option('onelogin_saml_advanced_settings_want_assertion_encrypted') : get_option('onelogin_saml_advanced_settings_want_assertion_encrypted');
	echo '<input type="checkbox" name="onelogin_saml_advanced_settings_want_assertion_encrypted" id="onelogin_saml_advanced_settings_want_assertion_encrypted"
		  '.($value ? 'checked="checked"': '').'>'.
		  '<p class="description">'.__('Reject unencrypted saml:Assertion received', 'onelogin-saml-sso').'</p>';
}

function plugin_setting_textarea_onelogin_saml_advanced_settings_sp_x509cert($network = false) {
	$value = $network ? get_site_option('onelogin_saml_advanced_settings_sp_x509cert') : get_option('onelogin_saml_advanced_settings_sp_x509cert');
	echo '<textarea name="onelogin_saml_advanced_settings_sp_x509cert" id="onelogin_saml_advanced_settings_sp_x509cert" style="width:600px; height:220px; font-size:12px; font-family:courier,arial,sans-serif;">';
	echo esc_textarea($value);
	echo '</textarea>';
	echo '<p class="description">'.__('Public x509 certificate of the SP. Leave this field empty if you are providing the cert by the sp.crt.', 'onelogin-saml-sso');
}

function plugin_setting_textarea_onelogin_saml_advanced_settings_sp_privatekey($network = false) {
	$value = $network ? get_site_option('onelogin_saml_advanced_settings_sp_privatekey') : get_option('onelogin_saml_advanced_settings_sp_privatekey');
	echo '<textarea name="onelogin_saml_advanced_settings_sp_privatekey" id="onelogin_saml_advanced_settings_sp_privatekey" style="width:600px; height:220px; font-size:12px; font-family:courier,arial,sans-serif;">';
	echo esc_textarea($value);
	echo '</textarea>';
	echo '<p class="description">'.__('Private Key of the SP. Leave this field empty if you are providing the private key by the sp.key.', 'onelogin-saml-sso');
}

function plugin_setting_boolean_onelogin_saml_advanced_settings_retrieve_parameters_from_server($network = false) {
	$value = $network ? get_site_option('onelogin_saml_advanced_settings_retrieve_parameters_from_server') : get_option('onelogin_saml_advanced_settings_retrieve_parameters_from_server');
	echo '<input type="checkbox" name="onelogin_saml_advanced_settings_retrieve_parameters_from_server" id="onelogin_saml_advanced_settings_retrieve_parameters_from_server"
		  '.($value ? 'checked="checked"': '').'>'.
		  '<p class="description">'.__('Sometimes when the app is behind a firewall or proxy, the query parameters can be modified an this affects the signature validation process on HTTP-Redirectbinding. Active this if you are seeing signature validation failures. The plugin will try to extract the original query parameters.', 'onelogin-saml-sso').'</p>';
}

function plugin_setting_select_onelogin_saml_advanced_nameidformat($network = false) {
	$nameidformat_value = $network ? get_site_option('onelogin_saml_advanced_nameidformat') : get_option('onelogin_saml_advanced_nameidformat');
	$posible_nameidformat_values = array(
		'unspecified' => Constants::NAMEID_UNSPECIFIED,
		'emailAddress' => Constants::NAMEID_EMAIL_ADDRESS,
		'transient' => Constants::NAMEID_TRANSIENT,
		'persistent' => Constants::NAMEID_PERSISTENT,
		'entity' => Constants::NAMEID_ENTITY,
		'encrypted' => Constants::NAMEID_ENCRYPTED,
		'kerberos' => Constants::NAMEID_KERBEROS,
		'x509subjecname' => Constants::NAMEID_X509_SUBJECT_NAME,
		'windowsdomainqualifiedname' => Constants::NAMEID_WINDOWS_DOMAIN_QUALIFIED_NAME
	);

	echo '<select name="onelogin_saml_advanced_nameidformat" id="onelogin_saml_advanced_nameidformat">';

	foreach ($posible_nameidformat_values as $key => $value) {
		echo '<option value='.esc_attr($key).' '.($key === $nameidformat_value ? 'selected="selected"': '').' >'.esc_html($value).'</option>';
	}

	echo '</select>'.
		 '<p class="description">'.__("Specifies constraints on the name identifier to be used to represent the requested subject.", 'onelogin-saml-sso').'</p>';
}

function plugin_setting_select_onelogin_saml_advanced_requestedauthncontext($network = false) {
	if ($network) {
		$requestedauthncontext_values = get_site_option('onelogin_saml_advanced_requestedauthncontext', array());
	} else {
		$requestedauthncontext_values = get_option('onelogin_saml_advanced_requestedauthncontext', array());
	}

	if (!is_array($requestedauthncontext_values)) {
		$requestedauthncontext_values = array($requestedauthncontext_values);
	}

	$posible_requestedauthncontext_values = array(
		'unspecified' => Constants::AC_UNSPECIFIED,
		'password' => Constants::AC_PASSWORD,
		'passwordprotectedtransport' =>	Constants::AC_PASSWORD_PROTECTED,
		'x509' => Constants::AC_X509,
		'smartcard' => Constants::AC_SMARTCARD,
		'kerberos' => Constants::AC_KERBEROS,
	);

	echo '<select multiple="multiple" name="onelogin_saml_advanced_requestedauthncontext[]" id="onelogin_saml_advanced_requestedauthncontext">';
	echo '<option value=""></option>';
	foreach ($posible_requestedauthncontext_values as $key => $value) {
		echo '<option value='.esc_attr($key).' '.(in_array($key, $requestedauthncontext_values, true) ? 'selected="selected"': '').' >'.esc_html($value).'</option>';
	}

	echo '</select>'.
		 '<p class="description">'.__("AuthContext sent in the AuthNRequest. You can select none, one or multiple values", 'onelogin-saml-sso').'</p>';

}

function plugin_setting_select_onelogin_saml_advanced_signaturealgorithm($network = false) {
	$signaturealgorithm_value = $network ? get_site_option('onelogin_saml_advanced_signaturealgorithm') : get_option('onelogin_saml_advanced_signaturealgorithm');
	$posible_signaturealgorithm_values = array(
		XMLSecurityKey::RSA_SHA1 => XMLSecurityKey::RSA_SHA1,
		XMLSecurityKey::DSA_SHA1 => XMLSecurityKey::DSA_SHA1,
		XMLSecurityKey::RSA_SHA256 => XMLSecurityKey::RSA_SHA256,
		XMLSecurityKey::RSA_SHA384 => XMLSecurityKey::RSA_SHA384,
		XMLSecurityKey::RSA_SHA512 => XMLSecurityKey::RSA_SHA512
	);

	echo '<select name="onelogin_saml_advanced_signaturealgorithm" id="onelogin_saml_advanced_signaturealgorithm">';

	foreach ($posible_signaturealgorithm_values as $key => $value) {
		echo '<option value='.esc_attr($key).' '.($key === $signaturealgorithm_value ? 'selected="selected"': '').' >'.esc_html($value).'</option>';
	}

	echo '</select>'.
		 '<p class="description">'.__("Algorithm that will be used on signing process").'</p>';
}

function plugin_setting_select_onelogin_saml_advanced_digestalgorithm($network = false) {
	$digestalgorithm_value = $network ? get_site_option('onelogin_saml_advanced_digestalgorithm') : get_option('onelogin_saml_advanced_digestalgorithm');
	$posible_digestalgorithm_values = array(
		XMLSecurityDSig::SHA1 => XMLSecurityDSig::SHA1,
		XMLSecurityDSig::SHA256 => XMLSecurityDSig::SHA256,
		XMLSecurityDSig::SHA384 => XMLSecurityDSig::SHA384,
		XMLSecurityDSig::SHA512 => XMLSecurityDSig::SHA512
	);

	echo '<select name="onelogin_saml_advanced_digestalgorithm" id="onelogin_saml_advanced_digestalgorithm">';

	foreach ($posible_digestalgorithm_values as $key => $value) {
		echo '<option value='.esc_attr($key).' '.($key === $digestalgorithm_value ? 'selected="selected"': '').' >'.esc_html($value).'</option>';
	}

	echo '</select>'.
		 '<p class="description">'.__("Algorithm that will be used on digest process").'</p>';
}

function plugin_section_status_text() {
	echo "<p>".__("Use this flag for enable or disable the SAML support.", 'onelogin-saml-sso')."</p>";
}

function plugin_section_idp_text() {
	echo "<p>".__("Set information relating to the IdP that will be connected with our WordPress. You can find these values at the Onelogin's platform inside WordPress on the Single Sign-On tab.", 'onelogin-saml-sso')."</p>";
}

function plugin_section_options_text() {
	echo "<p>".__("This section customizes the behavior of the plugin.", 'onelogin-saml-sso')."</p>";
}

function plugin_section_attr_mapping_text() {
	echo "<p>".__("Sometimes the names of the attributes sent by the IdP do not match the names used by WordPress for the user accounts. In this section you can set the mapping between IdP fields and WordPress fields. Note: This mapping could be also set at Onelogin's IdP.", 'onelogin-saml-sso')."</p>";
}

function plugin_section_role_mapping_text() {
	echo "<p>".__("The IdP can use its own roles. In this section, you can set the mapping between IdP and WordPress roles. Accepts comma separated values. Example: <code>admin,owner,superuser</code>", 'onelogin-saml-sso')."</p>";
}

function plugin_section_role_precedence_text() {
	echo "<p>".__("In some cases, the IdP returns more than one role. In this secion, you can set the precedence of the different roles which makes sense if multi-role support is not enabled. The smallest integer will be the role chosen.", 'onelogin-saml-sso')."</p>";
}

function plugin_section_customize_links_text() {
	echo "<p>".__("When SAML SSO is enabled to be integrated with an IdP, some WordPress actions and links could be changed. In this section, you will be able to enable or disable the ability for users to change their email address, password and reset their password. You can also override the user registration and the lost password links.", 'onelogin-saml-sso')."</p>";
}

function plugin_section_advanced_settings_text() {
	echo "<p>".__("Handle some other parameters related to customizations and security issues.<br>If signing/encryption is enabled, then x509 cert and private key for the SP must be provided. There are 2 ways:<br>
		 1. Store them as files named sp.key and sp.crt on the 'certs' folder of the plugin. (Make sure that the <code>/cert</code> folder is read-protected and not exposed to internet.)<br>
		 2. Store them at the database, filling the corresponding textareas.", 'onelogin-saml-sso')."</p>";
}

function plugin_section_text() {}

function onelogin_saml_configuration_multisite() {
	add_menu_page(__("Network SAML Settings"), __("Network SAML Settings"), 'manage_options', 'network_saml_settings', 'load_saml_network_config_page');
	add_submenu_page('network_saml_settings', __("Network Global Settings"), __("Network Global Settings"), 'manage_options','network_saml_global_settings', 'load_saml_network_global_config_page');
	add_submenu_page('network_saml_settings', __("Inject SAML Settings in sites"), __("Inject SAML Settings in sites"), 'manage_options','network_saml_injection', 'load_saml_network_injection');
	add_submenu_page('network_saml_settings', __("Enable/Disable SAML on sites"), __("Enable/Disable SAML on sites"), 'manage_options','network_saml_enabler', 'load_saml_network_enabler');
}

function load_saml_network_global_config_page() {
	require "network_saml_global_settings.php";
}

function load_saml_network_config_page() {
	require "network.php";
}

function load_saml_network_injection() {
	require "network_saml_injection.php";
}

function load_saml_network_enabler() {
	require "network_saml_enabler.php";
}

function onelogin_saml_global_configuration_multisite_save() {
	check_admin_referer('network_saml_global_settings_validate'); // Nonce security check
	
	if (isset($_POST)) {
		if (isset($_POST['global_jit']) && $_POST['global_jit'] === 'on') {
			$global_jit = true;
		} else {
			$global_jit = false;
		}
		update_site_option("onelogin_network_saml_global_jit", $global_jit);
	}

	wp_redirect(add_query_arg( array(
		'page' => 'network_saml_global_settings',
		'updated' => true ), network_admin_url('admin.php')
	));

	exit;
}

function onelogin_saml_configuration_multisite_save() {
	check_admin_referer('network_saml_settings_validate'); // Nonce security check

	$fields = get_onelogin_saml_settings();

	foreach (array_keys($fields) as $section) {
		foreach (array_keys($fields[$section]) as $name) {
			$value = isset($_POST[$name]) ? $_POST[$name] : NULL;
			update_site_option($name, wp_unslash($value));
		}
	}

	wp_redirect(add_query_arg( array(
		'page' => 'network_saml_settings',
		'updated' => true ), network_admin_url('admin.php')
	));

	exit;
}

function onelogin_saml_configuration_multisite_injection() {
	$updated = false;
	if (!empty($_POST) && isset($_POST['inject_saml_in_site'])) {
		check_admin_referer('network_saml_injection_validate'); // Nonce security check

		$fields = get_onelogin_saml_settings();
		$sites = sanitize_array_int($_POST['inject_saml_in_site']);

		foreach ($sites as $site_id) {
			foreach (array_keys($fields) as $section) {
				foreach (array_keys($fields[$section]) as $name) {
					$name = sanitize_key($name);
					update_blog_option($site_id, $name, get_site_option($name, ''));
				}
			}
		}
		$updated = true;
	}

	wp_redirect(add_query_arg( array(
		'page' => 'network_saml_injection',
		'updated' => $updated ), network_admin_url('admin.php')
	));

	exit();
}

function onelogin_saml_configuration_multisite_enabler() {
	$updated = false;
	if (!empty($_POST)) {
		check_admin_referer('network_saml_enabler_validate'); // Nonce security check
		$enable_on_sites = array();
		if (isset($_POST['enable_saml_in_site'])) {
			$enable_on_sites = sanitize_array_int($_POST['enable_saml_in_site']);
		}

		$opts = array('number' => 1000);
        $sites = get_sites($opts);
		foreach ($sites as $site) {
			$value = false;
			if (in_array($site->id, $enable_on_sites, true)) {
				$value = "on";
			}
			update_blog_option($site->id, 'onelogin_saml_enabled', $value);
		}
		$updated = true;
	}

	wp_redirect(add_query_arg( array(
		'page' => 'network_saml_enabler',
		'updated' => $updated ), network_admin_url('admin.php')
	));
	exit();
}

function get_onelogin_saml_settings() {
	$status_fields = array(
		'onelogin_saml_enabled' => array(
			__('Enable', 'onelogin-saml-sso'),
			'boolean'
		)
	);

	$idp_fields = get_onelogin_saml_settings_idp();
	$options_fields = get_onelogin_saml_settings_options();
	$attr_mapping_fields = get_onelogin_saml_settings_attribute_mapping();
	$role_mapping_fields = get_onelogin_saml_settings_role_mapping();
	$role_precedence_fields = get_onelogin_saml_settings_role_precedence();
	$customize_links_fields = get_onelogin_saml_settings_customize_links();
	$advanced_fields = get_onelogin_saml_settings_advanced();

	$settings = array (
		'status' => $status_fields,
		'idp' => $idp_fields,
		'options' => $options_fields,
		'attr_mapping' => $attr_mapping_fields,
		'role_mapping' => $role_mapping_fields,
		'role_precedence' => $role_precedence_fields,
		'customize_links' => $customize_links_fields,
		'advanced_settings' => $advanced_fields
	);

	return $settings;
}

function get_sections() {
	return array (
		'status' => __('STATUS', 'onelogin-saml-sso'),
		'idp' => __('IDENTITY PROVIDER SETTINGS', 'onelogin-saml-sso'),
		'options' => __('OPTIONS', 'onelogin-saml-sso'),
		'attr_mapping' => __('ATTRIBUTE MAPPING', 'onelogin-saml-sso'),
		'role_mapping' => __('ROLE MAPPING', 'onelogin-saml-sso'),
		'role_precedence' => __('ROLE PRECEDENCE', 'onelogin-saml-sso'),
		'customize_links' => __('CUSTOMIZE ACTIONS AND LINKS', 'onelogin-saml-sso'),
		'advanced_settings' => __('ADVANCED SETTINGS', 'onelogin-saml-sso'),
	);
}

function get_onelogin_saml_settings_idp() {
	return array (
		'onelogin_saml_idp_entityid' => array(
			__('IdP Entity Id', 'onelogin-saml-sso') . ' *',
			'string'
		),
		'onelogin_saml_idp_sso' => array(
			__('Single Sign On Service Url', 'onelogin-saml-sso') . ' *',
			'string'
		),
		'onelogin_saml_idp_slo' => array(
			__('Single Log Out Service Url', 'onelogin-saml-sso'),
			'string'
		),
		'onelogin_saml_idp_x509cert' => array(
			__('X.509 Certificate', 'onelogin-saml-sso'),
			'textarea'
		),
	);
}

function get_onelogin_saml_settings_options() {
	return array (
		'onelogin_saml_autocreate' => array(
			__('Create user if not exists', 'onelogin-saml-sso'),
			'boolean'
		),
		'onelogin_saml_updateuser' => array(
			__('Update user data', 'onelogin-saml-sso'),
			'boolean'
		),
		'onelogin_saml_forcelogin' => array(
			__('Force SAML login', 'onelogin-saml-sso'),
			'boolean'
		),
		'onelogin_saml_slo' => array(
			__('Single Log Out', 'onelogin-saml-sso'),
			'boolean'
		),
		'onelogin_saml_keep_local_login' => array(
			__('Keep Local login', 'onelogin-saml-sso'),
			'boolean'
		),
		'onelogin_saml_alternative_acs' => array(
			__('Alternative ACS Endpoint', 'onelogin-saml-sso'),
			'boolean'
		),
		'onelogin_saml_account_matcher' => array(
			__('Match Wordpress account by', 'onelogin-saml-sso'),
			'select'
		),
		'onelogin_saml_multirole' => array(
			__('Multi Role Support', 'onelogin-saml-sso'),
			'boolean'
		),
		'onelogin_saml_trusted_url_domains' => array(
			__('Trust URL domains on RelayState', 'onelogin-saml-sso'),
			'textarea'
		)
	);
}

function get_onelogin_saml_settings_attribute_mapping() {
	return array (
		'onelogin_saml_attr_mapping_username' =>  array(
			__('Username', 'onelogin-saml-sso') . ' *',
			'string'
		),
		'onelogin_saml_attr_mapping_mail' =>  array(
			__('E-mail', 'onelogin-saml-sso') . ' *',
			'string'
		),
		'onelogin_saml_attr_mapping_firstname' =>  array(
			__('First Name', 'onelogin-saml-sso'),
			'string'
		),
		'onelogin_saml_attr_mapping_lastname' =>  array(
			__('Last Name', 'onelogin-saml-sso'),
			'string'
		),
		'onelogin_saml_attr_mapping_role' =>  array(
			__('Role', 'onelogin-saml-sso'),
			'string'
		),
		'onelogin_saml_attr_mapping_rememberme' =>  array(
			__('Remember Me', 'onelogin-saml-sso'),
			'string'
		)
	);
}

function get_onelogin_saml_settings_role_mapping() {
	$fields = array();
	foreach (wp_roles()->get_names() as $role_value => $role_name) {
		$name = 'onelogin_saml_role_mapping_'.$role_value;
		$fields[$name] = array(
			$role_name,
			'string'
		);
	}

	$fields['onelogin_saml_role_mapping_multivalued_in_one_attribute_value'] = array(
		__('Multiple role values in one saml attribute value', 'onelogin-saml-sso'),
		'boolean'
	);

	$fields['onelogin_saml_role_mapping_multivalued_pattern'] = array(
		__('Regular expression for multiple role values', 'onelogin-saml-sso'),
		'string'
	);

	return $fields;
}


function get_onelogin_saml_settings_role_precedence() {
	$fields = array();
	foreach (wp_roles()->get_names() as $role_value => $role_name) {
		$name = 'onelogin_saml_role_order_'.$role_value;
		$fields[$name] = array(
			$role_name,
			'string'
		);
	}

	return $fields;
 }

function get_onelogin_saml_settings_customize_links() {
	return array (
		'onelogin_saml_customize_action_prevent_local_login' =>  array(
			__('Prevent use of ?normal', 'onelogin-saml-sso'),
			'boolean'
		),
		'onelogin_saml_customize_action_prevent_reset_password' =>  array(
			__('Prevent reset password', 'onelogin-saml-sso'),
			'boolean'
		),
		'onelogin_saml_customize_action_prevent_change_password' =>  array(
			__('Prevent change password', 'onelogin-saml-sso'),
			'boolean'
		),
		'onelogin_saml_customize_action_prevent_change_mail' =>  array(
			__('Prevent change mail', 'onelogin-saml-sso'),
			'boolean'
		),
		'onelogin_saml_customize_stay_in_wordpress_after_slo' =>  array(
			__('Stay in WordPress after SLO', 'onelogin-saml-sso'),
			'boolean'
		),
		'onelogin_saml_customize_links_user_registration' =>  array(
			__('User Registration', 'onelogin-saml-sso'),
			'string'
		),
		'onelogin_saml_customize_links_lost_password' =>  array(
			__('Lost Password', 'onelogin-saml-sso'),
			'string'
		),
		'onelogin_saml_customize_links_saml_login' =>  array(
			__('SAML Link Message', 'onelogin-saml-sso'),
			'string'
		)
	);
}

function get_onelogin_saml_settings_advanced() {
	return array (
		'onelogin_saml_advanced_settings_debug' =>  array(
			__('Debug Mode', 'onelogin-saml-sso'),
			'boolean'
		),
		'onelogin_saml_advanced_settings_strict_mode' =>  array(
			__('Strict Mode', 'onelogin-saml-sso'),
			'boolean'
		),
		'onelogin_saml_advanced_settings_sp_entity_id' =>  array(
			__('Service Provider Entity Id', 'onelogin-saml-sso'),
			'string'
		),
		'onelogin_saml_advanced_idp_lowercase_url_encoding' =>  array(
			__('Lowercase URL encoding?', 'onelogin-saml-sso'),
			'boolean'
		),
		'onelogin_saml_advanced_settings_nameid_encrypted' =>  array(
			__('Encrypt nameID', 'onelogin-saml-sso'),
			'boolean'
		),
		'onelogin_saml_advanced_settings_authn_request_signed' =>  array(
			__('Sign AuthnRequest', 'onelogin-saml-sso'),
			'boolean'
		),
		'onelogin_saml_advanced_settings_logout_request_signed' =>  array(
			__('Sign LogoutRequest', 'onelogin-saml-sso'),
			'boolean'
		),
		'onelogin_saml_advanced_settings_logout_response_signed' =>  array(
			__('Sign LogoutResponse', 'onelogin-saml-sso'),
			'boolean'
		),
		'onelogin_saml_advanced_settings_want_message_signed' =>  array(
			__('Reject Unsigned Messages', 'onelogin-saml-sso'),
			'boolean'
		),
		'onelogin_saml_advanced_settings_want_assertion_signed' =>  array(
			__('Reject Unsigned Assertions', 'onelogin-saml-sso'),
			'boolean'
		),
		'onelogin_saml_advanced_settings_want_assertion_encrypted' =>  array(
			__('Reject Unencrypted Assertions', 'onelogin-saml-sso'),
			'boolean'
		),
		'onelogin_saml_advanced_settings_retrieve_parameters_from_server' =>  array(
			__('Retrieve Parameters From Server', 'onelogin-saml-sso'),
			'boolean'
		),
		'onelogin_saml_advanced_nameidformat' =>  array(
			__('NameIDFormat', 'onelogin-saml-sso'),
			'select'
		),
		'onelogin_saml_advanced_requestedauthncontext' =>  array(
			__('requestedAuthnContext', 'onelogin-saml-sso'),
			'select'
		),
		'onelogin_saml_advanced_settings_sp_x509cert' =>  array(
			__('Service Provider X.509 Certificate', 'onelogin-saml-sso'),
			'textarea'
		),
		'onelogin_saml_advanced_settings_sp_privatekey' =>  array(
			__('Service Provider Private Key', 'onelogin-saml-sso'),
			'textarea'
		),
		'onelogin_saml_advanced_signaturealgorithm' =>  array(
			__('Signature Algorithm', 'onelogin-saml-sso'),
			'select'
		),
		'onelogin_saml_advanced_digestalgorithm' =>  array(
			__('Digest Algorithm', 'onelogin-saml-sso'),
			'select'
		)
	);
}
