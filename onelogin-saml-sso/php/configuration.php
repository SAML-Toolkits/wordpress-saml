<?php

// Make sure we don't expose any info if called directly
if ( !function_exists( 'add_action' ) ) {
	echo 'Hi there!  I\'m just a plugin, not much I can do when called directly.';
	exit;
}
	
require_once (dirname(__FILE__) . "/lib/Saml2/Constants.php");


	function onelogin_saml_configuration_render() {
		$title = __("SSO/SAML Settings", 'onelogin-saml-sso');
		?>
			<div class="wrap">
				<?php screen_icon(); ?>
				<div class="alignleft">
					<a href="http://www.onelogin.com"><img src="<?php echo plugins_url('onelogin.png', dirname(__FILE__));?>"></a>
				</div>
				<div class="alignright">
					<a href="<?php echo get_site_url().'/wp-login.php?saml_metadata'; ?>" target="blank"><?php echo __("Go to the metadata of this SP", 'onelogin-saml-sso');?></a><br>
					<a href="<?php echo get_site_url().'/wp-login.php?saml_validate_config'; ?>" target="blank"><?php echo __("Once configured, validate here your OneLogin SSO/SAML Settings", 'onelogin-saml-sso');?></a>
				</div>
				<div style="clear:both"></div>
				<h2><?php echo esc_html( $title ); ?></h2>
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
		
		if (function_exists('add_contextual_help')) {
			@add_contextual_help($current_screen, $helpText);
		}

		$option_group = 'onelogin_saml_configuration';

		add_settings_section('idp', __('IDENTITY PROVIDER SETTINGS', 'onelogin-saml-sso'), 'plugin_section_idp_text', $option_group);
		$idp_fields = array (
			'onelogin_saml_idp_entityid' => __('IdP Entity Id', 'onelogin-saml-sso') . ' *',
			'onelogin_saml_idp_sso' => __('Single Sign On Service Url', 'onelogin-saml-sso') . ' *',
			'onelogin_saml_idp_slo' => __('Single Log Out Service Url', 'onelogin-saml-sso'),
			'onelogin_saml_idp_x509cert' => __('X.509 Certificate', 'onelogin-saml-sso')
		);
		foreach ($idp_fields as $name => $description) {
			register_setting($option_group, $name);
			add_settings_field($name, $description, "plugin_setting_string_$name", $option_group, 'idp');
		}

		add_settings_section('options', __('OPTIONS', 'onelogin-saml-sso'), 'plugin_section_options_text', $option_group);
		$options_fields = array (
			'onelogin_saml_autocreate' => __('Create user if not exists', 'onelogin-saml-sso'),
			'onelogin_saml_updateuser' => __('Update user data', 'onelogin-saml-sso'),
			'onelogin_saml_forcelogin' => __('Force SAML login', 'onelogin-saml-sso'),
			'onelogin_saml_slo' => __('Single Log Out', 'onelogin-saml-sso'),
			'onelogin_saml_keep_local_login' => __('Keep Local login', 'onelogin-saml-sso')
		);
		foreach ($options_fields as $name => $description) {
			register_setting($option_group, $name);
			add_settings_field($name, $description, "plugin_setting_boolean_$name", $option_group, 'options');
		}

		register_setting($option_group, 'onelogin_saml_account_matcher');
		add_settings_field('onelogin_saml_account_matcher', __('Match Wordpress account by', 'onelogin-saml-sso'), "plugin_setting_select_onelogin_saml_account_matcher", $option_group, 'options');

		add_settings_section('attr_mapping', __('ATTRIBUTE MAPPING', 'onelogin-saml-sso'), 'plugin_section_attr_mapping_text', $option_group);		
		$mapping_fields = array (
			'onelogin_saml_attr_mapping_username' => __('Username', 'onelogin-saml-sso') . ' *',
			'onelogin_saml_attr_mapping_mail' => __('E-mail', 'onelogin-saml-sso') . ' *',
			'onelogin_saml_attr_mapping_firstname' => __('First Name', 'onelogin-saml-sso'),
			'onelogin_saml_attr_mapping_lastname' => __('Last Name', 'onelogin-saml-sso'),
			'onelogin_saml_attr_mapping_role' => __('Role', 'onelogin-saml-sso')
		);
		foreach ($mapping_fields as $name => $description) {
			register_setting($option_group, $name);
			add_settings_field($name, $description, "plugin_setting_string_$name", $option_group, 'attr_mapping');
		}

		add_settings_section('role_mapping', __('ROLE MAPPING', 'onelogin-saml-sso'), 'plugin_section_role_mapping_text', $option_group);
		$mapping_fields = array (
			'onelogin_saml_role_mapping_administrator' => __('Administrator', 'onelogin-saml-sso'),
			'onelogin_saml_role_mapping_editor' => __('Editor', 'onelogin-saml-sso'),
			'onelogin_saml_role_mapping_author' => __('Author', 'onelogin-saml-sso'),
			'onelogin_saml_role_mapping_contributor' => __('Contributor', 'onelogin-saml-sso'),
			'onelogin_saml_role_mapping_subscriber' => __('Subscriber', 'onelogin-saml-sso')
		);
		foreach ($mapping_fields as $name => $description) {
			register_setting($option_group, $name);
			add_settings_field($name, $description, "plugin_setting_string_$name", $option_group, 'role_mapping');
		}

		register_setting($option_group, 'onelogin_saml_role_mapping_multivalued_in_one_attribute_value');
		add_settings_field('onelogin_saml_role_mapping_multivalued_in_one_attribute_value', __('Multiple role values in one saml attribute value', 'onelogin-saml-sso'), "plugin_setting_boolean_onelogin_saml_role_mapping_multivalued_in_one_attribute_value", $option_group, 'role_mapping');

		register_setting($option_group, 'onelogin_saml_role_mapping_multivalued_pattern');
		add_settings_field('onelogin_saml_role_mapping_multivalued_pattern', __('Regular expression for multiple role values', 'onelogin-saml-sso'), "plugin_setting_string_onelogin_saml_role_mapping_multivalued_pattern", $option_group, 'role_mapping');

		add_settings_section('customize_links', __('CUSTOMIZE ACTIONS AND LINKS', 'onelogin-saml-sso'), 'plugin_section_customize_links_text', $option_group);

		register_setting($option_group, 'onelogin_saml_customize_action_prevent_local_login');
		add_settings_field('onelogin_saml_customize_action_prevent_local_login', __('Prevent use of ?normal', 'onelogin-saml-sso'), "plugin_setting_boolean_onelogin_saml_customize_action_prevent_local_login", $option_group, 'customize_links');

		register_setting($option_group, 'onelogin_saml_customize_action_prevent_reset_password');
		add_settings_field('onelogin_saml_customize_action_prevent_reset_password', __('Prevent reset password', 'onelogin-saml-sso'), "plugin_setting_boolean_onelogin_saml_customize_action_prevent_reset_password", $option_group, 'customize_links');

		register_setting($option_group, 'onelogin_saml_customize_action_prevent_change_password');
		add_settings_field('onelogin_saml_customize_action_prevent_change_password', __('Prevent change password', 'onelogin-saml-sso'), "plugin_setting_boolean_onelogin_saml_customize_action_prevent_change_password", $option_group, 'customize_links');

		register_setting($option_group, 'onelogin_saml_customize_action_prevent_change_mail');
		add_settings_field('onelogin_saml_customize_action_prevent_change_mail', __('Prevent change mail', 'onelogin-saml-sso'), "plugin_setting_boolean_onelogin_saml_customize_action_prevent_change_mail", $option_group, 'customize_links');

		register_setting($option_group, 'onelogin_saml_customize_stay_in_wordpress_after_slo');
		add_settings_field('onelogin_saml_customize_stay_in_wordpress_after_slo', __('Stay in Wordpress after SLO', 'onelogin-saml-sso'), "plugin_setting_boolean_onelogin_saml_customize_stay_in_wordpress_after_slo", $option_group, 'customize_links');

		register_setting($option_group, 'onelogin_saml_customize_links_user_registration');
		add_settings_field('onelogin_saml_customize_links_user_registration', __('User Registration', 'onelogin-saml-sso'), "plugin_setting_string_onelogin_saml_customize_links_user_registration", $option_group, 'customize_links');

		register_setting($option_group, 'onelogin_saml_customize_links_lost_password');
		add_settings_field('onelogin_saml_customize_links_lost_password', __('Lost Password', 'onelogin-saml-sso'), "plugin_setting_string_onelogin_saml_customize_links_lost_password", $option_group, 'customize_links');

		register_setting($option_group, 'onelogin_saml_customize_links_saml_login');
		add_settings_field('onelogin_saml_customize_links_saml_login', __('SAML Link Message', 'onelogin-saml-sso'), "plugin_setting_string_onelogin_saml_customize_links_saml_login", $option_group, 'customize_links');

		add_settings_section('advanced_settings', __('ADVANCED SETTINGS', 'onelogin-saml-sso'), 'plugin_section_advanced_settings_text', $option_group);

		register_setting($option_group, 'onelogin_saml_advanced_settings_debug');
		add_settings_field('onelogin_saml_advanced_settings_debug', __('Debug Mode', 'onelogin-saml-sso'), "plugin_setting_boolean_onelogin_saml_advanced_settings_debug", $option_group, 'advanced_settings');

		register_setting($option_group, 'onelogin_saml_advanced_settings_strict_mode');
		add_settings_field('onelogin_saml_advanced_settings_strict_mode', __('Strict Mode', 'onelogin-saml-sso'), "plugin_setting_boolean_onelogin_saml_advanced_settings_strict_mode", $option_group, 'advanced_settings');

		register_setting($option_group, 'onelogin_saml_advanced_settings_sp_entity_id');
		add_settings_field('onelogin_saml_advanced_settings_sp_entity_id', __('Service Provider Entity Id', 'onelogin-saml-sso'), "plugin_setting_string_onelogin_saml_advanced_settings_sp_entity_id", $option_group, 'advanced_settings');

		$mapping_fields = array (
			'onelogin_saml_advanced_settings_nameid_encrypted' => __('Encrypt nameID', 'onelogin-saml-sso'),
			'onelogin_saml_advanced_settings_authn_request_signed' => __('Sign AuthnRequest', 'onelogin-saml-sso'),
			'onelogin_saml_advanced_settings_logout_request_signed' => __('Sign LogoutRequest', 'onelogin-saml-sso'),
			'onelogin_saml_advanced_settings_logout_response_signed' => __('Sign LogoutResponse', 'onelogin-saml-sso'),
			'onelogin_saml_advanced_settings_want_message_signed' => __('Reject Unsigned Messages', 'onelogin-saml-sso'),
			'onelogin_saml_advanced_settings_want_assertion_signed' => __('Reject Unsigned Assertions', 'onelogin-saml-sso'),
			'onelogin_saml_advanced_settings_want_assertion_encrypted' => __('Reject Unencrypted Assertions', 'onelogin-saml-sso'),
			'onelogin_saml_advanced_settings_retrieve_parameters_from_server' => __('Retrieve Parameters From Server', 'onelogin-saml-sso')
		);
		foreach ($mapping_fields as $name => $description) {
			register_setting($option_group, $name);
			add_settings_field($name, $description, "plugin_setting_boolean_$name", $option_group, 'advanced_settings');
		}

		register_setting($option_group, 'onelogin_saml_advanced_nameidformat');
		add_settings_field('onelogin_saml_advanced_nameidformat', __('NameIDFormat', 'onelogin-saml-sso'), "plugin_setting_select_onelogin_saml_advanced_nameidformat", $option_group, 'advanced_settings');

		register_setting($option_group, 'onelogin_saml_advanced_requestedauthncontext');
		add_settings_field('onelogin_saml_advanced_requestedauthncontext', __('requestedAuthnContext', 'onelogin-saml-sso'), "plugin_setting_select_onelogin_saml_advanced_requestedauthncontext", $option_group, 'advanced_settings');

		register_setting($option_group, 'onelogin_saml_advanced_settings_sp_x509cert');
		add_settings_field('onelogin_saml_advanced_settings_sp_x509cert', __('Service Provider X.509 Certificate', 'onelogin-saml-sso'), "plugin_setting_string_onelogin_saml_advanced_settings_sp_x509cert", $option_group, 'advanced_settings');

		register_setting($option_group, 'onelogin_saml_advanced_settings_sp_privatekey');
		add_settings_field('onelogin_saml_advanced_settings_sp_privatekey', __('Service Provider Private Key', 'onelogin-saml-sso'), "plugin_setting_string_onelogin_saml_advanced_settings_sp_privatekey", $option_group, 'advanced_settings');
	}

	function plugin_setting_string_onelogin_saml_idp_entityid() {
		echo '<input type="text" name="onelogin_saml_idp_entityid" id="onelogin_saml_idp_entityid" 
			  value= "'.get_option('onelogin_saml_idp_entityid').'" size="80">'.
			  '<p class="description">'.__('Identifier of the IdP entity. ("Issuer URL")', 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_string_onelogin_saml_idp_sso() {
		echo '<input type="text" name="onelogin_saml_idp_sso" id="onelogin_saml_idp_sso"
			  value= "'.get_option('onelogin_saml_idp_sso').'" size="80">'.
			  '<p class="description">'.__('SSO endpoint info of the IdP. URL target of the IdP where the SP will send the Authentication Request. ("SAML 2.0 Endpoint (HTTP)")', 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_string_onelogin_saml_idp_slo() {
		echo '<input type="text" name="onelogin_saml_idp_slo" id="onelogin_saml_idp_slo"
			  value= "'.get_option('onelogin_saml_idp_slo').'" size="80">'.
			  '<p class="description">'.__('SLO endpoint info of the IdP. URL target of the IdP where the SP will send the SLO Request. ("SLO Endpoint (HTTP)")', 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_string_onelogin_saml_idp_x509cert() {
		echo '<textarea name="onelogin_saml_idp_x509cert" id="onelogin_saml_idp_x509cert" style="width:600px; height:220px; font-size:12px; font-family:courier,arial,sans-serif;">';
		echo get_option('onelogin_saml_idp_x509cert');
		echo '</textarea>';
		echo '<p class="description">'.__('Public x509 certificate of the IdP.  ("X.509 certificate")', 'onelogin-saml-sso');
	}
	
	function plugin_setting_boolean_onelogin_saml_autocreate() {
		$value = get_option('onelogin_saml_autocreate');
		echo '<input type="checkbox" name="onelogin_saml_autocreate" id="onelogin_saml_autocreate"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__('Auto-provisioning. If user not exists,  Wordpress will create a new user with the data provided by the IdP.<br>Review the Mapping section.', 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_boolean_onelogin_saml_updateuser() {
		$value = get_option('onelogin_saml_updateuser');
		echo '<input type="checkbox" name="onelogin_saml_updateuser" id="onelogin_saml_updateuser"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__('Auto-update. Wordpress will update the account of the user with the data provided by the IdP.<br>Review the Mapping section.', 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_boolean_onelogin_saml_forcelogin() {
		$value = get_option('onelogin_saml_forcelogin');
		echo '<input type="checkbox" name="onelogin_saml_forcelogin" id="onelogin_saml_forcelogin"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__('Protect Wordpress and force the user to authenticate at the IdP in order to access when any wordpress page is loaded and no active session', 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_boolean_onelogin_saml_slo() {
		$value = get_option('onelogin_saml_slo');
		echo '<input type="checkbox" name="onelogin_saml_slo" id="onelogin_saml_slo"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__('Enable/disable Single Log Out. SLO  is a complex functionality, the most common SLO implementation is based on front-channel (redirections), sometimes if the SLO workflow fails a user can be blocked in an unhandled view. If the admin does not controls the set of apps involved in the SLO process maybe is better to disable this functionality due could carry more problems than benefits.', 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_boolean_onelogin_saml_keep_local_login() {
		$value = get_option('onelogin_saml_keep_local_login');
		echo '<input type="checkbox" name="onelogin_saml_keep_local_login" id="onelogin_saml_keep_local_login"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__('Enable/disable the normal login form. If disabled, instead of prompt the login form, WP will excecute directly the SP-initiated SSO flow. If enabled te normal login form is showed and a link to initiate that flow is prompted.', 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_select_onelogin_saml_account_matcher() {
		$value = get_option('onelogin_saml_account_matcher');

		echo '<select name="onelogin_saml_account_matcher" id="onelogin_saml_account_matcher">
			  <option value="username" '.($value == 'username'?'selected="selected"':'').'>'.__("Username", 'onelogin-saml-sso').'</option>
			  <option value="email" '.($value == 'email'? 'selected="selected"':'').'>'.__("E-mail", 'onelogin-saml-sso').'</option>
			</select>'.
			'<p class="description">'.__("Select what field will be used in order to find the user account. If you select the 'email' fieldname the plugin will prevent that the user can change his mail in his profile.", 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_string_onelogin_saml_attr_mapping_username() {
		echo '<input type="text" name="onelogin_saml_attr_mapping_username" id="onelogin_saml_attr_mapping_username"
			  value= "'.get_option('onelogin_saml_attr_mapping_username').'" size="30">';
	}

	function plugin_setting_string_onelogin_saml_attr_mapping_mail() {
		echo '<input type="text" name="onelogin_saml_attr_mapping_mail" id="onelogin_saml_attr_mapping_mail"
			  value= "'.get_option('onelogin_saml_attr_mapping_mail').'" size="30">';
	}

	function plugin_setting_string_onelogin_saml_attr_mapping_firstname() {
		echo '<input type="text" name="onelogin_saml_attr_mapping_firstname" id="onelogin_saml_attr_mapping_firstname"
			  value= "'.get_option('onelogin_saml_attr_mapping_firstname').'" size="30">';
	}

	function plugin_setting_string_onelogin_saml_attr_mapping_lastname() {
		echo '<input type="text" name="onelogin_saml_attr_mapping_lastname" id="onelogin_saml_attr_mapping_lastname"
			  value= "'.get_option('onelogin_saml_attr_mapping_lastname').'" size="30">';
	}

	function plugin_setting_string_onelogin_saml_attr_mapping_role() {
		echo '<input type="text" name="onelogin_saml_attr_mapping_role" id="onelogin_saml_attr_mapping_role"
			  value= "'.get_option('onelogin_saml_attr_mapping_role').'" size="30">'.
			  '<p class="description">'.__("The attribute that contains the role of the user, For example 'memberOf'. If Wordpress can't figure what role assign to the user, it will assign the default role defined at the general settings.", 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_string_onelogin_saml_role_mapping_administrator() {
		echo '<input type="text" name="onelogin_saml_role_mapping_administrator" id="onelogin_saml_role_mapping_administrator"
			  value= "'.get_option('onelogin_saml_role_mapping_administrator').'" size="30">';
	}

	function plugin_setting_string_onelogin_saml_role_mapping_editor() {
		echo '<input type="text" name="onelogin_saml_role_mapping_editor" id="onelogin_saml_role_mapping_editor"
			  value= "'.get_option('onelogin_saml_role_mapping_editor').'" size="30">';
	}

	function plugin_setting_string_onelogin_saml_role_mapping_author() {
		echo '<input type="text" name="onelogin_saml_role_mapping_author" id="onelogin_saml_role_mapping_author"
			  value= "'.get_option('onelogin_saml_role_mapping_author').'" size="30">';
	}

	function plugin_setting_string_onelogin_saml_role_mapping_contributor() {
		echo '<input type="text" name="onelogin_saml_role_mapping_contributor" id="onelogin_saml_role_mapping_contributor"
			  value= "'.get_option('onelogin_saml_role_mapping_contributor').'" size="30">';
	}

	function plugin_setting_string_onelogin_saml_role_mapping_subscriber() {
		echo '<input type="text" name="onelogin_saml_role_mapping_subscriber" id="onelogin_saml_role_mapping_subscriber"
			  value= "'.get_option('onelogin_saml_role_mapping_subscriber').'" size="30">';
	}


	function plugin_setting_boolean_onelogin_saml_role_mapping_multivalued_in_one_attribute_value() {
		$value = get_option('onelogin_saml_role_mapping_multivalued_in_one_attribute_value');
		echo '<input type="checkbox" name="onelogin_saml_role_mapping_multivalued_in_one_attribute_value" id="onelogin_saml_role_mapping_multivalued_in_one_attribute_value"
			  '.($value ? 'checked="checked"': '').'>
			  <p class="description">'.__("Sometimes role values are provided in an unique attribute statement (instead multiple attribute statements). Active it and the plugin will try to split those values by ;<br>Use the regular pattern in order to extract complex data", 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_string_onelogin_saml_role_mapping_multivalued_pattern() {
		echo '<input type="text" name="onelogin_saml_role_mapping_multivalued_pattern" id="onelogin_saml_role_mapping_multivalued_pattern"
			  value= "'.get_option('onelogin_saml_role_mapping_multivalued_pattern').'" size="70">
			  <p class="description">'.__("Regular expression that extract roles from complex multivalued data (require to active the previous boolean).<br> Ex. If the SAMLResponse has a role attribute like: CN=admin;CN=superuser;CN=europe-admin; , use the regular expression /CN=([A-Z0-9\s _-]*);/i to retrieve the values", 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_boolean_onelogin_saml_customize_action_prevent_local_login() {
		$value = get_option('onelogin_saml_customize_action_prevent_local_login');
		echo '<input type="checkbox" name="onelogin_saml_customize_action_prevent_local_login" id="onelogin_saml_customize_action_prevent_local_login"
			  '.($value ? 'checked="checked"': '').'>
			  <p class="description">'.__("Check it in order to disable the ?normal option in order to offer the local login when it is not enabled.", 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_boolean_onelogin_saml_customize_action_prevent_reset_password() {
		$value = get_option('onelogin_saml_customize_action_prevent_reset_password');
		echo '<input type="checkbox" name="onelogin_saml_customize_action_prevent_reset_password" id="onelogin_saml_customize_action_prevent_reset_password"
			  '.($value ? 'checked="checked"': '').'>
			  <p class="description">'.__("Check it in order to disable the ability of reset the password on Wordpress.", 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_boolean_onelogin_saml_customize_action_prevent_change_password() {
		$value = get_option('onelogin_saml_customize_action_prevent_change_password');
		echo '<input type="checkbox" name="onelogin_saml_customize_action_prevent_change_password" id="onelogin_saml_customize_action_prevent_change_password"
			  '.($value ? 'checked="checked"': '').'>
			  <p class="description">'.__("Check it in order to disable the ability of change the password on Wordpress.", 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_boolean_onelogin_saml_customize_action_prevent_change_mail() {
		$value = get_option('onelogin_saml_customize_action_prevent_change_mail');
		echo '<input type="checkbox" name="onelogin_saml_customize_action_prevent_change_mail" id="onelogin_saml_customize_action_prevent_change_mail"
			  '.($value ? 'checked="checked"': '').'>
			  <p class="description">'.__("Check it in order to disable the ability of change the mail on Wordpress (we recommend that if you are using mail as the account matcher field.", 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_boolean_onelogin_saml_customize_stay_in_wordpress_after_slo() {
		$value = get_option('onelogin_saml_customize_stay_in_wordpress_after_slo');
		echo '<input type="checkbox" name="onelogin_saml_customize_stay_in_wordpress_after_slo" id="onelogin_saml_customize_stay_in_wordpress_after_slo"
			  '.($value ? 'checked="checked"': '').'>
			  <p class="description">'.__("If SLO and Force SAML login are enabled, after the SLO process you will be redirected to the WP main page and a SAML SSO process will start, to prevent that check this and you will stay at the Wordpress Login Form. ", 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_string_onelogin_saml_customize_links_user_registration() {
		echo '<input type="text" name="onelogin_saml_customize_links_user_registration" id="onelogin_saml_customize_links_user_registration"
			  value= "'.get_option('onelogin_saml_customize_links_user_registration').'" size="80">
			  <p class="description">'.__("Override the user registration link. ", 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_string_onelogin_saml_customize_links_lost_password() {
		echo '<input type="text" name="onelogin_saml_customize_links_lost_password" id="onelogin_saml_customize_links_lost_password"
			  value= "'.get_option('onelogin_saml_customize_links_lost_password').'" size="80">
 			  <p class="description">'.__("Override the lost password link. (prevent reset password must be deactivated or always the SAMl SSO will be forced)", 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_string_onelogin_saml_customize_links_saml_login() {
		echo '<input type="text" name="onelogin_saml_customize_links_saml_login" id="onelogin_saml_customize_links_saml_login"
			  value= "'.get_option('onelogin_saml_customize_links_saml_login').'" size="80">
 			  <p class="description">'.__("If 'Keep Local login' enabled, this will be showed as message at the SAML Link.", 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_boolean_onelogin_saml_advanced_settings_debug() {
		$value = get_option('onelogin_saml_advanced_settings_debug');
		echo '<input type="checkbox" name="onelogin_saml_advanced_settings_debug" id="onelogin_saml_advanced_settings_debug"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__('Enable it when your are debugging the SAML workflow. Errors and Warnigs will be showed.', 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_boolean_onelogin_saml_advanced_settings_strict_mode() {
		$value = get_option('onelogin_saml_advanced_settings_strict_mode');
		echo '<input type="checkbox" name="onelogin_saml_advanced_settings_strict_mode" id="onelogin_saml_advanced_settings_strict_mode"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__("If Strict mode is Enabled, then Wordpress will reject unsigned or unencrypted messages if it expects them signed or encrypted.
			   Also will reject the messages if not strictly follow the SAML standard: Destination, NameId, Conditions ... are validated too.", 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_string_onelogin_saml_advanced_settings_sp_entity_id() {
		echo '<input type="text" name="onelogin_saml_advanced_settings_sp_entity_id" id="onelogin_saml_advanced_settings_sp_entity_id"
			  value= "'.get_option('onelogin_saml_advanced_settings_sp_entity_id').'" size="80">'.
			  '<p class="description">'.__("Set the Entity ID for the Service Provider. If not provided, 'php-saml' will be used.", 'onelogin-saml-sso').'</p>';
	}


	function plugin_setting_boolean_onelogin_saml_advanced_settings_nameid_encrypted() {
		$value = get_option('onelogin_saml_advanced_settings_nameid_encrypted');
		echo '<input type="checkbox" name="onelogin_saml_advanced_settings_nameid_encrypted" id="onelogin_saml_advanced_settings_nameid_encrypted"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__('The nameID sent by this SP will be encrypted.', 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_boolean_onelogin_saml_advanced_settings_authn_request_signed() {
		$value = get_option('onelogin_saml_advanced_settings_authn_request_signed');
		echo '<input type="checkbox" name="onelogin_saml_advanced_settings_authn_request_signed" id="onelogin_saml_advanced_settings_authn_request_signed"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__('The samlp:AuthnRequest messages sent by this SP will be signed.', 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_boolean_onelogin_saml_advanced_settings_logout_request_signed() {
		$value = get_option('onelogin_saml_advanced_settings_logout_request_signed');
		echo '<input type="checkbox" name="onelogin_saml_advanced_settings_logout_request_signed" id="onelogin_saml_advanced_settings_logout_request_signed"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__('The samlp:logoutRequest messages sent by this SP will be signed.', 'onelogin-saml-sso').'</p>';
	}	

	function plugin_setting_boolean_onelogin_saml_advanced_settings_logout_response_signed() {
		$value = get_option('onelogin_saml_advanced_settings_logout_response_signed');
		echo '<input type="checkbox" name="onelogin_saml_advanced_settings_logout_response_signed" id="onelogin_saml_advanced_settings_logout_response_signed"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__('The samlp:logoutResponse messages sent by this SP will be signed.', 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_boolean_onelogin_saml_advanced_settings_want_message_signed() {
		$value = get_option('onelogin_saml_advanced_settings_want_message_signed');
		echo '<input type="checkbox" name="onelogin_saml_advanced_settings_want_message_signed" id="onelogin_saml_advanced_settings_want_message_signed"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__('Reject unsigned samlp:Response, samlp:LogoutRequest and samlp:LogoutResponse received', 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_boolean_onelogin_saml_advanced_settings_want_assertion_signed() {
		$value = get_option('onelogin_saml_advanced_settings_want_assertion_signed');
		echo '<input type="checkbox" name="onelogin_saml_advanced_settings_want_assertion_signed" id="onelogin_saml_advanced_settings_want_assertion_signed"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__('Reject unsigned saml:Assertion received', 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_boolean_onelogin_saml_advanced_settings_want_assertion_encrypted() {
		$value = get_option('onelogin_saml_advanced_settings_want_assertion_encrypted');
		echo '<input type="checkbox" name="onelogin_saml_advanced_settings_want_assertion_encrypted" id="onelogin_saml_advanced_settings_want_assertion_encrypted"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__('Reject unencrypted saml:Assertion received', 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_string_onelogin_saml_advanced_settings_sp_x509cert() {
		echo '<textarea name="onelogin_saml_advanced_settings_sp_x509cert" id="onelogin_saml_advanced_settings_sp_x509cert" style="width:600px; height:220px; font-size:12px; font-family:courier,arial,sans-serif;">';
		echo get_option('onelogin_saml_advanced_settings_sp_x509cert');
		echo '</textarea>';
		echo '<p class="description">'.__('Public x509 certificate of the SP. Leave this field empty if you gonna provide the cert by the sp.crt', 'onelogin-saml-sso');
	}

	function plugin_setting_string_onelogin_saml_advanced_settings_sp_privatekey() {
		echo '<textarea name="onelogin_saml_advanced_settings_sp_privatekey" id="onelogin_saml_advanced_settings_sp_privatekey" style="width:600px; height:220px; font-size:12px; font-family:courier,arial,sans-serif;">';
		echo get_option('onelogin_saml_advanced_settings_sp_privatekey');
		echo '</textarea>';
		echo '<p class="description">'.__('Private Key of the SP. Leave this field empty if you gonna provide the private key by the sp.key', 'onelogin-saml-sso');
	}

	function plugin_setting_boolean_onelogin_saml_advanced_settings_retrieve_parameters_from_server() {
		$value = get_option('onelogin_saml_advanced_settings_retrieve_parameters_from_server', false);
		echo '<input type="checkbox" name="onelogin_saml_advanced_settings_retrieve_parameters_from_server" id="onelogin_saml_advanced_settings_retrieve_parameters_from_server"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__('Sometimes when the app is behind a firewall or proxy, the query parameters can be modified an this affects the signature validation process on HTTP-Redirectbinding. Active this when you noticed signature validation failures, the plugin will try to extract the original query parameters.', 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_select_onelogin_saml_advanced_nameidformat() {
		$nameidformat_value = get_option('onelogin_saml_advanced_nameidformat');
		$posible_nameidformat_values = array(
			'unspecified' => OneLogin_Saml2_Constants::NAMEID_UNSPECIFIED,
			'emailAddress' => OneLogin_Saml2_Constants::NAMEID_EMAIL_ADDRESS,
			'transient' => OneLogin_Saml2_Constants::NAMEID_TRANSIENT,
			'persistent' => OneLogin_Saml2_Constants::NAMEID_PERSISTENT,
			'entity' => OneLogin_Saml2_Constants::NAMEID_ENTITY,
			'encrypted' => OneLogin_Saml2_Constants::NAMEID_ENCRYPTED,
			'kerberos' => OneLogin_Saml2_Constants::NAMEID_KERBEROS,
			'x509subjecname' => OneLogin_Saml2_Constants::NAMEID_X509_SUBJECT_NAME,
			'windowsdomainqualifiedname' => OneLogin_Saml2_Constants::NAMEID_WINDOWS_DOMAIN_QUALIFIED_NAME
		);

		echo '<select name="onelogin_saml_advanced_nameidformat" id="onelogin_saml_advanced_nameidformat">';

		foreach ($posible_nameidformat_values as $key => $value) {
			echo '<option value='.$key.' '.($key == $nameidformat_value ? 'selected="selected"': '').' >'.$value.'</option>';
		}

		echo '</select>'.
			 '<p class="description">'.__("Specifies constraints on the name identifier to be used to represent the requested subject.", 'onelogin-saml-sso').'</p>';
	}

	function plugin_setting_select_onelogin_saml_advanced_requestedauthncontext() {
		$requestedauthncontext_values = get_option('onelogin_saml_advanced_requestedauthncontext', array());

		if (!is_array($requestedauthncontext_values)) {
			$requestedauthncontext_values = array($requestedauthncontext_values);
		}

		$posible_requestedauthncontext_values = array(
			'unspecified' => OneLogin_Saml2_Constants::AC_UNSPECIFIED,
			'password' => OneLogin_Saml2_Constants::AC_PASSWORD,
			'passwordprotectedtransport' =>	"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
			'x509' => OneLogin_Saml2_Constants::AC_X509,
			'smartcard' => OneLogin_Saml2_Constants::AC_SMARTCARD,
			'kerberos' => OneLogin_Saml2_Constants::AC_KERBEROS,
		);

		echo '<select multiple="multiple" name="onelogin_saml_advanced_requestedauthncontext[]" id="onelogin_saml_advanced_requestedauthncontext">';
		echo '<option value=""></option>';
		foreach ($posible_requestedauthncontext_values as $key => $value) {
			echo '<option value='.$key.' '.(in_array($key, $requestedauthncontext_values) ? 'selected="selected"': '').' >'.$value.'</option>';
		}

		echo '</select>'.
			 '<p class="description">'.__("AuthContext sent in the AuthNRequest. You can select none, one or multiple values", 'onelogin-saml-sso').'</p>';

	}

	function plugin_section_idp_text() {
		echo "<p>".__("Set here some info related to the IdP that will be connected with our Wordpress. You can find this values at the Onelogin's platform in the Wordpress App at the Single Sign-On tab", 'onelogin-saml-sso')."</p>";
	}

	function plugin_section_options_text() {
		echo "<p>".__("In this section the behavior of the plugin is set.", 'onelogin-saml-sso')."</p>";
	}

	function plugin_section_attr_mapping_text() {
		echo "<p>".__("Sometimes the names of the attributes sent by the IdP not match the names used by Wordpress for the user accounts. In this section we can set the mapping between IdP fields and Wordpress fields. Notice that this mapping could be also set at Onelogin's IdP", 'onelogin-saml-sso')."</p>";
	}

	function plugin_section_role_mapping_text() {
		echo "<p>".__("The IdP can use it's own roles. Set in this section the mapping between IdP and Wordpress roles. Accepts multiple valued comma separated. Example: admin,owner,superuser", 'onelogin-saml-sso')."</p>";
	}

	function plugin_section_customize_links_text() {
		echo "<p>".__("When we enable the SAML SSO to be integrated with a IdP some Wordpress actions and links could be changed. In this section you will be able to enable or disable the ability of change the mail, change the password and reset the password. Also can override the user registration and the lost password links", 'onelogin-saml-sso')."</p>";
	}

	function plugin_section_advanced_settings_text() {
		echo "<p>".__("Handle some other parameters related to customizations and security issues.<br>If sign/encryption is enabled, then x509 cert and private key for the SP must be provided. There are 2 ways:<br>
			 1. Store them as files named sp.key and sp.crt on the 'certs' folder of the plugin. (be sure that the folder is protected and not exposed to internet)<br>
			 2. Store them at the database, filling the corresponding textareas. (take care of security issues)", 'onelogin-saml-sso')."</p>";
	}

	function plugin_section_text() {}
