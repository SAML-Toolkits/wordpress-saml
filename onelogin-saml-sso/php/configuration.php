<?php

	function onelogin_saml_configuration_render() {
		$title = "OneLogin SSO/SAML Settings";
		?>
			<div class="wrap">
				<?php screen_icon(); ?>
				<div class="alignright">
					<a href="<?php echo get_site_url().'/wp-content/plugins/onelogin-saml-sso/php/metadata.php'; ?>" target="blank"><?php echo __("Go to the metadata of this SP");?></a>
				</div>
				<h2><?php echo esc_html( $title ); ?></h2>
				<div class="alignright">
					<a href="<?php echo get_site_url().'/wp-content/plugins/onelogin-saml-sso/php/validate.php'; ?>" target="blank"><?php echo __("Once configured, validate here your OneLogin SSO/SAML Settings");?></a>
				</div>
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

		$helpText = '<p>' . __('This plugin provides single sign-on via SAML and gives users one-click access to their WordPress accounts from identity providers like OneLogin') . '</p>' .
			'<p><strong>' . __('For more information') . '</strong> '.__("access to the").' <a href="https://onelogin.zendesk.com/hc/en-us/articles/201173454-Configuring-SAML-for-WordPress" target="_blank">'.__("Plugin Info").'</a> ' .
			__("or visit") . ' <a href="http://onelogin.com/" target="_blank">OneLogin, Inc.</a>' . '</p>';
		
		if (function_exists('add_contextual_help')) {
			@add_contextual_help($current_screen, $helpText);
		}

		$option_group = 'onelogin_saml_configuration';

		add_settings_section('idp', __('IDENTITY PROVIDER SETTINGS'), 'plugin_section_idp_text', $option_group);
		$idp_fields = array (
			'onelogin_saml_idp_entityid' => __('IdP Entity Id') . ' *',
			'onelogin_saml_idp_sso' => __('Single Sign On Service Url') . ' *',
			'onelogin_saml_idp_slo' => __('Single Log Oout Service Url'),
			'onelogin_saml_idp_x509cert' => __('X.509 Certificate')
		);
		foreach ($idp_fields as $name => $description) {
			register_setting($option_group, $name);
			add_settings_field($name, $description, "plugin_setting_string_$name", $option_group, 'idp');
		}

		add_settings_section('options', 'OPTIONS', 'plugin_section_options_text', $option_group);
		$options_fields = array (
			'onelogin_saml_autocreate' => __('Create user if not exists'),
			'onelogin_saml_updateuser' => __('Update user data'),
			'onelogin_saml_forcelogin' => __('Force SAML login'),
			'onelogin_saml_slo' => __('Single Log Out')
		);
		foreach ($options_fields as $name => $description) {
			register_setting($option_group, $name);
			add_settings_field($name, $description, "plugin_setting_boolean_$name", $option_group, 'options');
		}

		register_setting($option_group, 'onelogin_saml_account_matcher');
		add_settings_field('onelogin_saml_account_matcher', __('Match Wordpress account by'), "plugin_setting_select_onelogin_saml_account_matcher", $option_group, 'options');

		add_settings_section('attr_mapping', 'ATTRIBUTE MAPPING', 'plugin_section_attr_mapping_text', $option_group);		
		$mapping_fields = array (
			'onelogin_saml_attr_mapping_username' => __('Username') . ' *',
			'onelogin_saml_attr_mapping_mail' => __('E-mail') . ' *',
			'onelogin_saml_attr_mapping_firstname' => __('First Name'),
			'onelogin_saml_attr_mapping_lastname' => __('Last Name'),
			'onelogin_saml_attr_mapping_role' => __('Role')
		);
		foreach ($mapping_fields as $name => $description) {
			register_setting($option_group, $name);
			add_settings_field($name, $description, "plugin_setting_string_$name", $option_group, 'attr_mapping');
		}

		add_settings_section('role_mapping', 'ROLE MAPPING', 'plugin_section_role_mapping_text', $option_group);		
		$mapping_fields = array (
			'onelogin_saml_role_mapping_administrator' => __('Administrator'),
			'onelogin_saml_role_mapping_editor' => __('Editor'),
			'onelogin_saml_role_mapping_author' => __('Author'),
			'onelogin_saml_role_mapping_contributor' => __('Contributor'),
			'onelogin_saml_role_mapping_subscriber' => __('Subscriber')
		);
		foreach ($mapping_fields as $name => $description) {
			register_setting($option_group, $name);
			add_settings_field($name, $description, "plugin_setting_string_$name", $option_group, 'role_mapping');
		}

		add_settings_section('advanced_settings', 'ADVANCED SETTINGS', 'plugin_section_advanced_settings_text', $option_group);

		register_setting($option_group, 'onelogin_saml_advanced_settings_debug');
		add_settings_field('onelogin_saml_advanced_settings_debug', __('Debug Mode'), "plugin_setting_boolean_onelogin_saml_advanced_settings_debug", $option_group, 'advanced_settings');

		register_setting($option_group, 'onelogin_saml_advanced_settings_strict_mode');
		add_settings_field('onelogin_saml_advanced_settings_strict_mode', __('Strict Mode'), "plugin_setting_boolean_onelogin_saml_advanced_settings_strict_mode", $option_group, 'advanced_settings');

		register_setting($option_group, 'onelogin_saml_advanced_settings_sp_entity_id');
		add_settings_field('onelogin_saml_advanced_settings_sp_entity_id', __('Service Provider Entity Id'), "plugin_setting_string_onelogin_saml_advanced_settings_sp_entity_id", $option_group, 'advanced_settings');

		$mapping_fields = array (
			'onelogin_saml_advanced_settings_nameid_encrypted' => __('Encrypt nameID'),
			'onelogin_saml_advanced_settings_authn_request_signed' => __('Sign AuthnRequest'),
			'onelogin_saml_advanced_settings_logout_request_signed' => __('Sign LogoutRequest'),
			'onelogin_saml_advanced_settings_logout_response_signed' => __('Sign LogoutResponse'),
			'onelogin_saml_advanced_settings_want_message_signed' => __('Reject Unsigned Messages'),
			'onelogin_saml_advanced_settings_want_assertion_signed' => __('Reject Unsigned Assertions'),						
			'onelogin_saml_advanced_settings_want_assertion_encrypted' => __('Reject Unencrypted Assertions')
		);
		foreach ($mapping_fields as $name => $description) {
			register_setting($option_group, $name);
			add_settings_field($name, $description, "plugin_setting_boolean_$name", $option_group, 'advanced_settings');
		}

		register_setting($option_group, 'onelogin_saml_advanced_settings_sp_x509cert');
		add_settings_field('onelogin_saml_advanced_settings_sp_x509cert', __('Service Provider X.509 Certificate'), "plugin_setting_string_onelogin_saml_advanced_settings_sp_x509cert", $option_group, 'advanced_settings');

		register_setting($option_group, 'onelogin_saml_advanced_settings_sp_privatekey');
		add_settings_field('onelogin_saml_advanced_settings_sp_privatekey', __('Service Provider Private Key'), "plugin_setting_string_onelogin_saml_advanced_settings_sp_privatekey", $option_group, 'advanced_settings');
	}

	function plugin_setting_string_onelogin_saml_idp_entityid() {
		echo '<input type="text" name="onelogin_saml_idp_entityid" id="onelogin_saml_idp_entityid" 
			  value= "'.get_option('onelogin_saml_idp_entityid').'" size="80">'.
			  '<p class="description">'.__('Identifier of the IdP entity. ("Issuer URL")').'</p>';
	}

	function plugin_setting_string_onelogin_saml_idp_sso() {
		echo '<input type="text" name="onelogin_saml_idp_sso" id="onelogin_saml_idp_sso"
			  value= "'.get_option('onelogin_saml_idp_sso').'" size="80">'.
			  '<p class="description">'.__('SSO endpoint info of the IdP. URL target of the IdP where the SP will send the Authentication Request. ("SAML 2.0 Endpoint (HTTP)")').'</p>';
	}

	function plugin_setting_string_onelogin_saml_idp_slo() {
		echo '<input type="text" name="onelogin_saml_idp_slo" id="onelogin_saml_idp_slo"
			  value= "'.get_option('onelogin_saml_idp_slo').'" size="80">'.
			  '<p class="description">'.__('SLO endpoint info of the IdP. URL target of the IdP where the SP will send the SLO Request. ("SLO Endpoint (HTTP)")').'</p>';
	}

	function plugin_setting_string_onelogin_saml_idp_x509cert() {
		echo '<textarea name="onelogin_saml_idp_x509cert" id="onelogin_saml_idp_x509cert" style="width:600px; height:220px; font-size:12px; font-family:courier,arial,sans-serif;">';
		echo get_option('onelogin_saml_idp_x509cert');
		echo '</textarea>';
		echo '<p class="description">'.__('Public x509 certificate of the IdP.  ("X.509 certificate")');
	}
	
	function plugin_setting_boolean_onelogin_saml_autocreate() {
		$value = get_option('onelogin_saml_autocreate');
		echo '<input type="checkbox" name="onelogin_saml_autocreate" id="onelogin_saml_autocreate"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__('Auto-provisioning. If user not exists,  Wordpress will create a new user with the data provided by the IdP.<br>Review the Mapping section.').'</p>';
	}

	function plugin_setting_boolean_onelogin_saml_updateuser() {
		$value = get_option('onelogin_saml_updateuser');
		echo '<input type="checkbox" name="onelogin_saml_updateuser" id="onelogin_saml_updateuser"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__('Auto-update. Wordpress will update the account of the user with the data provided by the IdP.<br>Review the Mapping section.').'</p>';
	}

	function plugin_setting_boolean_onelogin_saml_forcelogin() {
		$value = get_option('onelogin_saml_forcelogin');
		echo '<input type="checkbox" name="onelogin_saml_forcelogin" id="onelogin_saml_forcelogin"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__('Protect Wordpress and force the user to authenticate at the IdP in order to access').'</p>';
	}

	function plugin_setting_boolean_onelogin_saml_slo() {
		$value = get_option('onelogin_saml_slo');
		echo '<input type="checkbox" name="onelogin_saml_slo" id="onelogin_saml_slo"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__('Enable/disable Single Log Out. SLO  is a complex functionality, the most common SLO implementation is based on front-channel (redirections), sometimes if the SLO workflow fails a user can be blocked in an unhandled view. If the admin does not controls the set of apps involved in the SLO process maybe is better to disable this functionality due could carry more problems than benefits.').'</p>';
	}

	function plugin_setting_select_onelogin_saml_account_matcher() {
		$value = get_option('onelogin_saml_account_matcher');

		echo '<select name="onelogin_saml_account_matcher" id="onelogin_saml_account_matcher">
			  <option value="username" '.($value == 'username'?'selected="selected"':'').'>'.__("Username").'</option>
			  <option value="email" '.($value == 'email'? 'selected="selected"':'').'>'.__("E-mail").'</option>
			</select>'.
			'<p class="description">'.__("Select what field will be used in order to find the user account. If you select the 'email' fieldname the plugin will prevent that the user can change his mail in his profile.").'</p>';
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
			  '<p class="description">'.__("The attribute that contains the role of the user, For example 'memberof'. If Wordpress can't figure what role assign to the user, it will assign the default role defined at the general settings.").'</p>';
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

	function plugin_setting_boolean_onelogin_saml_advanced_settings_debug() {
		$value = get_option('onelogin_saml_advanced_settings_debug');
		echo '<input type="checkbox" name="onelogin_saml_advanced_settings_debug" id="onelogin_saml_advanced_settings_debug"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__('Enable it when your are debugging the SAML workflow. Errors and Warnigs will be showed.').'</p>';
	}

	function plugin_setting_boolean_onelogin_saml_advanced_settings_strict_mode() {
		$value = get_option('onelogin_saml_advanced_settings_strict_mode');
		echo '<input type="checkbox" name="onelogin_saml_advanced_settings_strict_mode" id="onelogin_saml_advanced_settings_strict_mode"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__("If Strict mode is Enabled, then Wordpress will reject unsigned or unencrypted messages if it expects them signed or encrypted.
			   Also will reject the messages if not strictly follow the SAML standard: Destination, NameId, Conditions ... are validated too.").'</p>';
	}

	function plugin_setting_string_onelogin_saml_advanced_settings_sp_entity_id() {
		echo '<input type="text" name="onelogin_saml_advanced_settings_sp_entity_id" id="onelogin_saml_advanced_settings_sp_entity_id"
			  value= "'.get_option('onelogin_saml_advanced_settings_sp_entity_id').'" size="30">'.
			  '<p class="description">'.__("Set the Entity ID for the Service Provider. If not provided, 'php-saml' will be used.").'</p>';
	}


	function plugin_setting_boolean_onelogin_saml_advanced_settings_nameid_encrypted() {
		$value = get_option('onelogin_saml_advanced_settings_nameid_encrypted');		
		echo '<input type="checkbox" name="onelogin_saml_advanced_settings_nameid_encrypted" id="onelogin_saml_advanced_settings_nameid_encrypted"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__('The nameID sent by this SP will be encrypted.').'</p>';
	}

	function plugin_setting_boolean_onelogin_saml_advanced_settings_authn_request_signed() {
		$value = get_option('onelogin_saml_advanced_settings_authn_request_signed');		
		echo '<input type="checkbox" name="onelogin_saml_advanced_settings_authn_request_signed" id="onelogin_saml_advanced_settings_authn_request_signed"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__('The samlp:AuthnRequest messages sent by this SP will be signed.').'</p>';
	}

	function plugin_setting_boolean_onelogin_saml_advanced_settings_logout_request_signed() {
		$value = get_option('onelogin_saml_advanced_settings_logout_request_signed');		
		echo '<input type="checkbox" name="onelogin_saml_advanced_settings_logout_request_signed" id="onelogin_saml_advanced_settings_logout_request_signed"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__('The samlp:logoutRequest messages sent by this SP will be signed.').'</p>';
	}	

	function plugin_setting_boolean_onelogin_saml_advanced_settings_logout_response_signed() {
		$value = get_option('onelogin_saml_advanced_settings_logout_response_signed');		
		echo '<input type="checkbox" name="onelogin_saml_advanced_settings_logout_response_signed" id="onelogin_saml_advanced_settings_logout_response_signed"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__('The samlp:logoutResponse messages sent by this SP will be signed.').'</p>';
	}

	function plugin_setting_boolean_onelogin_saml_advanced_settings_want_message_signed() {
		$value = get_option('onelogin_saml_advanced_settings_want_message_signed');		
		echo '<input type="checkbox" name="onelogin_saml_advanced_settings_want_message_signed" id="onelogin_saml_advanced_settings_want_message_signed"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__('Reject unsigned samlp:Response, samlp:LogoutRequest and samlp:LogoutResponse received').'</p>';
	}

	function plugin_setting_boolean_onelogin_saml_advanced_settings_want_assertion_signed() {
		$value = get_option('onelogin_saml_advanced_settings_want_assertion_signed');		
		echo '<input type="checkbox" name="onelogin_saml_advanced_settings_want_assertion_signed" id="onelogin_saml_advanced_settings_want_assertion_signed"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__('Reject unsigned saml:Assertion received').'</p>';
	}

	function plugin_setting_boolean_onelogin_saml_advanced_settings_want_assertion_encrypted() {
		$value = get_option('onelogin_saml_advanced_settings_want_assertion_encrypted');		
		echo '<input type="checkbox" name="onelogin_saml_advanced_settings_want_assertion_encrypted" id="onelogin_saml_advanced_settings_want_assertion_encrypted"
			  '.($value ? 'checked="checked"': '').'>'.
			  '<p class="description">'.__('Reject unencrypted saml:Assertion received').'</p>';
	}

	function plugin_setting_string_onelogin_saml_advanced_settings_sp_x509cert() {
		echo '<textarea name="onelogin_saml_advanced_settings_sp_x509cert" id="onelogin_saml_advanced_settings_sp_x509cert" style="width:600px; height:220px; font-size:12px; font-family:courier,arial,sans-serif;">';
		echo get_option('onelogin_saml_advanced_settings_sp_x509cert');
		echo '</textarea>';
		echo '<p class="description">'.__('Public x509 certificate of the SP. Leave this field empty if you gonna provide the private key by the sp.crt');
	}

	function plugin_setting_string_onelogin_saml_advanced_settings_sp_privatekey() {
		echo '<textarea name="onelogin_saml_advanced_settings_sp_privatekey" id="onelogin_saml_advanced_settings_sp_privatekey" style="width:600px; height:220px; font-size:12px; font-family:courier,arial,sans-serif;">';
		echo get_option('onelogin_saml_advanced_settings_sp_privatekey');
		echo '</textarea>';
		echo '<p class="description">'.__('Private Key of the SP. Leave this field empty if you gonna provide the private key by the sp.key');
	}	

	function plugin_section_idp_text() {
		echo "<p>".__("Set here some info related to the IdP that will be connected with our Wordpress. You can find this values at the Onelogin's platform in the Wordpress App at the Single Sign-On tab")."</p>";
	}

	function plugin_section_options_text() {
		echo "<p>".__("In this section the behavior of the plugin is set.")."</p>";
	}

	function plugin_section_attr_mapping_text() {
		echo "<p>".__("Sometimes the names of the attributes sent by the IdP not match the names used by Wordpress for the user accounts. In this section we can set the mapping between IdP fields and Wordpress fields. Notice that this mapping could be also set at Onelogin's IdP")."</p>";
	}

	function plugin_section_role_mapping_text() {
		echo "<p>".__("The IdP can use it's own roles. Set in this section the mapping between IdP and Wordpress roles. Accepts multiple valued comma separated. Example: admin,owner,superuser")."</p>";
	}

	function plugin_section_advanced_settings_text() {
		echo "<p>".__("Handle some other parameters related to customizations and security issues.<br>If sign/encryption is enabled, then x509 cert and private key for the SP must be provided. There are 2 ways:<br>
			 1. Store them as files named sp.key and sp.crt on the 'certs' folder of the plugin. (be sure that the folder is protected and not exposed to internet)<br>
			 2. Store them at the database, filling the corresponding textareas. (take care of security issues)")."</p>";
	}

	function plugin_section_text() {}
