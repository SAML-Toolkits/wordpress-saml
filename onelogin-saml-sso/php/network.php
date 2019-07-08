<?php

if ( !function_exists( 'add_action' ) ) {
    echo 'Hi there!  I\'m just a plugin, not much I can do when called directly.';
    exit;
}

if (!current_user_can('manage_options')) {
     header("HTTP/1.0 403 Forbidden");
     echo '<h1>'.__("Access Forbidden!", 'onelogin-saml-sso').'</h1>';
     exit();
}

$title = __("Network SSO/SAML Settings", 'network-onelogin-saml-sso');

$option_group = 'onelogin_saml_configuration_network';

?>

<h1><?php echo esc_html($title); ?></h1>

<p>Define here SAML Settings that can be later injected in several sites</p>

<form method="post" action="edit.php?action=network_saml_settings">
<?php
	wp_nonce_field('network_saml_settings_validate');

	$sections = get_sections();
	unset($sections['status']);
	$fields = get_onelogin_saml_settings();
	unset($fields['status']);
	$special_fields = array(
		'onelogin_saml_role_mapping_multivalued_in_one_attribute_value',
		'onelogin_saml_role_mapping_multivalued_pattern'
	);

	foreach ($sections as $section => $description) {
		echo '<h2>'.$description.'</h2>';
		call_user_func('plugin_section_'.$section.'_text');

		echo '<table class="form-table"><tbody>';
		foreach ($fields[$section] as $name => $data) {
			$description = $data[0];
			$type = $data[1];
			echo '<tr><th scope="row">'.$description.'</th>';
			echo '<td>';

			if ($section == 'role_mapping' && !in_array($name, $special_fields)) {
				$role_value = str_replace('onelogin_saml_role_mapping_', '', $name);
				call_user_func("plugin_setting_".$type."_onelogin_saml_role_mapping", $role_value, true);
			} else if ($section == 'role_precedence') {
				$role_value = str_replace('onelogin_saml_role_order_', '', $name);
				call_user_func("plugin_setting_".$type."_onelogin_saml_role_order", $role_value, true);
			} else {
				call_user_func("plugin_setting_".$type."_".$name, true);
			}

			echo '</td>';
		}
		echo '</tbody></table>';
	}

	submit_button();

	echo '</form>';
