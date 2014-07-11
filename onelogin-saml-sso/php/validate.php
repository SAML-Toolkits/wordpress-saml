<?php

require_once(dirname(dirname(dirname(dirname(dirname(__FILE__))))) . '/wp-load.php');

require plugin_dir_path(__FILE__).'settings.php';

if (!current_user_can('delete_plugins')) {
     header("HTTP/1.0 403 Forbidden");
     echo '<h1>'.__("Access Forbidden!").'</h1>';
     exit();
}

require_once plugin_dir_path(__FILE__).'_toolkit_loader.php';

echo '<h1>OneLogin SSO/SAML Settings validation</h1>';

echo 'Debug mode '. ($settings['strict']?'<strong>on</strong>. '.__("In production turn it off"):'<strong>off</strong>').'<br>';
echo 'Strict mode '. ($settings['debug']?'<strong>on</strong>':'<strong>off</strong>. '.__("In production we recommend to turn it on.")).'<br>';

$spPrivatekey = $settings['sp']['x509cert'];
$spCert = $settings['sp']['privateKey'];

try {
	$samlSettings = new OneLogin_Saml2_Settings($settings);
	echo '<br>'.__("SAML settings are").' <strong>ok</strong>.<br>';
} catch (Exception $e) {
	echo '<br>'.__("Found errors while validating SAML settings info. ");
	print_r($e->getMessage());
	echo '<br>';
}

$forcelogin = get_option('onelogin_saml_forcelogin');
if ($forcelogin) {
	echo '<br>'.__("Force SAML Login is enabled, that means that the user will be redirected to the IdP before getting access to Wordpress.").'<br>';
}

$slo = get_option('onelogin_saml_slo');
if ($slo) {
	echo '<br>'.__("Single Log Out is enabled. If the SLO process fail, close your browser to be sure that session of the apps are closed.").'<br>';
} else {
	echo '<br>'.__("Single Log Out is disabled. If you log out from Wordpress your session at the IdP keeps alive.").'<br>';
}

$fileSystemKeyExists = file_exists(plugin_dir_path(__FILE__).'certs/sp.key');
$fileSystemCertExists = file_exists(plugin_dir_path(__FILE__).'certs/sp.crt');
if ($fileSystemKeyExists) {
	$privatekey_url = plugins_url('php/certs/sp.key', dirname(__FILE__));
	echo '<br>'.__("There is a private key stored at the filesystem. Protect the 'certs' path. Nobody should be allowed to access:").'<br>'.$privatekey_url.'<br>';
}

if ($spPrivatekey && !empty($spPrivatekey)) {
	echo '<br>'.__("There is a private key stored at the database. (An attacker could own your database and get it. Take care)<br>");
}

if (($spPrivatekey && !empty($spPrivatekey) && $fileSystemKeyExists) ||
	($spCert && !empty($spCert) && $fileSystemCertExists)) {
	echo '<br>'.__("Private key/certs stored on database have priority over the private key/cert stored at filesystem").'<br>';
}

$autocreate = get_option('onelogin_saml_autocreate');
$updateuser = get_option('onelogin_saml_updateuser');

if ($autocreate) {
	echo '<br>'.__("User will be created if not exists, based on the data sent by the IdP.").'<br>';
} else {
	echo '<br>'.__("If the user not exists, access is prevented.").'<br>';
}

if ($updateuser) {
	echo '<br>'.__("User account will be updated with the data sent by the IdP.").'<br>';
}

if ($autocreate || $updateuser) {
	echo '<br>'.__("Is important to set the attribute and the role mapping when auto-provisioning or account update are active.").'<br>';
}

$attr_mappings = array (
	'onelogin_saml_attr_mapping_username' => __('Username'),
	'onelogin_saml_attr_mapping_mail' => __('E-mail'),
	'onelogin_saml_attr_mapping_firstname' => __('First Name'),
	'onelogin_saml_attr_mapping_lastname' => __('Last Name'),
	'onelogin_saml_attr_mapping_role' => __('Role'),
);

$account_matcher = get_option('onelogin_saml_account_matcher', 'username');

$lacked_attr_mappings = array();
foreach ($attr_mappings as $field => $name) {
	$value = get_option($field);
	if (empty($value)) {
		if ($account_matcher == 'username' && $field == 'onelogin_saml_attr_mapping_username') {
			echo '<br>'.__("Username mapping is required in order to enable the SAML Single Sign On").'<br>';
		}
		if ($account_matcher == 'email' && $field == 'onelogin_saml_attr_mapping_mail') {
			echo '<br>'.__("E-mail mapping is required in order to enable the SAML Single Sign On").'<br>';
		}		
		$lacked_attr_mappings[] = $name;
	}
}

if (!empty($lacked_attr_mappings)) {
	echo '<br>'.__("Notice that there are attributes without mapping:").'<br>';
	print_r(implode('<br>', $lacked_attr_mappings).'</br>');
}

$role_mappings = array (
	'onelogin_saml_role_mapping_administrator' => __('Administrator'),
	'onelogin_saml_role_mapping_editor' => __('Editor'),
	'onelogin_saml_role_mapping_author' => __('Author'),
	'onelogin_saml_role_mapping_contributor' => __('Contributor'),
	'onelogin_saml_role_mapping_subscriber' => __('Subscriber')
);

$lacked_role_mappings = array();
foreach ($role_mappings as $field => $name) {
	$value = get_option($field);
	if (empty($value)) {
		$lacked_role_mappings[] = $name;
	}
}

if (!empty($lacked_role_mappings)) {
	echo '<br>'.__("Notice that there are roles without mapping:").'<br>';
	print_r(implode('<br>', $lacked_role_mappings).'</br>');
}
