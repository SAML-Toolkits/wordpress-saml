<?php

if ( !function_exists( 'add_action' ) ) {
	echo 'Hi there!  I\'m just a plugin, not much I can do when called directly.';
	exit;
}

if (!current_user_can('delete_plugins')) {
     header("HTTP/1.0 403 Forbidden");
     echo '<h1>'.__("Access Forbidden!", 'onelogin-saml-sso').'</h1>';
     exit();
}

require_once "_toolkit_loader.php";
use OneLogin\Saml2\Settings;

require_once "compatibility.php";

?>
<!DOCTYPE html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>SSO/SAML Settings &lsaquo; Demo Onelogin wordpress &#8212; WordPress</title>
</head>
<body>

<?php

echo '<h1>'.__('OneLogin SSO/SAML Settings validation', 'onelogin-saml-sso').'</h1>';

echo __('Debug mode', 'onelogin-saml-sso').' '. ($settings['debug']?'<strong>on</strong>. '.__("In production turn it off", 'onelogin-saml-sso'):'<strong>off</strong>').'<br>';
echo __('Strict mode', 'onelogin-saml-sso').' '. ($settings['strict']?'<strong>on</strong>':'<strong>off</strong>. '.__("In production we recommend to turn it on.", 'onelogin-saml-sso')).'<br>';

$spPrivatekey = $settings['sp']['x509cert'];
$spCert = $settings['sp']['privateKey'];

try {
	$samlSettings = new Settings($settings);
	echo '<br>'.__("SAML settings are", 'onelogin-saml-sso').' <strong>ok</strong>.<br>';
} catch (\Exception $e) {
	echo '<br>'.__("Found errors while validating SAML settings info.", 'onelogin-saml-sso');
	echo esc_html($e->getMessage());
	echo '<br>';
}

$forcelogin = get_option('onelogin_saml_forcelogin');
if ($forcelogin) {
	echo '<br>'.__("Force SAML Login is enabled, that means that the user will be redirected to the IdP before getting access to Wordpress.", 'onelogin-saml-sso').'<br>';
}

$slo = get_option('onelogin_saml_slo');
if ($slo) {
	echo '<br>'.__("Single Log Out is enabled. If the SLO process fail, close your browser to be sure that session of the apps are closed.", 'onelogin-saml-sso').'<br>';
} else {
	echo '<br>'.__("Single Log Out is disabled. If you log out from Wordpress your session at the IdP keeps alive.", 'onelogin-saml-sso').'<br>';
}

$fileSystemKeyExists = file_exists(plugin_dir_path(__FILE__).'certs/sp.key');
$fileSystemCertExists = file_exists(plugin_dir_path(__FILE__).'certs/sp.crt');
if ($fileSystemKeyExists) {
	$privatekey_url = plugins_url('php/certs/sp.key', __DIR__);
	echo '<br>'.__("There is a private key stored at the filesystem. Protect the 'certs' path. Nobody should be allowed to access:", 'onelogin-saml-sso').'<br>'.esc_html( $privatekey_url ).'<br>';
}

if ($spPrivatekey && !empty($spPrivatekey)) {
	echo '<br>'.__("There is a private key stored at the database. (An attacker could own your database and get it. Take care)", 'onelogin-saml-sso').'<br>';
}

if (($spPrivatekey && !empty($spPrivatekey) && $fileSystemKeyExists) ||
	($spCert && !empty($spCert) && $fileSystemCertExists)) {
	echo '<br>'.__("Private key/certs stored on database have priority over the private key/cert stored at filesystem", 'onelogin-saml-sso').'<br>';
}

$autocreate = get_option('onelogin_saml_autocreate');
$updateuser = get_option('onelogin_saml_updateuser');

if ($autocreate) {
	echo '<br>'.__("User will be created if not exists, based on the data sent by the IdP.", 'onelogin-saml-sso').'<br>';
} else {
	echo '<br>'.__("If the user not exists, access is prevented.", 'onelogin-saml-sso').'<br>';
}

if ($updateuser) {
	echo '<br>'.__("User account will be updated with the data sent by the IdP.", 'onelogin-saml-sso').'<br>';
}

if ($autocreate || $updateuser) {
	echo '<br>'.__("Is important to set the attribute and the role mapping before auto-provisioning or updating an account.", 'onelogin-saml-sso').'<br>';
}

$attr_mappings = array (
	'onelogin_saml_attr_mapping_username' => __('Username', 'onelogin-saml-sso'),
	'onelogin_saml_attr_mapping_mail' => __('E-mail', 'onelogin-saml-sso'),
	'onelogin_saml_attr_mapping_firstname' => __('First Name', 'onelogin-saml-sso'),
	'onelogin_saml_attr_mapping_lastname' => __('Last Name', 'onelogin-saml-sso'),
	'onelogin_saml_attr_mapping_role' => __('Role', 'onelogin-saml-sso'),
);

$account_matcher = get_option('onelogin_saml_account_matcher', 'username');

$lacked_attr_mappings = array();
foreach ($attr_mappings as $field => $name) {
	$value = get_option($field);
	if (empty($value)) {
		if ($account_matcher == 'username' && $field == 'onelogin_saml_attr_mapping_username') {
			echo '<br>'.__("Username mapping is required in order to enable the SAML Single Sign On", 'onelogin-saml-sso').'<br>';
		}
		if ($account_matcher == 'email' && $field == 'onelogin_saml_attr_mapping_mail') {
			echo '<br>'.__("E-mail mapping is required in order to enable the SAML Single Sign On", 'onelogin-saml-sso').'<br>';
		}
		$lacked_attr_mappings[] = $name;
	}
}

if (!empty($lacked_attr_mappings)) {
	echo '<br>'.__("Notice that there are attributes without mapping:", 'onelogin-saml-sso').'<br>';
	echo wp_kses( implode('<br>',$lacked_attr_mappings), array( 'br' => array() ) ).'</br>';
}

$lacked_role_mappings = array();
$lacked_role_orders = array();
foreach (wp_roles()->get_names() as $roleid => $name) {
	$value = get_option('onelogin_saml_role_mapping_'.$roleid);
	if (empty($value)) {
		$lacked_role_mappings[] = $name;
	}
	$value = get_option('onelogin_saml_role_order_'.$roleid);
	if (empty($value)) {
		$lacked_role_orders[] = $name;
	}
}

if (!empty($lacked_role_mappings)) {
	echo '<br>'.__("Notice that there are roles without mapping:", 'onelogin-saml-sso').'<br>';
	echo wp_kses( implode('<br>', $lacked_role_mappings ), array( 'br' => array() ) ).'</br>';
}

if (!empty($lacked_role_orders)) {
	echo '<br>'.__("Notice that there are roles without ordering:", 'onelogin-saml-sso').'<br>';
	echo wp_kses( implode('<br>', $lacked_role_orders), array( 'br' => array() ) ).'</br>';
}
?>

</body>
</html>
