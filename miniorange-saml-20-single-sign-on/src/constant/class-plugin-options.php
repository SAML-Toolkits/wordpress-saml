<?php
/**
 * Plugin Options.
 *
 * This class contains the options for the plugin.
 *
 * @package miniorange-saml-20-single-sign-on/src/constant
 */

namespace MOSAML\SRC\Constant;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Plugin Options.
 *
 * This class contains the options for the plugin.
 */
class Plugin_Options {

	const SAML_REQUEST_OPTION = array(
		'SAML_USER_LOGIN'      => 'saml_user_login',
		'TEST_CONFIG'          => 'testConfig',
		'END_USER_TEST_CONFIG' => 'testSSOLogin',
		'CONTINUE_TO_SITE'     => 'mo_saml_continue_to_site',
	);

	const SAML_REQUEST = 'SAMLRequest';

	const SAML_RESPONSE_OPTION = array(
		'SAML_RESPONSE' => 'SAMLResponse',
	);
}
