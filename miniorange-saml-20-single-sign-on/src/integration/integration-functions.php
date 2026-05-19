<?php
/**
 * Integration Functions.
 *
 * @package miniorange-saml-20-single-sign-on/integration
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound -- Already defined functions.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Plugin_Files_Constants;
use MOSAML\SRC\Hook\Hooks_Action;
use MOSAML\SRC\Utils\Feature_Control;
use MOSAML\SRC\Utils\Utility;

/**
 * Check if license is verified
 *
 * @return bool
 */
function mo_saml_is_customer_license_key_verified() {
	return Feature_Control::check_is_license_valid();
}

/**
 * Check if customer is registered.
 *
 * @return mixed|null
 */
function mo_saml_is_customer_registered() {
	return Utility::handle_license_calls( 'is_account_verified', 'library', false );
}

/**
 * Check if customer is registered.
 *
 * @return mixed|null
 */
function mo_saml_is_customer_registered_saml() {
	return Utility::handle_license_calls( 'is_account_verified', 'library', false );
}

/**
 * Add Support file.
 *
 * @return void
 */
function miniorange_support_saml() {
	require_once Plugin_Files_Constants::TEMPLATE_SUPPORT_FORM;
}

/**
 * Back-compat: serves legacy `saml_identity_providers` option data from custom tables.
 *
 * Registered on {@see 'pre_option_saml_identity_providers'} so `get_option( 'saml_identity_providers' )`
 * returns the historical associative array shape for older add-ons.
 *
 * @param mixed  $pre_option Value passed through pre_option (typically false).
 * @param string $option     Option name.
 * @param mixed  $default    Default passed to get_option.
 * @return array|false
 */
function mo_saml_get_legacy_idp_option( $pre_option, $option = '', $default = false ) {
	return Hooks_Action::mo_saml_get_legacy_idp_option( $pre_option, $option, $default );
}

/**
 * Back-compat: serves legacy `mo_saml_test_config_attrs` option data from custom tables.
 *
 * Registered on {@see 'pre_option_mo_saml_test_config_attrs'} so `get_option( 'mo_saml_test_config_attrs' )`
 * returns the historical associative array shape for older add-ons.
 *
 * @param mixed  $pre_option Value passed through pre_option (typically false).
 * @param string $option     Option name.
 * @param mixed  $default    Default passed to get_option.
 * @return array|false
 */
function mo_saml_get_legacy_test_config_attrs( $pre_option, $option = '', $default = false ) {
	return Hooks_Action::mo_saml_get_legacy_test_config_attrs( $pre_option, $option, $default );
}

/**
 * Renders the SAML attributes table markup for third-party add-ons using {@see Plugin_Files_Constants::TEMPLATE_TEST_CONFIG_ATTRIBUTE_TABLE}.
 *
 * Displays only the passed attribute map; no database or IdP resolution is performed. The first parameter is kept for
 * add-on API compatibility and is unused here.
 *
 * @param mixed $idp_id Unused. Reserved for add-on compatibility.
 * @param array $attrs  Attribute map: attribute name => string or list of strings.
 * @return string HTML markup, or empty string if the template cannot be loaded.
 */
function mo_saml_display_attrs_list( $idp_id, $attrs = array() ) {
	unset( $idp_id );

	if ( ! is_array( $attrs ) ) {
		if ( is_string( $attrs ) ) {
			$decoded = json_decode( $attrs, true );
			$attrs   = is_array( $decoded ) ? $decoded : array();
		} else {
			$attrs = array();
		}
	}

	$idp_details                         = new \stdClass();
	$idp_details->id                     = 0;
	$idp_details->test_config_attributes = $attrs;

	$disable_due_to_no_idp = 'disabled';

	require_once Plugin_Files_Constants::TEMPLATE_TEST_CONFIG_ATTRIBUTE_TABLE;
}
