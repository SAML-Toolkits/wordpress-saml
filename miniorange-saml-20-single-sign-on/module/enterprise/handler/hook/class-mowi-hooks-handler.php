<?php
/**
 * Mowi hooks handler (enterprise module).
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\Module\Enterprise\Handler\Hook;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Hook\Mowi_Hooks_Handler as Premium_Mowi_Hooks_Handler;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Utils\Utility;

/**
 * Mowi_Hooks_Handler class.
 */
class Mowi_Hooks_Handler extends Premium_Mowi_Hooks_Handler {
	/**
	 * Function to initialize the hooks for the integrator addon.
	 *
	 * @return void
	 */
	public function init() {
		add_filter( 'mowi_authentication_plugins', array( self::class, 'mo_saml_plugin_name' ) );
		add_filter( 'mowi_configured_idps', array( self::class, 'mo_saml_configured_idps' ), 10, 2 );
		add_filter( 'mowi_idp_test_attributes', array( self::class, 'mo_saml_test_attributes' ), 10, 3 );
		add_filter( 'mowi_is_license_valid', array( self::class, 'mo_saml_is_license_valid' ), 10, 3 );
		add_filter( 'mowi_is_customer_logged_in', array( self::class, 'mo_saml_is_customer_logged_in' ) );
		add_filter( 'mowi_login_page_url', array( self::class, 'mo_saml_login_page_url' ) );
		add_filter( 'mowi_logged_in_customer_details', array( self::class, 'mo_saml_logged_in_customer_details' ) );
	}

	/**
	 * Function to handle the mowi_authentication_plugins filter.
	 *
	 * @param array $authentication_plugins List of the SSO plugins that are compatible with the integrator addon.
	 * @return array
	 */
	public static function mo_saml_plugin_name( $authentication_plugins ) {
		return array_merge(
			$authentication_plugins,
			array(
				'saml' => 'SAML 2.0 SSO',
			)
		);
	}

	/**
	 * Function to handle the mowi_configured_idps filter.
	 *
	 * @param array  $idps IDP list for all the authentication plugins.
	 * @param string $plugin Selected plugin to get the IDPs list.
	 * @return array
	 */
	public static function mo_saml_configured_idps( $idps, $plugin ) {
		$configured_idps = array();
		if ( 'saml' === $plugin ) {
			$idp_details = DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['idp_details'], array( 'environment_id' => DB_Utils::get_environment_details( 'id' ) ) );
			if ( $idp_details ) {
				foreach ( $idp_details as $idp_detail ) {
					if ( 'All IDPs' === $idp_detail->idp_name ) {
						continue;
					}
					$configured_idps[ $idp_detail->idp_id ] = $idp_detail->idp_name;
				}
			}
			$idps[ $plugin ] = $configured_idps;
		}
		return $idps;
	}

	/**
	 * Function to handle the mowi_idp_test_attributes filter
	 *
	 * @param array  $attributes Attributes for all the other configured IDPs.
	 * @param string $idp Selected IDP to get the test attributes.
	 * @param string $plugin Selected authentication plugin to show the test configuration attributes.
	 * @return array
	 */
	public static function mo_saml_test_attributes( $attributes, $idp, $plugin ) {
		if ( 'saml' === $plugin ) {
			$idp_details = DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['idp_details'], array( 'idp_id' => $idp ), true );
			if ( $idp_details ) {
				$attributes[ $plugin ][ $idp ] = maybe_unserialize( $idp_details->test_config_attributes );
			}
		}
		return $attributes;
	}

	/**
	 * Function to handle the mowi_is_license_valid filter.
	 *
	 * @param bool|string $status Current status of the plugin.
	 * @param bool        $html_element Boolean value to determine if license validity needs to be checked for form input fields.
	 * @param bool        $check_expiry Boolean value to determine if the function only checks if the customer has logged into the plugin and the entered license key is valid.
	 * @return bool|string
	 */
	public static function mo_saml_is_license_valid( $status, $html_element, $check_expiry ) {
		return Utility::handle_license_calls(
			'is_license_valid',
			'library',
			false,
			$status,
			$html_element,
			$check_expiry,
		);
	}

	/**
	 * Function to handle the mowi_is_customer_logged_in filter.
	 *
	 * @return boolean
	 */
	public static function mo_saml_is_customer_logged_in() {
		return Utility::handle_license_calls( 'is_account_verified', 'library', false );
	}

	/**
	 * Function to handle the mowi_login_page_url filter.
	 *
	 * @return string
	 */
	public static function mo_saml_login_page_url() {
		return 'admin.php?page=mo_saml_settings&tab=login';
	}

	/**
	 * Function to handle the mowi_logged_in_customer_details filter.
	 *
	 * @return array
	 */
	public static function mo_saml_logged_in_customer_details() {
		return array(
			'EMAIL'        => get_option( 'mo_saml_admin_email' ),
			'PHONE'        => get_option( 'mo_saml_admin_phone' ),
			'CUSTOMER_KEY' => get_option( 'mo_saml_admin_customer_key' ),
			'API_KEY'      => get_option( 'mo_saml_admin_api_key' ),
		);
	}
}
