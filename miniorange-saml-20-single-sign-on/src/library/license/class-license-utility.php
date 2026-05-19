<?php
/**
 * License Utility Class.
 *
 * @package MOSAML
 */

namespace MOSAML\SRC\Library\License;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\LicenseLibrary\Classes\Mo_License_Constants;
use MOSAML\LicenseLibrary\Classes\Mo_License_Dao;
use MOSAML\SRC\Exception\OpenSSL_Extension_Disabled_Exception;
use MOSAML\SRC\Handler\Exception_Handler;
use MOSAML\SRC\Utils\Utility;
use MOSAML\LicenseLibrary\Mo_License_Config;
use MOSAML\LicenseLibrary\Mo_License_Service;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\LicenseLibrary\Utils\Mo_License_View_Utility;
use MOSAML\LicenseLibrary\Classes\Mo_License_Library;
use MOSAML\LicenseLibrary\Mo_Update_Framework;
use MOSAML\SRC\Constant\Constants;

/**
 * Class License Utility.
 */
class License_Utility {

	/**
	 * Update framework instance.
	 *
	 * @var Mo_Update_Framework|null
	 */
	private static $update_framework_instance = null;

	/**
	 * Paid Plans.
	 *
	 * @var array
	 */
	const PAID_PLANS = array(
		'wp_saml_sso_standard_plan',
		'wp_saml_sso_basic_plan',
		'wp_saml_sso_multiple_idp_plan',
		'wp_saml_sso_all_inclusive_plan',
	);

	/**
	 * Initialize the bundled license library (paid plans only).
	 *
	 * @return void
	 */
	public static function initialize_library() {
		if ( ! self::common_checks( '\MOSAML\LicenseLibrary\Mo_License_Service' ) && ! ( MOSAML_VERSION > 1 ) ) {
			return;
		}

		$missing = Utility::check_required_extensions();
		if ( ! empty( $missing ) ) {
			$e = Utility::create_extension_disabled_exception( $missing[0] );
			if ( $e ) {
				Exception_Handler::throw_exception( $e, true );
			}
			return;
		}
		new Mo_License_Library();
	}

	/**
	 * Function to verify customer login and save details and show the admin notices accordingly.
	 */
	public function verify_customer() {

		if ( ! self::common_checks( '\MOSAML\LicenseLibrary\Mo_License_Service' ) ) {
			Error_Success_Message::show_admin_notice( 'Please upgrade your plan to be able to use paid features of the Plugin.' );
			return;
		}

		Utility::validate_curl_extension();

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verification is done already.
		if ( empty( $_POST ['email'] ) || empty( $_POST ['password'] ) ) {
			Error_Success_Message::show_admin_notice( 'All the fields are required. Please enter valid entries.' );
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verification is done already.
		$email    = sanitize_email( wp_unslash( $_POST['email'] ) );
		$password = Utility::sanitize_post_data( 'password' );

		$login_response = Mo_License_Service::verify_customer_credentials( $email, $password );

		$license_key = get_option( 'sml_lk' );
		if ( ! empty( $license_key ) ) {
			$license_response = Mo_License_Service::validate_customer_license_key( $license_key );
			Error_Success_Message::show_admin_notice( $license_response['MESSAGE'], 'LICENSE_VALID' === $license_response['STATUS'] ? 'SUCCESS' : 'ERROR' );
			return;
		}

		Error_Success_Message::show_admin_notice( $login_response['MESSAGE'], 'CUSTOMER_LOGGED_IN' === $login_response['STATUS'] ? 'SUCCESS' : 'ERROR' );
	}

	/**
	 * Function to verify license key and save details and show the admin notices accordingly.
	 */
	public function verify_license() {
		if ( ! self::common_checks( '\MOSAML\LicenseLibrary\Mo_License_Service' ) ) {
			Error_Success_Message::show_admin_notice( 'Please upgrade your plan to be able to use paid features of the Plugin.' );
			return;
		}
		$license_key = Utility::sanitize_post_data( 'mo_saml_license_key' );
		$result      = Mo_License_Service::validate_customer_license_key( $license_key );
		Error_Success_Message::show_admin_notice( $result['MESSAGE'], 'LICENSE_VALID' === $result['STATUS'] ? 'SUCCESS' : 'ERROR' );
	}

	/**
	 * Function to remove the user details and show the admin notices accordingly.
	 */
	public static function remove_user_login() {
		if ( ! self::common_checks( '\MOSAML\LicenseLibrary\Mo_License_Service' ) ) {
			return;
		}
		Mo_License_Service::reset_account_values();
		Error_Success_Message::show_admin_notice( 'Please login using your miniorange credentials.', 'SUCCESS' );
	}

	/**
	 * Function to remove license key and show the admin notices accordingly.
	 */
	public static function remove_account() {
		if ( ! self::common_checks( '\MOSAML\LicenseLibrary\Mo_License_Service' ) ) {
			return;
		}
		do_action( 'mosaml_flush_cache_internal' );
		$result = Mo_License_Service::free_license_key();
		Error_Success_Message::show_admin_notice( $result['MESSAGE'], 'LICENSE_FREED' === $result['STATUS'] ? 'SUCCESS' : 'ERROR' );
	}

	/**
	 * Function to remove license key and show the admin notices accordingly.
	 */
	public static function remove_account_from_plugin_deactivation() {
		if ( ! self::common_checks( '\MOSAML\LicenseLibrary\Mo_License_Service' ) ) {
			return;
		}
		$result = Mo_License_Service::free_license_key();
		Error_Success_Message::show_admin_notice( 'miniOrange SAML SSO plugin deactivated successfully.', 'SUCCESS' );
	}

	/**
	 * Function to sync license details and show the admin notices accordingly.
	 */
	public static function sync_license() {
		if ( ! self::common_checks( '\MOSAML\LicenseLibrary\Mo_License_Service' ) ) {
			return;
		}
		$result = Mo_License_Service::sync_license_details();
		Error_Success_Message::show_admin_notice( $result['MESSAGE'], 'LICENSE_SYNCED' === $result['STATUS'] ? 'SUCCESS' : 'ERROR' );
	}

	/**
	 * Function to check if the installed plugin is Free version.
	 *
	 * @return bool
	 */
	public static function is_free() {
		if ( ! class_exists( '\MOSAML\LicenseLibrary\Mo_License_Config' ) || ! defined( '\MOSAML\LicenseLibrary\Mo_License_Config::LICENSE_PLAN_NAME' ) ) {
			return true;
		}

		$plan_name = Mo_License_Config::LICENSE_PLAN_NAME;
		if ( in_array( $plan_name, self::PAID_PLANS, true ) ) {
			return false;
		}
		return true;
	}

	/**
	 * Function to perform a common check functionality used in multiple functions in this file.
	 *
	 * @param string $class_name Class Name.
	 * @return bool
	 */
	public static function common_checks( $class_name ) {
		if ( self::is_free() ) {
			return false;
		}
		if ( ! class_exists( $class_name ) ) {
			return false;
		}
		return true;
	}

	/**
	 * Function to check if the license is valid by calling library's function.
	 *
	 * @param bool $html_element Html Element.
	 * @param bool $check_expiry Check Expiry.
	 * @return bool
	 */
	public static function is_license_valid( $html_element = false, $check_expiry = true ) {
		if ( ! self::common_checks( '\MOSAML\LicenseLibrary\Mo_License_Service' ) ) {
			return false;
		}
		return Mo_License_Service::is_customer_license_valid( $html_element, $check_expiry );
	}

	/**
	 * Check if the license is expired.
	 *
	 * @return bool
	 */
	public static function is_license_expired() {
		if ( ! self::common_checks( '\MOSAML\LicenseLibrary\Mo_License_Service' ) ) {
			return false;
		}
		return Mo_License_Service::is_license_expired();
	}

	/**
	 * Function to check if the license is verified by calling library's function.
	 *
	 * @return bool
	 */
	public static function is_license_verified() {
		if ( ! self::common_checks( '\MOSAML\LicenseLibrary\Mo_License_Service' ) ) {
			return false;
		}
		return Mo_License_Service::is_customer_license_verified();
	}

	/**
	 * Function to check if the account is verified by calling library's function.
	 *
	 * @return bool
	 */
	public static function is_account_verified() {
		if ( ! self::common_checks( '\MOSAML\LicenseLibrary\Mo_License_Service' ) ) {
			return false;
		}
		return Mo_License_Service::is_customer_logged_into_plugin();
	}

	/**
	 * Function to check if the account is verified by calling library's function.
	 *
	 * @return string
	 */
	public static function get_expiry_date() {
		if ( ! self::common_checks( '\MOSAML\LicenseLibrary\Mo_License_Service' ) ) {
			return '';
		}
		return Mo_License_Service::get_expiry_date();
	}

	/**
	 * Function to check if the account is verified by calling library's function.
	 *
	 * @param string $expiry_date The expiry date of the license.
	 * @return bool
	 */
	public static function get_formatted_license_expiry_date( $expiry_date ) {
		if ( ! self::common_checks( '\MOSAML\LicenseLibrary\Mo_License_Service' ) ) {
			return '';
		}
		return Mo_License_Service::get_formatted_license_expiry_date( $expiry_date );
	}

	/**
	 * Function to get the disable date of the license.
	 *
	 * @param string $expiry_date The expiry date of the license.
	 * @return bool
	 */
	public static function get_disable_date( $expiry_date ) {
		if ( ! self::common_checks( '\MOSAML\LicenseLibrary\Mo_License_Service' ) ) {
			return '';
		}
		return Mo_License_Service::get_disable_date( $expiry_date );
	}

	/**
	 * Function to get the grace days left of the license.
	 *
	 * @param string $expiry_date The expiry date of the license.
	 * @return bool
	 */
	public static function get_grace_days_left( $expiry_date ) {
		if ( ! self::common_checks( '\MOSAML\LicenseLibrary\Mo_License_Service' ) ) {
			return '';
		}
		return Mo_License_Service::get_grace_days_left( $expiry_date );
	}

	/**
	 * Function to get the remaining days of the license.
	 *
	 * @param string $expiry_date The expiry date of the license.
	 * @return bool
	 */
	public static function get_remaining_days( $expiry_date ) {
		if ( ! self::common_checks( '\MOSAML\LicenseLibrary\Mo_License_Service' ) ) {
			return '';
		}
		return Mo_License_Service::get_expiry_remaining_days( $expiry_date );
	}

	/**
	 * Function to get the notice day key of the license.
	 *
	 * @param string $remaining_days The remaining days of the license.
	 * @return string
	 */
	public static function get_notice_day_key( $remaining_days ) {
		if ( ! self::common_checks( '\MOSAML\LicenseLibrary\Mo_License_Service' ) ) {
			return '';
		}
		return Mo_License_View_Utility::get_notice_day_key( $remaining_days );
	}

	/**
	 * Function to get the admin notice html of the license.
	 *
	 * @param string $day_key The day key of the license.
	 * @param array  $content_options The content options of the license.
	 * @return string
	 */
	public static function get_admin_notice_html( $day_key, $content_options ) {
		if ( ! self::common_checks( '\MOSAML\LicenseLibrary\Mo_License_Service' ) ) {
			return '';
		}
		return Mo_License_View_Utility::get_admin_notice_html( $day_key, $content_options );
	}

	/**
	 * Function to get the last synced time of the license.
	 *
	 * @return string
	 */
	public static function get_last_synced_time() {
		if ( ! self::common_checks( '\MOSAML\LicenseLibrary\Mo_License_Service' ) ) {
			return '';
		}
		return Mo_License_Dao::mo_get_option( Mo_License_Constants::LAST_CHECK_TIME_OPTION );
	}

	/**
	 * Function to fetch and display the addons view.
	 *
	 * @return void
	 */
	public static function fetch_addons_view() {
		if ( ! self::common_checks( '\MOSAML\LicenseLibrary\Mo_License_Service' ) ) {
			$addons_url = 'https://plugins.miniorange.com/wordpress-single-sign-on-sso-integrations';
			add_filter( 'allowed_redirect_hosts', array( __CLASS__, 'allowed_redirect_hosts' ) );
			wp_safe_redirect( $addons_url );
			remove_filter( 'allowed_redirect_hosts', array( __CLASS__, 'allowed_redirect_hosts' ) );
			exit;
		}
		Mo_License_Service::fetch_addons_view();
	}

	/**
	 * Allow redirects to miniOrange integrations page when using wp_safe_redirect().
	 *
	 * @param string[] $hosts Allowed redirect hosts.
	 * @return string[]
	 */
	public static function allowed_redirect_hosts( $hosts ) {
		$hosts[] = 'plugins.miniorange.com';
		return $hosts;
	}

	/**
	 * Function to validate license key and return result (for CLI usage).
	 *
	 * @param string $license_key License key to validate.
	 * @return array Array with STATUS and MESSAGE keys.
	 */
	public static function validate_license_key( $license_key ) {
		if ( ! self::common_checks( '\MOSAML\LicenseLibrary\Mo_License_Service' ) ) {
			return array(
				'STATUS'  => 'ERROR',
				'MESSAGE' => 'Please upgrade your plan to be able to use paid features of the Plugin.',
			);
		}
		return Mo_License_Service::validate_customer_license_key( $license_key );
	}

	/**
	 * Get the update framework instance.
	 * Follows the same pattern as the Instance trait for consistency.
	 * This is called early (on 'init' hook) to ensure it works in both admin and WP-CLI contexts.
	 *
	 * @return Mo_Update_Framework|null
	 */
	public static function update_framework_instance() {
		if ( ! class_exists( 'MOSAML\LicenseLibrary\Mo_Update_Framework' ) ) {
			return null;
		}

		if ( ! class_exists( 'MOSAML\LicenseLibrary\Mo_License_Config' ) ) {
			return null;
		}

		if ( ! Mo_License_Config::ENABLE_UPDATE_FRAMEWORK ) {
			return null;
		}

		if ( is_null( self::$update_framework_instance ) ) {
			$plugin_current_version          = Constants::VERSION_NUMBER[ MOSAML_VERSION ];
			$plugin_slug                     = plugin_basename( dirname( __DIR__, 3 ) . '/login.php' );
			self::$update_framework_instance = new Mo_Update_Framework( $plugin_current_version, $plugin_slug );
		}
		return self::$update_framework_instance;
	}
}
