<?php
/**
 * This file is part of miniOrange WP plugin.
 *
 * @package    miniOrange
 * @author     miniOrange Security Software Pvt. Ltd.
 */

namespace MOSAML\LicenseLibrary;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'MO_LICENSE_LIBRARY_PATH' ) ) {
	define( 'MO_LICENSE_LIBRARY_PATH', plugin_dir_url( __FILE__ ) );
}

use MOSAML\LicenseLibrary\Classes\Mo_License_Constants;
use MOSAML\LicenseLibrary\Classes\Mo_License_Dao;
use MOSAML\LicenseLibrary\Exceptions\Mo_License_Already_Used_License_Key_Exception;
use MOSAML\LicenseLibrary\Exceptions\Mo_License_Grace_Expired_Exception;
use MOSAML\LicenseLibrary\Exceptions\Mo_License_Invalid_Expiry_Date_Exception;
use MOSAML\LicenseLibrary\Exceptions\Mo_License_Invalid_License_Key_Exception;
use MOSAML\LicenseLibrary\Exceptions\Mo_License_Invalid_Username_Or_Password_Exception;
use MOSAML\LicenseLibrary\Exceptions\Mo_License_Plan_Not_Purchased_Exception;
use MOSAML\LicenseLibrary\Exceptions\Mo_License_Missing_Customer_Email_Exception;
use MOSAML\LicenseLibrary\Exceptions\Mo_License_Missing_License_Key_Exception;
use MOSAML\LicenseLibrary\Exceptions\Mo_License_Missing_Or_Invalid_Customer_Key_Exception;
use MOSAML\LicenseLibrary\Exceptions\Mo_License_Network_Error_Exception;
use MOSAML\LicenseLibrary\Exceptions\Mo_License_Unknown_Error_Exception;
use MOSAML\LicenseLibrary\Utils\Mo_License_Actions_Utility;
use MOSAML\LicenseLibrary\Utils\Mo_License_Service_Utility;
use MOSAML\LicenseLibrary\Views\Mo_License_Addons_Views;

/**
 * Contains utility functions which can be used to implement the licensing framework.
 */
class Mo_License_Service {

	/**
	 * Base URL/path for license library assets.
	 *
	 * @var string
	 */
	public static $license_library_path;

	/**
	 * Function to check whether the plugin’s license grace period has expired. It internally first verifies
	 * if the customer’s license is verified by calling the check_customer_login_and_license() function.
	 *
	 * @return array
	 */
	public static function is_license_expired() {

		try {
			Mo_License_Service_Utility::check_customer_login_and_license();
			$license_status = Mo_License_Service_Utility::is_license_grace_expired();

		} catch ( Mo_License_Grace_Expired_Exception $e ) {
			return Mo_License_Service_Utility::return_true_with_code( $e::MESSAGE );
		} catch ( Mo_License_Invalid_Expiry_Date_Exception $e ) {
			return Mo_License_Service_Utility::return_true_with_code( $e::MESSAGE );
		} catch ( Mo_License_Missing_License_Key_Exception $e ) {
			return Mo_License_Service_Utility::return_true_with_code( $e::MESSAGE );
		} catch ( Mo_License_Missing_Customer_Email_Exception $e ) {
			return Mo_License_Service_Utility::return_true_with_code( $e::MESSAGE );
		} catch ( Mo_License_Missing_Or_Invalid_Customer_Key_Exception $e ) {
			return Mo_License_Service_Utility::return_true_with_code( $e::MESSAGE );
		} catch ( Mo_License_Unknown_Error_Exception $e ) {
			return Mo_License_Service_Utility::return_true_with_code( $e::CODE );
		}

		return Mo_License_Service_Utility::return_false_with_code( $license_status['CODE'] );
	}

	/**
	 * Checks if the customer is license is verified by checking if
	 * customer's email, customer key and license key exists in database.
	 *
	 * @return boolean
	 */
	public static function is_customer_license_verified() {
		try {
			Mo_License_Service_Utility::check_customer_login_and_license();
		} catch ( Mo_License_Missing_Customer_Email_Exception $e ) {
			return false;
		} catch ( Mo_License_Missing_Or_Invalid_Customer_Key_Exception $e ) {
			return false;
		} catch ( Mo_License_Missing_License_Key_Exception $e ) {
			return false;
		}
		return true;
	}

	/**
	 * Checks if the customer is logged into the plugin by checking if
	 * customer's email and customer key exists in database.
	 *
	 * @return boolean
	 */
	public static function is_customer_logged_into_plugin() {

		try {
			Mo_License_Service_Utility::check_customer_login();
		} catch ( Mo_License_Missing_Customer_Email_Exception $e ) {
			return false;
		} catch ( Mo_License_Missing_Or_Invalid_Customer_Key_Exception $e ) {
			return false;
		}
		return true;
	}


	/**
	 * Function to check if the HTML input should be disabled based on the license grace period expiry.
	 * It internally first verifies if the customer’s license is verified by calling the
	 * check_customer_login_and_license() function.
	 *
	 * @param boolean $check_expiry Optional boolean value to determine if the customer's license key
	 * expiry has to be checked.
	 *
	 * @return string
	 */
	public static function get_html_disabled_status( $check_expiry = true ) {

		if ( $check_expiry ) {
			$is_license_expired = self::is_license_expired();
			$license_valid      = ! $is_license_expired['STATUS'];
		} else {
			$license_valid = self::is_customer_license_verified();
		}

		if ( false === $license_valid ) {
			return 'disabled';
		}

		return '';
	}

	/**
	 * Fetches and updates the license expiry in the database. Calls utility functions internally
	 * for fetching license via API call and updating the license expiry.
	 *
	 * Uses the backupcode/check API for verification.
	 *
	 * @return bool|string License expiry date on success, false on failure.
	 */
	public static function refresh_license_expiry() {
		$license_expiry_date = Mo_License_Actions_Utility::fetch_license_expiry_date();

		if ( $license_expiry_date ) {
			if ( is_string( $license_expiry_date ) ) {
				self::update_license_expiry( $license_expiry_date );
			}
			return $license_expiry_date;
		}
		return false;
	}

	/**
	 * Wrapper Function to verify the nonce of the option passed to the function for a form submission.
	 * The function also checks if the customer license is valid for any form submission based on the
	 * value of $check_expiry bool passed to the function.
	 *
	 * @param int|string $option_name Optional Default WP check_admin_referer() parameter. The nonce
	 * action for which the nonce has to be verified. Default: -1.
	 * @param string     $query_arg Optional Default WP check_admin_referer() parameter. Key to check
	 *     for nonce in $_REQUEST. Default '_wpnonce'.
	 * @param bool       $check_expiry Optional Decides if license expiry needs to be checked along with
	 *       nonce verification. Default: true.
	 *
	 * @return true|void
	 */
	public static function mo_check_admin_referer( $option_name = -1, $query_arg = '_wpnonce', $check_expiry = true ) {

		$admin_referer = check_admin_referer( $option_name, $query_arg );

		$is_license_expired = false;
		if ( $check_expiry ) {
			$is_license_expired = self::is_license_expired();
			$license_valid      = ! $is_license_expired['STATUS'];
		} else {
			$license_valid = self::is_customer_license_verified();
		}

		if ( ! $license_valid || ! $admin_referer ) {
			wp_die( esc_html( Mo_License_Constants::ADMIN_ERROR_MESSAGE ) );
		}
		return true;
	}

	/**
	 * Wrapper Function to verify the nonce of the option passed to the function for an AJAX call.
	 * The function also checks if the customer license is valid for any AJAX call based on the
	 * value of $check_expiry bool passed to the function.
	 *
	 * @param int|string $action Optional Default WP check_ajax_referer() parameter. Action for which nonce
	 * has to be verified. Default: -1.
	 * @param bool       $query_arg Optional Default WP check_ajax_referer() parameter. Key to check for the
	 *       nonce in $_REQUEST (since WP 2.5). If false, $_REQUEST values will be evaluated for '_ajax_nonce',
	 *       and '_wpnonce' (in that order). Default: false.
	 * @param bool       $stop Optional Default WP check_ajax_referer() parameter. Whether to stop early when
	 *       the nonce cannot be verified. Default: true.
	 * @param bool       $check_expiry Optional Decides if license expiry needs to be checked along with nonce
	 *       verification. Default: true.
	 *
	 * @return void
	 */
	public static function mo_check_ajax_referer( $action = -1, $query_arg = false, $stop = true, $check_expiry = true ) {

		if ( $check_expiry ) {
			$is_license_expired = self::is_license_expired();
			$license_valid      = ! $is_license_expired['STATUS'];
		} else {
			$license_valid = self::is_customer_license_verified();
		}

		$ajax_referer = check_ajax_referer( $action, $query_arg, $stop );

		if ( ! $license_valid || ! $ajax_referer ) {
			wp_send_json_error(
				array(
					'message' => 'Invalid License Key.',
				),
				403
			);
			exit();
		}
		wp_send_json_success(
			array(
				'message' => 'Referer verified successfully.',
			),
			200
		);
	}

	/**
	 * Function to get the number of days remaining for plugin's license expiry.
	 *
	 * @param string $license_expiry_date The plugin license expiry date.
	 *
	 * @return int
	 */
	public static function get_expiry_remaining_days( $license_expiry_date ) {

		$expiry_datestamp = strtotime( $license_expiry_date );
		$today_datestamp  = strtotime( gmdate( 'Y-m-d' ) );
		$difference       = $expiry_datestamp - $today_datestamp;
		$remaining_days   = floor( $difference / ( 60 * 60 * 24 ) );

		return $remaining_days;
	}

	/**
	 * Function to get the remaining grace days for plugin license renewal.
	 *
	 * @param string $license_expiry_date The plugin license expiry date.
	 *
	 * @return int
	 */
	public static function get_grace_days_left( $license_expiry_date ) {

		$remaining_days = self::get_expiry_remaining_days( $license_expiry_date );
		if ( $remaining_days > 0 ) {
			return false;
		}

		return ( Mo_License_Config::GRACE_PERIOD_DAYS + $remaining_days );
	}

	/**
	 * Function to get the plugin's license grace period expiry date.
	 *
	 * @param string $license_expiry_date The plugin license expiry date.
	 *
	 * @return string|false
	 */
	public static function get_disable_date( $license_expiry_date ) {
		return gmdate( 'M d, Y', strtotime( $license_expiry_date . '+' . Mo_License_Config::GRACE_PERIOD_DAYS . ' days' ) );
	}

	/**
	 * Function to fetch the expiry date of the plugin's license. If the expiry date does
	 * not exist in database, an API call is made to fetch the updated expiry.
	 *
	 * @return string
	 */
	public static function get_expiry_date() {
		$expiry_date = Mo_License_Service_Utility::mo_decrypt_data( Mo_License_Dao::mo_get_option( Mo_License_Constants::LICENSE_EXPIRY_DATE_OPTION ) );

		if ( ! $expiry_date ) {
			$expiry_date = Mo_License_Actions_Utility::fetch_license_expiry_date();
			if ( ! $expiry_date ) {
				$expiry_date = Mo_License_Constants::EPOCH_DATE;
			}
			self::update_license_expiry( $expiry_date );
		}

		return $expiry_date;
	}

	/**
	 * Function to return the license expiry date in the proper format before use.
	 *
	 * @param string $license_expiry License Expiry Date of the plugin's license.
	 *
	 * @return string
	 */
	public static function get_formatted_license_expiry_date( $license_expiry ) {
		try {
			$date_obj       = new \DateTime( $license_expiry );
			$timestamp      = $date_obj->getTimestamp();
			$license_expiry = gmdate( 'F j, Y', $timestamp );
			return $license_expiry;
		} catch ( \Exception $e ) {
			return $license_expiry;
		}
	}

	/**
	 * Function to check if license is valid. It can be used where functionality needs to be disabled after license
	 * grace period expiry. For example - disabling html elements. Returns false if invalid license key or invalid
	 * customer key is found, or if plugin license expiry has not crossed grace period. When the license is flagged
	 * as not associated with the customer account, boolean checks stay false (SSO off) but HTML mode returns an empty
	 * string so Account / sync controls are not disabled.
	 *
	 * @param bool $html_element Optional boolean value to determine if license validity needs to be checked for
	 * form input fields. Default: false.
	 * @param bool $check_expiry Optional boolean value to determine if the function only checks if the customer has
	 * logged into the plugin and the entered license key is valid. Default: true.
	 *
	 * @return bool|string
	 */
	public static function is_customer_license_valid( $html_element = false, $check_expiry = true ) {

		if ( Mo_License_Dao::mo_get_option( Mo_License_Constants::LICENSE_NOT_ASSOCIATED_WITH_CUSTOMER_OPTION ) ) {
		
			return $html_element ? '' : false;
		}

		if ( $check_expiry ) {
			$is_license_expired = self::is_license_expired();
			$license_valid      = ! $is_license_expired['STATUS'];
		} else {
			$license_valid = self::is_customer_license_verified();
		}

		if ( true === $license_valid ) {
			return $html_element ? '' : true;
		}

		return $html_element ? 'disabled' : false;
	}

	/**
	 * Function to check if license is a trial license or not.
	 *
	 * @return bool
	 */
	public static function is_trial_license() {

		$license_valid = self::is_customer_license_verified();
		if ( $license_valid ) {
			$is_trial = Mo_License_Dao::mo_get_option( Mo_License_Constants::IS_TRIAL );
			if ( 'true' === $is_trial ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Updates the passed license expiry date in the database. If license has expired,
	 * plugin option is set to expired. Else, it resets license values when the license
	 * has not expired but license expired was already set in the database.
	 *
	 * @param string $license_expiry_date Contains license information fetched from API call.
	 *
	 * @return void
	 */
	public static function update_license_expiry( $license_expiry_date ) {

		Mo_License_Dao::mo_update_option( Mo_License_Constants::LICENSE_EXPIRY_DATE_OPTION, Mo_License_Service_Utility::mo_encrypt_data( self::get_formatted_license_expiry_date( $license_expiry_date ) ) );

		$license_grace_expired = self::is_license_expired();
		if ( true === $license_grace_expired['STATUS'] ) {
			Mo_License_Dao::mo_update_option( Mo_License_Constants::LICENSE_EXPIRED_OPTION, true );
		} elseif ( Mo_License_Dao::mo_get_option( Mo_License_Constants::LICENSE_EXPIRED_OPTION ) ) {
			self::reset_license_values();
		}
	}

	/**
	 * Updates the passed license plan in the database.
	 *
	 * @param string $license_plan Contains license information fetched from API call.
	 *
	 * @return void
	 */
	public static function update_license_plan( $license_plan ) {
		$license_plan_array = array();
		$token              = Mo_License_Dao::mo_get_option( Mo_License_Config::CUSTOMER_OPTIONS['token'] );
		if ( ! empty( Mo_License_Dao::mo_get_option( Mo_License_Constants::LICENSE_PLAN_OPTION ) ) ) {
			$license_plan_array = json_decode( Mo_License_Service_Utility::mo_decrypt_data( Mo_License_Dao::mo_get_option( Mo_License_Constants::LICENSE_PLAN_OPTION ) ), true );
			if ( ! is_array( $license_plan_array ) || empty( $license_plan_array ) ) {
				$license_plan_array = array();
			}
			if ( ! array_key_exists( $token, $license_plan_array ) ) {
				$license_plan_array[ $token ] = Mo_License_Service_Utility::mo_encrypt_data( $license_plan );
			}
		} else {
			$license_plan_array[ $token ] = Mo_License_Service_Utility::mo_encrypt_data( $license_plan );
		}
		Mo_License_Dao::mo_update_option( Mo_License_Constants::LICENSE_PLAN_OPTION, wp_json_encode( $license_plan_array ) );
	}

	/**
	 * Updates the passed license trial status in the database.
	 *
	 * @param string $is_trial Contains license information fetched from API call.
	 *
	 * @return void
	 */
	public static function update_trial_status( $is_trial ) {

		if ( self::is_customer_license_verified() && true === $is_trial ) {
			Mo_License_Dao::mo_update_option( Mo_License_Constants::IS_TRIAL, 'true' );
		} else {
			Mo_License_Dao::mo_update_option( Mo_License_Constants::IS_TRIAL, 'false' );
		}
	}

	/**
	 * Function to delete the values of license framework options.
	 *
	 * @return void
	 */
	public static function reset_license_values() {
		$license_constants = Mo_License_Constants::get_constants();
		foreach ( $license_constants as $key => $value ) {
			if ( strpos( $key, 'OPTION' ) !== false && is_string( $value ) ) {
				Mo_License_Dao::mo_delete_option( $value );
			}
		}
	}

	/**
	 * Function to delete the values of all the customer and license related information.
	 *
	 * @return void
	 */
	public static function reset_account_values() {
		foreach ( Mo_License_Config::LICENSE_OPTIONS as $key => $value ) {
			Mo_License_Dao::mo_delete_option( $value );
		}
		foreach ( Mo_License_Config::CUSTOMER_OPTIONS as $key => $value ) {
			Mo_License_Dao::mo_delete_option( $value );
		}
		foreach ( Mo_License_Config::CUSTOMER_MANUALLY_CONFIGURED_OPTIONS as $key => $value ) {
			Mo_License_Dao::mo_delete_option( $value );
		}
	}

	/**
	 * Function to validate the customer license key.
	 *
	 * This function takes the license key as input, validates the license key using the
	 * licensing service utility, and if successful, fetches and saves the license details.
	 * If an error occurs during the validation process, appropriate error messages are returned.
	 *
	 * @param string $license_key The license key to be validated.
	 *
	 * @return mixed Returns a success code if the license key is validated successfully,
	 *               or a failure code with an error message if an exception is caught.
	 *               {STATUS: true, CODE: 'LICENSE_VALID'}
	 *               {STATUS: false, CODE: 'MISSING_LICENSE_KEY'}
	 *               {STATUS: false, CODE: 'NETWORK_ERROR'}
	 *               {STATUS: false, CODE: 'INVALID_LICENSE_KEY'}
	 *               {STATUS: false, CODE: 'ALREADY_USED_LICENSE_KEY'}
	 *               {STATUS: false, CODE: 'LICENSE_PLAN_NOT_PURCHASED'}
	 *               {STATUS: false, CODE: 'MISSING_CUSTOMER_EMAIL'}
	 *               {STATUS: false, CODE: 'MISSING_OR_INVALID_CUSTOMER_KEY'}
	 *
	 * @throws Mo_License_Missing_License_Key_Exception When license key is missing.
	 */
	public static function validate_customer_license_key( $license_key ) {
		try {
			Mo_License_Service_Utility::check_customer_login();
			$license_key = sanitize_text_field( trim( wp_unslash( $license_key ) ) );
			if ( empty( $license_key ) ) {
				throw new Mo_License_Missing_License_Key_Exception();
			}
			Mo_License_Service_Utility::fetch_and_save_license_details( $license_key );
			return Mo_License_Service_Utility::return_status_with_message( Mo_License_Constants::LICENSE_VERIFY_VALID_STATUS, Mo_License_Constants::LICENSE_VERIFIED_MESSAGE );
		} catch ( Mo_License_Missing_License_Key_Exception $e ) {
			return Mo_License_Service_Utility::return_status_with_message( $e::CODE, $e::MESSAGE );
		} catch ( Mo_License_Network_Error_Exception $e ) {
			return Mo_License_Service_Utility::return_status_with_message( $e::CODE, $e::MESSAGE );
		} catch ( Mo_License_Invalid_License_Key_Exception $e ) {
			return Mo_License_Service_Utility::return_status_with_message( $e::CODE, $e::MESSAGE );
		} catch ( Mo_License_Already_Used_License_Key_Exception $e ) {
			return Mo_License_Service_Utility::return_status_with_message( $e::CODE, $e::MESSAGE );
		} catch ( Mo_License_Plan_Not_Purchased_Exception $e ) {
			return Mo_License_Service_Utility::return_status_with_message( $e::CODE, $e::MESSAGE );
		} catch ( Mo_License_Missing_Customer_Email_Exception $e ) {
			return Mo_License_Service_Utility::return_status_with_message( $e::CODE, $e::MESSAGE );
		} catch ( Mo_License_Missing_Or_Invalid_Customer_Key_Exception $e ) {
			return Mo_License_Service_Utility::return_status_with_message( $e::CODE, $e::MESSAGE );
		}
	}

	/**
	 * Function to verify customer login and save details.
	 *
	 * This function takes the customer's email and password, verifies the login credentials
	 * using the licensing service utility, and if successful, saves the customer's email.
	 * If an error occurs during the login process, appropriate error messages are returned.
	 *
	 * @param string $email The customer's email address.
	 * @param string $password The customer's password.
	 *
	 * @return mixed Returns a success code if the customer is logged in successfully,
	 *               or a failure code with an error message if an exception is caught.
	 *               {STATUS: true, CODE: 'CUSTOMER_LOGGED_IN'}
	 *               {STATUS: false, CODE: 'NETWORK_ERROR'}
	 *               {STATUS: false, CODE: 'INVALID_EMAIL_OR_PASSWORD'}
	 */
	public static function verify_customer_credentials( $email, $password ) {
		try {
			if ( Mo_License_Service_Utility::handle_customer_login( $email, $password ) ) {
				Mo_License_Dao::mo_update_option( Mo_License_Config::CUSTOMER_MANUALLY_CONFIGURED_OPTIONS['CUSTOMER_EMAIL_OPTION'], $email );
				return Mo_License_Service_Utility::return_status_with_message( Mo_License_Constants::CUSTOMER_LOGGED_IN_STATUS, Mo_License_Constants::CUSTOMER_LOGGED_IN_MESSAGE );
			}
		} catch ( Mo_License_Network_Error_Exception $e ) {
			return Mo_License_Service_Utility::return_status_with_message( $e::CODE, $e::MESSAGE );
		} catch ( Mo_License_Invalid_Username_Or_Password_Exception $e ) {
			return Mo_License_Service_Utility::return_status_with_message( $e::CODE, $e::MESSAGE );
		}
	}

	/**
	 * Frees the license key and removes account data locally.
	 *
	 * Attempts to notify the license server via API. Catches any exception (network
	 * errors, invalid response, missing credentials, etc.) and always proceeds to
	 * clear local license and account values so the user can remove the account.
	 *
	 * @return array{STATUS: string, MESSAGE: string} Always returns LICENSE_FREED status.
	 *               MESSAGE is LICENSE_FREED_MESSAGE on API success, or
	 *               LICENSE_REMOVED_LOCALLY_MESSAGE when the API call failed.
	 */
	public static function free_license_key() {
		$api_succeeded = false;
		try {
			Mo_License_Service_Utility::check_customer_login_and_license();
			Mo_License_Service_Utility::handle_update_license_status();
			$api_succeeded = true;
		} catch ( \Exception $e ) {
			// Proceed with local removal despite API or validation failure.
		}

		self::reset_license_values();
		self::reset_account_values();

		$message = $api_succeeded
			? Mo_License_Constants::LICENSE_FREED_MESSAGE
			: Mo_License_Constants::LICENSE_REMOVED_LOCALLY_MESSAGE;

		return Mo_License_Service_Utility::return_status_with_message( Mo_License_Constants::LICENSE_FREED_STATUS, $message );
	}

	/**
	 * Synchronizes the license details with the system.
	 *
	 * This function attempts to save the license details by calling the
	 * `fetch_and_save_license_details` method. If the operation is successful, it returns a
	 * success code. If any exceptions are thrown during the process (such as network
	 * errors, license key already used, or invalid license key), the function catches
	 * the exceptions and returns a failure code with the appropriate error message.
	 *
	 * @return array An array indicating whether the license sync was successful or not, along with a corresponding message.
	 *               {STATUS: true, CODE: 'LICENSE_SYNCED'}
	 *               {STATUS: false, CODE: 'NETWORK_ERROR'}
	 *               {STATUS: false, CODE: 'ALREADY_USED_LICENSE_KEY'}
	 *               {STATUS: false, CODE: 'INVALID_LICENSE_KEY'}
	 */
	public static function sync_license_details() {
		try {
			Mo_License_Service_Utility::fetch_and_save_license_details( '', true );
			return Mo_License_Service_Utility::return_status_with_message( Mo_License_Constants::LICENSE_SYNCED_STATUS, Mo_License_Constants::LICENSE_SYNCED_MESSAGE );
		} catch ( Mo_License_Network_Error_Exception $e ) {
			return Mo_License_Service_Utility::return_status_with_message( $e::CODE, $e::MESSAGE );
		} catch ( Mo_License_Already_Used_License_Key_Exception $e ) {
			return Mo_License_Service_Utility::return_status_with_message( $e::CODE, $e::MESSAGE );
		} catch ( Mo_License_Invalid_License_Key_Exception $e ) {
			return Mo_License_Service_Utility::return_status_with_message( $e::CODE, $e::MESSAGE );
		} catch ( Mo_License_Unknown_Error_Exception $e ) {
			return Mo_License_Service_Utility::return_status_with_message( $e::CODE, $e::MESSAGE );
		}
	}

	/**
	 * Function to fetch the Addons from the license they are having.
	 *
	 * @return void
	 */
	public static function fetch_addons_view() {
		Mo_License_Addons_Views::show_addons_page();
	}

	/**
	 * Function to add filters for addons license library.
	 *
	 * @return void
	 */
	public static function add_addons_license_filters() {
		add_filter( 'mo_addons_authentication_plugins', array( __CLASS__, 'mo_addons_authentication_plugins' ) );
		add_filter( 'mo_addons_is_license_valid', array( __CLASS__, 'mo_addons_is_license_valid' ), 10, 3 );
		add_filter( 'mo_addons_is_customer_logged_in', array( __CLASS__, 'mo_addons_is_customer_logged_in' ) );
		add_filter( 'mo_addons_login_page_url', array( __CLASS__, 'mo_addons_login_page_url' ) );
		add_filter( 'mo_addons_logged_in_customer_details', array( __CLASS__, 'mo_addons_logged_in_customer_details' ) );
	}

	/**
	 * Function to add authentication plugins.
	 *
	 * @param array $authentication_plugins The array of miniOrange authentication plugins installed in the site.
	 * @return array
	 */
	public static function mo_addons_authentication_plugins( $authentication_plugins ) {
		return array_merge(
			$authentication_plugins,
			array(
				Mo_License_Config::OPTION_PREFIX => Mo_License_Config::PLUGIN_NAME,
			)
		);
	}

	/**
	 * Function to check if license is valid.
	 *
	 * @return bool
	 */
	public static function mo_addons_is_license_valid() {
		return self::is_customer_license_verified();
	}

	/**
	 * Function to check if customer is logged in.
	 *
	 * @return bool
	 */
	public static function mo_addons_is_customer_logged_in() {
		return self::is_customer_logged_into_plugin();
	}

	/**
	 * Function to get the login page url.
	 *
	 * @return string
	 */
	public static function mo_addons_login_page_url() {
		return Mo_License_Config::ACCOUNT_PAGE_URL;
	}

	/**
	 * Function to get the logged in customer details.
	 *
	 * @return array
	 */
	public static function mo_addons_logged_in_customer_details() {
		return array(
			'EMAIL'        => Mo_License_Dao::mo_get_option( Mo_License_Config::CUSTOMER_MANUALLY_CONFIGURED_OPTIONS['CUSTOMER_EMAIL_OPTION'] ),
			'PHONE'        => Mo_License_Dao::mo_get_option( Mo_License_Config::CUSTOMER_OPTIONS['phone'] ),
			'CUSTOMER_KEY' => Mo_License_Dao::mo_get_option( Mo_License_Config::CUSTOMER_OPTIONS['id'] ),
			'API_KEY'      => Mo_License_Dao::mo_get_option( Mo_License_Config::CUSTOMER_OPTIONS['apiKey'] ),
		);
	}

	/**
	 * Function to get the license library path.
	 *
	 * @return string
	 */
	public static function get_license_library_path() {
		if ( ! self::$license_library_path ) {
			self::$license_library_path = plugin_dir_url( __FILE__ );
		}
		return self::$license_library_path;
	}
}
