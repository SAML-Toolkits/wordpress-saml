<?php
/**
 * This file is part of miniOrange WP plugin.
 *
 * @package    miniOrange
 * @author     miniOrange Security Software Pvt. Ltd.
 */

namespace MOSAML\LicenseLibrary\Utils;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\LicenseLibrary\Classes\Mo_AESEncryption;
use MOSAML\LicenseLibrary\Classes\Mo_License_API_Client;
use MOSAML\LicenseLibrary\Classes\Mo_License_Dao;
use MOSAML\LicenseLibrary\Exceptions\Mo_License_Grace_Expired_Exception;
use MOSAML\LicenseLibrary\Exceptions\Mo_License_Invalid_Expiry_Date_Exception;
use MOSAML\LicenseLibrary\Exceptions\Mo_License_Missing_Customer_Email_Exception;
use MOSAML\LicenseLibrary\Exceptions\Mo_License_Missing_License_Key_Exception;
use MOSAML\LicenseLibrary\Exceptions\Mo_License_Missing_Or_Invalid_Customer_Key_Exception;
use MOSAML\LicenseLibrary\Exceptions\Mo_License_Unknown_Error_Exception;
use MOSAML\LicenseLibrary\Classes\Mo_License_Constants;
use MOSAML\LicenseLibrary\Exceptions\Mo_License_Already_Used_License_Key_Exception;
use MOSAML\LicenseLibrary\Exceptions\Mo_License_Invalid_License_Key_Exception;
use MOSAML\LicenseLibrary\Exceptions\Mo_License_Invalid_Username_Or_Password_Exception;
use MOSAML\LicenseLibrary\Exceptions\Mo_License_Plan_Not_Purchased_Exception;
use MOSAML\LicenseLibrary\Exceptions\Mo_License_Network_Error_Exception;
use MOSAML\LicenseLibrary\Mo_License_Config;
use MOSAML\LicenseLibrary\Mo_License_Service;

/**
 * Class Mo_License_Service_Utility contains utility functions required to perform
 * License Service functions.
 */
class Mo_License_Service_Utility {

	/**
	 * Function to check if the customer has properly activated and logged in to the plugin.
	 * It checks the CUSTOMER_EMAIL, CUSTOMER_KEY values in the database.
	 *
	 * @throws Mo_License_Missing_Customer_Email_Exception Depicts that the Customer's miniOrange
	 * Account Email Address is not found in the database.
	 * @throws Mo_License_Missing_Or_Invalid_Customer_Key_Exception Depicts that the Customer's
	 * miniOrange Account Customer Key is not found in the database.
	 *
	 * @return void
	 */
	public static function check_customer_login() {
		$email        = Mo_License_Dao::mo_get_option( Mo_License_Config::CUSTOMER_MANUALLY_CONFIGURED_OPTIONS['CUSTOMER_EMAIL_OPTION'] );
		$customer_key = Mo_License_Dao::mo_get_option( Mo_License_Config::CUSTOMER_OPTIONS['id'] );
		if ( ! $email ) {
			throw new Mo_License_Missing_Customer_Email_Exception();
		} elseif ( ! $customer_key || ! is_numeric( trim( $customer_key ) ) ) {
			throw new Mo_License_Missing_Or_Invalid_Customer_Key_Exception();
		}
	}

	/**
	 * Function to check if the customer has properly activated and logged in to the plugin.
	 * It checks the CUSTOMER_EMAIL, CUSTOMER_KEY, LICENSE_KEY values in the database. Calls
	 * check_customer_login() internally.
	 *
	 * @throws Mo_License_Missing_License_Key_Exception Depicts that the License Key used to
	 * login into the plugin is not found in the database.
	 *
	 * @return void
	 */
	public static function check_customer_login_and_license() {

		self::check_customer_login();

		$license_key = Mo_License_Dao::mo_get_option( Mo_License_Config::CUSTOMER_MANUALLY_CONFIGURED_OPTIONS['LICENSE_KEY_OPTION'] );
		if ( ! $license_key ) {
			throw new Mo_License_Missing_License_Key_Exception();
		}
	}

	/**
	 * Function to check if the customer's plugin license is expired. Returns true if expired.
	 * Else, returns false.
	 *
	 * @throws Mo_License_Invalid_Expiry_Date_Exception Depicts that Plugin's Expiry Date is not
	 * in the correct format.
	 * @throws Mo_License_Unknown_Error_Exception Depicts that the there has been an unknown error
	 * while processing the License Expiry Date found in the database.
	 * @throws Mo_License_Grace_Expired_Exception Depicts that Plugin's License Grace Period has
	 * expired.
	 *
	 * @return array|void
	 */
	public static function is_license_grace_expired() {

		$license_expiry_date = self::mo_decrypt_data( Mo_License_Dao::mo_get_option( Mo_License_Constants::LICENSE_EXPIRY_DATE_OPTION ) );
		if ( ! $license_expiry_date ) {
			throw new Mo_License_Invalid_Expiry_Date_Exception();
		}
		try {
			$plugin_expiry_date = gmdate( 'Y-m-d', strtotime( $license_expiry_date ) );

			if ( Mo_License_Service::is_trial_license() ) {
				$plugin_grace_expiry = strtotime( '+' . 0 . ' days', strtotime( $license_expiry_date ) );
			} else {
				$plugin_grace_expiry = strtotime( '+' . Mo_License_Config::GRACE_PERIOD_DAYS . ' days', strtotime( $license_expiry_date ) );
			}
			$plugin_disable_date = gmdate( 'Y-m-d', $plugin_grace_expiry );

			$today_date = new \DateTime();
			$today_date = $today_date->format( 'Y-m-d' );

		} catch ( \Exception $e ) {
			throw new Mo_License_Unknown_Error_Exception();
		}

		if ( $today_date > $plugin_disable_date ) {
			throw new Mo_License_Grace_Expired_Exception();
		} elseif ( $today_date > $plugin_expiry_date ) {
			return self::return_false_with_code( 'LICENSE_IN_GRACE' );
		}

		return self::return_false_with_code( 'LICENSE_VALID' );
	}

	/**
	 * Function to return a true array with the passed code. This is
	 * used in the license service functions.
	 *
	 * @param string $code The success message.
	 *
	 * @return array
	 */
	public static function return_true_with_code( $code ) {
		return array(
			'STATUS' => true,
			'CODE'   => $code,
		);
	}

	/**
	 * Function to return a false array with the passed code. This is
	 * used in the license service functions.
	 *
	 * @param string $code The failure message.
	 *
	 * @return array
	 */
	public static function return_false_with_code( $code ) {
		return array(
			'STATUS' => false,
			'CODE'   => $code,
		);
	}

	/**
	 * Function to return a status array with the passed message. This is
	 * used in the license service functions.
	 *
	 * @param string $status  The status of the request.
	 * @param string $message The message to be returned.
	 *
	 * @return array
	 */
	public static function return_status_with_message( $status, $message ) {
		return array(
			'STATUS'  => $status,
			'MESSAGE' => $message,
		);
	}

	/**
	 * When the license API reports the license is not linked to the customer, SSO must be disabled until fixed.
	 *
	 * @param array $decoded Decoded JSON response body.
	 *
	 * @return void
	 */
	public static function maybe_set_license_not_associated_flag_from_response( $decoded ) {
		if ( ! is_array( $decoded ) ) {
			return;
		}
		$msg = isset( $decoded['message'] ) ? (string) $decoded['message'] : '';
		if ( false === stripos( $msg, 'License is not associated with customer' ) ) {
			return;
		}
		Mo_License_Dao::mo_update_option( Mo_License_Constants::LICENSE_NOT_ASSOCIATED_WITH_CUSTOMER_OPTION, true );
	}

	/**
	 * Wrapper Function to decrypt the data passed to it. Calls the Mo_AESEncryption class
	 * decrypt_data with the data to decrypted and the key to use for decryption. Returns the
	 * decrypted value.
	 *
	 * @param string $data The data to be decrypted.
	 *
	 * @return string
	 */
	public static function mo_decrypt_data( $data ) {
		$key            = Mo_License_Dao::mo_get_option( Mo_License_Config::CUSTOMER_OPTIONS['token'] );
		$decrypted_data = Mo_AESEncryption::decrypt_data( $data, $key );
		return $decrypted_data;
	}

	/**
	 * Wrapper Function to encrypt the data passed to it. Calls the Mo_AESEncryption class
	 * encrypt_data with the data to encrypted and the key to use for encryption. Returns the
	 * encrypted value.
	 *
	 * @param string $data The data to be encrypted.
	 *
	 * @return string
	 */
	public static function mo_encrypt_data( $data ) {
		$key            = Mo_License_Dao::mo_get_option( Mo_License_Config::CUSTOMER_OPTIONS['token'] );
		$encrypted_data = Mo_AESEncryption::encrypt_data( $data, $key );
		return $encrypted_data;
	}

	/**
	 * Handles customer login by verifying the provided email and password with the license API.
	 *
	 * This function sends a request to fetch account information using the provided email and password.
	 * If the credentials are valid and the response is correctly formatted, it updates the customer options.
	 *
	 * @param string $email The customer's email address.
	 * @param string $password The customer's password.
	 *
	 * @return bool Returns true if the customer login is successful and account info is updated.
	 *
	 * @throws Mo_License_Network_Error_Exception If there is a network error while fetching account info.
	 * @throws Mo_License_Invalid_Username_Or_Password_Exception If the JSON response is invalid or if the credentials are incorrect.
	 */
	public static function handle_customer_login( $email, $password ) {
		$email        = sanitize_email( $email );
		$password     = self::validate_and_sanitize_user_password( $password );
		$account_info = Mo_License_API_Client::fetch_account_info( $email, $password );
		if ( empty( $account_info ) ) {
			throw new Mo_License_Network_Error_Exception();
		}
		$account_info = json_decode( $account_info, true );
		if ( JSON_ERROR_NONE === json_last_error() && isset( $account_info['status'] ) && 'SUCCESS' === $account_info['status'] ) {

			foreach ( Mo_License_Config::CUSTOMER_OPTIONS as $key => $value ) {
				if ( ! empty( $account_info[ $key ] ) ) {
					Mo_License_Dao::mo_update_option( $value, $account_info[ $key ] );
				}
			}
			Mo_License_Dao::mo_update_option( Mo_License_Config::CUSTOMER_MANUALLY_CONFIGURED_OPTIONS['CUSTOMER_PASSWORD_OPTION'], '' );
			return true;
		} else {
			throw new Mo_License_Invalid_Username_Or_Password_Exception();
		}
	}

	/**
	 * Updates the license status by calling the license API.
	 *
	 * This function makes a request to update the current license status and handles the response.
	 * If the response indicates the license is linked to another domain, or the license key is invalid, appropriate exceptions
	 * are thrown to handle the error cases.
	 *
	 * @throws Mo_License_Network_Error_Exception If the API response is empty or there's a network issue.
	 *
	 * @return bool Returns true if the license status update is successful.
	 */
	public static function handle_update_license_status() {
		$updated_license_status_response = Mo_License_API_Client::update_license_status();

		if ( empty( $updated_license_status_response ) ) {
			throw new Mo_License_Network_Error_Exception();
		}

		$updated_license_status_response = json_decode( $updated_license_status_response, true );
		self::validate_license_status( $updated_license_status_response );
		return true;
	}

	/**
	 * Checks the license validation response and handles errors.
	 *
	 * This function checks the response from a license validation request. If the
	 * response status is not "SUCCESS", it checks for specific error messages indicating
	 * the license key is already used or linked to a different domain. Appropriate exceptions
	 * are thrown based on the error message.
	 *
	 * @param array $response The response array from the license validation API.
	 *
	 * @throws Mo_License_Already_Used_License_Key_Exception If the license key is already used or linked to a different domain.
	 * @throws Mo_License_Invalid_License_Key_Exception If the license key is invalid or the response status is not "SUCCESS".
	 */
	public static function validate_license_status( $response ) {

		if ( empty( $response['status'] ) || strcasecmp( $response['status'], 'SUCCESS' ) !== 0 ) {
			if ( ! empty( $response['message'] ) && strpos( $response['message'], Mo_License_Constants::MESSAGE_LICENSE_KEY_ALREADY_USED ) !== false ) {
				throw new Mo_License_Already_Used_License_Key_Exception();
			}
			self::maybe_set_license_not_associated_flag_from_response( $response );
			throw new Mo_License_Invalid_License_Key_Exception();
		}
	}

	/**
	 * Checks if the provided license key is linked to a customer.
	 *
	 * This function fetches the license key information from the license API and
	 * validates the response. If the license key information cannot be retrieved
	 * or if the response indicates an error, an exception is thrown.
	 *
	 * @param string $license_key The license key to check.
	 *
	 * @throws Mo_License_Network_Error_Exception If there is a network error while fetching license key information.
	 */
	public static function is_license_linked_to_customer( $license_key ) {
		$license_key_info = Mo_License_API_Client::fetch_license_key_info( $license_key );
		if ( false === $license_key_info ) {
			throw new Mo_License_Network_Error_Exception();
		}
		$license_key_info = json_decode( $license_key_info, true );
		self::validate_license_status( $license_key_info );
	}

	/**
	 * Saves the license details and updates the system options.
	 *
	 * This function retrieves the license plan information using the provided license key.
	 * If the information is successfully fetched and the response status is "SUCCESS",
	 * it updates various system options, such as the license key, expiry, and trial status.
	 * If the license is attached to a different plugin type or the license key is invalid,
	 * appropriate exceptions are thrown.
	 *
	 * @param string $license_key The license key to fetch and save details for. Defaults to an empty string.
	 * @param bool   $is_sync_request Indicates if this is a sync request. Defaults to false.
	 *
	 * @return bool Returns true if the license details were successfully saved and updated.
	 *
	 * @throws Mo_License_Network_Error_Exception If there is a network error while fetching the license plan information.
	 * @throws Mo_License_Plan_Not_Purchased_Exception If the license key is attached to a different plugin type.
	 * @throws Mo_License_Invalid_License_Key_Exception If the license key is invalid or the response status is not "SUCCESS".
	 */
	public static function fetch_and_save_license_details( $license_key = '', $is_sync_request = false ) {
		if ( empty( $license_key ) ) {
			$license_key = self::mo_decrypt_data( Mo_License_Dao::mo_get_option( Mo_License_Config::CUSTOMER_MANUALLY_CONFIGURED_OPTIONS['LICENSE_KEY_OPTION'] ) );
		}
		$license_plan_info = Mo_License_API_Client::fetch_license_info( $license_key );
		if ( false === $license_plan_info ) {
			throw new Mo_License_Network_Error_Exception();
		}
		$license_plan_info = json_decode( $license_plan_info, true );
		if ( ! empty( $license_plan_info['status'] ) && strcasecmp( $license_plan_info['status'], 'SUCCESS' ) === 0 ) {
			Mo_License_Dao::mo_delete_option( Mo_License_Constants::LICENSE_NOT_ASSOCIATED_WITH_CUSTOMER_OPTION );
			if ( ! $is_sync_request ) {
				self::is_license_linked_to_customer( $license_key );
			} else {
				Mo_License_Backup_Code_Checker::check_license();
				Mo_License_Dao::mo_update_option( Mo_License_Constants::DOMAIN_CHECK_FAILED_OPTION, self::mo_encrypt_data( 'SUCCESS' ) );
			}
			if ( ! empty( $license_key ) ) {
				Mo_License_Dao::mo_update_option( Mo_License_Config::CUSTOMER_MANUALLY_CONFIGURED_OPTIONS['LICENSE_KEY_OPTION'], self::mo_encrypt_data( $license_key ) );
			}
			if ( ! empty( $license_plan_info['licenseExpiry'] ) ) {
				Mo_License_Service::update_license_expiry( $license_plan_info['licenseExpiry'] );
				Mo_License_Dao::mo_update_option( Mo_License_Constants::LAST_CHECK_TIME_OPTION, time() );
			}
			if ( ! empty( $license_plan_info['isTrial'] ) ) {
				Mo_License_Service::update_trial_status( $license_plan_info['isTrial'] );
			}
			foreach ( Mo_License_Config::LICENSE_OPTIONS as $key => $value ) {
				if ( ! empty( $license_plan_info[ $key ] ) ) {
					Mo_License_Dao::mo_update_option( $value, self::mo_encrypt_data( $license_plan_info[ $key ] ) );
				}
			}
			Mo_License_Dao::mo_update_option( Mo_License_Constants::DOMAIN_CHECK_FAILED_OPTION, self::mo_encrypt_data( $license_plan_info['status'] ) );
			return true;
		}

		if ( ! empty( $license_plan_info['message'] ) && strpos( $license_plan_info['message'], Mo_License_Constants::MESSAGE_LICENSE_KEY_ATTACHED_TO_DIFFERENT_PLUGIN_TYPE ) !== false ) {
			throw new Mo_License_Plan_Not_Purchased_Exception();
		}

		self::maybe_set_license_not_associated_flag_from_response( $license_plan_info );
		throw new Mo_License_Invalid_License_Key_Exception();
	}

	/**
	 * Validates and sanitizes the provided password.
	 *
	 * This function validates the provided password and sanitizes it using the
	 * sanitize_text_field function. If the password is empty or contains invalid
	 * characters, an exception is thrown.
	 *
	 * @param string $password The password to validate and sanitize.
	 *
	 * @return string Returns the sanitized password.
	 *
	 * @throws Mo_License_Invalid_Username_Or_Password_Exception If the password is empty or contains invalid characters.
	 */
	public static function validate_and_sanitize_user_password( $password ) {
		$password = sanitize_text_field( $password );
		if ( empty( $password ) ) {
			throw new Mo_License_Invalid_Username_Or_Password_Exception();
		}
		return $password;
	}
}
