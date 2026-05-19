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

use MOSAML\LicenseLibrary\Classes\Mo_License_Constants;
use MOSAML\LicenseLibrary\Classes\Mo_License_Dao;
use MOSAML\LicenseLibrary\Classes\Mo_License_URL;
use MOSAML\LicenseLibrary\Exceptions\Mo_License_Already_Used_License_Key_Exception;
use MOSAML\LicenseLibrary\Exceptions\Mo_License_Invalid_License_Key_Exception;
use MOSAML\LicenseLibrary\Exceptions\Mo_License_Unknown_Error_Exception;
use MOSAML\LicenseLibrary\Mo_License_Config;
use MOSAML\LicenseLibrary\Mo_License_Service;
use MOSAML\LicenseLibrary\Utils\Mo_License_Service_Utility;

/**
 * License checker for periodic verification via miniOrange marketplace backupcode/check API.
 *
 * Used for CRON-style license verification. Schedule is driven by LICENSE_CRON_INTERVAL in Mo_License_Config.
 */
class Mo_License_Backup_Code_Checker {

	/**
	 * API request timeout in seconds.
	 */
	const API_TIMEOUT = 15;

	/**
	 * Performs the backup code check and updates license state.
	 *
	 * Calls the backupcode/check API, parses the response, and updates license
	 * expiry, trial status, or clears cached data on failure.
	 *
	 * @return array{status: string, message?: string, is_expired?: bool, license_expiry_date?: string} Result with status (SUCCESS|FAILED|ERROR) and optional data.
	 *
	 * @throws Mo_License_Invalid_License_Key_Exception When the license key is invalid.
	 * @throws Mo_License_Already_Used_License_Key_Exception When license key is already in use on another site.
	 * @throws Mo_License_Unknown_Error_Exception When an unknown error is returned by the API.
	 */
	public static function check_license() {
		$customer_key = Mo_License_Dao::mo_get_option( Mo_License_Config::CUSTOMER_OPTIONS['id'] );
		$api_key      = Mo_License_Dao::mo_get_option( Mo_License_Config::CUSTOMER_OPTIONS['apiKey'] );
		$license_key  = Mo_License_Service_Utility::mo_decrypt_data(
			Mo_License_Dao::mo_get_option( Mo_License_Config::CUSTOMER_MANUALLY_CONFIGURED_OPTIONS['LICENSE_KEY_OPTION'] )
		);

		if ( ! Mo_License_API_Utility::are_all_not_empty( $customer_key, $api_key, $license_key ) ) {
			return array(
				'status'  => 'ERROR',
				'message' => 'Missing license configuration (customer key, API key, or license code).',
			);
		}

		$url             = Mo_License_URL::LICENSE_DOMAIN_CHECK_URL;
		$body            = Mo_License_API_Utility::get_backup_code_check_body(
			$license_key,
			$customer_key,
			null,
			false,
			3,
			Mo_License_Config::LICENSE_TYPE
		);
		$body['version'] = Mo_License_API_Utility::get_version_from_plugin_file();
		$auth            = self::build_auth_hash( $customer_key, $api_key );
		$headers         = Mo_License_API_Utility::get_api_headers( $customer_key, $auth['timestamp'], $auth['authorization'] );

		$args = array(
			'method'      => 'POST',
			'body'        => wp_json_encode( $body ),
			'timeout'     => self::API_TIMEOUT,
			'redirection' => 5,
			'httpversion' => '1.0',
			'blocking'    => true,
			'headers'     => array_merge(
				$headers,
				array(
					'Content-Type' => 'application/json',
					'charset'      => 'UTF-8',
				)
			),
		);

		$response = wp_remote_post( $url, $args );

		if ( is_wp_error( $response ) ) {
			return array(
				'status'  => 'ERROR',
				'message' => $response->get_error_message(),
			);
		}

		$http_code = (int) wp_remote_retrieve_response_code( $response );
		$body_raw  = wp_remote_retrieve_body( $response );

		$result = self::parse_response( $body_raw, $http_code );

		$body_decoded = json_decode( $body_raw, true );
		if ( is_array( $body_decoded ) ) {
			Mo_License_Service_Utility::maybe_set_license_not_associated_flag_from_response( $body_decoded );
		}

		if ( strcasecmp( $result['status'], 'FAILED' ) === 0 || strcasecmp( $result['status'], 'ERROR' ) === 0 ) {
			$message = isset( $result['message'] ) ? sanitize_text_field( $result['message'] ) : '';

			if ( '' !== $message && strpos( $message, 'License key is not valid.' ) !== false ) {
				throw new Mo_License_Invalid_License_Key_Exception( esc_html( $message ) );
			} elseif ( '' !== $message && strpos( $message, 'Host not Found' ) !== false ) {
				throw new Mo_License_Already_Used_License_Key_Exception( esc_html( $message ) );
			} else {
				throw new Mo_License_Unknown_Error_Exception( esc_html( $message ) );
			}
		}

		return $result;
	}

	/**
	 * Builds the Authorization header hash.
	 *
	 * SHA-512(customerKey + timestamp + apiKey) in hex, lowercase.
	 *
	 * @param string $customer_key Customer ID (numeric).
	 * @param string $api_key      API key for hashing.
	 *
	 * @return array{authorization: string, timestamp: string} Hash and timestamp in milliseconds.
	 */
	private static function build_auth_hash( $customer_key, $api_key ) {
		$timestamp      = (int) round( microtime( true ) * 1000 );
		$timestamp_str  = (string) $timestamp;
		$string_to_hash = $customer_key . $timestamp_str . $api_key;
		$hash           = hash( 'sha512', $string_to_hash );

		return array(
			'authorization' => $hash,
			'timestamp'     => $timestamp_str,
		);
	}

	/**
	 * Validates and parses the backupcode/check API response.
	 *
	 * On SUCCESS: updates license expiry, trial status, and domain check; returns success.
	 * On FAILED or explicit API error (4xx/5xx with failure): marks license invalid.
	 * On network/parse errors: returns error without clearing cached data.
	 *
	 * @param string $body_raw  Raw response body (JSON).
	 * @param int    $http_code HTTP status code.
	 *
	 * @return array{status: string, message?: string, is_expired?: bool, license_expiry_date?: string}
	 */
	private static function parse_response( $body_raw, $http_code ) {
		$decoded = json_decode( $body_raw, true );

		if ( json_last_error() !== JSON_ERROR_NONE || ! is_array( $decoded ) ) {
			return array(
				'status'  => 'ERROR',
				'message' => 'Invalid API response.',
			);
		}

		$status              = isset( $decoded['status'] ) ? $decoded['status'] : '';
		$message             = isset( $decoded['message'] ) ? $decoded['message'] : '';
		$is_expired          = isset( $decoded['isExpired'] ) && $decoded['isExpired'];
		$is_trial            = isset( $decoded['isTrial'] ) && $decoded['isTrial'];
		$license_expiry_date = isset( $decoded['licenseExpiryDate'] ) ? $decoded['licenseExpiryDate'] : '';

		if ( 200 === $http_code && strcasecmp( $status, 'SUCCESS' ) === 0 ) {
			self::handle_check_success( $license_expiry_date, $is_expired, $is_trial );
			return array(
				'status'              => 'SUCCESS',
				'message'             => $message,
				'is_expired'          => $is_expired,
				'license_expiry_date' => $license_expiry_date,
			);
		}

		$error_message = isset( $decoded['message'] ) ? $decoded['message'] : ( isset( $decoded['statusCode'] ) ? 'HTTP ' . $decoded['statusCode'] : 'License check failed.' );
		self::handle_check_failure();
		return array(
			'status'  => 'FAILED',
			'message' => $error_message,
		);
	}

	/**
	 * Handles successful license check: updates expiry, trial, and domain status.
	 *
	 * @param string $license_expiry_date Expiry date from API.
	 * @param bool   $is_expired          Whether license is expired.
	 * @param bool   $is_trial            Whether license is trial.
	 *
	 * @return void
	 */
	private static function handle_check_success( $license_expiry_date, $is_expired, $is_trial ) {
		if ( ! empty( $license_expiry_date ) ) {
			Mo_License_Service::update_license_expiry( $license_expiry_date );
		}
		Mo_License_Service::update_trial_status( $is_trial );
		Mo_License_Dao::mo_update_option( Mo_License_Constants::LAST_CHECK_TIME_OPTION, time() );
		Mo_License_Dao::mo_update_option( Mo_License_Constants::LAST_DOMAIN_CHECK_TIME_OPTION, time() );
		Mo_License_Dao::mo_update_option( Mo_License_Constants::DOMAIN_CHECK_FAILED_OPTION, Mo_License_Service_Utility::mo_encrypt_data( 'SUCCESS' ) );
	}

	/**
	 * Handles failed license check: marks invalid and clears cached license data.
	 *
	 * @return void
	 */
	private static function handle_check_failure() {
		Mo_License_Dao::mo_update_option( Mo_License_Constants::DOMAIN_CHECK_FAILED_OPTION, Mo_License_Service_Utility::mo_encrypt_data( 'FAILED' ) );
		Mo_License_Dao::mo_update_option( Mo_License_Constants::LICENSE_EXPIRED_OPTION, true );
	}
}
