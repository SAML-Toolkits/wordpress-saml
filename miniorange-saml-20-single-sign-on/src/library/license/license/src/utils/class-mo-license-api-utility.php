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
use MOSAML\LicenseLibrary\Mo_License_Config;

/**
 * Class Mo_License_API_Utility contains utility functions required for
 * license related API calls.
 */
class Mo_License_API_Utility {

	/**
	 * Function to get the current time and hash value for customer related API calls.
	 *
	 * @param string $customer_key The customer's key used to create the hash value.
	 *
	 * @return array
	 */
	public static function get_current_time_in_millis( $customer_key ) {
		$api_key                = Mo_License_Dao::mo_get_option( Mo_License_Config::CUSTOMER_OPTIONS['apiKey'] );
		$current_time_in_millis = round( microtime( true ) * 1000 );
		$string_to_hash         = $customer_key . number_format( $current_time_in_millis, 0, '', '' ) . $api_key;
		$hash_value             = hash( 'sha512', $string_to_hash );
		$current_time_in_millis = number_format( $current_time_in_millis, 0, '', '' );

		return array(
			'milliTime' => $current_time_in_millis,
			'hash'      => $hash_value,
		);
	}

	/**
	 * Function to get headers for customer related API calls.
	 *
	 * @return array
	 */
	public static function get_basic_api_headers() {
		return array(
			'Content-Type'  => 'application/json',
			'charset'       => 'UTF-8',
			'Authorization' => 'Basic',
		);
	}

	/**
	 * Function to get headers for customer related API calls.
	 *
	 * @param string $customer_key Customer's key to be sent in the header.
	 * @param int    $current_time_millis Current time value to be sent in the header.
	 * @param string $hash_value Hash value to be sent in the header for authorization.
	 *
	 * @return array
	 */
	public static function get_api_headers( $customer_key, $current_time_millis, $hash_value ) {
		return array(
			'Content-Type'  => 'application/json',
			'Customer-Key'  => $customer_key,
			'Timestamp'     => $current_time_millis,
			'Authorization' => $hash_value,
		);
	}

	/**
	 * Function to get the API arguments for customer related API calls.
	 *
	 * @param array $fields Fields array to be sent in the API request body.
	 * @param array $headers Headers to be sent with the API request.
	 *
	 * @return array
	 */
	public static function get_api_args( $fields, $headers ) {
		$field_string = wp_json_encode( $fields );
		return array(
			'method'      => 'POST',
			'body'        => $field_string,
			'timeout'     => '10',
			'redirection' => '5',
			'httpversion' => '1.0',
			'blocking'    => true,
			'headers'     => $headers,
		);
	}

	/**
	 * Wrapper Function to make a remote POST or GET call to the specified url.
	 *
	 * @param string $url The endpoint to which the POST/GET call needs to be made.
	 * @param array  $args Arguments which need to be sent in the POST/GET call.
	 * @param bool   $is_get Boolean value which specifies whether a GET call needs to be made.
	 *
	 * @return bool|array
	 */
	public static function mo_wp_remote_call( $url, $args = array(), $is_get = false ) {
		if ( ! $is_get ) {
			$response = wp_remote_post( $url, $args );
		} else {
			$response = wp_remote_get( $url, $args );
		}

		if ( ! is_wp_error( $response ) ) {
			return $response['body'];
		} else {
			return false;
		}
	}

	/**
	 * Builds the API request body with provided parameters.
	 *
	 * This function creates and returns an associative array structured to be used
	 * as the body of an API request. It includes the code, customer key, and an
	 * additional fields array containing a URL.
	 *
	 * @param string $code         The code to include in the API body.
	 * @param string $customer_key The customer key to include in the API body.
	 * @param string $url          The URL to include in the additional fields.
	 *
	 * @return array The structured API request body.
	 */
	public static function get_api_body( $code, $customer_key, $url ) {
		return array(
			'code'             => $code,
			'customerKey'      => $customer_key,
			'additionalFields' => array(
				'field1' => $url,
			),
		);
	}

	/**
	 * Builds the API request body for the backupcode/check endpoint.
	 *
	 * Used for periodic license verification. Includes site URL, optional
	 * mismatch email flag, and notification days.
	 *
	 * @param string $code             License key or backup code (alphanumeric).
	 * @param string $customer_key     Customer ID (numeric).
	 * @param string $site_url         Current site URL (e.g. home_url()).
	 * @param bool   $send_mismatch_email Optional. Send mismatch email "true"/"false". Default false.
	 * @param int    $notification_days Optional. Notification days. Default 3.
	 * @param string $license_type     Optional. License type.
	 *
	 * @return array The structured API request body for backupcode/check.
	 */
	public static function get_backup_code_check_body( $code, $customer_key, $site_url = null, $send_mismatch_email = false, $notification_days = 3, $license_type = '' ) {
		if ( null === $site_url ) {
			$site_url = function_exists( 'home_url' ) ? home_url() : '';
		}
		$body = array(
			'code'             => $code,
			'customerKey'      => $customer_key,
			'additionalFields' => array(
				'field1' => $site_url,
				'field2' => $send_mismatch_email ? 'true' : 'false',
				'field3' => (string) $notification_days,
			),
		);
		if ( ! empty( $license_type ) ) {
			$body['licenseType'] = $license_type;
		}
		return $body;
	}

	/**
	 * Checks if all provided variables are not empty.
	 *
	 * This function accepts any number of variables as arguments and verifies
	 * that each variable is not empty. If any of the variables are empty, it
	 * returns false. If all variables are non-empty, it returns true.
	 *
	 * @param mixed ...$vars Variables to check for emptiness.
	 *
	 * @return bool Returns true if all variables are not empty; false otherwise.
	 */
	public static function are_all_not_empty( ...$vars ) {
		foreach ( $vars as $var ) {
			if ( empty( $var ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Get the plugin version from the main plugin file header.
	 *
	 * Reads the 'Version' field from the plugin file header using WordPress's
	 * get_file_data() function.
	 *
	 * @param string $plugin_slug The plugin slug in format 'directory/file.php'.
	 * @return string The plugin version string, or an empty string if unavailable.
	 */
	public static function get_version_from_plugin_file( $plugin_slug = '' ) {
		if ( empty( $plugin_slug ) ) {
			$plugin_slug = Mo_License_Config::PLUGIN_FILE;
		}

		if ( ! function_exists( 'get_file_data' ) ) {
			require_once ABSPATH . Mo_License_Constants::PLUGIN_FILE_PATH;
		}

		$plugin_file = WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $plugin_slug;

		if ( file_exists( $plugin_file ) ) {
			$plugin_data = get_file_data(
				$plugin_file,
				array(
					'Version' => 'Version',
				)
			);

			if ( ! empty( $plugin_data['Version'] ) ) {
				return $plugin_data['Version'];
			}
		}

		return Mo_License_Config::PLUGIN_VERSION;
	}
}
