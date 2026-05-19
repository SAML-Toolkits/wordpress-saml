<?php
/**
 * This file is part of miniOrange WP plugin.
 *
 * @package    miniOrange
 * @author     miniOrange Security Software Pvt. Ltd.
 * @license    GNU/GPLv3
 * @copyright  Copyright 2015 miniOrange. All Rights Reserved.
 */

namespace MOSAML\LicenseLibrary\Classes;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\LicenseLibrary\Mo_License_Config;
use MOSAML\LicenseLibrary\Mo_License_Service;
use MOSAML\LicenseLibrary\Utils\Mo_License_API_Utility;
use MOSAML\LicenseLibrary\Utils\Mo_License_Service_Utility;
use MOSAML\LicenseLibrary\Classes\Mo_AESEncryption;
use MOSAML\LicenseLibrary\Classes\Mo_License_URL;

/**
 * Contains functions to interact with the API for license framework.
 */
class Mo_License_API_Client {

	/**
	 * Calls the license endpoint for fetching customer's license details.
	 *
	 * @param string $license_key The license key to fetch and save details for. Defaults to an empty string.
	 *
	 * @return string
	 */
	public static function fetch_license_info( $license_key = '' ) {

		$url          = Mo_License_URL::LICENSE_SYNC_URL;
		$customer_key = Mo_License_Dao::mo_get_option( Mo_License_Config::CUSTOMER_OPTIONS['id'] );
		if ( empty( $license_key ) ) {
			$license_key = Mo_License_Service_Utility::mo_decrypt_data( Mo_License_Dao::mo_get_option( Mo_License_Config::CUSTOMER_MANUALLY_CONFIGURED_OPTIONS['LICENSE_KEY_OPTION'] ) );
		}

		if ( ! $customer_key ) {
			return false;
		}

		$current_time_array = Mo_License_API_Utility::get_current_time_in_millis( $customer_key );

		$fields  = array(
			'customerId'      => $customer_key,
			'applicationName' => Mo_License_Config::LICENSE_PLAN_NAME,
			'code'            => $license_key,
			'version'         => Mo_License_API_Utility::get_version_from_plugin_file(),
		);
		$headers = Mo_License_API_Utility::get_api_headers( $customer_key, $current_time_array['milliTime'], $current_time_array['hash'] );
		$args    = Mo_License_API_Utility::get_api_args( $fields, $headers );

		$response = Mo_License_API_Utility::mo_wp_remote_call( $url, $args );
		return $response;
	}

	/**
	 * Calls the license endpoint for fetching customer's account details.
	 *
	 * @param string $email The customer's email address.
	 * @param string $password The customer's password.
	 *
	 * @return string
	 */
	public static function fetch_account_info( $email, $password ) {
		$url = Mo_License_URL::ACCOUNT_VERIFICATION_URL;
		if ( empty( $email ) || empty( $password ) ) {
			return false;
		}
		$fields   = array(
			'email'    => $email,
			'password' => $password,
		);
		$headers  = Mo_License_API_Utility::get_basic_api_headers();
		$args     = Mo_License_API_Utility::get_api_args( $fields, $headers );
		$response = Mo_License_API_Utility::mo_wp_remote_call( $url, $args );
		return $response;
	}

	/**
	 * Calls the license endpoint for verifying customer's license key and after verification the license key information is returned.
	 *
	 * @param string $code The license key to be verified.
	 * @return string
	 */
	public static function fetch_license_key_info( $code ) {
		$url          = Mo_License_URL::LICENSE_VERIFICATION_URL;
		$customer_key = Mo_License_Dao::mo_get_option( Mo_License_Config::CUSTOMER_OPTIONS['id'] );
		$api_key      = Mo_License_Dao::mo_get_option( Mo_License_Config::CUSTOMER_OPTIONS['apiKey'] );
		if ( ! Mo_License_API_Utility::are_all_not_empty( $customer_key, $api_key ) ) {
			return false;
		}
		$current_time_array = Mo_License_API_Utility::get_current_time_in_millis( $customer_key );
		$fields             = Mo_License_API_Utility::get_api_body( $code, $customer_key, home_url() );
		$fields['version']  = Mo_License_API_Utility::get_version_from_plugin_file();
		$headers            = Mo_License_API_Utility::get_api_headers( $customer_key, $current_time_array['milliTime'], $current_time_array['hash'] );
		$args               = Mo_License_API_Utility::get_api_args( $fields, $headers );
		$response           = Mo_License_API_Utility::mo_wp_remote_call( $url, $args );
		return $response;
	}

	/**
	 * Calls the license endpoint to release the customer's license key, changing its status to free.
	 *
	 * @return string
	 */
	public static function update_license_status() {
		$url          = Mo_License_URL::REMOVE_ACCOUNT_URL;
		$customer_key = Mo_License_Dao::mo_get_option( Mo_License_Config::CUSTOMER_OPTIONS['id'] );
		$api_key      = Mo_License_Dao::mo_get_option( Mo_License_Config::CUSTOMER_OPTIONS['apiKey'] );
		if ( ! Mo_License_API_Utility::are_all_not_empty( $customer_key, $api_key ) ) {
			return false;
		}
		$current_time_array = Mo_License_API_Utility::get_current_time_in_millis( $customer_key );
		$code               = Mo_License_Service_Utility::mo_decrypt_data( Mo_License_Dao::mo_get_option( Mo_License_Config::CUSTOMER_MANUALLY_CONFIGURED_OPTIONS['LICENSE_KEY_OPTION'] ) );
		$fields             = Mo_License_API_Utility::get_api_body( $code, $customer_key, home_url() );
		$headers            = Mo_License_API_Utility::get_api_headers( $customer_key, $current_time_array['milliTime'], $current_time_array['hash'] );
		$args               = Mo_License_API_Utility::get_api_args( $fields, $headers );
		$response           = Mo_License_API_Utility::mo_wp_remote_call( $url, $args );
		return $response;
	}

	/**
	 * Calls the addon list endpoint for fetching available addons.
	 *
	 * @return string|false Response from the API or false if customer key is not set.
	 */
	public static function fetch_addon_list() {
		$url          = Mo_License_URL::ADDON_FETCH_URL;
		$customer_key = Mo_License_Dao::mo_get_option( Mo_License_Config::CUSTOMER_OPTIONS['id'] );
		$license_key  = Mo_License_Dao::mo_get_option( Mo_License_Config::CUSTOMER_MANUALLY_CONFIGURED_OPTIONS['LICENSE_KEY_OPTION'] );

		if ( ! $customer_key ) {
			return false;
		}

		$key = Mo_License_Dao::mo_get_option( Mo_License_Config::CUSTOMER_OPTIONS['token'] );

		$code = Mo_AESEncryption::decrypt_data( $license_key ?? '', $key ?? '' );

		$license_plan_raw = Mo_License_Dao::mo_get_option( Mo_License_Constants::LICENSE_PLAN_OPTION );
		$license_plan = is_string( $license_plan_raw ) ? json_decode( $license_plan_raw, true ) : null;
		if ( is_array( $license_plan ) && ! empty( $key ) && isset( $license_plan[ $key ] ) ) {
			$license_plan = Mo_License_Service_Utility::mo_decrypt_data( $license_plan[ $key ] );
		} else {
			$license_plan = null;
		}

		if ( empty( $license_plan ) ) {
			$license_plan = Mo_License_Config::LICENSE_PLAN_NAME;
		}

		$current_time_array = Mo_License_API_Utility::get_current_time_in_millis( $customer_key );

		$fields = array(
			'code'            => $code,
			'pluginType'      => Mo_License_Config::ADDON_FETCH_PLUGIN_TYPE,
			'customerId'      => $customer_key,
			'applicationName' => $license_plan,
		);

		$headers = Mo_License_API_Utility::get_api_headers( $customer_key, $current_time_array['milliTime'], $current_time_array['hash'] );
		$args = Mo_License_API_Utility::get_api_args( $fields, $headers );
		$response = Mo_License_API_Utility::mo_wp_remote_call( $url, $args );

		return $response;
	}

	/**
	 * Get the download URL for an addon.
	 *
	 * @param string $plan_name  The plan name for the addon.
	 * @return string The download URL for the addon.
	 */
	public static function get_addon_download_url( $plan_name ) {
		$customer_key = Mo_License_Dao::mo_get_option( Mo_License_Config::CUSTOMER_OPTIONS['id'] );

		$current_time_array = Mo_License_API_Utility::get_current_time_in_millis( $customer_key );

		$hash         = $current_time_array['hash'];
		$current_time = $current_time_array['milliTime'];

		return add_query_arg(
			array(
				'applicationName' => $plan_name,
				'Customer-Key'    => $customer_key,
				'Authorization'   => $hash,
				'Timestamp'       => $current_time,
			),
			Mo_License_URL::PLUGIN_DOWNLOAD_URL
		);
	}
}
