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

use MOSAML\LicenseLibrary\Classes\Mo_License_API_Client;
use MOSAML\LicenseLibrary\Classes\Mo_License_Constants;
use MOSAML\LicenseLibrary\Classes\Mo_License_Library;
use MOSAML\LicenseLibrary\Mo_License_Config;
use MOSAML\LicenseLibrary\Classes\Mo_License_Dao;
use MOSAML\LicenseLibrary\Mo_License_Service;

/**
 * Class Mo_License_Actions_Utility contains utility functions required during performing
 * the License Actions.
 */
class Mo_License_Actions_Utility {

	/**
	 * Fetches license information and updates the license expiry date in database.
	 * Returns the license expiry date if information is fetched and updated correctly, else returns false.
	 *
	 * @return bool|string License expiry date on success, false on failure.
	 */
	public static function fetch_license_expiry_date() {
		try {
			$license_info = Mo_License_API_Client::fetch_license_info();
			if ( empty( $license_info ) ) {
				return false;
			}

			$license_info = json_decode( $license_info, true );
			if ( ! empty( $license_info['status'] ) && strcasecmp( $license_info['status'], 'SUCCESS' ) === 0 ) {
				if ( ! empty( $license_info['licensePlan'] ) ) {
					Mo_License_Service::update_license_plan( $license_info['licensePlan'] );
				}
				if ( ! empty( $license_info['licenseExpiry'] ) ) {
					return $license_info['licenseExpiry'];
				}
				return false;
			}
			return false;
		} catch ( \Exception $e ) {
			return false;
		}
	}

	/**
	 * Returns the hook name based on the current environment type.
	 *
	 * @param string $hook The hook for which the environment specific hook name is required.
	 *
	 * @return string
	 */
	public static function get_current_environment_hook_name( $hook ) {
		return Mo_License_Constants::ENVIRONMENT_SPECIFIC_HOOKS[ $hook ][ Mo_License_Library::$environment_type ];
	}

	/**
	 * Returns the environment type based on the whether the plugin
	 * is activated on a network or not.
	 *
	 * @return string
	 */
	public static function get_environment_type() {

		if ( ! function_exists( 'is_plugin_active_for_network' ) ) {
			require_once ABSPATH . Mo_License_Constants::PLUGIN_FILE_PATH;
		}

		$plugin_folder  = explode( '/', Mo_License_Config::PLUGIN_FILE );
		$active_plugins = (array) Mo_License_Dao::mo_get_option( 'active_sitewide_plugins', array() );
		if ( is_plugin_active_for_network( Mo_License_Config::PLUGIN_FILE ) ) {
			return 'network';
		} elseif ( ! empty( $active_plugins ) ) {
			foreach ( $active_plugins as $active_plugin => $value ) {
				if ( strpos( $active_plugin, $plugin_folder[0] ) !== false ) {
					return 'network';
				}
			}
		}
		return 'standalone';
	}
}