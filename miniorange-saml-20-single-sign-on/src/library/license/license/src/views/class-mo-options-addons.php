<?php
/**
 * This file displays all the add-ons listed in the plugin.
 *
 * @package    miniOrange
 * @author     miniOrange Security Software Pvt. Ltd.
 */

namespace MOSAML\LicenseLibrary\Views;

use MOSAML\LicenseLibrary\Classes\Mo_License_API_Client;
use MOSAML\LicenseLibrary\Mo_License_Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Defines addons constants and manages addon data.
 */
class Mo_Options_Addons {

	/**
	 * A map for addons name and URL.
	 *
	 * @var array
	 */
	private static $addons_landing_page = array();

	/**
	 * A map for addons name and Description.
	 *
	 * @var array
	 */
	private static $addon_description = array();

	/**
	 * A map for addon names and titles.
	 *
	 * @var array
	 */
	private static $addon_titles = array();

	/**
	 * A map for addon names and slugs.
	 *
	 * @var array
	 */
	private static $addon_slug = array();

	/**
	 * A map for addons name and icon.
	 *
	 * @var array
	 */
	private static $addon_icon = array();

	/**
	 * A map for addons name and plan name.
	 *
	 * @var array
	 */
	private static $addon_plan_name = array();

	/**
	 * Licensed addons data.
	 *
	 * @var array
	 */
	private static $licensed_addons = array();

	/**
	 * Available addons data.
	 *
	 * @var array
	 */
	private static $available_addons = array();

	/**
	 * Initialize the addon data from API.
	 *
	 * @return void
	 */
	public static function init() {
		$addon_list = Mo_License_API_Client::fetch_addon_list();
		if ( is_string( $addon_list ) ) {
			$addon_list = json_decode( $addon_list, true );
		}

		if ( $addon_list && isset( $addon_list['status'] ) && 'SUCCESS' === $addon_list['status'] ) {
			if ( isset( $addon_list['licensedAddons'] ) && is_array( $addon_list['licensedAddons'] ) ) {
				foreach ( $addon_list['licensedAddons'] as $plan_name => $addon ) {
					self::process_addon_data( $addon, true );
				}
			}

			if ( isset( $addon_list['availableAddons'] ) && is_array( $addon_list['availableAddons'] ) && ! empty( $addon_list['availableAddons'] ) ) {
				foreach ( $addon_list['availableAddons'] as $plan_name => $addon ) {
					self::process_addon_data( $addon, false );
				}
			}

			$fallback_addons = self::get_fallback_addons();
			if ( ! empty( $fallback_addons ) && is_array( $fallback_addons ) ) {
				foreach ( $fallback_addons as $addon ) {
					if ( ! is_array( $addon ) || empty( $addon['addonTitle'] ) ) {
						continue;
					}

					$key = $addon['addonTitle'];

					if ( isset( self::$licensed_addons[ $key ] ) || isset( self::$available_addons[ $key ] ) ) {
						continue;
					}

					self::process_addon_data( $addon, false );
				}
			}
		} else {
			$fallback_addons = self::get_fallback_addons();
			foreach ( $fallback_addons as $addon ) {
				self::process_addon_data( $addon, false );
			}
		}
	}

	/**
	 * Get the addon slug from the Key.
	 *
	 * @param string $message_key The key of the addon to fetch.
	 *
	 * @return string|null Addon slug corresponding to the provided key.
	 */
	public static function mo_get_addon_slug( $message_key ) {
		return isset( self::$addon_slug[ $message_key ] ) ? self::$addon_slug[ $message_key ] : null;
	}

	/**
	 * Get the addon plan name from the Key.
	 *
	 * @param string $message_key The key of the addon to fetch.
	 *
	 * @return string|null Addon plan name corresponding to the provided key.
	 */
	public static function mo_get_addon_plan_name( $message_key ) {
		return isset( self::$addon_plan_name[ $message_key ] ) ? self::$addon_plan_name[ $message_key ] : null;
	}

	/**
	 * Get all licensed addons.
	 *
	 * @return array Array of licensed addons.
	 */
	public static function get_licensed_addons() {
		return self::$licensed_addons;
	}

	/**
	 * Get all available addons.
	 *
	 * @return array Array of available addons.
	 */
	public static function get_available_addons() {
		return self::$available_addons;
	}

	/**
	 * Get fallback addons data when API fails or returns empty.
	 *
	 * @return array Fallback addons array.
	 */
	private static function get_fallback_addons() {
		return Mo_License_Config::get_fallback_addons_data();
	}

	/**
	 * Process addon data and store in static arrays.
	 *
	 * @param array $addon Addon data array.
	 * @param bool  $is_licensed Whether this is a licensed addon.
	 *
	 * @return void
	 */
	private static function process_addon_data( $addon, $is_licensed = false ) {
		if ( ! is_array( $addon ) || empty( $addon ) || ! isset( $addon['addonTitle'] ) ) {
			return;
		}

		$key = $addon['addonTitle'];

		// Store addon data.
		if ( isset( $addon['addonIcon'] ) ) {
			self::$addon_icon[ $key ] = $addon['addonIcon'];
		}

		if ( isset( $addon['landingPage'] ) ) {
			self::$addons_landing_page[ $key ] = $addon['landingPage'];
		}

		if ( isset( $addon['addonDescription'] ) ) {
			self::$addon_description[ $key ] = $addon['addonDescription'];
		}

		if ( isset( $addon['addonTitle'] ) ) {
			self::$addon_titles[ $key ] = $addon['addonTitle'];
		}

		if ( isset( $addon['addonSlug'] ) ) {
			self::$addon_slug[ $key ] = $addon['addonSlug'];
		}

		if ( isset( $addon['planName'] ) ) {
			self::$addon_plan_name[ $key ] = $addon['planName'];
		}

		// Store in appropriate array.
		if ( $is_licensed ) {
			self::$licensed_addons[ $key ] = $addon;
		} else {
			self::$available_addons[ $key ] = $addon;
		}
	}
}
