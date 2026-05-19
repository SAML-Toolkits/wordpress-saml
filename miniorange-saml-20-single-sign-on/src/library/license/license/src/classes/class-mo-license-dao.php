<?php
/**
 * This file is part of miniOrange WP plugin.
 *
 * @package    miniOrange
 * @author     miniOrange Security Software Pvt. Ltd.
 */

namespace MOSAML\LicenseLibrary\Classes;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\LicenseLibrary\Mo_License_Config;

/**
 * Contains wrapper functions for interactions with the WP database.
 */
class Mo_License_Dao {

	/**
	 * Wrapper function to get option values from the WordPress database. Fetches option
	 * value passed from the options table by default. Override this function to use
	 * custom logic for fetching values from custom tables.
	 *
	 * @param string  $option Name of the option to retrieve. Expected to not be SQL-escaped.
	 * @param boolean $default_value Optional. Value to return if the option doesn't exist.
	 * Default: false.
	 * @param boolean $deprecated Optional. Whether to use cache. Multisite only. Always set
	 * to true.
	 *
	 * @return string
	 */
	public static function mo_get_option( $option, $default_value = false, $deprecated = true ) {

		switch ( Mo_License_Config::PLUGIN_TYPE ) {
			case 'WP_SS':
				return get_option( $option, $default_value );
			case 'WP_MS':
				return get_site_option( $option, $default_value );
		}
	}

	/**
	 * Wrapper function to update the value of an option in the WordPress database. If the option does
	 * not exist, it will be created. Override this function to use custom logic for updating values
	 * into custom tables.
	 *
	 * @param string $option  Name of the option to update. Expected to not be SQL-escaped.
	 * @param mixed  $value  Option value. Expected to not be SQL-escaped.
	 *
	 * @return bool
	 */
	public static function mo_update_option( $option, $value ) {

		switch ( Mo_License_Config::PLUGIN_TYPE ) {
			case 'WP_SS':
				return update_option( $option, $value );
			case 'WP_MS':
				return update_site_option( $option, $value );
		}
	}

	/**
	 * Wrapper function to delete the value of an option in the WordPress database.
	 *
	 * @param string $option Name of the option to delete. Expected to not be SQL-escaped.
	 *
	 * @return bool
	 */
	public static function mo_delete_option( $option ) {

		switch ( Mo_License_Config::PLUGIN_TYPE ) {
			case 'WP_SS':
				return delete_option( $option );
			case 'WP_MS':
				return delete_site_option( $option );
		}
	}
}