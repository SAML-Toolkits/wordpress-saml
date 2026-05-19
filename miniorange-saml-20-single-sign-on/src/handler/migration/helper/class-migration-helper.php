<?php
/**
 * Migration Value Mapper.
 *
 * @package    MOSAML
 * @subpackage MOSAML/src/handler/migration/helper
 */

namespace MOSAML\SRC\Handler\Migration\Helper;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;

/**
 * Migration Value Mapper.
 */
class Migration_Helper {

	/**
	 * Map the value.
	 *
	 * @param string $mapper The mapper to use.
	 * @param mixed  $value The value to map.
	 * @return mixed The mapped value.
	 */
	public static function map_value( $mapper, $value ) {
		switch ( $mapper ) {
			case 'true_to_checked':
				if ( is_string( $value ) && 'false' === strtolower( trim( $value ) ) ) {
					return '';
				}
				return $value ? 'checked' : '';
			case 'on_to_checked':
				return 'on' === $value ? 'checked' : '';
			case 'unchecked_to_checked':
				return 'unchecked' === $value ? 'checked' : '';
			default:
				return $value;
		}
	}

	/**
	 * Get the mapper.
	 *
	 * @return object The mapper.
	 */
	public static function get_mapper() {
		$version       = self::detect_legacy_version();
		$version       = 1 === $version ? 2 : $version;
		$hierarchy_key = isset( Constants::VERSION_HIERARCHY[ $version ] ) ? Constants::VERSION_HIERARCHY[ $version ] : Constants::VERSION_HIERARCHY[ MOSAML_VERSION ];
		$class_name    = ucfirst( strtolower( $hierarchy_key ) ) . '_Version_Mapper';
		$class_name    = 'MOSAML\SRC\Handler\Migration\Mapper\\' . $class_name;
		return new $class_name();
	}

	/**
	 * Detect the legacy plugin version.
	 *
	 * @return int The legacy plugin version.
	 */
	public static function detect_legacy_version() {
		$plan_details = get_option( 'mosaml_plugin_plan_details', array() );

		if ( ! empty( $plan_details ) && ! empty( $plan_details['version_hierarchy'] ) ) {
			return 1 !== intval( $plan_details['version_hierarchy'] ) ? intval( $plan_details['version_hierarchy'] ) : 2;
		}

		if ( get_option( 'mo_enable_multiple_licenses' ) || get_option( 'saml_identity_providers' ) || get_option( 'mo_saml_environment_objects' ) ) {
			return 4;
		}
		if ( get_option( 'mo_saml_add_button_wp_login' ) || get_option( 'mo_saml_keep_settings_on_deletion' ) ) {
			return 2;
		}
		return 1 !== intval( MOSAML_VERSION ) ? intval( MOSAML_VERSION ) : 2;
	}

		/**
		 * Check if migration is needed.
		 *
		 * @return bool True if migration is needed, false otherwise.
		 */
	public static function is_migration_needed() {
		$is_completed   = self::is_migration_completed();
		$is_in_progress = self::is_migration_in_progress();

		if ( $is_completed || $is_in_progress ) {
			return false;
		}

		$has_legacy = self::has_legacy_data();

		if ( ! $has_legacy ) {
			update_option( Constants::MIGRATION_STATUS, 'completed' );
			return false;
		}

		return true;
	}

	/**
	 * Check if migration has been completed.
	 *
	 * @return bool True if migration completed, false otherwise.
	 */
	public static function is_migration_completed() {
		return 'completed' === get_option( Constants::MIGRATION_STATUS, '' );
	}

	/**
	 * Check if migration is in progress.
	 *
	 * @return bool True if migration in progress, false otherwise.
	 */
	public static function is_migration_in_progress() {
		return 'in_progress' === get_option( Constants::MIGRATION_STATUS, '' );
	}

	/**
	 * Check if legacy plugin data exists.
	 *
	 * @return bool True if legacy data exists, false otherwise.
	 */
	public static function has_legacy_data() {
		// Detect plugin version to look for the options accordingly to check if legacy data exists.
		$plugin_version = self::detect_legacy_version();

		// Check for key legacy options that indicate the legacy plugin was configured.
		$key_options = array(
			// Standard/Premium.
			'saml_identity_name',
			'saml_login_url',
			'saml_issuer',
			// Enterprise.
			'saml_identity_providers',
			'mo_saml_environment_objects',
		);

		foreach ( $key_options as $option ) {
			$value = get_option( $option );
			if ( false !== $value ) {
				return true;
			}
		}

		return false;
	}
}
