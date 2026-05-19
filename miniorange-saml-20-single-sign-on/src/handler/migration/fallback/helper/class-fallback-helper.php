<?php
/**
 * Fallback Helper.
 *
 * @package    MOSAML
 * @subpackage MOSAML/src/handler/migration/fallback/helper
 */

namespace MOSAML\SRC\Handler\Migration\Fallback\Helper;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Constant\Constants;

/**
 * Fallback Helper.
 */
class Fallback_Helper {

	/**
	 * Get the method name from the table name.
	 *
	 * @param string $table_name The table name.
	 * @return array The method names.
	 */
	public static function get_method_name_from_table_name( $table_name ) {
		$method_name = preg_replace( '/^mosaml/', 'map', $table_name );

		$idp_dependent_methods = array( 'map_sso_settings', 'map_attribute_mapping', 'map_role_mapping' );
		if ( in_array( $method_name, $idp_dependent_methods, true ) ) {
			return array( 'map_idp_details', $method_name );
		}

		return array( $method_name );
	}

	/**
	 * Map the data to the handler.
	 *
	 * @param array  $normalized_model The normalized model.
	 * @param object $handler The handler object.
	 * @param array  $where The where conditions.
	 * @return object The handler object.
	 */
	public static function map_data_to_handler( $normalized_model, $handler, $where = array() ) {
		if ( empty( $normalized_model ) ) {
			return $handler;
		}

		$data = self::get_data_for_where_conditions( $normalized_model, $handler->get_table_name(), $where );

		foreach ( get_object_vars( $handler ) as $property_name => $property_value ) {
			if ( 'id' === $property_name || 'environment_id' === $property_name || 'subsite_id' === $property_name ) {
				$handler->{$property_name} = 1;
				continue;
			}
			$handler->{$property_name} = isset( $data[ $property_name ] ) ? $data[ $property_name ] : $property_value;
		}
		return $handler;
	}

	/**
	 * Get the data for the where conditions.
	 *
	 * @param object $normalized_model The normalized model.
	 * @param string $table_name The table name.
	 * @param array  $where The where conditions.
	 * @return array The data for the where conditions.
	 */
	private static function get_data_for_where_conditions( $normalized_model, $table_name, $where = array() ) {
		$data = self::get_data_from_normalized_model( $normalized_model, $table_name );
		if ( empty( $data ) ) {
			return array();
		}

		$data_separator = self::get_data_separator( $table_name, $where );
		if ( empty( $data_separator ) ) {
			return $data;
		}

		foreach ( $data_separator as $key ) {
			if ( ! is_array( $data ) || ! isset( $data[ $key ] ) ) {
				return array();
			}
			if ( self::check_data_instead_idp_id( $where, $table_name ) ) {
				foreach ( $where as $where_key => $where_value ) {
					if ( in_array( $where_key, array( 'id', 'environment_id', 'subsite_id', 'idp_id' ), true ) ) {
						continue;
					}
					foreach ( $data[ $key ] as $data_value ) {
						if ( isset( $data_value[ $where_key ] ) && $data_value[ $where_key ] === $where_value ) {
							return $data_value;
						}
					}
				}
			}
			$data = $data[ $key ];
		}

		return $data;
	}

	/**
	 * Get the data separator.
	 *
	 * @param string $table_name The table name.
	 * @param array  $where The where conditions.
	 * @return array The data separator.
	 */
	private static function get_data_separator( $table_name, $where = array() ) {
		$idp_id = ! empty( $where['idp_id'] ) ? $where['idp_id'] : 'DEFAULT';
		$parsed_url = Utility::parse_environment_url( site_url() );
		switch ( $table_name ) {
			case Constants::DATABASE_TABLE_NAMES['environments']:
			case Constants::DATABASE_TABLE_NAMES['sp_metadata']:
			case Constants::DATABASE_TABLE_NAMES['subsites']:
				return array( $parsed_url );
			case Constants::DATABASE_TABLE_NAMES['idp_details']:
				return array( $parsed_url, $idp_id );
			case Constants::DATABASE_TABLE_NAMES['attribute_mapping']:
				return array( $idp_id );
			case Constants::DATABASE_TABLE_NAMES['sso_settings']:
			case Constants::DATABASE_TABLE_NAMES['role_mapping']:
				return array( $parsed_url, $idp_id );
			default:
				return array();
		}
	}

	/**
	 * Get the data from the normalized model.
	 *
	 * @param object $normalized_model The normalized model.
	 * @param string $table_name The table name.
	 * @return mixed The data from the normalized model.
	 */
	private static function get_data_from_normalized_model( $normalized_model, $table_name ) {
		switch ( $table_name ) {
			case Constants::DATABASE_TABLE_NAMES['environments']:
				return $normalized_model->environments;
			case Constants::DATABASE_TABLE_NAMES['sp_metadata']:
				return $normalized_model->sp_metadata;
			case Constants::DATABASE_TABLE_NAMES['subsites']:
				return $normalized_model->subsites;
			case Constants::DATABASE_TABLE_NAMES['idp_details']:
				return $normalized_model->idp_details;
			case Constants::DATABASE_TABLE_NAMES['attribute_mapping']:
				return $normalized_model->attribute_mapping;
			case Constants::DATABASE_TABLE_NAMES['sso_settings']:
				return $normalized_model->sso_settings;
			case Constants::DATABASE_TABLE_NAMES['role_mapping']:
				return $normalized_model->role_mapping;
			default:
				return $normalized_model->global_options;
		}
	}

	/**
	 * Check the data instead of idp_id.
	 *
	 * @param array  $where The where conditions.
	 * @param string $table_name The table name.
	 * @return bool True if the data instead of idp_id, false otherwise.
	 */
	public static function check_data_instead_idp_id( $where, $table_name ) {
		if ( isset( $where['idp_id'] ) && Constants::DATABASE_TABLE_NAMES['idp_details'] === $table_name ) {
			return false;
		}
		return true;
	}
}
