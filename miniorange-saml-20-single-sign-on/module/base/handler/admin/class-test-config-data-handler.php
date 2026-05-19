<?php
/**
 * This file contains the class to handle the test configuration data.
 *
 * @package miniorange-saml-20-single-sign-on/handler/admin
 */

namespace MOSAML\Module\Base\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Constant\Constants;

/**
 * Test Config Data Handler.
 */
class Test_Config_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Validate and save the test configuration data.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$details = json_decode( Utility::sanitize_post_data( 'details' ), true );

		if ( ! is_array( $details ) || empty( $details ) ) {
			return;
		}

		if ( ! isset( $details['idp_id'] ) || empty( $details['idp_id'] ) ) {
			return;
		}

		$result = DB_Utils::insert_or_update(
			$this->get_table_name(),
			$details,
			array(
				'environment_id' => DB_Utils::get_environment_details( 'id' ),
				'idp_id'         => $details['idp_id'],
			)
		);

		if ( $result ) {
			$test_url = Utility::get_test_config_url( $details['idp_id'] );
			wp_safe_redirect( $test_url );
			exit;
		}
	}

	/**
	 * Get the test configuration data.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return void
	 */
	public function get_data( $where = array() ) {}

	/**
	 * Get the table name.
	 *
	 * @return string
	 */
	protected function get_table_name() {
		return Constants::DATABASE_TABLE_NAMES['idp_details'];
	}

	/**
	 * Load all stored test configuration attribute sets for the current environment.
	 *
	 * Performs a single query for all IdP rows, then filters rows with non-empty
	 * `test_config_attributes`. Keys are IdP `idp_id` strings to match the legacy
	 * `mo_saml_test_config_attrs` option shape.
	 *
	 * @return array<string, array<string, mixed>> Map of idp_id => decoded attribute map.
	 */
	public static function get_all_test_configs() {
		if ( Utility::is_legacy_data_fallback_required() ) {
			return array();
		}

		$environment_id = DB_Utils::get_environment_details( 'id', true );
		if ( '' === $environment_id || null === $environment_id ) {
			return array();
		}

		$rows = DB_Utils::get_records(
			Constants::DATABASE_TABLE_NAMES['idp_details'],
			array( 'environment_id' => $environment_id )
		);

		if ( empty( $rows ) || ! is_array( $rows ) ) {
			return array();
		}

		$out = array();
		foreach ( $rows as $row ) {
			$attrs = self::decode_test_config_attributes_from_row( $row );
			if ( null === $attrs ) {
				continue;
			}
			$out[ (string) $row->idp_id ] = $attrs;
		}

		return $out;
	}

	/**
	 * Returns decoded test config attributes for a row, or null when the row should be skipped.
	 *
	 * @param mixed $row Database row object.
	 * @return array<string, mixed>|null
	 */
	private static function decode_test_config_attributes_from_row( $row ) {
		if ( ! is_object( $row ) ) {
			return null;
		}
		if ( isset( $row->idp_name ) && 'All IDPs' === $row->idp_name ) {
			return null;
		}
		if ( empty( $row->test_config_attributes ) ) {
			return null;
		}
		if ( ! isset( $row->idp_id ) || '' === $row->idp_id ) {
			return null;
		}

		return self::normalize_stored_test_config_attributes( $row->test_config_attributes );
	}

	/**
	 * Unserializes stored test attributes and, when still a non-empty string, tries JSON decode.
	 *
	 * @param mixed $raw Value from `test_config_attributes` column.
	 * @return array<string, mixed>|null Non-empty array, or null if not usable.
	 */
	private static function normalize_stored_test_config_attributes( $raw ) {
		$attrs = maybe_unserialize( $raw );
		if ( is_string( $attrs ) && '' !== $attrs ) {
			$decoded = json_decode( $attrs, true );
			if ( is_array( $decoded ) ) {
				$attrs = $decoded;
			}
		}

		return ( is_array( $attrs ) && ! empty( $attrs ) ) ? $attrs : null;
	}
}
