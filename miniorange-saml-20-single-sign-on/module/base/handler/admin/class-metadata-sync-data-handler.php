<?php
/**
 * Metadata Sync Data Handler for Base version.
 * Provides stub implementation - metadata sync functionality is not available in Base.
 *
 * @package miniorange-saml-20-single-sign-on/module/base/handler/admin
 */

namespace MOSAML\Module\Base\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Constant\Constants;

/**
 * Base Metadata Sync Data Handler.
 * Stub implementation for Base version - no actual sync functionality.
 */
class Metadata_Sync_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Environment ID.
	 *
	 * @var string
	 */
	public $environment_id;

	/**
	 * IDP ID.
	 *
	 * @var string
	 */
	public $idp_id;

	/**
	 * Enable metadata sync.
	 *
	 * @var bool
	 */
	public $sync_metadata;

	/**
	 * Metadata URL.
	 *
	 * @var string
	 */
	public $metadata_url;

	/**
	 * Sync only certificates.
	 *
	 * @var bool
	 */
	public $sync_only_certificate = 'checked';

	/**
	 * Sync interval key.
	 *
	 * @var string
	 */
	public $sync_time_interval;

	/**
	 * Save metadata sync data implementation.
	 * Does nothing in Base version.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
	}

	/**
	 * Get metadata sync data.
	 * Returns empty object in Base version.
	 *
	 * @param array $where The where clause.
	 * @param bool  $single_record Whether to return single record.
	 * @return object|array Empty object or array.
	 */
	public function get_data( $where = array(), $single_record = true ) {
		return $single_record ? $this : array();
	}

	/**
	 * Handle metadata sync from upload
	 * Does nothing in Base version.
	 *
	 * @param object $idp_data The IDP data.
	 * @return void
	 */
	public function handle_metadata_sync_from_upload( $idp_data ) {}

	/**
	 * Handle metadata sync cron - stub implementation.
	 * Does nothing in Base version.
	 *
	 * @param string $idp_id The IDP ID.
	 * @return void
	 */
	public static function handle_metadata_sync_cron( $idp_id ) {}

	/**
	 * Save the data for the metadata sync configuration.
	 *
	 * @param object $data The data to save.
	 * @param array  $details The details array.
	 * @return void
	 */
	public function save_data( $data, $details = array() ) {
		$this->environment_id = ! empty( $details['environment_url'] ) ? DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['environments'], array( 'environment_url' => $details['environment_url'] ), true )->id : DB_Utils::get_environment_details( 'id', false );
		$idp                  = null;
		if ( ! empty( $details['idp_id'] ) ) {
			$idp = 'DEFAULT' === $details['idp_id'] ? DB_Utils::get_records(
				Constants::DATABASE_TABLE_NAMES['idp_details'],
				array(
					'environment_id' => $this->environment_id,
					'idp_name'       => 'ALL IDPs',
				),
				true
			) : DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['idp_details'], array( 'idp_id' => $details['idp_id'] ), true );
		}
		$this->idp_id = ! is_null( $idp ) ? $idp->id : Utility::get_default_idp( $this->environment_id )->id;
		DB_Utils::insert_or_update(
			Constants::DATABASE_TABLE_NAMES['idp_details'],
			array(
				'sync_metadata'         => $this->sync_metadata,
				'metadata_url'          => $this->metadata_url,
				'sync_only_certificate' => $this->sync_only_certificate,
				'sync_time_interval'    => $this->sync_time_interval,
			),
			array(
				'id'             => $this->idp_id,
				'environment_id' => $this->environment_id,
			)
		);
	}
}
