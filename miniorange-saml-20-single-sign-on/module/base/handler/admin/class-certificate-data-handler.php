<?php
/**
 * Custom Certificate Handler file.
 *
 * @package MOSAML\Module\Base\Handler\Admin
 */

namespace MOSAML\Module\Base\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\Utility;

/**
 * Custom Certificate Handler class.
 *
 * This class handles the data for the custom certificate.
 *
 * @package MOSAML\Module\Base\Handler\Admin
 */
class Certificate_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Public key.
	 *
	 * @var string
	 */
	public $public_key;

	/**
	 * Private key.
	 *
	 * @var string
	 */
	public $private_key;

	/**
	 * Is custom certificate.
	 *
	 * @var string
	 */
	public $is_custom_certificate;

	/**
	 * Constructor to initialize the object variables.
	 */
	public function __construct() {
		$this->is_custom_certificate = 0;
	}

	/**
	 * Get the table name.
	 *
	 * @return string
	 */
	public function get_table_name() {
		return Constants::DATABASE_TABLE_NAMES['sp_metadata'];
	}

	/**
	 * Validate and save the custom certificate data.
	 *
	 * @return int|false
	 */
	public function validate_and_save_data() {
		if ( empty( $this->public_key ) || empty( $this->private_key ) ) {
			return;
		}

		$insert_data = get_object_vars( $this );

		$where = array(
			'environment_id' => DB_Utils::get_environment_details( 'id', false ),
		);

		if ( empty( DB_Utils::get_records( $this->get_table_name(), $where, true ) ) ) {
			$insert_data['sp_entity_id']   = site_url() . Constants::SP_ENTITY_ID;
			$insert_data['sp_base_url']    = site_url();
			$insert_data['environment_id'] = DB_Utils::get_environment_details( 'id', false );
		}

		$is_reset = 'Reset' === Utility::sanitize_post_data( 'submit' ) ? true : false;

		$query_result = DB_Utils::insert_or_update( $this->get_table_name(), $insert_data, $where );

		if ( $query_result ) {
			if ( $is_reset ) {
				Error_Success_Message::show_admin_notice( 'Reset Certificate successfully.', 'SUCCESS' );
			} else {
				Error_Success_Message::show_admin_notice( 'Custom Certificate updated successfully.', 'SUCCESS' );
			}
		}

		return $query_result;
	}

	/**
	 * Get the custom certificate data from the database.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object
	 */
	public function get_data( $where = array() ) {
		$where = array_merge( $where, array( 'environment_id' => DB_Utils::get_environment_details( 'id', false ) ) );

		$record = DB_Utils::get_records( $this->get_table_name(), $where, true );
		if ( $record ) {
			$values_to_be_set = (array) $record;
			foreach ( $values_to_be_set as $column => $value ) {
				if ( property_exists( $this, $column ) && null !== $value && '' !== $value ) {
					$this->$column = $value;
				}
			}
		}

		return $this;
	}

	/**
	 * Upgrade the new certificate.
	 *
	 * @return void
	 */
	public function upgrade_new_certificate() {
		$new_certificate_file = MOSAML_PLUGIN_DIR . 'resource' . DIRECTORY_SEPARATOR . \MOSAML\SRC\Constant\Constants::NEW_SP_CERT_FILE_NAME;
		$new_private_key_file = MOSAML_PLUGIN_DIR . 'resource' . DIRECTORY_SEPARATOR . \MOSAML\SRC\Constant\Constants::NEW_SP_PRIVATE_KEY_FILE_NAME;

		if ( ! file_exists( $new_certificate_file ) && ! file_exists( $new_private_key_file ) ) {
			Error_Success_Message::show_admin_notice( 'New certificate file or private key file not found.', 'ERROR' );
			return;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading a local plugin resource file.
		$new_certificate = file_get_contents( $new_certificate_file );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading a local plugin resource file.
		$new_private_key = file_get_contents( $new_private_key_file );

		$selected_idp_id = Utility::sanitize_post_data( 'selected_idp_id' );
		if ( 'All IDPs' === $selected_idp_id ) {
			DB_Utils::insert_or_update(
				Constants::DATABASE_TABLE_NAMES['sp_metadata'],
				array(
					'environment_id'        => DB_Utils::get_environment_details( 'id', false ),
					'public_key'            => $new_certificate,
					'private_key'           => $new_private_key,
					'is_custom_certificate' => 0,
				),
				array(
					'environment_id' => DB_Utils::get_environment_details( 'id', false ),
				)
			);
		} else {
			DB_Utils::insert_or_update(
				Constants::DATABASE_TABLE_NAMES['sp_metadata'],
				array(
					'environment_id'        => DB_Utils::get_environment_details( 'id', false ),
					'public_key'            => $new_certificate,
					'private_key'           => $new_private_key,
					'is_custom_certificate' => 0,
				),
				array(
					'environment_id' => DB_Utils::get_environment_details( 'id', false ),
				)
			);

			DB_Utils::insert_or_update(
				Constants::DATABASE_TABLE_NAMES['idp_details'],
				array(
					'sp_certificate' => $new_certificate,
					'sp_private_key' => $new_private_key,
				),
				array(
					'idp_id' => $selected_idp_id,
				)
			);
		}
		Error_Success_Message::show_admin_notice( 'Certificate upgraded successfully.', 'SUCCESS' );
	}

	/**
	 * Save the data for the certificate.
	 *
	 * @param object $data The data to save.
	 * @param array  $details The details array.
	 * @return void
	 */
	public function save_data( $data, $details = array() ) {
		$selected_environment_id = ! empty( $details['environment_url'] ) ? DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['environments'], array( 'environment_url' => $details['environment_url'] ), true )->id : DB_Utils::get_environment_details( 'id', false );
		$idp                     = null;
		if ( ! empty( $details['idp_id'] ) ) {
			$idp = 'DEFAULT' === $details['idp_id'] ? DB_Utils::get_records(
				Constants::DATABASE_TABLE_NAMES['idp_details'],
				array(
					'environment_id' => $selected_environment_id,
					'idp_name'       => 'ALL IDPs',
				),
				true
			) : DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['idp_details'], array( 'idp_id' => $details['idp_id'] ), true );
		}
		$selected_idp = ! is_null( $idp ) ? $idp->id : Utility::get_default_idp( $selected_environment_id )->id;

		if ( empty( $this->public_key ) || empty( $this->private_key ) ) {
			return;
		}
		DB_Utils::insert_or_update(
			Constants::DATABASE_TABLE_NAMES['sp_metadata'],
			array(
				'public_key'            => $this->public_key,
				'private_key'           => $this->private_key,
				'is_custom_certificate' => 1,
			),
			array(
				'environment_id' => $selected_environment_id,
			)
		);
		DB_Utils::insert_or_update(
			Constants::DATABASE_TABLE_NAMES['idp_details'],
			array(
				'sp_certificate' => $this->public_key,
				'sp_private_key' => $this->private_key,
			),
			array(
				'id'             => $selected_idp,
				'environment_id' => $selected_environment_id,
			)
		);
	}
}
