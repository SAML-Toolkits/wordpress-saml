<?php
/**
 * SP Endpoints Data Handler file.
 *
 * @package MOSAML\Module\Base\Handler\Admin
 */

namespace MOSAML\Module\Base\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Constant\Constants;

/**
 * SP Endpoints Data Handler class.
 *
 * This class handles the data for the SP endpoints.
 *
 * @package MOSAML\Module\Base\Handler\Admin
 */
class SP_Endpoints_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * SP Base URL.
	 *
	 * @var string
	 */
	public $sp_base_url;

	/**
	 * SP Entity ID.
	 *
	 * @var string
	 */
	public $sp_entity_id;

	/**
	 * Get the table name.
	 *
	 * @return string
	 */
	public function get_table_name() {
		return Constants::DATABASE_TABLE_NAMES['sp_metadata'];
	}

	/**
	 * Validate and save the sp endpoints data.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {

        // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.MissingUnslash,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Nonce Verification is done from mo_check_option_admin_referer function.
		$this->sp_entity_id = ! empty( $_POST['mo_saml_sp_entity_id'] ) ? Utility::sanitize_post_data( 'mo_saml_sp_entity_id' ) : '';

		if ( empty( $this->sp_entity_id ) ) {
			Error_Success_Message::show_admin_notice( 'Please enter a valid SP Base URL or SP Entity ID/Issuer.' );
			return;
		}

		$insert_data                   = get_object_vars( $this );
		$insert_data['environment_id'] = ! empty( $insert_data['environment_id'] ) ? $insert_data['environment_id'] : DB_Utils::get_environment_details( 'id', false );

		$where = array(
			'environment_id' => $insert_data['environment_id'],
		);

		$query_result = DB_Utils::insert_or_update( $this->get_table_name(), $insert_data, $where );

		if ( 'ENTERPRISE' !== Constants::VERSION_HIERARCHY[ MOSAML_VERSION ] ) {
			$idps = DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['idp_details'], $where );

			if ( ! empty( $idps ) && is_array( $idps ) ) {
				foreach ( $idps as $idp ) {
					$idp_update_data = array(
						'sp_entity_id' => $this->sp_entity_id,
					);

					$idp_where = array(
						'id'             => $idp->id,
						'environment_id' => $insert_data['environment_id'],
					);
					DB_Utils::insert_or_update( Constants::DATABASE_TABLE_NAMES['idp_details'], $idp_update_data, $idp_where );
				}
			}
		}

		$success_msg  = 'Service Provider Endpoints saved successfully. ';
		$success_msg .= Error_Success_Message::get_sp_metadata_view_link_for_notice();
		Error_Success_Message::show_admin_notice( $success_msg, 'SUCCESS' );
		return $query_result;
	}

	/**
	 * Get the sp endpoints data from the database.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object
	 */
	public function get_data( $where = array() ) {
		if ( Utility::is_legacy_data_fallback_required() ) {
			$self_object        = apply_filters( 'mosaml_legacy_data_fallback_object', $this, $where );
			$this->sp_base_url  = $self_object->sp_base_url ? $self_object->sp_base_url : site_url();
			$this->sp_entity_id = $self_object->sp_entity_id ? $self_object->sp_entity_id : site_url() . '/wp-content/plugins/miniorange-saml-20-single-sign-on/';
		} else {
			$record = DB_Utils::get_records( $this->get_table_name(), $where, true );
			if ( $record ) {
				$values_to_be_set = (array) $record;
				foreach ( $values_to_be_set as $column => $value ) {
					if ( property_exists( $this, $column ) && null !== $value && '' !== $value ) {
						$this->$column = $value;
					}
				}
			}
		}
		$current_environment_id = DB_Utils::get_environment_details( 'id', true );
		$current_environment    = false;
		if ( isset( $where['environment_id'] ) && $current_environment_id === $where['environment_id'] ) {
			$current_environment = true;
		}

		if ( empty( $this->sp_base_url ) ) {
			$this->sp_base_url = DB_Utils::get_sp_details( 'sp_base_url', $current_environment );
		}
		if ( empty( $this->sp_entity_id ) ) {
			$this->sp_entity_id = DB_Utils::get_sp_details( 'sp_entity_id', $current_environment );
			if ( ! preg_match( '/^https?:\/\//i', $this->sp_entity_id ) ) {
				$scheme             = Utility::mo_saml_is_ssl() ? 'https://' : 'http://';
				$this->sp_entity_id = $scheme . ltrim( $this->sp_entity_id, '/' );
			}
		}
		return $this;
	}

	/**
	 * Save the sp endpoints data.
	 *
	 * @param object $data The data to save.
	 * @param array  $details The details array.
	 * @return void
	 */
	public function save_data( $data, $details = array() ) {

		$environment_id                   = ! empty( $details['environment_url'] ) ? DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['environments'], array( 'environment_url' => $details['environment_url'] ), true )->id : DB_Utils::get_environment_details( 'id', false );
		$data_to_insert                   = get_object_vars( $data );
		$data_to_insert['environment_id'] = ! empty( $data_to_insert['environment_id'] ) ? $data_to_insert['environment_id'] : $environment_id;
		$where                            = array(
			'environment_id' => $data_to_insert['environment_id'],
		);
		DB_Utils::insert_or_update( $this->get_table_name(), $data_to_insert, $where );
	}
}
