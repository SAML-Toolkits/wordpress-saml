<?php
/**
 * This file contains the backend operations related to the Attribute Mapping tab for the base module.
 *
 * @package MOSAML
 */

namespace MOSAML\Module\Base\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Constant\Constants;

/**
 * Attribute Mapping Data Handler.
 */
class Attribute_Mapping_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Username attribute to be mapped.
	 *
	 * @var string
	 */
	public $user_name;

	/**
	 * Email attribute to be mapped.
	 *
	 * @var string
	 */
	public $email;

	/**
	 * First name attribute to be mapped.
	 *
	 * @var string
	 */
	public $first_name;

	/**
	 * Last name attribute to be mapped.
	 *
	 * @var string
	 */
	public $last_name;

	/**
	 * Display name attribute to be mapped.
	 *
	 * @var string
	 */
	public $display_name;

	/**
	 * Nickname attribute to be mapped.
	 *
	 * @var string
	 */
	public $nick_name;

	/**
	 * Do not update display name flag.
	 *
	 * @var string
	 */
	public $do_not_update_display_name;

	/**
	 * Custom attributes to be mapped.
	 *
	 * @var array
	 */
	public $custom_attributes = array();


	/**
	 * Save the data for the Attribute Mapping tab.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$selected_idp = Utility::sanitize_post_data( 'selected_idp_name' );
		if ( empty( $selected_idp ) ) {
			Error_Success_Message::show_admin_notice( 'Something went wrong!', 'ERROR' );
			return;
		}

		$this->user_name = Utility::sanitize_post_data( 'mo_saml_user_name' );
		$this->email     = Utility::sanitize_post_data( 'mo_saml_email' );

		if ( empty( $this->user_name ) || empty( $this->email ) ) {
			Error_Success_Message::show_admin_notice( 'Please provide a valid value for username and email.', 'ERROR' );
			return;
		}

		foreach ( get_object_vars( $this ) as $option_name => $option_value ) {
			if ( 'custom_attributes' === $option_name ) {
				continue;
			}

			DB_Utils::insert_or_update(
				$this->get_table_name(),
				array(
					'option_name'  => $option_name,
					'option_value' => $option_value,
					'custom'       => 0,
					'idp_id'       => $selected_idp,
					'display'      => 0,
				),
				array(
					'option_name' => $option_name,
					'idp_id'      => $selected_idp,
					'custom'      => 0,
				)
			);
		}

		Error_Success_Message::show_admin_notice( 'Attribute mapping saved successfully.', 'SUCCESS' );
	}

	/**
	 * Get the data for the Attribute/role mapping tab.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object The data.
	 */
	public function get_data( $where = array() ) {
		if ( Utility::is_legacy_data_fallback_required() ) {
			return apply_filters( 'mosaml_legacy_data_fallback_object', $this, $where );
		}
		return $this;
	}

	/**
	 * Get the table name for the Attribute Mapping tab.
	 *
	 * @return string The table name.
	 */
	public function get_table_name() {
		return Constants::DATABASE_TABLE_NAMES['attribute_mapping'];
	}

	/**
	 * Delete the data for the Attribute Mapping tab.
	 *
	 * @return void
	 */
	public function delete_data() {
		$selected_idp = Utility::sanitize_post_data( 'selected_idp_name' );
		if ( empty( $selected_idp ) ) {
			return;
		}
		DB_Utils::delete_records(
			$this->get_table_name(),
			array(
				'idp_id' => $selected_idp,
			)
		);
		Error_Success_Message::show_admin_notice( 'Attribute Mapping Configurations reset successfully.', 'SUCCESS' );
	}

	/**
	 * Save the data for the Attribute Mapping tab.
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

		foreach ( get_object_vars( $this ) as $option_name => $option_value ) {
			if ( empty( $option_value ) || 'custom_attributes' === $option_name ) {
				continue;
			}
			DB_Utils::insert_or_update(
				$this->get_table_name(),
				array(
					'option_name'  => $option_name,
					'option_value' => $option_value,
					'custom'       => 0,
					'idp_id'       => $selected_idp,
					'display'      => 0,
				),
				array(
					'option_name' => $option_name,
					'idp_id'      => $selected_idp,
					'custom'      => 0,
				)
			);
		}

		$custom_attrs_keys   = ! empty( $this->custom_attributes['mosaml_custom_attr_keys'] ) ? $this->custom_attributes['mosaml_custom_attr_keys'] : array();
		$custom_attrs_values = ! empty( $this->custom_attributes['mosaml_custom_attr_values'] ) ? $this->custom_attributes['mosaml_custom_attr_values'] : array();
		$attrs_to_display    = ! empty( $this->custom_attributes['mosaml_show_custom_attrs'] ) ? $this->custom_attributes['mosaml_show_custom_attrs'] : array();

		if ( ! empty( $custom_attrs_keys ) && is_array( $custom_attrs_keys ) ) {
			foreach ( $custom_attrs_keys as $key => $value ) {
				if ( empty( $custom_attrs_values[ $key ] ) ) {
					continue;
				}
				if ( ! empty( trim( $value ) ) && ! empty( trim( $custom_attrs_values[ $key ] ) ) ) {
					DB_Utils::insert_or_update(
						$this->get_table_name(),
						array(
							'option_name'  => $value,
							'option_value' => $custom_attrs_values[ $key ],
							'idp_id'       => $selected_idp,
							'display'      => is_array( $attrs_to_display ) && in_array( $key, $attrs_to_display, true ),
							'custom'       => true,
						),
						array(
							'option_name' => $value,
							'idp_id'      => $selected_idp,
							'custom'      => true,
						)
					);
				}
			}
		}
	}
}
