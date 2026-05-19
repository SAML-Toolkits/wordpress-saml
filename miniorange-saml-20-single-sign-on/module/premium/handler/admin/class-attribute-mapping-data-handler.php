<?php
/**
 * This file contains the backend operations related to the Attribute Mapping tab for the premium module.
 *
 * @package MOSAML
 */

namespace MOSAML\Module\Premium\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Admin\Attribute_Mapping_Data_Handler as Standard_Attribute_Mapping_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Utils\Utility;

/**
 * Attribute Mapping Data Handler.
 */
class Attribute_Mapping_Data_Handler extends Standard_Attribute_Mapping_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Validate and save the data for the Attribute Mapping tab.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$selected_idp = Utility::sanitize_post_data( 'selected_idp_name' );
		if ( ! $selected_idp ) {
			Error_Success_Message::show_admin_notice( 'Something went wrong!', 'ERROR' );
			return;
		}

		$custom_attrs_keys   = Utility::sanitize_post_data( 'mo_saml_custom_attr_keys', true );
		$custom_attrs_values = Utility::sanitize_post_data( 'mo_saml_custom_attr_values', true );
		$attrs_to_display    = Utility::sanitize_post_data( 'mo_saml_show_custom_attrs', true );

		DB_Utils::delete_records(
			$this->get_table_name(),
			array(
				'idp_id' => $selected_idp,
				'custom' => true,
			),
			'AND',
			'option_name',
			array_values( $custom_attrs_keys ),
			'NOT IN',
			'AND'
		);

		foreach ( $custom_attrs_keys as $key => $value ) {
			if ( ! empty( trim( $value ) ) && ! empty( trim( $custom_attrs_values[ $key ] ) ) ) {
				DB_Utils::insert_or_update(
					$this->get_table_name(),
					array(
						'option_name'  => $value,
						'option_value' => $custom_attrs_values[ $key ],
						'idp_id'       => $selected_idp,
						'display'      => in_array( "$key", $attrs_to_display, true ),
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

		$this->do_not_update_display_name = Utility::sanitize_post_data( 'mo_saml_do_not_update_display_name' );

		parent::validate_and_save_data();
	}

	/**
	 * Get the data for the Attribute Mapping tab.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object The data for the Attribute Mapping tab.
	 */
	public function get_data( $where = array() ) {
		parent::get_data( $where );

		$where = array_merge(
			$where,
			array(
				'custom' => true,
			)
		);

		$configured_custom_attributes = DB_Utils::get_records(
			$this->get_table_name(),
			$where
		);
		if ( ! is_countable( $configured_custom_attributes ) ) {
			return $this;
		}
		foreach ( $configured_custom_attributes as $configured_custom_attribute ) {
			$this->custom_attributes[] = array(
				'name'    => $configured_custom_attribute->option_name,
				'value'   => $configured_custom_attribute->option_value,
				'display' => $configured_custom_attribute->display,
			);
		}
		return $this;
	}
}
