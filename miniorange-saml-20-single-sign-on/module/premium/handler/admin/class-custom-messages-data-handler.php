<?php
/**
 * Custom Messages Data Handler - Premium Module
 *
 * Extends the standard custom messages data handler to provide premium module functionality.
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Premium\Handler\Admin
 */

namespace MOSAML\Module\Premium\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Admin\Custom_Messages_Data_Handler as Standard_Custom_Messages_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Utils\Utility;

/**
 * Custom Messages Data Handler.
 */
class Custom_Messages_Data_Handler extends Standard_Custom_Messages_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Validate and save the custom messages configuration.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$this->account_creation_disabled_msg = Utility::sanitize_post_data( 'mo_saml_account_creation_disabled_msg' );
		$this->restricted_domain_error_msg   = Utility::sanitize_post_data( 'mo_saml_restricted_domain_error_msg' );

		$fields_to_save = array(
			'account_creation_disabled_msg',
			'restricted_domain_error_msg',
		);

		$selected_environment_id   = DB_Utils::get_environment_details( 'id', false );
		$blog_id_for_environment = Utility::get_subsite_id_for_environment( $selected_environment_id );
		$default_idp_id            = DB_Utils::get_default_inserted_idp_details( 'id', $selected_environment_id );

		foreach ( $fields_to_save as $field_name ) {
			$table_data = array(
				'option_name'  => $field_name,
				'option_value' => $this->{$field_name},
				'idp_id'       => $default_idp_id,
				'subsite_id'   => $blog_id_for_environment,
			);
			DB_Utils::insert_or_update(
				$this->get_table_name(),
				$table_data,
				array(
					'option_name' => $field_name,
					'idp_id'      => $default_idp_id,
					'subsite_id'  => $blog_id_for_environment,
				)
			);
		}
		Error_Success_Message::show_admin_notice( 'Configuration has been saved successfully.', 'SUCCESS' );
	}

	/**
	 * Get the custom messages configuration.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object
	 */
	public function get_data( $where = array() ) {
		$record = DB_Utils::get_records( $this->get_table_name(), $where );
		if ( is_array( $record ) && ! empty( $record ) ) {
			foreach ( $record as $record_item ) {
				$this->{$record_item->option_name} = $record_item->option_value;
			}
		} else {
			$this->account_creation_disabled_msg = '';
			$this->restricted_domain_error_msg   = '';
		}
		return $this;
	}
}
