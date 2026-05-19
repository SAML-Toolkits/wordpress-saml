<?php
/**
 * This file contains the backend operations related to the Attribute Mapping tab for the standard module.
 *
 * @package MOSAML
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Admin\Attribute_Mapping_Data_Handler as Base_Attribute_Mapping_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Utils\Utility;

/**
 * Attribute Mapping Handler.
 */
class Attribute_Mapping_Data_Handler extends Base_Attribute_Mapping_Data_Handler implements Form_Data_Handler_Interface {


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

		$this->first_name                 = Utility::sanitize_post_data( 'mo_saml_first_name' );
		$this->last_name                  = Utility::sanitize_post_data( 'mo_saml_last_name' );
		$this->display_name               = Utility::sanitize_post_data( 'mo_saml_display_name' );
		$this->do_not_update_display_name = Utility::sanitize_post_data( 'mo_saml_do_not_update_display_name' );
		$this->nick_name                  = Utility::sanitize_post_data( 'mo_saml_nick_name' );

		parent::validate_and_save_data();
	}

	/**
	 * Get the data for the Attribute/role mapping tab.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object The data.
	 */
	public function get_data( $where = array() ) {
		parent::get_data( $where );

		$where = array_merge(
			$where,
			array(
				'custom' => false,
			)
		);

		$configured_user_attributes = DB_Utils::get_records(
			$this->get_table_name(),
			$where
		);
		if ( ! is_countable( $configured_user_attributes ) ) {
			return $this;
		}
		foreach ( $configured_user_attributes as $configured_user_attribute ) {
			if ( property_exists( $this, $configured_user_attribute->option_name ) ) {
				$this->{$configured_user_attribute->option_name} = $configured_user_attribute->option_value;
			}
		}
		return $this;
	}
}
