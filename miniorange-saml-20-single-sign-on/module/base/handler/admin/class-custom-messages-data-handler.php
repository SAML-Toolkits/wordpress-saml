<?php
/**
 * Custom Messages Data Handler - Base Module
 *
 * Handles data operations for custom messages configuration in the base module.
 *
 * PHP Compatibility: 5.6+
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Base\Handler\Admin
 */

namespace MOSAML\Module\Base\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Utility;

/**
 * Custom Messages Data Handler.
 */
class Custom_Messages_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Account creation disabled message.
	 *
	 * @var string
	 */
	public $account_creation_disabled_msg = Constants::ACCOUNT_CREATION_DISABLED_MSG;

	/**
	 * Restricted domain error message.
	 *
	 * @var string
	 */
	public $restricted_domain_error_msg = Constants::RESTRICTED_DOMAIN_ERROR_MSG;

	/**
	 * Get the table name for this DTO.
	 *
	 * @return string
	 */
	public function get_table_name() {
		return Constants::DATABASE_TABLE_NAMES['sso_settings'];
	}

	/**
	 * Validate and save the custom messages configuration.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
	}

	/**
	 * Get the custom messages configuration.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object The data.
	 */
	public function get_data( $where = array() ) {
		return $this;
	}

	/**
	 * Save the data for the custom messages configuration.
	 *
	 * @param object $data The data to save.
	 * @param array  $details The details array.
	 * @return void
	 */
	public function save_data( $data, $details = array() ) {

		$selected_environment_id = ! empty( $details['environment_url'] ) ? DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['environments'], array( 'environment_url' => $details['environment_url'] ), true )->id : DB_Utils::get_environment_details( 'id', false );
		$blog_id_for_environment = Utility::get_subsite_id_for_environment( $selected_environment_id );
		$idp_id                  = DB_Utils::get_default_inserted_idp_details( 'id', $selected_environment_id );
		foreach ( get_object_vars( $data ) as $option_name => $option_value ) {
			if ( empty( $option_value ) ) {
				continue;
			}
			DB_Utils::insert_or_update(
				$this->get_table_name(),
				array(
					'option_name'  => $option_name,
					'option_value' => $option_value,
					'idp_id'       => $idp_id,
					'subsite_id'   => $blog_id_for_environment,
				),
				array(
					'option_name' => $option_name,
					'idp_id'      => $idp_id,
					'subsite_id'  => $blog_id_for_environment,
				)
			);
		}
	}
}
