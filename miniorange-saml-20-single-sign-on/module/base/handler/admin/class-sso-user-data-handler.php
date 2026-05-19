<?php
/**
 * SSO User Data Handler - Base Module
 *
 * Handles data operations for SSO user display configuration in the base module.
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
 * SSO User Data Handler.
 */
class SSO_User_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Whether to show SSO user in WordPress user section.
	 *
	 * @var string
	 */
	public $sso_show_user;


	/**
	 * Get the table name for this DTO.
	 *
	 * @return string
	 */
	public function get_table_name() {
		return Constants::DATABASE_TABLE_NAMES['sso_settings'];
	}

	/**
	 * Validate and save the SSO user configuration.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {}

	/**
	 * Get the SSO user configuration.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object The data.
	 */
	public function get_data( $where = array() ) {
		return $this;
	}

	/**
	 * Save the data for the SSO user configuration.
	 *
	 * @param object $data The data to save.
	 * @param array  $details The details array.
	 * @return void
	 */
	public function save_data( $data, $details = array() ) {

		$selected_environment_id = ! empty( $details['environment_url'] ) ? DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['environments'], array( 'environment_url' => $details['environment_url'] ), true )->id : DB_Utils::get_environment_details( 'id', false );
		$idp_id                  = DB_Utils::get_default_inserted_idp_details( 'id', $selected_environment_id );
		if ( empty( $this->sso_show_user ) ) {
			return;
		}
		DB_Utils::insert_or_update(
			$this->get_table_name(),
			array(
				'option_name'  => 'sso_show_user',
				'option_value' => $this->sso_show_user,
				'idp_id'       => $idp_id,
				'subsite_id'   => Utility::get_subsite_id_for_environment( $selected_environment_id ),
			),
			array(
				'option_name' => 'sso_show_user',
				'idp_id'      => $idp_id,
				'subsite_id'  => Utility::get_subsite_id_for_environment( $selected_environment_id ),
			)
		);
	}
}
