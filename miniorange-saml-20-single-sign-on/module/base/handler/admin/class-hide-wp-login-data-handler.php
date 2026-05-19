<?php
/**
 * Hide WP Login Data Handler - Base Module
 *
 * Handles data operations for hide WordPress login configuration in the base module.
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
 * Hide WP Login Data Handler.
 */
class Hide_WP_Login_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Hide WordPress login checkbox value.
	 *
	 * @var string
	 */
	public $hide_wp_login;

	/**
	 * Get the table name for this DTO.
	 *
	 * @return string
	 */
	public function get_table_name() {
		return Constants::DATABASE_TABLE_NAMES['sso_settings'];
	}

	/**
	 * Validate and save the hide WP login configuration.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
	}

	/**
	 * Get the hide WP login configuration.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object The data.
	 */
	public function get_data( $where = array() ) {
		return $this;
	}

	/**
	 * Save the hide WP login configuration.
	 *
	 * @param object $data The data to save.
	 * @param array  $details The details array.
	 * @return void
	 */
	public function save_data( $data, $details = array() ) {

		$selected_environment_id = ! empty( $details['environment_url'] ) ? DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['environments'], array( 'environment_url' => $details['environment_url'] ), true )->id : DB_Utils::get_environment_details( 'id', false );
		$blog_id_for_environment = Utility::get_subsite_id_for_environment( $selected_environment_id );
		$idp_id                  = DB_Utils::get_default_inserted_idp_details( 'id', $selected_environment_id );
		if ( empty( $this->hide_wp_login ) ) {
			return;
		}
		$table_data = array(
			'option_name'  => 'hide_wp_login',
			'option_value' => $this->hide_wp_login,
			'idp_id'       => $idp_id,
			'subsite_id'   => $blog_id_for_environment,
		);

		DB_Utils::insert_or_update(
			$this->get_table_name(),
			$table_data,
			array(
				'option_name' => 'hide_wp_login',
				'idp_id'      => $idp_id,
				'subsite_id'  => $blog_id_for_environment,
			)
		);
	}
}
