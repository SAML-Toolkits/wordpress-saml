<?php
/**
 * Multiple Environments Data Handler
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\Module\Base\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Constant\Constants;

/**
 * Multiple Environments Data Handler.
 */
class Multiple_Environments_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * ID.
	 *
	 * @var int
	 */
	public $id;

	/**
	 * Environment Name.
	 *
	 * @var string
	 */
	public $environment_name;

	/**
	 * Environment URL.
	 *
	 * @var string
	 */
	public $environment_url;

	/**
	 * Environment Selected.
	 *
	 * @var int
	 */
	public $selected;

	/**
	 * Get the table name for this handler.
	 *
	 * @return string
	 */
	public function get_table_name() {
		return Constants::DATABASE_TABLE_NAMES['environments'];
	}

	/**
	 * Validate and save the data.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {}

	/**
	 * Change the environment.
	 *
	 * @return void
	 */
	public function change_environment() {}

	/**
	 * Get the data from the database.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return array
	 */
	public function get_data( $where = array() ) {
		return DB_Utils::get_records( $this->get_table_name(), $where );
	}

	/**
	 * Save the data.
	 *
	 * @param object $data The data to save.
	 * @param array  $details The details array.
	 * @return void
	 */
	public function save_data( $data, $details = array() ) {
		$environment = ! empty( $details['environment_url'] ) ? DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['environments'], array( 'environment_url' => $details['environment_url'] ), true ) : null;

		$result = DB_Utils::insert_or_update(
			$this->get_table_name(),
			array(
				'environment_name' => $details['environment_name'],
				'environment_url'  => $details['environment_url'],
			),
			array(
				'environment_url' => $details['environment_url'],
			),
			'AND',
			true
		);

		if ( $result && is_null( $environment ) ) {
			DB_Utils::initialize_sp_metadata_table( $result, $details['environment_url'] );
			DB_Utils::initialize_idp_details_table( $result );
			DB_Utils::initialize_subsites_table( $result, Constants::DEFAULT_BLOG_ID, $details['environment_url'] );
			DB_Utils::initialize_attribute_mapping_table( $result );
		}
	}
}
