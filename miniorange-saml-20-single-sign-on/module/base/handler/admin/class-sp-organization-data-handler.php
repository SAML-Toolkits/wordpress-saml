<?php
/**
 * This file includes the save and get function for SP Organization as per the base plan.
 *
 * @package MOSAML\Module\Base\Handler\Admin
 */

namespace MOSAML\Module\Base\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Utils\DB_Utils;

/**
 * SP Organization Data Handler.
 */
class SP_Organization_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Organization name.
	 *
	 * @var string
	 */
	public $organization_name;

	/**
	 * Organization display name.
	 *
	 * @var string
	 */
	public $organization_display_name;

	/**
	 * Organization URL.
	 *
	 * @var string
	 */
	public $organization_url;

	/**
	 * Technical person name.
	 *
	 * @var string
	 */
	public $technical_person_name;

	/**
	 * Technical person email.
	 *
	 * @var string
	 */
	public $technical_person_email;

	/**
	 * Support person name.
	 *
	 * @var string
	 */
	public $support_person_name;

	/**
	 * Support person email.
	 *
	 * @var string
	 */
	public $support_person_email;

	/**
	 * Constructor to initialize the default values.
	 */
	public function __construct() {
		$this->organization_name         = Constants::DEFAULT_ORGANIZATION_DETAILS['name'];
		$this->organization_display_name = Constants::DEFAULT_ORGANIZATION_DETAILS['name'];
		$this->organization_url          = Constants::DEFAULT_ORGANIZATION_DETAILS['url'];
		$this->technical_person_name     = Constants::DEFAULT_ORGANIZATION_DETAILS['name'];
		$this->technical_person_email    = Constants::DEFAULT_ORGANIZATION_DETAILS['email'];
		$this->support_person_name       = Constants::DEFAULT_ORGANIZATION_DETAILS['name'];
		$this->support_person_email      = Constants::DEFAULT_ORGANIZATION_DETAILS['email'];
	}

	/**
	 * Get the table name.
	 *
	 * @return string The table name.
	 */
	public function get_table_name() {
		return Constants::DATABASE_TABLE_NAMES['sp_metadata'];
	}

	/**
	 * Validate and save the sp organization data.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {}

	/**
	 * Get the sp organization data.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object The data.
	 */
	public function get_data( $where = array() ) {
		return $this;
	}

	/**
	 * Save the sp organization data.
	 *
	 * @param object $data The data to save.
	 * @param array  $details The details array.
	 * @return void
	 */
	public function save_data( $data, $details = array() ) {
		$environment_id = ! empty( $details['environment_url'] ) ? DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['environments'], array( 'environment_url' => $details['environment_url'] ), true )->id : DB_Utils::get_environment_details( 'id', false );

		DB_Utils::insert_or_update(
			$this->get_table_name(),
			get_object_vars( $data ),
			array(
				'environment_id' => $environment_id,
			)
		);
	}
}
