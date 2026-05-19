<?php
/**
 * Logout All Sessions Data Handler file for enterprise plan.
 *
 * @package MOSAML\Module\Enterprise\Handler\Admin
 */

namespace MOSAML\Module\Base\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Constant\Constants;

/**
 * Logout All Sessions Data Handler class for enterprise plan.
 */
class Logout_All_Sessions_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Whether to force complete logout.
	 *
	 * @var string
	 */
	public $saml_force_complete_logout;

	/**
	 * Get the table name for this DTO.
	 *
	 * @return string
	 */
	public function get_table_name() {
		return Constants::DATABASE_TABLE_NAMES['sso_settings'];
	}

	/**
	 * Validate and save the logout all sessions data.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {}

	/**
	 * Get the logout all sessions data from the database.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object
	 */
	public function get_data( $where = array() ) {
		return $this;
	}
}
