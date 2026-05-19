<?php
/**
 * Account Info Data Handler - Base Module
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Base\Handler\Admin
 */

namespace MOSAML\Module\Base\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Account Info Data Handler - Base Module
 */
class Account_Info_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Validate and save the account info configuration.
	 *
	 * @return boolean
	 */
	public function validate_and_save_data() {
		return true;
	}

	/**
	 * Get the account info data.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object The data.
	 */
	public function get_data( $where = array() ) {
		return $this;
	}
}
