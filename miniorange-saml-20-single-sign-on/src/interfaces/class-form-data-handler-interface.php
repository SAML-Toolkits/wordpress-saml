<?php
/**
 * Base Admin Handler.
 *
 * @package miniorange-saml-20-single-sign-on/interface
 */

namespace MOSAML\SRC\Interfaces;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Base Admin Handler which should be implemented by all admin handlers.
 */
interface Form_Data_Handler_Interface {

	/**
	 * Validate and save the data.
	 *
	 * @return void
	 */
	public function validate_and_save_data();

	/**
	 * Get the data.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object The data.
	 */
	public function get_data( $where = array() );
}
