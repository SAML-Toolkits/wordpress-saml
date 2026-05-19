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
interface Tab_Data_Handler_Interface {

	/**
	 * Save the data.
	 *
	 * @param object $data The data to save.
	 * @param array  $details Additional details required.
	 * @return void
	 */
	public function save_data( $data, $details = array() );

	/**
	 * Get the data.
	 *
	 * @param object $data The data to get.
	 * @return object The data.
	 */
	public function get_data( $data );
}
