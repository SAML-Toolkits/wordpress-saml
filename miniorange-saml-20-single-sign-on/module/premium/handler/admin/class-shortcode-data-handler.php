<?php
/**
 * Shortcode Data Handler - Premium Module
 *
 * Extends the standard shortcode data handler to provide premium module functionality.
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Premium\Handler\Admin
 */

namespace MOSAML\Module\Premium\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Admin\Shortcode_Data_Handler as Standard_Shortcode_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\DB_Utils;

/**
 * Shortcode Data Handler.
 */
class Shortcode_Data_Handler extends Standard_Shortcode_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Get the shortcode configuration.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object
	 */
	public function get_data( $where = array() ) {
		$record = DB_Utils::get_records( $this->get_table_name(), $where, true );
		if ( $record ) {
			$this->{ $record->option_name } = $record->option_value;
		}
		return $this;
	}
}
