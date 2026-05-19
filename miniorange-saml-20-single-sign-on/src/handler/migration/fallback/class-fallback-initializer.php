<?php
/**
 * Fallback Initializer.
 *
 * @package    MOSAML
 * @subpackage MOSAML/src/handler/migration/fallback
 */

namespace MOSAML\SRC\Handler\Migration\Fallback;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Handler\Migration\Fallback\Helper\Fallback_Helper;
use MOSAML\SRC\Handler\Migration\Helper\Migration_Helper;

/**
 * Fallback Initializer.
 */
class Fallback_Initializer {

	/**
	 * Initialize the fallback.
	 *
	 * @param object $handler The handler object.
	 * @param array  $where The where conditions.
	 * @return object The handler object.
	 */
	public static function initialize( $handler, $where = array() ) {
		$method_names = Fallback_Helper::get_method_name_from_table_name( $handler->get_table_name() );

		$mapper           = Migration_Helper::get_mapper();
		$normalized_model = $mapper->map( $method_names );

		return Fallback_Helper::map_data_to_handler( $normalized_model, $handler, $where );
	}
}
