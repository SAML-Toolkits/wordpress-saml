<?php
/**
 * Legacy Version Mapper.
 *
 * @package    MOSAML
 * @subpackage MOSAML/src/handler/migration/mapper
 */

namespace MOSAML\SRC\Handler\Migration\Mapper;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Legacy Version Mapper Interface.
 */
interface Legacy_Version_Mapper {
	/**
	 * Map the legacy version.
	 *
	 * @param array $methods The methods to map.
	 * @return object Normalized Migration Model.
	 * @throws \InvalidArgumentException If the method does not exist.
	 */
	public function map( $methods = array() );
}
