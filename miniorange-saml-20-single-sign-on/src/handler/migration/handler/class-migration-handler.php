<?php
/**
 * Migration Handler.
 *
 * @package    MOSAML
 * @subpackage MOSAML/src/handler/migration/handler
 */

namespace MOSAML\SRC\Handler\Migration\Handler;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Migration Handler.
 */
interface Migration_Handler {

	/**
	 * Migrate the data.
	 *
	 * @param array $data The data to migrate.
	 * @return void
	 */
	public function migrate( $data );
}
