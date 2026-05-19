<?php
/**
 * Global Option Migration Handler.
 *
 * @package    MOSAML
 * @subpackage MOSAML/src/handler/migration/handler
 */

namespace MOSAML\SRC\Handler\Migration\Handler;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Handler\Migration\Handler\Migration_Handler;

/**
 * Global Option Migration Handler.
 */
class Global_Option_Migration_Handler implements Migration_Handler {

	/**
	 * Migrate the global option.
	 *
	 * @param array $global_options The global options to migrate.
	 * @return void
	 */
	public function migrate( $global_options ) {
		foreach ( $global_options as $option_name => $option_value ) {
			update_option( $option_name, $option_value );
		}
	}
}
