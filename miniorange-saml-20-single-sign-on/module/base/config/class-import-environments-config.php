<?php
/**
 * Base Module - Import Environments Configuration Class
 *
 * Handles environments configuration data import for the base module.
 *
 * @package MOSAML\Module\Base\Config
 * @since 1.0.0
 */

namespace MOSAML\Module\Base\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;

/**
 * Base Import Environments Configuration Class
 */
class Import_Environments_Config {

	/**
	 * Get the database table name
	 *
	 * @return string The table name
	 */
	protected function get_table_name() {
		return Constants::DATABASE_TABLE_NAMES['environments'];
	}

	/**
	 * Environment Name
	 *
	 * @var string
	 */
	public $environment_name = '';

	/**
	 * Environment URL
	 *
	 * @var string
	 */
	public $environment_url = '';
}
