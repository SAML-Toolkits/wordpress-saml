<?php
/**
 * Base Module - Import Attribute Mapping Configuration Class
 *
 * Handles attribute mapping configuration data import for the base module.
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
 * Base Import Attribute Mapping Configuration Class
 */
class Import_Attribute_Mapping_Config {

	/**
	 * Get the database table name
	 *
	 * @return string The table name
	 */
	protected function get_table_name() {
		return Constants::DATABASE_TABLE_NAMES['attribute_mapping'];
	}

	/**
	 * Attribute Username
	 *
	 * @var string
	 */
	public $attribute_username = '';

	/**
	 * Attribute Email
	 *
	 * @var string
	 */
	public $attribute_email = '';

	/**
	 * Attribute First Name
	 *
	 * @var string
	 */
	public $attribute_first_name = '';

	/**
	 * Attribute Last Name
	 *
	 * @var string
	 */
	public $attribute_last_name = '';

	/**
	 * Attribute Display Name
	 *
	 * @var string
	 */
	public $attribute_display_name = '';

	/**
	 * Attribute Nickname
	 *
	 * @var string
	 */
	public $attribute_nick_name = '';
}
