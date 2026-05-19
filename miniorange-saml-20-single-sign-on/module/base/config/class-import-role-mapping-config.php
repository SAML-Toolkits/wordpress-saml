<?php
/**
 * Base Module - Import Role Mapping Configuration Class
 *
 * Handles role mapping configuration data import for the base module.
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
 * Base Import Role Mapping Configuration Class
 */
class Import_Role_Mapping_Config {

	/**
	 * Get the database table name
	 *
	 * @return string The table name
	 */
	protected function get_table_name() {
		return Constants::DATABASE_TABLE_NAMES['role_mapping'];
	}

	/**
	 * Subsite ID
	 *
	 * @var int
	 */
	public $subsite_id;

	/**
	 * Role do not update existing user
	 *
	 * @var string
	 */
	public $role_do_not_update_existing_user = '';

	/**
	 * Role default role
	 *
	 * @var string
	 */
	public $role_default_role = '';

	/**
	 * Group attribute name
	 *
	 * @var string
	 */
	public $group_attribute_name = '';

	/**
	 * Default role for new users
	 *
	 * @var string
	 */
	public $default_role_new = '';

	/**
	 * Update existing user with role
	 *
	 * @var string
	 */
	public $update_existing_user = '';

	/**
	 * Group mapping values
	 *
	 * @var array
	 */
	public $group_mapping_values = array();
}
