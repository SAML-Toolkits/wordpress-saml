<?php
/**
 * Base Module - Import Redirection Configuration Class
 *
 * Handles redirection configuration data import for the base module.
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
 * Base Import Redirection Configuration Class
 */
class Import_Redirection_Config {

	/**
	 * Get the database table name
	 *
	 * @return string The table name
	 */
	protected function get_table_name() {
		return Constants::DATABASE_TABLE_NAMES['sso_settings'];
	}

	/**
	 * Subsite ID
	 *
	 * @var int
	 */
	public $subsite_id;

	/**
	 * Login redirect URL
	 *
	 * @var string
	 */
	public $login_redirect_url = '';

	/**
	 * Logout redirect URL
	 *
	 * @var string
	 */
	public $logout_redirect_url = '';

	/**
	 * Default redirect URL
	 *
	 * @var string
	 */
	public $default_redirect_url = '';
}
