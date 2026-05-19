<?php
/**
 * Login Page Auto Redirection Handler.
 *
 * @package MOSAML\Module\Base\Handler\Core
 */

namespace MOSAML\Module\Base\Handler\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;

/**
 * Login Page Auto Redirection Handler.
 */
class Login_Page_Auto_Redirection_Handler {

	/**
	 * Enable login page auto redirection.
	 *
	 * @var string
	 */
	public $redirect_from_wp_login;

	/**
	 * Enable backdoor url login.
	 *
	 * @var string
	 */
	public $enable_backdoor_url_login;

	/**
	 * Backdoor url.
	 *
	 * @var string
	 */
	public $backdoor_url = 'false';

	/**
	 * Handle login page auto redirection.
	 *
	 * @return void
	 */
	public function handle_login_page_auto_redirection() {}

	/**
	 * Get the table name for database operations.
	 *
	 * @return string The table name.
	 */
	public function get_table_name() {
		return Constants::DATABASE_TABLE_NAMES['sso_settings'];
	}
}
