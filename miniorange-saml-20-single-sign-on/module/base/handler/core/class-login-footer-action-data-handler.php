<?php
/**
 * Login Footer Action Handler.
 *
 * @package MOSAML
 * @subpackage Module\Base\Handler\Core
 */

namespace MOSAML\Module\Base\Handler\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Login Footer Action Handler.
 */
class Login_Footer_Action_Data_Handler {

	/**
	 * Login footer actions.
	 *
	 * @return void
	 */
	public function login_footer_actions() {}

	/**
	 * Fetch domain mapping.
	 *
	 * @param string $user_email The user email.
	 * @return WP_Error|WP_REST_Response
	 */
	public function fetch_domain_mapping( $user_email ) {
		return wp_send_json_error( 'Upgrade to enterprise version to enable the domain mapping', 404 );
	}
}
