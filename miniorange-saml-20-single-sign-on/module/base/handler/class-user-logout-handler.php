<?php
/**
 * User Logout Handler for Base Version.
 *
 * @package MOSAML\Module\Base\Handler
 */

namespace MOSAML\Module\Base\Handler;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Traits\Instance;

/**
 * User Logout Handler for Base Version.
 *
 * This class handles the user logout process.
 */
class User_Logout_Handler {

	use Instance;

	/**
	 * Get the relay state for logout request.
	 *
	 * @param string $sp_base_url SP base URL.
	 * @return string
	 */
	public function get_relay_state( $sp_base_url ) {
		return $sp_base_url ? $sp_base_url : '/';
	}

	/**
	 * Create the logout request and redirect to the IDP logout URL.
	 *
	 * @param SAML_Request_DTO $saml_request_dto SAML request DTO.
	 * @param int              $user_id The user ID.
	 * @return void
	 */
	public function create_logout_request_and_redirect( $saml_request_dto, $user_id ) {}

	/**
	 * Create the logout response and redirect.
	 *
	 * @param SAML_Request_DTO $saml_request_dto SAML request DTO.
	 * @return void
	 */
	public function create_logout_response_and_redirect( $saml_request_dto ) {}

	/**
	 * Handles the user logout process for base version.
	 *
	 * @param string $relay_state The relay state.
	 *
	 * @return void
	 */
	public function handle_logout( $relay_state ) {}
}
