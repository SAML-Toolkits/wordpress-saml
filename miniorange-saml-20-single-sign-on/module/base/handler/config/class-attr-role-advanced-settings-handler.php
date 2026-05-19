<?php
/**
 * Attr Role Advanced Settings Handler.
 *
 * @package MOSAML\Module\Base\Handler\Config
 */

namespace MOSAML\Module\Base\Handler\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Attr Role Advanced Settings Handler.
 */
class Attr_Role_Advanced_Settings_Handler {

	/**
	 * Advanced settings data.
	 *
	 * @var object
	 */
	protected $advanced_settings_data;

	/**
	 * Constructor.
	 *
	 * @param object $advanced_settings_data The advanced settings data.
	 */
	public function __construct( $advanced_settings_data ) {
		$this->advanced_settings_data = $advanced_settings_data;
	}

	/**
	 * Validate user email domain.
	 *
	 * @param string $user_email The user email.
	 * @return void
	 */
	public function validate_user_email_domain( $user_email ) {}

	/**
	 * Validate user IDP attribute.
	 *
	 * @param string $user_idp_attribute The user IDP attribute.
	 * @return void
	 */
	public function validate_user_idp_attribute( $user_idp_attribute ) {}

	/**
	 * Validate user new user creation.
	 *
	 * @return void
	 */
	public function validate_new_user_creation() {}
}
