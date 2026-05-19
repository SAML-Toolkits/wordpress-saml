<?php
/**
 * SSO User Tag Handler - Base Module
 *
 * Handles data operations for SSO user tag configuration in the base module.
 *
 * PHP Compatibility: 5.6+
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Base\Handler\Config
 */

namespace MOSAML\Module\Base\Handler\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * SSO User Tag Handler.
 */
class SSO_User_Tag_Handler {

	/**
	 * SSO user tag data.
	 *
	 * @var object
	 */
	protected $sso_user_tag_data;

	/**
	 * Constructor.
	 *
	 * @param object $sso_user_tag_data The SSO user tag data.
	 */
	public function __construct( $sso_user_tag_data ) {
		$this->sso_user_tag_data = $sso_user_tag_data;
	}

	/**
	 * Display SSO user tag.
	 *
	 * @return void
	 */
	public function display_sso_user_tag() {}
}
