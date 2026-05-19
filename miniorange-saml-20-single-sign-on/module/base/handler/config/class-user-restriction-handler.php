<?php
/**
 * User restriction handler (base module).
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\Module\Base\Handler\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * User Restriction Handler.
 *
 * @package MOSAML\Module\Base\Handler
 */
class User_Restriction_Handler {

	/**
	 * Verifies the user restriction.
	 *
	 * @param User_Attributes_DTO $user_attributes_dto User attributes DTO.
	 */
	public function verify_user_restriction( $user_attributes_dto ) {
	}
}
