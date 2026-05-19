<?php
/**
 * User restriction handler (premium module).
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\Module\Premium\Handler\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Config\User_Restriction_Handler as Standard_User_Restriction_Handler;
use MOSAML\Traits\Instance;

/**
 * User Restriction Handler.
 *
 * @package MOSAML\Module\Premium\Handler
 */
class User_Restriction_Handler extends Standard_User_Restriction_Handler {
	use Instance;

	/**
	 * Verifies the user restriction.
	 *
	 * @param User_Attributes_DTO $user_attributes_dto User attributes DTO.
	 */
	public function verify_user_restriction( $user_attributes_dto ) {
		$this->verify_user_creation_restriction();
		$this->verify_attribute_restriction( $user_attributes_dto );
		$this->verify_domain_restriction( $user_attributes_dto );
	}

	/**
	 * Verifies the attribute restriction.
	 *
	 * @param User_Attributes_DTO $user_attributes_dto User attributes DTO.
	 */
	private function verify_attribute_restriction( $user_attributes_dto ) {}

	/**
	 * Verifies the domain restriction.
	 *
	 * @param User_Attributes_DTO $user_attributes_dto User attributes DTO.
	 */
	private function verify_domain_restriction( $user_attributes_dto ) {}

	/**
	 * Verifies the user creation restriction.
	 */
	private function verify_user_creation_restriction() {}
}
