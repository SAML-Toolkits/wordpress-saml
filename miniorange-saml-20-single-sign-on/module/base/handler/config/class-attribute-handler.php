<?php
/**
 * Base Attribute Handler.
 *
 * This file contains the Base Attribute_Handler class that processes SAML attributes
 * and maps them to User Attributes DTO.
 *
 * @package MOSAML
 * @subpackage Base\Handler\Config
 * @since 1.0.0
 */

namespace MOSAML\Module\Base\Handler\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\DTO\User_Attributes_DTO;
use MOSAML\Traits\Instance;

/**
 * Base Attribute Handler.
 *
 * This class handles the processing of SAML attributes and maps them to user attributes.
 *
 * @since 1.0.0
 */
class Attribute_Handler {
	use Instance;

	/**
	 * Attribute Mapping Data Handler object.
	 *
	 * @var object
	 */
	public $attribute_data_object;

	/**
	 * Constructor.
	 *
	 * @param object $attribute_data_object The attribute data object.
	 */
	public function __construct( $attribute_data_object ) {
		$this->attribute_data_object = $attribute_data_object;
	}

	/**
	 * Processes SAML attributes and assigns them to a User Attributes DTO.
	 *
	 * This method extracts user information from SAML response attributes
	 * and maps them to the appropriate user attributes data transfer object.
	 * Currently maps the NameID value to both username and email fields.
	 *
	 * @since 1.0.0
	 * @param array $saml_attributes The assertion saml attributes.
	 * @return User_Attributes_DTO The populated user attributes data transfer object
	 */
	public function get_user_attributes( $saml_attributes ) {
		$user_attributes_dto = new User_Attributes_DTO();
		$user_attributes_dto->set_username( $saml_attributes['NameID'] );
		$user_attributes_dto->set_email( $saml_attributes['NameID'] );
		$user_attributes_dto->set_display_name( $saml_attributes['NameID'] );

		return $user_attributes_dto;
	}

	/**
	 * Assign attributes to a WordPress user.
	 *
	 * @param \WP_User            $user The WordPress user object.
	 * @param User_Attributes_DTO $user_attributes_dto The user attributes DTO.
	 * @return void
	 */
	public function assign_attributes( $user, $user_attributes_dto ) {
		if ( $user_attributes_dto->get_email() ) {
			$user->data->user_email = $user_attributes_dto->get_email();
		}
		wp_update_user( $user );
	}
}
