<?php
/**
 * Standard Attribute Handler.
 *
 * This file contains the Standard Attribute_Handler class that extends base
 * attribute processing with standard-level functionality for basic attributes.
 *
 * @package MOSAML
 * @subpackage Standard\Handler\Config
 * @since 1.0.0
 */

namespace MOSAML\Module\Standard\Handler\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Config\Attribute_Handler as Base_Attribute_Handler;
use MOSAML\SRC\DTO\User_Attributes_DTO;
use MOSAML\Traits\Instance;

/**
 * Standard Attribute Handler.
 *
 * This class extends the base attribute handler with standard-level functionality.
 *
 * @since 1.0.0
 */
class Attribute_Handler extends Base_Attribute_Handler {
	use Instance;

	/**
	 * Processes SAML attributes and assigns them to a User Attributes DTO.
	 *
	 * This standard version extends the base attribute processing by adding
	 * support for basic attributes.
	 *
	 * @since 1.0.0
	 * @param array $attributes The assertion saml attributes.
	 * @return User_Attributes_DTO The populated user attributes data transfer object
	 */
	public function get_user_attributes( $attributes ) {
		$user_attributes_dto = parent::get_user_attributes( $attributes );
		if ( ! empty( $this->attribute_data_object->user_name ) && isset( $attributes[ $this->attribute_data_object->user_name ] ) ) {
			$user_attributes_dto->set_username( $attributes[ $this->attribute_data_object->user_name ] );
		}
		if ( ! empty( $this->attribute_data_object->email ) && isset( $attributes[ $this->attribute_data_object->email ] ) ) {
			$user_attributes_dto->set_email( $attributes[ $this->attribute_data_object->email ] );
		}
		if ( ! empty( $this->attribute_data_object->first_name ) && isset( $attributes[ $this->attribute_data_object->first_name ] ) ) {
			$user_attributes_dto->set_first_name( $attributes[ $this->attribute_data_object->first_name ] );
		}
		if ( ! empty( $this->attribute_data_object->last_name ) && isset( $attributes[ $this->attribute_data_object->last_name ] ) ) {
			$user_attributes_dto->set_last_name( $attributes[ $this->attribute_data_object->last_name ] );
		}
		if ( ! empty( $this->attribute_data_object->nick_name ) && isset( $attributes[ $this->attribute_data_object->nick_name ] ) ) {
			$user_attributes_dto->set_nick_name( $attributes[ $this->attribute_data_object->nick_name ] );
		}
		if ( ! empty( $this->attribute_data_object->display_name ) ) {
			if ( strcmp( $this->attribute_data_object->display_name, 'USERNAME' ) === 0 ) {
				$user_attributes_dto->set_display_name( $user_attributes_dto->get_username() );
			} elseif ( strcmp( $this->attribute_data_object->display_name, 'FNAME' ) === 0 && ! empty( $user_attributes_dto->get_first_name() ) ) {
				$user_attributes_dto->set_display_name( $user_attributes_dto->get_first_name() );
			} elseif ( strcmp( $this->attribute_data_object->display_name, 'LNAME' ) === 0 && ! empty( $user_attributes_dto->get_last_name() ) ) {
				$user_attributes_dto->set_display_name( $user_attributes_dto->get_last_name() );
			} elseif ( strcmp( $this->attribute_data_object->display_name, 'NICKNAME' ) === 0 && ! empty( $user_attributes_dto->get_nick_name() ) ) {
				$user_attributes_dto->set_display_name( $user_attributes_dto->get_nick_name() );
			} elseif ( strcmp( $this->attribute_data_object->display_name, 'FNAME_LNAME' ) === 0 && ! empty( $user_attributes_dto->get_last_name() ) && ! empty( $user_attributes_dto->get_first_name() ) ) {
				$user_attributes_dto->set_display_name( $user_attributes_dto->get_first_name() . ' ' . $user_attributes_dto->get_last_name() );
			} elseif ( strcmp( $this->attribute_data_object->display_name, 'LNAME_FNAME' ) === 0 && ! empty( $user_attributes_dto->get_last_name() ) && ! empty( $user_attributes_dto->get_first_name() ) ) {
				$user_attributes_dto->set_display_name( $user_attributes_dto->get_last_name() . ' ' . $user_attributes_dto->get_first_name() );
			}
		}
		return $user_attributes_dto;
	}

	/**
	 * Assign attributes to a WordPress user.
	 *
	 * @param \WP_User            $user The WordPress user object.
	 * @param User_Attributes_DTO $user_attributes_dto The user attributes DTO.
	 * @param bool                $is_new_user Whether the user is new.
	 * @return void
	 */
	public function assign_attributes( $user, $user_attributes_dto, $is_new_user = false ) {
		if ( $user_attributes_dto->get_first_name() ) {
			$user->data->first_name = $user_attributes_dto->get_first_name();
		}

		if ( $user_attributes_dto->get_last_name() ) {
			$user->data->last_name = $user_attributes_dto->get_last_name();
		}

		if ( $user_attributes_dto->get_nick_name() ) {
			$user->data->nickname = $user_attributes_dto->get_nick_name();
		}

		if ( $user_attributes_dto->get_display_name() && ! ( ! $is_new_user && 'checked' === $this->attribute_data_object->do_not_update_display_name ) ) {
			$user->data->display_name = $user_attributes_dto->get_display_name();
		}

		parent::assign_attributes( $user, $user_attributes_dto );
	}
}
