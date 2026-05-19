<?php
/**
 * Premium Attribute Handler.
 *
 * This file contains the Premium Attribute_Handler class that extends standard
 * attribute processing with premium-level functionality including custom attributes.
 *
 * @package MOSAML
 * @subpackage Premium\Handler\Config
 * @since 1.0.0
 */

namespace MOSAML\Module\Premium\Handler\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Config\Attribute_Handler as Standard_Attribute_Handler;
use MOSAML\SRC\DTO\User_Attributes_DTO;
use MOSAML\Traits\Instance;


/**
 * Premium Attribute Handler.
 *
 * This class extends the standard attribute handler with premium-level functionality.
 *
 * @since 1.0.0
 */
class Attribute_Handler extends Standard_Attribute_Handler {
	use Instance;

	/**
	 * Processes SAML attributes and assigns them to a User Attributes DTO.
	 *
	 * This premium version extends the standard attribute processing by adding
	 * support for custom attributes.
	 *
	 * @since 1.0.0
	 * @param array $attributes The attributes.
	 * @return User_Attributes_DTO The populated user attributes data transfer object
	 */
	public function get_user_attributes( $attributes ) {
		$user_attributes_dto = parent::get_user_attributes( $attributes );
		if ( 'checked' === $this->attribute_data_object->do_not_update_display_name ) {
			$user_attributes_dto->set_display_name( null );
		}
		$user_attributes_dto->set_custom_attributes( $this->get_user_custom_attributes( $attributes ) );

		$attributes_for_action = array();
		foreach ( $attributes as $key => $value ) {
			if ( ! is_array( $value ) ) {
				$attributes_for_action[ $key ] = array( $value );
			} else {
				$attributes_for_action[ $key ] = $value;
			}
		}

		return $user_attributes_dto;
	}

	/**
	 * Get custom attributes.
	 *
	 * @since 1.0.0
	 * @param array $attributes The attributes.
	 * @return array The custom attributes array
	 */
	private function get_user_custom_attributes( $attributes ) {
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Legacy hook name to get custom attributes.
		$attributes = apply_filters( 'mo_saml_custom_attributes_filter', $attributes );

		$custom_attributes = array();

		$custom_attributes_mapping = $this->attribute_data_object->custom_attributes;
		if ( $custom_attributes_mapping && is_array( $custom_attributes_mapping ) ) {
			foreach ( $custom_attributes_mapping as $value ) {
				if ( isset( $value['name'] ) && isset( $value['value'] ) && isset( $attributes[ $value['value'] ] ) ) {
					$custom_attributes[ $value['name'] ] = $attributes[ $value['value'] ];
				}
			}
		}
		return $custom_attributes;
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
		parent::assign_attributes( $user, $user_attributes_dto );

		if ( $user_attributes_dto->get_custom_attributes() && is_array( $user_attributes_dto->get_custom_attributes() ) ) {
			foreach ( $user_attributes_dto->get_custom_attributes() as $key => $value ) {
				update_user_meta( $user->ID, trim( $key ), $value );
			}
		}
		update_user_meta( $user->ID, 'mosaml_user_type', 'sso_user' );
	}
}
