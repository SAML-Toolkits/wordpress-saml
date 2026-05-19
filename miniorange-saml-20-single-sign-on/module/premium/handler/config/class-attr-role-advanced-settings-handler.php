<?php
/**
 * Attr Role Advanced Settings Handler.
 *
 * @package MOSAML\Module\Premium\Handler\Config
 */

namespace MOSAML\Module\Premium\Handler\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Config\Attr_Role_Advanced_Settings_Handler as Standard_Attr_Role_Advanced_Settings_Handler;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Exception\Blacklisted_User_Exception;
use MOSAML\SRC\Exception\Non_Whitelisted_User_Exception;
use MOSAML\SRC\Exception\Attribute_Restriction_Exception;
use MOSAML\SRC\Exception\Non_WP_Member_Exception;

/**
 * Attr Role Advanced Settings Handler.
 */
class Attr_Role_Advanced_Settings_Handler extends Standard_Attr_Role_Advanced_Settings_Handler {

	/**
	 * Validate user email domain.
	 *
	 * @param string $user_email The user email.
	 * @return void
	 *
	 * @throws Non_Whitelisted_User_Exception If user domain not allowed.
	 * @throws Blacklisted_User_Exception If user domain blacklisted.
	 */
	public function validate_user_email_domain( $user_email ) {
		if ( $user_email && 'checked' === $this->advanced_settings_data->allow_deny_user_domain_toggle ) {
			$user_domain        = strtolower( Utility::get_domain_from_email( $user_email ) );
			$configured_domains = array_map(
				'strtolower',
				array_map(
					'trim',
					explode( ';', $this->advanced_settings_data->allow_deny_user_domain_value )
				)
			);
			$restricted_domain_error_msg = Utility::get_handler_object( 'custom_messages_data', true, 'admin' )->get_data(
				array(
					'option_name' => 'restricted_domain_error_msg',
					'subsite_id'  => Utility::get_subsite_id_for_environment( DB_Utils::get_environment_details( 'id', true ) ),
				)
			)->restricted_domain_error_msg;
			if ( ! in_array( $user_domain, $configured_domains, true ) && 'allow' === $this->advanced_settings_data->allow_deny_user_domain_type ) {
				if ( Utility::is_plugin_active( Constants::CUSTOM_SSO_ERROR_MESSAGE_ADDON_SLUG ) ) {
					// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Legacy public hook.
					do_action( 'mo_custom_sso_error_msg', 'domain-restriction' );
				}
				if ( ! empty( $restricted_domain_error_msg ) ) {
					wp_die( esc_html( $restricted_domain_error_msg ), 'Permission Denied : Not a Whitelisted user.' );
				}
				throw new Non_Whitelisted_User_Exception( 'User domain not allowed' );
			}
			if ( in_array( $user_domain, $configured_domains, true ) && 'deny' === $this->advanced_settings_data->allow_deny_user_domain_type ) {
				if ( Utility::is_plugin_active( Constants::CUSTOM_SSO_ERROR_MESSAGE_ADDON_SLUG ) ) {
					// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Legacy public hook.
					do_action( 'mo_custom_sso_error_msg', 'domain-restriction' );
				}
				if ( ! empty( $restricted_domain_error_msg ) ) {
					wp_die( esc_html( $restricted_domain_error_msg ), 'Permission Denied : Blacklisted user.' );
				}
				throw new Blacklisted_User_Exception( 'User domain blacklisted' );
			}
		}
	}

	/**
	 * Validate user IDP attribute.
	 *
	 * @param array $user_idp_attribute The user IDP attribute.
	 * @return void
	 *
	 * @throws Attribute_Restriction_Exception If user attribute value not allowed or denied.
	 */
	public function validate_user_idp_attribute( $user_idp_attribute ) {
		if ( 'checked' === $this->advanced_settings_data->allow_deny_idp_attribute_toggle ) {
			$configured_attribute_name   = $this->advanced_settings_data->attribute_restriction_group;
			$configured_attribute_values = array_map( 'trim', explode( ';', $this->advanced_settings_data->attribute_restriction_value ) );
			$raw_user_value              = isset( $user_idp_attribute[ $configured_attribute_name ] ) ? $user_idp_attribute[ $configured_attribute_name ] : array();
			$user_attribute_values       = is_array( $raw_user_value ) ? $raw_user_value : array( $raw_user_value );
			$has_match                   = ! empty( array_intersect( $user_attribute_values, $configured_attribute_values ) );
			if ( ! $has_match && 'allow' === $this->advanced_settings_data->allow_deny_idp_attribute ) {
				throw new Attribute_Restriction_Exception( 'User attribute value not allowed' );
			}
			if ( $has_match && 'deny' === $this->advanced_settings_data->allow_deny_idp_attribute ) {
				throw new Attribute_Restriction_Exception( 'User attribute value blacklisted' );
			}
		}
	}

	/**
	 * Validate new user creation.
	 *
	 * @return void
	 *
	 * @throws Non_WP_Member_Exception If new user creation is disabled.
	 */
	public function validate_new_user_creation() {
		if ( 'checked' === $this->advanced_settings_data->do_not_create_new_users ) {
			if ( Utility::is_plugin_active( Constants::CUSTOM_SSO_ERROR_MESSAGE_ADDON_SLUG ) ) {
				// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Legacy public hook.
				do_action( 'mo_custom_sso_error_msg', 'user-creation' );
			}
			$account_creation_disabled_msg = Utility::get_handler_object( 'custom_messages_data', true, 'admin' )->get_data(
				array(
					'option_name' => 'account_creation_disabled_msg',
					'subsite_id'  => Utility::get_subsite_id_for_environment( DB_Utils::get_environment_details( 'id', true ) ),
				)
			)->account_creation_disabled_msg;
			if ( ! empty( $account_creation_disabled_msg ) ) {
				wp_die( esc_html( $account_creation_disabled_msg ), 'User Creation Disabled' );
			}
			throw new Non_WP_Member_Exception( 'User Creation Disabled' );
		}
	}
}
