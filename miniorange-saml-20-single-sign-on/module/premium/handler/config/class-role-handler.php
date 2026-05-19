<?php
/**
 * Premium Role Handler.
 *
 * This file contains the Premium Role Handler class which extends
 * the standard role handler with premium-level functionality for
 * advanced role mapping and custom role assignment features.
 *
 * @package miniorange-saml-20-single-sign-on/module/premium/handler/config
 * @since 1.0
 */

namespace MOSAML\Module\Premium\Handler\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Config\Role_Handler as Standard_Role_Handler;
use MOSAML\Traits\Instance;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Exception\Non_WP_Member_Exception;

/**
 * Role Handler.
 *
 * @package MOSAML\Module\Premium\Handler\Config
 */
class Role_Handler extends Standard_Role_Handler {
	use Instance;

	/**
	 * Get the assigned roles.
	 *
	 * @param array $saml_attributes The SAML attributes.
	 * @param bool  $regex_enabled Whether regex is enabled.
	 * @return array The assigned roles array.
	 */
	public function get_assigned_roles( $saml_attributes, $regex_enabled ) {
		$assigned_roles = parent::get_assigned_roles( $saml_attributes, $regex_enabled );
		$group_attribute_name = $this->default_role_mapping_data_object->group_attribute_name;
		if ( $group_attribute_name && is_array( $saml_attributes ) ) {
			$user_attribute_values = isset( $saml_attributes[ $group_attribute_name ] )
				? $saml_attributes[ $group_attribute_name ]
				: null;
			$user_attribute_values = apply_filters( 'mosaml_group_separator_internal', $user_attribute_values );
			if ( $user_attribute_values ) {
				$configured_role_values = $this->roles_data_object->role_mapping_values;
				if ( is_array( $user_attribute_values ) ) {
					foreach ( $user_attribute_values as $user_attribute_value ) {
						foreach ( $configured_role_values as $role_key => $role_values ) {
							$role_values_array = array_map( 'trim', explode( ';', $role_values ) );
							if ( $regex_enabled ) {
								foreach ( $role_values_array as $role_value ) {
									if ( $role_value && preg_match( '/' . $role_value . '/', $user_attribute_value ) ) {
										$assigned_roles[] = $role_key;
									}
								}
							} elseif ( in_array( trim( $user_attribute_value ), $role_values_array, true ) ) {
								$assigned_roles[] = $role_key;
							}
						}
					}
				} else {
					foreach ( $configured_role_values as $role_key => $role_values ) {
						$role_values_array = array_map( 'trim', explode( ';', $role_values ) );
						if ( $regex_enabled ) {
							foreach ( $role_values_array as $role_value ) {
								if ( $role_value && preg_match( '/' . $role_value . '/', $user_attribute_values ) ) {
									$assigned_roles[] = $role_key;
								}
							}
						} elseif ( in_array( trim( $user_attribute_values ), $role_values_array, true ) ) {
							$assigned_roles[] = $role_key;
						}
					}
				}
			}
		}
		return $assigned_roles;
	}

	/**
	 * Validate new user creation.
	 *
	 * @param array $assigned_roles The assigned roles array.
	 * @return void
	 *
	 * @throws Non_WP_Member_Exception If no roles assigned so new user creation is not allowed.
	 */
	public function validate_new_user_creation( $assigned_roles ) {
		if ( 'checked' !== $this->default_role_mapping_data_object->create_new_user && ! $assigned_roles ) {
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
			throw new Non_WP_Member_Exception( 'No roles assigned so new user creation is not allowed' );
		}
	}

	/**
	 * Assign roles to a WordPress user.
	 *
	 * @param \WP_User $user The WordPress user object.
	 * @param array    $assigned_roles The assigned roles array.
	 * @param bool     $is_new_user Whether the user is new.
	 * @param bool     $whitelist_existing_users_roles Whether to whitelist existing users roles.
	 * @param array    $whitelisted_roles The whitelisted roles array.
	 * @return void
	 */
	public function assign_roles( $user, $assigned_roles, $is_new_user, $whitelist_existing_users_roles, $whitelisted_roles ) {
		if ( Utility::is_user_administrator( $user ) && 'checked' !== $this->default_role_mapping_data_object->apply_role_mapping_to_admin ) {
			return;
		}

		$roles_to_keep = array();
		if ( 'checked' === $whitelist_existing_users_roles ) {
			$roles_to_keep = array_intersect( $user->roles, array_keys( $whitelisted_roles ) );
		}

		if ( $assigned_roles ) {
			$roles_to_add    = array_diff( $assigned_roles, $user->roles );
			$roles_to_remove = array_diff( $user->roles, $assigned_roles );
			foreach ( $roles_to_add as $role ) {
				$user->add_role( $role );
			}
			foreach ( $roles_to_remove as $role ) {
				if ( ! in_array( $role, $roles_to_keep, true ) ) {
					$user->remove_role( $role );
				}
			}
			return;
		}

		if ( ! $is_new_user && 'checked' === $this->default_role_mapping_data_object->update_existing_user ) {
			$roles_to_remove = array_diff( $user->roles, $roles_to_keep );
			foreach ( $roles_to_remove as $role ) {
				$user->remove_role( $role );
			}
			$user->add_role( $this->default_role_mapping_data_object->default_role_existing );
			return;
		}

		parent::assign_roles( $user, $assigned_roles, $is_new_user, $whitelist_existing_users_roles, $whitelisted_roles );
	}
}
