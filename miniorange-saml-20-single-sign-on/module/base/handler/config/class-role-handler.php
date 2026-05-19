<?php
/**
 * Base Role Handler.
 *
 * This file contains the Base Role Handler class which provides
 * fundamental role processing functionality for SAML user authentication
 * and role assignment in the WordPress environment.
 *
 * @package miniorange-saml-20-single-sign-on/module/base/handler/config
 * @since 1.0
 */

namespace MOSAML\Module\Base\Handler\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Traits\Instance;
use Exception;

/**
 * Role Handler.
 *
 * @package MOSAML\Module\Base\Handler\Config
 */
class Role_Handler {
	use Instance;

	/**
	 * Role Mapping Data object.
	 *
	 * @var object
	 */
	protected $roles_data_object;

	/**
	 * Default role mapping data object.
	 *
	 * @var object
	 */
	protected $default_role_mapping_data_object;

	/**
	 * Constructor.
	 *
	 * @param object $roles_data_object The roles data object.
	 * @param object $default_role_mapping_data_object The default role mapping data object.
	 */
	public function __construct( $roles_data_object, $default_role_mapping_data_object ) {
		$this->roles_data_object                = $roles_data_object;
		$this->default_role_mapping_data_object = $default_role_mapping_data_object;
	}

	/**
	 * Get the assigned roles.
	 *
	 * @param array $saml_attributes The SAML attributes.
	 * @param bool  $regex_enabled Whether regex is enabled.
	 * @return array The user roles array.
	 */
	public function get_assigned_roles( $saml_attributes, $regex_enabled ) {
		return array();
	}

	/**
	 * Validate new user creation.
	 *
	 * @param array $assigned_roles The assigned roles array.
	 * @return void
	 *
	 * @throws Exception If no roles assigned so new user creation is not allowed.
	 */
	public function validate_new_user_creation( $assigned_roles ) {}

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
		if ( $is_new_user ) {
			$user->set_role( $this->default_role_mapping_data_object->default_role_new );
		}
	}
}
