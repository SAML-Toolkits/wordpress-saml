<?php
/**
 * Standard Role Handler.
 *
 * This file contains the Standard Role Handler class which extends
 * the base role handler with standard-level functionality for
 * role assignment.
 *
 * @package miniorange-saml-20-single-sign-on/module/standard/handler/config
 * @since 1.0
 */

namespace MOSAML\Module\Standard\Handler\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Config\Role_Handler as Base_Role_Handler;
use MOSAML\Traits\Instance;
use MOSAML\SRC\Utils\Utility;

/**
 * Role Handler.
 *
 * @package MOSAML\Module\Standard\Handler\Config
 */
class Role_Handler extends Base_Role_Handler {
	use Instance;

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

		if ( ! $is_new_user && 'checked' === $this->default_role_mapping_data_object->update_existing_user && ! Utility::is_user_administrator( $user ) ) {
			$user->set_role( $this->default_role_mapping_data_object->default_role_existing );
			return;
		}

		parent::assign_roles( $user, $assigned_roles, $is_new_user, $whitelist_existing_users_roles, $whitelisted_roles );
	}
}
