<?php
/**
 * This file contains the backend operations related to the Attribute Mapping tab for the premium module.
 *
 * @package MOSAML
 */

namespace MOSAML\Module\Premium\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Admin\Role_Mapping_Data_Handler as Standard_Role_Mapping_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\Utility;

/**
 * Role Mapping Data Handler.
 */
class Role_Mapping_Data_Handler extends Standard_Role_Mapping_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Validate and save the data for the Role Mapping tab.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$wp_roles_object = wp_roles();
		$wp_roles_names  = $wp_roles_object->get_names();
		foreach ( $wp_roles_names as $role_slug => $role_name ) {
			$this->role_mapping_values[ $role_slug ] = Utility::sanitize_post_data( 'mo_saml_role_value_' . $role_slug );
		}
		parent::validate_and_save_data();
	}
}
