<?php
/**
 * This file contains the backend operations related to the Role Mapping tab for the premium module.
 *
 * @package MOSAML
 */

namespace MOSAML\Module\Premium\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Admin\Role_Assignment_Settings_Data_Handler as Standard_Role_Assignment_Settings_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\Utility;

/**
 * Role Assignment Settings Data Handler.
 */
class Role_Assignment_Settings_Data_Handler extends Standard_Role_Assignment_Settings_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Validate and save the data for the Role Mapping tab.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$this->group_attribute_name        = Utility::sanitize_post_data( 'mo_saml_group_attribute_name' );
		$this->apply_role_mapping_to_admin = Utility::sanitize_post_data( 'mo_saml_apply_role_to_admin' );
		$this->create_new_user             = Utility::sanitize_post_data( 'mo_saml_create_new_user_with_role' );

		parent::validate_and_save_data();
	}
}
