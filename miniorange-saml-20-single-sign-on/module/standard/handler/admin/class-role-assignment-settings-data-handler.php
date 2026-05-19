<?php
/**
 * This file contains the backend operations related to the Role Mapping tab for the standard module.
 *
 * @package MOSAML
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Admin\Role_Assignment_Settings_Data_Handler as Base_Role_Assignment_Settings_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\Utility;

/**
 * Role Mapping Handler.
 */
class Role_Assignment_Settings_Data_Handler extends Base_Role_Assignment_Settings_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Validate and save the data for the Role Mapping tab.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$this->update_existing_user = Utility::sanitize_post_data( 'mo_saml_update_existing_user_with_role' );
		if ( 'checked' === $this->update_existing_user ) {
			$this->default_role_existing = Utility::sanitize_post_data( 'mo_saml_default_role_existing' );
			if ( empty( $this->default_role_existing ) ) {
				$this->default_role_existing = get_option( 'default_role' );
			}
		}

		parent::validate_and_save_data();
	}
}
