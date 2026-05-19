<?php
/**
 * This file contains the backend operations related to the Role Mapping Advanced Settings tab for the premium module.
 *
 * @package MOSAML
 */

namespace MOSAML\Module\Premium\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Admin\Role_Mapping_Advanced_Settings_Data_Handler as Standard_Role_Mapping_Advanced_Settings_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\Error_Success_Message;

/**
 * Role Mapping Advanced Settings Data Handler.
 */
class Role_Mapping_Advanced_Settings_Data_Handler extends Standard_Role_Mapping_Advanced_Settings_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Save the data for the Attribute Mapping tab.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$this->do_not_create_new_users = Utility::sanitize_post_data( 'mo_saml_dont_create_new_users' );

		$this->do_not_update_existing_user_roles = Utility::sanitize_post_data( 'mo_saml_do_not_update_existing_user' );

		$this->whitelist_existing_users_roles = Utility::sanitize_post_data( 'mo_saml_whitelist_existing_users_roles' );
		$this->whitelisted_roles              = Utility::sanitize_post_data( 'mo_saml_whitelisted_roles', true );
		if ( 'checked' === $this->whitelist_existing_users_roles && ! $this->whitelisted_roles ) {
			Error_Success_Message::show_admin_notice( 'Please select at least one role to whitelist.' );
			return;
		}

		$this->allow_deny_idp_attribute_toggle = Utility::sanitize_post_data( 'mo_saml_allow_deny_idp_attribute_toggle' );
		$this->attribute_restriction_group     = Utility::sanitize_post_data( 'mo_saml_attribute_restriction_attr_name' );
		$this->attribute_restriction_value     = Utility::sanitize_post_data( 'mo_saml_attribute_restriction_attr_value' );
		$this->allow_deny_idp_attribute        = Utility::sanitize_post_data( 'mo_saml_allow_deny_idp_attribute' );
		if ( 'checked' === $this->allow_deny_idp_attribute_toggle ) {
			if ( ! $this->attribute_restriction_group ) {
				Error_Success_Message::show_admin_notice( 'Please select/enter the attribute restriction group.' );
				return;
			} elseif ( ! $this->attribute_restriction_value ) {
				Error_Success_Message::show_admin_notice( 'Please enter the attribute restriction value.' );
				return;
			} elseif ( ! $this->allow_deny_idp_attribute ) {
				Error_Success_Message::show_admin_notice( 'Please select the Allow/Deny IDP attribute.' );
				return;
			}
		}

		$this->allow_deny_user_domain_toggle = Utility::sanitize_post_data( 'mo_saml_allow_deny_user_domain_toggle' );
		$this->allow_deny_user_domain_value  = Utility::sanitize_post_data( 'mo_saml_allow_deny_user_domain_value' );
		$this->allow_deny_user_domain_type   = Utility::sanitize_post_data( 'mo_saml_allow_deny_user_domain' );

		if ( 'checked' === $this->allow_deny_user_domain_toggle ) {
			$regex = '/^\s*(?:[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*(\.[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*)+\s*;\s*)*[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*(\.[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*)+\s*;?\s*$/';
			if ( ! $this->allow_deny_user_domain_value ) {
				Error_Success_Message::show_admin_notice( 'Please enter the email domain.' );
				return;
			} elseif ( ! $this->allow_deny_user_domain_type ) {
				Error_Success_Message::show_admin_notice( 'Please select the Allow/Deny user domain.' );
				return;
			} elseif ( ! preg_match( $regex, $this->allow_deny_user_domain_value ) ) {
				Error_Success_Message::show_admin_notice( 'Please enter one or more valid domain names separated by semicolons.' );
				return;
			}
		}

		$this->enable_regex_for_role_mapping = Utility::sanitize_post_data( 'mo_saml_enable_regex_for_role_mapping' );

		parent::validate_and_save_data();
	}
}
