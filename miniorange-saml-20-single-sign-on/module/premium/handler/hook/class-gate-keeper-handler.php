<?php
/**
 * Gatekeeper handler class.
 *
 * @package miniorange-saml-20-single-sign-on/module/premium/handler/hook
 */

namespace MOSAML\Module\Premium\Handler\Hook;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Hook\Gate_Keeper_Handler as Standard_Gate_Keeper_Handler;

/**
 * Gate_Keeper_Handler class.
 */
class Gate_Keeper_Handler extends Standard_Gate_Keeper_Handler {

	/**
	 * Get the actions.
	 *
	 * @return array The actions.
	 */
	protected static function get_allowed_actions() {
		return array_merge(
			parent::get_allowed_actions(),
			array(
				'mosaml_abr_filter_login_internal' => 'mo_abr_filter_login',
				'mosaml_guest_login_internal'      => 'mo_guest_login',
				'mosaml_assign_role_arm_internal'  => 'mo_saml_assign_role_arm',
				'mosaml_attributes_internal'       => 'mo_saml_attributes',
				'mosaml_flush_cache_internal'      => 'mo_saml_flush_cache',
				'mosaml_settings_deleted_internal' => 'mo_saml_settings_deleted',
				'mosaml_settings_updated_internal' => 'mo_saml_settings_updated',
				'mosaml_user_register_internal'    => 'user_register',
				'mosaml_wp_login_internal'         => 'wp_login',
			)
		);
	}

	/**
	 * Get the filters.
	 *
	 * @return array The filters.
	 */
	protected static function get_allowed_filters() {
		return array_merge(
			parent::get_allowed_filters(),
			array(
				'mosaml_remember_me_internal'          => 'mo_remember_me',
				'mosaml_add_custom_css_in_sso_button_internal' => 'mo_saml_add_custom_css_in_sso_button',
				'mosaml_before_auto_redirect_internal' => 'mo_saml_before_auto_redirect',
				'mosaml_set_secure_cookie_attribute_internal' => 'mo_saml_set_secure_cookie_attribute',
				'mosaml_skip_check_saml_response_for_reply_attack_internal' => 'mo_saml_skip_check_saml_response_for_reply_attack',
				'mosaml_pre_user_login_internal'       => 'pre_user_login',
				'mosaml_widget_title_internal'         => 'widget_title',
				'mosaml_login_redirect_url_internal'   => 'mosaml_login_redirect_url',
				'mosaml_sanitize_attributes_internal'  => 'mo_saml_sanitize_attributes',
			)
		);
	}
}
