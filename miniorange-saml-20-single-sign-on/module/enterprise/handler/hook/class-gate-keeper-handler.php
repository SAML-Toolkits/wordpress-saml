<?php
/**
 * Gatekeeper class.
 *
 * @package miniorange-saml-20-single-sign-on/module/enterprise/handler/hook
 */

namespace MOSAML\Module\Enterprise\Handler\Hook;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Hook\Gate_Keeper_Handler as Premium_Gate_Keeper_Handler;

/**
 * Gate_Keeper_Handler class.
 */
class Gate_Keeper_Handler extends Premium_Gate_Keeper_Handler {

	/**
	 * Get the actions.
	 *
	 * @return array The actions.
	 */
	protected static function get_allowed_actions() {
		return array_merge(
			parent::get_allowed_actions(),
			array(
				'mosaml_miniorange_post_authenticate_user_login_internal' => 'miniorange_post_authenticate_user_login',
				'mosaml_abr_filter_login_internal'     => 'mo_abr_filter_login',
				'mosaml_custom_sso_error_msg_internal' => 'mo_custom_sso_error_msg',
				'mosaml_guest_login_internal'          => 'mo_guest_login',
				'mosaml_assign_role_arm_internal'      => 'mo_saml_assign_role_arm',
				'mosaml_attributes_internal'           => 'mo_saml_attributes',
				'mosaml_flush_cache_internal'          => 'mo_saml_flush_cache',
				'mosaml_update_username_internal'      => 'mo_saml_update_username',
				'mosaml_wp_user_attributes_internal'   => 'mo_wp_user_attributes',
				'mosaml_wp_login_internal'             => 'wp_login',
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
				'mosaml_group_separator_internal'          => 'mo_group_separator',
				'mosaml_remember_me_internal'              => 'mo_remember_me',
				'mosaml_acs_url_internal'                  => 'mo_saml_acs_url',
				'mosaml_add_custom_css_in_shortcode_dropdown_internal' => 'mo_saml_add_custom_css_in_shortcode_dropdown',
				'mosaml_add_custom_css_in_sso_button_internal' => 'mo_saml_add_custom_css_in_sso_button',
				'mosaml_api_restricted_message_internal'   => 'mo_saml_api_restricted_message',
				'mosaml_custom_attributes_filter_internal' => 'mo_saml_custom_attributes_filter',
				'mosaml_logout_url_internal'               => 'mo_saml_logout_url',
				'mosaml_post_login_sso_relay_state_internal' => 'mo_saml_post_login_sso_relay_state',
				'mosaml_post_logout_slo_relay_state_internal' => 'mo_saml_post_logout_slo_relay_state',
				'mosaml_post_logout_slo_request_relay_state_internal' => 'mo_saml_post_logout_slo_request_relay_state',
				'mosaml_pre_auto_redirection_internal'     => 'mo_saml_pre_auto_redirection',
				'mosaml_pre_login_sso_relay_state_internal' => 'mo_saml_pre_login_sso_relay_state',
				'mosaml_pre_logout_slo_relay_state_internal' => 'mo_saml_pre_logout_slo_relay_state',
				'mosaml_sanitize_attributes_internal'      => 'mo_saml_sanitize_attributes',
				'mosaml_set_secure_cookie_attribute_internal' => 'mo_saml_set_secure_cookie_attribute',
				'mosaml_show_lost_password_url_internal'   => 'mo_saml_show_lost_password_url',
				'mosaml_skip_check_saml_response_for_replay_attack_internal' => 'mo_saml_skip_check_saml_response_for_replay_attack',
				'mosaml_sso_url_internal'                  => 'mo_saml_sso_url',
				'mosaml_pre_user_login_internal'           => 'pre_user_login',
				'mosaml_widget_title_internal'             => 'widget_title',
				'mosaml_login_redirect_url_internal'       => 'mosaml_login_redirect_url',
				'mosaml_idp_slo_triggered_internal'        => 'mo_saml_idp_slo_triggered',
			)
		);
	}
}
