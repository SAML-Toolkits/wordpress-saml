<?php
/**
 * Gatekeeper handler class.
 *
 * @package miniorange-saml-20-single-sign-on/module/base/handler/hook
 */

namespace MOSAML\Module\Base\Handler\Hook;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Abstracts\Hook_Gate_Keeper;

/**
 * Gate_Keeper_Handler class.
 */
class Gate_Keeper_Handler extends Hook_Gate_Keeper {

	/**
	 * Get the added actions.
	 *
	 * @return array The actions.
	 */
	protected static function get_added_actions() {
		return array(
			'mosaml_miniorange_post_authenticate_user_login_internal',
			'mosaml_abr_filter_login_internal',
			'mosaml_custom_sso_error_msg_internal',
			'mosaml_guest_login_internal',
			'mosaml_assign_role_arm_internal',
			'mosaml_attributes_internal',
			'mosaml_flush_cache_internal',
			'mosaml_update_username_internal',
			'mosaml_wp_user_attributes_internal',
			'mosaml_wp_login_internal',
			'mosaml_settings_deleted_internal',
			'mosaml_settings_updated_internal',
			'mosaml_user_register_internal',
		);
	}

	/**
	 * Get the added filters.
	 *
	 * @return array The filters.
	 */
	protected static function get_added_filters() {
		return array(
			'mosaml_remember_me_internal',
			'mosaml_add_custom_css_in_sso_button_internal',
			'mosaml_before_auto_redirect_internal',
			'mosaml_set_secure_cookie_attribute_internal',
			'mosaml_skip_check_saml_response_for_replay_attack_internal',
			'mosaml_pre_user_login_internal',
			'mosaml_widget_title_internal',
			'mosaml_group_separator_internal',
			'mosaml_acs_url_internal',
			'mosaml_add_custom_css_in_shortcode_dropdown_internal',
			'mosaml_api_restricted_message_internal',
			'mosaml_custom_attributes_filter_internal',
			'mosaml_filter_identity_providers_internal',
			'mosaml_logout_url_internal',
			'mosaml_post_login_sso_relay_state_internal',
			'mosaml_post_logout_slo_relay_state_internal',
			'mosaml_post_logout_slo_request_relay_state_internal',
			'mosaml_pre_auto_redirection_internal',
			'mosaml_pre_login_sso_relay_state_internal',
			'mosaml_pre_logout_slo_relay_state_internal',
			'mosaml_sanitize_attributes_internal',
			'mosaml_show_lost_password_url_internal',
			'mosaml_sso_url_internal',
			'mosaml_login_redirect_url_internal',
			'mosaml_idp_slo_triggered_internal',
		);
	}

	/**
	 * Get the actions.
	 *
	 * @return array The actions.
	 */
	protected static function get_allowed_actions() {
		return array();
	}

	/**
	 * Get the filters.
	 *
	 * @return array The filters.
	 */
	protected static function get_allowed_filters() {
		return array();
	}

	/**
	 * Check if the hook is allowed.
	 *
	 * @param string $internal The internal hook.
	 * @param string $type The type of hook.
	 * @return bool True if the hook is allowed, false otherwise.
	 */
	protected static function is_allowed( $internal, $type ) {
		return 'action' === $type ? array_key_exists( $internal, static::get_allowed_actions() ) : array_key_exists( $internal, static::get_allowed_filters() );
	}
}
