<?php
/**
 * Gatekeeper handler class.
 *
 * @package miniorange-saml-20-single-sign-on/module/standard/handler/hook
 */

namespace MOSAML\Module\Standard\Handler\Hook;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Hook\Gate_Keeper_Handler as Base_Gate_Keeper_Handler;

/**
 * Gate_Keeper_Handler class.
 */
class Gate_Keeper_Handler extends Base_Gate_Keeper_Handler {

	/**
	 * Get the actions.
	 *
	 * @return array The actions.
	 */
	protected static function get_allowed_actions() {
		return array_merge(
			parent::get_allowed_actions(),
			array(
				'mosaml_flush_cache_internal'   => 'mo_saml_flush_cache',
				'mosaml_user_register_internal' => 'user_register',
				'mosaml_wp_login_internal'      => 'wp_login',
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
				'mosaml_remember_me_internal'        => 'mo_remember_me',
				'mosaml_filter_identity_providers_internal' => 'mo_saml_filter_identity_providers',
				'mosaml_widget_title_internal'       => 'widget_title',
				'mosaml_login_redirect_url_internal' => 'mosaml_login_redirect_url',
			)
		);
	}
}
