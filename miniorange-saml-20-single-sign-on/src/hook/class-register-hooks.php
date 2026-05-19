<?php
/**
 * Register hooks for the plugin.
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\SRC\Hook;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Classes\Debug_Logger;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Utils\Utility;

/**
 * Register hooks for the plugin.
 */
class Register_Hooks {

	/**
	 * Register only the hooks needed to show the admin menu and missing-extensions notice.
	 * Called first; when extensions are missing, no other hooks are registered.
	 *
	 * @return void
	 */
	public static function register_necessary_hooks() {
		register_activation_hook( MOSAML_PLUGIN_FILE, array( Hooks_Action::class, 'activation_hook_actions' ) );
		register_deactivation_hook( MOSAML_PLUGIN_FILE, array( Hooks_Action::class, 'deactivation_hook_actions' ) );
		add_action( 'admin_menu', array( Hooks_Action::class, 'admin_menu_actions' ) );
		add_action( 'admin_notices', array( Hooks_Action::class, 'admin_notices_actions' ) );
	}

	/**
	 * Register hooks for the plugin.
	 * Registers necessary hooks first, then checks extensions; if any are missing, stops.
	 */
	public static function register_hooks() {
		self::register_necessary_hooks();

		if ( ! empty( Utility::check_is_extension_installed( Constants::REQUIRED_EXTENSIONS ) ) ) {
			return;
		}

		add_action( 'admin_init', array( Hooks_Action::class, 'admin_init_actions' ) );
		add_action( 'admin_init', array( Debug_Logger::class, 'debug_log_actions' ) );
		add_action( 'init', array( Hooks_Action::class, 'init_actions' ) );
		add_action( 'admin_enqueue_scripts', array( Hooks_Action::class, 'admin_enqueue_scripts' ) );
		add_filter( 'set-screen-option', array( Hooks_Action::class, 'set_custom_screen_option' ), 10, 3 );
		add_action( 'plugin_action_links_' . plugin_basename( MOSAML_PLUGIN_FILE ), array( Hooks_Action::class, 'plugin_action_links' ) );
		add_action( 'login_form', array( Hooks_Action::class, 'mo_saml_add_login_links' ), 15, 0 );
		add_action( 'login_form', array( Hooks_Action::class, 'mo_saml_modify_login_form' ), 10, 0 );
		add_filter( 'site_status_tests', array( Hooks_Action::class, 'site_status_tests' ) );
		add_action( 'login_footer', array( Hooks_Action::class, 'login_footer_actions' ) );
		add_action( 'wp_ajax_nopriv_mosaml_fetch_domain_mapping', array( Hooks_Action::class, 'mosaml_fetch_domain_mapping' ) );
		add_action( Constants::METADATA_SYNC_CRON_HOOK, array( Hooks_Action::class, 'handle_metadata_sync_cron' ), 10, 1 );
		add_filter( 'cron_schedules', array( Hooks_Action::class, 'custom_cron_schedule' ) ); // phpcs:ignore WordPress.WP.CronInterval.ChangeDetected -- Interval is set in callback.
		add_action( 'wp', array( Hooks_Action::class, 'wp_actions' ) );
		add_action( 'wp_authenticate', array( Hooks_Action::class, 'wp_authenticate_actions' ) );
		add_filter( 'manage_users_columns', array( Hooks_Action::class, 'wp_get_custom_columns' ) );
		add_filter( 'manage_users_custom_column', array( Hooks_Action::class, 'wp_custom_column_content' ), 1, 3 );
		add_action( 'widgets_init', array( Hooks_Action::class, 'register_saml_widget' ) );
		add_action( 'admin_footer', array( Hooks_Action::class, 'admin_footer_actions' ) );
		add_action( 'wp_ajax_mosaml_skip_feedback', array( Hooks_Action::class, 'ajax_skip_feedback' ) );
		add_action( 'wp_ajax_mosaml_sync_license_on_expiry', array( Hooks_Action::class, 'license_sync_callback' ) );
		add_action( 'wp_ajax_mosaml_expiry_page_license_sync', array( Hooks_Action::class, 'expiry_page_license_sync' ) );
		add_action( 'wp_ajax_mosaml_deactivate_plugin', array( Hooks_Action::class, 'ajax_deactivate_plugin' ) );
		add_action( 'wp_ajax_mosaml_change_environment', array( Hooks_Action::class, 'ajax_change_environment' ) );
		add_action( 'wp_ajax_mo_saml_close_advertise_products_notice', array( Hooks_Action::class, 'ajax_close_advertise_products_notice' ) );
		add_action( 'plugins_loaded', array( Hooks_Action::class, 'plugins_loaded_actions' ), PHP_INT_MIN );
		add_filter( 'allowed_redirect_hosts', array( Hooks_Action::class, 'allow_external_redirect_hosts' ), 10, 1 );
		add_filter( 'mo_saml_sanitize_attributes', array( Hooks_Action::class, 'sanitize_saml_attrs' ), 10 );

		global $wp_version;
		if ( (float) $wp_version < 5.5 && (float) $wp_version > 5.2 ) {
			add_filter( 'logout_redirect', array( Hooks_Action::class, 'wp_logout_filter' ), 10, 3 );
		} else {
			add_action( 'wp_logout', array( Hooks_Action::class, 'wp_logout_action' ), 1, 1 );
		}

		add_filter( 'mo_saml_idp_slo_triggered', array( Hooks_Action::class, 'mosaml_logout_users_all_sessions' ), 10, 2 );

		add_filter( 'mosaml_legacy_data_fallback_object', array( Hooks_Action::class, 'mosaml_legacy_data_fallback_object' ), 10, 2 );
		add_filter( 'pre_option_saml_identity_providers', 'mo_saml_get_legacy_idp_option', 10, 3 );
		add_filter( 'pre_option_mo_saml_test_config_attrs', 'mo_saml_get_legacy_test_config_attrs', 10, 3 );

		$mowi_hooks_handler = Utility::get_handler_object( 'mowi_hooks', true, 'hook' );
		if ( $mowi_hooks_handler ) {
			$mowi_hooks_handler->init();
		}
	}
}
