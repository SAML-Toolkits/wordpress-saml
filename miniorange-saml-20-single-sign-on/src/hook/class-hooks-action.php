<?php
/**
 * Hooks Action.
 *
 * @package miniorange-saml-20-single-sign-on/hook
 */

namespace MOSAML\SRC\Hook;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Controller\Menu_Page_Controller;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Constant\Plugin_Files_Constants;
use MOSAML\SRC\Controller\Admin_Init_Controller;
use MOSAML\SRC\Controller\Init_Controller;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Classes\Debug_Logger;
use MOSAML\SRC\Classes\Mo_Customer;
use MOSAML\SRC\Handler\UI\Login_Page_UI_Handler;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Handler\Database_Cleanup_Handler;
use MOSAML\SRC\Controller\Logout_Controller;
use MOSAML\SRC\Handler\UI\Feedback_Form_Handler;
use MOSAML\SRC\Utils\Feature_Control;
use MOSAML\SRC\Handler\Migration\Migration_Initializer;
use MOSAML\SRC\Handler\Migration\Fallback\Fallback_Initializer;

/**
 * Class to handle the actions of all the hooks added in the plugin.
 */
class Hooks_Action {

	/**
	 * Request-level memoization for `pre_option_saml_identity_providers` (keyed by blog + environment).
	 *
	 * @var array<string, array|false>
	 */
	private static $legacy_saml_identity_providers_option_cache = array();

	/**
	 * Request-level memoization for `pre_option_mo_saml_test_config_attrs` (keyed by blog + environment).
	 *
	 * @var array<string, array|false>
	 */
	private static $legacy_mo_saml_test_config_attrs_option_cache = array();

	/**
	 * Activation hook actions.
	 *
	 * @return void
	 */
	public static function activation_hook_actions() {
		ob_start();
		DB_Utils::initialize_database();
		ob_end_clean();
	}

	/**
	 * Deactivation hook actions.
	 *
	 * @return void
	 */
	public static function deactivation_hook_actions( $is_network_deactivation = false ) {
		if ( ! empty( Utility::check_is_extension_installed( Constants::REQUIRED_EXTENSIONS ) ) ) {
			return;
		}

		if ( $is_network_deactivation ) {
			$original_blog_id = get_current_blog_id();
			foreach ( get_sites(
				array(
					'fields' => 'ids',
					'number' => 0,
				)
			)
			as $blog_id ) {
				switch_to_blog( (int) $blog_id );
				Database_Cleanup_Handler::delete_plugin_license_detail();
				Database_Cleanup_Handler::delete_plugin_options_on_deactivation();
			}
			switch_to_blog( $original_blog_id );
			return;
		}

		Database_Cleanup_Handler::delete_plugin_license_detail();
		Database_Cleanup_Handler::delete_plugin_options_on_deactivation();
	}

	/**
	 * Admin menu actions.
	 *
	 * @return void
	 */
	public static function admin_menu_actions() {
		$capability = 'manage_options';

		$page = add_menu_page(
			'miniOrange SAML SSO',
			'miniOrange SAML SSO',
			$capability,
			'mo_saml_settings',
			array( Menu_Page_Controller::class, 'plugin_configuration_page_ui' ),
			plugins_url( 'static/image/miniorange.webp', MOSAML_PLUGIN_FILE )
		);

		add_submenu_page(
			'mo_saml_settings',
			'Plugin Configuration',
			'Plugin Configuration',
			$capability,
			'mo_saml_settings',
			array( Menu_Page_Controller::class, 'plugin_configuration_page_ui' )
		);

		if ( DB_Utils::all_tables_exist() ) {

			add_submenu_page(
				'mo_saml_settings',
				'Multiple Environments',
				'Multiple Environments',
				$capability,
				'mosaml-multiple-environment',
				array( Menu_Page_Controller::class, 'multiple_environment_page_ui' )
			);
		}

		add_submenu_page(
			'mo_saml_settings',
			'Troubleshoot',
			'Troubleshoot',
			$capability,
			'mosaml-troubleshoot',
			array( Menu_Page_Controller::class, 'troubleshoot_page_ui' )
		);

		add_submenu_page(
			'mo_saml_settings',
			'SSO Addons',
			'SSO Addons',
			$capability,
			'mo_saml_settings&tab=addons',
			array( Menu_Page_Controller::class, 'plugin_configuration_page_ui' )
		);

		add_filter( 'submenu_file', array( self::class, 'highlight_addons_submenu' ), 10, 2 );

		$tab    = Utility::sanitize_get_data( 'tab' );
		$action = Utility::sanitize_get_data( 'action' );
		if ( ! empty( $tab ) && 'sp_setup' === $tab && empty( $action ) ) {
			add_action( "load-$page", array( self::class, 'add_screen_options' ) );
			add_action( 'admin_head', array( self::class, 'add_custom_screen_options_filter' ) );
		}
	}

	/**
	 * Highlight SSO Addons submenu when on the Addons tab of plugin settings.
	 *
	 * @param string $submenu_file The submenu file.
	 * @param string $parent_file  The parent file.
	 * @return string
	 */
	public static function highlight_addons_submenu( $submenu_file, $parent_file ) {
		if ( 'mo_saml_settings' === $parent_file && 'addons' === Utility::sanitize_get_data( 'tab' ) ) {
			return 'mo_saml_settings&tab=addons';
		}
		return $submenu_file;
	}

	/**
	 * Add screen options.
	 *
	 * @return void
	 */
	public static function add_screen_options() {
		add_screen_option(
			'per_page',
			array(
				'label'   => 'Items per page',
				'default' => 5,
				'option'  => 'items_per_page',
			)
		);
	}

	/**
	 * Add custom screen options filter.
	 *
	 * @return void
	 */
	public static function add_custom_screen_options_filter() {
		$screen = get_current_screen();
		add_filter( 'manage_' . $screen->id . '_columns', array( self::class, 'manage_screen_options_columns' ) );
	}

	/**
	 * Manage screen options columns.
	 *
	 * @param array $columns Columns.
	 * @return array
	 */
	public static function manage_screen_options_columns( $columns ) {
		$columns = array( 'idp_id' => 'IDP ID' );
		return $columns;
	}

	/**
	 * Add plugin action links.
	 *
	 * @param array $links The links.
	 * @return array The modified links.
	 */
	public static function plugin_action_links( $links ) {
		$settings_link = '<a href="' . admin_url( 'admin.php?page=mo_saml_settings' ) . '">Plugin Configuration</a>';
		$links         = array_merge( array( $settings_link ), $links );
		return $links;
	}

	/**
	 * Set custom screen option.
	 *
	 * @param bool|string $status Status.
	 * @param string      $option Option.
	 * @param int|string  $value Value.
	 * @return bool
	 */
	public static function set_custom_screen_option( $status, $option, $value ) {
		if ( 'items_per_page' === $option ) {
			return $value;
		}
		return $status;
	}

	/**
	 * Admin init actions.
	 *
	 * @return void
	 */
	public static function admin_init_actions() {
		Admin_Init_Controller::instance()->admin_init_actions();

		if ( ! DB_Utils::create_tables_and_initialize() ) {
			update_option( Constants::DATABASE_UPDATE_STATUS, 'failed' );
			Debug_Logger::log( 'MOSAML ERROR: Failed to create tables - migration terminated' );
			return;
		}

		if ( 'completed' !== get_option( Constants::MIGRATION_STATUS ) ) {
			$migration_initializer = new Migration_Initializer();
			$migration_initializer->initialize();
		}

		$sso_user_data = Utility::get_handler_object( 'sso_user_data', true, 'admin' )->get_data(
			array(
				'idp_id'     => DB_Utils::get_default_inserted_idp_details( 'id', DB_Utils::get_environment_details( 'id' ) ),
				'subsite_id' => Utility::get_subsite_id_for_environment( DB_Utils::get_environment_details( 'id', true ) ),
			)
		);
		Utility::get_handler_object( 'sso_user_tag', true, 'config', $sso_user_data )->display_sso_user_tag();

		if ( Utility::any_idp_url_contains_keyword( 'salesforce', null, true ) ) {
			$sf_notice = get_option( 'mo_saml_display_salesforce_products_notice', null );
			if ( null === $sf_notice ) {
				update_option( 'mo_saml_display_salesforce_products_notice', true );
			}
		} else {
			delete_option( 'mo_saml_display_salesforce_products_notice' );
		}

		if ( Utility::any_idp_url_contains_keyword( 'microsoft', null, true ) ) {
			$ms_notice = get_option( 'mo_saml_display_microsoft_products_notice', null );
			if ( null === $ms_notice ) {
				update_option( 'mo_saml_display_microsoft_products_notice', true );
			}
		} else {
			delete_option( 'mo_saml_display_microsoft_products_notice' );
		}
	}

	/**
	 * Hook callback for `login_form`.
	 *
	 * @return void
	 */
	public static function mo_saml_add_login_links() {
		Login_Page_UI_Handler::mo_saml_add_login_links();
	}

	/**
	 * Init actions.
	 *
	 * @return void
	 */
	public static function init_actions() {
		Init_Controller::instance()->init_actions();
		Init_Controller::instance()->init_cli_actions();
		Init_Controller::instance()->control_license_expiry_page();
		add_shortcode( 'MO_SAML_FORM', array( self::class, 'shortcode_mo_saml_form' ) );
		add_shortcode( 'MO_SAML_IDP_LIST', array( self::class, 'shortcode_mo_saml_idp_list' ) );
	}

	/**
	 * Render [MO_SAML_FORM].
	 *
	 * @param array $atts Shortcode attributes.
	 * @return string
	 */
	public static function shortcode_mo_saml_form( $atts ) {
		$handler = Utility::get_handler_object( 'shortcode_data', true, 'Admin' );
		return method_exists( $handler, 'render_form_shortcode' ) ? $handler->render_form_shortcode( $atts ) : '';
	}

	/**
	 * Render [MO_SAML_IDP_LIST].
	 *
	 * @return string
	 */
	public static function shortcode_mo_saml_idp_list() {
		$handler = Utility::get_handler_object( 'shortcode_data', true, 'Admin' );
		return method_exists( $handler, 'render_idp_list_shortcode' ) ? $handler->render_idp_list_shortcode() : '';
	}

	/**
	 * Admin enqueue scripts.
	 *
	 * @return void
	 */
	public static function admin_enqueue_scripts() {
		$current_page = Utility::sanitize_get_data( 'page' );
		if ( ! empty( $current_page ) && in_array( $current_page, Constants::ADMIN_PAGE_SLUGS, true ) ) {
			wp_enqueue_style( 'mo_saml_settings', plugins_url( 'static/css/settings.css', MOSAML_PLUGIN_FILE ), array(), Constants::VERSION_NUMBER[ MOSAML_VERSION ] );
			wp_enqueue_style( 'mosaml_modal', plugins_url( 'static/css/modal.css', MOSAML_PLUGIN_FILE ), array(), Constants::VERSION_NUMBER[ MOSAML_VERSION ] );
			wp_enqueue_script( 'mo_saml_settings', plugins_url( 'static/js/settings.js', MOSAML_PLUGIN_FILE ), array(), Constants::VERSION_NUMBER[ MOSAML_VERSION ], true );
			wp_enqueue_script( 'mosaml_modal', plugins_url( 'static/js/modal.js', MOSAML_PLUGIN_FILE ), array(), Constants::VERSION_NUMBER[ MOSAML_VERSION ], true );
			wp_localize_script(
				'mo_saml_settings',
				'mosamlSettings',
				array(
					'version'          => MOSAML_VERSION,
					'featureAvailable' => Feature_Control::free_or_license_specific_feature_enabled(),
				)
			);
			wp_enqueue_script( 'mosaml-color-script', plugins_url( 'static/js/jscolor/jscolor.js', MOSAML_PLUGIN_FILE ), array(), Constants::VERSION_NUMBER[ MOSAML_VERSION ], true );
			wp_enqueue_style( 'mosaml-phone-style', plugins_url( 'static/css/phone.css', MOSAML_PLUGIN_FILE ), array(), Constants::VERSION_NUMBER[ MOSAML_VERSION ] );
			wp_enqueue_script( 'mosaml-phone-script', plugins_url( 'static/js/phone.js', MOSAML_PLUGIN_FILE ), array(), Constants::VERSION_NUMBER[ MOSAML_VERSION ], true );

			self::license_admin_enqueue_scripts();
		}

		$screen = get_current_screen();
		if ( $screen && 'plugins' === $screen->id ) {
			wp_enqueue_style( 'mosaml-feedback-form', plugins_url( 'static/css/feedback-form.css', MOSAML_PLUGIN_FILE ), array(), Constants::VERSION_NUMBER[ MOSAML_VERSION ] );
			wp_enqueue_script( 'mosaml-feedback-form', plugins_url( 'static/js/feedback-form.js', MOSAML_PLUGIN_FILE ), array( 'jquery' ), Constants::VERSION_NUMBER[ MOSAML_VERSION ], true );
			wp_localize_script(
				'mosaml-feedback-form',
				'mosamlFeedback',
				array(
					'ajaxurl' => admin_url( 'admin-ajax.php' ),
				)
			);
		}

		$mosaml_advertise_notice_active = get_option( 'mo_saml_display_salesforce_products_notice' ) || get_option( 'mo_saml_display_microsoft_products_notice' );
		$mosaml_on_plugin_admin_screen  = ! empty( $current_page ) && in_array( $current_page, Constants::ADMIN_PAGE_SLUGS, true );
		if ( $mosaml_advertise_notice_active && ! $mosaml_on_plugin_admin_screen ) {
			wp_enqueue_style(
				'mo_saml_settings',
				plugins_url( 'static/css/settings.css', MOSAML_PLUGIN_FILE ),
				array(),
				Constants::VERSION_NUMBER[ MOSAML_VERSION ]
			);
		}
	}

	/**
	 * License admin enqueue scripts.
	 *
	 * @return void
	 */
	public static function license_admin_enqueue_scripts() {
		if ( Utility::get_active_tab() === 'account_settings' ) {
			$unformatted_expiry_date = Utility::handle_license_calls( 'get_expiry_date', 'library', '' );
			$expiry_date             = Utility::handle_license_calls( 'get_formatted_license_expiry_date', 'library', '', $unformatted_expiry_date );
			$remaining_days          = Utility::handle_license_calls( 'get_remaining_days', 'library', '', $expiry_date );

			wp_enqueue_script( 'mo-saml-ajax', plugins_url( 'static/js/mo_saml_ajax.js', MOSAML_PLUGIN_FILE ), array(), Constants::VERSION_NUMBER[ MOSAML_VERSION ], true );

			wp_localize_script(
				'mo-saml-ajax',
				'moSamlAjax',
				array(
					'ajax_url'       => admin_url( 'admin-ajax.php' ),
					'nonce'          => wp_create_nonce( 'mosaml_sync_license_ajax_nonce' ),
					'remaining_days' => $remaining_days,
				)
			);
		}
	}

	/**
	 * AJAX callback to sync license.
	 *
	 * @return void
	 */
	public static function license_sync_callback() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array() );
			return;
		}

		if ( ! check_ajax_referer( 'mosaml_sync_license_ajax_nonce' ) ) {
			wp_send_json_error( array() );
			return;
		}

		Utility::handle_license_calls( 'sync_license', 'library' );

		$unformatted_expiry_date = Utility::handle_license_calls( 'get_expiry_date', 'library', '' );
		$expiry_date             = Utility::handle_license_calls( 'get_formatted_license_expiry_date', 'library', '', $unformatted_expiry_date );
		$remaining_days          = Utility::handle_license_calls( 'get_remaining_days', 'library', '', $expiry_date );

		$response = array(
			'message'        => 'License synced successfully!',
			'last_synced'    => gmdate( 'M d, Y H:i:s' ),
			'remaining_days' => $remaining_days,
			'expiry_date'    => $expiry_date,
		);
		wp_send_json_success( $response );
	}

	/**
	 * AJAX callback to sync license via license expiry page.
	 *
	 * @return void
	 */
	public static function expiry_page_license_sync() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'You are not authorized to perform this action.' ) );
		}

		if ( ! isset( $_POST['nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['nonce'] ) ), 'mosaml_grace_notice_nonce' ) ) {
			wp_send_json_error( array( 'message' => 'Invalid nonce' ) );
		}

		Utility::handle_license_calls( 'sync_license', 'library' );

		$license_status = Utility::handle_license_calls( 'is_license_expired', 'library', array() );
		if ( ! $license_status['STATUS'] && 'LICENSE_IN_GRACE' !== $license_status['CODE'] ) {
			wp_send_json_success( array( 'message' => 'You have successfully synced your license.' ) );
		}

		wp_send_json_error( array( 'message' => 'You have not renewed your license yet.' ) );
	}

	/**
	 * AJAX callback to deactivate plugin.
	 *
	 * @return void
	 */
	public static function ajax_deactivate_plugin() {
		$plugin_file = plugin_basename( MOSAML_PLUGIN_DIR ) . '/login.php';
		if ( ! current_user_can( 'manage_options' ) || ! current_user_can( 'deactivate_plugins' ) ) {
			wp_send_json_error( array( 'message' => 'You are not authorized to deactivate the plugin' ) );
		}
		if ( ! isset( $_POST['nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['nonce'] ) ), 'mosaml_grace_notice_nonce' ) ) {
			wp_send_json_error( array( 'message' => 'Invalid nonce' ) );
		}
		if ( ! function_exists( 'deactivate_plugins' ) ) {
			require_once ABSPATH . Plugin_Files_Constants::WP_ADMIN_INCLUDES_PLUGIN_FILE;
		}

		$customer = new Mo_Customer();
		$email    = get_option( 'mo_saml_admin_email' );
		$phone    = get_option( 'mo_saml_admin_phone' );
		$query    = 'Plugin deactivated';
		$response = $customer->submit_contact_us( $email, $phone, $query, true );

		/**
		 * This action is used to deactivate the plugin.
		 *
		 * @param string $plugin_file The plugin file.
		 * @return void
		 */
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core hook pattern for plugin deactivation.
		do_action( 'deactivate_' . $plugin_file );
		deactivate_plugins( $plugin_file );

		wp_send_json_success( array( 'message' => 'Plugin deactivated successfully' ) );
	}

	/**
	 * AJAX callback to change environment.
	 *
	 * @return void
	 */
	public static function ajax_change_environment() {
		if ( ! check_ajax_referer( 'mosaml_change_environment', 'nonce' ) || ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error(
				array(
					'message' => 'Unauthorized request',
				),
				403
			);
		}

		$environment_name = Utility::sanitize_post_data( 'environment' );
		if ( empty( $environment_name ) ) {
			wp_send_json_error(
				array(
					'message' => 'Environment not found',
				),
				400
			);
		}

		$environment_exists = DB_Utils::get_records(
			Constants::DATABASE_TABLE_NAMES['environments'],
			array( 'environment_name' => $environment_name ),
			true
		);

		if ( ! $environment_exists ) {
			wp_send_json_error(
				array(
					'message' => 'Environment not found',
				),
				400
			);
		}

		$selected_environment = DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['environments'], array( 'selected' => true ) );
		if ( $selected_environment ) {
			foreach ( $selected_environment as $environment ) {
				DB_Utils::insert_or_update( Constants::DATABASE_TABLE_NAMES['environments'], array( 'selected' => false ), array( 'id' => $environment->id ) );
			}
		}

		DB_Utils::insert_or_update( Constants::DATABASE_TABLE_NAMES['environments'], array( 'selected' => true ), array( 'environment_name' => $environment_name ) );

		wp_send_json_success(
			array(
				'message' => 'Environment changed successfully',
			),
			200
		);
	}

	/**
	 * Site status tests.
	 *
	 * @param array $tests Tests.
	 * @return array
	 */
	public static function site_status_tests( $tests ) {
		$tests['direct']['mosaml_debug_log'] = array(
			'label' => 'miniOrange SAML Debug Log',
			'test'  => array( Debug_Logger::class, 'debug_log_enabled_warning' ),
		);
		return $tests;
	}

	/**
	 * Login footer actions.
	 *
	 * @return void
	 */
	public static function login_footer_actions() {
		if ( 4 !== MOSAML_VERSION || ! Feature_Control::check_is_license_verified() ) {
			return;
		}

		$handler = Utility::get_handler_object( 'login_footer_action_data', true, 'core' );
		$handler->login_footer_actions();
	}

	/**
	 * Login ajax action.
	 *
	 * @return WP_Error|WP_REST_Response
	 */
	public static function mosaml_fetch_domain_mapping() {
		check_ajax_referer( 'mosaml_fetch_domain_mapping_ajax_nonce' );
		$handler = Utility::get_handler_object( 'login_footer_action_data', true, 'core' );
		return $handler->fetch_domain_mapping( Utility::sanitize_get_data( 'userEmail' ) );
	}

	/**
	 * Handle metadata sync cron.
	 *
	 * @param string|null $idp_id The IDP ID (optional for backward compatibility with legacy cron events).
	 * @return void
	 */
	public static function handle_metadata_sync_cron( $idp_id = null ) {
		if ( empty( $idp_id ) ) {
			return;
		}
		$handler = Utility::get_handler_object( 'metadata_sync_data', true, 'Admin' );
		$handler->handle_metadata_sync_cron( $idp_id );
	}

	/**
	 * Add custom cron schedules.
	 *
	 * @param array $schedules Existing schedules.
	 * @return array Modified schedules with custom intervals.
	 */
	public static function custom_cron_schedule( $schedules ) {
		$schedules['monthly'] = array(
			'interval' => 2629746, // 1 month in seconds
			'display'  => __( 'Once Monthly', 'miniorange-saml-20-single-sign-on' ),
		);
		return $schedules;
	}

	/**
	 * WP logout action.
	 *
	 * @param int $user_id The user ID.
	 * @return void
	 */
	public static function wp_logout_action( $user_id ) {
		( new Logout_Controller() )->control_logout_flow( $user_id );
	}

	/**
	 * WP logout filter.
	 *
	 * @param string $redirect_to The redirect to.
	 * @param string $requested_redirect_to The requested redirect to.
	 * @param object $user The user.
	 * @return void
	 */
	public static function wp_logout_filter( $redirect_to, $requested_redirect_to, $user ) {
		( new Logout_Controller() )->control_logout_flow( $user->ID, $redirect_to );
	}

	/**
	 * WP actions.
	 *
	 * @return void
	 */
	public static function wp_actions() {
		if ( 1 !== MOSAML_VERSION && ! Feature_Control::check_is_license_verified() ) {
			return;
		}

		$handler = Utility::get_handler_object( 'site_auto_redirection', true, 'core' );
		$handler->handle_site_auto_redirection();
	}

	/**
	 * WP authenticate actions.
	 *
	 * @return void
	 */
	public static function wp_authenticate_actions() {
		if ( 1 !== MOSAML_VERSION && ! Feature_Control::check_is_license_verified() ) {
			return;
		}

		$handler = Utility::get_handler_object( 'login_page_auto_redirection', true, 'core' );
		$handler->handle_login_page_auto_redirection();
	}

	/**
	 * WP get custom columns.
	 *
	 * @param array $columns The columns.
	 * @return array The modified columns.
	 */
	public static function wp_get_custom_columns( $columns ) {
		$handler = Utility::get_handler_object( 'show_custom_attributes', true, 'config' );
		return $handler->mo_saml_custom_attr_column( $columns );
	}

	/**
	 * WP custom column content.
	 *
	 * @param string $output The output to be displayed for the columns speficied.
	 * @param string $column_name The column name where output to be displayed.
	 * @param int    $user_id The user for which output to be displayed.
	 * @return string The modified output.
	 */
	public static function wp_custom_column_content( $output, $column_name, $user_id ) {
		$handler = Utility::get_handler_object( 'show_custom_attributes', true, 'config' );
		return $handler->mo_saml_attr_column_content( $output, $column_name, $user_id );
	}

	/**
	 * Register SAML login widget.
	 * Uses module-specific widget handler based on active module.
	 *
	 * @return void
	 */
	public static function register_saml_widget() {
		if ( 1 !== MOSAML_VERSION && ! Feature_Control::check_is_license_verified() ) {
			return;
		}

		$widget_instance = Utility::get_handler_object( 'widget_ui', true, 'ui' );
		register_widget( get_class( $widget_instance ) );
	}

	/**
	 * Hook callback for `login_form` to modify login form.
	 *
	 * @return void
	 */
	public static function mo_saml_modify_login_form() {
		Login_Page_UI_Handler::mo_saml_modify_login_form();
	}

	/**
	 * Admin notices actions.
	 *
	 * @return void
	 */
	public static function admin_notices_actions() {
		require_once Plugin_Files_Constants::TEMPLATE_DATABASE_UPDATE_ADMIN_NOTICE;

		if ( get_option( 'mo_saml_display_salesforce_products_notice' ) ) {
			ob_start();
			require_once Plugin_Files_Constants::TEMPLATE_ADVERTISE_NOTICES_SALESFORCE;
			$notice_content = ob_get_clean();
			$notice_type    = 'salesforce';
			require Plugin_Files_Constants::TEMPLATE_ADVERTISE_PRODUCTS_NOTICE;
		}

		if ( get_option( 'mo_saml_display_microsoft_products_notice' ) ) {
			ob_start();
			require_once Plugin_Files_Constants::TEMPLATE_ADVERTISE_NOTICES_AZURE;
			$notice_content = ob_get_clean();
			$notice_type    = 'microsoft';
			require Plugin_Files_Constants::TEMPLATE_ADVERTISE_PRODUCTS_NOTICE;
		}
	}
	/**
	 * Display feedback form on plugins page.
	 *
	 * @return void
	 */
	public static function admin_footer_actions() {
		$screen = get_current_screen();
		if ( ! $screen || 'plugins' !== $screen->id ) {
			return;
		}

		$feedback_handler = new Feedback_Form_Handler();
		$feedback_handler->display_feedback_modal();
	}

	/**
	 * AJAX handler for skipping feedback.
	 *
	 * @return void
	 */
	public static function ajax_skip_feedback() {
		check_ajax_referer( 'mosaml_skip_feedback' );
		wp_send_json_success();
	}

	/**
	 * Dismiss Salesforce / Microsoft product admin notice: store false so it stays hidden while IdP URL still matches.
	 *
	 * @return void
	 */
	public static function ajax_close_advertise_products_notice() {
		check_ajax_referer( 'mo_saml_close_advertise_products_notice' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to dismiss this notice.', 'miniorange-saml-20-single-sign-on' ), '', array( 'response' => 403 ) );
		}

		$notice_type = isset( $_POST['notice_type'] ) ? sanitize_text_field( wp_unslash( $_POST['notice_type'] ) ) : '';

		if ( 'salesforce' === $notice_type ) {
			update_option( 'mo_saml_display_salesforce_products_notice', false );
		} 
		if ( 'microsoft' === $notice_type ) {
			update_option( 'mo_saml_display_microsoft_products_notice', false );
		}

		$redirect = wp_get_referer();
		if ( ! $redirect || false !== strpos( $redirect, 'admin-ajax.php' ) ) {
			$redirect = admin_url();
		}

		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * Get legacy data fallback.
	 *
	 * @param object $handler The handler object.
	 * @param array  $where The where conditions.
	 * @return object The legacy data fallback.
	 */
	public static function mosaml_legacy_data_fallback_object( $handler, $where = array() ) {
		return Fallback_Initializer::initialize( $handler, $where );
	}

	/**
	 * Supplies legacy `saml_identity_providers` option shape from custom tables for add-on compatibility.
	 *
	 * When the DB-backed IDP store is not available or has no usable rows, returns false so core
	 * can fall back to the real option value (or default).
	 *
	 * @param mixed  $pre_option Value passed through pre_option (typically false).
	 * @param string $option     Option name.
	 * @param mixed  $default    Default passed to get_option.
	 * @return array|false
	 */
	public static function mo_saml_get_legacy_idp_option( $pre_option, $option = '', $default = false ) {
		unset( $pre_option, $option, $default );

		if ( Utility::is_legacy_data_fallback_required() ) {
			return false;
		}

		$environment_id = DB_Utils::get_environment_details( 'id', true );
		if ( '' === $environment_id || null === $environment_id ) {
			return false;
		}

		$cache_key = (string) Utility::get_subsite_id_for_environment( $environment_id ) . '|' . (string) $environment_id;
		if ( isset( self::$legacy_saml_identity_providers_option_cache[ $cache_key ] ) ) {
			return self::$legacy_saml_identity_providers_option_cache[ $cache_key ];
		}

		$handler = Utility::get_handler_object( 'sp_setup_data', true, 'admin' );
		if ( ! $handler || ! is_object( $handler ) || ! method_exists( $handler, 'get_data' ) ) {
			self::$legacy_saml_identity_providers_option_cache[ $cache_key ] = false;
			return false;
		}

		$idp_rows = $handler->get_data(
			array(
				'environment_id' => $environment_id,
			),
			false
		);

		if ( empty( $idp_rows ) || ! is_array( $idp_rows ) ) {
			self::$legacy_saml_identity_providers_option_cache[ $cache_key ] = false;
			return false;
		}

		$legacy = array();
		foreach ( $idp_rows as $idp ) {
			if ( ! is_object( $idp ) ) {
				continue;
			}
			if ( isset( $idp->idp_name ) && 'All IDPs' === $idp->idp_name ) {
				continue;
			}

			$idp_key = ! empty( $idp->idp_id ) ? $idp->idp_id : ( isset( $idp->id ) ? (string) $idp->id : '' );
			if ( '' === $idp_key ) {
				continue;
			}

			$legacy[ $idp_key ] = self::map_idp_object_to_legacy_option_entry( $idp );
		}

		if ( empty( $legacy ) ) {
			self::$legacy_saml_identity_providers_option_cache[ $cache_key ] = false;
			return false;
		}

		/**
		 * Filters the legacy associative array returned for `get_option( 'saml_identity_providers' )`.
		 *
		 * @param array $legacy     Map of idp_id => legacy IDP configuration.
		 * @param array $idp_rows   Raw IDP objects from {@see \MOSAML\Module\Base\Handler\Admin\SP_Setup_Data_Handler::get_data()}.
		 * @param mixed $environment_id Current environment ID.
		 */
		$legacy = apply_filters( 'mosaml_pre_option_saml_identity_providers', $legacy, $idp_rows, $environment_id );

		if ( ! is_array( $legacy ) || empty( $legacy ) ) {
			self::$legacy_saml_identity_providers_option_cache[ $cache_key ] = false;
			return false;
		}

		self::$legacy_saml_identity_providers_option_cache[ $cache_key ] = $legacy;
		return $legacy;
	}

	/**
	 * Maps an SP setup data object to one legacy `saml_identity_providers` entry.
	 *
	 * @param object $idp IDP row object from {@see \MOSAML\Module\Base\Handler\Admin\SP_Setup_Data_Handler::get_data()}.
	 * @return array<string, mixed>
	 */
	private static function map_idp_object_to_legacy_option_entry( $idp ) {
		$sso_binding = isset( $idp->sso_binding ) && '' !== $idp->sso_binding ? $idp->sso_binding : 'HttpRedirect';
		$slo_binding = isset( $idp->slo_binding ) && '' !== $idp->slo_binding ? $idp->slo_binding : 'HttpRedirect';

		$nameid_format = isset( $idp->name_id_format ) ? (string) $idp->name_id_format : '';
		$urn_prefix    = 'urn:oasis:names:tc:SAML:';
		if ( '' !== $nameid_format && 0 === strpos( $nameid_format, $urn_prefix ) ) {
			$nameid_format = substr( $nameid_format, strlen( $urn_prefix ) );
		}

		$certs = self::normalize_legacy_x509_certificate( isset( $idp->idp_certificate ) ? $idp->idp_certificate : null );
		if ( empty( $certs ) ) {
			$certs = array( '' );
		}

		$is_active = isset( $idp->status ) && 'active' === $idp->status;

		return array(
			'idp_name'                       => isset( $idp->idp_id ) ? (string) $idp->idp_id : '',
			'idp_display_name'                => isset( $idp->idp_name ) ? (string) $idp->idp_name : '',
			'idp_entity_id'                  => isset( $idp->entity_id ) ? (string) $idp->entity_id : '',
			'saml_sp_entity_id'              => isset( $idp->sp_entity_id ) ? (string) $idp->sp_entity_id : '',
			'sso_url'                        => isset( $idp->sso_url ) ? (string) $idp->sso_url : '',
			'sso_binding_type'               => $sso_binding,
			'slo_url'                        => isset( $idp->slo_url ) ? (string) $idp->slo_url : '',
			'slo_response_url'               => isset( $idp->slo_response_url ) ? (string) $idp->slo_response_url : '',
			'slo_binding_type'               => $slo_binding,
			'x509_certificate'               => $certs,
			'response_signed'                => 'Yes',
			'assertion_signed'               => 'Yes',
			'request_signed'                 => self::mo_saml_idp_flag_to_legacy_checked( isset( $idp->sign_sso_slo_request ) ? $idp->sign_sso_slo_request : null ),
			'nameid_format'                  => $nameid_format,
			'mo_saml_encoding_enabled'       => self::mo_saml_to_legacy_checked_setting( isset( $idp->character_encoding ) ? $idp->character_encoding : null, true ),
			'mo_saml_assertion_time_validity' => self::mo_saml_to_legacy_checked_setting( isset( $idp->assertion_time_validity ) ? $idp->assertion_time_validity : null, true ),
			'enable_idp'                     => $is_active ? 1 : 0,
		);
	}

	/**
	 * Normalizes stored certificate value to a zero-indexed list of PEM strings.
	 *
	 * @param mixed $cert Certificate string, list of strings, or serialized data.
	 * @return array<int, string>
	 */
	private static function normalize_legacy_x509_certificate( $cert ) {
		if ( empty( $cert ) && '0' !== $cert ) {
			return array();
		}
		if ( is_string( $cert ) ) {
			$cert = trim( $cert );
			return '' === $cert ? array() : array( $cert );
		}
		if ( ! is_array( $cert ) ) {
			return array();
		}
		$out = array();
		foreach ( $cert as $piece ) {
			if ( ! is_string( $piece ) ) {
				continue;
			}
			$piece = trim( $piece );
			if ( '' !== $piece ) {
				$out[] = $piece;
			}
		}
		return array_values( $out );
	}

	/**
	 * Maps sign_sso_slo_request DB values to legacy checkbox token.
	 *
	 * @param mixed $value Raw value.
	 * @return string 'checked' or empty string.
	 */
	private static function mo_saml_idp_flag_to_legacy_checked( $value ) {
		if ( true === $value || 1 === $value || '1' === $value ) {
			return 'checked';
		}
		if ( is_string( $value ) ) {
			if ( 'checked' === $value ) {
				return 'checked';
			}
			if ( '' === $value || 'unchecked' === $value ) {
				return '';
			}
		}
		return ! empty( $value ) ? 'checked' : '';
	}

	/**
	 * Maps boolean-ish and checkbox-style values to legacy 'checked' or ''.
	 *
	 * @param mixed $value         Raw value.
	 * @param bool  $default_checked When value is null/empty, whether legacy default is checked (matches SP setup defaults).
	 * @return string
	 */
	private static function mo_saml_to_legacy_checked_setting( $value, $default_checked = true ) {
		if ( null === $value || '' === $value ) {
			return $default_checked ? 'checked' : '';
		}
		if ( true === $value || 1 === $value || '1' === $value || 'checked' === $value ) {
			return 'checked';
		}
		if ( false === $value || 0 === $value || '0' === $value || 'unchecked' === $value ) {
			return '';
		}
		return ! empty( $value ) ? 'checked' : '';
	}

	/**
	 * Supplies legacy `mo_saml_test_config_attrs` option shape from `idp_details.test_config_attributes`.
	 *
	 * @param mixed  $pre_option Value passed through pre_option (typically false).
	 * @param string $option     Option name.
	 * @param mixed  $default    Default passed to get_option.
	 * @return array|false
	 */
	public static function mo_saml_get_legacy_test_config_attrs( $pre_option, $option = '', $default = false ) {
		unset( $pre_option, $option, $default );

		if ( Utility::is_legacy_data_fallback_required() ) {
			return false;
		}

		$environment_id = DB_Utils::get_environment_details( 'id', true );
		if ( '' === $environment_id || null === $environment_id ) {
			return false;
		}

		$cache_key = (string) Utility::get_subsite_id_for_environment( $environment_id ) . '|' . (string) $environment_id;
		if ( isset( self::$legacy_mo_saml_test_config_attrs_option_cache[ $cache_key ] ) ) {
			return self::$legacy_mo_saml_test_config_attrs_option_cache[ $cache_key ];
		}

		$handler = Utility::get_handler_object( 'test_config_data', true, 'admin' );
		$class   = is_object( $handler ) ? get_class( $handler ) : '';
		if ( '' === $class || ! is_callable( array( $class, 'get_all_test_configs' ) ) ) {
			self::$legacy_mo_saml_test_config_attrs_option_cache[ $cache_key ] = false;
			return false;
		}

		$raw = call_user_func( array( $class, 'get_all_test_configs' ) );
		if ( empty( $raw ) || ! is_array( $raw ) ) {
			self::$legacy_mo_saml_test_config_attrs_option_cache[ $cache_key ] = false;
			return false;
		}

		$legacy = array();
		foreach ( $raw as $idp_key => $attrs ) {
			$idp_key = is_scalar( $idp_key ) ? (string) $idp_key : '';
			if ( '' === $idp_key ) {
				continue;
			}
			$normalized = self::normalize_legacy_mo_saml_test_config_attrs_entry( $attrs );
			if ( ! empty( $normalized ) ) {
				$legacy[ $idp_key ] = $normalized;
			}
		}

		if ( empty( $legacy ) ) {
			self::$legacy_mo_saml_test_config_attrs_option_cache[ $cache_key ] = false;
			return false;
		}

		/**
		 * Filters the legacy associative array returned for `get_option( 'mo_saml_test_config_attrs' )`.
		 *
		 * @param array $legacy         Map of idp_id => attribute map (each value is an array of strings).
		 * @param array $raw            Raw maps from {@see \MOSAML\Module\Base\Handler\Admin\Test_Config_Data_Handler::get_all_test_configs()}.
		 * @param mixed $environment_id Current environment ID.
		 */
		$legacy = apply_filters( 'mosaml_pre_option_mo_saml_test_config_attrs', $legacy, $raw, $environment_id );

		if ( ! is_array( $legacy ) || empty( $legacy ) ) {
			self::$legacy_mo_saml_test_config_attrs_option_cache[ $cache_key ] = false;
			return false;
		}

		self::$legacy_mo_saml_test_config_attrs_option_cache[ $cache_key ] = $legacy;
		return $legacy;
	}

	/**
	 * Normalizes one IdP's test attributes to the legacy option structure.
	 *
	 * @param mixed $attrs Raw attribute map.
	 * @return array<string, array<int, string>>
	 */
	private static function normalize_legacy_mo_saml_test_config_attrs_entry( $attrs ) {
		if ( ! is_array( $attrs ) ) {
			return array();
		}

		$out = array();
		foreach ( $attrs as $key => $value ) {
			if ( 'sanitize_further' === $key ) {
				continue;
			}
			$nkey = self::normalize_legacy_test_config_attribute_key( $key );
			if ( '' === $nkey ) {
				continue;
			}
			$out[ $nkey ] = self::coerce_attribute_values_to_legacy_arrays( $value );
		}

		return $out;
	}

	/**
	 * Maps attribute keys to legacy-friendly names where appropriate.
	 *
	 * @param mixed $key Attribute key from SAML or internal data.
	 * @return string
	 */
	private static function normalize_legacy_test_config_attribute_key( $key ) {
		$k = is_scalar( $key ) ? (string) $key : '';
		if ( '' === $k ) {
			return '';
		}
		$lower = strtolower( $k );
		if ( 'nameid' === $lower ) {
			return 'NameID';
		}
		$simple = array( 'nickname', 'firstname', 'lastname', 'email', 'roles' );
		if ( in_array( $lower, $simple, true ) ) {
			return $lower;
		}
		return $k;
	}

	/**
	 * Ensures each attribute value is represented as a list of strings (legacy add-on expectation).
	 *
	 * @param mixed $value Raw value.
	 * @return array<int, string>
	 */
	private static function coerce_attribute_values_to_legacy_arrays( $value ) {
		if ( is_array( $value ) ) {
			return self::flatten_mixed_items_to_legacy_attribute_list( $value );
		}

		if ( is_string( $value ) ) {
			return self::coerce_string_to_legacy_attribute_list( $value );
		}

		if ( is_bool( $value ) ) {
			return array( $value ? 'true' : 'false' );
		}

		if ( is_numeric( $value ) ) {
			return array( (string) $value );
		}

		if ( null === $value ) {
			return array( '' );
		}

		return array( wp_json_encode( $value ) );
	}

	/**
	 * Flattens nested arrays into a single list of string values.
	 *
	 * @param array $value Raw list or nested structure.
	 * @return array<int, string>
	 */
	private static function flatten_mixed_items_to_legacy_attribute_list( array $value ) {
		$flat = array();
		foreach ( $value as $item ) {
			if ( is_array( $item ) ) {
				foreach ( self::coerce_attribute_values_to_legacy_arrays( $item ) as $n ) {
					$flat[] = $n;
				}
			} elseif ( is_scalar( $item ) ) {
				$flat[] = (string) $item;
			} else {
				$flat[] = wp_json_encode( $item );
			}
		}

		return array_values( $flat );
	}

	/**
	 * Interprets a string as JSON (when it looks like an array/object) or wraps it as a single value.
	 *
	 * @param string $value Raw string.
	 * @return array<int, string>
	 */
	private static function coerce_string_to_legacy_attribute_list( $value ) {
		$trim = trim( $value );
		if ( '' !== $trim && isset( $trim[0] ) && ( '[' === $trim[0] || '{' === $trim[0] ) ) {
			$decoded = json_decode( $trim, true );
			if ( is_array( $decoded ) ) {
				return self::coerce_attribute_values_to_legacy_arrays( $decoded );
			}
		}

		return array( $value );
	}

	/**
	 * Plugins loaded actions.
	 *
	 * @return void
	 */
	public static function plugins_loaded_actions() {
		Utility::get_handler_object( 'gate_keeper', true, 'hook' )->init();
	}

	/**
	 * Adds third-party relay state hosts to WordPress allowed redirect hosts.
	 *
	 * External hosts from IdP login/logout relay state URLs are whitelisted
	 * only when third-party redirects are explicitly enabled.
	 *
	 * @param string[] $allowed_hosts Allowed redirect hosts.
	 * @return string[] Updated allowed redirect hosts.
	 */
	public static function allow_external_redirect_hosts( $allowed_hosts ) {
		if ( Feature_Control::is_feature_disabled( 3 ) ) {
			return $allowed_hosts;
		}

		$identity_providers = DB_Utils::get_configured_idps_details( 'id' );
		$site_host          = wp_parse_url( get_site_url(), PHP_URL_HOST );
		foreach ( $identity_providers as $idp ) {
			$relay_state_data = Utility::get_handler_object(
				'relay_state_data',
				true,
				'admin'
			)->get_data(
				array(
					'idp_id' => $idp,
				)
			);

			if ( empty( $relay_state_data ) || 'checked' !== $relay_state_data->allow_third_party_relay_state ) {
				continue;
			}

			foreach ( array( 'login_relay_state', 'logout_relay_state' ) as $key ) {
				if ( empty( $relay_state_data->$key ) ) {
					continue;
				}

				$parsed_url = wp_parse_url( $relay_state_data->$key );
				if ( ! empty( $parsed_url['host'] ) && $parsed_url['host'] !== $site_host ) {
					$allowed_hosts[] = $parsed_url['host'];
				}
			}
		}

		return array_unique( $allowed_hosts );
	}

	/**
	 * Filter to logout users from all sessions in currrent system if enabled in idp settings.
	 *
	 * @param string $name_id_value NameID value of the user.
	 * @param string $idp_name      IDP name.
	 *
	 * @return void
	 */
	public static function mosaml_logout_users_all_sessions( $name_id_value, $idp_name ) {

		$idp_details           = Utility::get_handler_object( 'sp_setup_data', true, 'admin' )->get_data( array( 'idp_name' => $idp_name ) );
		$force_complete_logout = Utility::get_handler_object( 'logout_all_sessions_data', true, 'admin' )->get_data(
			array(
				'idp_id'      => $idp_details->id,
				'option_name' => 'saml_force_complete_logout',
			)
		);
		if ( $force_complete_logout && 'checked' === $force_complete_logout->saml_force_complete_logout ) {

			$attribute_handler = Utility::get_handler_object( 'attribute_mapping_data', true, 'admin' )->get_data(
				array(
					'idp_id'      => $idp_details->id,
					'option_name' => 'user_name',
				)
			);

			if ( $attribute_handler ) {
				if ( 'NameID' === $attribute_handler->option_value ) {
					$user = get_user_by( 'login', $name_id_value );
				}

				if ( empty( $user ) || empty( $user->ID ) ) {
					$user = get_user_by( 'email', $name_id_value );
				}

				wp_set_current_user( $user->ID );
				wp_destroy_all_sessions();
			}
		}
	}

	/**
	 * Sanitize SAML attributes.
	 *
	 * This function applies `sanitize_text_field()` recursively to all attributes
	 * if the 'sanitize_further' flag is set. It then removes the 'sanitize_further'
	 * key before returning the sanitized attributes.
	 *
	 * @param array $attrs The array of SAML attributes.
	 * @return array Sanitized SAML attributes.
	 */
	public static function sanitize_saml_attrs( $attrs ) {

		if ( ! empty( $attrs ) && $attrs['sanitize_further'] ) {
			$attrs = map_deep( $attrs, 'sanitize_text_field' );
		}
		unset( $attrs['sanitize_further'] );
		return $attrs;
	}
}
