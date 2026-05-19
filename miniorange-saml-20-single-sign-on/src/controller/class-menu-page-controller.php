<?php
/**
 * Admin Menu Controller.
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\SRC\Controller;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Constant\Plugin_Files_Constants;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Certificate_Utility;
use MOSAML\SRC\Database\Table_Queries;
use MOSAML\Module\Base\Handler\Admin\Certificate_Data_Handler;

/**
 * Plugin UI Controller.
 *
 * @package miniorange-saml-20-single-sign-on
 */
class Menu_Page_Controller {

	/**
	 * If required PHP extensions are missing, render the missing-extensions template and return true.
	 * Call at the start of admin page callbacks so the plugin menu still loads.
	 *
	 * @return bool True if template was rendered (caller should return), false otherwise.
	 */
	public static function maybe_render_missing_extensions_and_exit() {
		$missing_extensions = Utility::check_is_extension_installed( Constants::REQUIRED_EXTENSIONS );
		if ( empty( $missing_extensions ) ) {
			return false;
		}
		require_once Plugin_Files_Constants::TEMPLATE_MISSING_EXTENSIONS;
		return true;
	}

	/**
	 * Render the admin menu UI.
	 *
	 * @return void
	 */
	public static function plugin_configuration_page_ui() {
		if ( self::maybe_render_missing_extensions_and_exit() ) {
			return;
		}
		$db_update_status = get_option( Constants::DATABASE_UPDATE_STATUS );
		if ( ! DB_Utils::all_tables_exist() || 'failed' === $db_update_status ) {

			if ( 'failed' === $db_update_status ) {
				$suffix          = '_table_query';
				$existing_tables = DB_Utils::existing_tables( Constants::DATABASE_TABLE_NAMES );
				$existing_tables = array_map( fn( $key ) => $key . $suffix, array_keys( $existing_tables ) );

				$table_queries_object = new Table_Queries();
				$all_table_queries    = get_object_vars( $table_queries_object );

				$tables_to_show_sql_queries = array_diff( array_keys( $all_table_queries ), $existing_tables );
			}
		}

		$active_tab = Utility::sanitize_get_data( 'tab' );
		if ( empty( $active_tab ) || ! array_key_exists( $active_tab, Constants::TABS ) ) {
			$active_tab = Utility::get_active_tab();
		}
		$certificate_expired = false;
		$certificate_data     = ( new Certificate_Data_Handler() )->get_data();
		$remaining_days       = Certificate_Utility::get_remaining_days_of_certificate( $certificate_data->public_key ?? '' );
		$certificate_expired  = $remaining_days < 0;
		$template_handler             = Utility::get_handler_object( $active_tab . '_ui', false, 'ui' );
		$sidebar_ui_handler           = Utility::get_handler_object( 'plugin_sidebar_ui', false, 'ui' );
		$multiple_environment_handler = Utility::get_handler_object( 'multiple_environments_data', true, 'admin' )->get_data();
		require_once Plugin_Files_Constants::TEMPLATE_ADMIN_MENU_PAGE;
		require_once Plugin_Files_Constants::TEMPLATE_CUSTOM_MODAL;
	}

	/**
	 * Render the multiple environment page UI.
	 *
	 * @return void
	 */
	public static function multiple_environment_page_ui() {
		if ( self::maybe_render_missing_extensions_and_exit() ) {
			return;
		}
		$sidebar_ui_handler = Utility::get_handler_object( 'plugin_sidebar_ui', false, 'ui' );
		$active_tab         = Utility::sanitize_get_data( 'tab' );
		if ( empty( $active_tab ) || ! array_key_exists( $active_tab, Constants::MULTIPLE_ENVIRONMENTS_TABS ) ) {
			$active_tab = 'manage_multiple_environments';
		}
		$template_handler = Utility::get_handler_object( $active_tab . '_ui', false, 'ui' );
		require_once Plugin_Files_Constants::TEMPLATE_MULTIPLE_ENVIRONMENT_MENU_PAGE;
	}

	/**
	 * Render the debug log page UI.
	 *
	 * @return void
	 */
	public static function troubleshoot_page_ui() {
		if ( self::maybe_render_missing_extensions_and_exit() ) {
			return;
		}
		$active_tab = Utility::sanitize_get_data( 'tab' );
		if ( empty( $active_tab ) || ! array_key_exists( $active_tab, Constants::TABS ) ) {
			$active_tab = 'debug_logger';
		}
		$template_handler   = Utility::get_handler_object( $active_tab . '_ui', false, 'ui' );
		$sidebar_ui_handler = Utility::get_handler_object( 'plugin_sidebar_ui', false, 'ui' );
		require_once Plugin_Files_Constants::TEMPLATE_TROUBLESHOOT_MENU_PAGE;
	}
}
