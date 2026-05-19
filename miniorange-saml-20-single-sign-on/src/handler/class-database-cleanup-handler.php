<?php
/**
 * Database Cleanup Handler
 *
 * Drops the plugin-created database tables and deletes the license details.
 *
 * @package miniorange-saml-20-single-sign-on/src/handler
 */

namespace MOSAML\SRC\Handler;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Constant\Constants;

/**
 * Class to cleanup the database.
 *
 * @package MOSAML\SRC\Handler
 */
class Database_Cleanup_Handler {

	/**
	 * Drop all plugin-created tables .
	 *
	 * @return void
	 */
	public static function drop_plugin_tables_and_options_on_uninstall() {
		$keep_settings_intact = get_option( Constants::KEEP_SETTINGS_OPTION_NAME );
		if ( 'checked' === $keep_settings_intact ) {
			return;
		}

		self::drop_plugin_tables_and_options();
	}

	/**
	 * Drop the plugin tables and options.
	 *
	 * @return void
	 */
	public static function drop_plugin_tables_and_options() {
		$tables = array(
			Constants::DATABASE_TABLE_NAMES['role_mapping'],
			Constants::DATABASE_TABLE_NAMES['sso_settings'],
			Constants::DATABASE_TABLE_NAMES['attribute_mapping'],
			Constants::DATABASE_TABLE_NAMES['idp_details'],
			Constants::DATABASE_TABLE_NAMES['sp_metadata'],
			Constants::DATABASE_TABLE_NAMES['subsites'],
			Constants::DATABASE_TABLE_NAMES['environments'],
		);

		DB_Utils::drop_tables( $tables );
		self::delete_plugin_options();
	}

	/**
	 * Delete license details from the database.
	 *
	 * @return void
	 */
	public static function delete_plugin_license_detail() {
		Utility::handle_license_calls( 'remove_account_from_plugin_deactivation', 'both' );
	}

	/**
	 * Delete all plugin options from the database.
	 *
	 * @param bool $preserve_migration_options Whether to preserve legacy migration options during import/export operations.
	 * @return void
	 */
	public static function delete_plugin_options( $preserve_migration_options = false ) {
		$options_to_delete = array(
			Constants::DB_VERSION_OPTION_NAME,
			Constants::ENABLE_MULTIPLE_ENVIRONMENTS_OPTION_NAME,
			Constants::SEND_PLUGIN_CONFIG_OPTION_NAME,
			Constants::KEEP_SETTINGS_OPTION_NAME,
			Constants::ENABLE_BACKUP_SETTINGS,
			Constants::DEBUG_LOG_FILE_PATH_OPTION_NAME,
			Constants::ADMIN_NOTICE_MESSAGE_OPTION_NAME,
			Constants::DATABASE_UPDATE_STATUS,
			Constants::DATABASE_SETUP_COMPLETED_OPTION_NAME,
			Constants::DISMISSED_DATABASE_UPDATE_REQUIRED_NOTICE_OPTION_NAME,
			'mo-saml-plugin-timer',
			'widget_mosaml_login_widget',
		);

		if ( ! $preserve_migration_options ) {
			$options_to_delete[] = Constants::MIGRATION_STATUS;
		}

		foreach ( $options_to_delete as $option ) {
			delete_option( $option );
		}
	}

	/**
	 * Delete the plugin options on deactivation.
	 *
	 * @return void
	 */
	public static function delete_plugin_options_on_deactivation() {
		$options_to_delete = array(
			Constants::DATABASE_UPDATE_STATUS,
			Constants::DATABASE_SETUP_COMPLETED_OPTION_NAME,
			Constants::DISMISSED_DATABASE_UPDATE_REQUIRED_NOTICE_OPTION_NAME,
		);

		foreach ( $options_to_delete as $option ) {
			delete_option( $option );
		}
	}
}
