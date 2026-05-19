<?php
/**
 * Import Export Config Handler.
 *
 * Provides helper methods to export and import plugin configuration tables as JSON.
 *
 * @package MOSAML\SRC\Handler\Import_Export
 */

namespace MOSAML\SRC\Handler\Import_Export;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Traits\Instance;
use MOSAML\SRC\Database\Database_Migrator;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Classes\Debug_Logger;
use MOSAML\SRC\Constant\Plugin_Files_Constants;

/**
 * Import Export Config Handler.
 */
class Import_Export_Config_Handler {

	use Instance;

	/**
	 * Export plugin configuration tables to a JSON string.
	 *
	 * @return void|string JSON representation of exported data or empty string on failure.
	 */
	public static function export_plugin_configuration() {
		try {
			$data = self::prepare_configurations();

			$config_backup_file_name = 'mosaml-backup-configuration-' . gmdate( 'Ymd-His' ) . '.json';

			header( 'Content-Type: application/json' );
			header( "Content-Disposition: attachment; filename=$config_backup_file_name" );

			echo wp_json_encode( $data, JSON_PRETTY_PRINT );
			Error_Success_Message::show_admin_notice( '<strong>Export plugin configuration in file ' . $config_backup_file_name . '.</strong>', 'SUCCESS' );
			exit;
		} catch ( \Exception $e ) {
			Error_Success_Message::show_admin_notice( '<strong>Export Failed:</strong> Could not export configuration.' );
			exit;
		}
	}

	/**
	 * Import plugin configuration from a JSON string.
	 *
	 * @param array $data The decoded JSON data to import.
	 * @return void
	 */
	public static function import_config_from_json( $data ) {
		Utility::start_output_buffering();

		try {
			global $wpdb;

			if ( empty( $data['configuration'] ) || ! is_array( $data['configuration'] ) ) {
				Error_Success_Message::show_admin_notice( '<strong>Import Failed:</strong> Could not import configuration.' );
				Utility::clean_output_buffer();
				exit;
			}

			foreach ( Constants::DATABASE_TABLE_NAMES as $table ) {
				if ( ! array_key_exists( $table, $data['configuration'] ) ) {
					Error_Success_Message::show_admin_notice( '<strong>Import Failed:</strong> The imported file has missing table \'' . $table . '\'' );
					Utility::clean_output_buffer();
					exit;
				}
			}

			self::backup_existing_configuration();

			if ( isset( $wpdb ) ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
				$wpdb->query( 'START TRANSACTION' ); // Start DB Transaction.
			}

			DB_Utils::truncate_table_data();

			foreach ( Constants::DATABASE_TABLE_NAMES as $table ) {
				$full_table = $wpdb->prefix . $table;
				$rows       = $data['configuration'][ $table ];

				foreach ( $rows as $row ) {
					// Ensure foreign key constraints are satisfied.
					if ( Constants::DATABASE_TABLE_NAMES['idp_details'] === $table && empty( $row['environment_id'] ) ) {
						$row['environment_id'] = DB_Utils::get_environment_details( 'id' );
					}
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
					$wpdb->insert( $full_table, $row );
				}
			}

			update_option( Constants::KEEP_SETTINGS_OPTION_NAME, 'checked' );
			update_option( Constants::ENABLE_BACKUP_SETTINGS, 'checked' );
			update_option( Constants::SEND_PLUGIN_CONFIG_OPTION_NAME, 'checked' );
			$latest = Database_Migrator::get_latest_migration_version();
			update_option( Constants::DB_VERSION_OPTION_NAME, $latest ? $latest : Constants::DB_VERSION );
			update_option( Constants::DATABASE_UPDATE_STATUS, 'completed' );
			update_option( Constants::MIGRATION_STATUS, 'completed' );

			$enable_multiple_environments = ! empty( $data['meta']['enable_multiple_environments'] ) ? $data['meta']['enable_multiple_environments'] : '';
			if ( MOSAML_VERSION >= 4 && 'checked' === $enable_multiple_environments ) {
				update_option( Constants::ENABLE_MULTIPLE_ENVIRONMENTS_OPTION_NAME, 'checked' );
			} else {
				update_option( Constants::ENABLE_MULTIPLE_ENVIRONMENTS_OPTION_NAME, '' );
			}

			if ( isset( $wpdb ) ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
				$wpdb->query( 'COMMIT' );
			}
			DB_Utils::initialize_environment_table( str_replace( ' ', '_', get_bloginfo( 'name' ) ), Utility::parse_environment_url( site_url() ) );

			Error_Success_Message::show_admin_notice( '<strong>Import Success:</strong> Configuration imported successfully.', 'SUCCESS' );
			Utility::clean_output_buffer();
		} catch ( \Throwable $t ) {
			if ( isset( $wpdb ) ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
				$wpdb->query( 'ROLLBACK' );
			}
			Debug_Logger::log( 'Import failed: ' . $t->getMessage() );
			Error_Success_Message::show_admin_notice( '<strong>Import Failed:</strong> Could not import configuration.' );
			Utility::clean_output_buffer();
			exit;
		}
	}

	/**
	 * Backup existing configuration.
	 *
	 * @return void
	 */
	public static function backup_existing_configuration() {
		try {
			$data = self::prepare_configurations();

			if ( ! Debug_Logger::create_debug_log_folder_if_not_exists() ) {
				return;
			}

			$backup_dir              = Debug_Logger::get_plugin_debug_log_directory();
			$config_backup_file_name = 'mosaml-backup-configuration-' . gmdate( 'Ymd-His' ) . '.json';
			$filepath                = $backup_dir . DIRECTORY_SEPARATOR . $config_backup_file_name;

			if ( ! function_exists( 'WP_Filesystem' ) ) {
				require_once ABSPATH . Plugin_Files_Constants::WP_ADMIN_INCLUDES_FILE;
			}
			WP_Filesystem();
			global $wp_filesystem;
			if ( ! $wp_filesystem || ! is_object( $wp_filesystem ) ) {
				return;
			}

			$wp_filesystem->put_contents( $filepath, wp_json_encode( $data, JSON_PRETTY_PRINT ), FS_CHMOD_FILE );

			Debug_Logger::log( "Auto-backup created at: {$filepath}" );
		} catch ( \Exception $e ) {
			Debug_Logger::log( 'Auto-backup of existing configuration failed at the time of import' );
			return;
		}
	}

	/**
	 * Prepare configurations.
	 *
	 * @return array The prepared configurations.
	 */
	public static function prepare_configurations() {
		global $wpdb;
		$data = array(
			'meta'          => array(
				'plugin_version'               => Constants::VERSION_NUMBER[ MOSAML_VERSION ],
				'db_version'                   => Constants::DB_VERSION,
				'enable_multiple_environments' => get_option( Constants::ENABLE_MULTIPLE_ENVIRONMENTS_OPTION_NAME ),
				'common_codebase'              => true,
				'exported_at'                  => gmdate( 'c' ),
			),
			'configuration' => array(),
		);

		foreach ( Constants::DATABASE_TABLE_NAMES as $table ) {
			if ( ! in_array( $table, Constants::DATABASE_TABLE_NAMES, true ) ) {
				continue;
			}
			$full_table = $wpdb->prefix . $table;
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- $full_table is built from a fixed allowlist.
			$rows = $wpdb->get_results( "SELECT * FROM {$full_table}", ARRAY_A );

			$data['configuration'][ $table ] = $rows;
		}
		$data['version_dependencies'] = array(
			'php_version'       => phpversion(),
			'wordpress_version' => get_bloginfo( 'version' ),
			'openssl'           => Utility::is_extension_installed( 'openssl' ),
			'curl'              => Utility::is_extension_installed( 'curl' ),
			'iconv'             => Utility::is_extension_installed( 'iconv' ),
			'dom'               => Utility::is_extension_installed( 'dom' ),
		);
		return $data;
	}
}
