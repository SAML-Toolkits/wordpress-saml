<?php
/**
 * This file is part of miniOrange WP plugin.
 *
 * @package    miniOrange
 * @author     miniOrange Security Software Pvt. Ltd.
 */

namespace MOSAML\LicenseLibrary\Handlers;

use MOSAML\LicenseLibrary\Views\Mo_Options_Addons;
use MOSAML\LicenseLibrary\Classes\Mo_License_Constants;
use MOSAML\LicenseLibrary\Mo_License_Service;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Mo_License_Install_Addon_Handler handles the addon installation functionality.
 */
class Mo_License_Install_Addon_Handler {

	/**
	 * Constructor to initialize the addon handler.
	 */
	public function __construct() {
		add_action( 'wp_ajax_mo_install_addon', array( $this, 'handle_install_addon' ) );
	}

	/**
	 * Handle the AJAX request to install an addon.
	 *
	 * @return void
	 */
	public function handle_install_addon() {
		check_ajax_referer( 'mo_install_addon', 'nonce' );
		if ( ! current_user_can( 'install_plugins' ) ) {
			wp_send_json_error( 'You do not have permission to install plugins.' );
		}

		if ( ! Mo_License_Service::is_customer_logged_into_plugin() ) {
			wp_send_json_error( 'Account is not verified.' );
		}

		if ( ! Mo_License_Service::is_customer_license_verified() ) {
			wp_send_json_error( 'License key is not verified.' );
		}

		$download_url = isset( $_POST['download_url'] ) ? sanitize_text_field( wp_unslash( $_POST['download_url'] ) ) : '';
		$addon_name   = isset( $_POST['addon_name'] ) ? sanitize_text_field( wp_unslash( $_POST['addon_name'] ) ) : '';

		if ( empty( $download_url ) || empty( $addon_name ) || ! filter_var( $download_url, FILTER_VALIDATE_URL ) ) {
			set_transient( 'addon_install_error', 'An error occurred while downloading the plugin.', 10 );
			wp_send_json_error( 'An error occurred while downloading the plugin.' );
		}

		$result = self::install_addon( $download_url, $addon_name );

		if ( is_wp_error( $result ) ) {
			set_transient( 'addon_install_error', $result->get_error_message(), 10 );
			wp_send_json_error( $result->get_error_message() );
		}
		if ( false === $result ) {
			set_transient( 'addon_install_error', 'Failed to install the addon. Please try again.', 10 );
			wp_send_json_error( 'Failed to install the addon. Please try again.' );
		}

		set_transient( 'addon_install_success', $addon_name . ' Addon installed and activated successfully.', 10 );
		wp_send_json_success( 'Addon installed and activated successfully.' );
	}

	/**
	 * Install and activate an addon.
	 *
	 * @param string $download_url The URL to download the addon from.
	 * @param string $addon_name   The name of the addon to install.
	 * @return array|WP_Error|false The result of the installation, WP_Error on download error, or false on failure.
	 */
	public static function install_addon( $download_url, $addon_name ) {

		$response = wp_remote_get( $download_url, array( 'timeout' => 300 ) );

		if ( is_wp_error( $response ) ) {
			return new \WP_Error( 'download_error', 'An error occurred while downloading the addon.' );
		}

		$response_code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $response_code ) {
			switch ( $response_code ) {
				case 400:
					return new \WP_Error( 'download_error_400', 'Addon license is not associated with customer' );

				case 404:
					return new \WP_Error( 'download_error_404', 'Plan not found for Addon: ' . $addon_name );

				case 500:
					return new \WP_Error( 'download_error_500', 'An error occurred while downloading the addon.' );

				default:
					return new \WP_Error( 'download_error', 'An error occurred while downloading the addon.' );
			}
		}

		$body = wp_remote_retrieve_body( $response );
		if ( empty( $body ) ) {
			return new \WP_Error( 'download_error', 'Downloaded file is empty.' );
		}

		return self::install_and_activate_addon( $body, $addon_name );
	}

	/**
	 * Install and activate an addon.
	 *
	 * @param string $body       The body of the addon.
	 * @param string $addon_name The name of the addon to install.
	 * @return array|WP_Error|false The result of the installation, WP_Error on download error, or false on failure.
	 */
	public static function install_and_activate_addon( $body, $addon_name ) {
		$tmp_file = wp_tempnam();
		if ( ! $tmp_file ) {
			return new \WP_Error( 'installation_error', 'Failed to create temporary file for addon installation.' );
		}

		if ( ! function_exists( 'WP_Filesystem' ) ) {
			require_once ABSPATH . Mo_License_Constants::FILE_PATH;
		}

		WP_Filesystem();
		global $wp_filesystem;

		$file_written = $wp_filesystem ? $wp_filesystem->put_contents( $tmp_file, $body, FS_CHMOD_FILE ) : false;
		if ( false === $file_written ) {
			wp_delete_file( $tmp_file );
			return new \WP_Error( 'installation_error', 'Failed to write downloaded addon to temporary location.' );
		}

		$plugin_dir = WP_PLUGIN_DIR;
		$result     = unzip_file( $tmp_file, $plugin_dir );

		if ( is_wp_error( $result ) && class_exists( 'ZipArchive' ) ) {
			$result = self::extract_addon_fallback( $tmp_file, $plugin_dir, $result );
		}

		wp_delete_file( $tmp_file );
		if ( is_wp_error( $result ) ) {
			return new \WP_Error( 'installation_error', 'Failed to extract addon.' );
		}

		Mo_Options_Addons::init();
		$addon_slug = Mo_Options_Addons::mo_get_addon_slug( $addon_name );

		if ( ! $addon_slug ) {
			return new \WP_Error( 'installation_error', 'Addon slug not found for: ' . $addon_name );
		}

		$addon_slug = str_replace( '\\', '/', $addon_slug );

		if ( ! file_exists( WP_PLUGIN_DIR . '/' . $addon_slug ) ) {
			return new \WP_Error( 'installation_error', 'Addon not found after installation.' );
		}

		$activate = activate_plugin( $addon_slug );
		if ( is_wp_error( $activate ) ) {
			return new \WP_Error( 'installation_error', 'Failed to activate addon.' );
		}

		return array( 'success' => true );
	}

	/**
	 * Fallback extraction using ZipArchive::extractTo when unzip_file fails (e.g. copy_failed_ziparchive on Windows).
	 *
	 * @param string     $tmp_file   Path to the downloaded zip file.
	 * @param string     $plugin_dir WP_PLUGIN_DIR.
	 * @param \WP_Error  $previous   The error from unzip_file.
	 * @return true|\WP_Error
	 */
	private static function extract_addon_fallback( $tmp_file, $plugin_dir, $previous ) {
		WP_Filesystem();
		global $wp_filesystem;
		if ( ! $wp_filesystem ) {
			return $previous;
		}

		$zip = new \ZipArchive();
		if ( true !== $zip->open( $tmp_file, \ZipArchive::RDONLY ) ) {
			return $previous;
		}

		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- ZipArchive property name.
		$num_files = $zip->numFiles;
		if ( 0 === $num_files ) {
			$zip->close();
			return $previous;
		}

		for ( $file_index = 0; $file_index < $num_files; $file_index++ ) {
			$entry = $zip->getNameIndex( $file_index );
			if ( false === $entry ) {
				continue;
			}
			$entry = str_replace( '\\', '/', $entry );
			if ( strpos( $entry, '__MACOSX/' ) === 0 || strpos( $entry, '.' ) === 0 ) {
				continue;
			}
			$dest_path = $plugin_dir . '/' . $entry;
			if ( substr( $entry, -1 ) === '/' ) {
				if ( ! is_dir( $dest_path ) && ! wp_mkdir_p( $dest_path ) ) {
					$zip->close();
					return new \WP_Error( 'installation_error', 'Could not create directory: ' . $entry, $entry );
				}
				continue;
			}
			$dir = dirname( $dest_path );
			if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
				$zip->close();
				return new \WP_Error( 'installation_error', 'Could not create directory: ' . dirname( $entry ), $entry );
			}
			$contents = $zip->getFromIndex( $file_index );
			if ( false === $contents ) {
				$contents = $zip->getFromName( $entry );
			}

			if ( false === $contents || $wp_filesystem->put_contents( $dest_path, $contents, FS_CHMOD_FILE ) === false ) {
				$zip->close();
				return new \WP_Error( 'installation_error', 'Could not copy file: ' . $entry, $entry );
			}
		}

		$zip->close();
		return true;
	}

}
