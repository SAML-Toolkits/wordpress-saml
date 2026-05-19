<?php
/**
 * Update Framework Utility Class
 *
 * This class contains utility functions for the Update Framework.
 * These functions were extracted from the main Mo_Update_Framework class
 * to improve code organization and maintainability.
 *
 * @package MiniOrange\SAML\License\Handler
 * @since 1.0.0
 */

namespace MOSAML\LicenseLibrary\Classes;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use DateTime;
use MOSAML\LicenseLibrary\Mo_License_Config;
use MOSAML\LicenseLibrary\Utils\Mo_License_API_Utility;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use stdClass;
use ZipArchive;

/**
 * Class Mo_Update_Framework_Utility
 *
 * Contains utility functions for plugin update operations.
 */
class Mo_Update_Framework_Utility {

	/**
	 * Generate an authentication token for secure API communication.
	 *
	 * Creates a SHA-512 hash using customer key, current timestamp, and API key
	 * to authenticate requests to the remote update server.
	 *
	 * @return string The generated authentication hash.
	 */
	public static function get_auth_token() {
		$customer_key           = get_option( Mo_License_Config::CUSTOMER_OPTIONS['id'] );
		$api_key                = get_option( Mo_License_Config::CUSTOMER_OPTIONS['apiKey'] );
		$current_time_in_millis = round( microtime( true ) * 1000 );

		/* Creating the Hash using SHA-512 algorithm */
		$string_to_hash = $customer_key . number_format( $current_time_in_millis, 0, '', '' ) . $api_key;
		$hash_value     = hash( 'sha512', $string_to_hash );
		return $hash_value;
	}

	/**
	 * Get license information with fallback values.
	 *
	 * Returns license plan name and type, using fallback values if the license
	 * framework classes are not available (e.g., after plugin upgrade from microservice).
	 *
	 * @return array Array containing 'plan_name' and 'type' keys.
	 */
	public static function get_license_info() {
		return array(
			'plan_name' => Mo_License_Config::LICENSE_PLAN_NAME,
			'type'      => Mo_License_Config::LICENSE_TYPE,
		);
	}

	/**
	 * Create a ZIP archive from a source directory or file.
	 *
	 * Recursively compresses a directory or single file into a ZIP archive.
	 * Used for creating backup archives before plugin updates.
	 *
	 * @param string $source      The source directory or file path to compress.
	 * @param string $destination The destination ZIP file path.
	 * @return bool True on success, false on failure.
	 */
	public static function zip_data( $source, $destination ) {
		if ( extension_loaded( 'zip' ) && file_exists( $source ) && count( glob( $source . DIRECTORY_SEPARATOR . '*' ) ) !== 0 ) {
			$zip = new ZipArchive();
			if ( $zip->open( $destination, ZIPARCHIVE::CREATE ) ) {
				$source = realpath( $source );
				if ( is_dir( $source ) === true ) {
					$iterator = new RecursiveDirectoryIterator( $source );
					// Skip dot files while iterating.
					$iterator->setFlags( RecursiveDirectoryIterator::SKIP_DOTS );
					$files = new RecursiveIteratorIterator( $iterator, RecursiveIteratorIterator::SELF_FIRST );

					foreach ( $files as $file ) {
						$file = realpath( $file );
						if ( is_dir( $file ) === true ) {
							$zip->addEmptyDir( str_replace( $source . DIRECTORY_SEPARATOR, '', $file . DIRECTORY_SEPARATOR ) );
						} elseif ( is_file( $file ) === true ) {
							// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading local file into zip archive.
							$zip->addFromString( str_replace( $source . DIRECTORY_SEPARATOR, '', $file ), file_get_contents( $file ) );
						}
					}
				} elseif ( is_file( $source ) ) {
					// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading local file into zip archive.
					$zip->addFromString( basename( $source ), file_get_contents( $source ) );
				}
			}
			return $zip->close();
		}
		return false;
	}

	/**
	 * Create a backup directory and copy plugin files before updating.
	 *
	 * Creates a backup directory in the WordPress uploads folder and copies
	 * all plugin files to ensure a safe rollback option if the update fails.
	 *
	 * @param string $current_version The current version of the plugin.
	 * @return void
	 */
	public static function create_backup_dir( $current_version ) {
		if ( ! Mo_License_Config::allow_backup() ) {
			return;
		}

		$plugin_file = WP_PLUGIN_DIR . '/' . Mo_License_Config::PLUGIN_FILE;
		$dir         = rtrim( plugin_dir_path( $plugin_file ), '/' . \DIRECTORY_SEPARATOR );

		$plugin_dir_name  = Mo_License_Config::PLUGIN_BACKUP_ZIP_NAME;
		$uploads_dir      = wp_upload_dir();
		$base_uploads_dir = $uploads_dir['basedir'];
		$uploads_dir      = rtrim( $base_uploads_dir, '/' );
		$backup_path      = $uploads_dir . DIRECTORY_SEPARATOR . 'backup' . DIRECTORY_SEPARATOR . $plugin_dir_name . '-backup-' . $current_version;
		if ( ! file_exists( $backup_path ) ) {
			mkdir( $backup_path, 0777, true ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir
		}

		$source      = $dir;
		$destination = $backup_path;

		self::copy_files_to_backup_dir( $source, $destination );
	}

	/**
	 * Recursively copy plugin files to the backup directory.
	 *
	 * Copies all files and subdirectories from the plugin directory to the
	 * backup location, preserving the directory structure for a complete backup.
	 *
	 * @param string $dir         The source directory to copy from.
	 * @param string $backup_path The destination backup directory path.
	 * @return void
	 */
	public static function copy_files_to_backup_dir( $dir, $backup_path ) {
		if ( is_dir( $dir ) ) {
			$plugin_dir_content = scandir( $dir );
		}

		if ( empty( $plugin_dir_content ) ) {
			return;
		}

		foreach ( $plugin_dir_content as $content ) {
			if ( '.' === $content || '..' === $content ) {
				continue;
			}
			$plugin_sub_dir = $dir . DIRECTORY_SEPARATOR . $content;
			$backup_sub_dir = $backup_path . DIRECTORY_SEPARATOR . $content;
			if ( is_dir( $plugin_sub_dir ) ) {
				if ( ! file_exists( $backup_sub_dir ) ) {
					mkdir( $backup_sub_dir, 0777, true ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir
				}
				self::copy_files_to_backup_dir( $plugin_sub_dir, $backup_sub_dir );
			} else {
				copy( $plugin_sub_dir, $backup_sub_dir ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_copy
			}
		}
	}

	/**
	 * Generate current timestamp in milliseconds.
	 *
	 * @return string Formatted timestamp.
	 */
	public static function get_current_timestamp() {
		$current_time_in_millis = round( microtime( true ) * 1000 );
		return number_format( $current_time_in_millis, 0, '', '' );
	}

	/**
	 * Build download URL for plugin updates.
	 *
	 * @param string $plugin_slug            The plugin slug.
	 * @param string $hash_value             The authentication hash.
	 * @param string $current_time_in_millis The current timestamp.
	 * @param string $current_version        The current version.
	 * @return string The complete download URL.
	 */
	public static function build_download_url( $plugin_slug, $hash_value, $current_time_in_millis, $current_version ) {
		$license_info = self::get_license_info();
		return Mo_License_URL::PLUGIN_DOWNLOAD_URL . '?pluginSlug=' .
			$plugin_slug . '&licensePlanName=' . $license_info['plan_name'] . '&customerId=' . get_option( Mo_License_Config::CUSTOMER_OPTIONS['id'] ) .
			'&licenseType=' . $license_info['type'] . '&authToken=' . $hash_value . '&otpToken=' . $current_time_in_millis . '&version=' . $current_version;
	}

	/**
	 * Create basic update object with common properties.
	 *
	 * @param string $slug           The plugin slug.
	 * @param string $plugin_slug    The full plugin slug.
	 * @param string $new_version    The new version.
	 * @param array  $remote_version The remote version data.
	 * @return stdClass The update object.
	 */
	public static function create_update_object( $slug, $plugin_slug, $new_version, $remote_version ) {
		$obj              = new stdClass();
		$obj->slug        = $slug;
		$obj->new_version = $new_version;
		$obj->url         = 'https://miniorange.com';
		$obj->plugin      = $plugin_slug;
		$obj->tested      = $remote_version['cmsCompatibilityVersion'];
		$obj->icons       = array( '1x' => $remote_version['icon'] );
		$obj->status_code = $remote_version['status'];

		return $obj;
	}

	/**
	 * Create plugin information object for WordPress API.
	 *
	 * @param string $slug         The plugin slug.
	 * @param string $plugin_slug  The full plugin slug.
	 * @param array  $remote_info  The remote information data.
	 * @param array  $wp_api_data  The WordPress API data.
	 * @return stdClass The plugin information object.
	 */
	public static function create_plugin_info_object( $slug, $plugin_slug, $remote_info, $wp_api_data = array() ) {
		$remote_obj                 = new stdClass();
		$remote_obj->slug           = $slug;
		$remote_obj->name           = $remote_info['pluginName'];
		$remote_obj->plugin         = $plugin_slug;
		$remote_obj->version        = $remote_info['newVersion'];
		$remote_obj->new_version    = $remote_info['newVersion'];
		$remote_obj->tested         = $remote_info['cmsCompatibilityVersion'];
		$remote_obj->requires       = $remote_info['cmsMinVersion'];
		$remote_obj->requires_php   = $remote_info['phpMinVersion'];
		$remote_obj->compatibility  = array( $remote_info['cmsCompatibilityVersion'] );
		$remote_obj->url            = $remote_info['cmsPluginUrl'];
		$remote_obj->author         = $remote_info['pluginAuthor'];
		$remote_obj->author_profile = $remote_info['pluginAuthorProfile'];
		$remote_obj->last_updated   = $remote_info['lastUpdated'];
		$remote_obj->banners        = array( 'low' => $remote_info['banner'] );
		$remote_obj->icons          = array( '1x' => $remote_info['icon'] );

		// Add WordPress API data if available.
		if ( ! empty( $wp_api_data ) ) {
			$remote_obj->active_installs = $wp_api_data['active_installs'] ?? false;
			$remote_obj->rating          = $wp_api_data['rating'] ?? false;
			$remote_obj->ratings         = $wp_api_data['ratings'] ?? false;
			$remote_obj->num_ratings     = $wp_api_data['num_ratings'] ?? false;
		}

		$remote_obj->reviews  = true;
		$remote_obj->external = '';
		$remote_obj->homepage = $remote_info['homepage'];

		return $remote_obj;
	}

	/**
	 * Add sections to plugin info object.
	 *
	 * @param stdClass $remote_obj   The plugin info object.
	 * @param array    $remote_info  The remote information data.
	 * @param string   $description  The description.
	 * @param string   $reviews      The reviews.
	 * @return void
	 */
	public static function add_plugin_info_sections( $remote_obj, $remote_info, $description = '', $reviews = '' ) {
		$remote_obj->sections = array(
			'changelog'           => $remote_info['changelog'],
			'license_information' => $remote_info['licenseInformation'],
			'description'         => $description,
			'Reviews'             => $reviews,
		);
	}

	/**
	 * Make remote API request to update server.
	 *
	 * @param string $update_path The update path URL.
	 * @param string $plugin_slug The plugin slug.
	 * @return array|false The response array or false on failure.
	 */
	public static function make_remote_request( $update_path, $plugin_slug ) {
		$customer_key = get_option( Mo_License_Config::CUSTOMER_OPTIONS['id'] );
		$api_key      = get_option( Mo_License_Config::CUSTOMER_OPTIONS['apiKey'] );

		$current_time_in_millis = self::get_current_timestamp();
		$string_to_hash         = $customer_key . $current_time_in_millis . $api_key;
		$hash_value             = hash( 'sha512', $string_to_hash );

		$license_info    = self::get_license_info();
		$body_parameters = array(
			'pluginSlug'      => $plugin_slug,
			'licensePlanName' => $license_info['plan_name'],
			'customerId'      => $customer_key,
			'licenseType'     => $license_info['type'],
			'version'         => Mo_License_API_Utility::get_version_from_plugin_file(),
		);

		$params = array(
			'headers'     => array(
				'Content-Type'  => 'application/json; charset=utf-8',
				'Customer-Key'  => $customer_key,
				'Timestamp'     => $current_time_in_millis,
				'Authorization' => $hash_value,
			),
			'body'        => wp_json_encode( $body_parameters ),
			'method'      => 'POST',
			'data_format' => 'body',
			'sslverify'   => false,
		);

		$response = wp_remote_post( $update_path, $params );

		if ( ! is_wp_error( $response ) && wp_remote_retrieve_response_code( $response ) === 200 ) {
			return json_decode( $response['body'], true );
		}

		return false;
	}

	/**
	 * Get WordPress API data for plugin.
	 *
	 * @param string $slug The plugin slug.
	 * @return array The WordPress API data.
	 */
	public static function get_wordpress_api_data( $slug ) {
		$api = plugins_api(
			'plugin_information',
			array(
				'slug'   => $slug,
				'fields' => array(
					'active_installs' => true,
					'num_ratings'     => true,
					'rating'          => true,
					'ratings'         => true,
					'reviews'         => true,
				),
			)
		);

		$data = array(
			'active_installs' => false,
			'rating'          => false,
			'ratings'         => false,
			'num_ratings'     => false,
			'description'     => '',
			'reviews'         => '',
		);

		if ( ! is_wp_error( $api ) ) {
			$data['active_installs'] = $api->active_installs;
			$data['rating']          = $api->rating;
			$data['ratings']         = $api->ratings;
			$data['num_ratings']     = $api->num_ratings;
			$data['description']     = $api->sections['description'] ?? '';
			$data['reviews']         = $api->sections['reviews'] ?? '';
		}

		return $data;
	}

	/**
	 * Handle admin notice dismissal.
	 *
	 * @return void
	 */
	public static function handle_notice_dismissal() {
		if ( empty( $_GET['mosaml-dismiss'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}

		$nonce = sanitize_text_field( wp_unslash( $_GET['mosaml-dismiss'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! wp_verify_nonce( $nonce, 'saml-dismiss' ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}

		// Set timer to prevent notice from reappearing for 1 day.
		$date_time = new DateTime();
		$date_time->modify( '+1 day' );
		update_option( 'mo-saml-plugin-timer', $date_time );
	}

	/**
	 * Display update message for successful updates.
	 *
	 * @param string $current_version The current version.
	 * @param string $changelog       The changelog HTML.
	 * @return void
	 */
	public static function display_success_update_message( $current_version, $changelog ) {
		$uploads_dir      = wp_upload_dir();
		$base_uploads_dir = $uploads_dir['basedir'];
		$uploads_dir      = rtrim( $base_uploads_dir, '/' );
		$dir              = $uploads_dir . DIRECTORY_SEPARATOR . 'backup';
		$dir              = str_replace( '/', '\\', $dir );
		$backup           = Mo_License_Config::PLUGIN_BACKUP_ZIP_NAME . '-backup-' . esc_attr( $current_version );

		$arr   = explode( '</ul>', $changelog );
		$first = $arr[0];
		$html  = $first . '</ul>';

		$allowed_tags = array(
			'h4'  => array(),
			'div' => array(),
			'em'  => array(),
			'ul'  => array(),
			'li'  => array(),
		);

		echo '<div>
			<b><br/>An automatic backup of current version ' . esc_attr( $current_version ) . ' has been created at the location ' . esc_attr( $dir ) . ' with the name <span style="color:#0073aa;">' . esc_attr( $backup ) . '</span>. In case, something breaks during the update, you can revert to your current version by replacing the backup using FTP access.</b>
		</div>
		<div style="color: #f00;">
			<br/>Take a minute to check the changelog of latest version of the plugin. Here\'s why you need to update:
		</div>';

		echo '<div style="font-weight: normal;">' . wp_kses( $html, $allowed_tags ) . '</div><b>Note:</b> Please click on <b>View Version details</b> link to get complete changelog and license information. Click on <b>Update Now</b> link to update the plugin to latest version.';
	}
}
