<?php
/**
 * Plugin Version Update Handler
 *
 * This class handles plugin version updates and framework updates.
 *
 * @package MiniOrange\SAML\License\Handler
 * @since 1.0.0
 */

namespace MOSAML\LicenseLibrary;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use DateTime;
use MOSAML\LicenseLibrary\Classes\Mo_Update_Framework_Utility;
use MOSAML\LicenseLibrary\Classes\Mo_License_Constants;
use MOSAML\LicenseLibrary\Classes\Mo_License_URL;
use MOSAML\LicenseLibrary\Utils\Mo_Extension_Utility;
use MOSAML\LicenseLibrary\Utils\Mo_License_API_Utility;
use stdClass;

/**
 * Class Mo_Update_Framework
 *
 * Handles plugin version updates and framework-related updates.
 */
class Mo_Update_Framework {

	/**
	 * The plugin current version
	 *
	 * @var string
	 */
	private $current_version;

	/**
	 * The plugin remote update path
	 *
	 * @var string
	 */
	private $update_path;

	/**
	 * Plugin Slug (plugin_directory/plugin_file.php)
	 *
	 * @var string
	 */
	private $plugin_slug;

	/**
	 * Plugin name (plugin_file)
	 *
	 * @var string
	 */
	private $slug;

	/**
	 * Plugin file name.
	 *
	 * @var string
	 */
	private $plugin_file;

	/**
	 * New version changelog.
	 *
	 * @var string
	 */
	private $new_version_changelog;

	/**
	 * Initialize a new instance of the WordPress Auto-Update class.
	 *
	 * Sets up the plugin update framework by configuring version information,
	 * plugin paths, and registering WordPress hooks for automatic updates.
	 *
	 * @param string $current_version The current version of the plugin.
	 * @param string $plugin_slug     The plugin slug in format 'directory/file.php' (default: '/').
	 */
	public function __construct( $current_version, $plugin_slug = '/' ) {
		$this->current_version = $current_version;
		$this->update_path     = Mo_License_URL::PLUGIN_METADATA_URL;
		$this->plugin_slug     = $plugin_slug;
		$plugin_parts          = explode( '/', $plugin_slug );
		$this->slug            = isset( $plugin_parts[0] ) ? $plugin_parts[0] : '';
		$this->plugin_file     = isset( $plugin_parts[1] ) ? $plugin_parts[1] : '';

		// Register WordPress hooks for plugin updates.
		add_filter( 'pre_set_site_transient_update_plugins', array( &$this, 'check_update' ) );
		// Provide plugin information in the "View details" modal when available.
		add_filter( 'plugins_api', array( &$this, 'check_info' ), 10, 3 );
	}

	/**
	 * Check for plugin updates and add update information to the WordPress transient.
	 *
	 * This method is hooked into WordPress's update system to check for new versions
	 * of the plugin from the remote server. It validates required PHP extensions,
	 * fetches remote version information, and prepares update data for WordPress.
	 *
	 * @param object $transient The WordPress update transient object.
	 * @return object The modified transient object with update information.
	 */
	public function check_update( $transient ) {
		if ( ! class_exists( 'MOSAML\LicenseLibrary\Utils\Mo_Extension_Utility' ) ) {
			return $transient;
		}

		if ( ! Mo_Extension_Utility::validate_required_extensions() || empty( $transient->checked ) ) {
			return $transient;
		}

		$remote_version = Mo_Update_Framework_Utility::make_remote_request( $this->update_path, $this->plugin_slug );

		if ( $remote_version && isset( $remote_version['status'] ) ) {
			if ( 'SUCCESS' === $remote_version['status'] ) {
				return $this->handle_success_update( $transient, $remote_version );
			} elseif ( 'DENIED' === $remote_version['status'] ) {
				return $this->handle_denied_update( $transient, $remote_version );
			}
		}

		return $transient;
	}

	/**
	 * Handle successful update response.
	 *
	 * @param object $transient      The WordPress update transient object.
	 * @param array  $remote_version The remote version data.
	 * @return object The modified transient object.
	 */
	private function handle_success_update( $transient, $remote_version ) {
		$current_version = $this->get_current_version_from_main_file();
		if ( version_compare( $current_version, $remote_version['newVersion'], '<' ) ) {
			$this->prepare_for_update();

			$obj = Mo_Update_Framework_Utility::create_update_object(
				$this->slug,
				$this->plugin_slug,
				$remote_version['newVersion'],
				$remote_version
			);

			$hash_value = Mo_Update_Framework_Utility::get_auth_token();
			$current_time_in_millis = Mo_Update_Framework_Utility::get_current_timestamp();
			$obj->package = Mo_Update_Framework_Utility::build_download_url(
				$this->plugin_slug,
				$hash_value,
				$current_time_in_millis,
				$current_version
			);
			$obj->new_version_changelog = $remote_version['changelog'];

			Mo_License_Service::update_license_expiry( $remote_version['liceneExpiryDate'] );

			$transient->response[ $this->plugin_slug ] = $obj;
		}

		return $transient;
	}

	/**
	 * Handle denied update response.
	 *
	 * @param object $transient      The WordPress update transient object.
	 * @param array  $remote_version The remote version data.
	 * @return object The modified transient object.
	 */
	private function handle_denied_update( $transient, $remote_version ) {
		$current_version = $this->get_current_version_from_main_file();
		if ( version_compare( $current_version, $remote_version['newVersion'], '<' ) ) {
			$obj = Mo_Update_Framework_Utility::create_update_object(
				$this->slug,
				$this->plugin_slug,
				$remote_version['newVersion'],
				$remote_version
			);
			$obj->license_information = $remote_version['licenseInformation'];

			Mo_License_Service::update_license_expiry( $remote_version['liceneExpiryDate'] );

			$transient->response[ $this->plugin_slug ] = $obj;
		}

		return $transient;
	}

	/**
	 * Prepare system for update (set limits and create backup).
	 *
	 * @return void
	 */
	private function prepare_for_update() {
		Mo_Update_Framework_Utility::create_backup_dir( $this->current_version );
	}

	/**
	 * Get plugin version from the main plugin file.
	 *
	 * @return string Plugin version string.
	 */
	private function get_current_version_from_main_file() {
		$version = Mo_License_API_Utility::get_version_from_plugin_file( $this->plugin_slug );

		return ! empty( $version ) ? $version : $this->current_version;
	}

	/**
	 * Provide plugin information for the WordPress plugin installation/update interface.
	 *
	 * This method is hooked into WordPress's plugins_api filter to provide detailed
	 * information about the plugin when users view update details. It fetches remote
	 * plugin information and combines it with WordPress.org data for a complete view.
	 *
	 * @param bool|object $obj    The default return value (false or object).
	 * @param string      $action The action being performed ('query_plugins' or 'plugin_information').
	 * @param object      $arg    Arguments passed to the API call.
	 * @return bool|object Plugin information object or false if not applicable.
	 */
	public function check_info( $obj, $action, $arg ) {
		if ( ! $this->is_valid_plugin_info_request( $action, $arg ) ) {
			return $obj;
		}

		$remote_info = Mo_Update_Framework_Utility::make_remote_request( $this->update_path, $this->plugin_slug );
		$wp_api_data = $this->get_wordpress_api_data();

		if ( $remote_info && isset( $remote_info['status'] ) ) {
			if ( 'SUCCESS' === $remote_info['status'] ) {
				return $this->handle_success_plugin_info( $remote_info, $wp_api_data );
			} elseif ( 'DENIED' === $remote_info['status'] ) {
				return $this->handle_denied_plugin_info( $remote_info, $wp_api_data );
			}
		}

		return $obj;
	}

	/**
	 * Check if the plugin info request is valid.
	 *
	 * @param string $action The action being performed.
	 * @param object $arg    Arguments passed to the API call.
	 * @return bool True if valid, false otherwise.
	 */
	private function is_valid_plugin_info_request( $action, $arg ) {
		return ( 'query_plugins' === $action || 'plugin_information' === $action ) &&
			! empty( $arg->slug ) &&
			( $arg->slug === $this->slug || $arg->slug === $this->plugin_file );
	}

	/**
	 * Get WordPress API data for the plugin.
	 *
	 * @return array The WordPress API data.
	 */
	private function get_wordpress_api_data() {
		// Remove our filter temporarily to get WordPress.org data.
		remove_filter( 'plugins_api', array( $this, 'check_info' ) );

		$wp_api_data = Mo_Update_Framework_Utility::get_wordpress_api_data( $this->slug );

		// Add our filter back.
		add_filter( 'plugins_api', array( $this, 'check_info' ), 10, 3 );

		return $wp_api_data;
	}

	/**
	 * Handle successful plugin info response.
	 *
	 * @param array $remote_info The remote information data.
	 * @param array $wp_api_data The WordPress API data.
	 * @return object|false The plugin info object or false.
	 */
	private function handle_success_plugin_info( $remote_info, $wp_api_data ) {
		if ( version_compare( $this->current_version, $remote_info['newVersion'], '<=' ) ) {
			$remote_obj = Mo_Update_Framework_Utility::create_plugin_info_object(
				$this->slug,
				$this->plugin_slug,
				$remote_info,
				$wp_api_data
			);

			Mo_Update_Framework_Utility::add_plugin_info_sections(
				$remote_obj,
				$remote_info,
				$wp_api_data['description'],
				$wp_api_data['reviews']
			);

			$hash_value = Mo_Update_Framework_Utility::get_auth_token();
			$current_time_in_millis = Mo_Update_Framework_Utility::get_current_timestamp();
			$remote_obj->download_link = Mo_Update_Framework_Utility::build_download_url(
				$this->plugin_slug,
				$hash_value,
				$current_time_in_millis,
				$this->get_current_version_from_main_file()
			);
			$remote_obj->package = $remote_obj->download_link;

			Mo_License_Service::update_license_expiry( $remote_info['liceneExpiryDate'] );

			return $remote_obj;
		}

		return false;
	}

	/**
	 * Handle denied plugin info response.
	 *
	 * @param array $remote_info The remote information data.
	 * @param array $wp_api_data The WordPress API data.
	 * @return object|false The plugin info object or false.
	 */
	private function handle_denied_plugin_info( $remote_info, $wp_api_data ) {
		if ( version_compare( $this->current_version, $remote_info['newVersion'], '<' ) ) {
			$remote_obj = Mo_Update_Framework_Utility::create_plugin_info_object(
				$this->slug,
				$this->plugin_slug,
				$remote_info,
				$wp_api_data
			);

			Mo_Update_Framework_Utility::add_plugin_info_sections(
				$remote_obj,
				$remote_info,
				$wp_api_data['description'],
				$wp_api_data['reviews']
			);

			Mo_License_Service::update_license_expiry( $remote_info['liceneExpiryDate'] );

			return $remote_obj;
		}

		return false;
	}




	/**
	 * Display custom update messages in the WordPress plugin update interface.
	 *
	 * Shows backup information and changelog details when users view plugin updates.
	 * Provides important information about the update process and what changes are included.
	 *
	 * @param array  $plugin_data Plugin data array containing update information.
	 * @param object $response    The update response object from the remote server.
	 * @return void
	 */
	public function plugin_update_message( $plugin_data, $response ) {
		if ( empty( $plugin_data['status_code'] ) ) {
			return;
		}

		if ( 'SUCCESS' === $plugin_data['status_code'] ) {
			Mo_Update_Framework_Utility::display_success_update_message(
				$this->current_version,
				$plugin_data['new_version_changelog']
			);
		} elseif ( 'DENIED' === $plugin_data['status_code'] ) {
			echo esc_html( $plugin_data['license_information'] );
		}
	}

	/**
	 * Handle dismissal of admin notices related to plugin updates.
	 *
	 * Processes dismiss requests for update-related admin notices and sets
	 * appropriate timers to prevent the notices from reappearing immediately.
	 *
	 * @return void
	 */
	public function dismiss_notice() {
		Mo_Update_Framework_Utility::handle_notice_dismissal();
	}

}
