<?php
/**
 * Debug Logger Class.
 *
 * Handles logging of debug messages.
 * Provides functionality to log debug messages to a file.
 *
 * @package miniorange-saml-20-single-sign-on/src/class
 */

namespace MOSAML\SRC\Classes;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Constant\Plugin_Files_Constants;

/**
 * Debug Logger Class.
 *
 * Handles logging of debug messages.
 * Provides functionality to log debug messages to a file.
 *
 * @package miniorange-saml-20-single-sign-on/src/class
 */
class Debug_Logger {

	/**
	 * Enable debug logging.
	 *
	 * @return bool True on success, false on failure.
	 */
	public static function enable_debug_log() {
		if ( defined( Constants::DEBUG_LOG_CONSTANT ) && true === constant( Constants::DEBUG_LOG_CONSTANT ) ) {
			return true;
		}
		if ( ! self::is_wp_config_writable() ) {
			return false;
		}

		if ( self::set_debug_log_constant_to_wp_config( true ) ) {
			if ( self::create_debug_log_file() ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Disable debug logging.
	 *
	 * @return bool True on success, false on failure.
	 */
	public static function disable_debug_log() {
		if ( ! defined( Constants::DEBUG_LOG_CONSTANT ) || false === constant( Constants::DEBUG_LOG_CONSTANT ) ) {
			return true;
		}
		if ( ! self::is_wp_config_writable() ) {
			return false;
		}
		if ( self::set_debug_log_constant_to_wp_config( false ) ) {
			return true;
		}
		return false;
	}

	/**
	 * The admin init actions which need to be taken regarding debug logs i.e., displaying the error/success message.
	 *
	 * @return void
	 */
	public static function debug_log_actions() {
		if ( ! self::is_wp_config_writable() && defined( Constants::DEBUG_LOG_CONSTANT ) && true === constant( Constants::DEBUG_LOG_CONSTANT ) ) {
			add_action(
				'admin_notices',
				function () {
					echo wp_kses_post(
						sprintf(
							/* translators: %1s: search term */
							'<div class="error" style=""><p/>' . __( 'To allow logging, make  <code>"%1s"</code> directory writable.miniOrange will not be able to log the errors.', 'miniorange-saml-20-single-sign-on' ) . '</div>',
							self::get_plugin_debug_log_directory()
						)
					);
				}
			);
		}
		if ( self::is_wp_config_writable() && defined( Constants::DEBUG_LOG_CONSTANT ) && true === constant( Constants::DEBUG_LOG_CONSTANT ) && current_user_can( 'manage_options' ) ) {
			add_action(
				'admin_notices',
				function () {
					echo wp_kses_post(
						sprintf(
							/* translators: %s: search term */
							'<div class="updated"><p/>' . __( ' miniOrange SAML 2.0 logs are active. Want to turn it off? <a href="%s">Learn more here.', 'miniorange-saml-20-single-sign-on' ) . '</a></div>',
							admin_url() . 'admin.php?page=mosaml-troubleshoot'
						)
					);
				}
			);
		}
	}

	/**
	 * Clear the debug logs.
	 *
	 * @return void
	 */
	public static function clear_debug_logs() {
		if ( ! defined( Constants::DEBUG_LOG_CONSTANT ) || true !== constant( Constants::DEBUG_LOG_CONSTANT ) ) {
			return;
		}

		$result          = get_option( Constants::DEBUG_LOG_FILE_PATH_OPTION_NAME );
		$debug_file_path = ! empty( $result ) ? $result : '';
		if ( ! $debug_file_path ) {
			$debug_file_path = self::create_debug_log_file();
		}

		if ( ! $debug_file_path || ! self::init_filesystem() ) {
			return;
		}

		global $wp_filesystem;
		$wp_filesystem->put_contents( $debug_file_path, '', self::get_file_chmod( $debug_file_path ) );
	}

	/**
	 * Download the debug logs.
	 *
	 * @return void
	 */
	public static function download_debug_logs() {
		if ( ! defined( Constants::DEBUG_LOG_CONSTANT ) || true !== constant( Constants::DEBUG_LOG_CONSTANT ) ) {
			return;
		}

		$result          = get_option( Constants::DEBUG_LOG_FILE_PATH_OPTION_NAME );
		$debug_file_path = ! empty( $result ) ? $result : '';
		if ( $debug_file_path ) {
			if ( ! self::init_filesystem() ) {
				return;
			}

			global $wp_filesystem;
			if ( $wp_filesystem->exists( $debug_file_path ) ) {
				$content = $wp_filesystem->get_contents( $debug_file_path );
				if ( false === $content ) {
					return;
				}
				header( 'Content-Description: File Transfer' );
				header( 'Content-Type: application/octet-stream' );
				header( 'Content-Disposition: attachment; filename="' . basename( $debug_file_path ) . '"' );
				header( 'Content-Length: ' . strlen( $content ) );
				// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- This is to download the file.
				echo $content;
				exit;
			}
		}
	}

	/**
	 * Delete the debug log files.
	 *
	 * @return void
	 */
	public static function delete_debug_log_files() {
		if ( defined( Constants::DEBUG_LOG_CONSTANT ) && true === constant( Constants::DEBUG_LOG_CONSTANT ) ) {
			return;
		}
		if ( ! self::init_filesystem() ) {
			return;
		}

		global $wp_filesystem;
		$dir = self::get_plugin_debug_log_directory();

		$files = $wp_filesystem->dirlist( $dir );

		if ( is_array( $files ) ) {
			foreach ( $files as $filename => $fileinfo ) {
				if ( isset( $fileinfo['type'] ) && 'f' === $fileinfo['type'] && strpos( $filename, 'mosaml-debug-' ) !== false ) {
					$wp_filesystem->delete( $dir . DIRECTORY_SEPARATOR . $filename );
				}
			}
		}
	}

	/**
	 * Create the debug log file.
	 *
	 * @return string|false The file path on success, false on failure.
	 */
	private static function create_debug_log_file() {
		if ( ! self::create_debug_log_folder_if_not_exists() ) {
			return false;
		}
		$debug_log_file_name = 'mosaml-debug-' . str_replace( '-', '', wp_generate_uuid4() ) . '-' . gmdate( 'Ymd-His' ) . '.log';
		$log_file            = self::get_plugin_debug_log_directory() . DIRECTORY_SEPARATOR . $debug_log_file_name;
		$debug_log_file_path = self::create_file_if_not_exists( $log_file, '' );
		if ( $debug_log_file_path ) {
			update_option( Constants::DEBUG_LOG_FILE_PATH_OPTION_NAME, $debug_log_file_path );
		}
		return $debug_log_file_path;
	}

	/**
	 * Create the debug log folder if it doesn't exist.
	 *
	 * @return bool
	 */
	public static function create_debug_log_folder_if_not_exists() {
		if ( ! self::init_filesystem() ) {
			return false;
		}

		global $wp_filesystem;
		$plugin_debug_log_dir = self::get_plugin_debug_log_directory();
		if ( ! $wp_filesystem->is_dir( $plugin_debug_log_dir ) ) {
			$created = $wp_filesystem->mkdir( $plugin_debug_log_dir, self::get_file_chmod( $plugin_debug_log_dir ) );
			if ( ! $created ) {
				return false;
			}
			self::create_index_file_if_not_exists( $plugin_debug_log_dir, $wp_filesystem );
		}
		return true;
	}

	/**
	 * Create the index file if it doesn't exist.
	 *
	 * @param string $plugin_debug_log_dir The path to the plugin debug log directory.
	 * @param object $wp_filesystem The WordPress filesystem object.
	 * @return void
	 */
	private static function create_index_file_if_not_exists( $plugin_debug_log_dir, $wp_filesystem ) {
		if ( ! $wp_filesystem ) {
			if ( ! self::init_filesystem() ) {
				return;
			}
			global $wp_filesystem;
		}

		$index_file    = $plugin_debug_log_dir . '/index.php';
		$index_content = "<?php\n// Silence is golden.\n";

		$existing_content = $wp_filesystem->exists( $index_file ) ? $wp_filesystem->get_contents( $index_file ) : false;
		if ( false === $existing_content || trim( $existing_content ) !== trim( $index_content ) ) {
			$wp_filesystem->put_contents( $index_file, $index_content, self::get_file_chmod( $index_file ) );
		}
	}

	/**
	 * Get the plugin debug log directory path.
	 *
	 * @return string The absolute path to the plugin debug log directory.
	 */
	public static function get_plugin_debug_log_directory() {
		$upload_dir = wp_upload_dir();
		if ( false === $upload_dir || ! isset( $upload_dir['basedir'] ) ) {
			return '';
		}
		return $upload_dir['basedir'] . DIRECTORY_SEPARATOR . Constants::PLUGIN_NAME;
	}

	/**
	 * Create the file if it doesn't exist.
	 *
	 * @param string $file_path The file path to create.
	 * @param string $content The content to write to the file.
	 * @return string|false The file path on success, false on failure.
	 */
	private static function create_file_if_not_exists( $file_path, $content ) {
		if ( ! self::init_filesystem() ) {
			return false;
		}

		global $wp_filesystem;
		if ( ! $wp_filesystem->put_contents( $file_path, $content, self::get_file_chmod( $file_path ) ) ) {
			return false;
		}
		return $file_path;
	}

	/**
	 * Log a debug message.
	 *
	 * @param mixed $content The message to log.
	 * @return void
	 */
	public static function log( $content ) {
		if ( ! defined( Constants::DEBUG_LOG_CONSTANT ) || false === constant( Constants::DEBUG_LOG_CONSTANT ) ) {
			return;
		}

		if ( ! self::init_filesystem() ) {
			return;
		}

		global $wp_filesystem;
		$result          = get_option( Constants::DEBUG_LOG_FILE_PATH_OPTION_NAME );
		$debug_file_path = ! empty( $result ) ? $result : '';
		if ( ! $debug_file_path ) {
			$debug_file_path = self::create_debug_log_file();
		}

		if ( ! $debug_file_path ) {
			return;
		}

		$content          = '[' . gmdate( 'Y-m-d H:i:s' ) . '] ' . $content . PHP_EOL;
		$existing_content = $wp_filesystem->get_contents( $debug_file_path );
		$content          = ( false !== $existing_content ? $existing_content : '' ) . $content;
		$wp_filesystem->put_contents( $debug_file_path, $content, self::get_file_chmod( $debug_file_path ) );
	}

	/**
	 * Check if wp-config.php is writable.
	 *
	 * @return bool True if writable, false otherwise.
	 */
	private static function is_wp_config_writable() {
		if ( ! self::init_filesystem() ) {
			return false;
		}

		global $wp_filesystem;
		return $wp_filesystem->is_writable( self::get_wp_config_path() );
	}

	/**
	 * Get the path to wp-config.php file.
	 *
	 * @return string The path to wp-config.php file.
	 */
	private static function get_wp_config_path() {
		return ABSPATH . Plugin_Files_Constants::WP_CONFIG_PHP_FILE;
	}

	/**
	 * Add or update a constant definition in wp-config.php.
	 *
	 * @param bool $value The value to set the constant to.
	 * @return bool True on success, false on failure.
	 */
	private static function set_debug_log_constant_to_wp_config( $value ) {
		if ( ! self::init_filesystem() ) {
			return false;
		}

		global $wp_filesystem;
		$wp_config_path    = self::get_wp_config_path();
		$wp_config_content = $wp_filesystem->get_contents( $wp_config_path );
		if ( false === $wp_config_content ) {
			return false;
		}

		$constant_pattern = '/define\s*\(\s*[\'"]' . preg_quote( Constants::DEBUG_LOG_CONSTANT, '/' ) . '[\'"]\s*,\s*[^)]+\)\s*;/';
		if ( preg_match( $constant_pattern, $wp_config_content ) ) {
			$new_content = preg_replace(
				$constant_pattern,
				"define( '" . Constants::DEBUG_LOG_CONSTANT . "', " . ( $value ? 'true' : 'false' ) . ' );',
				$wp_config_content
			);
		} else {
			$insert_position = strpos( $wp_config_content, "/* That's all, stop editing!" );
			if ( false === $insert_position ) {
				return false;
			}
			$insert_position = strrpos( substr( $wp_config_content, 0, $insert_position ), "\n" );
			if ( false === $insert_position ) {
				return false;
			}

			$new_content = substr( $wp_config_content, 0, $insert_position ) .
							"define( '" . Constants::DEBUG_LOG_CONSTANT . "', " . ( $value ? 'true' : 'false' ) . " );\n" .
							substr( $wp_config_content, $insert_position );
		}

		// Use get_file_chmod() to preserve existing file permissions for wp-config.php security.
		// This ensures restrictive permissions (e.g., 0600, 0640) are maintained to prevent
		// unauthorized access to sensitive configuration data.
		$result = $wp_filesystem->put_contents( $wp_config_path, $new_content, self::get_file_chmod( $wp_config_path ) );
		return false !== $result;
	}

	/**
	 * Debug log enabled warning.
	 *
	 * @return array
	 */
	public static function debug_log_enabled_warning() {
		if ( ! defined( Constants::DEBUG_LOG_CONSTANT ) || false === constant( Constants::DEBUG_LOG_CONSTANT ) ) {
			return array(
				'label'       => __( 'Debug Log Disabled', 'miniorange-saml-20-single-sign-on' ),
				'status'      => 'good',
				'badge'       => array(
					'label' => __( 'Security', 'miniorange-saml-20-single-sign-on' ),
					'color' => 'blue',
				),
				'description' => __( 'Debug logging is disabled for the miniOrange SAML plugin. This is the recommended setting.', 'miniorange-saml-20-single-sign-on' ),
				'test'        => 'mosaml_debug_log_enabled_warning',
			);
		} else {
			return array(
				'label'       => __( 'Debug Log Enabled', 'miniorange-saml-20-single-sign-on' ),
				'status'      => 'critical',
				'badge'       => array(
					'label' => __( 'Security', 'miniorange-saml-20-single-sign-on' ),
					'color' => 'red',
				),
				'description' => __( 'Debug logging is enabled for the miniOrange SAML plugin. This can expose sensitive information to the public.', 'miniorange-saml-20-single-sign-on' ),
				'actions'     => sprintf(
					'<a href="%s">%s</a>',
					esc_url( admin_url( 'admin.php?page=mo_saml_settings' ) ),
					__( 'Disable Debug Logging', 'miniorange-saml-20-single-sign-on' )
				),
				'test'        => 'mosaml_debug_log_enabled_warning',
			);

		}
	}

	/**
	 * Get the appropriate file permissions (chmod) for a file.
	 *
	 * This function intelligently determines file permissions by:
	 * 1. Preserving existing permissions if the file already exists (important for security)
	 * 2. Using FS_CHMOD_FILE if defined and more restrictive than current permissions
	 * 3. Falling back to default 0644 if neither condition applies
	 *
	 * For wp-config.php specifically, this ensures restrictive permissions (e.g., 0600, 0640)
	 * are preserved to prevent unauthorized access to sensitive configuration data.
	 *
	 * @param string|null $file_path Optional. The path to the file. If provided and file exists,
	 *                               current permissions will be preserved. Default null.
	 * @return int The file permissions value to use (e.g., 0644, 0600, 0640).
	 */
	private static function get_file_chmod( $file_path = null ) {
		$default_chmod = defined( 'FS_CHMOD_FILE' ) ? FS_CHMOD_FILE : 0644;

		// If no file path provided, return default.
		if ( null === $file_path ) {
			return $default_chmod;
		}

		// If file exists, preserve its current permissions for security.
		// This is especially important for sensitive files like wp-config.php.
		if ( file_exists( $file_path ) ) {
			$current_perms = fileperms( $file_path ) & 0777;

			// Use FS_CHMOD_FILE only if it's defined and more restrictive than current permissions.
			// More restrictive means fewer permissions granted (e.g., 0600 is more restrictive than 0644).
			// This ensures we don't weaken security by using less restrictive permissions.
			if ( defined( 'FS_CHMOD_FILE' ) ) {
				$fs_chmod = FS_CHMOD_FILE & 0777;
				// Check if FS_CHMOD_FILE is more restrictive by comparing permission bits.
				// A permission is more restrictive if it grants fewer access rights overall.
				// For wp-config.php, common restrictive values are 0600 (owner only) or 0640 (owner+group).
				// We use numeric comparison which works for typical cases: 0600 < 0640 < 0644.
				if ( $fs_chmod < $current_perms ) {
					return FS_CHMOD_FILE;
				}
			}

			return $current_perms;
		}

		// File doesn't exist, use default.
		return $default_chmod;
	}

	/**
	 * Initialize WordPress filesystem.
	 *
	 * @return bool True if filesystem is available, false otherwise.
	 */
	private static function init_filesystem() {
		global $wp_filesystem;

		if ( $wp_filesystem ) {
			return true;
		}

		require_once ABSPATH . Plugin_Files_Constants::WP_ADMIN_INCLUDES_FILE;

		// Suppress FTP warnings if filesystem initialization fails.
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_set_error_handler -- Needed to prevent filesystem initialization warnings.
		set_error_handler(
			static function ( $errno, $errstr ) {
				unset( $errno, $errstr );
				return true;
			}
		);
		$result = WP_Filesystem();
		restore_error_handler();

		return $result && $wp_filesystem;
	}
}
