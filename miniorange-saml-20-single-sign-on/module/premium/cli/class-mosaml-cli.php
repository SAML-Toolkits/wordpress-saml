<?php
/**
 * WP-CLI commands for MOSAML plugin.
 *
 * @package MOSAML
 * @subpackage Module\Premium\CLI
 */

namespace MOSAML\Module\Premium\CLI;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\Feature_Control;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Handler\Database_Cleanup_Handler;
use MOSAML\SRC\Classes\Mo_Customer;
use MOSAML\SRC\Handler\Import_Export\Import_Config_Handler;
use MOSAML\SRC\Handler\Import_Export\Import_Export_Config_Handler;
use WP_CLI;

/**
 * Manages MOSAML SAML SSO plugin via WP-CLI.
 */
class MOSAML_CLI {

	/**
	 * Constructor to register WP-CLI commands.
	 */
	public function __construct() {
		WP_CLI::add_command( 'saml', $this );
	}

	/**
	 * Fetches plugin configuration from a provided config file and updates plugin settings.
	 *
	 * ## OPTIONS
	 *
	 * --config=<file>
	 * : Path to the configuration JSON file. If relative, will look in plugin root directory.
	 *
	 * ## EXAMPLES
	 *
	 *     # Import config from plugin root directory
	 *     wp saml fetch --config=config.json
	 *
	 *     # Import config from absolute path
	 *     wp saml fetch --config=/path/to/config.json
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 * @return void
	 */
	public function fetch( $args, $assoc_args ) {
		if ( ! Feature_Control::check_is_license_valid() ) {
			WP_CLI::error( 'License is not valid. Please activate the license first.' );
			return;
		}

		if ( empty( $assoc_args['config'] ) ) {
			WP_CLI::error( 'Please specify --config parameter (e.g., --config=config.json)' );
			return;
		}

		$config_file = $assoc_args['config'];

		// Resolve file path - check if absolute path, otherwise look in plugin root.
		if ( ! file_exists( $config_file ) ) {
			$config_file = MOSAML_PLUGIN_DIR . $config_file;
		}

		if ( ! file_exists( $config_file ) ) {
			WP_CLI::error( sprintf( 'Configuration file not found: %s', $config_file ) );
			return;
		}

		WP_CLI::line( sprintf( 'Reading configuration file: %s', $config_file ) );

		// Read and validate JSON file.
		if ( ! is_readable( $config_file ) ) {
			WP_CLI::error( sprintf( 'Failed to read configuration file: %s', $config_file ) );
			return;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading a local file provided to CLI.
		$file_content = file_get_contents( $config_file );
		if ( false === $file_content ) {
			WP_CLI::error( sprintf( 'Failed to read configuration file: %s', $config_file ) );
			return;
		}

		$configurations = json_decode( $file_content, true );
		if ( json_last_error() !== JSON_ERROR_NONE ) {
			WP_CLI::error( sprintf( 'Invalid JSON file. Error: %s', json_last_error_msg() ) );
			return;
		}

		if ( empty( $configurations ) || ! is_array( $configurations ) ) {
			WP_CLI::error( 'Invalid configuration file. Please upload a valid JSON configuration file.' );
			return;
		}

		// Check if it's the new common codebase format.
		if ( isset( $configurations['meta']['common_codebase'] ) && $configurations['meta']['common_codebase'] ) {
			WP_CLI::line( 'Importing configuration...' );
			$this->import_new_format( $configurations );
		} else {
			WP_CLI::line( 'Importing configuration...' );
			$this->import_legacy_format( $configurations );
		}

		WP_CLI::success( 'Configuration imported successfully!' );
	}

	/**
	 * Import configuration using the new common codebase format.
	 *
	 * @param array $configurations Configuration data.
	 * @return void
	 */
	private function import_new_format( $configurations ) {
		try {
			Import_Export_Config_Handler::import_config_from_json( $configurations );
		} catch ( \Throwable $e ) {
			WP_CLI::error( sprintf( 'Import failed: %s', $e->getMessage() ) );
		}
	}

	/**
	 * Import configuration using the legacy format handler.
	 *
	 * @param array $configurations Configuration data.
	 * @return void
	 */
	private function import_legacy_format( $configurations ) {
		try {
			$import_handler = new Import_Config_Handler();

			$import_file_version = Utility::detect_config_type( $configurations );
			$enum_map            = $import_handler->get_config_enum_map( $import_file_version );
			$handler_instances   = $import_handler->prepare_configurations( $configurations, $enum_map );

			DB_Utils::truncate_table_data();
			Database_Cleanup_Handler::delete_plugin_options( true );
			DB_Utils::create_tables_and_initialize();

			$class_import_order = $import_handler->get_class_import_order_map( $import_file_version );
			foreach ( $class_import_order as $class_name ) {
				$class_instance = isset( $handler_instances[ $class_name ] ) ? $handler_instances[ $class_name ] : null;
				if ( ! is_null( $class_instance ) && method_exists( $class_instance, 'save_data' ) ) {
					$class_instance->save_data( $class_instance );
				}
			}
		} catch ( \Exception $e ) {
			WP_CLI::error( sprintf( 'Import failed: %s', $e->getMessage() ) );
		}
	}

	/**
	 * Activates the plugin with the details fetched from the provided license file.
	 *
	 * @param array $args argument to fetch.
	 * @param array $assoc_args Parameters passed with the WP CLI command.
	 * @return void
	 */
	public function activate( $args, $assoc_args ) {
		if ( empty( $assoc_args ) ) {
			WP_CLI::error( 'There was an error processing your request. Missing arguments. Please check the documentation for the correct usage.' );
		}

		$args_to_check = array( 'file', 'domain' );
		$this->throw_cli_error_for_empty_values( $assoc_args, $args_to_check );
		$domain           = $assoc_args['domain'];
		$customer_details = $this->fetch_and_validate_file_content( $assoc_args['file'] );
		if ( empty( $customer_details ) || ! is_array( $customer_details ) ) {
			WP_CLI::error( 'Error while retrieving the details. Invalid JSON found.' );
		}

		$this->throw_cli_error_for_empty_values( $customer_details, array( 'admin_email', 'customer_key', 'customer_api_key', 'customer_token_key', $domain ) );

		$domain_keys = $customer_details[ $domain ];
		$this->throw_cli_error_for_empty_values( $domain_keys, array( 'mo_saml_license_key' ) );

		$license_key = $customer_details[ $domain ]['mo_saml_license_key'];

		Database_Cleanup_Handler::delete_plugin_license_detail();
		$this->save_details( $customer_details['customer_key'], $customer_details['customer_api_key'], $customer_details['customer_token_key'], $customer_details['admin_email'], $license_key );
	}

	/**
	 * Throws CLI Error when any of the passed keys do not exist in the array or if the
	 * value of the key is empty in the array.
	 *
	 * @param array $arr Array to check the key in.
	 * @param array $keys_to_check List of keys which need to be checked in the array.
	 * @return void
	 */
	private function throw_cli_error_for_empty_values( $arr, $keys_to_check ) {
		foreach ( $keys_to_check as $key ) {
			if ( empty( $arr[ $key ] ) ) {
				WP_CLI::error( 'There was an error processing your request. ' . $key . ' is either empty or null' );
			}
		}
	}

	/**
	 * Fetches the file from a specified path function and returns a valid
	 * content array from the json file.
	 *
	 * @param string $file_name Name of the file to be fetched.
	 * @return array|bool
	 */
	private function fetch_and_validate_file_content( $file_name ) {
		$path         = ( file_exists( $file_name ) ) ? $file_name : MOSAML_PLUGIN_DIR . $file_name;
		$json         = $this->get_valid_file_data( $path );
		$file_content = json_decode( $json, true );

		if ( json_last_error() !== JSON_ERROR_NONE ) {
			WP_CLI::error( 'Error while retrieving the details. Invalid JSON found.' );
		}
		return $file_content;
	}

	/**
	 * Fetches the file data and returns the data if it is valid.
	 * Otherwise, throws a CLI Error.
	 *
	 * @param string $path File path to fetch.
	 * @return string
	 */
	private function get_valid_file_data( $path ) {
		if ( ! file_exists( $path ) ) {
			WP_CLI::error( 'Error while retrieving the details. Specified file not found in the plugin directory.' );
		}

		if ( ! is_readable( $path ) ) {
			WP_CLI::error( 'Error while retrieving the details. Specified file is not readable.' );
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading a local JSON file for CLI import.
		$data = file_get_contents( $path );
		if ( ! ( $this->validate_json( $data ) ) ) {
			WP_CLI::error( 'Error while retrieving the details. Please upload a valid configuration file in .json format.' );
		}
		return $data;
	}

	/**
	 * Validates if the data passed is a valid JSON.
	 *
	 * @param string $data Data to be validated.
	 * @return bool
	 */
	private function validate_json( $data ) {
		if ( ! empty( $data ) ) {
			return ( is_string( $data ) && is_array( json_decode( $data, true ) ) ? true : false );
		}
		return false;
	}

	/**
	 * Function to save the customer details.
	 *
	 * @param string $customer_key        customer key.
	 * @param string $customer_api_key    customer api key.
	 * @param string $customer_token_key  customer token key.
	 * @param string $mo_saml_admin_email Admin email.
	 * @param string $license_key         License key.
	 */
	private function save_details( $customer_key, $customer_api_key, $customer_token_key, $mo_saml_admin_email, $license_key ) {
		if ( ! Utility::is_extension_installed( 'curl' ) ) {
			WP_CLI::error( 'Error while retrieving the details. CURL extension is not installed.' );
		}
		update_option( 'mo_saml_verify_customer', '' );
		delete_option( 'mo_saml_admin_email' );
		delete_option( 'mo_saml_admin_phone' );
		delete_option( 'sml_lk' );
		delete_option( 'site_ck_l' );
		$email = sanitize_email( $mo_saml_admin_email );
		update_option( 'mo_saml_admin_email', $email );
		$customer = new Mo_Customer();
		$content  = $customer->check_customer( $email );
		if ( ! $content ) {
			WP_CLI::error( 'Unable to connect to the internet. Please try connecting again.' );
		}
		$content = json_decode( $content, true );
		if ( isset( $content['status'] ) && strcasecmp( $content['status'], 'CUSTOMER_NOT_FOUND' ) === 0 ) {
			WP_CLI::error( 'There was an error processing your request. Registered customer not found in our system.' );
		}
		$customer_key       = sanitize_text_field( $customer_key );
		$customer_api_key   = sanitize_text_field( $customer_api_key );
		$customer_token_key = sanitize_text_field( $customer_token_key );
		update_option( 'mo_saml_admin_customer_key', $customer_key );
		update_option( 'mo_saml_admin_api_key', $customer_api_key );
		update_option( 'mo_saml_customer_token', $customer_token_key );
		delete_option( 'mo_saml_verify_customer' );
		$license_key = sanitize_text_field( trim( $license_key ) );
		$result      = Utility::handle_license_calls( 'validate_license_key', 'library', array(), array( 'license_key' => $license_key ) );
		if ( isset( $result['STATUS'] ) && 'LICENSE_VALID' !== $result['STATUS'] ) {
			$error_message = isset( $result['MESSAGE'] ) ? $result['MESSAGE'] : 'License validation failed.';
			WP_CLI::error( $error_message );
		}
		WP_CLI::success( 'License activated successfully!' );
	}

	/**
	 * Function to handle the plugin update using wp-cli command.
	 *
	 * Note: This command is not used. The update framework is initialized
	 * on the 'init' hook, so WordPress's standard 'wp plugin update' command
	 * will automatically use the custom update framework via API calls.
	 *
	 * @return void
	 */
	public function update() {
		WP_CLI::line( 'Use the standard WordPress command: wp plugin update miniorange-saml-20-single-sign-on' );
		WP_CLI::line( 'The custom update framework is automatically initialized and will handle API calls.' );
	}

	/**
	 * Updates a specific field in a database table.
	 *
	 * ## OPTIONS
	 *
	 * --table=<table>
	 * : Table name without prefix (e.g., mosaml_idp_details)
	 *
	 * --set=<value>
	 * : Field and value to set in format field=value (e.g., status=active)
	 *
	 * --where=<value>
	 * : Where condition in format field=value (e.g., idp_id=my_idp)
	 *
	 * [--environment_id=<id>]
	 * : Environment ID. Uses current environment if not specified.
	 *
	 * ## EXAMPLES
	 *
	 *     # Update IDP status
	 *     wp saml update-field --table=mosaml_idp_details --set=status=active --where=idp_id=my_idp
	 *
	 *     # Update multiple conditions
	 *     wp saml update-field --table=mosaml_idp_details --set=default_idp=1 --where=idp_id=my_idp --environment_id=1
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 *
	 * @return void
	 */
	public function update_field( $args, $assoc_args ) {
		// Validate required parameters.
		if ( empty( $assoc_args['table'] ) ) {
			WP_CLI::error( 'Please specify --table parameter.' );
			return;
		}

		if ( empty( $assoc_args['set'] ) ) {
			WP_CLI::error( 'Please specify --set parameter (e.g., --set=status=active).' );
			return;
		}

		if ( empty( $assoc_args['where'] ) ) {
			WP_CLI::error( 'Please specify --where parameter (e.g., --where=idp_id=my_idp).' );
			return;
		}

		$table_name = $assoc_args['table'];

		// Parse the --set parameter.
		$set_parts = explode( '=', $assoc_args['set'], 2 );
		if ( count( $set_parts ) !== 2 ) {
			WP_CLI::error( 'Invalid --set format. Use: --set=field=value' );
			return;
		}
		$set_field = trim( $set_parts[0] );
		$set_value = trim( $set_parts[1] );

		// Parse the --where parameter(s).
		$where_conditions = array();
		if ( is_array( $assoc_args['where'] ) ) {
			foreach ( $assoc_args['where'] as $where ) {
				$where_parts = explode( '=', $where, 2 );
				if ( count( $where_parts ) === 2 ) {
					$where_conditions[ trim( $where_parts[0] ) ] = trim( $where_parts[1] );
				}
			}
		} else {
			$where_parts = explode( '=', $assoc_args['where'], 2 );
			if ( count( $where_parts ) === 2 ) {
				$where_conditions[ trim( $where_parts[0] ) ] = trim( $where_parts[1] );
			}
		}

		if ( empty( $where_conditions ) ) {
			WP_CLI::error( 'Invalid --where format. Use: --where=field=value' );
			return;
		}

		// Add environment_id if specified.
		if ( ! empty( $assoc_args['environment_id'] ) ) {
			$where_conditions['environment_id'] = $assoc_args['environment_id'];
		} elseif ( 0 === strpos( $table_name, 'mosaml_' ) && 'mosaml_environments' !== $table_name ) {
			// Auto-add current environment_id for mosaml tables (except environments table).
			$environment_id = DB_Utils::get_environment_details( 'id', false );
			if ( $environment_id ) {
				$where_conditions['environment_id'] = $environment_id;
			}
		}

		// Check if record exists.
		$existing_record = DB_Utils::get_records( $table_name, $where_conditions, true );
		if ( ! $existing_record ) {
			WP_CLI::error( sprintf( 'No record found in table "%s" with specified conditions.', $table_name ) );
			return;
		}

		// Update the field.
		$result = DB_Utils::insert_or_update(
			$table_name,
			array( $set_field => $set_value ),
			$where_conditions
		);

		if ( false !== $result ) {
			WP_CLI::success( sprintf( 'Successfully updated %s=%s in table "%s".', $set_field, $set_value, $table_name ) );
		} else {
			WP_CLI::error( sprintf( 'Failed to update field in table "%s".', $table_name ) );
		}
	}

	/**
	 * Displays plugin version and license information.
	 *
	 * ## EXAMPLES
	 *
	 *     wp saml info
	 *
	 * @return void
	 */
	public function info() {
		$version          = defined( 'MOSAML_VERSION' ) ? MOSAML_VERSION : 'Unknown';
		$license_valid    = Feature_Control::check_is_license_valid() ? 'Valid' : 'Invalid/Not Set';
		$license_verified = Feature_Control::check_is_license_verified() ? 'Verified' : 'Not Verified';

		WP_CLI::line( 'MOSAML Plugin Information:' );
		WP_CLI::line( '------------------------' );
		WP_CLI::line( sprintf( 'Version: %s', $version ) );
		WP_CLI::line( sprintf( 'License Status: %s', $license_valid ) );
		WP_CLI::line( sprintf( 'License Verified: %s', $license_verified ) );
		WP_CLI::line( sprintf( 'Plugin Directory: %s', MOSAML_PLUGIN_DIR ) );
	}

	/**
	 * Displays help information for MOSAML CLI commands.
	 *
	 * ## EXAMPLES
	 *
	 *     wp saml help
	 *
	 * @return void
	 */
	public function help() {
		WP_CLI::line( 'MOSAML CLI Commands:' );
		WP_CLI::line( '===================' );
		WP_CLI::line( '' );
		WP_CLI::line( 'wp saml fetch        - Fetch plugin configuration from a config file' );
		WP_CLI::line( 'wp saml activate     - Activate the plugin with details from license file' );
		WP_CLI::line( 'wp saml update       - Handle the plugin update' );
		WP_CLI::line( 'wp saml update-field - Update a specific field in a database table' );
		WP_CLI::line( 'wp saml info         - Display plugin version and license info' );
		WP_CLI::line( '' );
		WP_CLI::line( 'For more information on a specific command, use:' );
		WP_CLI::line( 'wp help saml <command>' );
	}
}

// Initialize the CLI commands if WP-CLI is available.
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	new MOSAML_CLI();
}
