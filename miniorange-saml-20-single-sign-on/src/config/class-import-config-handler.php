<?php
/**
 * Import Configuration Handler
 *
 * This class provides centralized configuration management for all modules.
 * It loads configuration data from files and distributes it to appropriate
 * feature-specific configuration classes.
 *
 * @package MOSAML\SRC\Config
 * @since 1.0.0
 */

namespace MOSAML\SRC\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\Traits\Instance;
use MOSAML\SRC\Utils\DB_Utils;

/**
 * Import Configuration Handler
 *
 * Manages loading and distribution of configuration data across all modules.
 */
class Import_Config_Handler {

	use Instance;

	/**
	 * Current environment ID
	 *
	 * @var int
	 */
	private $environment_id;

	/**
	 * Configuration data
	 *
	 * @var array
	 */
	private $config_data;

	/**
	 * Detected configuration type
	 *
	 * @var string
	 */
	private $config_type;

	/**
	 * Constructor
	 */
	public function __construct() {
		$this->environment_id = DB_Utils::get_environment_details( 'id', false );
	}

	/**
	 * Handle configuration import with admin notices
	 *
	 * @return void
	 */
	public function handle_config_file_import() {
		Utility::start_output_buffering();

		if ( $this->process_configuration_file() ) {
			Error_Success_Message::show_admin_notice( '<strong>Configuration imported successfully!</strong> All settings have been updated from the uploaded file.', 'SUCCESS' );
		}

		Utility::clean_output_buffer();
	}

	/**
	 * Import configuration from uploaded file
	 *
	 * @return bool Success status.
	 */
	public function process_configuration_file() {
		$config_file = Utility::get_global_file_data( 'configuration_file' );

		$file_info = pathinfo( $config_file['name'] );
		if ( ! isset( $file_info['extension'] ) || strtolower( $file_info['extension'] ) !== 'json' ) {
			Error_Success_Message::show_admin_notice( '<strong>Invalid File:</strong> Please upload a valid JSON configuration file.' );
			Utility::clean_output_buffer();
			return false;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading an uploaded local file.
		$json_content = file_get_contents( $config_file['tmp_name'] );
		if ( false === $json_content ) {
			Error_Success_Message::show_admin_notice( '<strong>Read Error:</strong> Failed to read configuration file.' );
			Utility::clean_output_buffer();
			return false;
		}

		$this->config_data = json_decode( $json_content, true );

		if ( json_last_error() !== JSON_ERROR_NONE ) {
			Error_Success_Message::show_admin_notice( '<strong>JSON Error:</strong> Invalid JSON configuration: ' . json_last_error_msg() );
			Utility::clean_output_buffer();
			return false;
		}

		$this->config_type = Utility::detect_config_type( $this->config_data );
		$this->distribute_config_to_modules();

		return true;
	}

	/**
	 * Process configuration sections by delegating to module-specific classes
	 */
	private function distribute_config_to_modules() {
		if ( $this->contains_identity_provider_data() ) {
			$this->process_identity_providers();
		}
	}

	/**
	 * Process identity providers - handles both single and multiple IDPs
	 */
	private function process_identity_providers() {
		$identity_names = $this->extract_identity_provider_names();

		if ( empty( $identity_names ) ) {
			return;
		}

		if ( is_string( $identity_names ) ) {
			$context = $this->prepare_import_context_for_idp( $identity_names, $this->config_data );
			$this->load_and_execute_config_class( 'Import_Idp_Details_Config', $this->config_data, $context );
			return;
		}

		if ( is_array( $identity_names ) ) {
			foreach ( $identity_names as $idp_key => $idp_data ) {
				if ( is_array( $idp_data ) && isset( $idp_data['idp_name'] ) ) {
					$idp_config_data = $this->create_single_idp_config( $idp_key, $idp_data );
					$context         = $this->prepare_import_context_for_idp( $idp_data['idp_name'], $idp_config_data );
					$this->load_and_execute_config_class( 'Import_Idp_Details_Config', $idp_config_data, $context );
				}
			}
		}
	}

	/**
	 * Create configuration data structure for a single IDP
	 *
	 * @param string $idp_key IDP key/identifier.
	 * @param array  $idp_data IDP specific data.
	 * @return array Configuration data for single IDP.
	 */
	private function create_single_idp_config( $idp_key, $idp_data ) {
		$config = $this->config_data;

		if ( isset( $config['Service_Provider']['Identity_name'] ) ) {
			$config['Service_Provider']['Identity_name'] = $idp_data['idp_name'];
			foreach ( $idp_data as $key => $value ) {
				$config['Service_Provider'][ $key ] = $value;
			}
		}

		return $config;
	}

	/**
	 * Extract identity provider names from configuration
	 *
	 * @return string|array|null Single IDP name, array of IDPs, or null
	 */
	private function extract_identity_provider_names() {
		$sections  = array( 'Service_Provider', 'Identity_Provider' );
		$name_keys = array( 'IDENTITY_NAME' );

		foreach ( $sections as $section ) {
			if ( ! isset( $this->config_data[ $section ] ) || ! is_array( $this->config_data[ $section ] ) ) {
				continue;
			}

			foreach ( $this->config_data[ $section ] as $key => $value ) {
				foreach ( $name_keys as $name_key ) {
					if ( strtoupper( $key ) === strtoupper( $name_key ) && ! empty( $value ) ) {
						return $value;
					}
				}
			}
		}

		return null;
	}

	/**
	 * Build context information for configuration processing for a specific IDP
	 *
	 * @param string $idp_name IDP name.
	 * @param array  $config_data Configuration data.
	 * @return array Context information.
	 */
	private function prepare_import_context_for_idp( $idp_name, $config_data ) {
		unset( $config_data );
		$context = array(
			'environment_id' => $this->environment_id,
			'idp_id'         => 1,
			'config_type'    => $this->config_type,
			'idp_name'       => $idp_name,
		);

		return $context;
	}

	/**
	 * Check if configuration has IDP data
	 *
	 * @return bool
	 */
	private function contains_identity_provider_data() {
		return isset( $this->config_data['Identity_Provider'] ) ||
				isset( $this->config_data['Service_Provider'] );
	}

	/**
	 * Load and execute module-specific configuration class
	 *
	 * @param string $class_name Configuration class name.
	 * @param array  $section_data Configuration section data.
	 * @param array  $context Processing context.
	 */
	private function load_and_execute_config_class( $class_name, $section_data, $context ) {
		$config_class = Utility::get_config_class_instance( $class_name, $this->config_type );
		if ( ! $config_class ) {
			return;
		}

		if ( method_exists( $config_class, 'import_config' ) ) {
			$config_class->import_config( $section_data, $context );
		} else {
			$this->set_basic_config_variables( $config_class, $context );
		}
	}

	/**
	 * Set basic configuration variables (fallback when import_config not available)
	 *
	 * @param object $config_class Configuration class instance.
	 * @param array  $context Processing context.
	 */
	private function set_basic_config_variables( $config_class, $context ) {
		$common_vars = array( 'environment_id', 'subsite_id', 'idp_id', 'config_type' );

		foreach ( $common_vars as $var ) {
			if ( property_exists( $config_class, $var ) && isset( $context[ $var ] ) ) {
				$config_class->{$var} = $context[ $var ];
			}
		}
	}

	/**
	 * Get nested value from array using dot notation
	 *
	 * @param array  $data Source array.
	 * @param string $key Dot-separated key (e.g., 'Service_Provider.Identity_name').
	 * @return mixed|null Value if found, null otherwise.
	 */
	private function get_nested_value( $data, $key ) {
		$keys  = explode( '.', $key );
		$value = $data;

		foreach ( $keys as $k ) {
			if ( ! is_array( $value ) || ! isset( $value[ $k ] ) ) {
				return null;
			}
			$value = $value[ $k ];
		}

		return $value;
	}
}
