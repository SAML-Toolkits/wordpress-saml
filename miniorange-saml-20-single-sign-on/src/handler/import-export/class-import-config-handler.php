<?php
/**
 * Import Config Handler.
 *
 * @package MOSAML
 */

namespace MOSAML\SRC\Handler\Import_Export;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Handler\Import_Export\Version_Mappings\Legacy_Options_Enum_Enterprise;
use MOSAML\SRC\Handler\Import_Export\Version_Mappings\Legacy_Options_Enum_Premium;
use MOSAML\SRC\Handler\Import_Export\Version_Mappings\Legacy_Options_Enum_Standard;
use MOSAML\SRC\Handler\Import_Export\Version_Mappings\Legacy_Options_Enum_Base;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Constant\Plugin_Files_Constants;
use MOSAML\SRC\Handler\Database_Cleanup_Handler;

/**
 * Import Config Handler.
 */
class Import_Config_Handler {

	const REQUIRED_CONFIG_KEYS = array(
		'entity_id',
		'sso_url',
		'idp_certificate',
	);

	/**
	 * Handle configuration import.
	 *
	 * @return void
	 */
	public function handle_config_import() {
		Utility::start_output_buffering();

		try {
			if ( ! function_exists( 'wp_handle_upload' ) ) {
				require_once ABSPATH . Plugin_Files_Constants::WP_ADMIN_INCLUDES_FILE;
			}

			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verification is done already.
			$file_type = isset( $_FILES['configuration_file']['type'] ) ? sanitize_text_field( $_FILES['configuration_file']['type'] ) : '';
			$slash_pos = strpos( $file_type, '/' );
			$file_ext  = ( false !== $slash_pos ) ? substr( $file_type, $slash_pos + 1 ) : '';
			if ( 'json' !== $file_ext ) {
				Error_Success_Message::show_admin_notice( '<strong>Invalid File:</strong> Please upload a valid JSON configuration file.' );
				Utility::clean_output_buffer();
				return;
			}

			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verification is done already.
			$config_file_tmp_name = ! empty( $_FILES['configuration_file']['tmp_name'] ) ? sanitize_text_field( $_FILES['configuration_file']['tmp_name'] ) : '';
			if ( ! empty( $config_file_tmp_name ) ) {
				if ( ! is_readable( $config_file_tmp_name ) ) {
					Error_Success_Message::show_admin_notice( 'Error importing configuration. Please check the file and try again.' );
					Utility::clean_output_buffer();
					return;
				}

				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading an uploaded local file.
				$file = file_get_contents( $config_file_tmp_name );
				if ( false === $file ) {
					Error_Success_Message::show_admin_notice( 'Error importing configuration. Please check the file and try again.' );
					Utility::clean_output_buffer();
					return;
				}

				$configurations = json_decode( $file, true );
				if ( isset( $configurations['meta']['common_codebase'] ) ) {
					Import_Export_Config_Handler::import_config_from_json( $configurations );
					return;
				}

				$import_file_version = Utility::detect_config_type( $configurations );
				$is_multiple_env     = 'enterprise' === $import_file_version && isset( $configurations['Multiple Environments'] ) && isset( $configurations['Multiple Environments']['Multiple_Licenses'] ) && 'checked' === $configurations['Multiple Environments']['Multiple_Licenses'];
				$enum_map            = $this->get_config_enum_map( $import_file_version, $is_multiple_env );

				if ( empty( $import_file_version ) || empty( $enum_map ) ) {
					Error_Success_Message::show_admin_notice( '<strong>Invalid File:</strong> Please upload a valid JSON configuration file.' );
					Utility::clean_output_buffer();
					return;
				}

				if ( 'enterprise' === $import_file_version ) {
					$this->handle_multiple_idp_configurations( $configurations, $enum_map, $import_file_version, $is_multiple_env );
				} else {
					$this->handle_single_idp_configurations( $configurations, $enum_map, $import_file_version );
				}
				Error_Success_Message::show_admin_notice( '<strong>Configuration imported successfully!</strong> All settings have been updated from the uploaded file.', 'SUCCESS' );
				Utility::clean_output_buffer();
				return;
			}
			Error_Success_Message::show_admin_notice( 'Error importing configuration. Please check the file and try again.' );
			Utility::clean_output_buffer();
		} catch ( \Exception $e ) {
			Error_Success_Message::show_admin_notice( 'Error importing configuration. Please check the file and try again.' );
			Utility::clean_output_buffer();
			return;
		}
	}

	/**
	 * Get the enum map.
	 *
	 * @param string $import_file_version The import file version.
	 * @param bool   $is_multiple_env Whether the configurations are for multiple environments.
	 * @return array The enum map.
	 */
	public function get_config_enum_map( $import_file_version, $is_multiple_env = false ) {
		switch ( $import_file_version ) {
			case 'enterprise':
				return $is_multiple_env ? Legacy_Options_Enum_Enterprise::MULTIPLE_ENV_CONFIG_KEY_TO_COMMON_MAP : Legacy_Options_Enum_Enterprise::CONFIG_KEY_TO_COMMON_MAP;
			case 'premium':
				return Legacy_Options_Enum_Premium::CONFIG_KEY_TO_COMMON_MAP;
			case 'standard':
				return Legacy_Options_Enum_Standard::CONFIG_KEY_TO_COMMON_MAP;
			case 'base':
				return Legacy_Options_Enum_Base::CONFIG_KEY_TO_COMMON_MAP;
			default:
				return array();
		}
	}

	/**
	 * Get the class import order map.
	 *
	 * @param string $import_file_version The import file version.
	 * @return array The class import order map.
	 */
	public function get_class_import_order_map( $import_file_version ) {
		switch ( $import_file_version ) {
			case 'enterprise':
				return Legacy_Options_Enum_Enterprise::CLASS_IMPORT_ORDER;
			case 'premium':
				return Legacy_Options_Enum_Premium::CLASS_IMPORT_ORDER;
			case 'standard':
				return Legacy_Options_Enum_Standard::CLASS_IMPORT_ORDER;
			case 'base':
				return Legacy_Options_Enum_Base::CLASS_IMPORT_ORDER;
			default:
				return array();
		}
	}

	/**
	 * Handle single IDP configurations.
	 *
	 * @param array  $configurations The configurations.
	 * @param array  $enum_map The enum map.
	 * @param string $import_file_version The import file version.
	 * @return void
	 */
	public function handle_single_idp_configurations( $configurations, $enum_map, $import_file_version ) {

		$handler_instances = $this->prepare_configurations( $configurations, $enum_map );
		Import_Export_Config_Handler::backup_existing_configuration();
		DB_Utils::truncate_table_data();
		Database_Cleanup_Handler::delete_plugin_options( true );
		DB_Utils::create_tables_and_initialize();
		$class_import_order = $this->get_class_import_order_map( $import_file_version );
		foreach ( $class_import_order as $class_name ) {
			if ( ! isset( $handler_instances[ $class_name ] ) ) {
				continue;
			}
			$class_instance = $handler_instances[ $class_name ];
			if ( ! is_null( $class_instance ) && method_exists( $class_instance, 'save_data' ) ) {
				$class_instance->save_data( $class_instance );
			}
		}
	}

	/**
	 * Handle multiple IDP configurations.
	 *
	 * @param array  $configurations The configurations.
	 * @param array  $enum_map The enum map.
	 * @param string $import_file_version The import file version.
	 * @param bool   $is_multiple_env Whether the configurations are for multiple environments.
	 * @return void
	 */
	public function handle_multiple_idp_configurations( $configurations, $enum_map, $import_file_version, $is_multiple_env = false ) {

		$handler_instances = array();
		$env_config_arr    = $is_multiple_env && ! empty( $configurations['Multiple Environments']['Environment_Objects'] ) ? $configurations['Multiple Environments']['Environment_Objects'] : array();
		if ( $is_multiple_env && ! empty( $env_config_arr ) ) {
			foreach ( $env_config_arr as $config_key => $config_value ) {
				$handler_instances[ $config_key ] = $this->prepare_configurations( $config_value, $enum_map, true );
				$handler_instances[ $config_key ] = $this->collect_arrays_first( $handler_instances[ $config_key ] );

				$anomaly_handler = Import_Anomaly_Handler::instance();
				if ( ! empty( $handler_instances[ $config_key ]['default_idp'] ) ) {
					$anomaly_handler->set_default_idp( $handler_instances[ $config_key ]['default_idp'], $handler_instances[ $config_key ] );
				}
				if ( ! empty( $configurations['Custom_Certificate'] ) && empty( $handler_instances[ $config_key ]['Certificate_Data'] ) ) {
					$custom_certificate_obj = Utility::get_handler_object( 'Certificate_Data', true, 'admin' );
					$anomaly_handler->set_custom_certificate( $configurations['Custom_Certificate'], $custom_certificate_obj );
					$handler_instances[ $config_key ]['Certificate_Data'] = $custom_certificate_obj;
				}
			}
		} else {
			$handler_instances = $this->prepare_configurations( $configurations, $enum_map );
			$handler_instances = $this->collect_arrays_first( $handler_instances );

			if ( ! empty( $handler_instances['default_idp'] ) ) {
				$anomaly_handler = Import_Anomaly_Handler::instance();
				$anomaly_handler->set_default_idp( $handler_instances['default_idp'], $handler_instances );
			}
		}

		Import_Export_Config_Handler::backup_existing_configuration();
		DB_Utils::truncate_table_data();
		Database_Cleanup_Handler::delete_plugin_options( true );
		DB_Utils::create_tables_and_initialize();
		$class_import_order = $this->get_class_import_order_map( $import_file_version );

		if ( $is_multiple_env && ! empty( $env_config_arr ) ) {
			foreach ( $handler_instances as $env_key => $env_value ) {
				$info_arr             = array(
					'environment_name' => $env_key,
					'environment_url'  => ! empty( $env_value['Multiple_Environments_Data'] ) ? Utility::parse_environment_url( $env_value['Multiple_Environments_Data']->environment_url ) : '',
				);
				$env_handler_instance = Utility::get_handler_object( 'Multiple_Environments_Data', true, 'admin' );
				update_option( Constants::ENABLE_MULTIPLE_ENVIRONMENTS_OPTION_NAME, 'checked' );
				if ( method_exists( $env_handler_instance, 'save_data' ) ) {
					$env_handler_instance->save_data( $env_handler_instance, $info_arr );
				}
				$this->multiple_idp_save_data_wrapper( $env_value, $class_import_order, $info_arr );
			}
		} else {
			$this->multiple_idp_save_data_wrapper( $handler_instances, $class_import_order );
		}
	}

	/**
	 * Multiple IDP save data wrapper.
	 *
	 * @param array $handler_instances The handler instances.
	 * @param array $class_import_order The class import order.
	 * @param array $info_arr The info array.
	 * @return void
	 */
	public function multiple_idp_save_data_wrapper( $handler_instances, $class_import_order, $info_arr = array() ) {
		foreach ( $handler_instances as $config_key => $config_value ) {
			if ( is_array( $config_value ) ) {
				if ( 'DEFAULT' !== $config_key && ! isset( $config_value['SP_Setup_Data'] ) ) {
					continue;
				}
				$info_arr['idp_id'] = $config_key;
				foreach ( $class_import_order as $class_name ) {
					if ( ! isset( $config_value[ $class_name ] ) ) {
						continue;
					}
					$class_instance = $config_value[ $class_name ];
					if ( ! is_null( $class_instance ) && method_exists( $class_instance, 'save_data' ) ) {
						$class_instance->save_data( $class_instance, $info_arr );
					}
				}
			} elseif ( ! is_null( $config_value ) && method_exists( $config_value, 'save_data' ) ) {
				$config_value->save_data( $config_value, $info_arr );
			}
		}
	}

	/**
	 * Collect the arrays first.
	 *
	 * @param array $handler_instances The handler instances.
	 * @return array The handler instances.
	 */
	public function collect_arrays_first( $handler_instances ) {
		$arrays  = array();
		$objects = array();
		foreach ( $handler_instances as $key => $value ) {
			if ( is_array( $value ) ) {
				$arrays[ $key ] = $value;
			} else {
				$objects[ $key ] = $value;
			}
		}
		return array_merge( $arrays, $objects );
	}

	/**
	 * Prepare the configurations.
	 *
	 * @param array $config_arr The configuration array.
	 * @param array $enum_map The enum map.
	 * @param bool  $is_multiple_env Whether the configurations are for multiple environments.
	 * @param array $handler_instances The handler instances.
	 * @return array The handler instances.
	 */
	public function prepare_configurations( $config_arr, $enum_map, $is_multiple_env = false, $handler_instances = array() ) {

		foreach ( $config_arr as $config_key => $config_value ) {
			$lower_config_key = strtolower( $config_key );
			if ( ! $is_multiple_env && 'multiple environments' === $lower_config_key ) {
				continue;
			}
			if ( is_array( $config_value ) && ( ! isset( $enum_map[ $lower_config_key ] ) || 'Role_Mapping' === $config_key || 'Attribute_Mapping' === $config_key || 'Advanced_settings' === $config_key ) && 'saml_search_idp' !== $lower_config_key && 'mo_saml_enabled_idps' !== $lower_config_key ) {
				$handler_instances = $this->prepare_configurations( $config_value, $enum_map, $is_multiple_env, $handler_instances );
			} else {
				if ( empty( $enum_map[ $lower_config_key ] ) ) {
					if ( 'default_identity_provider' === $lower_config_key || 'saml_default_idp' === $lower_config_key ) {
						$handler_instances['default_idp'] = $config_value;
					}
					continue;
				}

				$enum_map_config_arr = $enum_map[ $lower_config_key ];

				if ( isset( $enum_map_config_arr['specific_to'] ) && 'idp' === $enum_map_config_arr['specific_to'] ) {
					if ( is_array( $config_value ) ) {
						foreach ( $config_value as $idp_config_key => $idp_config_value ) {
							$idp_config = isset( $handler_instances[ $idp_config_key ] ) ? $handler_instances[ $idp_config_key ] : array();
							if ( is_array( $idp_config_value ) && 'configured_role_values' !== $lower_config_key && 'mo_saml_configured_role_values' !== $lower_config_key && 'mo_saml_custom_attrs_mapping' !== $lower_config_key && 'saml_attrs_to_display_idp' !== $lower_config_key && 'attribute_custom_mapping' !== $lower_config_key && 'attribute_show_in_user_menu' !== $lower_config_key && 'test_config_attibutes' !== $lower_config_key && 'mo_saml_test_config_attrs' !== $lower_config_key ) {
								$handler_instances[ $idp_config_key ] = $this->prepare_configurations( $idp_config_value, $enum_map, $is_multiple_env, $idp_config );
							} else {
								$handler_instances[ $idp_config_key ] = $this->set_property_in_object( $enum_map_config_arr, $lower_config_key, $idp_config_value, $idp_config );
							}
						}
					}
				} else {
					$handler_instances = $this->set_property_in_object( $enum_map_config_arr, $lower_config_key, $config_value, $handler_instances );
				}
			}
		}
		return $handler_instances;
	}

	/**
	 * Set the property in the object.
	 *
	 * @param array  $enum_map_config_arr The enum map config array.
	 * @param string $config_key The config key.
	 * @param mixed  $config_value The config value.
	 * @param array  $import_config_arr The import config array.
	 * @return array The import config array.
	 * @throws \Exception If the property is required and the value is empty.
	 */
	public function set_property_in_object( $enum_map_config_arr, $config_key, $config_value, $import_config_arr ) {

		$object = null;
		if ( ! empty( $enum_map_config_arr['class'] ) ) {
			$class_name = $enum_map_config_arr['class'];

			if ( ! isset( $import_config_arr[ $class_name ] ) ) {
				$import_config_arr[ $class_name ] = Utility::get_handler_object( $class_name, true, 'admin' );
			}

			$object   = $import_config_arr[ $class_name ];
			$property = $enum_map_config_arr['property'];
			if ( empty( $config_value ) ) {
				if ( in_array( $property, self::REQUIRED_CONFIG_KEYS, true ) ) {
					// TODO: throw particular exception for invalid file.
					throw new \Exception( 'Invalid File' . esc_html( $config_key ) );
				}
			}

			if ( ! empty( $property ) ) {

				if ( ! empty( $enum_map_config_arr['transform'] ) ) {
					$transform_handler = Import_Config_Transform::instance();
					$config_value      = $transform_handler->{$enum_map_config_arr['transform']}( $object, $config_key, $config_value );
				}
				if ( property_exists( $object, $property ) && ( ! in_array( $class_name, array( 'Domain_Mapping_Data', 'Site_Auto_Redirection_Data' ), true ) || ! empty( $config_value ) ) ) {
					$object->{$property} = $config_value;
				}
			}

			if ( isset( $enum_map_config_arr['anomaly'] ) ) {
				$anomaly_handler = Import_Anomaly_Handler::instance();
				$anomaly_handler->{$enum_map_config_arr['anomaly']}( $config_value, $object );
			}
		}
		return $import_config_arr;
	}
}
