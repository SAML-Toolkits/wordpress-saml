<?php
/**
 * Base Module - Import IDP Details Configuration Class
 *
 * Handles IDP details configuration data import for the base module.
 *
 * @package MOSAML\Module\Base\Config
 * @since 1.0.0
 */

namespace MOSAML\Module\Base\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Utils\Utility;

/**
 * Base Import IDP Details Configuration Class
 */
class Import_Idp_Details_Config {

	/**
	 * Get the database table name
	 *
	 * @return string The table name
	 */
	protected function get_table_name() {
		return Constants::DATABASE_TABLE_NAMES['idp_details'];
	}

	/**
	 * Environment ID
	 *
	 * @var int
	 */
	public $environment_id;

	/**
	 * IDP ID
	 *
	 * @var int
	 */
	public $idp_id;

	/**
	 * IDP Name
	 *
	 * @var string
	 */
	public $idp_name = '';

	/**
	 * Entity ID
	 *
	 * @var string
	 */
	public $entity_id = '';

	/**
	 * SSO URL
	 *
	 * @var string
	 */
	public $sso_url = '';

	/**
	 * SLO URL
	 *
	 * @var string
	 */
	public $slo_url = '';

	/**
	 * Certificate
	 *
	 * @var string
	 */
	public $certificate = '';

	/**
	 * SLO Response URL
	 *
	 * @var string
	 */
	public $slo_response_url = '';

	/**
	 * Password Reset URL
	 *
	 * @var string
	 */
	public $password_reset_url = '';

	/**
	 * Character Encoding
	 *
	 * @var string
	 */
	public $character_encoding = '';

	/**
	 * Assertion Time Validity
	 *
	 * @var string
	 */
	public $assertion_time_validity = '';

	/**
	 * Sign SSO SLO Request
	 *
	 * @var string
	 */
	public $sign_sso_slo_request = '';

	/**
	 * SSO Binding
	 *
	 * @var string
	 */
	public $sso_binding = '';

	/**
	 * SLO Binding
	 *
	 * @var string
	 */
	public $slo_binding = '';

	/**
	 * SP Entity ID
	 *
	 * @var string
	 */
	public $sp_entity_id = '';

	/**
	 * Sync Metadata
	 *
	 * @var string
	 */
	public $sync_metadata = '';

	/**
	 * Metadata URL
	 *
	 * @var string
	 */
	public $metadata_url = '';

	/**
	 * Sync Time Interval
	 *
	 * @var string
	 */
	public $sync_time_interval = '';

	/**
	 * Sync Only Certificate
	 *
	 * @var string
	 */
	public $sync_only_certificate = '';

	/**
	 * Name ID Format
	 *
	 * @var string
	 */
	public $name_id_format = '';

	/**
	 * Default IDP
	 *
	 * @var bool
	 */
	public $default_idp;

	/**
	 * Status
	 *
	 * @var string
	 */
	public $status = '';

	/**
	 * Test Config Attributes
	 *
	 * @var string
	 */
	public $test_config_attributes = '';

	/**
	 * Import configuration data (Base module implementation)
	 *
	 * @param array $config_data Full configuration data (contains Identity_Provider and Service_Provider sections).
	 * @param array $idp_info IDP information.
	 */
	public function import_config( $config_data, $idp_info ) {
		$this->environment_id = $idp_info['environment_id'];

		$this->default_idp = ! empty( Utility::get_default_idp( $this->environment_id ) );

		$this->map_base_idp_data( $config_data );

		$this->save_to_database();
	}

	/**
	 * Map base module IDP data
	 *
	 * @param array $config_data Configuration data.
	 */
	protected function map_base_idp_data( $config_data ) {
		$identity_data = isset( $config_data['Identity_Provider'] ) ? $config_data['Identity_Provider'] : array();
		$service_data  = isset( $config_data['Service_Provider'] ) ? $config_data['Service_Provider'] : array();
		$all_data      = array_merge( $identity_data, $service_data );

		$mapping = array(
			'SP_ENTITY_ID'              => 'sp_entity_id',
			'IDENTITY_NAME'             => 'idp_name',
			'IDP_NAME'                  => 'idp_name',
			'LOGIN_URL'                 => 'sso_url',
			'SSO_URL'                   => 'sso_url',
			'ISSUER'                    => 'entity_id',
			'IDP_ENTITY_ID'             => 'entity_id',
			'X509_CERTIFICATE'          => 'certificate',
			'NAMEID_FORMAT'             => 'name_id_format',
			'IS_ENCODING_ENABLED'       => 'character_encoding',
			'CHARACTER_ENCODING'        => 'character_encoding',
			'ASSERTION_TIME_VALIDITY'   => 'assertion_time_validity',
			'ASSERTION_TIME_VALIDATION' => 'assertion_time_validity',
		);

		foreach ( $mapping as $json_key => $class_var ) {
			$value = null;
			foreach ( $all_data as $data_key => $data_value ) {
				if ( strtoupper( $data_key ) === strtoupper( $json_key ) ) {
					$value = $data_value;
					break;
				}
			}

			if ( null !== $value ) {
				if ( is_array( $value ) && isset( $value[0] ) ) {
					$value = $value[0];
				}
				$this->$class_var = $value;
			}
		}

		if ( empty( $this->idp_name ) || is_array( $this->idp_name ) ) {
			Error_Success_Message::show_admin_notice( '<strong>IDP Import Error:</strong> Invalid IDP name provided in configuration.' );
			return;
		}

		$this->idp_id = sanitize_title( $this->idp_name );

		$this->name_id_format = $this->format_nameid_as_urn( $this->name_id_format );

		if ( empty( $this->sp_entity_id ) ) {
			$this->sp_entity_id = DB_Utils::get_sp_details( 'sp_entity_id', false );
		}

		$this->status = 'active';
	}

	/**
	 * Format NameID to standard SAML URN notation
	 *
	 * Validates and converts NameID format to the full SAML URN specification.
	 * Checks against allowed NameID formats defined in Constants::NAMEID_FORMATS.
	 *
	 * @param string $name_id_format The NameID format value from import.
	 * @return string The NameID format in full URN notation.
	 */
	protected function format_nameid_as_urn( $name_id_format ) {
		if ( empty( $name_id_format ) ) {
			return Constants::NAMEID_FORMATS['unspecified'];
		}

		$valid_nameid_formats = array_values( Constants::NAMEID_FORMATS );

		if ( in_array( $name_id_format, $valid_nameid_formats, true ) ) {
			return $name_id_format;
		}

		foreach ( $valid_nameid_formats as $valid_format ) {
			if ( strpos( $valid_format, $name_id_format ) !== false ) {
				return $valid_format;
			}
		}

		return Constants::NAMEID_FORMATS['unspecified'];
	}

	/**
	 * Save configuration to database
	 */
	protected function save_to_database() {
		try {
			$base_data = array(
				'idp_id'                  => $this->idp_id,
				'idp_name'                => $this->idp_name,
				'entity_id'               => $this->entity_id,
				'sso_url'                 => $this->sso_url,
				'idp_certificate'         => $this->certificate,
				'name_id_format'          => $this->name_id_format,
				'status'                  => $this->status,
				'sp_entity_id'            => $this->sp_entity_id,
				'character_encoding'      => $this->character_encoding,
				'assertion_time_validity' => $this->assertion_time_validity,
				'default_idp'             => $this->default_idp,
			);

			$this->save_idp_data( $base_data );

		} catch ( \Exception $e ) {
			Error_Success_Message::show_admin_notice( '<strong>IDP Save Error:</strong> Failed to save IDP Details configuration: ' . esc_html( $e->getMessage() ) );
		}
	}

	/**
	 * Save IDP data array to database
	 *
	 * @param array $data_array Array of field_name => field_value pairs.
	 */
	protected function save_idp_data( $data_array ) {
		foreach ( $data_array as $field_name => $field_value ) {
			if ( ! empty( $field_value ) ) {
				$this->save_idp_field( $field_name, $field_value );
			}
		}
	}

	/**
	 * Save individual IDP field to database
	 *
	 * @param string $field_name Field name.
	 * @param mixed  $field_value Field value.
	 */
	protected function save_idp_field( $field_name, $field_value ) {
		$data = array(
			'environment_id' => $this->environment_id,
			$field_name      => $field_value,
		);

		$where = array(
			'environment_id' => $this->environment_id,
		);
		DB_Utils::insert_or_update( $this->get_table_name(), $data, $where );
	}
}
